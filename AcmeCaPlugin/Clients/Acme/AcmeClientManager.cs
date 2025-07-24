using ACMESharp.Crypto;
using ACMESharp.Crypto.JOSE;
using ACMESharp.Crypto.JOSE.Impl;
using ACMESharp.Protocol;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.Acme.Clients.Acme
{
    /// <summary>
    /// Manages ACME client lifecycle including account creation, caching, and client initialization.
    /// Handles both External Account Binding (EAB) and standard ACME account workflows.
    /// </summary>
    public class AcmeClientManager
    {
        #region Private Fields

        private readonly ILogger _log;
        private readonly HttpClient _httpClient;
        private readonly string _directoryUrl;
        private readonly string _email;
        private readonly string _eabKid;
        private readonly string _eabHmac;
        private readonly AccountManager _accountManager;

        #endregion

        #region Constants

        /// <summary>
        /// User-Agent string identifying this plugin to ACME servers
        /// </summary>
        private const string UserAgentString = "KeyfactorAcmePlugin/1.0";

        /// <summary>
        /// HMAC algorithm used for External Account Binding
        /// </summary>
        private const string EabHmacAlgorithm = "HS256";

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the AcmeClientManager with the specified configuration.
        /// </summary>
        /// <param name="log">Logger instance for diagnostic output</param>
        /// <param name="config">ACME client configuration containing directory URL, email, and EAB settings</param>
        /// <param name="httpClient">HTTP client for making requests to the ACME server</param>
        public AcmeClientManager(ILogger log, AcmeClientConfig config, HttpClient httpClient)
        {
            _log = log ?? throw new ArgumentNullException(nameof(log));
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

            if (config == null)
                throw new ArgumentNullException(nameof(config));

            _directoryUrl = config.DirectoryUrl;
            _email = config.Email;
            _eabKid = config.EabKid;
            _eabHmac = config.EabHmacKey;
            _accountManager = new AccountManager(log,config.SignerEncryptionPhrase);

            _log.LogDebug("AcmeClientManager initialized for directory: {DirectoryUrl}", _directoryUrl);
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Creates and configures an ACME protocol client with associated account and signer.
        /// First attempts to load a cached account, and if not found, creates a new account
        /// with optional External Account Binding (EAB) support.
        /// </summary>
        /// <returns>
        /// A tuple containing:
        /// - Client: Configured AcmeProtocolClient ready for use
        /// - Account: Account details from the ACME server
        /// - Signer: Account signer for cryptographic operations
        /// </returns>
        /// <exception cref="Exception">Thrown when account creation or client setup fails</exception>
        public async Task<(AcmeProtocolClient Client, AccountDetails Account, AccountSigner Signer)> CreateClientAsync()
        {
            // Configure HTTP client with base address and user-agent
            await ConfigureHttpClientAsync();

            // Attempt to load existing cached account first
            var cachedAccount = await TryLoadCachedAccountAsync();
            if (cachedAccount.HasValue)
            {
                _log.LogInformation("Using cached ACME account for directory: {DirectoryUrl}", _directoryUrl);
                return cachedAccount.Value;
            }

            // No cached account found - create new account
            _log.LogInformation("No cached account found, creating new ACME account");
            return await CreateNewAccountAsync();
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Configures the HTTP client with the ACME directory URL and user-agent header.
        /// </summary>
        private async Task ConfigureHttpClientAsync()
        {
            _httpClient.BaseAddress = new Uri(_directoryUrl);

            // Set user-agent header if not already present
            if (!_httpClient.DefaultRequestHeaders.UserAgent.Any())
            {
                _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgentString);
                _log.LogDebug("User-Agent header set to: {UserAgent}", UserAgentString);
            }
        }

        /// <summary>
        /// Manually creates an ACME account by constructing the JWS with correct field ordering.
        /// This ensures compatibility with ZeroSSL's strict field ordering requirements.
        /// </summary>
        /// <param name="client">The ACME protocol client</param>
        /// <param name="signer">The account signer</param>
        /// <param name="contacts">Contact information for the account</param>
        /// <param name="eab">External Account Binding object (null if not using EAB)</param>
        /// <returns>The created account details</returns>
        private async Task<AccountDetails> CreateAccountManuallyAsync(
            AcmeProtocolClient client,
            IJwsTool signer,
            string[] contacts,
            object eab)
        {
            // Get a fresh nonce
            await client.GetNonceAsync();

            // Create the payload
            var payload = new
            {
                contact = contacts,
                termsOfServiceAgreed = true,
                externalAccountBinding = eab
            };

            // Create protected header with CORRECT field ordering for ZeroSSL
            var protectedHeader = new
            {
                jwk = signer.ExportJwk(),           // JWK MUST come first for ZeroSSL
                alg = signer.JwsAlg,                // Algorithm second
                url = client.Directory.NewAccount,  // URL third
                nonce = client.NextNonce            // Nonce last
            };

            // Serialize payload and protected header
            var payloadJson = JsonConvert.SerializeObject(payload,
                Formatting.None,
                new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });

            var protectedJson = JsonConvert.SerializeObject(protectedHeader, Formatting.None);

            // Base64url encode
            var protectedB64 = CryptoHelper.Base64.UrlEncode(Encoding.UTF8.GetBytes(protectedJson));
            var payloadB64 = CryptoHelper.Base64.UrlEncode(Encoding.UTF8.GetBytes(payloadJson));

            // Create signing input and sign
            var signingInput = $"{protectedB64}.{payloadB64}";
            var signature = signer.Sign(Encoding.UTF8.GetBytes(signingInput));
            var signatureB64 = CryptoHelper.Base64.UrlEncode(signature);

            // Create JWS object
            var jws = new
            {
                @protected = protectedB64,
                payload = payloadB64,
                signature = signatureB64
            };

            var jwsJson = JsonConvert.SerializeObject(jws);
            var requestContent = new StringContent(jwsJson, Encoding.UTF8);

            // Explicitly set content type
            requestContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/jose+json");

            var response = await _httpClient.PostAsync(client.Directory.NewAccount, requestContent);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _log.LogError("Account creation failed. Status: {StatusCode}, Response: {Response}",
                    response.StatusCode, errorContent);
                throw new Exception($"Account creation failed: {response.StatusCode} - {errorContent}");
            }

            // Parse the response
            var responseContent = await response.Content.ReadAsStringAsync();
            var accountDetails = JsonConvert.DeserializeObject<AccountDetails>(responseContent);

            // Set the account location from the Location header
            if (response.Headers.Location != null)
            {
                accountDetails.Kid = response.Headers.Location.ToString();
            }

            // Note: NextNonce is read-only, the client will automatically get a new nonce on the next request

            return accountDetails;
        }

        /// <summary>
        /// Attempts to load a cached account and create a client from it.
        /// </summary>
        /// <returns>
        /// A tuple with client, account, and signer if cached account exists and is valid;
        /// otherwise null.
        /// </returns>
        private async Task<(AcmeProtocolClient Client, AccountDetails Account, AccountSigner Signer)?> TryLoadCachedAccountAsync()
        {
            var cachedAccount = _accountManager.LoadDefaultAccount(_directoryUrl);

            if (cachedAccount?.Signer == null)
            {
                _log.LogDebug("No valid cached account found for directory: {DirectoryUrl}", _directoryUrl);
                return null;
            }

            try
            {
                // Create client using cached account's signer
                var signerTool = cachedAccount.Signer.GetJwsTool();
                var client = new AcmeProtocolClient(_httpClient, usePostAsGet: true, signer: signerTool);

                // Initialize client with directory and nonce
                client.Directory = await client.GetDirectoryAsync();
                await client.GetNonceAsync();
                client.Account = cachedAccount.Details;

                _log.LogDebug("Successfully loaded cached account with key ID: {AccountId}",
                    cachedAccount.Details?.Kid);

                return (client, cachedAccount.Details, cachedAccount.Signer);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Failed to initialize client with cached account, will create new account");
                return null;
            }
        }

        /// <summary>
        /// Creates a new ACME account with optional External Account Binding (EAB) support.
        /// </summary>
        /// <returns>
        /// A tuple containing the new client, account details, and signer.
        /// </returns>
        private async Task<(AcmeProtocolClient Client, AccountDetails Account, AccountSigner Signer)> CreateNewAccountAsync()
        {
            // Create temporary signer for account creation
            var tempSigner = new ESJwsTool();
            tempSigner.Init();
            _log.LogDebug("Created temporary ES256 signer for account creation");

            // Create setup client for account creation
            var setupClient = new AcmeProtocolClient(_httpClient, usePostAsGet: true, signer: tempSigner);
            setupClient.Directory = await setupClient.GetDirectoryAsync();
            await setupClient.GetNonceAsync();

            var contacts = new[] { $"mailto:{_email}" };
            object eab = null;

            if (IsEabConfigured())
            {
                eab = ExternalAccountBindingHelper.CreateExternalAccountBinding(
                    setupClient, tempSigner, _eabKid, _eabHmac, EabHmacAlgorithm);
            }

            // Create account with or without EAB
            //AccountDetails account = await CreateAccountWithEabSupportAsync(setupClient, tempSigner);
            AccountDetails account = await CreateAccountManuallyAsync(setupClient, tempSigner,contacts,eab);

            // Cache the new account for future use
            var newSigner = new AccountSigner(tempSigner);
            var newAccount = new Account(account, newSigner);
            _accountManager.StoreAccount(newAccount, _directoryUrl);
            _log.LogInformation("New ACME account created and cached with key ID: {AccountId}", account.Kid);

            // Create final client with the new account
            return await CreateFinalClientAsync(setupClient, newSigner, account);
        }


        /// <summary>
        /// Creates the final ACME client using the newly created account.
        /// </summary>
        /// <param name="setupClient">The setup client containing the directory information</param>
        /// <param name="signer">The account signer</param>
        /// <param name="account">The account details</param>
        /// <returns>A tuple with the final client, account, and signer</returns>
        private async Task<(AcmeProtocolClient Client, AccountDetails Account, AccountSigner Signer)> CreateFinalClientAsync(
            AcmeProtocolClient setupClient, AccountSigner signer, AccountDetails account)
        {
            var finalSignerTool = signer.GetJwsTool();
            var finalClient = new AcmeProtocolClient(_httpClient, usePostAsGet: true, signer: finalSignerTool);

            // Reuse directory from setup client to avoid additional roundtrip
            finalClient.Directory = setupClient.Directory;
            await finalClient.GetNonceAsync();
            finalClient.Account = account;

            _log.LogDebug("Final ACME client created and configured");

            return (finalClient, account, signer);
        }

        /// <summary>
        /// Determines if External Account Binding (EAB) is configured by checking
        /// if both the key identifier and HMAC key are provided.
        /// </summary>
        /// <returns>True if EAB is configured, false otherwise</returns>
        private bool IsEabConfigured()
        {
            return !string.IsNullOrWhiteSpace(_eabKid) && !string.IsNullOrWhiteSpace(_eabHmac);
        }

        #endregion
    }
}