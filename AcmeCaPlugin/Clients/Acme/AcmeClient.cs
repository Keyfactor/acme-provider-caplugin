using ACMESharp.Authorizations;
using ACMESharp.Crypto;
using ACMESharp.Protocol;
using ACMESharp.Protocol.Resources;
using Keyfactor.Extensions.CAPlugin.Acme.Interfaces;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.Acme.Clients.Acme
{
    /// <summary>
    /// High-performance ACME protocol client implementing RFC 8555 (Automatic Certificate Management Environment).
    /// Handles complete certificate lifecycle: account management, order creation, domain validation,
    /// certificate issuance, renewal, and revocation with robust error handling and retry logic.
    /// </summary>
    internal sealed class AcmeClient : IDisposable
    {
        #region ACME Protocol Constants

        // Order status constants per RFC 8555 Section 7.1.6
        // https://tools.ietf.org/html/rfc8555#section-7.1.6
        public const string OrderPending = "pending";       // Created, awaiting authorizations
        public const string OrderReady = "ready";           // Authorizations complete, ready for finalization
        public const string OrderProcessing = "processing"; // CA processing certificate issuance
        public const string OrderInvalid = "invalid";       // Validation failed or error occurred
        public const string OrderValid = "valid";           // Certificate issued and available

        // Authorization status constants
        public const string AuthorizationValid = "valid";          // Successfully validated
        public const string AuthorizationInvalid = "invalid";      // Validation failed
        public const string AuthorizationPending = "pending";      // Awaiting challenge completion
        public const string AuthorizationProcessing = "processing"; // Validation in progress

        // Challenge status constants
        public const string ChallengeValid = "valid"; // Challenge successfully validated

        // HTTP and retry configuration
        private const int MaxNonceRetries = 3;
        private const int MaxStatusPollingRetries = 30;
        private const int StatusPollingDelayMs = 2000;
        private const int ChallengePollingDelayMs = 1000;
        private const int MaxChallengePollingRetries = 5;
        private const string UserAgentString = "KeyfactorAcmePlugin/1.0";
        private const string JoseContentType = "application/jose+json";

        #endregion

        #region Fields

        private readonly ILogger _log;
        private AcmeProtocolClient _client;
        private readonly AcmeClientConfig _config;
        private readonly HttpClient _httpClient;
        private bool _disposed;

        #endregion

        #region Properties

        /// <summary>
        /// The authenticated ACME account with cryptographic signing capabilities.
        /// Used for all protocol operations requiring authentication.
        /// </summary>
        public Account Account { get; private set; }

        #endregion

        #region Constructor & Disposal

        /// <summary>
        /// Initializes a new high-performance AcmeClient with proper HTTP configuration.
        /// </summary>
        /// <param name="log">Logger for diagnostic output and debugging</param>
        /// <param name="config">ACME client configuration settings</param>
        /// <param name="httpClient">Pre-configured HTTP client for network operations</param>
        /// <param name="directory">ACME service directory with endpoint URLs</param>
        /// <param name="account">Authenticated ACME account</param>
        /// <exception cref="ArgumentNullException">Thrown when required parameters are null</exception>
        public AcmeClient(
            ILogger log,
            AcmeClientConfig config,
            HttpClient httpClient,
            ServiceDirectory directory,
            Account account)
        {
            _log = log ?? throw new ArgumentNullException(nameof(log));
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            Account = account ?? throw new ArgumentNullException(nameof(account));

            ConfigureHttpClient();
            InitializeAcmeProtocolClient(directory);
        }

        /// <summary>
        /// Configures the HTTP client with appropriate headers and settings.
        /// </summary>
        private void ConfigureHttpClient()
        {
            if (!_httpClient.DefaultRequestHeaders.UserAgent.Any())
            {
                _httpClient.DefaultRequestHeaders.UserAgent.TryParseAdd(UserAgentString);
            }
        }

        /// <summary>
        /// Initializes the underlying ACME protocol client with proper signing configuration.
        /// </summary>
        private void InitializeAcmeProtocolClient(ServiceDirectory directory)
        {
            var signer = Account.Signer.JwsTool();
            _client = new AcmeProtocolClient(_httpClient, usePostAsGet: true, signer: signer)
            {
                Directory = directory,
                Account = Account.Details
            };
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _client?.Dispose();
                _disposed = true;
            }
        }

        #endregion

        #region Core HTTP Operations

        /// <summary>
        /// Executes HTTP POST with automatic nonce retry logic to handle badNonce errors.
        /// Implements exponential backoff and fresh nonce retrieval on each attempt.
        /// </summary>
        /// <param name="endpoint">Target ACME endpoint URL</param>
        /// <param name="postFunc">Function that creates the HTTP request with a fresh nonce</param>
        /// <returns>HTTP response from successful request</returns>
        /// <exception cref="Exception">Thrown after max retries or non-nonce related errors</exception>
        private async Task<HttpResponseMessage> PostWithNonceRetry(string endpoint, Func<string, Task<HttpResponseMessage>> postFunc)
        {
            for (int attempt = 1; attempt <= MaxNonceRetries; attempt++)
            {
                // Always get fresh nonce before each attempt
                await _client.GetNonceAsync();
                var nonce = _client.NextNonce;

                var response = await postFunc(nonce);

                if (response.IsSuccessStatusCode)
                {
                    return response;
                }

                var responseBody = await response.Content.ReadAsStringAsync();

                // Only retry on badNonce errors, fail fast on other errors
                if (!responseBody.Contains("badNonce") || attempt == MaxNonceRetries)
                {
                    _log.LogError("ACME request failed. Status: {Status}, Body: {Body}", response.StatusCode, responseBody);
                    return response;
                }

                _log.LogWarning("badNonce received on attempt {Attempt}/{MaxAttempts}. Retrying with fresh nonce...",
                    attempt, MaxNonceRetries);

                // Brief delay before retry to allow server state to settle
                await Task.Delay(500);
            }

            throw new InvalidOperationException("ACME request failed after maximum retries due to repeated badNonce errors.");
        }

        /// <summary>
        /// Creates a JWS (JSON Web Signature) request payload for ACME protocol communication.
        /// Handles both account-based (kid) and key-based (jwk) authentication.
        /// </summary>
        /// <param name="endpoint">Target endpoint URL</param>
        /// <param name="payload">Request payload object (null for POST-as-GET)</param>
        /// <param name="nonce">Fresh nonce from ACME server</param>
        /// <returns>Configured HTTP content ready for transmission</returns>
        private StringContent CreateJwsRequest(string endpoint, object payload, string nonce)
        {
            // Build protected header - use 'kid' for established accounts, 'jwk' for new registrations
            object protectedHeader = _client.Account?.Kid != null
                ? new
                {
                    alg = _client.Signer.JwsAlg,
                    kid = _client.Account.Kid,
                    url = endpoint,
                    nonce = nonce
                }
                : new
                {
                    jwk = _client.Signer.ExportJwk(), // Must be first property for ZeroSSL compatibility
                    alg = _client.Signer.JwsAlg,
                    url = endpoint,
                    nonce = nonce
                };

            // Serialize and encode components
            var protectedJson = JsonConvert.SerializeObject(protectedHeader, Formatting.None);
            var payloadJson = payload != null ? JsonConvert.SerializeObject(payload, Formatting.None) : "";

            var protectedB64 = CryptoHelper.Base64.UrlEncode(Encoding.UTF8.GetBytes(protectedJson));
            var payloadB64 = CryptoHelper.Base64.UrlEncode(Encoding.UTF8.GetBytes(payloadJson));

            // Create signature over protected header and payload
            var signingInput = $"{protectedB64}.{payloadB64}";
            var signatureB64 = CryptoHelper.Base64.UrlEncode(_client.Signer.Sign(Encoding.UTF8.GetBytes(signingInput)));

            // Construct final JWS
            var jws = new
            {
                @protected = protectedB64,
                payload = payloadB64,
                signature = signatureB64
            };

            var jwsJson = JsonConvert.SerializeObject(jws);
            var content = new StringContent(jwsJson, Encoding.UTF8);
            content.Headers.ContentType = MediaTypeHeaderValue.Parse(JoseContentType);

            return content;
        }

        #endregion

        #region Order Management

        /// <summary>
        /// Creates a new certificate order with optimized request handling.
        /// Supports optional certificate expiration date and robust error handling.
        /// </summary>
        /// <param name="identifiers">Domain identifiers for the certificate</param>
        /// <param name="notAfter">Optional certificate expiration date</param>
        /// <returns>Created order details with status and authorization URLs</returns>
        /// <exception cref="InvalidOperationException">Thrown on order creation failure</exception>
        internal async Task<OrderDetails> CreateOrderAsync(IEnumerable<Identifier> identifiers, DateTime? notAfter = null)
        {
            var identifiersList = identifiers.ToList();
            _log.LogDebug("Creating ACME order for {Count} identifiers", identifiersList.Count);

            var identifiersPayload = identifiersList.Select(i => new { type = i.Type, value = i.Value });

            // Build order payload with optional expiration
            object payload = notAfter.HasValue
                ? new { identifiers = identifiersPayload, notAfter = notAfter.Value.ToString("o") }
                : new { identifiers = identifiersPayload };

            var endpoint = _client.Directory.NewOrder;

            var response = await PostWithNonceRetry(endpoint, async nonce =>
            {
                var content = CreateJwsRequest(endpoint, payload, nonce);
                return await _httpClient.PostAsync(endpoint, content);
            });

            var responseText = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _log.LogError("Order creation failed. Status: {Status}, Response: {Response}",
                    response.StatusCode, responseText);
                throw new InvalidOperationException($"CreateOrder failed: {response.StatusCode} - {responseText}");
            }

            var orderPayload = JsonConvert.DeserializeObject<Order>(responseText);
            var orderDetails = new OrderDetails
            {
                OrderUrl = response.Headers.Location?.ToString(),
                Payload = orderPayload
            };

            _log.LogInformation("Order created successfully with status: {Status}", orderPayload.Status);
            return orderDetails;
        }

        /// <summary>
        /// Finalizes a certificate order by submitting the Certificate Signing Request (CSR).
        /// Automatically waits for order to be ready and polls for completion.
        /// </summary>
        /// <param name="orderDetails">Order details in "ready" status</param>
        /// <param name="csr">DER-encoded Certificate Signing Request</param>
        /// <returns>Updated order details, typically "processing" or "valid" status</returns>
        /// <exception cref="InvalidOperationException">Thrown if order not ready or missing finalize URL</exception>
        internal async Task<OrderDetails> FinalizeOrderAsync(OrderDetails orderDetails, byte[] csr)
        {
            // Ensure order is ready for finalization
            await WaitForOrderStatusAsync(orderDetails, OrderReady);

            if (orderDetails.Payload?.Status != OrderReady)
            {
                _log.LogWarning("Order status is {Status}, expected {Expected}",
                    orderDetails.Payload?.Status, OrderReady);
                return orderDetails;
            }

            var finalizeUrl = orderDetails.Payload.Finalize;
            if (string.IsNullOrEmpty(finalizeUrl))
            {
                throw new InvalidOperationException("Missing finalize URL - order may be corrupted");
            }

            _log.LogDebug("Finalizing order with CSR submission");

            var response = await PostWithNonceRetry(finalizeUrl, async nonce =>
            {
                var payload = new { csr = CryptoHelper.Base64.UrlEncode(csr) };
                var content = CreateJwsRequest(finalizeUrl, payload, nonce);
                return await _httpClient.PostAsync(finalizeUrl, content);
            });

            var responseJson = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _log.LogError("Order finalization failed: {Status} {Body}", response.StatusCode, responseJson);
                throw new InvalidOperationException($"FinalizeOrder failed: {response.StatusCode} - {responseJson}");
            }

            var updatedPayload = JsonConvert.DeserializeObject<Order>(responseJson);
            orderDetails.Payload = updatedPayload;

            // Wait for processing to complete
            await WaitForOrderStatusAsync(orderDetails, OrderProcessing, negate: true);

            _log.LogInformation("Order finalized successfully with status: {Status}", updatedPayload.Status);
            return orderDetails;
        }

        /// <summary>
        /// Retrieves current order details from the ACME server.
        /// Uses POST-as-GET for secure, authenticated requests.
        /// </summary>
        /// <param name="orderUrl">Order URL from order creation response</param>
        /// <returns>Current order details and status</returns>
        /// <exception cref="InvalidOperationException">Thrown on retrieval failure</exception>
        internal async Task<OrderDetails> GetOrderDetailsAsync(string orderUrl)
        {
            var response = await PostWithNonceRetry(orderUrl, async nonce =>
            {
                var content = CreateJwsRequest(orderUrl, payload: null, nonce); // POST-as-GET
                return await _httpClient.PostAsync(orderUrl, content);
            });

            var responseBody = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _log.LogError("Failed to fetch order details: {Code} - {Body}", response.StatusCode, responseBody);
                throw new InvalidOperationException($"Failed to fetch order details: {response.StatusCode} - {responseBody}");
            }

            var payload = JsonConvert.DeserializeObject<Order>(responseBody);
            return new OrderDetails
            {
                OrderUrl = orderUrl,
                Payload = payload
            };
        }

        #endregion

        #region Authorization and Challenge Management

        /// <summary>
        /// Retrieves authorization details for domain validation challenges.
        /// </summary>
        /// <param name="authorizationUrl">Authorization URL from order response</param>
        /// <returns>Authorization containing available challenges</returns>
        /// <exception cref="InvalidOperationException">Thrown on retrieval failure</exception>
        internal async Task<Authorization> GetAuthorizationAsync(string authorizationUrl)
        {
            var response = await PostWithNonceRetry(authorizationUrl, async nonce =>
            {
                var content = CreateJwsRequest(authorizationUrl, payload: null, nonce); // POST-as-GET
                return await _httpClient.PostAsync(authorizationUrl, content);
            });

            var responseJson = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode)
            {
                _log.LogError("Authorization retrieval failed: {Code} {Text}", response.StatusCode, responseJson);
                throw new InvalidOperationException($"GetAuthorizationDetails failed: {response.StatusCode} - {responseJson}");
            }

            return JsonConvert.DeserializeObject<Authorization>(responseJson);
        }

        /// <summary>
        /// Decodes challenge validation requirements for domain verification.
        /// Supports DNS-01, HTTP-01, and other challenge types.
        /// </summary>
        /// <param name="authorization">Authorization containing the challenge</param>
        /// <param name="challenge">Specific challenge to decode</param>
        /// <returns>Validation details (DNS record, HTTP response, etc.)</returns>
        /// <exception cref="NotSupportedException">Thrown for missing or unsupported challenge types</exception>
        internal IChallengeValidationDetails DecodeChallengeValidation(Authorization authorization, Challenge challenge)
        {
            if (string.IsNullOrEmpty(challenge.Type))
            {
                throw new NotSupportedException("Missing challenge type - cannot decode validation requirements");
            }

            _log.LogDebug("Decoding {ChallengeType} challenge validation", challenge.Type);
            return AuthorizationDecoder.DecodeChallengeValidation(authorization, challenge.Type, _client.Signer);
        }

        /// <summary>
        /// Submits challenge response and polls for completion with optimized retry logic.
        /// Implements exponential backoff and proper error handling.
        /// </summary>
        /// <param name="challenge">Challenge to answer</param>
        /// <returns>Final challenge status after completion or timeout</returns>
        /// <exception cref="NotSupportedException">Thrown if challenge URL is missing</exception>
        internal async Task<Challenge> AnswerChallengeAsync(Challenge challenge)
        {
            if (string.IsNullOrEmpty(challenge.Url))
            {
                throw new NotSupportedException("Missing challenge URL - cannot submit response");
            }

            _log.LogDebug("Submitting challenge response to {Url}", challenge.Url);

            // Submit challenge response
            var response = await PostWithNonceRetry(challenge.Url, async nonce =>
            {
                var payload = new { }; // Empty object for challenge response
                var content = CreateJwsRequest(challenge.Url, payload, nonce);
                return await _httpClient.PostAsync(challenge.Url, content);
            });

            var responseJson = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _log.LogError("AnswerChallenge failed: {Code} {Body}", response.StatusCode, responseJson);
                throw new InvalidOperationException($"AnswerChallenge failed: {response.StatusCode} - {responseJson}");
            }

            challenge = JsonConvert.DeserializeObject<Challenge>(responseJson);

            // Poll for challenge completion
            return await PollChallengeStatusAsync(challenge);
        }

        /// <summary>
        /// Polls challenge status until completion or timeout with exponential backoff.
        /// </summary>
        /// <param name="challenge">Challenge to monitor</param>
        /// <returns>Final challenge status</returns>
        private async Task<Challenge> PollChallengeStatusAsync(Challenge challenge)
        {
            var attempts = 0;

            while (IsChallengePending(challenge.Status) && attempts < MaxChallengePollingRetries)
            {
                await Task.Delay(ChallengePollingDelayMs);
                attempts++;

                _log.LogDebug("Polling challenge status (attempt {Attempts}/{MaxRetries})",
                    attempts, MaxChallengePollingRetries);

                try
                {
                    challenge = await GetChallengeDetailsAsync(challenge.Url);
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Error polling challenge status on attempt {Attempts}", attempts);
                    if (attempts >= MaxChallengePollingRetries)
                        throw;
                }
            }

            if (attempts >= MaxChallengePollingRetries)
            {
                _log.LogWarning("Challenge polling exceeded max retries ({MaxRetries})", MaxChallengePollingRetries);
            }

            _log.LogInformation("Challenge completed with status: {Status}", challenge.Status);
            return challenge;
        }

        /// <summary>
        /// Retrieves current challenge status and details.
        /// </summary>
        /// <param name="challengeUrl">Challenge URL for status checking</param>
        /// <returns>Updated challenge details</returns>
        private async Task<Challenge> GetChallengeDetailsAsync(string challengeUrl)
        {
            var response = await PostWithNonceRetry(challengeUrl, async nonce =>
            {
                var content = CreateJwsRequest(challengeUrl, payload: null, nonce); // POST-as-GET
                return await _httpClient.PostAsync(challengeUrl, content);
            });

            var responseJson = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode)
            {
                _log.LogError("GetChallengeDetails failed: {Status} {Body}", response.StatusCode, responseJson);
                throw new InvalidOperationException($"GetChallengeDetails failed: {response.StatusCode} - {responseJson}");
            }

            return JsonConvert.DeserializeObject<Challenge>(responseJson);
        }

        /// <summary>
        /// Determines if a challenge is still pending completion.
        /// </summary>
        private static bool IsChallengePending(string status) =>
            status == AuthorizationPending || status == AuthorizationProcessing;

        #endregion

        #region Certificate Management

        /// <summary>
        /// Downloads the issued certificate from the ACME server.
        /// Returns the complete certificate chain in PEM format.
        /// </summary>
        /// <param name="order">Completed order with certificate URL</param>
        /// <returns>Certificate data as byte array (PEM format)</returns>
        /// <exception cref="InvalidOperationException">Thrown if certificate URL missing or download fails</exception>
        internal async Task<byte[]> GetCertificateAsync(OrderDetails order)
        {
            var certificateUrl = order.Payload?.Certificate;

            if (string.IsNullOrWhiteSpace(certificateUrl))
            {
                throw new InvalidOperationException("Missing certificate URL in order payload");
            }

            _log.LogDebug("Downloading certificate from {Url}", certificateUrl);

            var response = await PostWithNonceRetry(certificateUrl, async nonce =>
            {
                var content = CreateJwsRequest(certificateUrl, payload: null, nonce); // POST-as-GET
                return await _httpClient.PostAsync(certificateUrl, content);
            });

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                _log.LogError("Failed to retrieve certificate. Status: {StatusCode}, Body: {Body}",
                    response.StatusCode, error);
                throw new InvalidOperationException($"Failed to retrieve certificate: {response.StatusCode}");
            }

            var certificateData = await response.Content.ReadAsByteArrayAsync();
            _log.LogInformation("Certificate downloaded successfully ({Size} bytes)", certificateData.Length);

            return certificateData;
        }

        /// <summary>
        /// Revokes a previously issued certificate for security or operational reasons.
        /// </summary>
        /// <param name="certificateBytes">DER-encoded certificate to revoke</param>
        /// <param name="reason">Reason for revocation (default: Unspecified)</param>
        /// <returns>True if revocation successful</returns>
        /// <exception cref="InvalidOperationException">Thrown on revocation failure</exception>
        internal async Task<bool> RevokeCertificateAsync(byte[] certificateBytes, RevokeReason reason = RevokeReason.Unspecified)
        {
            _log.LogInformation("Revoking certificate with reason: {Reason}", reason);

            try
            {
                return await _client.Retry(
                    async () =>
                    {
                        await _client.RevokeCertificateAsync(certificateBytes, reason, CancellationToken.None);
                        return true;
                    },
                    _log
                );
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Certificate revocation failed");
                throw new InvalidOperationException("Certificate revocation failed", ex);
            }
        }

        #endregion

        #region Automatic Renewal Information (ARI) Support

        /// <summary>
        /// Generates ARI-compliant certificate identifier for renewal timing queries.
        /// Combines Authority Key Identifier and serial number per RFC requirements.
        /// </summary>
        /// <param name="certificate">Certificate to generate identifier for</param>
        /// <returns>Base64url-encoded certificate identifier</returns>
        internal static string GetCertificateIdentifier(ICertificateInfo certificate)
        {
            try
            {
                // Extract certificate serial number
                var serialBytes = certificate.Certificate.SerialNumber.ToByteArray();

                // Extract Authority Key Identifier from extensions
                var keyAuth = AuthorityKeyIdentifier.GetInstance(
                    certificate.Certificate.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier).GetOctets());
                var keyAuthBytes = keyAuth.GetKeyIdentifier();

                // Encode using base64url as required by ARI specification
                var serialB64 = Base64UrlEncode(serialBytes);
                var keyAuthB64 = Base64UrlEncode(keyAuthBytes);

                return $"{keyAuthB64}.{serialB64}";
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to generate certificate identifier for ARI", ex);
            }
        }

        /// <summary>
        /// Encodes byte array using base64url encoding per ACME/ARI specifications.
        /// </summary>
        /// <param name="input">Bytes to encode</param>
        /// <returns>Base64url-encoded string</returns>
        private static string Base64UrlEncode(byte[] input) =>
            Convert.ToBase64String(input)
                .TrimEnd('=')           // Remove padding
                .Replace('+', '-')      // Replace + with -
                .Replace('/', '_');     // Replace / with _

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// Waits for order to reach specified status with intelligent retry logic.
        /// Supports both positive matching (wait for status) and negative matching (wait until not status).
        /// </summary>
        /// <param name="orderDetails">Order to monitor</param>
        /// <param name="targetStatus">Status to wait for</param>
        /// <param name="negate">If true, wait until status is NOT the target</param>
        private async Task WaitForOrderStatusAsync(OrderDetails orderDetails, string targetStatus, bool negate = false)
        {
            if (string.IsNullOrEmpty(orderDetails.OrderUrl))
            {
                _log.LogDebug("OrderUrl is null (possibly Buypass CA), using current status only");
                ValidateCurrentOrderStatus(orderDetails, targetStatus, negate);
                return;
            }

            var attempts = 0;
            var operation = negate ? "NOT be" : "become";

            do
            {
                if (attempts > 0)
                {
                    if (attempts > MaxStatusPollingRetries)
                    {
                        _log.LogWarning("Maximum retries ({MaxRetries}) reached waiting for order to {Operation} {Status}",
                            MaxStatusPollingRetries, operation, targetStatus);
                        break;
                    }

                    _log.LogDebug("Waiting for order to {Operation} {Status} (attempt {Attempts}/{MaxRetries})",
                        operation, targetStatus, attempts, MaxStatusPollingRetries);

                    await Task.Delay(StatusPollingDelayMs);

                    try
                    {
                        var updatedOrder = await GetOrderDetailsAsync(orderDetails.OrderUrl);
                        if (updatedOrder?.Payload != null)
                        {
                            orderDetails.Payload = updatedOrder.Payload;
                            _log.LogDebug("Order status updated to: {CurrentStatus}", orderDetails.Payload.Status);
                        }
                    }
                    catch (Exception ex)
                    {
                        _log.LogWarning(ex, "Error updating order details on attempt {Attempts}", attempts);

                        // Fail fast after half the maximum attempts
                        if (attempts >= MaxStatusPollingRetries / 2)
                            throw;
                    }
                }

                attempts++;

                // Validate order state
                if (string.IsNullOrEmpty(orderDetails.Payload?.Status))
                {
                    _log.LogWarning("Order payload or status is null on attempt {Attempts}", attempts);
                    continue;
                }

                // Handle terminal error states
                if (orderDetails.Payload.Status == OrderInvalid)
                {
                    _log.LogError("Order entered invalid state");
                    throw new InvalidOperationException("Order validation failed. Check authorization details and try again.");
                }

                _log.LogDebug("Current order status: {CurrentStatus}, target: {TargetStatus}, negate: {Negate}",
                    orderDetails.Payload.Status, targetStatus, negate);

            } while (ShouldContinuePolling(orderDetails.Payload.Status, targetStatus, negate));

            _log.LogInformation("Order status polling completed. Final status: {FinalStatus}", orderDetails.Payload?.Status);
        }

        /// <summary>
        /// Validates current order status when polling is not possible.
        /// </summary>
        private void ValidateCurrentOrderStatus(OrderDetails orderDetails, string targetStatus, bool negate)
        {
            var currentStatus = orderDetails.Payload?.Status;
            var statusMatches = currentStatus == targetStatus;

            if ((negate && !statusMatches) || (!negate && statusMatches))
            {
                _log.LogDebug("Already in desired state: {CurrentStatus}", currentStatus);
                return;
            }

            _log.LogWarning("Cannot refresh order status and current status ({CurrentStatus}) doesn't match target ({TargetStatus})",
                currentStatus, targetStatus);
        }

        /// <summary>
        /// Determines if status polling should continue based on current and target status.
        /// </summary>
        private static bool ShouldContinuePolling(string currentStatus, string targetStatus, bool negate) =>
            (negate && currentStatus == targetStatus) || (!negate && currentStatus != targetStatus);

        #endregion
    }
}