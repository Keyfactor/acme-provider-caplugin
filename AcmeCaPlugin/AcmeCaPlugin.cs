// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Linq;
using System.Net.Http;
using ACMESharp.Authorizations;
using Keyfactor.Extensions.CAPlugin.Acme.Clients.Acme;
using System.Threading;
using ACMESharp.Protocol.Resources;
using ACMESharp.Protocol;
using System.Text;
using Keyfactor.Extensions.CAPlugin.Acme.Clients.DNS;
using System.Text.RegularExpressions;

namespace Keyfactor.Extensions.CAPlugin.Acme
{
    /// <summary>
    /// HTTP message handler that logs all requests and responses for debugging ACME communication
    /// </summary>
    public class LoggingHandler : DelegatingHandler
    {
        public LoggingHandler(HttpMessageHandler innerHandler) : base(innerHandler) { }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Add consistent user agent for all ACME requests
            request.Headers.UserAgent.TryParseAdd("KeyfactorAcmePlugin/1.0");

            // Log request details for debugging (consider removing in production for security)
            var body = request.Content != null ? await request.Content.ReadAsStringAsync() : "<empty>";
            Console.WriteLine($"REQUEST: {request.Method} {request.RequestUri}");
            Console.WriteLine($"HEADERS: {request.Headers}");
            Console.WriteLine($"BODY: {body}");

            var response = await base.SendAsync(request, cancellationToken);

            // Log response details for debugging
            Console.WriteLine($"RESPONSE: {response.StatusCode}");
            var respContent = await response.Content.ReadAsStringAsync();
            Console.WriteLine($"RESPONSE BODY: {respContent}");

            return response;
        }
    }

    /// <summary>
    /// Keyfactor CA Plugin implementation for ACME (Automatic Certificate Management Environment) protocol
    /// Handles certificate enrollment via ACME-compliant Certificate Authorities like Let's Encrypt
    /// </summary>
    public class AcmeCaPlugin : IAnyCAPlugin
    {
        private static readonly ILogger _logger = LogHandler.GetClassLogger<AcmeCaPlugin>();
        private IAnyCAPluginConfigProvider Config { get; set; }

        // Constants for better maintainability
        private const string DEFAULT_PRODUCT_ID = "default";
        private const string DNS_CHALLENGE_TYPE = "dns-01";
        private const int DNS_PROPAGATION_DELAY_SECONDS = 30;
        private const string USER_AGENT = "KeyfactorAcmePlugin/1.0";

        /// <summary>
        /// Initialize the plugin with configuration and certificate data reader
        /// </summary>
        public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
        {
            _logger.MethodEntry();
            Config = configProvider ?? throw new ArgumentNullException(nameof(configProvider));
            _logger.MethodExit();
        }

        /// <summary>
        /// Health check method - currently no-op for ACME
        /// </summary>
        /// <summary>
        /// Health check method - pings the ACME directory endpoint to verify connectivity
        /// </summary>
        public async Task Ping()
        {
            _logger.MethodEntry();

            HttpClient httpClient = null;
            try
            {
                var config = GetConfig();

                // Create HTTP client for ping operation
                var handler = new HttpClientHandler();
                httpClient = new HttpClient(handler)
                {
                    Timeout = TimeSpan.FromSeconds(30) // Set reasonable timeout for ping
                };
                httpClient.DefaultRequestHeaders.UserAgent.TryParseAdd(USER_AGENT);

                _logger.LogInformation("Pinging ACME directory at: {DirectoryUrl}", config.DirectoryUrl);

                // Attempt to fetch the ACME directory
                var response = await httpClient.GetAsync(config.DirectoryUrl);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();

                    // Verify it's a valid ACME directory by checking for required endpoints
                    if (content.Contains("newAccount") && content.Contains("newOrder"))
                    {
                        _logger.LogInformation("ACME directory ping successful - valid directory response received");
                    }
                    else
                    {
                        _logger.LogWarning("ACME directory responded but may not be a valid ACME directory");
                        throw new InvalidOperationException("Directory response does not contain required ACME endpoints");
                    }
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("ACME directory ping failed with status: {StatusCode}, Content: {Content}",
                        response.StatusCode, errorContent);
                    throw new HttpRequestException($"Directory ping failed: {response.StatusCode} - {response.ReasonPhrase}");
                }
            }
            catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
            {
                _logger.LogError("ACME directory ping timed out");
                throw new TimeoutException("ACME directory ping timed out", ex);
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP error during ACME directory ping");
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during ACME directory ping");
                throw;
            }
            finally
            {
                httpClient?.Dispose();
                _logger.MethodExit();
            }
        }

        /// <summary>
        /// Validates required connection information for ACME CA
        /// </summary>
        public Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
        {
            _logger.MethodEntry();

            if (connectionInfo == null)
                throw new ArgumentNullException(nameof(connectionInfo));

            var rawData = JsonConvert.SerializeObject(connectionInfo);
            var config = JsonConvert.DeserializeObject<AcmeClientConfig>(rawData);

            // Validate required configuration fields
            var missingFields = new List<string>();
            if (string.IsNullOrWhiteSpace(config?.DirectoryUrl))
                missingFields.Add(nameof(AcmeClientConfig.DirectoryUrl));
            if (string.IsNullOrWhiteSpace(config?.Email))
                missingFields.Add(nameof(AcmeClientConfig.Email));

            if (missingFields.Count > 0)
                throw new ArgumentException($"Missing required fields: {string.Join(", ", missingFields)}");

            _logger.MethodExit();
            return Task.CompletedTask;
        }

        /// <summary>
        /// Validates product information - currently no validation needed for ACME
        /// </summary>
        public Task ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
        {
            _logger.MethodEntry();
            _logger.MethodExit();
            return Task.CompletedTask;
        }

        /// <summary>
        /// Returns available product IDs - ACME typically has one default product
        /// </summary>
        public List<string> GetProductIds()
        {
            _logger.MethodEntry();
            _logger.MethodExit();
            return new List<string> { DEFAULT_PRODUCT_ID };
        }

        /// <summary>
        /// Synchronization not supported by ACME protocol as certificates are managed externally
        /// </summary>
        public Task Synchronize(
            System.Collections.Concurrent.BlockingCollection<AnyCAPluginCertificate> blockingBuffer,
            DateTime? lastSync,
            bool fullSync,
            CancellationToken cancelToken)
        {
            _logger.MethodEntry();
            _logger.MethodEntry();
            _logger.LogWarning("Certificate sync is not supported by standard ACME protocol");
            _logger.MethodExit();
            return Task.CompletedTask;
        }



        /// <summary>
        /// Main certificate enrollment method using ACME protocol
        /// </summary>
        public async Task<EnrollmentResult> Enroll(
            string csr,
            string subject,
            Dictionary<string, string[]> san,
            EnrollmentProductInfo productInfo,
            RequestFormat requestFormat,
            EnrollmentType enrollmentType)
        {
            _logger.MethodEntry();

            if (string.IsNullOrWhiteSpace(csr))
                throw new ArgumentException("CSR cannot be null or empty", nameof(csr));
            if (string.IsNullOrWhiteSpace(subject))
                throw new ArgumentException("Subject cannot be null or empty", nameof(subject));

            csr = FormatCsrToSingleLine(csr);

            HttpClient httpClient = null;

            try
            {
                var config = GetConfig();
                var handler = new LoggingHandler(new HttpClientHandler());
                httpClient = new HttpClient(handler);
                httpClient.DefaultRequestHeaders.UserAgent.TryParseAdd(USER_AGENT);

                // Init ACME client
                var clientManager = new AcmeClientManager(_logger, config, httpClient);
                var (protocolClient, accountDetails, signer) = await clientManager.CreateClientAsync();
                var acmeClient = new AcmeClient(_logger, config, httpClient, protocolClient.Directory,
                    new Clients.Acme.Account(accountDetails, signer));

                // Extract domain
                var cleanDomain = ExtractDomainFromSubject(subject);
                var identifiers = new List<Identifier>
        {
            new Identifier { Type = "dns", Value = cleanDomain }
        };

                // Create order
                var order = await acmeClient.CreateOrderAsync(identifiers, null);

                // Store pending order immediately
                var accountId = accountDetails.Kid.Split('/').Last();

                // Process challenges
                await ProcessAuthorizations(acmeClient, order, config);

                // Finalize
                var csrBytes = Convert.FromBase64String(csr);
                order = await acmeClient.FinalizeOrderAsync(order, csrBytes);

                // If order is valid immediately, download cert
                if (order.Payload?.Status == "valid" && !string.IsNullOrEmpty(order.Payload.Certificate))
                {
                    var certBytes = await acmeClient.GetCertificateAsync(order);
                    var certPem = EncodeToPem(certBytes, "CERTIFICATE");

                    return new EnrollmentResult
                    {
                        CARequestID = order.Payload.Finalize,
                        Certificate = certPem,
                        Status = (int)EndEntityStatus.GENERATED
                    };
                }
                else
                {
                    _logger.LogInformation("⏳ Order not valid yet — will be synced later. Status: {Status}", order.Payload?.Status);
                    // Order stays saved for next sync
                    return new EnrollmentResult
                    {
                        CARequestID = order.Payload.Finalize,
                        Status = (int)EndEntityStatus.FAILED,
                        StatusMessage = "Could not retrieve order in allowed time."
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Enrollment failed for subject: {Subject}", subject);
                return new EnrollmentResult
                {
                    Status = (int)EndEntityStatus.FAILED,
                    StatusMessage = ex.Message
                };
            }
            finally
            {
                httpClient?.Dispose();
                _logger.MethodExit();
            }
        }



        /// <summary>
        /// Extracts the domain name from X.509 subject string
        /// </summary>
        /// <param name="subject">Subject string in format "CN=domain.com" or similar</param>
        /// <returns>Clean domain name</returns>
        private static string ExtractDomainFromSubject(string subject)
        {
            if (string.IsNullOrWhiteSpace(subject))
                throw new ArgumentException("Subject cannot be null or empty", nameof(subject));

            // Match CN=value (capturing everything until comma or end of string)
            var match = Regex.Match(subject, @"CN=([^,]+)", RegexOptions.IgnoreCase);
            if (match.Success)
            {
                return match.Groups[1].Value.Trim();
            }

            throw new ArgumentException($"Could not extract CN from subject: {subject}", nameof(subject));
        }

        /// <summary>
        /// Processes ACME authorizations for domain validation
        /// Currently hardcoded to use DNS-01 challenge with Google DNS provider
        /// </summary>
        /// <summary>
        /// Processes ACME authorizations with DNS verification before challenge submission
        /// </summary>
        private async Task ProcessAuthorizations(AcmeClient acmeClient, OrderDetails order, AcmeClientConfig config)
        {
            if (order?.Payload is not Order payload || payload.Authorizations == null)
            {
                throw new InvalidOperationException("Missing or invalid authorization list in order payload.");
            }

            var dnsVerifier = new DnsVerificationHelper(_logger);
            var pendingChallenges = new List<(Authorization authz, Challenge challenge, Dns01ChallengeValidationDetails validation)>();

            // First pass: Create all DNS records
            foreach (var authzUrl in payload.Authorizations)
            {
                var authz = await acmeClient.GetAuthorizationAsync(authzUrl);

                // Skip if authorization is already valid (cached)
                if (authz.Status == "valid")
                {
                    _logger.LogInformation("Using cached authorization for {Domain}", authz.Identifier.Value);
                    continue;
                }

                // Find DNS-01 challenge
                var challenge = authz.Challenges.FirstOrDefault(c => c.Type == DNS_CHALLENGE_TYPE);
                if (challenge == null)
                    throw new InvalidOperationException($"{DNS_CHALLENGE_TYPE} challenge not available");

                // Decode challenge validation details
                var validation = acmeClient.DecodeChallengeValidation(authz, challenge) as Dns01ChallengeValidationDetails;
                if (validation == null)
                    throw new InvalidOperationException($"Failed to decode {DNS_CHALLENGE_TYPE} challenge validation details");

                // Create DNS record
                var dnsProvider = DnsProviderFactory.Create(config, _logger);
                await dnsProvider.CreateRecordAsync(validation.DnsRecordName, validation.DnsRecordValue);

                _logger.LogInformation("Created DNS record {RecordName} for domain {Domain}",
                    validation.DnsRecordName, authz.Identifier.Value);

                pendingChallenges.Add((authz, challenge, validation));
            }

            // Second pass: Wait for DNS propagation and submit challenges
            foreach (var (authz, challenge, validation) in pendingChallenges)
            {
                // Skip external DNS verification for Infoblox since it cannot ping external DNS providers
                bool isInfoblox = config.DnsProvider?.Trim().Equals("infoblox", StringComparison.OrdinalIgnoreCase) ?? false;

                if (isInfoblox)
                {
                    _logger.LogInformation("Skipping external DNS propagation check for Infoblox provider for {Domain}. Adding short delay...", authz.Identifier.Value);
                    // Add a short delay to allow Infoblox to process the record internally
                    await Task.Delay(TimeSpan.FromSeconds(5));
                }
                else
                {
                    _logger.LogInformation("Waiting for DNS propagation for {Domain}...", authz.Identifier.Value);

                    // Wait for DNS propagation with verification
                    var propagated = await dnsVerifier.WaitForDnsPropagationAsync(
                        validation.DnsRecordName,
                        validation.DnsRecordValue,
                        minimumServers: 3 // Require at least 3 DNS servers to confirm
                    );

                    if (!propagated)
                    {
                        _logger.LogWarning("DNS record may not have fully propagated for {Domain}. Proceeding anyway...",
                            authz.Identifier.Value);

                        // Optional: Add a final delay as fallback
                        await Task.Delay(TimeSpan.FromSeconds(30));
                    }
                }

                // Submit challenge response
                _logger.LogInformation("Submitting challenge for {Domain}", authz.Identifier.Value);
                await acmeClient.AnswerChallengeAsync(challenge);
            }
        }

        /// <summary>
        /// Encodes binary data to PEM format with specified label
        /// </summary>
        /// <param name="data">Binary data to encode</param>
        /// <param name="label">PEM label (e.g., "CERTIFICATE")</param>
        /// <returns>PEM formatted string</returns>
        private static string EncodeToPem(byte[] data, string label)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("Data cannot be null or empty", nameof(data));
            if (string.IsNullOrWhiteSpace(label))
                throw new ArgumentException("Label cannot be null or empty", nameof(label));

            var builder = new StringBuilder();
            builder.AppendLine($"-----BEGIN {label}-----");
            builder.AppendLine(Convert.ToBase64String(data, Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine($"-----END {label}-----");
            return builder.ToString();
        }

        /// <summary>
        /// Certificate revocation not supported by standard ACME protocol
        /// </summary>
        public Task<int> Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
        {
            _logger.MethodEntry();
            _logger.LogWarning("Certificate revocation is not supported by standard ACME protocol");
            _logger.MethodExit();
            return Task.FromResult((int)EndEntityStatus.FAILED);
        }

        /// <summary>
        /// Individual certificate record retrieval not supported by standard ACME protocol
        /// </summary>
        public Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
        {
            _logger.MethodEntry();
            _logger.LogWarning("Individual certificate record retrieval is not supported by standard ACME protocol");
            _logger.MethodExit();
            return Task.FromResult(new AnyCAPluginCertificate
            {
                CARequestID = caRequestID,
                Status = (int)EndEntityStatus.FAILED
            });
        }

        /// <summary>
        /// Returns CA connector configuration annotations
        /// </summary>
        public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
        {
            _logger.MethodEntry();
            var annotations = AcmeCaPluginConfig.GetPluginAnnotations();
            _logger.MethodExit();
            return annotations;
        }

        /// <summary>
        /// Returns template parameter annotations - none needed for ACME
        /// </summary>
        public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
        {
            _logger.MethodEntry();
            _logger.MethodExit();
            return new Dictionary<string, PropertyConfigInfo>();
        }

        /// <summary>
        /// Converts a PEM CSR with headers to a compact single-line Base64 CSR.
        /// </summary>
        /// <param name="pemCsr">PEM formatted CSR including BEGIN and END lines.</param>
        /// <returns>Single-line Base64 CSR string.</returns>
        public static string FormatCsrToSingleLine(string pemCsr)
        {
            if (string.IsNullOrWhiteSpace(pemCsr))
                throw new ArgumentException("CSR input is null or empty.", nameof(pemCsr));

            // Remove header/footer and all line breaks
            var cleaned = Regex.Replace(pemCsr,
                "-----BEGIN CERTIFICATE REQUEST-----|-----END CERTIFICATE REQUEST-----|\\s+",
                string.Empty);

            // Decode to binary to validate it's valid base64
            byte[] derBytes = Convert.FromBase64String(cleaned);

            // Re-encode as single-line Base64 (optional: strip padding or line length limits)
            string singleLine = Convert.ToBase64String(derBytes);

            return singleLine;
        }

        /// <summary>
        /// Deserializes configuration from connection data
        /// </summary>
        /// <returns>Typed ACME client configuration</returns>
        private AcmeClientConfig GetConfig()
        {
            if (Config?.CAConnectionData == null)
                throw new InvalidOperationException("CA connection data is not configured");

            var raw = JsonConvert.SerializeObject(Config.CAConnectionData);
            var config = JsonConvert.DeserializeObject<AcmeClientConfig>(raw);

            if (config == null)
                throw new InvalidOperationException("Failed to deserialize ACME client configuration");

            return config;
        }
    }
}