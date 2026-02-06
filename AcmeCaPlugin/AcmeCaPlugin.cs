// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0
using ACMESharp.Authorizations;
using ACMESharp.Protocol;
using ACMESharp.Protocol.Resources;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.Acme.Clients.Acme;
using Keyfactor.Extensions.CAPlugin.Acme.Clients.DNS;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

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
        private readonly IDomainValidatorFactory _validatorFactory;

        // Constants for better maintainability
        private const string DEFAULT_PRODUCT_ID = "default";
        private const string DNS_CHALLENGE_TYPE = "dns-01";
        private const int DNS_PROPAGATION_DELAY_SECONDS = 30;
        private const string USER_AGENT = "KeyfactorAcmePlugin/1.0";

        /// <summary>
        /// Constructor requires domain validator factory for plugin-based DNS providers
        /// </summary>
        /// <param name="validatorFactory">Factory to resolve domain validators from plugins (Required)</param>
        public AcmeCaPlugin(IDomainValidatorFactory validatorFactory)
        {
            _validatorFactory = validatorFactory ?? throw new ArgumentNullException(nameof(validatorFactory),
                "IDomainValidatorFactory is required. DNS providers are now externalized as plugins.");
        }

        /// <summary>
        /// Initialize the plugin with configuration and certificate data reader
        /// </summary>
        public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
        {
            _logger.MethodEntry();
            Config = configProvider ?? throw new ArgumentNullException(nameof(configProvider));

            // Validate that factory is available - validators will be resolved per-domain during enrollment
            if (_validatorFactory == null)
            {
                var errorMsg = "IDomainValidatorFactory is required. DNS providers are now loaded as external plugins. " +
                    "Ensure the Keyfactor platform is configured to inject the factory.";
                _logger.LogError(errorMsg);
                throw new InvalidOperationException(errorMsg);
            }

            _logger.LogInformation("IDomainValidatorFactory available - domain validators will be resolved per-domain during enrollment");

            _logger.MethodExit();
        }

        /// <summary>
        /// Simple implementation of IDomainValidatorConfigProvider to pass configuration to plugins
        /// </summary>
        private class DomainValidatorConfigProvider : IDomainValidatorConfigProvider
        {
            public Dictionary<string, object> DomainValidationConfiguration { get; }

            public DomainValidatorConfigProvider(Dictionary<string, object> config)
            {
                DomainValidationConfiguration = config ?? new Dictionary<string, object>();
            }
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

                // Decode CSR first so we can extract all domains from it
                var csrBytes = Convert.FromBase64String(csr);

                // Extract all domains directly from CSR (CN + SANs) for the ACME order
                // This ensures we authorize exactly what's in the CSR
                var identifiers = ExtractDomainsFromCsr(csrBytes);

                // Create order
                var order = await acmeClient.CreateOrderAsync(identifiers, null);

                _logger.LogInformation("Order created. OrderUrl: {OrderUrl}, Status: {Status}",
                    order.OrderUrl, order.Payload?.Status);

                // Store pending order immediately
                var accountId = accountDetails.Kid.Split('/').Last();

                // Process challenges
                await ProcessAuthorizations(acmeClient, order, config);

                // Finalize with original CSR bytes
                order = await acmeClient.FinalizeOrderAsync(order, csrBytes);

                // Extract order identifier (path only) for database storage
                var orderIdentifier = ExtractOrderIdentifier(order.OrderUrl);

                // If order is valid immediately, download cert
                if (order.Payload?.Status == "valid" && !string.IsNullOrEmpty(order.Payload.Certificate))
                {
                    var certBytes = await acmeClient.GetCertificateAsync(order);
                    var certPem = EncodeToPem(certBytes, "CERTIFICATE");

                    _logger.LogInformation("✅ Enrollment completed successfully. OrderUrl: {OrderUrl}, CARequestID: {OrderId}, Status: GENERATED",
                        order.OrderUrl, orderIdentifier);

                    return new EnrollmentResult
                    {
                        CARequestID = orderIdentifier,
                        Certificate = certPem,
                        Status = (int)EndEntityStatus.GENERATED
                    };
                }
                else
                {
                    _logger.LogInformation("⏳ Order not valid yet — will be synced later. OrderUrl: {OrderUrl}, CARequestID: {OrderId}, Status: {Status}",
                        order.OrderUrl, orderIdentifier, order.Payload?.Status);
                    // Order stays saved for next sync
                    return new EnrollmentResult
                    {
                        CARequestID = orderIdentifier,
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
        /// Extracts the order path from the full ACME order URL for use as a unique identifier.
        /// This removes the scheme, host, and port, keeping only the path portion.
        /// </summary>
        /// <param name="orderUrl">Full order URL (e.g., https://dv.acme-v02.api.pki.goog/order/ABC123)</param>
        /// <returns>Order path without leading slash (e.g., "order/ABC123")</returns>
        /// <example>
        /// Input: "https://dv.acme-v02.api.pki.goog/order/IlYl06mPl5VcAQpx3pzR6w"
        /// Output: "order/IlYl06mPl5VcAQpx3pzR6w"
        /// </example>
        private static string ExtractOrderIdentifier(string orderUrl)
        {
            if (string.IsNullOrWhiteSpace(orderUrl))
                return orderUrl;

            try
            {
                var uri = new Uri(orderUrl);
                // Remove leading slash and return the path
                return uri.AbsolutePath.TrimStart('/');
            }
            catch (Exception)
            {
                // If URL parsing fails, return the original (shouldn't happen with valid ACME URLs)
                return orderUrl;
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
        /// Extracts all DNS names (CN + SANs) directly from the CSR.
        /// This ensures the ACME order authorizes exactly what's in the CSR.
        /// </summary>
        /// <param name="csrBytes">DER-encoded CSR bytes</param>
        /// <returns>List of ACME identifiers for all domains in the CSR</returns>
        private List<Identifier> ExtractDomainsFromCsr(byte[] csrBytes)
        {
            var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                // Parse the CSR using BouncyCastle
                var pkcs10 = new Pkcs10CertificationRequest(csrBytes);
                var csrInfo = pkcs10.GetCertificationRequestInfo();

                // Extract CN from subject
                var subject = csrInfo.Subject;
                var cnValues = subject.GetValueList(X509Name.CN);
                if (cnValues != null && cnValues.Count > 0)
                {
                    var cn = cnValues[0]?.ToString();
                    if (!string.IsNullOrWhiteSpace(cn))
                    {
                        domains.Add(cn);
                        _logger.LogDebug("Extracted CN from CSR: {Domain}", cn);
                    }
                }

                // Extract SANs from CSR attributes
                var attributes = csrInfo.Attributes;
                if (attributes != null)
                {
                    foreach (var attr in attributes)
                    {
                        var attribute = Org.BouncyCastle.Asn1.Pkcs.AttributePkcs.GetInstance(attr);
                        if (attribute.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
                        {
                            // This attribute contains extension requests
                            var extensions = X509Extensions.GetInstance(attribute.AttrValues[0]);
                            var sanExtension = extensions.GetExtension(X509Extensions.SubjectAlternativeName);

                            if (sanExtension != null)
                            {
                                var sanNames = GeneralNames.GetInstance(sanExtension.GetParsedValue());
                                foreach (var name in sanNames.GetNames())
                                {
                                    // TagNo 2 = dNSName
                                    if (name.TagNo == GeneralName.DnsName)
                                    {
                                        var dnsName = name.Name.ToString();
                                        if (!string.IsNullOrWhiteSpace(dnsName))
                                        {
                                            domains.Add(dnsName);
                                            _logger.LogDebug("Extracted SAN from CSR: {Domain}", dnsName);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to parse CSR for domain extraction");
                throw new InvalidOperationException("Failed to parse CSR to extract domains", ex);
            }

            if (domains.Count == 0)
            {
                _logger.LogError("No DNS names found in CSR. CSR may be malformed or missing CN/SANs.");
                throw new InvalidOperationException("No DNS names found in CSR (neither CN nor SANs)");
            }

            var identifiers = domains.Select(d => new Identifier { Type = "dns", Value = d }).ToList();
            _logger.LogInformation("CSR domain extraction complete. Creating ACME order for {Count} domain(s): [{Domains}]",
                identifiers.Count, string.Join(", ", domains));

            return identifiers;
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
            var pendingChallenges = new List<(Authorization authz, Challenge challenge, Dns01ChallengeValidationDetails validation, IDomainValidator validator)>();

            // First pass: Create all DNS records using per-domain IDomainValidator
            foreach (var authzUrl in payload.Authorizations)
            {
                var authz = await acmeClient.GetAuthorizationAsync(authzUrl);

                if (authz.Status == "valid")
                {
                    _logger.LogInformation("Using cached authorization for {Domain}", authz.Identifier.Value);
                    continue;
                }

                var challenge = authz.Challenges.FirstOrDefault(c => c.Type == DNS_CHALLENGE_TYPE);
                if (challenge == null)
                    throw new InvalidOperationException($"{DNS_CHALLENGE_TYPE} challenge not available");

                var validation = acmeClient.DecodeChallengeValidation(authz, challenge) as Dns01ChallengeValidationDetails;
                if (validation == null)
                    throw new InvalidOperationException($"Failed to decode {DNS_CHALLENGE_TYPE} challenge validation details");

                // Resolve domain validator for this specific domain
                var domain = authz.Identifier.Value;
                _logger.LogInformation("Resolving domain validator for domain: {Domain}", domain);

                var domainValidator = _validatorFactory.ResolveDomainValidator(domain, DNS_CHALLENGE_TYPE);
                if (domainValidator == null)
                {
                    throw new InvalidOperationException(
                        $"Failed to resolve domain validator for domain '{domain}'. " +
                        "Ensure the appropriate DNS provider plugin is deployed and configured for this domain's zone.");
                }

                _logger.LogInformation("Using domain validator: {ValidatorType} for domain: {Domain}",
                    domainValidator.GetType().Name, domain);

                // Stage the DNS validation
                var result = await domainValidator.StageValidation(
                    validation.DnsRecordName,
                    validation.DnsRecordValue,
                    CancellationToken.None);

                if (!result.Success)
                    throw new InvalidOperationException($"Failed to stage DNS validation for {domain}: {result.ErrorMessage}");

                _logger.LogInformation("Created DNS record {RecordName} for domain {Domain}",
                    validation.DnsRecordName, domain);

                pendingChallenges.Add((authz, challenge, validation, domainValidator));
            }

            // Wait for initial DNS propagation delay if configured
            if (pendingChallenges.Count > 0 && config.DnsPropagationDelaySeconds > 0)
            {
                _logger.LogInformation("Waiting {DelaySeconds} seconds for DNS propagation before verification (configured delay)...",
                    config.DnsPropagationDelaySeconds);
                await Task.Delay(TimeSpan.FromSeconds(config.DnsPropagationDelaySeconds));
            }

            // Second pass: Verify DNS propagation and submit challenges
            foreach (var (authz, challenge, validation, validator) in pendingChallenges)
            {
                // Skip external DNS verification for private DNS providers
                // Private DNS providers (like RFC2136, Infoblox) typically cannot be queried via public DNS servers
                var validatorTypeName = validator.GetType().Name.ToLowerInvariant();
                bool isPrivateDnsProvider = validatorTypeName.Contains("rfc2136") || validatorTypeName.Contains("infoblox");

                if (isPrivateDnsProvider)
                {
                    _logger.LogInformation("Skipping external DNS propagation check for private DNS provider ({ValidatorType}) for {Domain}. Adding short delay...",
                        validator.GetType().Name, authz.Identifier.Value);
                    // Add a short delay to allow the DNS provider to process the record internally
                    await Task.Delay(TimeSpan.FromSeconds(5));
                }
                else
                {
                    _logger.LogInformation("Waiting for DNS propagation for {Domain}...", authz.Identifier.Value);
                    _logger.LogDebug("Expected DNS record: {RecordName} = {RecordValue}",
                        validation.DnsRecordName, validation.DnsRecordValue);

                    // First, try to get authoritative DNS servers for the domain
                    var baseDomain = authz.Identifier.Value;
                    var authServers = await dnsVerifier.GetAuthoritativeDnsServersAsync(baseDomain);

                    if (authServers.Any())
                    {
                        _logger.LogInformation("Found {Count} authoritative DNS servers for {Domain}: {Servers}",
                            authServers.Count, baseDomain, string.Join(", ", authServers));
                    }
                    else
                    {
                        _logger.LogWarning("Could not find authoritative DNS servers for {Domain}. This may indicate DNS delegation issues.", baseDomain);
                    }

                    // Wait for DNS propagation with verification
                    var propagated = await dnsVerifier.WaitForDnsPropagationAsync(
                        validation.DnsRecordName,
                        validation.DnsRecordValue,
                        minimumServers: 3 // Require at least 3 DNS servers to confirm
                    );

                    if (!propagated)
                    {
                        _logger.LogError("DNS record did not propagate to public DNS servers for {Domain}. " +
                            "Possible causes: 1) Azure DNS zone not properly delegated, 2) NS records not configured, 3) Zone is private not public. " +
                            "Check that your domain registrar has NS records pointing to Azure DNS nameservers.",
                            authz.Identifier.Value);

                        _logger.LogWarning("Adding extra 60s delay before submission, but challenge will likely fail...");

                        // Add a longer delay as fallback for slow DNS providers
                        await Task.Delay(TimeSpan.FromSeconds(60));
                        _logger.LogInformation("Extra delay complete. Proceeding with challenge submission for {Domain}...", authz.Identifier.Value);
                    }
                    else
                    {
                        // Even if verification passed, add a small safety buffer to ensure ACME server's DNS resolvers also have it
                        _logger.LogInformation("DNS propagation verified for {Domain}. Adding 10s safety buffer before challenge submission...", authz.Identifier.Value);
                        await Task.Delay(TimeSpan.FromSeconds(10));
                    }
                }

                // Submit challenge response
                _logger.LogInformation("Submitting challenge for {Domain} with record {RecordName}={RecordValue}",
                    authz.Identifier.Value, validation.DnsRecordName, validation.DnsRecordValue);
                await acmeClient.AnswerChallengeAsync(challenge);

                _logger.LogDebug("Challenge submitted for {Domain}. ACME server will now validate the DNS record.", authz.Identifier.Value);
            }

            // Cleanup: Remove DNS records using the per-domain validators
            foreach (var (authz, challenge, validation, validator) in pendingChallenges)
            {
                try
                {
                    await validator.CleanupValidation(validation.DnsRecordName, CancellationToken.None);
                    _logger.LogInformation("Cleaned up DNS record {RecordName} for domain {Domain}",
                        validation.DnsRecordName, authz.Identifier.Value);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to cleanup DNS record {RecordName} for domain {Domain}",
                        validation.DnsRecordName, authz.Identifier.Value);
                    // Continue cleanup for other domains even if one fails
                }
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