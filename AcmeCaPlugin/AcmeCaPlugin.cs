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
using System.Security.Cryptography;
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
        private AcmeClientConfig _config;

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

            _config = GetConfig();
            _logger.LogTrace("Enabled: {Enabled}", _config.Enabled);

            if (!_config.Enabled)
            {
                _logger.LogWarning("The CA is currently in the Disabled state. It must be Enabled to perform operations. Skipping config validation...");
                _logger.MethodExit();
                return;
            }

            // Validate that factory is available - validators will be resolved per-domain during enrollment
            if (_validatorFactory == null)
            {
                var errorMsg = "IDomainValidatorFactory is required. DNS providers are now loaded as external plugins. " +
                    "Ensure the Keyfactor platform is configured to inject the factory.";
                _logger.LogError(errorMsg);
                throw new InvalidOperationException(errorMsg);
            }

            ValidateConfigForEnrollment(_config);

            _logger.LogInformation("IDomainValidatorFactory available - domain validators will be resolved per-domain during enrollment");

            _logger.MethodExit();
        }

        /// <summary>
        /// Fail-fast configuration sanity checks that run at Initialize time (when the connector is Enabled)
        /// so operators see problems during save instead of on first enrollment attempt.
        /// </summary>
        private static void ValidateConfigForEnrollment(AcmeClientConfig config)
        {
            var problems = new List<string>();

            if (string.IsNullOrWhiteSpace(config.DirectoryUrl))
            {
                problems.Add($"{nameof(AcmeClientConfig.DirectoryUrl)} is required.");
            }
            else if (!Uri.TryCreate(config.DirectoryUrl, UriKind.Absolute, out var uri) ||
                     (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            {
                problems.Add($"{nameof(AcmeClientConfig.DirectoryUrl)} must be an absolute http(s) URL (got '{config.DirectoryUrl}').");
            }

            if (string.IsNullOrWhiteSpace(config.Email))
            {
                problems.Add($"{nameof(AcmeClientConfig.Email)} is required for ACME account registration.");
            }

            // EAB credentials must be supplied as a pair (or not at all)
            var hasKid = !string.IsNullOrWhiteSpace(config.EabKid);
            var hasHmac = !string.IsNullOrWhiteSpace(config.EabHmacKey);
            if (hasKid != hasHmac)
            {
                problems.Add($"{nameof(AcmeClientConfig.EabKid)} and {nameof(AcmeClientConfig.EabHmacKey)} must both be provided together, or neither.");
            }

            if (config.DnsPropagationDelaySeconds < 0)
            {
                problems.Add($"{nameof(AcmeClientConfig.DnsPropagationDelaySeconds)} must be >= 0 (got {config.DnsPropagationDelaySeconds}).");
            }

            if (problems.Count > 0)
            {
                var joined = string.Join(" ", problems);
                _logger.LogError("Configuration validation failed: {Problems}", joined);
                throw new ArgumentException($"ACME CA connector configuration is invalid: {joined}");
            }
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
            if (!_config.Enabled)
            {
                _logger.LogWarning("The CA is currently in the Disabled state. It must be Enabled to perform operations. Skipping connectivity test...");
                _logger.MethodExit();
                return;
            }

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

            if (config != null && !config.Enabled)
            {
                _logger.LogWarning("The CA is currently in the Disabled state. It must be Enabled to perform operations. Skipping config validation...");
                _logger.MethodExit();
                return Task.CompletedTask;
            }

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

            using var flow = new FlowLogger(_logger, $"Enroll:{subject ?? "<null-subject>"}");
            HttpClient httpClient = null;
            string orderIdentifier = null;

            try
            {
                if (!_config.Enabled)
                {
                    flow.Fail("EnabledCheck", "CA connector is disabled");
                    _logger.LogWarning("The CA is currently in the Disabled state. It must be Enabled to perform operations. Enrollment rejected.");
                    return new EnrollmentResult
                    {
                        Status = (int)EndEntityStatus.FAILED,
                        StatusMessage = $"CA connector is disabled. Enable it in the CA configuration to perform enrollments.\n\n{flow.GetSummary()}"
                    };
                }

                flow.Step("ValidateInput", () =>
                {
                    if (string.IsNullOrWhiteSpace(csr))
                        throw new ArgumentException("CSR cannot be null or empty", nameof(csr));
                    if (string.IsNullOrWhiteSpace(subject))
                        throw new ArgumentException("Subject cannot be null or empty", nameof(subject));
                }, detail: subject);

                csr = flow.Step("FormatCsr", () => FormatCsrToSingleLine(csr));

                var config = flow.Step("LoadConfig", () => GetConfig(), detail: _config.DirectoryUrl);

                httpClient = flow.Step("CreateHttpClient", () =>
                {
                    var handler = new LoggingHandler(new HttpClientHandler());
                    var c = new HttpClient(handler);
                    c.DefaultRequestHeaders.UserAgent.TryParseAdd(USER_AGENT);
                    return c;
                });

                var (protocolClient, accountDetails, signer) = await flow.StepAsync("InitAcmeAccount",
                    async () =>
                    {
                        var clientManager = new AcmeClientManager(_logger, config, httpClient);
                        return await clientManager.CreateClientAsync();
                    },
                    detail: config.DirectoryUrl);

                var acmeClient = flow.Step("CreateAcmeClient", () => new AcmeClient(_logger, config, httpClient, protocolClient.Directory,
                    new Clients.Acme.Account(accountDetails, signer)));

                var csrBytes = flow.Step("DecodeCsr", () => Convert.FromBase64String(csr));

                var identifiers = flow.Step("ExtractDomainsFromCsr", () => ExtractDomainsFromCsr(csrBytes),
                    detail: $"will be populated per-step");

                var order = await flow.StepAsync("CreateOrder",
                    async () => await acmeClient.CreateOrderAsync(identifiers, null),
                    detail: $"{identifiers.Count} identifier(s)");

                _logger.LogInformation("Order created. OrderUrl: {OrderUrl}, Status: {Status}",
                    order.OrderUrl, order.Payload?.Status);

                orderIdentifier = flow.Step("ExtractOrderIdentifier", () => ExtractOrderIdentifier(order.OrderUrl));

                await ProcessAuthorizations(acmeClient, order, config, flow);

                order = await flow.StepAsync("FinalizeOrder",
                    async () => await acmeClient.FinalizeOrderAsync(order, csrBytes),
                    detail: order.OrderUrl);

                if (order.Payload?.Status == "valid" && !string.IsNullOrEmpty(order.Payload.Certificate))
                {
                    var certBytes = await flow.StepAsync("DownloadCertificate",
                        async () => await acmeClient.GetCertificateAsync(order));

                    var certPem = flow.Step("EncodeCertificateToPem", () => EncodeToPem(certBytes, "CERTIFICATE"),
                        detail: $"{certBytes?.Length ?? 0} bytes");

                    _logger.LogInformation("✅ Enrollment completed successfully. OrderUrl: {OrderUrl}, CARequestID: {OrderId}, Status: GENERATED",
                        order.OrderUrl, orderIdentifier);

                    return new EnrollmentResult
                    {
                        CARequestID = orderIdentifier,
                        Certificate = certPem,
                        Status = (int)EndEntityStatus.GENERATED,
                        StatusMessage = $"Enrollment completed successfully for {subject}.\n\n{flow.GetSummary()}"
                    };
                }
                else
                {
                    flow.Fail("CertificateNotReady", $"Order status: {order.Payload?.Status ?? "unknown"}");
                    _logger.LogInformation("⏳ Order not valid yet — will be synced later. OrderUrl: {OrderUrl}, CARequestID: {OrderId}, Status: {Status}",
                        order.OrderUrl, orderIdentifier, order.Payload?.Status);
                    return new EnrollmentResult
                    {
                        CARequestID = orderIdentifier,
                        Status = (int)EndEntityStatus.FAILED,
                        StatusMessage = $"Could not retrieve order in allowed time (order status: {order.Payload?.Status ?? "unknown"}).\n\n{flow.GetSummary()}"
                    };
                }
            }
            catch (Exception ex)
            {
                var detail = DescribeException(ex);
                _logger.LogError(ex, "❌ Enrollment failed for subject: {Subject}", subject);
                return new EnrollmentResult
                {
                    CARequestID = orderIdentifier,
                    Status = (int)EndEntityStatus.FAILED,
                    StatusMessage = $"Enrollment failed: {detail}\n\n{flow.GetSummary()}"
                };
            }
            finally
            {
                httpClient?.Dispose();
                _logger.MethodExit();
            }
        }

        /// <summary>
        /// Unwraps aggregate/inner exceptions and produces a concise, operator-friendly description.
        /// Prefers the innermost meaningful message; surfaces HTTP status where present; trims long bodies.
        /// </summary>
        internal static string DescribeException(Exception ex)
        {
            if (ex == null) return "Unknown error";

            // Walk through AggregateException layers
            while (ex is AggregateException agg && agg.InnerExceptions.Count == 1)
            {
                ex = agg.InnerExceptions[0];
            }
            if (ex is AggregateException aggMulti)
            {
                var inners = aggMulti.InnerExceptions.Select(e => DescribeException(e));
                return "Multiple errors: " + string.Join(" | ", inners);
            }

            // Walk through TargetInvocationException / wrappers that only carry an inner
            while (ex.InnerException != null && (
                ex is System.Reflection.TargetInvocationException ||
                ex.GetType() == typeof(Exception)))
            {
                ex = ex.InnerException;
            }

            var message = ex.Message ?? ex.GetType().Name;

            // Attach HTTP status/body context if this is an HttpRequestException (or wraps one)
            var http = ex as HttpRequestException ?? ex.InnerException as HttpRequestException;
            if (http != null)
            {
                var httpMsg = http.Message ?? "";
                if (!ReferenceEquals(http, ex))
                    message = $"{message} [{httpMsg}]";
            }

            // Trim anything excessively long so the breadcrumb summary stays readable
            const int maxLen = 400;
            if (message.Length > maxLen)
                message = message.Substring(0, maxLen) + "…";

            return $"{ex.GetType().Name}: {message}";
        }



        /// <summary>
        /// Generates a fixed-length SHA256 hash of the ACME order URL for database storage.
        /// Produces a consistent 40-char hex string regardless of URL length or ACME CA format.
        /// The full order URL is logged separately during enrollment for traceability.
        /// </summary>
        private static string ExtractOrderIdentifier(string orderUrl)
        {
            if (string.IsNullOrWhiteSpace(orderUrl))
                return orderUrl;

            using (var sha256 = SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(orderUrl));
                // Take first 20 bytes (40 hex chars) — fits in DB column and is collision-safe
                var sb = new StringBuilder(40);
                for (int i = 0; i < 20; i++)
                {
                    sb.Append(hashBytes[i].ToString("x2"));
                }
                return sb.ToString();
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
        private async Task ProcessAuthorizations(AcmeClient acmeClient, OrderDetails order, AcmeClientConfig config, FlowLogger flow)
        {
            if (order?.Payload is not Order payload || payload.Authorizations == null)
            {
                throw new InvalidOperationException("Missing or invalid authorization list in order payload.");
            }

            var dnsVerifier = new DnsVerificationHelper(_logger, config.DnsVerificationServer);
            var pendingChallenges = new List<(Authorization authz, Challenge challenge, Dns01ChallengeValidationDetails validation, IDomainValidator validator)>();

            flow.Branch("StageDnsRecords");
            try
            {
                foreach (var authzUrl in payload.Authorizations)
                {
                    var authz = await acmeClient.GetAuthorizationAsync(authzUrl);
                    var domain = authz.Identifier.Value;

                    if (authz.Status == "valid")
                    {
                        flow.Skip($"Stage:{domain}", "authorization already valid (cached)");
                        _logger.LogInformation("Using cached authorization for {Domain}", domain);
                        continue;
                    }

                    var challenge = authz.Challenges.FirstOrDefault(c => c.Type == DNS_CHALLENGE_TYPE);
                    if (challenge == null)
                    {
                        flow.Fail($"Stage:{domain}", $"{DNS_CHALLENGE_TYPE} challenge not available");
                        throw new InvalidOperationException($"{DNS_CHALLENGE_TYPE} challenge not available for {domain}");
                    }

                    var validation = acmeClient.DecodeChallengeValidation(authz, challenge) as Dns01ChallengeValidationDetails;
                    if (validation == null)
                    {
                        flow.Fail($"Stage:{domain}", $"failed to decode {DNS_CHALLENGE_TYPE} challenge");
                        throw new InvalidOperationException($"Failed to decode {DNS_CHALLENGE_TYPE} challenge validation details for {domain}");
                    }

                    var domainValidator = flow.Step($"ResolveValidator:{domain}",
                        () =>
                        {
                            var v = _validatorFactory.ResolveDomainValidator(domain, DNS_CHALLENGE_TYPE);
                            if (v == null)
                            {
                                throw new InvalidOperationException(
                                    $"Failed to resolve domain validator for domain '{domain}'. " +
                                    "Ensure the appropriate DNS provider plugin is deployed and configured for this domain's zone.");
                            }
                            return v;
                        });

                    _logger.LogInformation("Using domain validator: {ValidatorType} for domain: {Domain}",
                        domainValidator.GetType().Name, domain);

                    await flow.StepAsync($"StageValidation:{domain}",
                        async () =>
                        {
                            var result = await domainValidator.StageValidation(
                                validation.DnsRecordName,
                                validation.DnsRecordValue,
                                CancellationToken.None);

                            if (!result.Success)
                                throw new InvalidOperationException($"Failed to stage DNS validation for {domain}: {result.ErrorMessage}");
                        },
                        detail: $"{validation.DnsRecordName} via {domainValidator.GetType().Name}");

                    pendingChallenges.Add((authz, challenge, validation, domainValidator));
                }
            }
            finally
            {
                flow.EndBranch();
            }

            if (pendingChallenges.Count > 0 && config.DnsPropagationDelaySeconds > 0)
            {
                await flow.StepAsync("InitialPropagationDelay",
                    async () => await Task.Delay(TimeSpan.FromSeconds(config.DnsPropagationDelaySeconds)),
                    detail: $"{config.DnsPropagationDelaySeconds}s");
            }

            flow.Branch("VerifyAndSubmit");
            try
            {
                foreach (var (authz, challenge, validation, validator) in pendingChallenges)
                {
                    var domain = authz.Identifier.Value;
                    var validatorTypeName = validator.GetType().Name.ToLowerInvariant();
                    bool isPrivateDnsProvider = validatorTypeName.Contains("rfc2136") || validatorTypeName.Contains("infoblox");

                    if (isPrivateDnsProvider)
                    {
                        await flow.StepAsync($"PrivateDnsSettle:{domain}",
                            async () => await Task.Delay(TimeSpan.FromSeconds(5)),
                            detail: $"{validator.GetType().Name} - skipping public DNS check");
                    }
                    else
                    {
                        var authServers = await flow.StepAsync($"GetAuthoritativeDns:{domain}",
                            async () => await dnsVerifier.GetAuthoritativeDnsServersAsync(domain));

                        if (!authServers.Any())
                        {
                            _logger.LogWarning("Could not find authoritative DNS servers for {Domain}. This may indicate DNS delegation issues.", domain);
                        }

                        var propagated = await flow.StepAsync($"AwaitDnsPropagation:{domain}",
                            async () => await dnsVerifier.WaitForDnsPropagationAsync(
                                validation.DnsRecordName,
                                validation.DnsRecordValue,
                                minimumServers: 3),
                            detail: $"{validation.DnsRecordName} across {authServers.Count} authoritative server(s)");

                        if (!propagated)
                        {
                            _logger.LogError("DNS record did not propagate to public DNS servers for {Domain}. " +
                                "Possible causes: 1) DNS zone not properly delegated, 2) NS records not configured, 3) Zone is private not public. " +
                                "Check that your domain registrar has NS records pointing to your authoritative nameservers.", domain);

                            await flow.StepAsync($"FallbackDelay:{domain}",
                                async () => await Task.Delay(TimeSpan.FromSeconds(60)),
                                detail: "propagation not verified - 60s fallback; challenge will likely fail");
                        }
                        else
                        {
                            await flow.StepAsync($"PropagationSafetyBuffer:{domain}",
                                async () => await Task.Delay(TimeSpan.FromSeconds(10)),
                                detail: "10s buffer for ACME resolvers");
                        }
                    }

                    await flow.StepAsync($"SubmitChallenge:{domain}",
                        async () => await acmeClient.AnswerChallengeAsync(challenge),
                        detail: $"{validation.DnsRecordName}={validation.DnsRecordValue}");
                }
            }
            finally
            {
                flow.EndBranch();
            }

            flow.Branch("CleanupDnsRecords");
            try
            {
                foreach (var (authz, challenge, validation, validator) in pendingChallenges)
                {
                    var domain = authz.Identifier.Value;
                    try
                    {
                        await validator.CleanupValidation(validation.DnsRecordName, CancellationToken.None);
                        flow.Step($"Cleanup:{domain}", detail: validation.DnsRecordName);
                        _logger.LogInformation("Cleaned up DNS record {RecordName} for domain {Domain}",
                            validation.DnsRecordName, domain);
                    }
                    catch (Exception ex)
                    {
                        flow.Fail($"Cleanup:{domain}", DescribeException(ex));
                        _logger.LogWarning(ex, "Failed to cleanup DNS record {RecordName} for domain {Domain}",
                            validation.DnsRecordName, domain);
                        // Continue cleanup for other domains even if one fails
                    }
                }
            }
            finally
            {
                flow.EndBranch();
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