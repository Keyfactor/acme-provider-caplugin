using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.Acme.Clients.DNS;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.Acme
{
    public class Dns01DomainValidator : IDomainValidator
    {
        private static readonly ILogger _logger = LogHandler.GetClassLogger<Dns01DomainValidator>();
        private AcmeClientConfig _config;
        private IDnsProvider _dnsProvider;

        public void Initialize(IDomainValidatorConfigProvider configProvider)
        {
            if (configProvider?.DomainValidationConfiguration == null)
                throw new ArgumentNullException(nameof(configProvider));

            var raw = JsonConvert.SerializeObject(configProvider.DomainValidationConfiguration);
            _config = JsonConvert.DeserializeObject<AcmeClientConfig>(raw);

            // Create the DNS provider using your existing factory
            _dnsProvider = DnsProviderFactory.Create(_config, _logger);

            _logger.LogInformation("Dns01DomainValidator initialized with provider: {Provider}",
                _config.DnsProvider ?? "default");
        }

        public async Task<DomainValidationResult> StageValidation(string key, string value, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Staging DNS-01 validation: {Key} -> {Value}", key, value);

            try
            {
                var success = await _dnsProvider.CreateRecordAsync(key, value);

                return new DomainValidationResult
                {
                    Success = success,
                    ErrorMessage = success ? null : $"Failed to create DNS TXT record for {key}"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to stage DNS validation for {Key}", key);
                return new DomainValidationResult
                {
                    Success = false,
                    ErrorMessage = ex.Message
                };
            }
        }

        public async Task<DomainValidationResult> CleanupValidation(string key, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Cleaning up DNS-01 validation: {Key}", key);

            try
            {
                // Use the overload without value if available, or pass empty string
                var success = await _dnsProvider.DeleteRecordAsync(key);

                return new DomainValidationResult
                {
                    Success = success,
                    ErrorMessage = success ? null : $"Failed to delete DNS TXT record for {key}"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cleanup DNS validation for {Key}", key);
                return new DomainValidationResult
                {
                    Success = false,
                    ErrorMessage = ex.Message
                };
            }
        }

        public Task ValidateConfiguration(Dictionary<string, object> configuration)
        {
            // Reuse existing validation logic or add specific checks
            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration));

            return Task.CompletedTask;
        }

        public Dictionary<string, PropertyConfigInfo> GetDomainValidatorAnnotations()
        {
            // Return DNS-related annotations from your existing config
            // Or return a subset specific to domain validation
            return AcmeCaPluginConfig.GetPluginAnnotations();
        }

        public string GetValidationType() => "dns-01";
    }
}