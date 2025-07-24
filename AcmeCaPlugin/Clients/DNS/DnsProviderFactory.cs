using Microsoft.Extensions.Logging;
using System;

namespace Keyfactor.Extensions.CAPlugin.Acme
{
    public static class DnsProviderFactory
    {
        public static IDnsProvider Create(AcmeClientConfig config, ILogger logger)
        {
            if (config == null || string.IsNullOrWhiteSpace(config.DnsProvider))
                throw new ArgumentException("DNS provider type is missing in config.");

            switch (config.DnsProvider.Trim().ToLowerInvariant())
            {
                case "google":
                    return new GoogleDnsProvider(
                        config.Google_ServiceAccountKeyPath,
                        config.Google_ProjectId
                    );

                case "cloudflare":
                    return new CloudflareDnsProvider(
                        config.Cloudflare_ApiToken
                    );

                case "azure":
                    return new AzureDnsProvider(
                        config.Azure_TenantId,
                        config.Azure_ClientId,
                        config.Azure_ClientSecret,
                        config.Azure_SubscriptionId
                    );
                case "awsroute53":
                    return new AwsRoute53DnsProvider(
                        config.AwsRoute53_AccessKey,
                        config.AwsRoute53_SecretKey
                    );
                case "ns1":
                    return new Ns1DnsProvider(
                        config.Ns1_ApiKey
                    );
                default:
                    throw new NotSupportedException($"DNS provider '{config.DnsProvider}' is not supported.");
            }
        }
    }
}
