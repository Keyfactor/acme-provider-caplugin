using Keyfactor.AnyGateway.Extensions;
using System.Collections.Generic;

namespace Keyfactor.Extensions.CAPlugin.Acme
{
    public class AcmeCaPluginConfig
    {
        public static Dictionary<string, PropertyConfigInfo> GetPluginAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>()
            {
                ["DirectoryUrl"] = new PropertyConfigInfo()
                {
                    Comments = "ACME directory URL (e.g. Let's Encrypt, ZeroSSL, etc.)",
                    Hidden = false,
                    DefaultValue = "https://acme-v02.api.letsencrypt.org/directory",
                    Type = "String"
                },
                ["Email"] = new PropertyConfigInfo()
                {
                    Comments = "Email for ACME account registration.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["EabKid"] = new PropertyConfigInfo()
                {
                    Comments = "External Account Binding Key ID (optional)",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["EabHmacKey"] = new PropertyConfigInfo()
                {
                    Comments = "External Account Binding HMAC key (optional)",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "Secret"
                },
                ["SignerEncryptionPhrase"] = new PropertyConfigInfo()
                {
                    Comments = "Used to encrypt singer information when account is saved to disk (optional)",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "Secret"
                },
                ["DnsProvider"] = new PropertyConfigInfo()
                {
                    Comments = "DNS Provider to use for ACME DNS-01 challenges (options Google, Cloudflare, AwsRoute53, Azure, Ns1, Infoblox)",
                    Hidden = false,
                    DefaultValue = "Google",
                    Type = "String"
                },

                // Google DNS
                ["Google_ServiceAccountKeyPath"] = new PropertyConfigInfo()
                {
                    Comments = "Google Cloud DNS: Path to service account JSON key file only if using Google DNS (Optional)",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Google_ProjectId"] = new PropertyConfigInfo()
                {
                    Comments = "Google Cloud DNS: Project ID only if using Google DNS (Optional)",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },

                // Cloudflare DNS
                ["Cloudflare_ApiToken"] = new PropertyConfigInfo()
                {
                    Comments = "Cloudflare DNS: API Token only if using Cloudflare DNS (Optional)",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "Secret"
                },

                // Azure DNS
                ["Azure_ClientId"] = new PropertyConfigInfo()
                {
                    Comments = "Azure DNS: ClientId only if using Azure DNS and Not Managed Itentity in Azure (Optional)",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "Secret"
                },
                ["Azure_ClientSecret"] = new PropertyConfigInfo()
                {
                    Comments = "Azure DNS: ClientSecret only if using Azure DNS and Not Managed Itentity in Azure (Optional)",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "Secret"
                },
                ["Azure_SubscriptionId"] = new PropertyConfigInfo()
                {
                    Comments = "Azure DNS: SubscriptionId only if using Azure DNS and Not Managed Itentity in Azure (Optional)",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Azure_TenantId"] = new PropertyConfigInfo()
                {
                    Comments = "Azure DNS: TenantId only if using Azure DNS and Not Managed Itentity in Azure (Optional)",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["AwsRoute53_AccessKey"] = new PropertyConfigInfo()
                {
                    Comments = "Aws DNS: Access Key only if not using AWS DNS and default AWS Chain Creds on AWS (Optional)",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["AwsRoute53_SecretKey"] = new PropertyConfigInfo()
                {
                    Comments = "Aws DNS: Secret Key only if using AWS DNS and not using default AWS Chain Creds on AWS (Optional)",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "Secret"
                }
                //IBM NS1 DNS
                ,
                ["Ns1_ApiKey"] = new PropertyConfigInfo()
                {
                    Comments = "Ns1 DNS: Api Key only if Using Ns1 DNS (Optional)",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "String"
                }

                //Infoblox DNS
                ,
                ["Infoblox_Host"] = new PropertyConfigInfo()
                {
                    Comments = "Infoblox DNS: API URL (e.g., https://infoblox.example.com/wapi/v2.12) only if using Infoblox DNS (Optional)",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Infoblox_Username"] = new PropertyConfigInfo()
                {
                    Comments = "Infoblox DNS: Username for authentication only if using Infoblox DNS (Optional)",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Infoblox_Password"] = new PropertyConfigInfo()
                {
                    Comments = "Infoblox DNS: Password for authentication only if using Infoblox DNS (Optional)",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "Secret"
                }

            };
        }

        public static Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>();
        }
    }
}
