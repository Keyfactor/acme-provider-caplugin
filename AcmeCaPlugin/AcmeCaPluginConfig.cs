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
                // Container Deployment
                ["AccountStoragePath"] = new PropertyConfigInfo()
                {
                    Comments = "Path for ACME account storage. Defaults to %APPDATA%\\AcmeAccounts on Windows or ./AcmeAccounts in containers.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },

                // DNS Propagation Settings
                ["DnsPropagationDelaySeconds"] = new PropertyConfigInfo()
                {
                    Comments = "Time in seconds to wait after creating DNS records before checking propagation. Set to 0 to skip the delay.",
                    Hidden = false,
                    DefaultValue = "60",
                    Type = "Number"
                }

            };
        }

        public static Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>();
        }
    }
}
