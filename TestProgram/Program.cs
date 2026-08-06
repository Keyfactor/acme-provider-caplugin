using Microsoft.Extensions.Logging;
using Keyfactor.Extensions.CAPlugin.Acme;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using System.Text;
using System.Text.Json;
using System.Collections.Concurrent;

internal class Program
{
    private const string CONFIG_FILE_PATH = "c:\\acme\\config\\acme-config.json";

    public static async Task Main()
    {

        // ================================
        // 📌 === LOAD CONFIGURATION ===
        // ================================
        AcmeConfig config;
        try
        {
            config = await LoadConfigurationAsync(CONFIG_FILE_PATH);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Failed to load configuration: {ex.Message}");
            Console.WriteLine($"Please ensure {CONFIG_FILE_PATH} exists and is properly formatted.");
            return;
        }

        // ================================
        // ✅ Setup logging + plugin
        // ================================
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddSimpleConsole(options =>
            {
                options.SingleLine = true;
                options.TimestampFormat = "[HH:mm:ss] ";
            });
            builder.SetMinimumLevel(LogLevel.Debug);
        });

        ILogger logger = LogHandler.GetClassLogger<AcmeCaPlugin>();
        logger.LogInformation("🚀 Starting secure ACME test client...");

        var selectedAcmeProvider = GetSelectedAcmeProvider(config);
        logger.LogInformation($"📋 Using ACME Provider: {config.AcmeProvider}");
        logger.LogInformation($"🌐 Directory URL: {selectedAcmeProvider.DirectoryUrl}");
        logger.LogInformation($"📧 Email: {selectedAcmeProvider.Email}");
        logger.LogInformation($"🔒 EAB Required: {(!string.IsNullOrEmpty(selectedAcmeProvider.EabKid) ? "Yes" : "No")}");
        logger.LogInformation($"🌍 DNS Provider: {config.DnsProvider}");
        logger.LogInformation($"🏷️  Domain: {config.Domain}");

        // ✅ Convert to flat dictionary for AnyGateway
        var configDict = BuildConfigurationDictionary(config);

        var configProvider = new MockConfigProvider(configDict);
        var plugin = new AcmeCaPlugin();
        plugin.Initialize(configProvider, null);

        if (config.RunEnroll)
        {
            // ================================
            // ✅ Generate CSR dynamically
            // ================================
            string privateKeyPem;
            string csrString = CsrHelper.GenerateCsrBase64(config.Domain, new List<string> { config.Domain }, config.KeySize, out privateKeyPem);

            logger.LogInformation($"Generated CSR (Base64): {csrString[..Math.Min(80, csrString.Length)]}...");
            logger.LogInformation($"Generated Private Key PEM:\n{privateKeyPem[..Math.Min(200, privateKeyPem.Length)]}...");

            var san = new Dictionary<string, string[]>
            {
                { "dns", new[] { config.Domain } }
            };

            // ================================
            // ✅ Run ACME enrollment
            // ================================
            var result = await plugin.Enroll(
                csr: csrString,
                subject: $"CN={config.Domain}",
                san: san,
                productInfo: new EnrollmentProductInfo { ProductID = "default" },
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New
            );

            logger.LogInformation("✅ Enrollment Result:");
            logger.LogInformation($"Status: {(EndEntityStatus)result.Status}");
            logger.LogInformation($"Certificate:\n{(string.IsNullOrEmpty(result.Certificate) ? "None" : result.Certificate[..Math.Min(result.Certificate.Length, 300)] + "...")}");
            logger.LogInformation($"CA Request ID: {result.CARequestID}");

            // ================================
            // ✅ Save outputs to disk
            // ================================
            await File.WriteAllTextAsync($"{config.Domain}_privatekey.pem", privateKeyPem);
            await File.WriteAllTextAsync($"{config.Domain}_certificate.pem", result.Certificate ?? "");

            logger.LogInformation($"✅ Saved private key and certificate: {config.Domain}_*.pem");
        }
        else
        {
            // ================================
            // ✅ Run Synchronize always (or stand-alone)
            // ================================
            using var cancelTokenSource = new CancellationTokenSource();
            var buffer = new BlockingCollection<Keyfactor.AnyGateway.Extensions.AnyCAPluginCertificate>();

            logger.LogInformation("🔄 Running Synchronize to check for pending orders...");

            await plugin.Synchronize(
                buffer,
                lastSync: null,
                fullSync: true,
                cancelToken: cancelTokenSource.Token);

            foreach (var cert in buffer)
            {
                logger.LogInformation($"🔑 Synced Certificate: CARequestID={cert.CARequestID}, Status={(EndEntityStatus)cert.Status}");
                if (!string.IsNullOrWhiteSpace(cert.Certificate))
                {
                    var filename = $"{config.Domain}_synced_certificate.pem";
                    await File.WriteAllTextAsync(filename, cert.Certificate);
                    logger.LogInformation($"✅ Saved synced certificate to: {filename}");
                }
            }

            logger.LogInformation("✅ Synchronize call completed.");
        }
    }

    private static async Task<AcmeConfig> LoadConfigurationAsync(string configPath)
    {
        if (!File.Exists(configPath))
        {
            // Create a sample configuration file
            await CreateSampleConfigAsync(configPath);
            throw new FileNotFoundException($"Configuration file not found. A sample configuration has been created at {configPath}. Please edit it with your actual values.");
        }

        var jsonString = await File.ReadAllTextAsync(configPath);
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            AllowTrailingCommas = true,
            ReadCommentHandling = JsonCommentHandling.Skip
        };

        return JsonSerializer.Deserialize<AcmeConfig>(jsonString, options)
               ?? throw new InvalidOperationException("Failed to deserialize configuration file.");
    }

    private static async Task CreateSampleConfigAsync(string configPath)
    {
        var sampleConfig = new AcmeConfig
        {
            RunEnroll = true,
            Domain = "www.example.com",
            KeySize = 4096,
            AcmeProvider = "LetsEncrypt", // Options: LetsEncrypt, Buypass, ZeroSsl, GoogleCas, Custom
            AcmeProviders = new AcmeProvidersSettings
            {
                LetsEncrypt = new AcmeProviderSettings
                {
                    DirectoryUrl = "https://acme-v02.api.letsencrypt.org/directory",
                    Email = "your-email@example.com",
                    EabKid = null, // Not required for Let's Encrypt
                    EabHmacKey = null, // Not required for Let's Encrypt
                    Description = "Let's Encrypt Production Environment"
                },
                Buypass = new AcmeProviderSettings
                {
                    DirectoryUrl = "https://api.buypass.com/acme/directory",
                    Email = "your-email@example.com",
                    EabKid = "your-buypass-eab-kid",
                    EabHmacKey = "your-buypass-eab-hmac-key",
                    Description = "Buypass ACME CA"
                },
                ZeroSsl = new AcmeProviderSettings
                {
                    DirectoryUrl = "https://acme.zerossl.com/v2/DV90/directory",
                    Email = "your-email@example.com",
                    EabKid = "your-zerossl-eab-kid",
                    EabHmacKey = "your-zerossl-eab-hmac-key",
                    Description = "ZeroSSL ACME CA"
                },
                GoogleCas = new AcmeProviderSettings
                {
                    DirectoryUrl = "https://dv.acme-v02.api.pki.goog/directory",
                    Email = "your-email@example.com",
                    EabKid = "your-google-cas-eab-kid",
                    EabHmacKey = "your-google-cas-eab-hmac-key",
                    Description = "Google Certificate Authority Service"
                },
                Custom = new AcmeProviderSettings
                {
                    DirectoryUrl = "https://your-custom-acme-server.com/directory",
                    Email = "your-email@example.com",
                    EabKid = "your-custom-eab-kid",
                    EabHmacKey = "your-custom-eab-hmac-key",
                    Description = "Custom ACME Provider"
                }
            },
            DnsProvider = "Google", // Options: Google, Cloudflare, AwsRoute53, Azure, Ns1
            DnsProviderSettings = new DnsProviderSettings
            {
                Google = new GoogleDnsSettings
                {
                    ServiceAccountKeyPath = "C:\\path\\to\\service-account.json",
                    ProjectId = "your-project-id"
                },
                Cloudflare = new CloudflareDnsSettings
                {
                    ApiToken = "your-cloudflare-api-token"
                },
                AwsRoute53 = new AwsRoute53Settings
                {
                    AccessKeyId = "your-aws-access-key",
                    SecretAccessKey = "your-aws-secret-key",
                    Region = "us-east-1"
                },
                Azure = new AzureDnsSettings
                {
                    TenantId = "your-tenant-id",
                    ClientId = "your-client-id",
                    SubscriptionId = "your-subscription-id",
                    ClientSecret = "your-client-secret"
                },
                Ns1 = new Ns1DnsSettings
                {
                    ApiKey = "your-ns1-api-key"
                }
            }
        };

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        var jsonString = JsonSerializer.Serialize(sampleConfig, options);
        await File.WriteAllTextAsync(configPath, jsonString);
    }

    private static Dictionary<string, object> BuildConfigurationDictionary(AcmeConfig config)
    {
        // Get the selected ACME provider settings
        var selectedAcmeProvider = GetSelectedAcmeProvider(config);

        var dict = new Dictionary<string, object>
        {
            ["DirectoryUrl"] = selectedAcmeProvider.DirectoryUrl,
            ["Email"] = selectedAcmeProvider.Email,
            ["EabKid"] = selectedAcmeProvider.EabKid ?? "",
            ["EabHmacKey"] = selectedAcmeProvider.EabHmacKey ?? "",
            ["DnsProvider"] = config.DnsProvider,
            ["SignerEncryptionPhrase"] = config.SignerEncryptionPhrase
        };

        // Add DNS provider credentials based on selected provider
        var dns = config.DnsProviderSettings;

        if (dns.Google != null)
        {
            dict["Google_ServiceAccountKeyPath"] = dns.Google.ServiceAccountKeyPath ?? "";
            dict["Google_ProjectId"] = dns.Google.ProjectId ?? "";
        }

        if (dns.Cloudflare != null)
        {
            dict["Cloudflare_ApiToken"] = dns.Cloudflare.ApiToken ?? "";
        }

        if (dns.AwsRoute53 != null)
        {
            dict["AwsRoute53_AccessKey"] = dns.AwsRoute53.AccessKeyId ?? "";
            dict["AwsRoute53_SecretKey"] = dns.AwsRoute53.SecretAccessKey ?? "";
        }

        if (dns.Azure != null)
        {
            dict["Azure_ClientId"] = dns.Azure.ClientId ?? "";
            dict["Azure_TenantId"] = dns.Azure.TenantId ?? "";
            dict["Azure_SubscriptionId"] = dns.Azure.SubscriptionId ?? "";
            dict["Azure_ClientSecret"] = dns.Azure.ClientSecret ?? "";
        }

        if (dns.Ns1 != null)
        {
            dict["Ns1_ApiKey"] = dns.Ns1.ApiKey ?? "";
        }

        return dict;
    }

    private static AcmeProviderSettings GetSelectedAcmeProvider(AcmeConfig config)
    {
        var providers = config.AcmeProviders;

        return config.AcmeProvider.ToLower() switch
        {
            "letsencrypt" => providers.LetsEncrypt ?? throw new InvalidOperationException("Let's Encrypt configuration not found"),
            "buypass" => providers.Buypass ?? throw new InvalidOperationException("Buypass configuration not found"),
            "zerossl" => providers.ZeroSsl ?? throw new InvalidOperationException("ZeroSSL configuration not found"),
            "googlecas" => providers.GoogleCas ?? throw new InvalidOperationException("Google CAS configuration not found"),
            "custom" => providers.Custom ?? throw new InvalidOperationException("Custom ACME provider configuration not found"),
            _ => throw new InvalidOperationException($"Unknown ACME provider: {config.AcmeProvider}")
        };
    }

    // === Configuration Classes ===
    public class AcmeConfig
    {
        public bool RunEnroll { get; set; }
        public string Domain { get; set; } = "";
        public int KeySize { get; set; }
        public string AcmeProvider { get; set; } = "";
        public AcmeProvidersSettings AcmeProviders { get; set; } = new();
        public string DnsProvider { get; set; } = "";
        public DnsProviderSettings DnsProviderSettings { get; set; } = new();
        public string SignerEncryptionPhrase { get; set; } = "";
    }

    public class AcmeProvidersSettings
    {
        public AcmeProviderSettings? LetsEncrypt { get; set; }
        public AcmeProviderSettings? Buypass { get; set; }
        public AcmeProviderSettings? ZeroSsl { get; set; }
        public AcmeProviderSettings? GoogleCas { get; set; }
        public AcmeProviderSettings? Custom { get; set; }
    }

    public class AcmeProviderSettings
    {
        public string DirectoryUrl { get; set; } = "";
        public string Email { get; set; } = "";
        public string? EabKid { get; set; }
        public string? EabHmacKey { get; set; }
        public string? Description { get; set; }
    }

    public class DnsProviderSettings
    {
        public GoogleDnsSettings? Google { get; set; }
        public CloudflareDnsSettings? Cloudflare { get; set; }
        public AwsRoute53Settings? AwsRoute53 { get; set; }
        public AzureDnsSettings? Azure { get; set; }
        public Ns1DnsSettings? Ns1 { get; set; }
    }

    public class GoogleDnsSettings
    {
        public string? ServiceAccountKeyPath { get; set; }
        public string? ProjectId { get; set; }
    }

    public class CloudflareDnsSettings
    {
        public string? ApiToken { get; set; }
    }

    public class AwsRoute53Settings
    {
        public string? AccessKeyId { get; set; }
        public string? SecretAccessKey { get; set; }
        public string Region { get; set; } = "us-east-1";
    }

    public class AzureDnsSettings
    {
        public string? TenantId { get; set; }
        public string? ClientId { get; set; }
        public string? SubscriptionId { get; set; }
        public string? ClientSecret { get; set; }
    }

    public class Ns1DnsSettings
    {
        public string? ApiKey { get; set; }
    }

    // === Local config provider ===
    private class MockConfigProvider : IAnyCAPluginConfigProvider
    {
        public MockConfigProvider(Dictionary<string, object> config) =>
            CAConnectionData = config;

        public Dictionary<string, object> CAConnectionData { get; }
        public Dictionary<string, object> CertificateAuthorityData => new();
        public Dictionary<string, object> Metadata => new();
    }

    // === CSR helper ===
    public static class CsrHelper
    {
        public static string GenerateCsrBase64(string domainName, List<string> sanNames, int keySize, out string privateKeyPem)
        {
            var keyPairGenerator = new Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator();
            keyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), keySize));
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

            var subject = new X509Name($"CN={domainName}");

            var sanBuilder = new GeneralNames(
                sanNames.ConvertAll(name => new GeneralName(GeneralName.DnsName, name)).ToArray()
            );
            var extensionsGenerator = new X509ExtensionsGenerator();
            extensionsGenerator.AddExtension(
                X509Extensions.SubjectAlternativeName,
                false,
                sanBuilder
            );
            var extensions = extensionsGenerator.Generate();
            var attrSet = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions));

            var csr = new Pkcs10CertificationRequest(
                "SHA256WITHRSA",
                subject,
                keyPair.Public,
                new DerSet(attrSet),
                keyPair.Private
            );

            byte[] csrDer = csr.GetDerEncoded();
            string csrBase64 = Convert.ToBase64String(csrDer);

            StringBuilder sb = new StringBuilder();
            using (var writer = new StringWriter(sb))
            {
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(keyPair.Private);
                pemWriter.Writer.Flush();
                privateKeyPem = sb.ToString();
            }

            return csrBase64;
        }
    }
}