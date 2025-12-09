using Amazon;

namespace Keyfactor.Extensions.CAPlugin.Acme
{
    public class AcmeClientConfig
    {
        public string DirectoryUrl { get; set; } = "https://acme-v02.api.letsencrypt.org/directory";
        public string Email { get; set; } = string.Empty;
        public string EabKid { get; set; } = null;
        public string EabHmacKey { get; set; } = null;
        public string SignerEncryptionPhrase{ get; set; } = null;

        // Chosen DNS Provider
        public string DnsProvider { get; set; } = null;

        // Google Cloud DNS
        public string Google_ServiceAccountKeyPath { get; set; } = null;
        public string Google_ProjectId { get; set; } = null;

        // Cloudflare DNS
        public string Cloudflare_ApiToken { get; set; } = null;


        // Azure DNS
        public string Azure_ClientId { get; set; } = null;
        public string Azure_ClientSecret { get; set; } = null;
        public string Azure_SubscriptionId { get; set; } = null;
        public string Azure_TenantId { get; set; } = null;

        // AWS Route53 
        public string AwsRoute53_AccessKey { get; set; } = null;
        public string AwsRoute53_SecretKey { get; set; } = null;

        //IBM NS1 DNS Ns1_ApiKey
        public string Ns1_ApiKey { get; set; } = null;

        // RFC 2136 Dynamic DNS (BIND/Microsoft DNS)
        public string Rfc2136_Server { get; set; } = null;
        public int Rfc2136_Port { get; set; } = 53;
        public string Rfc2136_Zone { get; set; } = null;
        public string Rfc2136_TsigKeyName { get; set; } = null;
        public string Rfc2136_TsigKey { get; set; } = null;
        public string Rfc2136_TsigAlgorithm { get; set; } = "hmac-sha256";

        // Windows DNS Server (PowerShell-based)
        public string WindowsDns_Server { get; set; } = null;
        public string WindowsDns_Zone { get; set; } = null;
        public string WindowsDns_Username { get; set; } = null;
        public string WindowsDns_Password { get; set; } = null;

        // DNS Verification Settings
        public string DnsVerificationServer { get; set; } = null;

    }
}
