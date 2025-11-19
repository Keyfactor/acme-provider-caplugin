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

        // Infoblox DNS
        public string Infoblox_Host { get; set; } = null;
        public string Infoblox_Username { get; set; } = null;
        public string Infoblox_Password { get; set; } = null;
        public string Infoblox_WapiVersion { get; set; } = "2.12";
        public bool Infoblox_IgnoreSslErrors { get; set; } = false;

    }
}
