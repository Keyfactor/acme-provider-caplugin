namespace Keyfactor.Extensions.CAPlugin.Acme
{
    public class AcmeClientConfig
    {
        public bool Enabled { get; set; } = true;
        public string DirectoryUrl { get; set; } = "https://acme-v02.api.letsencrypt.org/directory";
        public string Email { get; set; } = string.Empty;
        public string EabKid { get; set; } = null;
        public string EabHmacKey { get; set; } = null;
        public string SignerEncryptionPhrase{ get; set; } = null;

        // Container Deployment Support
        public string AccountStoragePath { get; set; } = null;

        // DNS Propagation Delay (in seconds) - wait this long after creating DNS records before checking propagation
        public int DnsPropagationDelaySeconds { get; set; } = 60;

        // DNS Verification Settings - DNS server IP for verification (for private zones)
        public string DnsVerificationServer { get; set; } = null;

    }
}
