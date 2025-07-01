using ACMESharp.Protocol;

namespace Keyfactor.Extensions.CAPlugin.Acme.Clients.Acme
{
    internal class Account
    {
        /// <summary>
        /// Constructor requires signer to be present
        /// </summary>
        /// <param name="signer"></param>
        public Account(AccountDetails details, AccountSigner signer)
        {
            Details = details;
            Signer = signer;
        }

        /// <summary>
        /// Account information
        /// </summary>
        public AccountDetails Details { get; set; }

        /// <summary>
        /// Account "password"
        /// </summary>
        public AccountSigner Signer { get; set; }
    }
}
