using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System.Collections.Generic;

namespace Keyfactor.Extensions.CAPlugin.Acme.Interfaces
{
    public interface ICertificateInfo
    {
        /// <summary>
        /// The main certificate
        /// </summary>
        X509Certificate Certificate { get; }

        /// <summary>
        /// Private key in Bouncy Castle format
        /// </summary>
        AsymmetricKeyParameter PrivateKey { get; }

        /// <summary>
        /// The certificate chain, in the correct order
        /// </summary>
        IEnumerable<X509Certificate> Chain { get; }

        /// <summary>
        /// FriendlyName
        /// </summary>
        string FriendlyName { get; }

        /// <summary>
        /// Main certificate hash
        /// </summary>
        byte[] GetHash();

        /// <summary>
        /// Main certificate thumbprint
        /// </summary>
        string Thumbprint { get; }
    }
}