using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Keyfactor.Extensions.CAPlugin.Acme.Tests
{
    /// <summary>
    /// Builds real DER-encoded PKCS#10 CSRs (with CN and optional SAN dNSName extension) at test
    /// time using BouncyCastle, so ExtractDomainsFromCsr can be exercised against deterministic,
    /// known-good input rather than a hardcoded/guessed byte fixture.
    /// </summary>
    internal static class CsrTestFixture
    {
        /// <summary>Builds a CSR with an empty subject and no SAN extension at all, so
        /// ExtractDomainsFromCsr's "no DNS names found" guard can be exercised.</summary>
        public static byte[] BuildCsrWithNoIdentifiers()
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = keyGen.GenerateKeyPair();

            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA",
                new X509Name(new List<DerObjectIdentifier>(), new List<string>()),
                keyPair.Public,
                null,
                keyPair.Private);

            return csr.GetDerEncoded();
        }

        public static byte[] BuildCsr(string cn, string[] sanDnsNames)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair keyPair = keyGen.GenerateKeyPair();

            var subject = new X509Name($"CN={cn}");

            Asn1Set attributes = null;
            if (sanDnsNames != null && sanDnsNames.Length > 0)
            {
                var names = new List<GeneralName>();
                foreach (var dns in sanDnsNames)
                    names.Add(new GeneralName(GeneralName.DnsName, dns));

                var subjectAltName = new GeneralNames(names.ToArray());
                var extensions = new X509Extensions(new Dictionary<DerObjectIdentifier, X509Extension>
                {
                    { X509Extensions.SubjectAlternativeName, new X509Extension(false, new DerOctetString(subjectAltName)) }
                });

                var attribute = new AttributePkcs(
                    PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
                    new DerSet(extensions));

                attributes = new DerSet(attribute);
            }

            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA",
                subject,
                keyPair.Public,
                attributes,
                keyPair.Private);

            return csr.GetDerEncoded();
        }
    }
}
