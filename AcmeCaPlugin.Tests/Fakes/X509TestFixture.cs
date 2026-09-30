using System;
using System.Collections.Generic;
using System.Linq;
using Keyfactor.Extensions.CAPlugin.Acme.Interfaces;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Keyfactor.Extensions.CAPlugin.Acme.Tests.Fakes
{
    /// <summary>
    /// Builds real self-signed BouncyCastle X509Certificates (with/without an Authority Key
    /// Identifier extension) wrapped in a minimal ICertificateInfo, so
    /// AcmeClient.GetCertificateIdentifier (ARI support) can be exercised against deterministic,
    /// known-good/known-bad certificate shapes.
    /// </summary>
    internal static class X509TestFixture
    {
        private sealed class StubCertificateInfo : ICertificateInfo
        {
            public X509Certificate Certificate { get; set; }
            public AsymmetricKeyParameter PrivateKey { get; set; }
            public IEnumerable<X509Certificate> Chain { get; set; } = Enumerable.Empty<X509Certificate>();
            public string FriendlyName { get; set; } = "test";
            public byte[] GetHash() => Certificate.GetSignature();
            public string Thumbprint => "stub-thumbprint";
        }

        public static ICertificateInfo BuildCertificateInfo(bool includeAuthorityKeyIdentifier = true)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = keyGen.GenerateKeyPair();

            var generator = new X509V3CertificateGenerator();
            var subject = new X509Name("CN=test.example.com");
            generator.SetSubjectDN(subject);
            generator.SetIssuerDN(subject);
            generator.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks));
            generator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
            generator.SetNotAfter(DateTime.UtcNow.AddDays(30));
            generator.SetPublicKey(keyPair.Public);

            if (includeAuthorityKeyIdentifier)
            {
                var akiFactory = new SubjectKeyIdentifierStructure(keyPair.Public);
                var aki = new AuthorityKeyIdentifier(akiFactory.GetKeyIdentifier());
                generator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, aki);
            }

            var signatureFactory = new Asn1SignatureFactory("SHA256withRSA", keyPair.Private);
            var cert = generator.Generate(signatureFactory);

            return new StubCertificateInfo { Certificate = cert, PrivateKey = keyPair.Private };
        }

        public static ICertificateInfo BuildCertificateInfoWithoutAuthorityKeyIdentifier() =>
            BuildCertificateInfo(includeAuthorityKeyIdentifier: false);
    }
}
