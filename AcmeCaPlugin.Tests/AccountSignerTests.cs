using System;
using ACMESharp.Crypto.JOSE.Impl;
using Keyfactor.Extensions.CAPlugin.Acme.Clients.Acme;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.Acme.Tests
{
    public class AccountSignerTests
    {
        [Fact]
        public void Constructor_ES256_CreatesExportableKey()
        {
            var signer = new AccountSigner("ES256");
            Assert.Equal("ES256", signer.KeyType);
            Assert.False(string.IsNullOrEmpty(signer.KeyExport));
        }

        [Fact]
        public void Constructor_RS256_CreatesExportableKey()
        {
            var signer = new AccountSigner("RS256");
            Assert.Equal("RS256", signer.KeyType);
            Assert.False(string.IsNullOrEmpty(signer.KeyExport));
        }

        [Fact]
        public void Constructor_FromExistingJwsTool_CopiesKeyTypeAndExport()
        {
            var tool = new ESJwsTool { HashSize = 256 };
            tool.Init();

            var signer = new AccountSigner(tool);

            Assert.Equal(tool.JwsAlg, signer.KeyType);
            Assert.Equal(tool.Export(), signer.KeyExport);
        }

        [Fact]
        public void Constructor_FromNullJwsTool_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => new AccountSigner((ACMESharp.Crypto.JOSE.IJwsTool)null));
        }

        [Fact]
        public void JwsTool_CachesInstanceAcrossCalls()
        {
            var signer = new AccountSigner("ES256");
            var first = signer.JwsTool();
            var second = signer.JwsTool();
            Assert.Same(first, second);
        }

        [Fact]
        public void GetJwsTool_ReturnsSameAsJwsTool()
        {
            var signer = new AccountSigner("ES256");
            Assert.Same(signer.JwsTool(), signer.GetJwsTool());
        }

        [Fact]
        public void JwsTool_MissingKeyType_Throws()
        {
            var signer = new AccountSigner();
            Assert.Throws<Exception>(() => signer.JwsTool());
        }

        [Fact]
        public void JwsTool_UnsupportedKeyType_Throws()
        {
            var signer = new AccountSigner { KeyType = "XX999" };
            Assert.Throws<Exception>(() => signer.JwsTool());
        }

        [Fact]
        public void JwsTool_InvalidEcHashSizeFormat_Throws()
        {
            var signer = new AccountSigner { KeyType = "ESabc" };
            Assert.Throws<Exception>(() => signer.JwsTool());
        }

        [Fact]
        public void SettingKeyType_InvalidatesCachedTool()
        {
            // Re-assigning KeyType (even to the same algorithm family) unconditionally clears the
            // cached JWS tool; keep the same family here so the existing (ES256) KeyExport remains
            // importable and the test isolates cache-invalidation from key-import compatibility.
            var signer = new AccountSigner("ES256");
            var first = signer.JwsTool();
            signer.KeyType = "ES256";
            var second = signer.JwsTool();
            Assert.NotSame(first, second);
        }

        [Fact]
        public void SettingKeyExport_InvalidatesCachedTool()
        {
            var signer = new AccountSigner("ES256");
            var first = signer.JwsTool();
            signer.KeyExport = first.Export();
            var second = signer.JwsTool();
            Assert.NotSame(first, second);
        }

        [Fact]
        public void RoundTrip_ExportThenImport_ProducesUsableTool()
        {
            var original = new AccountSigner("ES256");
            var export = original.KeyExport;

            var restored = new AccountSigner { KeyType = "ES256", KeyExport = export };
            var tool = restored.JwsTool();

            Assert.NotNull(tool);
        }
    }
}
