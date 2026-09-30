using System;
using System.Net.Http;
using ACMESharp.Crypto.JOSE.Impl;
using ACMESharp.Protocol;
using ACMESharp.Protocol.Resources;
using Keyfactor.Extensions.CAPlugin.Acme.Clients.Acme;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.Acme.Tests
{
    public class ExternalAccountBindingHelperTests
    {
        private static AcmeProtocolClient NewClientWithDirectory(string newAccountUrl = "https://acme.example.com/new-acct")
        {
            var signer = new ESJwsTool { HashSize = 256 };
            signer.Init();
            var client = new AcmeProtocolClient(new HttpClient(), usePostAsGet: true, signer: signer)
            {
                Directory = new ServiceDirectory { NewAccount = newAccountUrl }
            };
            return client;
        }

        private static string ValidHmacKeyBase64Url() => ACMESharp.Crypto.CryptoHelper.Base64.UrlEncode(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 });

        [Fact]
        public void CreateExternalAccountBinding_ValidInputs_ReturnsJwsShapedObject()
        {
            var client = NewClientWithDirectory();
            var signer = new ESJwsTool { HashSize = 256 };
            signer.Init();

            var result = ExternalAccountBindingHelper.CreateExternalAccountBinding(
                client, signer, "kid-123", ValidHmacKeyBase64Url(), "HS256");

            Assert.NotNull(result);
            var type = result.GetType();
            Assert.NotNull(type.GetProperty("protected"));
            Assert.NotNull(type.GetProperty("payload"));
            Assert.NotNull(type.GetProperty("signature"));
        }

        [Theory]
        [InlineData("HS256")]
        [InlineData("HS384")]
        [InlineData("HS512")]
        public void CreateExternalAccountBinding_SupportedAlgorithms_Succeed(string algorithm)
        {
            var client = NewClientWithDirectory();
            var signer = new ESJwsTool { HashSize = 256 };
            signer.Init();

            var result = ExternalAccountBindingHelper.CreateExternalAccountBinding(
                client, signer, "kid-123", ValidHmacKeyBase64Url(), algorithm);

            Assert.NotNull(result);
        }

        [Fact]
        public void CreateExternalAccountBinding_UnsupportedAlgorithm_Throws()
        {
            var client = NewClientWithDirectory();
            var signer = new ESJwsTool { HashSize = 256 };
            signer.Init();

            Assert.Throws<NotSupportedException>(() =>
                ExternalAccountBindingHelper.CreateExternalAccountBinding(
                    client, signer, "kid-123", ValidHmacKeyBase64Url(), "HS128"));
        }

        [Fact]
        public void CreateExternalAccountBinding_NullClient_Throws()
        {
            var signer = new ESJwsTool { HashSize = 256 };
            signer.Init();
            Assert.Throws<ArgumentNullException>(() =>
                ExternalAccountBindingHelper.CreateExternalAccountBinding(
                    null, signer, "kid-123", ValidHmacKeyBase64Url(), "HS256"));
        }

        [Fact]
        public void CreateExternalAccountBinding_NullSigner_Throws()
        {
            var client = NewClientWithDirectory();
            Assert.Throws<ArgumentNullException>(() =>
                ExternalAccountBindingHelper.CreateExternalAccountBinding(
                    client, null, "kid-123", ValidHmacKeyBase64Url(), "HS256"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void CreateExternalAccountBinding_MissingKeyId_Throws(string keyId)
        {
            var client = NewClientWithDirectory();
            var signer = new ESJwsTool { HashSize = 256 };
            signer.Init();

            Assert.Throws<ArgumentNullException>(() =>
                ExternalAccountBindingHelper.CreateExternalAccountBinding(
                    client, signer, keyId, ValidHmacKeyBase64Url(), "HS256"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void CreateExternalAccountBinding_MissingHmacKey_Throws(string hmacKey)
        {
            var client = NewClientWithDirectory();
            var signer = new ESJwsTool { HashSize = 256 };
            signer.Init();

            Assert.Throws<ArgumentNullException>(() =>
                ExternalAccountBindingHelper.CreateExternalAccountBinding(
                    client, signer, "kid-123", hmacKey, "HS256"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void CreateExternalAccountBinding_MissingAlgorithm_Throws(string algorithm)
        {
            var client = NewClientWithDirectory();
            var signer = new ESJwsTool { HashSize = 256 };
            signer.Init();

            Assert.Throws<ArgumentNullException>(() =>
                ExternalAccountBindingHelper.CreateExternalAccountBinding(
                    client, signer, "kid-123", ValidHmacKeyBase64Url(), algorithm));
        }

        [Fact]
        public void CreateManualJws_ViaReflection_ProducesFlattenedJwsDictionary()
        {
            // CreateManualJws is a private, currently-unused fallback helper (the public
            // CreateExternalAccountBinding path builds its own JWS manually rather than calling
            // it). Invoked via reflection purely to exercise this otherwise-dead code
            // deterministically, since it is pure/side-effect-free.
            var method = typeof(ExternalAccountBindingHelper).GetMethod(
                "CreateManualJws", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            Assert.NotNull(method);

            var signFunc = new System.Func<byte[], byte[]>(data => new byte[] { 9, 9, 9 });
            var result = (System.Collections.Generic.Dictionary<string, string>)method.Invoke(
                null, new object[] { "{\"a\":1}", new { alg = "HS256" }, signFunc });

            Assert.True(result.ContainsKey("protected"));
            Assert.True(result.ContainsKey("payload"));
            Assert.True(result.ContainsKey("signature"));
        }

        [Fact]
        public void CreateExternalAccountBinding_NullDirectory_Throws()
        {
            var signer = new ESJwsTool { HashSize = 256 };
            signer.Init();
            var client = new AcmeProtocolClient(new HttpClient(), usePostAsGet: true, signer: signer);
            // Directory left at its default (null).

            Assert.Throws<ArgumentException>(() =>
                ExternalAccountBindingHelper.CreateExternalAccountBinding(
                    client, signer, "kid-123", ValidHmacKeyBase64Url(), "HS256"));
        }

        [Fact]
        public void CreateExternalAccountBinding_DirectoryMissingNewAccount_Throws()
        {
            var signer = new ESJwsTool { HashSize = 256 };
            signer.Init();
            var client = new AcmeProtocolClient(new HttpClient(), usePostAsGet: true, signer: signer)
            {
                Directory = new ServiceDirectory()
            };

            Assert.Throws<ArgumentException>(() =>
                ExternalAccountBindingHelper.CreateExternalAccountBinding(
                    client, signer, "kid-123", ValidHmacKeyBase64Url(), "HS256"));
        }
    }
}
