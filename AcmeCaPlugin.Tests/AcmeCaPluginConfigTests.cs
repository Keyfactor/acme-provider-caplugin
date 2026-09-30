using Xunit;

namespace Keyfactor.Extensions.CAPlugin.Acme.Tests
{
    public class AcmeCaPluginConfigTests
    {
        [Fact]
        public void GetPluginAnnotations_ContainsExpectedKeys()
        {
            var annotations = AcmeCaPluginConfig.GetPluginAnnotations();

            Assert.Equal(9, annotations.Count);
            Assert.True(annotations.ContainsKey("Enabled"));
            Assert.True(annotations.ContainsKey("DirectoryUrl"));
            Assert.True(annotations.ContainsKey("Email"));
            Assert.True(annotations.ContainsKey("EabKid"));
            Assert.True(annotations.ContainsKey("EabHmacKey"));
            Assert.True(annotations.ContainsKey("SignerEncryptionPhrase"));
            Assert.True(annotations.ContainsKey("AccountStoragePath"));
            Assert.True(annotations.ContainsKey("DnsPropagationDelaySeconds"));
            Assert.True(annotations.ContainsKey("DnsVerificationServer"));
        }

        [Fact]
        public void GetPluginAnnotations_SecretsAreHidden()
        {
            var annotations = AcmeCaPluginConfig.GetPluginAnnotations();
            Assert.True(annotations["EabHmacKey"].Hidden);
            Assert.True(annotations["SignerEncryptionPhrase"].Hidden);
            Assert.False(annotations["DirectoryUrl"].Hidden);
        }

        [Fact]
        public void GetPluginAnnotations_TypesAreExpected()
        {
            var annotations = AcmeCaPluginConfig.GetPluginAnnotations();
            Assert.Equal("Bool", annotations["Enabled"].Type);
            Assert.Equal("String", annotations["DirectoryUrl"].Type);
            Assert.Equal("Secret", annotations["EabHmacKey"].Type);
            Assert.Equal("Number", annotations["DnsPropagationDelaySeconds"].Type);
        }

        [Fact]
        public void GetTemplateParameterAnnotations_ReturnsEmpty()
        {
            var annotations = AcmeCaPluginConfig.GetTemplateParameterAnnotations();
            Assert.Empty(annotations);
        }
    }
}
