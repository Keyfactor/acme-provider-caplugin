using System;
using System.Collections.Generic;
using System.Reflection;
using ACMESharp.Protocol.Resources;
using Keyfactor.AnyGateway.Extensions;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.Acme.Tests
{
    /// <summary>
    /// Tests for pure/deterministic logic in AcmeCaPlugin.cs. Private static/instance helper
    /// methods are invoked via reflection since they are implementation details not exposed even
    /// via InternalsVisibleTo (which only affects `internal`, not `private`, members) and are not
    /// worth publicly/internally exposing just for testing.
    /// </summary>
    public class PureLogicTests
    {
        private static readonly string ValidPemCsr =
            "-----BEGIN CERTIFICATE REQUEST-----\n" +
            Convert.ToBase64String(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }) +
            "\n-----END CERTIFICATE REQUEST-----\n";

        #region FormatCsrToSingleLine

        [Fact]
        public void FormatCsrToSingleLine_ValidPem_ReturnsSingleLineBase64()
        {
            var result = AcmeCaPlugin.FormatCsrToSingleLine(ValidPemCsr);
            Assert.Equal(Convert.ToBase64String(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }), result);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void FormatCsrToSingleLine_NullOrWhitespace_Throws(string input)
        {
            Assert.Throws<ArgumentException>(() => AcmeCaPlugin.FormatCsrToSingleLine(input));
        }

        [Fact]
        public void FormatCsrToSingleLine_InvalidBase64_ThrowsFormatException()
        {
            Assert.ThrowsAny<FormatException>(() =>
                AcmeCaPlugin.FormatCsrToSingleLine("-----BEGIN CERTIFICATE REQUEST-----\nnot-valid-base64!!!\n-----END CERTIFICATE REQUEST-----"));
        }

        #endregion

        #region DescribeException (internal static)

        [Fact]
        public void DescribeException_Null_ReturnsUnknownError()
        {
            Assert.Equal("Unknown error", AcmeCaPlugin.DescribeException(null));
        }

        [Fact]
        public void DescribeException_SimpleException_ReturnsTypeAndMessage()
        {
            var result = AcmeCaPlugin.DescribeException(new InvalidOperationException("boom"));
            Assert.Equal("InvalidOperationException: boom", result);
        }

        [Fact]
        public void DescribeException_SingleInnerAggregateException_Unwraps()
        {
            var agg = new AggregateException(new InvalidOperationException("inner-boom"));
            var result = AcmeCaPlugin.DescribeException(agg);
            Assert.Equal("InvalidOperationException: inner-boom", result);
        }

        [Fact]
        public void DescribeException_MultiInnerAggregateException_JoinsAll()
        {
            var agg = new AggregateException(
                new InvalidOperationException("first"),
                new ArgumentException("second"));
            var result = AcmeCaPlugin.DescribeException(agg);
            Assert.StartsWith("Multiple errors: ", result);
            Assert.Contains("InvalidOperationException: first", result);
            Assert.Contains("ArgumentException: second", result);
        }

        [Fact]
        public void DescribeException_PlainWrapperException_UnwrapsInner()
        {
            // ex.GetType() == typeof(Exception) exactly (not a subclass) triggers unwrap loop
            var wrapper = new Exception("outer", new InvalidOperationException("real-cause"));
            var result = AcmeCaPlugin.DescribeException(wrapper);
            Assert.Equal("InvalidOperationException: real-cause", result);
        }

        [Fact]
        public void DescribeException_HttpRequestExceptionWrappedInGenericException_AttachesHttpDetail()
        {
            var http = new System.Net.Http.HttpRequestException("http-fail");
            // Use a subclass-avoiding wrapper: TargetInvocationException carries only inner, so it
            // unwraps fully to the HttpRequestException itself (ReferenceEquals true -> no bracket).
            var tie = new TargetInvocationException(http);
            var result = AcmeCaPlugin.DescribeException(tie);
            Assert.StartsWith("HttpRequestException: http-fail", result);
        }

        [Fact]
        public void DescribeException_ExceptionWithDistinctHttpRequestExceptionInner_AppendsHttpDetailBracket()
        {
            // Use a wrapper type that is neither exactly typeof(Exception) nor
            // TargetInvocationException, so the unwrap-loop leaves `ex` as the wrapper itself
            // (distinct from its HttpRequestException InnerException) - this is the only way to
            // hit the "!ReferenceEquals(http, ex)" branch that appends the HTTP message in brackets.
            var http = new System.Net.Http.HttpRequestException("http-fail-detail");
            var wrapper = new InvalidOperationException("outer-message", http);
            var result = AcmeCaPlugin.DescribeException(wrapper);
            Assert.StartsWith("InvalidOperationException: outer-message [http-fail-detail]", result);
        }

        [Fact]
        public void DescribeException_LongMessage_IsTrimmed()
        {
            var longMsg = new string('x', 500);
            var result = AcmeCaPlugin.DescribeException(new InvalidOperationException(longMsg));
            Assert.True(result.Length < 450);
            Assert.Contains("…", result);
        }

        #endregion

        #region Private helpers via reflection

        private static object InvokePrivateStatic(string methodName, params object[] args)
        {
            var method = typeof(AcmeCaPlugin).GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(method);
            try
            {
                return method.Invoke(null, args);
            }
            catch (TargetInvocationException tie) when (tie.InnerException != null)
            {
                throw tie.InnerException;
            }
        }

        private static AcmeCaPlugin CreatePlugin()
        {
            var factory = new Mock<IDomainValidatorFactory>();
            return new AcmeCaPlugin(factory.Object);
        }

        private static object InvokePrivateInstance(object instance, string methodName, params object[] args)
        {
            var method = instance.GetType().GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(method);
            try
            {
                return method.Invoke(instance, args);
            }
            catch (TargetInvocationException tie) when (tie.InnerException != null)
            {
                throw tie.InnerException;
            }
        }

        #region ExtractOrderIdentifier

        [Fact]
        public void ExtractOrderIdentifier_ValidUrl_Returns40CharHex()
        {
            var result = (string)InvokePrivateStatic("ExtractOrderIdentifier", "https://acme.example.com/order/12345");
            Assert.Equal(40, result.Length);
            Assert.Matches("^[0-9a-f]{40}$", result);
        }

        [Fact]
        public void ExtractOrderIdentifier_IsDeterministic()
        {
            var a = (string)InvokePrivateStatic("ExtractOrderIdentifier", "https://acme.example.com/order/12345");
            var b = (string)InvokePrivateStatic("ExtractOrderIdentifier", "https://acme.example.com/order/12345");
            Assert.Equal(a, b);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void ExtractOrderIdentifier_NullOrWhitespace_ReturnsInputUnchanged(string input)
        {
            var result = InvokePrivateStatic("ExtractOrderIdentifier", input);
            Assert.Equal(input, result);
        }

        #endregion

        #region ExtractDomainFromSubject

        [Fact]
        public void ExtractDomainFromSubject_ValidCn_ReturnsDomain()
        {
            var result = (string)InvokePrivateStatic("ExtractDomainFromSubject", "CN=example.com");
            Assert.Equal("example.com", result);
        }

        [Fact]
        public void ExtractDomainFromSubject_CnWithOtherFields_ExtractsOnlyCn()
        {
            var result = (string)InvokePrivateStatic("ExtractDomainFromSubject", "CN=example.com, O=MyOrg, C=US");
            Assert.Equal("example.com", result);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void ExtractDomainFromSubject_NullOrEmpty_ThrowsArgumentException(string input)
        {
            Assert.Throws<ArgumentException>(() => InvokePrivateStatic("ExtractDomainFromSubject", input));
        }

        [Fact]
        public void ExtractDomainFromSubject_NoCn_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => InvokePrivateStatic("ExtractDomainFromSubject", "O=MyOrg, C=US"));
        }

        #endregion

        #region EncodeToPem

        [Fact]
        public void EncodeToPem_ValidData_WrapsWithLabel()
        {
            var result = (string)InvokePrivateStatic("EncodeToPem", new byte[] { 1, 2, 3 }, "CERTIFICATE");
            Assert.StartsWith("-----BEGIN CERTIFICATE-----", result);
            Assert.Contains("-----END CERTIFICATE-----", result);
        }

        [Fact]
        public void EncodeToPem_NullData_Throws()
        {
            Assert.Throws<ArgumentException>(() => InvokePrivateStatic("EncodeToPem", null, "CERTIFICATE"));
        }

        [Fact]
        public void EncodeToPem_EmptyData_Throws()
        {
            Assert.Throws<ArgumentException>(() => InvokePrivateStatic("EncodeToPem", Array.Empty<byte>(), "CERTIFICATE"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void EncodeToPem_NullOrWhitespaceLabel_Throws(string label)
        {
            Assert.Throws<ArgumentException>(() => InvokePrivateStatic("EncodeToPem", new byte[] { 1 }, label));
        }

        #endregion

        #region ExtractDomainsFromCsr (private instance method, uses BouncyCastle CSR parsing)

        [Fact]
        public void ExtractDomainsFromCsr_ValidCsrWithCnAndSan_ExtractsAllDomains()
        {
            var plugin = CreatePlugin();
            var csrBytes = CsrTestFixture.BuildCsr("www.example.com", new[] { "www.example.com", "api.example.com" });

            var result = (List<Identifier>)InvokePrivateInstance(plugin, "ExtractDomainsFromCsr", csrBytes);

            var values = result.ConvertAll(i => i.Value);
            Assert.Contains("www.example.com", values);
            Assert.Contains("api.example.com", values);
            Assert.All(result, i => Assert.Equal("dns", i.Type));
        }

        [Fact]
        public void ExtractDomainsFromCsr_CnOnly_NoSan_ExtractsCn()
        {
            var plugin = CreatePlugin();
            var csrBytes = CsrTestFixture.BuildCsr("solo.example.com", Array.Empty<string>());

            var result = (List<Identifier>)InvokePrivateInstance(plugin, "ExtractDomainsFromCsr", csrBytes);

            Assert.Single(result);
            Assert.Equal("solo.example.com", result[0].Value);
        }

        [Fact]
        public void ExtractDomainsFromCsr_MalformedBytes_ThrowsInvalidOperationException()
        {
            var plugin = CreatePlugin();
            Assert.Throws<InvalidOperationException>(() =>
                InvokePrivateInstance(plugin, "ExtractDomainsFromCsr", new byte[] { 0x00, 0x01, 0x02 }));
        }

        [Fact]
        public void ExtractDomainsFromCsr_NoCnAndNoSan_ThrowsInvalidOperationException()
        {
            var plugin = CreatePlugin();
            var csrBytes = CsrTestFixture.BuildCsrWithNoIdentifiers();
            var ex = Assert.Throws<InvalidOperationException>(() =>
                InvokePrivateInstance(plugin, "ExtractDomainsFromCsr", csrBytes));
            Assert.Contains("No DNS names found", ex.Message);
        }

        #endregion

        #region DomainValidatorConfigProvider (private nested class, currently unused by any call site)

        [Fact]
        public void DomainValidatorConfigProvider_WithConfig_ExposesGivenDictionary()
        {
            var nestedType = typeof(AcmeCaPlugin).GetNestedType("DomainValidatorConfigProvider", BindingFlags.NonPublic);
            Assert.NotNull(nestedType);

            var dict = new Dictionary<string, object> { ["foo"] = "bar" };
            var instance = (IDomainValidatorConfigProvider)Activator.CreateInstance(nestedType, dict);

            Assert.Same(dict, instance.DomainValidationConfiguration);
        }

        [Fact]
        public void DomainValidatorConfigProvider_WithNullConfig_ExposesEmptyDictionary()
        {
            var nestedType = typeof(AcmeCaPlugin).GetNestedType("DomainValidatorConfigProvider", BindingFlags.NonPublic);
            var instance = (IDomainValidatorConfigProvider)Activator.CreateInstance(nestedType, new object[] { null });

            Assert.NotNull(instance.DomainValidationConfiguration);
            Assert.Empty(instance.DomainValidationConfiguration);
        }

        #endregion

        #region ProcessAuthorizations (private instance method) - invalid payload guard only

        [Fact]
        public async System.Threading.Tasks.Task ProcessAuthorizations_MissingAuthorizationList_Throws()
        {
            var plugin = CreatePlugin();
            var method = typeof(AcmeCaPlugin).GetMethod("ProcessAuthorizations", BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(method);

            // acmeClient may be null: the guard clause on order.Payload/Authorizations throws
            // before the client is ever touched.
            var order = new ACMESharp.Protocol.OrderDetails { Payload = new ACMESharp.Protocol.Resources.Order { Authorizations = null } };
            var config = new AcmeClientConfig();
            using var flow = new FlowLogger(Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, "test");

            var task = (System.Threading.Tasks.Task)method.Invoke(plugin, new object[] { null, order, config, flow });

            await Assert.ThrowsAsync<InvalidOperationException>(() => task);
        }

        #endregion

        #region GetConfig (private instance method)

        [Fact]
        public void Initialize_ThenGetConfig_ReflectsConnectionData()
        {
            var configProvider = new Mock<IAnyCAPluginConfigProvider>();
            configProvider.Setup(c => c.CAConnectionData).Returns(new Dictionary<string, object>
            {
                ["Enabled"] = false, // disabled avoids ValidateConfigForEnrollment during Initialize
                ["DirectoryUrl"] = "https://example.com/directory",
                ["Email"] = "test@example.com"
            });
            var certReader = new Mock<ICertificateDataReader>();
            var plugin = CreatePlugin();

            plugin.Initialize(configProvider.Object, certReader.Object);

            var config = (AcmeClientConfig)InvokePrivateInstance(plugin, "GetConfig");
            Assert.Equal("https://example.com/directory", config.DirectoryUrl);
            Assert.Equal("test@example.com", config.Email);
            Assert.False(config.Enabled);
        }

        [Fact]
        public void GetConfig_PluginNeverInitialized_ThrowsInvalidOperationException()
        {
            // Config itself (not just CAConnectionData) is null when Initialize() was never
            // called, exercising the other side of the `Config?.CAConnectionData == null` check.
            var plugin = CreatePlugin();
            var ex = Assert.Throws<InvalidOperationException>(() => InvokePrivateInstance(plugin, "GetConfig"));
            Assert.Contains("CA connection data", ex.Message);
        }

        [Fact]
        public void GetConfig_NoConnectionData_ThrowsInvalidOperationException()
        {
            var configProvider = new Mock<IAnyCAPluginConfigProvider>();
            configProvider.Setup(c => c.CAConnectionData).Returns((Dictionary<string, object>)null);
            var certReader = new Mock<ICertificateDataReader>();
            var plugin = CreatePlugin();

            // Set Config via Initialize path is not possible without CAConnectionData (Initialize
            // itself calls GetConfig()), so assert directly that Initialize surfaces the failure.
            Assert.Throws<InvalidOperationException>(() => plugin.Initialize(configProvider.Object, certReader.Object));
        }

        #endregion

        #endregion
    }
}
