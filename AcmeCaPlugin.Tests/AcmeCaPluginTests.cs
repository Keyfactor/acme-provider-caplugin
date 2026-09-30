using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.Acme.Tests.Fakes;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.Acme.Tests
{
    public class AcmeCaPluginTests : IDisposable
    {
        private readonly string _tempDir;

        public AcmeCaPluginTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "AcmeCaPluginTests_" + Guid.NewGuid());
            Directory.CreateDirectory(_tempDir);
        }

        public void Dispose()
        {
            try { Directory.Delete(_tempDir, recursive: true); } catch { }
        }

        private static Dictionary<string, object> ConnectionData(
            bool enabled = true,
            string directoryUrl = "https://acme.example.com/directory",
            string email = "test@example.com",
            string eabKid = null,
            string eabHmac = null,
            int dnsDelay = 0,
            string accountStoragePath = null,
            string dnsVerificationServer = null) => new Dictionary<string, object>
            {
                ["Enabled"] = enabled,
                ["DirectoryUrl"] = directoryUrl,
                ["Email"] = email,
                ["EabKid"] = eabKid,
                ["EabHmacKey"] = eabHmac,
                ["DnsPropagationDelaySeconds"] = dnsDelay,
                ["AccountStoragePath"] = accountStoragePath,
                ["DnsVerificationServer"] = dnsVerificationServer
            };

        private AcmeCaPlugin CreatePlugin(
            Dictionary<string, object> connectionData,
            out Mock<IDomainValidatorFactory> factoryMock)
        {
            factoryMock = new Mock<IDomainValidatorFactory>();
            var plugin = new AcmeCaPlugin(factoryMock.Object);
            var configProvider = new Mock<IAnyCAPluginConfigProvider>();
            configProvider.Setup(c => c.CAConnectionData).Returns(connectionData);
            var certReader = new Mock<ICertificateDataReader>();
            plugin.Initialize(configProvider.Object, certReader.Object);
            return plugin;
        }

        #region Constructor

        [Fact]
        public void Constructor_NullFactory_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => new AcmeCaPlugin(null));
        }

        #endregion

        #region Initialize / ValidateConfigForEnrollment

        [Fact]
        public void Initialize_Disabled_SkipsValidation()
        {
            var plugin = CreatePlugin(ConnectionData(enabled: false, directoryUrl: null, email: null), out _);
            Assert.NotNull(plugin);
        }

        [Fact]
        public void Initialize_NullConfigProvider_Throws()
        {
            var factory = new Mock<IDomainValidatorFactory>();
            var plugin = new AcmeCaPlugin(factory.Object);
            Assert.Throws<ArgumentNullException>(() => plugin.Initialize(null, new Mock<ICertificateDataReader>().Object));
        }

        [Fact]
        public void Initialize_MissingDirectoryUrl_Throws()
        {
            Assert.Throws<ArgumentException>(() =>
                CreatePlugin(ConnectionData(directoryUrl: null), out _));
        }

        [Fact]
        public void Initialize_InvalidDirectoryUrlScheme_Throws()
        {
            Assert.Throws<ArgumentException>(() =>
                CreatePlugin(ConnectionData(directoryUrl: "ftp://acme.example.com/directory"), out _));
        }

        [Fact]
        public void Initialize_RelativeDirectoryUrl_Throws()
        {
            Assert.Throws<ArgumentException>(() =>
                CreatePlugin(ConnectionData(directoryUrl: "not-a-url"), out _));
        }

        [Fact]
        public void Initialize_MissingEmail_Throws()
        {
            Assert.Throws<ArgumentException>(() =>
                CreatePlugin(ConnectionData(email: null), out _));
        }

        [Fact]
        public void Initialize_EabKidWithoutHmac_Throws()
        {
            Assert.Throws<ArgumentException>(() =>
                CreatePlugin(ConnectionData(eabKid: "kid-only"), out _));
        }

        [Fact]
        public void Initialize_EabHmacWithoutKid_Throws()
        {
            Assert.Throws<ArgumentException>(() =>
                CreatePlugin(ConnectionData(eabHmac: "hmac-only"), out _));
        }

        [Fact]
        public void Initialize_EabKidAndHmacBothProvided_Succeeds()
        {
            var plugin = CreatePlugin(ConnectionData(eabKid: "kid", eabHmac: "hmac"), out _);
            Assert.NotNull(plugin);
        }

        [Fact]
        public void Initialize_NegativeDnsPropagationDelay_Throws()
        {
            Assert.Throws<ArgumentException>(() =>
                CreatePlugin(ConnectionData(dnsDelay: -5), out _));
        }

        [Fact]
        public void Initialize_MultipleProblems_AllReportedInMessage()
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                CreatePlugin(ConnectionData(directoryUrl: null, email: null), out _));
            Assert.Contains("DirectoryUrl", ex.Message);
            Assert.Contains("Email", ex.Message);
        }

        [Fact]
        public void Initialize_ValidConfig_Succeeds()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            Assert.NotNull(plugin);
        }

        #endregion

        #region Ping

        [Fact]
        public async Task Ping_Disabled_ReturnsWithoutError()
        {
            var plugin = CreatePlugin(ConnectionData(enabled: false, directoryUrl: null, email: null), out _);
            await plugin.Ping();
        }

        [Fact]
        public async Task Ping_ValidDirectory_Succeeds()
        {
            using var server = new FakeAcmeServer();
            var plugin = CreatePlugin(ConnectionData(directoryUrl: server.DirectoryUrl), out _);
            await plugin.Ping();
        }

        [Fact]
        public async Task Ping_NonAcmeDirectoryResponse_Throws()
        {
            using var listener = new SimpleHttpStub("{}"); // missing newAccount/newOrder markers
            var plugin = CreatePlugin(ConnectionData(directoryUrl: listener.Url), out _);
            await Assert.ThrowsAsync<InvalidOperationException>(() => plugin.Ping());
        }

        [Fact]
        public async Task Ping_ServerErrorResponse_Throws()
        {
            using var listener = new SimpleHttpStub("error", statusCode: 500);
            var plugin = CreatePlugin(ConnectionData(directoryUrl: listener.Url), out _);
            await Assert.ThrowsAsync<HttpRequestException>(() => plugin.Ping());
        }

        [Fact]
        public async Task Ping_UnreachableHost_ThrowsHttpRequestException()
        {
            var plugin = CreatePlugin(ConnectionData(directoryUrl: "http://127.0.0.1:1/directory"), out _);
            await Assert.ThrowsAnyAsync<Exception>(() => plugin.Ping());
        }

        #endregion

        #region ValidateCAConnectionInfo

        [Fact]
        public async Task ValidateCAConnectionInfo_NullInput_Throws()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            await Assert.ThrowsAsync<ArgumentNullException>(() => plugin.ValidateCAConnectionInfo(null));
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_Disabled_SkipsValidation()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            await plugin.ValidateCAConnectionInfo(ConnectionData(enabled: false, directoryUrl: null, email: null));
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_MissingFields_Throws()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
                plugin.ValidateCAConnectionInfo(ConnectionData(directoryUrl: null, email: null)));
            Assert.Contains("DirectoryUrl", ex.Message);
            Assert.Contains("Email", ex.Message);
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_MissingDirectoryUrlOnly_Throws()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
                plugin.ValidateCAConnectionInfo(ConnectionData(directoryUrl: null)));
            Assert.Contains("DirectoryUrl", ex.Message);
            Assert.DoesNotContain("Email", ex.Message);
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_MissingEmailOnly_Throws()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
                plugin.ValidateCAConnectionInfo(ConnectionData(email: null)));
            Assert.Contains("Email", ex.Message);
            Assert.DoesNotContain("DirectoryUrl", ex.Message);
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_Valid_Succeeds()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            await plugin.ValidateCAConnectionInfo(ConnectionData());
        }

        #endregion

        #region Other simple members

        [Fact]
        public async Task ValidateProductInfo_AlwaysSucceeds()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            await plugin.ValidateProductInfo(new EnrollmentProductInfo(), new Dictionary<string, object>());
        }

        [Fact]
        public void GetProductIds_ReturnsDefault()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            var ids = plugin.GetProductIds();
            Assert.Equal(new List<string> { "default" }, ids);
        }

        [Fact]
        public async Task Synchronize_ReturnsCompletedTask()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            using var buffer = new System.Collections.Concurrent.BlockingCollection<AnyCAPluginCertificate>();
            await plugin.Synchronize(buffer, null, true, CancellationToken.None);
        }

        [Fact]
        public async Task Revoke_ReturnsFailedStatus()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            var status = await plugin.Revoke("req-id", "AA11", 0);
            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, status);
        }

        [Fact]
        public async Task GetSingleRecord_ReturnsFailedStatus()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            var record = await plugin.GetSingleRecord("req-id");
            Assert.Equal("req-id", record.CARequestID);
            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, record.Status);
        }

        [Fact]
        public void GetCAConnectorAnnotations_ReturnsAnnotations()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            var annotations = plugin.GetCAConnectorAnnotations();
            Assert.True(annotations.ContainsKey("DirectoryUrl"));
        }

        [Fact]
        public void GetTemplateParameterAnnotations_ReturnsEmpty()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            Assert.Empty(plugin.GetTemplateParameterAnnotations());
        }

        #endregion

        #region Enroll

        private static string BuildPemCsr(string cn, params string[] sans)
        {
            var der = CsrTestFixture.BuildCsr(cn, sans);
            var b64 = Convert.ToBase64String(der);
            return "-----BEGIN CERTIFICATE REQUEST-----\n" + b64 + "\n-----END CERTIFICATE REQUEST-----\n";
        }

        [Fact]
        public async Task Enroll_Disabled_ReturnsFailedResult()
        {
            var plugin = CreatePlugin(ConnectionData(enabled: false, directoryUrl: null, email: null), out _);
            var result = await plugin.Enroll(BuildPemCsr("example.com"), "CN=example.com", null,
                new EnrollmentProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
            Assert.Contains("disabled", result.StatusMessage, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task Enroll_EmptyCsr_ReturnsFailedResultWithFlowSummary(string csr)
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            var result = await plugin.Enroll(csr, "CN=example.com", null,
                new EnrollmentProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
            Assert.Contains("Enrollment failed", result.StatusMessage);
            Assert.Contains("Flow: Enroll", result.StatusMessage);
        }

        [Fact]
        public async Task Enroll_NullSubject_UsesPlaceholderInFlowNameAndReturnsFailedResult()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            var result = await plugin.Enroll(BuildPemCsr("example.com"), null, null,
                new EnrollmentProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
        }

        [Fact]
        public async Task Enroll_ValidOrderWithoutCertificateYet_ReturnsFailedWithStatusInMessage()
        {
            using var server = new FakeAcmeServer { FinalizeValidWithoutCertificate = true };
            var plugin = CreatePlugin(
                ConnectionData(directoryUrl: server.DirectoryUrl, accountStoragePath: _tempDir),
                out _);

            var result = await plugin.Enroll(BuildPemCsr("example.com"), "CN=example.com", null,
                new EnrollmentProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
            Assert.Contains("Could not retrieve order", result.StatusMessage);
        }

        [Fact]
        public async Task Enroll_FinalizeReturnsNullPayload_ReportsUnknownStatus()
        {
            using var server = new FakeAcmeServer { FinalizeReturnsNullStatus = true };
            var plugin = CreatePlugin(
                ConnectionData(directoryUrl: server.DirectoryUrl, accountStoragePath: _tempDir),
                out _);

            var result = await plugin.Enroll(BuildPemCsr("example.com"), "CN=example.com", null,
                new EnrollmentProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
            Assert.Contains("order status: unknown", result.StatusMessage);
        }

        [Fact]
        public async Task Enroll_EmptySubject_ReturnsFailedResult()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            var result = await plugin.Enroll(BuildPemCsr("example.com"), "", null,
                new EnrollmentProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
        }

        [Fact]
        public async Task Enroll_MalformedCsr_ReturnsFailedResult()
        {
            var plugin = CreatePlugin(ConnectionData(), out _);
            var result = await plugin.Enroll("not-a-valid-csr!!!", "CN=example.com", null,
                new EnrollmentProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
            Assert.Null(result.CARequestID);
        }

        [Fact]
        public async Task Enroll_HappyPath_AuthorizationAlreadyValid_ReturnsGenerated()
        {
            using var server = new FakeAcmeServer(); // AuthzStatus defaults to "valid" -> DNS staging skipped entirely
            var plugin = CreatePlugin(
                ConnectionData(directoryUrl: server.DirectoryUrl, dnsDelay: 0, accountStoragePath: _tempDir),
                out var factoryMock);

            var result = await plugin.Enroll(BuildPemCsr("example.com"), "CN=example.com", null,
                new EnrollmentProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.GENERATED, result.Status);
            Assert.NotNull(result.Certificate);
            Assert.NotNull(result.CARequestID);
            Assert.Contains("Enrollment completed successfully", result.StatusMessage);
            // Because the authorization was already valid, no domain validator should ever be resolved.
            factoryMock.Verify(f => f.ResolveDomainValidator(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task Enroll_OrderNeverBecomesValid_ReturnsFailedWithStatusInMessage()
        {
            using var server = new FakeAcmeServer { OrderStatus = "pending" };
            var plugin = CreatePlugin(
                ConnectionData(directoryUrl: server.DirectoryUrl, dnsDelay: 0, accountStoragePath: _tempDir),
                out _);

            var result = await plugin.Enroll(BuildPemCsr("example.com"), "CN=example.com", null,
                new EnrollmentProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
            Assert.Contains("Could not retrieve order", result.StatusMessage);
        }

        [Fact]
        public async Task Enroll_MissingDns01Challenge_ReturnsFailedResult()
        {
            using var server = new FakeAcmeServer { AuthzStatus = "pending", ChallengeType = "http-01" };
            var plugin = CreatePlugin(
                ConnectionData(directoryUrl: server.DirectoryUrl, dnsDelay: 0, accountStoragePath: _tempDir),
                out _);

            var result = await plugin.Enroll(BuildPemCsr("example.com"), "CN=example.com", null,
                new EnrollmentProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
            Assert.Contains("dns-01", result.StatusMessage);
        }

        [Fact]
        public async Task Enroll_PendingAuthorizationWithPrivateDnsProvider_StagesVerifiesCleansUpAndGenerates()
        {
            // AuthzStatus="pending" forces the real DNS-01 staging/verification/cleanup pipeline in
            // ProcessAuthorizations to run (rather than being skipped via the "already valid"
            // shortcut). Resolving the domain validator to a stub whose type name contains
            // "rfc2136" routes execution down the private-DNS-provider branch, which never calls
            // the real-network DnsVerificationHelper (only CnameResolver.ResolveChallengeTargetAsync
            // runs, and it fails fast against the unreachable loopback "DNS server" configured below
            // and treats that as "no CNAME delegation exists").
            using var server = new FakeAcmeServer { AuthzStatus = "pending" };
            var validator = new Rfc2136StyleDomainValidatorStub();
            var plugin = CreatePlugin(
                ConnectionData(directoryUrl: server.DirectoryUrl, dnsDelay: 1, accountStoragePath: _tempDir, dnsVerificationServer: "127.0.0.1"),
                out var factoryMock);
            factoryMock.Setup(f => f.ResolveDomainValidator(It.IsAny<string>(), "dns-01")).Returns(validator);

            var result = await plugin.Enroll(BuildPemCsr("example.com"), "CN=example.com", null,
                new EnrollmentProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.GENERATED, result.Status);
            Assert.Equal(1, validator.StageCallCount);
            Assert.Equal(1, validator.CleanupCallCount);
            factoryMock.Verify(f => f.ResolveDomainValidator(It.IsAny<string>(), "dns-01"), Times.Once);
        }

        [Fact]
        public async Task Enroll_StageValidationFails_ReturnsFailedResult()
        {
            using var server = new FakeAcmeServer { AuthzStatus = "pending" };
            var validator = new Rfc2136StyleDomainValidatorStub { StageSucceeds = false };
            var plugin = CreatePlugin(
                ConnectionData(directoryUrl: server.DirectoryUrl, accountStoragePath: _tempDir, dnsVerificationServer: "127.0.0.1"),
                out var factoryMock);
            factoryMock.Setup(f => f.ResolveDomainValidator(It.IsAny<string>(), "dns-01")).Returns(validator);

            var result = await plugin.Enroll(BuildPemCsr("example.com"), "CN=example.com", null,
                new EnrollmentProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
            Assert.Contains("Failed to stage DNS validation", result.StatusMessage);
            Assert.Equal(0, validator.CleanupCallCount);
        }

        [Fact]
        public async Task Enroll_CleanupValidationThrows_StillCompletesSuccessfully()
        {
            // Cleanup failures for one domain must not fail the overall enrollment - they're
            // logged and swallowed so cleanup continues for any other domains.
            using var server = new FakeAcmeServer { AuthzStatus = "pending" };
            var validator = new Rfc2136StyleDomainValidatorStub { ThrowOnCleanup = true };
            var plugin = CreatePlugin(
                ConnectionData(directoryUrl: server.DirectoryUrl, accountStoragePath: _tempDir, dnsVerificationServer: "127.0.0.1"),
                out var factoryMock);
            factoryMock.Setup(f => f.ResolveDomainValidator(It.IsAny<string>(), "dns-01")).Returns(validator);

            var result = await plugin.Enroll(BuildPemCsr("example.com"), "CN=example.com", null,
                new EnrollmentProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.GENERATED, result.Status);
            Assert.Equal(1, validator.CleanupCallCount);
        }

        [Fact]
        public async Task Enroll_ValidatorFactoryReturnsNull_ReturnsFailedResult()
        {
            using var server = new FakeAcmeServer { AuthzStatus = "pending" };
            var plugin = CreatePlugin(
                ConnectionData(directoryUrl: server.DirectoryUrl, accountStoragePath: _tempDir, dnsVerificationServer: "127.0.0.1"),
                out var factoryMock);
            factoryMock.Setup(f => f.ResolveDomainValidator(It.IsAny<string>(), "dns-01")).Returns((IDomainValidator)null);

            var result = await plugin.Enroll(BuildPemCsr("example.com"), "CN=example.com", null,
                new EnrollmentProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
            Assert.Contains("Failed to resolve domain validator", result.StatusMessage);
        }

        [Fact]
        public async Task Enroll_UnreachableAcmeServer_ReturnsFailedResultWithDescribedException()
        {
            var plugin = CreatePlugin(
                ConnectionData(directoryUrl: "http://127.0.0.1:1/directory", accountStoragePath: _tempDir),
                out _);

            var result = await plugin.Enroll(BuildPemCsr("example.com"), "CN=example.com", null,
                new EnrollmentProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
            Assert.Contains("Enrollment failed", result.StatusMessage);
        }

        #endregion
    }
}
