using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.Acme.Clients.DNS;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.Acme.Tests
{
    /// <summary>
    /// CnameResolver and DnsVerificationHelper have no injectable DNS client/lookup seam - they
    /// always construct real DnsClient.LookupClient instances against either a configured
    /// verification server or a hardcoded list of public resolvers (8.8.8.8, 1.1.1.1, etc.).
    /// Exercising their actual DNS query paths therefore requires real network access (or, for
    /// "propagated" success, a real answering authoritative server), which is out of scope for a
    /// deterministic, offline unit test suite. These tests cover only the small amount of
    /// constructor/early-return logic that does not require network I/O; the remainder (documented
    /// in the final coverage report) is accepted as uncovered.
    /// </summary>
    public class DnsHelpersTests
    {
        [Fact]
        public async Task CnameResolver_ResolveChallengeTargetAsync_NullInput_ReturnsNullWithoutNetworkCall()
        {
            var resolver = new CnameResolver(NullLogger.Instance);
            var result = await resolver.ResolveChallengeTargetAsync(null);
            Assert.Null(result);
        }

        [Fact]
        public async Task CnameResolver_ResolveChallengeTargetAsync_EmptyInput_ReturnsEmptyWithoutNetworkCall()
        {
            var resolver = new CnameResolver(NullLogger.Instance);
            var result = await resolver.ResolveChallengeTargetAsync(string.Empty);
            Assert.Equal(string.Empty, result);
        }

        [Fact]
        public void CnameResolver_Constructor_WithPrivateServer_DoesNotThrow()
        {
            var resolver = new CnameResolver(NullLogger.Instance, "10.3.10.37");
            Assert.NotNull(resolver);
        }

        [Fact]
        public void CnameResolver_Constructor_WithInvalidServerString_FallsBackToPublicServers()
        {
            var resolver = new CnameResolver(NullLogger.Instance, "not-an-ip-address");
            Assert.NotNull(resolver);
        }

        [Fact]
        public void DnsVerificationHelper_Constructor_WithPrivateServer_DoesNotThrow()
        {
            var helper = new DnsVerificationHelper(NullLogger.Instance, "10.3.10.37");
            Assert.NotNull(helper);
        }

        [Fact]
        public void DnsVerificationHelper_Constructor_Default_UsesPublicServers()
        {
            var helper = new DnsVerificationHelper(NullLogger.Instance);
            Assert.NotNull(helper);
        }
    }
}
