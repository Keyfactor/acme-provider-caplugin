using System;
using System.Net.Http;
using System.Threading.Tasks;
using ACMESharp.Crypto.JOSE.Impl;
using ACMESharp.Protocol;
using ACMESharp.Protocol.Resources;
using Keyfactor.Extensions.CAPlugin.Acme.Clients.Acme;
using Keyfactor.Extensions.CAPlugin.Acme.Tests.Fakes;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.Acme.Tests
{
    /// <summary>
    /// Tests the internal AcmeProtocolClient extension methods (Retry/Backoff/GetNonce) which
    /// implement ACME-specific retry semantics on top of AcmeProtocolException.
    /// </summary>
    public class AcmeClientExtensionsTests
    {
        private static AcmeProtocolClient NewProtocolClient()
        {
            var signer = new ESJwsTool { HashSize = 256 };
            signer.Init();
            return new AcmeProtocolClient(new HttpClient(), usePostAsGet: true, signer: signer);
        }

        private static AcmeProtocolException NewProblemException(string urnSuffix) =>
            new AcmeProtocolException(new Problem { Type = $"urn:ietf:params:acme:error:{urnSuffix}", Detail = "detail-" + urnSuffix });

        [Fact]
        public async Task Backoff_SucceedsFirstTry_ReturnsResult()
        {
            var client = NewProtocolClient();
            var result = await client.Backoff(() => Task.FromResult(42), NullLogger.Instance);
            Assert.Equal(42, result);
        }

        [Fact]
        public async Task Backoff_RateLimited_ThrowsImmediatelyWithoutRetry()
        {
            var client = NewProtocolClient();
            var calls = 0;
            await Assert.ThrowsAsync<AcmeProtocolException>(() =>
                client.Backoff<int>(() =>
                {
                    calls++;
                    throw NewProblemException("rateLimited");
                }, NullLogger.Instance));
            Assert.Equal(1, calls);
        }

        [Fact]
        public async Task Backoff_TransientError_RetriesThenSucceeds()
        {
            var client = NewProtocolClient();
            var calls = 0;
            var result = await client.Backoff(() =>
            {
                calls++;
                if (calls < 3)
                    throw NewProblemException("serverInternal");
                return Task.FromResult(99);
            }, NullLogger.Instance);

            Assert.Equal(99, result);
            Assert.Equal(3, calls);
        }

        [Fact]
        public async Task Backoff_ExceedsMaxAttempts_ThrowsWrappedException()
        {
            var client = NewProtocolClient();
            var ex = await Assert.ThrowsAsync<Exception>(() =>
                client.Backoff<int>(() => throw NewProblemException("serverInternal"), NullLogger.Instance));
            Assert.Contains("too busy", ex.Message);
        }

        [Fact]
        public async Task Retry_RateLimited_RethrowsAcmeProtocolExceptionImmediately()
        {
            // RateLimited is the one AcmeProtocolException type Backoff rethrows verbatim (instead
            // of retrying/wrapping), so it is also the only type that reaches Retry's own
            // AcmeProtocolException catch block through the normal call path; that block's final
            // "log and rethrow" branch preserves it as-is.
            using var server = new FakeAcmeServer();
            var client = NewProtocolClient();
            client.Directory = new ServiceDirectory { NewNonce = server.BaseUrl + "new-nonce" };
            await client.GetNonceAsync(); // prime NextNonce so Retry doesn't need a live network nonce fetch

            var calls = 0;
            var ex = await Assert.ThrowsAsync<AcmeProtocolException>(() =>
                client.Retry<int>(() =>
                {
                    calls++;
                    throw NewProblemException("rateLimited");
                }, NullLogger.Instance));

            Assert.Equal(ProblemType.RateLimited, ex.ProblemType);
            Assert.Equal(1, calls);
        }

        [Fact]
        public async Task Retry_NonAcmeException_PropagatesAndReleasesLock()
        {
            using var server = new FakeAcmeServer();
            var client = NewProtocolClient();
            client.Directory = new ServiceDirectory { NewNonce = server.BaseUrl + "new-nonce" };
            await client.GetNonceAsync(); // prime NextNonce so Retry doesn't need a live network nonce fetch

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                client.Retry<int>(() => throw new InvalidOperationException("boom"), NullLogger.Instance));

            // Lock must have been released - a second call should not deadlock.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                client.Retry<int>(() => throw new InvalidOperationException("boom-again"), NullLogger.Instance));
        }

        [Fact]
        public async Task Retry_NextNonceInitiallyEmpty_FetchesNonceFirst()
        {
            // Exercises the `if (string.IsNullOrEmpty(client.NextNonce))` branch inside Retry,
            // which triggers the internal GetNonce() extension call - unlike other Retry tests,
            // NextNonce is never primed beforehand.
            using var server = new FakeAcmeServer();
            var client = NewProtocolClient();
            client.Directory = new ServiceDirectory { NewNonce = server.BaseUrl + "new-nonce" };

            var result = await client.Retry(() => Task.FromResult(123), NullLogger.Instance);

            Assert.Equal(123, result);
        }

        [Fact]
        public async Task Retry_BadNonce_RetriesWithFreshNonceThenSucceeds()
        {
            // Note: because Retry() wraps both the nonce fetch and the executor in a single
            // Backoff() call, a badNonce AcmeProtocolException is actually absorbed and retried
            // by Backoff's own generic retry loop (like any non-RateLimited protocol error)
            // before Retry's dedicated "BadNonce" catch branch would ever see it. This test
            // therefore verifies the end-to-end retry-then-succeed behavior of Retry() as a whole,
            // exercised via that Backoff retry path.
            using var server = new FakeAcmeServer();
            var client = NewProtocolClient();
            client.Directory = new ServiceDirectory { NewNonce = server.BaseUrl + "new-nonce" };
            await client.GetNonceAsync();

            var calls = 0;
            var result = await client.Retry(() =>
            {
                calls++;
                if (calls < 2)
                    throw NewProblemException("badNonce");
                return Task.FromResult(7);
            }, NullLogger.Instance);

            Assert.Equal(7, result);
            Assert.Equal(2, calls);
        }
    }
}
