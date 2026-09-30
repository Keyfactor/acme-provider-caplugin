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
    /// Exercises the internal AcmeClient class (accessible via InternalsVisibleTo) against the
    /// in-process FakeAcmeServer over real loopback HTTP.
    /// </summary>
    public class AcmeClientTests
    {
        private static (AcmeClient client, FakeAcmeServer server, HttpClient http) NewClient(
            Action<FakeAcmeServer> configure = null)
        {
            var server = new FakeAcmeServer();
            configure?.Invoke(server);
            var http = new HttpClient { BaseAddress = new Uri(server.BaseUrl) };
            var signer = new ESJwsTool { HashSize = 256 };
            signer.Init();
            var accountSigner = new AccountSigner(signer);
            var directory = new ServiceDirectory
            {
                NewNonce = server.BaseUrl + "new-nonce",
                NewAccount = server.BaseUrl + "new-acct",
                NewOrder = server.BaseUrl + "new-order",
                RevokeCert = server.BaseUrl + "revoke-cert",
            };
            var config = new AcmeClientConfig { DirectoryUrl = server.DirectoryUrl };
            var account = new Clients.Acme.Account(new AccountDetails { Kid = server.BaseUrl + "acct/1" }, accountSigner);
            var client = new AcmeClient(NullLogger.Instance, config, http, directory, account);
            return (client, server, http);
        }

        [Fact]
        public void Constructor_NullLogger_Throws()
        {
            var (_, server, http) = NewClient();
            var signer = new ESJwsTool { HashSize = 256 };
            signer.Init();
            var account = new Clients.Acme.Account(new AccountDetails(), new AccountSigner(signer));
            Assert.Throws<ArgumentNullException>(() =>
                new AcmeClient(null, new AcmeClientConfig(), http, new ServiceDirectory(), account));
        }

        [Fact]
        public void Constructor_NullConfig_Throws()
        {
            var http = new HttpClient();
            var signer = new ESJwsTool { HashSize = 256 };
            signer.Init();
            var account = new Clients.Acme.Account(new AccountDetails(), new AccountSigner(signer));
            Assert.Throws<ArgumentNullException>(() =>
                new AcmeClient(NullLogger.Instance, null, http, new ServiceDirectory(), account));
        }

        [Fact]
        public void Constructor_NullHttpClient_Throws()
        {
            var signer = new ESJwsTool { HashSize = 256 };
            signer.Init();
            var account = new Clients.Acme.Account(new AccountDetails(), new AccountSigner(signer));
            Assert.Throws<ArgumentNullException>(() =>
                new AcmeClient(NullLogger.Instance, new AcmeClientConfig(), null, new ServiceDirectory(), account));
        }

        [Fact]
        public void Constructor_NullAccount_Throws()
        {
            var http = new HttpClient();
            Assert.Throws<ArgumentNullException>(() =>
                new AcmeClient(NullLogger.Instance, new AcmeClientConfig(), http, new ServiceDirectory(), null));
        }

        [Fact]
        public async Task CreateOrderAsync_Success_ReturnsOrderDetails()
        {
            var (client, server, http) = NewClient();
            using (server) using (http) using (client)
            {
                var order = await client.CreateOrderAsync(new[] { new Identifier { Type = "dns", Value = "example.com" } });
                Assert.Equal("ready", order.Payload.Status);
                Assert.NotNull(order.OrderUrl);
            }
        }

        [Fact]
        public async Task CreateOrderAsync_NoLocationHeader_OrderUrlIsNull()
        {
            var (client, server, http) = NewClient(s => s.OmitNewOrderLocationHeader = true);
            using (server) using (http) using (client)
            {
                var order = await client.CreateOrderAsync(new[] { new Identifier { Type = "dns", Value = "example.com" } });
                Assert.Null(order.OrderUrl);
                Assert.Equal("ready", order.Payload.Status);
            }
        }

        [Fact]
        public async Task GetCertificateAsync_NullPayload_ThrowsInvalidOperationException()
        {
            var (client, server, http) = NewClient();
            using (server) using (http) using (client)
            {
                var order = new OrderDetails { OrderUrl = server.BaseUrl + "order/1", Payload = null };
                await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetCertificateAsync(order));
            }
        }

        [Fact]
        public async Task CreateOrderAsync_ServerError_Throws()
        {
            var (client, server, http) = NewClient(s => s.FailNewOrder = true);
            using (server) using (http) using (client)
            {
                await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    client.CreateOrderAsync(new[] { new Identifier { Type = "dns", Value = "example.com" } }));
            }
        }

        [Fact]
        public async Task GetAuthorizationAsync_Success_ReturnsAuthorization()
        {
            var (client, server, http) = NewClient();
            using (server) using (http) using (client)
            {
                var authz = await client.GetAuthorizationAsync(server.BaseUrl + "authz/1");
                Assert.Equal("valid", authz.Status);
                Assert.Equal("example.com", authz.Identifier.Value);
                Assert.Single(authz.Challenges);
            }
        }

        [Fact]
        public async Task DecodeChallengeValidation_Dns01_ReturnsDetails()
        {
            var (client, server, http) = NewClient();
            using (server) using (http) using (client)
            {
                var authz = await client.GetAuthorizationAsync(server.BaseUrl + "authz/1");
                var challenge = authz.Challenges[0];
                var details = client.DecodeChallengeValidation(authz, challenge);
                Assert.Equal("dns-01", details.ChallengeType);
            }
        }

        [Fact]
        public void DecodeChallengeValidation_MissingChallengeType_Throws()
        {
            var (client, server, http) = NewClient();
            using (server) using (http) using (client)
            {
                var authz = new Authorization { Identifier = new Identifier { Type = "dns", Value = "example.com" } };
                var challenge = new Challenge { Type = null };
                Assert.Throws<NotSupportedException>(() => client.DecodeChallengeValidation(authz, challenge));
            }
        }

        [Fact]
        public async Task AnswerChallengeAsync_ValidChallenge_ReturnsCompletedChallenge()
        {
            var (client, server, http) = NewClient();
            using (server) using (http) using (client)
            {
                var challenge = new Challenge { Url = server.BaseUrl + "chal/1", Type = "dns-01" };
                var result = await client.AnswerChallengeAsync(challenge);
                Assert.Equal("valid", result.Status);
            }
        }

        [Fact]
        public async Task AnswerChallengeAsync_MissingUrl_Throws()
        {
            var (client, server, http) = NewClient();
            using (server) using (http) using (client)
            {
                var challenge = new Challenge { Url = null };
                await Assert.ThrowsAsync<NotSupportedException>(() => client.AnswerChallengeAsync(challenge));
            }
        }

        [Fact]
        public async Task AnswerChallengeAsync_PendingThenValid_PollsUntilComplete()
        {
            var (client, server, http) = NewClient(s => s.ChallengeStatus = "pending");
            using (server) using (http) using (client)
            {
                // Flip to valid shortly after the first submission to exercise the polling loop.
                _ = Task.Run(async () =>
                {
                    await Task.Delay(300);
                    server.ChallengeStatus = "valid";
                });

                var challenge = new Challenge { Url = server.BaseUrl + "chal/1", Type = "dns-01" };
                var result = await client.AnswerChallengeAsync(challenge);
                Assert.Equal("valid", result.Status);
            }
        }

        [Fact]
        public async Task AnswerChallengeAsync_StaysPendingForever_ReturnsPendingAfterExhaustingRetriesWithoutThrowing()
        {
            var (client, server, http) = NewClient(s => s.ChallengeStatus = "pending");
            using (server) using (http) using (client)
            {
                var challenge = new Challenge { Url = server.BaseUrl + "chal/1", Type = "dns-01" };
                var result = await client.AnswerChallengeAsync(challenge);
                Assert.Equal("pending", result.Status);
            }
        }

        [Fact]
        public async Task AnswerChallengeAsync_ChallengeBecomesInvalidWithError_LogsAndReturnsInvalid()
        {
            var (client, server, http) = NewClient(s =>
            {
                s.ChallengeStatus = "invalid";
                s.ChallengeErrorDetail = "no TXT record found";
            });
            using (server) using (http) using (client)
            {
                var challenge = new Challenge { Url = server.BaseUrl + "chal/1", Type = "dns-01" };
                var result = await client.AnswerChallengeAsync(challenge);
                Assert.Equal("invalid", result.Status);
                Assert.NotNull(result.Error);
            }
        }

        [Fact]
        public async Task FinalizeOrderAsync_ReadyOrder_ReturnsValidWithCertificate()
        {
            var (client, server, http) = NewClient();
            using (server) using (http) using (client)
            {
                var order = await client.CreateOrderAsync(new[] { new Identifier { Type = "dns", Value = "example.com" } });
                var finalized = await client.FinalizeOrderAsync(order, new byte[] { 1, 2, 3 });
                Assert.Equal("valid", finalized.Payload.Status);
                Assert.NotNull(finalized.Payload.Certificate);
            }
        }

        [Fact]
        public async Task FinalizeOrderAsync_OrderNotReady_ReturnsUnchangedOrder()
        {
            var (client, server, http) = NewClient(s => s.OrderStatus = "pending");
            using (server) using (http) using (client)
            {
                var order = await client.CreateOrderAsync(new[] { new Identifier { Type = "dns", Value = "example.com" } });
                var finalized = await client.FinalizeOrderAsync(order, new byte[] { 1, 2, 3 });
                Assert.Equal("pending", finalized.Payload.Status);
            }
        }

        [Fact]
        public async Task GetCertificateAsync_Success_ReturnsBytes()
        {
            var (client, server, http) = NewClient();
            using (server) using (http) using (client)
            {
                var order = await client.CreateOrderAsync(new[] { new Identifier { Type = "dns", Value = "example.com" } });
                var finalized = await client.FinalizeOrderAsync(order, new byte[] { 1, 2, 3 });
                var bytes = await client.GetCertificateAsync(finalized);
                Assert.NotEmpty(bytes);
            }
        }

        [Fact]
        public async Task GetCertificateAsync_MissingCertificateUrl_Throws()
        {
            var (client, server, http) = NewClient();
            using (server) using (http) using (client)
            {
                var order = new OrderDetails { OrderUrl = server.BaseUrl + "order/1", Payload = new Order { Status = "valid", Certificate = null } };
                await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetCertificateAsync(order));
            }
        }

        [Fact]
        public async Task GetAuthorizationAsync_ServerError_Throws()
        {
            var (client, server, http) = NewClient(s => s.FailGetAuthz = true);
            using (server) using (http) using (client)
            {
                await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetAuthorizationAsync(server.BaseUrl + "authz/1"));
            }
        }

        [Fact]
        public async Task AnswerChallengeAsync_ServerRejectsSubmission_Throws()
        {
            var (client, server, http) = NewClient(s => s.FailAnswerChallenge = true);
            using (server) using (http) using (client)
            {
                var challenge = new Challenge { Url = server.BaseUrl + "chal/1", Type = "dns-01" };
                await Assert.ThrowsAsync<InvalidOperationException>(() => client.AnswerChallengeAsync(challenge));
            }
        }

        [Fact]
        public async Task AnswerChallengeAsync_PollingFailsRepeatedly_RethrowsAfterMaxRetries()
        {
            var (client, server, http) = NewClient(s =>
            {
                s.ChallengeStatus = "pending";
                s.FailChallengePollsAfterSubmit = true;
            });
            using (server) using (http) using (client)
            {
                var challenge = new Challenge { Url = server.BaseUrl + "chal/1", Type = "dns-01" };
                await Assert.ThrowsAsync<InvalidOperationException>(() => client.AnswerChallengeAsync(challenge));
            }
        }

        [Fact]
        public async Task GetOrderDetailsAsync_ServerError_Throws()
        {
            var (client, server, http) = NewClient(s => s.FailGetOrder = true);
            using (server) using (http) using (client)
            {
                await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetOrderDetailsAsync(server.BaseUrl + "order/1"));
            }
        }

        [Fact]
        public async Task FinalizeOrderAsync_MissingFinalizeUrl_Throws()
        {
            var (client, server, http) = NewClient(s => s.OmitFinalizeUrl = true);
            using (server) using (http) using (client)
            {
                var order = await client.CreateOrderAsync(new[] { new Identifier { Type = "dns", Value = "example.com" } });
                await Assert.ThrowsAsync<InvalidOperationException>(() => client.FinalizeOrderAsync(order, new byte[] { 1 }));
            }
        }

        [Fact]
        public async Task GetCertificateAsync_ServerError_Throws()
        {
            var (client, server, http) = NewClient(s => s.FailCertificate = true);
            using (server) using (http) using (client)
            {
                var order = await client.CreateOrderAsync(new[] { new Identifier { Type = "dns", Value = "example.com" } });
                var finalized = await client.FinalizeOrderAsync(order, new byte[] { 1, 2, 3 });
                await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetCertificateAsync(finalized));
            }
        }

        [Fact]
        public async Task CreateOrderAsync_BadNonceOnceThenSucceeds_RetriesWithFreshNonce()
        {
            var (client, server, http) = NewClient(s => s.BadNonceFailuresRemaining = 1);
            using (server) using (http) using (client)
            {
                var order = await client.CreateOrderAsync(new[] { new Identifier { Type = "dns", Value = "example.com" } });
                Assert.Equal("ready", order.Payload.Status);
            }
        }

        [Fact]
        public async Task FinalizeOrderAsync_NoOrderUrl_UsesCurrentStatusOnly()
        {
            var (client, server, http) = NewClient();
            using (server) using (http) using (client)
            {
                var order = new OrderDetails
                {
                    OrderUrl = null,
                    Payload = new Order { Status = "ready", Finalize = server.BaseUrl + "finalize/1" }
                };
                var finalized = await client.FinalizeOrderAsync(order, new byte[] { 1, 2, 3 });
                Assert.Equal("valid", finalized.Payload.Status);
            }
        }

        [Fact]
        public async Task FinalizeOrderAsync_TransientOrderLookupFailure_RecoversAndSucceeds()
        {
            // The order starts "pending" so FinalizeOrderAsync's initial WaitForOrderStatusAsync
            // poll loop runs; the first poll attempt fails transiently (exercising the
            // catch-and-continue-without-rethrow branch) before a later poll succeeds with "ready".
            var (client, server, http) = NewClient(s =>
            {
                s.OrderStatus = "pending";
                s.FailGetOrderTimes = 1;
            });
            using (server) using (http) using (client)
            {
                var order = await client.CreateOrderAsync(new[] { new Identifier { Type = "dns", Value = "example.com" } });

                // Flip to "ready" shortly after creation so the recovering poll observes it.
                _ = Task.Run(async () =>
                {
                    await Task.Delay(500);
                    server.OrderStatus = "ready";
                });

                var finalized = await client.FinalizeOrderAsync(order, new byte[] { 1, 2, 3 });
                Assert.Equal("valid", finalized.Payload.Status);
            }
        }

        [Fact]
        public async Task FinalizeOrderAsync_EmptyStatusPollThenReady_ContinuesPolling()
        {
            var (client, server, http) = NewClient(s =>
            {
                s.OrderStatus = "pending";
                s.EmptyOrderStatusTimes = 1;
            });
            using (server) using (http) using (client)
            {
                var order = await client.CreateOrderAsync(new[] { new Identifier { Type = "dns", Value = "example.com" } });

                _ = Task.Run(async () =>
                {
                    await Task.Delay(500);
                    server.OrderStatus = "ready";
                });

                var finalized = await client.FinalizeOrderAsync(order, new byte[] { 1, 2, 3 });
                Assert.Equal("valid", finalized.Payload.Status);
            }
        }

        [Fact(Timeout = 60000)]
        public async Task FinalizeOrderAsync_PersistentOrderLookupFailures_RethrowsAfterHalfMaxRetries()
        {
            var (client, server, http) = NewClient(s =>
            {
                s.OrderStatus = "pending";
                s.FailGetOrderTimes = int.MaxValue;
            });
            using (server) using (http) using (client)
            {
                var order = await client.CreateOrderAsync(new[] { new Identifier { Type = "dns", Value = "example.com" } });
                await Assert.ThrowsAsync<InvalidOperationException>(() => client.FinalizeOrderAsync(order, new byte[] { 1 }));
            }
        }

        [Fact]
        public async Task CreateOrderAsync_WithNotAfter_Success()
        {
            var (client, server, http) = NewClient();
            using (server) using (http) using (client)
            {
                var order = await client.CreateOrderAsync(
                    new[] { new Identifier { Type = "dns", Value = "example.com" } },
                    DateTime.UtcNow.AddDays(90));
                Assert.Equal("ready", order.Payload.Status);
            }
        }

        [Fact]
        public async Task GetOrderDetailsAsync_Success_ReturnsPayload()
        {
            var (client, server, http) = NewClient();
            using (server) using (http) using (client)
            {
                var details = await client.GetOrderDetailsAsync(server.BaseUrl + "order/1");
                Assert.Equal("ready", details.Payload.Status);
            }
        }

        [Fact]
        public async Task FinalizeOrderAsync_OrderAlreadyInvalid_Throws()
        {
            var (client, server, http) = NewClient(s => s.OrderStatus = "invalid");
            using (server) using (http) using (client)
            {
                var order = new OrderDetails
                {
                    OrderUrl = server.BaseUrl + "order/1",
                    Payload = new Order { Status = "invalid", Finalize = server.BaseUrl + "finalize/1" }
                };
                await Assert.ThrowsAsync<InvalidOperationException>(() => client.FinalizeOrderAsync(order, new byte[] { 1 }));
            }
        }

        [Fact]
        public async Task RevokeCertificateAsync_Success_ReturnsTrue()
        {
            var (client, server, http) = NewClient();
            using (server) using (http) using (client)
            {
                var result = await client.RevokeCertificateAsync(new byte[] { 1, 2, 3 });
                Assert.True(result);
            }
        }

        [Fact]
        public async Task RevokeCertificateAsync_ServerRejects_ThrowsInvalidOperationException()
        {
            var (client, server, http) = NewClient(s => s.FailRevoke = true);
            using (server) using (http) using (client)
            {
                await Assert.ThrowsAsync<InvalidOperationException>(() => client.RevokeCertificateAsync(new byte[] { 1, 2, 3 }));
            }
        }

        [Fact]
        public void GetCertificateIdentifier_ValidCertificateInfo_ReturnsKeyAuthAndSerial()
        {
            var certInfo = X509TestFixture.BuildCertificateInfo();
            var identifier = AcmeClient.GetCertificateIdentifier(certInfo);
            Assert.Contains(".", identifier);
        }

        [Fact]
        public void GetCertificateIdentifier_MissingAuthorityKeyIdentifierExtension_ThrowsInvalidOperationException()
        {
            var certInfo = X509TestFixture.BuildCertificateInfoWithoutAuthorityKeyIdentifier();
            Assert.Throws<InvalidOperationException>(() => AcmeClient.GetCertificateIdentifier(certInfo));
        }

        [Fact]
        public void Dispose_MultipleCalls_DoesNotThrow()
        {
            var (client, server, http) = NewClient();
            using (server) using (http)
            {
                client.Dispose();
                client.Dispose();
            }
        }
    }
}
