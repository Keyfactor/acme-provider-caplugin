using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.Acme.Clients.Acme;
using Keyfactor.Extensions.CAPlugin.Acme.Tests.Fakes;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.Acme.Tests
{
    /// <summary>
    /// Exercises AcmeClientManager end-to-end against an in-process fake ACME server over real
    /// loopback HTTP (see FakeAcmeServer), since AcmeProtocolClient/AcmeClientManager have no
    /// injectable HttpMessageHandler seam and constructing valid signed protocol traffic by hand
    /// would just re-implement the library.
    /// </summary>
    public class AcmeClientManagerTests : IDisposable
    {
        private readonly string _tempDir;

        public AcmeClientManagerTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "AcmeClientManagerTests_" + Guid.NewGuid());
            Directory.CreateDirectory(_tempDir);
        }

        public void Dispose()
        {
            try { Directory.Delete(_tempDir, recursive: true); } catch { }
        }

        private AcmeClientConfig NewConfig(string directoryUrl, string eabKid = null, string eabHmac = null) => new AcmeClientConfig
        {
            Enabled = true,
            DirectoryUrl = directoryUrl,
            Email = "test@example.com",
            AccountStoragePath = _tempDir,
            EabKid = eabKid,
            EabHmacKey = eabHmac
        };

        [Fact]
        public async Task CreateClientAsync_NoCachedAccount_CreatesNewAccount()
        {
            using var server = new FakeAcmeServer();
            using var httpClient = new HttpClient();
            var manager = new AcmeClientManager(NullLogger.Instance, NewConfig(server.DirectoryUrl), httpClient);

            var (client, account, signer) = await manager.CreateClientAsync();

            Assert.NotNull(client);
            Assert.NotNull(account);
            Assert.NotNull(signer);
            Assert.Equal(1, server.NewAccountCallCount);
        }

        [Fact]
        public async Task CreateClientAsync_SecondCall_UsesCachedAccount_SkipsNewAccountCall()
        {
            using var server = new FakeAcmeServer();
            var config = NewConfig(server.DirectoryUrl);

            using (var httpClient1 = new HttpClient())
            {
                var manager1 = new AcmeClientManager(NullLogger.Instance, config, httpClient1);
                await manager1.CreateClientAsync();
            }

            Assert.Equal(1, server.NewAccountCallCount);

            using var httpClient2 = new HttpClient();
            var manager2 = new AcmeClientManager(NullLogger.Instance, config, httpClient2);
            var (client, account, signer) = await manager2.CreateClientAsync();

            Assert.NotNull(client);
            Assert.NotNull(account);
            // No additional new-acct call - cached account was reused.
            Assert.Equal(1, server.NewAccountCallCount);
        }

        [Fact]
        public async Task CreateClientAsync_WithEabConfigured_SendsEabAndCreatesAccount()
        {
            using var server = new FakeAcmeServer();
            using var httpClient = new HttpClient();
            var eabHmac = ACMESharp.Crypto.CryptoHelper.Base64.UrlEncode(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
            var manager = new AcmeClientManager(NullLogger.Instance, NewConfig(server.DirectoryUrl, "eab-kid-1", eabHmac), httpClient);

            var (client, account, signer) = await manager.CreateClientAsync();

            Assert.NotNull(client);
            Assert.NotNull(account);
            Assert.Equal(1, server.NewAccountCallCount);
        }

        [Fact]
        public async Task CreateClientAsync_ServerRejectsNewAccount_Throws()
        {
            using var server = new FakeAcmeServer { FailNewAccount = true };
            using var httpClient = new HttpClient();
            var manager = new AcmeClientManager(NullLogger.Instance, NewConfig(server.DirectoryUrl), httpClient);

            await Assert.ThrowsAnyAsync<Exception>(async () => await manager.CreateClientAsync());
        }

        [Fact]
        public async Task CreateClientAsync_CorruptCachedSigner_FallsBackToCreatingNewAccount()
        {
            // Prime a cached "default account" pointer file whose signer JWK is garbage, forcing
            // AcmeProtocolClient construction inside TryLoadCachedAccountAsync to fail and hitting
            // its catch-and-fallback branch.
            using var server = new FakeAcmeServer();
            var config = NewConfig(server.DirectoryUrl);

            var accountManager = new Keyfactor.Extensions.CAPlugin.Acme.Clients.Acme.AccountManager(
                Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, null, _tempDir);
            var hostKey = accountManager.ExtractHostKey(server.DirectoryUrl);
            var folder = "corrupt-account";
            System.IO.Directory.CreateDirectory(System.IO.Path.Combine(_tempDir, folder));
            System.IO.File.WriteAllText(System.IO.Path.Combine(_tempDir, folder, "Registration_v2"), "{\"Kid\":\"https://x/acct/1\"}");
            System.IO.File.WriteAllText(System.IO.Path.Combine(_tempDir, folder, "Signer_v2"), "{\"KeyType\":\"ES256\",\"KeyExport\":\"not-valid-jwk-json\"}");
            System.IO.File.WriteAllText(System.IO.Path.Combine(_tempDir, $"default_{hostKey}.txt"), folder);

            using var httpClient = new HttpClient();
            var manager = new AcmeClientManager(NullLogger.Instance, config, httpClient);

            var (client, account, signer) = await manager.CreateClientAsync();

            Assert.NotNull(client);
            Assert.NotNull(account);
            Assert.Equal(1, server.NewAccountCallCount); // fell back to creating a brand-new account
        }

        [Fact]
        public void Constructor_NullLogger_Throws()
        {
            using var httpClient = new HttpClient();
            Assert.Throws<ArgumentNullException>(() =>
                new AcmeClientManager(null, NewConfig("https://example.com/directory"), httpClient));
        }

        [Fact]
        public void Constructor_NullHttpClient_Throws()
        {
            Assert.Throws<ArgumentNullException>(() =>
                new AcmeClientManager(NullLogger.Instance, NewConfig("https://example.com/directory"), null));
        }

        [Fact]
        public void Constructor_NullConfig_Throws()
        {
            using var httpClient = new HttpClient();
            Assert.Throws<ArgumentNullException>(() =>
                new AcmeClientManager(NullLogger.Instance, null, httpClient));
        }
    }
}
