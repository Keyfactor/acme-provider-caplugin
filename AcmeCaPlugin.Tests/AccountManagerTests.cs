using System;
using System.IO;
using System.Linq;
using ACMESharp.Protocol;
using Keyfactor.Extensions.CAPlugin.Acme.Clients.Acme;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.Acme.Tests
{
    public class AccountManagerTests : IDisposable
    {
        private readonly string _tempDir;

        public AccountManagerTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "AcmeCaPluginTests_" + Guid.NewGuid());
            Directory.CreateDirectory(_tempDir);
        }

        public void Dispose()
        {
            try { Directory.Delete(_tempDir, recursive: true); } catch { }
        }

        private AccountManager NewManager(string passphrase = null) =>
            new AccountManager(NullLogger.Instance, passphrase, _tempDir);

        [Fact]
        public void NewAccount_DefaultEs256_CreatesSigner()
        {
            var manager = NewManager();
            var account = manager.NewAccount();
            Assert.NotNull(account.Signer);
            Assert.Equal("ES256", account.Signer.KeyType);
        }

        [Fact]
        public void NewAccount_Rs256_CreatesSigner()
        {
            var manager = NewManager();
            var account = manager.NewAccount("RS256");
            Assert.Equal("RS256", account.Signer.KeyType);
        }

        [Fact]
        public void LoadDefaultAccount_NoneStored_ReturnsNull()
        {
            var manager = NewManager();
            var result = manager.LoadDefaultAccount("https://acme.example.com/directory");
            Assert.Null(result);
        }

        [Fact]
        public void StoreAccount_ThenLoadDefaultAccount_RoundTrips()
        {
            var manager = NewManager();
            var account = manager.NewAccount();
            account.Details = new AccountDetails { Kid = "https://acme.example.com/acct/42" };

            manager.StoreAccount(account, "https://acme.example.com/directory");

            var loaded = manager.LoadDefaultAccount("https://acme.example.com/directory");
            Assert.NotNull(loaded);
            Assert.Equal(account.Details.Kid, loaded.Details.Kid);
            Assert.Equal(account.Signer.KeyType, loaded.Signer.KeyType);
        }

        [Fact]
        public void StoreAccount_WithPassphrase_ThenLoad_RoundTrips()
        {
            var manager = NewManager(passphrase: "s3cr3t-passphrase");
            var account = manager.NewAccount();
            account.Details = new AccountDetails { Kid = "https://acme.example.com/acct/99" };

            manager.StoreAccount(account, "https://acme.example.com/directory");

            var loaded = manager.LoadDefaultAccount("https://acme.example.com/directory");
            Assert.NotNull(loaded);
            Assert.Equal(account.Details.Kid, loaded.Details.Kid);
        }

        [Fact]
        public void StoreAccount_NullAccount_LogsAndSkipsStorage()
        {
            var manager = NewManager();
            manager.StoreAccount(null, "https://acme.example.com/directory");
            Assert.Null(manager.LoadDefaultAccount("https://acme.example.com/directory"));
        }

        [Fact]
        public void LoadDefaultAccount_PointerFileIsWhitespace_ReturnsNull()
        {
            var manager = NewManager();
            var hostKey = manager.ExtractHostKey("https://acme.example.com/directory");
            File.WriteAllText(Path.Combine(_tempDir, $"default_{hostKey}.txt"), "   ");

            Assert.Null(manager.LoadDefaultAccount("https://acme.example.com/directory"));
        }

        [Fact]
        public void StoreAccount_NullKid_LogsAndSkipsStorage()
        {
            var manager = NewManager();
            var account = manager.NewAccount();
            account.Details = null;

            manager.StoreAccount(account, "https://acme.example.com/directory");

            Assert.Null(manager.LoadDefaultAccount("https://acme.example.com/directory"));
        }

        [Fact]
        public void ExtractHostKey_ReplacesDotsWithDashes()
        {
            var manager = NewManager();
            var result = manager.ExtractHostKey("https://acme.example.com/directory");
            Assert.Equal("acme-example-com", result);
        }

        [Fact]
        public void GetAccountDirectoryName_ValidKid_SanitizesAndCombines()
        {
            var manager = NewManager();
            var result = manager.GetAccountDirectoryName("https://acme.example.com/acct/123");
            Assert.Equal("acme-example-com_123", result);
        }

        [Fact]
        public void GetAccountDirectoryName_InvalidUrl_Throws()
        {
            var manager = NewManager();
            Assert.ThrowsAny<Exception>(() => manager.GetAccountDirectoryName("not a url"));
        }

        [Fact]
        public void LoadAccount_MissingFiles_ReturnsNull()
        {
            var manager = NewManager();
            var result = manager.LoadAccount("nonexistent-folder");
            Assert.Null(result);
        }

        [Fact]
        public void ListAccountDirectories_NoBasePath_ReturnsEmpty()
        {
            var freshDir = Path.Combine(_tempDir, "does-not-exist-yet");
            var manager = new AccountManager(NullLogger.Instance, null, freshDir);
            Assert.Empty(manager.ListAccountDirectories());
        }

        [Fact]
        public void ListAccountDirectories_AfterStoringAccount_ListsFolder()
        {
            var manager = NewManager();
            var account = manager.NewAccount();
            account.Details = new AccountDetails { Kid = "https://acme.example.com/acct/7" };
            manager.StoreAccount(account, "https://acme.example.com/directory");

            var dirs = manager.ListAccountDirectories().ToList();
            Assert.Contains("acme-example-com_7", dirs);
        }

        [Fact]
        public void Constructor_NoStoragePath_UsesAppDataOrCurrentDirectoryFallback()
        {
            // Exercises the branch computing a default storage path when none is supplied.
            var manager = new AccountManager(NullLogger.Instance, null, storagePath: null);
            Assert.NotNull(manager);
        }

        [Fact]
        public void LoadSigner_CorruptFile_ReturnsNullAccountGracefully()
        {
            var manager = NewManager();
            var account = manager.NewAccount();
            account.Details = new AccountDetails { Kid = "https://acme.example.com/acct/55" };
            manager.StoreAccount(account, "https://acme.example.com/directory");

            var folder = manager.GetAccountDirectoryName(account.Details.Kid);
            var signerPath = Path.Combine(_tempDir, folder, "Signer_v2");
            File.WriteAllText(signerPath, "{not valid json");

            var loaded = manager.LoadAccount(folder);
            Assert.Null(loaded);
        }
    }
}
