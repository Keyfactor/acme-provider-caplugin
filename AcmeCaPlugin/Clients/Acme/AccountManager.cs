using ACMESharp.Protocol;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Keyfactor.Extensions.CAPlugin.Acme.Clients.Acme
{
    /// <summary>
    /// Manages ACME account storage, retrieval, and default account handling.
    /// Handles account persistence to the file system and provides methods for
    /// creating, loading, and storing ACME accounts with their associated signers.
    /// </summary>
    class AccountManager
    {
        #region Constants

        private const string SignerFileName = "Signer_v2";
        private const string RegistrationFileName = "Registration_v2";
        private const string DefaultAccountPointer = "default.txt";

        #endregion

        #region Fields

        private readonly ILogger _log;
        private readonly string _basePath;
        private readonly string _passphrase;

        private readonly JsonSerializerOptions _jsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };

        #endregion

        #region Constructor

        public AccountManager(ILogger log, string passphrase = null)
        {
            _log = log;
            _passphrase = passphrase;
            _basePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "AcmeAccounts");
        }

        #endregion

        #region Public Methods

        internal Account NewAccount(string keyType = "ES256")
        {
            AccountSigner signer;
            try
            {
                signer = NewSigner(keyType);
            }
            catch (CryptographicException cex)
            {
                if (keyType == "ES256")
                {
                    _log.LogTrace("ES256 key generation failed, falling back to RS256: {error}", cex.Message);
                    signer = NewSigner("RS256");
                }
                else
                {
                    throw;
                }
            }

            return new Account(default, signer);
        }

        internal Account LoadDefaultAccount(string directoryUrl)
        {
            var hostKey = ExtractHostKey(directoryUrl);
            var defaultFile = Path.Combine(_basePath, $"default_{hostKey}.txt");

            if (File.Exists(defaultFile))
            {
                var accountId = File.ReadAllText(defaultFile).Trim();
                if (!string.IsNullOrWhiteSpace(accountId))
                {
                    return LoadAccount(accountId);
                }
            }

            return null;
        }

        internal void SetDefaultAccount(string directoryUrl, string accountId)
        {
            var hostKey = ExtractHostKey(directoryUrl);
            var defaultFile = Path.Combine(_basePath, $"default_{hostKey}.txt");
            File.WriteAllText(defaultFile, accountId);
        }

        internal Account LoadAccount(string folderName)
        {
            var dir = EnsureAccountDirectory(folderName);
            var signerPath = Path.Combine(dir, SignerFileName);
            var detailsPath = Path.Combine(dir, RegistrationFileName);

            var signer = LoadSigner(signerPath);
            var details = LoadDetails(detailsPath);

            if (details == default || signer == null)
            {
                return null;
            }

            return new Account(details, signer);
        }

        internal void StoreAccount(Account account, string directoryUrl)
        {
            if (account?.Details?.Kid == null)
            {
                _log.LogError("Account Kid is null, cannot determine storage location.");
                return;
            }

            var folderName = GetAccountDirectoryName(account.Details.Kid);
            var dir = EnsureAccountDirectory(folderName);
            var signerPath = Path.Combine(dir, SignerFileName);
            var detailsPath = Path.Combine(dir, RegistrationFileName);

            StoreDetails(account.Details, detailsPath);
            StoreSigner(account.Signer, signerPath);

            SetDefaultAccount(directoryUrl, folderName);
        }

        internal IEnumerable<string> ListAccountDirectories()
        {
            if (!Directory.Exists(_basePath))
                yield break;

            var baseDir = new DirectoryInfo(_basePath);
            foreach (var dir in baseDir.GetDirectories())
            {
                var regPath = Path.Combine(dir.FullName, RegistrationFileName);
                if (File.Exists(regPath))
                    yield return dir.Name;
            }
        }

        #endregion

        #region Private Helper Methods

        private AccountSigner NewSigner(string keyType)
        {
            _log.LogDebug("Creating new {keyType} signer", keyType);
            return new AccountSigner(keyType);
        }

        public string ExtractHostKey(string directoryUrl)
        {
            return new Uri(directoryUrl).Host.Replace(".", "-");
        }

        public string GetAccountDirectoryName(string kidUrl)
        {
            try
            {
                var uri = new Uri(kidUrl);
                var accountId = uri.Segments[^1].Trim('/');
                var hostPart = uri.Host.Replace(".", "-");
                return SanitizeFileName($"{hostPart}_{accountId}");
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Invalid kid URL: {kidUrl}", kidUrl);
                throw;
            }
        }

        private string EnsureAccountDirectory(string folderName)
        {
            var accountDir = Path.Combine(_basePath, folderName);
            if (!Directory.Exists(accountDir))
            {
                _log.LogDebug("Creating account directory: {accountDir}", accountDir);
                Directory.CreateDirectory(accountDir);
            }
            return accountDir;
        }

        private string SanitizeFileName(string input)
        {
            foreach (var c in Path.GetInvalidFileNameChars())
                input = input.Replace(c, '_');
            return input;
        }

        private AccountSigner LoadSigner(string path)
        {
            if (!File.Exists(path))
            {
                _log.LogDebug("Signer not found at {signerPath}", path);
                return null;
            }

            try
            {
                _log.LogDebug("Loading signer from {signerPath}", path);
                var data = File.ReadAllBytes(path);

                string json;
                if (!string.IsNullOrEmpty(_passphrase))
                {
                    json = Decrypt(data, _passphrase);
                }
                else
                {
                    json = Encoding.UTF8.GetString(data);
                }

                return JsonSerializer.Deserialize<AccountSigner>(json, _jsonOptions);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Unable to load signer from {path}", path);
                return null;
            }
        }

        private void StoreSigner(AccountSigner signer, string path)
        {
            if (signer != null)
            {
                _log.LogDebug("Saving signer to {SignerPath}", path);
                var json = JsonSerializer.Serialize(signer, _jsonOptions);
                byte[] data;

                if (!string.IsNullOrEmpty(_passphrase))
                {
                    data = Encrypt(json, _passphrase);
                }
                else
                {
                    data = Encoding.UTF8.GetBytes(json);
                }

                File.WriteAllBytes(path, data);
            }
        }

        private AccountDetails LoadDetails(string path)
        {
            if (!File.Exists(path))
                return default;

            try
            {
                _log.LogDebug("Loading account details from {path}", path);
                return JsonSerializer.Deserialize<AccountDetails>(
                    File.ReadAllText(path), _jsonOptions);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Unable to load account details from {path}", path);
                return default;
            }
        }

        private void StoreDetails(AccountDetails details, string path)
        {
            if (details != default)
            {
                _log.LogDebug("Saving account details to {AccountPath}", path);
                File.WriteAllText(path, JsonSerializer.Serialize(details, _jsonOptions));
            }
        }

        #endregion

        #region AES Cross-Platform Encrypt/Decrypt

        private static byte[] Encrypt(string plaintext, string passphrase)
        {
            using var aes = Aes.Create();
            byte[] salt = new byte[16];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);

            using var derive = new Rfc2898DeriveBytes(passphrase, salt, 10000);
            aes.Key = derive.GetBytes(32);
            aes.IV = derive.GetBytes(16);

            using var ms = new MemoryStream();
            ms.Write(salt, 0, salt.Length);
            ms.Write(aes.IV, 0, aes.IV.Length);

            using var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
            using var writer = new StreamWriter(cs);
            writer.Write(plaintext);
            writer.Flush();
            cs.FlushFinalBlock();
            return ms.ToArray();
        }

        private static string Decrypt(byte[] data, string passphrase)
        {
            using var ms = new MemoryStream(data);

            byte[] salt = new byte[16];
            ms.Read(salt, 0, salt.Length);

            byte[] iv = new byte[16];
            ms.Read(iv, 0, iv.Length);

            using var aes = Aes.Create();
            using var derive = new Rfc2898DeriveBytes(passphrase, salt, 10000);
            aes.Key = derive.GetBytes(32);
            aes.IV = iv;

            using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var reader = new StreamReader(cs);
            return reader.ReadToEnd();
        }

        #endregion
    }
}
