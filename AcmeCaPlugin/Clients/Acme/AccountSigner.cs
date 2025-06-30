using ACMESharp.Crypto.JOSE;
using ACMESharp.Crypto.JOSE.Impl;
using System;

namespace Keyfactor.Extensions.CAPlugin.Acme.Clients.Acme
{
    /// <summary>
    /// Represents the cryptographic signing component of an ACME account.
    /// This class manages the private key used for ACME protocol authentication
    /// and can handle both RSA and Elliptic Curve key types.
    /// Acts as the "password" for ACME account operations.
    /// </summary>
    public class AccountSigner
    {
        #region Fields

        /// <summary>The cryptographic algorithm type (e.g., ES256, RS256)</summary>
        private string _keyType;

        /// <summary>Serialized key data for persistence</summary>
        private string _keyExport;

        /// <summary>Cached JWS tool instance to avoid recreation</summary>
        private IJwsTool _jwsTool;

        #endregion

        #region Constructors

        /// <summary>
        /// Default constructor for serialization/deserialization scenarios.
        /// Creates an uninitialized AccountSigner that must be configured before use.
        /// </summary>
        public AccountSigner()
        {
        }

        /// <summary>
        /// Creates a new AccountSigner with the specified key type.
        /// Automatically generates a new key pair for the specified algorithm.
        /// </summary>
        /// <param name="keyType">The signing algorithm type (ES256, ES384, ES512, RS256, etc.)</param>
        /// <exception cref="Exception">Thrown if the key type is unsupported or key generation fails</exception>
        public AccountSigner(string keyType)
        {
            KeyType = keyType;
            KeyExport = JwsTool().Export();
        }

        /// <summary>
        /// Creates an AccountSigner from an existing JWS tool.
        /// Useful for converting existing cryptographic tools to AccountSigner instances.
        /// </summary>
        /// <param name="source">The source JWS tool containing the key material</param>
        /// <exception cref="ArgumentNullException">Thrown if source is null</exception>
        public AccountSigner(IJwsTool source)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));

            KeyType = source.JwsAlg;
            KeyExport = source.Export();
        }

        #endregion

        #region Properties

        /// <summary>
        /// Gets or sets the cryptographic signature algorithm type.
        /// Supported values include ES256, ES384, ES512 (Elliptic Curve) and RS256 (RSA).
        /// Setting this property invalidates the cached JWS tool.
        /// </summary>
        /// <value>The signature algorithm identifier (default: ES256)</value>
        public string KeyType
        {
            get => _keyType;
            set
            {
                _keyType = value;
                _jwsTool = null; // Invalidate cached tool when key type changes
            }
        }

        /// <summary>
        /// Gets or sets the serialized key data for persistence.
        /// Contains both public and private key information in a format
        /// suitable for storage and later reconstruction.
        /// Setting this property invalidates the cached JWS tool.
        /// </summary>
        /// <value>Base64 or PEM encoded key data</value>
        public string KeyExport
        {
            get => _keyExport;
            set
            {
                _keyExport = value;
                _jwsTool = null; // Invalidate cached tool when key data changes
            }
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Gets or creates the JWS (JSON Web Signature) tool for cryptographic operations.
        /// This method implements lazy initialization and caching to avoid recreating
        /// expensive cryptographic objects unnecessarily.
        /// </summary>
        /// <returns>An initialized IJwsTool instance ready for signing operations</returns>
        /// <exception cref="Exception">
        /// Thrown if KeyType is missing, unsupported, or if key initialization fails
        /// </exception>
        public IJwsTool JwsTool()
        {
            // Return cached instance if available
            if (_jwsTool != null)
            {
                return _jwsTool;
            }

            // Validate that we have a key type
            if (string.IsNullOrWhiteSpace(KeyType))
            {
                throw new Exception("Missing KeyType - cannot create JWS tool without specifying algorithm");
            }

            IJwsTool tool = CreateJwsToolForKeyType(KeyType);

            // Initialize the tool with default parameters
            tool.Init();

            // Import existing key data if available
            if (!string.IsNullOrEmpty(KeyExport))
            {
                tool.Import(KeyExport);
            }

            // Cache the tool for future use
            _jwsTool = tool;
            return _jwsTool;
        }

        /// <summary>
        /// Convenience method that returns the JWS tool.
        /// Provides an alternative method name for accessing the cryptographic tool.
        /// </summary>
        /// <returns>An initialized IJwsTool instance</returns>
        /// <exception cref="Exception">
        /// Thrown if KeyType is missing, unsupported, or if key initialization fails
        /// </exception>
        public IJwsTool GetJwsTool() => JwsTool();

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// Creates the appropriate JWS tool instance based on the specified key type.
        /// Supports Elliptic Curve (ES*) and RSA (RS*) algorithm families.
        /// </summary>
        /// <param name="keyType">The cryptographic algorithm identifier</param>
        /// <returns>An uninitialized IJwsTool instance of the appropriate type</returns>
        /// <exception cref="Exception">Thrown if the key type is unknown or unsupported</exception>
        private IJwsTool CreateJwsToolForKeyType(string keyType)
        {
            // Handle Elliptic Curve algorithms (ES256, ES384, ES512)
            if (keyType.StartsWith("ES", StringComparison.OrdinalIgnoreCase))
            {
                // Extract hash size from algorithm name (e.g., "ES256" -> 256)
                if (int.TryParse(keyType.Substring(2), out int hashSize))
                {
                    return new ESJwsTool
                    {
                        HashSize = hashSize
                    };
                }
                else
                {
                    throw new Exception($"Invalid Elliptic Curve key type format: {keyType}. Expected format: ES[256|384|512]");
                }
            }
            // Handle RSA algorithms (RS256, RS384, RS512)
            else if (keyType.StartsWith("RS", StringComparison.OrdinalIgnoreCase))
            {
                return new RSJwsTool();
            }
            else
            {
                throw new Exception($"Unknown or unsupported KeyType [{keyType}]. Supported types: ES256, ES384, ES512, RS256, RS384, RS512");
            }
        }

        #endregion
    }
}