using ACMESharp.Crypto;
using ACMESharp.Crypto.JOSE;
using ACMESharp.Protocol;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Keyfactor.Extensions.CAPlugin.Acme.Clients.Acme
{
    /// <summary>
    /// Helper class for creating External Account Binding (EAB) objects as specified in RFC 8555 Section 7.3.4.
    /// EAB is used by Certificate Authorities to associate ACME accounts with pre-existing customer accounts
    /// or to implement additional authorization controls.
    /// </summary>
    public static class ExternalAccountBindingHelper
    {
        #region Constants

        /// <summary>
        /// Supported HMAC algorithm identifiers for EAB signatures
        /// </summary>
        private static readonly HashSet<string> SupportedAlgorithms = new HashSet<string>
        {
            "HS256", "HS384", "HS512"
        };

        #endregion

        #region Public Methods

        /// <summary>
        /// Creates an External Account Binding (EAB) JWS object using manual JWS construction.
        /// This method implements RFC 8555 Section 7.3.4 directly without relying on ACMESharp's JwsHelper.
        /// This is the preferred method as it provides more reliable results.
        /// </summary>
        /// <param name="acmeProtocolClient">The ACME protocol client containing directory information</param>
        /// <param name="signer">The account key signer whose public key will be bound to the external account</param>
        /// <param name="keyId">The key identifier provided by the Certificate Authority for EAB</param>
        /// <param name="hmacKey">The base64url-encoded HMAC key provided by the Certificate Authority</param>
        /// <param name="algorithm">The HMAC algorithm to use (HS256, HS384, or HS512)</param>
        /// <returns>A JWS object representing the External Account Binding</returns>
        /// <exception cref="ArgumentException">Thrown when an unsupported algorithm is specified</exception>
        /// <exception cref="ArgumentNullException">Thrown when required parameters are null</exception>
        public static object CreateExternalAccountBinding(
            AcmeProtocolClient acmeProtocolClient,
            IJwsTool signer,
            string keyId,
            string hmacKey,
            string algorithm)
        {
            ValidateEabParameters(acmeProtocolClient, signer, keyId, hmacKey, algorithm);

            // Step 1: Create the EAB payload containing the account's public key
            // The payload is the account key JWK serialized as JSON
            var accountKey = signer.ExportJwk();
            var eabPayload = JsonConvert.SerializeObject(accountKey,
                Formatting.None,
                new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });

            // Step 2: Create the EAB protected header
            // This contains algorithm, key ID, and the target URL
            var eabProtected = JsonConvert.SerializeObject(new
            {
                alg = algorithm,
                kid = keyId,
                url = acmeProtocolClient.Directory.NewAccount
            }, Formatting.None);

            // Step 3: Base64url encode the protected header and payload
            // This follows the JWS specification (RFC 7515)
            var protectedEncoded = CryptoHelper.Base64.UrlEncode(Encoding.UTF8.GetBytes(eabProtected));
            var payloadEncoded = CryptoHelper.Base64.UrlEncode(Encoding.UTF8.GetBytes(eabPayload));

            // Step 4: Create the signing input and compute HMAC signature
            // Signing input format: base64url(protected) + "." + base64url(payload)
            var signingInput = $"{protectedEncoded}.{payloadEncoded}";
            var signature = ComputeHmacSignature(Encoding.UTF8.GetBytes(signingInput), hmacKey, algorithm);
            var signatureEncoded = CryptoHelper.Base64.UrlEncode(signature);

            // Step 5: Return the complete EAB JWS in Flattened JSON Serialization format
            // Note: Using anonymous object with @protected to handle the reserved keyword
            return new
            {
                @protected = protectedEncoded,
                payload = payloadEncoded,
                signature = signatureEncoded
            };
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Validates all required parameters for EAB creation.
        /// </summary>
        /// <param name="acmeProtocolClient">The ACME protocol client</param>
        /// <param name="signer">The account signer</param>
        /// <param name="keyId">The EAB key identifier</param>
        /// <param name="hmacKey">The EAB HMAC key</param>
        /// <param name="algorithm">The HMAC algorithm</param>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null or empty</exception>
        /// <exception cref="NotSupportedException">Thrown when an unsupported algorithm is specified</exception>
        private static void ValidateEabParameters(
            AcmeProtocolClient acmeProtocolClient,
            IJwsTool signer,
            string keyId,
            string hmacKey,
            string algorithm)
        {
            if (acmeProtocolClient == null)
                throw new ArgumentNullException(nameof(acmeProtocolClient));

            if (signer == null)
                throw new ArgumentNullException(nameof(signer));

            if (string.IsNullOrWhiteSpace(keyId))
                throw new ArgumentNullException(nameof(keyId));

            if (string.IsNullOrWhiteSpace(hmacKey))
                throw new ArgumentNullException(nameof(hmacKey));

            if (string.IsNullOrWhiteSpace(algorithm))
                throw new ArgumentNullException(nameof(algorithm));

            if (!SupportedAlgorithms.Contains(algorithm))
                throw new NotSupportedException($"Algorithm '{algorithm}' is not supported. Supported algorithms: {string.Join(", ", SupportedAlgorithms)}");

            if (acmeProtocolClient.Directory?.NewAccount == null)
                throw new ArgumentException("ACME client directory must be initialized with NewAccount URL", nameof(acmeProtocolClient));
        }

        /// <summary>
        /// Computes HMAC signature for the given data using the specified algorithm and key.
        /// </summary>
        /// <param name="data">The data to sign</param>
        /// <param name="hmacKey">The base64url-encoded HMAC key</param>
        /// <param name="algorithm">The HMAC algorithm (HS256, HS384, or HS512)</param>
        /// <returns>The computed HMAC signature as byte array</returns>
        /// <exception cref="NotSupportedException">Thrown when an unsupported algorithm is specified</exception>
        private static byte[] ComputeHmacSignature(byte[] data, string hmacKey, string algorithm)
        {
            var keyBytes = CryptoHelper.Base64.UrlDecode(hmacKey);

            // Create appropriate HMAC algorithm instance based on the algorithm parameter
            HMAC hmacAlgorithm = algorithm switch
            {
                "HS256" => new HMACSHA256(keyBytes),
                "HS384" => new HMACSHA384(keyBytes),
                "HS512" => new HMACSHA512(keyBytes),
                _ => throw new NotSupportedException($"HMAC algorithm '{algorithm}' is not supported")
            };

            using (hmacAlgorithm)
            {
                return hmacAlgorithm.ComputeHash(data);
            }
        }

        /// <summary>
        /// Creates a JWS object manually when ACMESharp's JwsHelper fails.
        /// This provides a fallback mechanism for EAB creation.
        /// </summary>
        /// <param name="payload">The JSON payload to be signed</param>
        /// <param name="protectedHeaders">The protected headers object</param>
        /// <param name="signFunc">Function to compute the signature</param>
        /// <returns>A dictionary representing the JWS in Flattened JSON Serialization format</returns>
        private static Dictionary<string, string> CreateManualJws(
            string payload,
            object protectedHeaders,
            Func<byte[], byte[]> signFunc)
        {
            // Serialize and encode the protected headers
            var protectedJson = JsonConvert.SerializeObject(protectedHeaders, Formatting.None);
            var protectedB64 = CryptoHelper.Base64.UrlEncode(Encoding.UTF8.GetBytes(protectedJson));

            // Encode the payload
            var payloadB64 = CryptoHelper.Base64.UrlEncode(Encoding.UTF8.GetBytes(payload));

            // Create signing input and compute signature
            var signingInput = $"{protectedB64}.{payloadB64}";
            var signature = signFunc(Encoding.UTF8.GetBytes(signingInput));
            var signatureB64 = CryptoHelper.Base64.UrlEncode(signature);

            // Return JWS in Flattened JSON Serialization format
            return new Dictionary<string, string>
            {
                { "protected", protectedB64 },
                { "payload", payloadB64 },
                { "signature", signatureB64 }
            };
        }

        #endregion
    }
}