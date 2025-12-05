using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.CAPlugin.Acme
{
    /// <summary>
    /// RFC 2136 Dynamic DNS Update provider for BIND and Microsoft DNS servers.
    /// Supports TSIG authentication for secure updates.
    /// </summary>
    public class Rfc2136DnsProvider : IDnsProvider
    {
        private readonly string _serverHost;
        private readonly int _serverPort;
        private readonly string _zoneName;
        private readonly string _tsigKeyName;
        private readonly byte[] _tsigKey;
        private readonly string _tsigAlgorithm;
        private readonly ILogger _logger;

        // TSIG Algorithm OIDs/Names
        private static readonly Dictionary<string, string> TsigAlgorithms = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "hmac-md5", "hmac-md5.sig-alg.reg.int" },
            { "hmac-sha1", "hmac-sha1" },
            { "hmac-sha256", "hmac-sha256" },
            { "hmac-sha384", "hmac-sha384" },
            { "hmac-sha512", "hmac-sha512" }
        };

        /// <summary>
        /// Creates a new RFC 2136 DNS provider.
        /// </summary>
        /// <param name="serverHost">DNS server hostname or IP address</param>
        /// <param name="zoneName">The DNS zone to update (e.g., "example.com")</param>
        /// <param name="tsigKeyName">TSIG key name (e.g., "acme-update-key")</param>
        /// <param name="tsigKeyValue">Base64-encoded TSIG secret key</param>
        /// <param name="tsigAlgorithm">TSIG algorithm (hmac-sha256 recommended)</param>
        /// <param name="serverPort">DNS server port (default 53)</param>
        /// <param name="logger">Optional logger</param>
        public Rfc2136DnsProvider(
            string serverHost,
            string zoneName,
            string tsigKeyName,
            string tsigKeyValue,
            string tsigAlgorithm = "hmac-sha256",
            int serverPort = 53,
            ILogger logger = null)
        {
            _serverHost = serverHost ?? throw new ArgumentNullException(nameof(serverHost));
            _zoneName = zoneName?.TrimEnd('.') ?? throw new ArgumentNullException(nameof(zoneName));
            _tsigKeyName = tsigKeyName ?? throw new ArgumentNullException(nameof(tsigKeyName));
            _tsigKey = Convert.FromBase64String(tsigKeyValue ?? throw new ArgumentNullException(nameof(tsigKeyValue)));
            _tsigAlgorithm = NormalizeTsigAlgorithm(tsigAlgorithm);
            _serverPort = serverPort;
            _logger = logger;
        }

        /// <summary>
        /// Creates a TXT record for ACME DNS-01 challenge.
        /// </summary>
        public async Task<bool> CreateRecordAsync(string recordName, string txtValue)
        {
            try
            {
                var cleanName = recordName.TrimEnd('.');
                _logger?.LogDebug("[RFC2136] Creating TXT record: {RecordName} = {TxtValue}", cleanName, txtValue);

                // First, delete any existing records with the same name
                await DeleteRecordAsync(recordName);

                // Build DNS UPDATE message
                var updateMessage = BuildUpdateMessage(cleanName, txtValue, isDelete: false);

                // Send the update
                var response = await SendDnsUpdateAsync(updateMessage);

                // Check response code
                var rcode = (response[3] & 0x0F);
                if (rcode == 0) // NOERROR
                {
                    _logger?.LogInformation("[RFC2136] Successfully created TXT record: {RecordName}", cleanName);
                    return true;
                }

                var rcodeMessage = GetRcodeMessage(rcode);
                _logger?.LogError("[RFC2136] Failed to create TXT record. RCODE: {Rcode} ({RcodeMessage})", rcode, rcodeMessage);
                throw new InvalidOperationException($"RFC2136 DNS update failed with RCODE {rcode} ({rcodeMessage})");
            }
            catch (InvalidOperationException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "[RFC2136] Error creating TXT record for {RecordName}", recordName);
                throw new InvalidOperationException($"RFC2136 DNS provider error: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Deletes a TXT record.
        /// </summary>
        public async Task<bool> DeleteRecordAsync(string recordName)
        {
            try
            {
                var cleanName = recordName.TrimEnd('.');
                _logger?.LogDebug("[RFC2136] Deleting TXT record: {RecordName}", cleanName);

                // Build DNS UPDATE message for deletion
                var updateMessage = BuildUpdateMessage(cleanName, null, isDelete: true);

                // Send the update
                var response = await SendDnsUpdateAsync(updateMessage);

                // Check response code
                var rcode = (response[3] & 0x0F);
                if (rcode == 0 || rcode == 3) // NOERROR or NXDOMAIN (already doesn't exist)
                {
                    _logger?.LogInformation("[RFC2136] Successfully deleted TXT record: {RecordName}", cleanName);
                    return true;
                }

                var rcodeMessage = GetRcodeMessage(rcode);
                _logger?.LogWarning("[RFC2136] Delete returned RCODE: {Rcode} ({RcodeMessage})", rcode, rcodeMessage);
                return false;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "[RFC2136] Error deleting TXT record for {RecordName}", recordName);
                return false;
            }
        }

        /// <summary>
        /// Builds a DNS UPDATE message per RFC 2136.
        /// </summary>
        private byte[] BuildUpdateMessage(string recordName, string txtValue, bool isDelete)
        {
            var message = new List<byte>();

            // Transaction ID (random)
            var transactionId = new byte[2];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(transactionId);
            }
            message.AddRange(transactionId);

            // Flags: 0x2800 = UPDATE opcode (5), no flags
            message.Add(0x28);
            message.Add(0x00);

            // ZOCOUNT: 1 (one zone)
            message.Add(0x00);
            message.Add(0x01);

            // PRCOUNT: 0 (no prerequisites)
            message.Add(0x00);
            message.Add(0x00);

            // UPCOUNT: 1 (one update)
            message.Add(0x00);
            message.Add(0x01);

            // ADCOUNT: 1 (TSIG record)
            message.Add(0x00);
            message.Add(0x01);

            // Zone section
            message.AddRange(EncodeDomainName(_zoneName));
            message.Add(0x00); message.Add(0x06); // TYPE: SOA
            message.Add(0x00); message.Add(0x01); // CLASS: IN

            // Update section
            message.AddRange(EncodeDomainName(recordName));
            message.Add(0x00); message.Add(0x10); // TYPE: TXT

            if (isDelete)
            {
                // Delete all TXT records with this name
                message.Add(0x00); message.Add(0xFF); // CLASS: ANY (delete)
                message.Add(0x00); message.Add(0x00); message.Add(0x00); message.Add(0x00); // TTL: 0
                message.Add(0x00); message.Add(0x00); // RDLENGTH: 0
            }
            else
            {
                // Add new TXT record
                message.Add(0x00); message.Add(0x01); // CLASS: IN
                message.Add(0x00); message.Add(0x00); message.Add(0x00); message.Add(0x3C); // TTL: 60 seconds

                // TXT RDATA
                var txtData = EncodeTxtRecord(txtValue);
                message.Add((byte)((txtData.Length >> 8) & 0xFF));
                message.Add((byte)(txtData.Length & 0xFF));
                message.AddRange(txtData);
            }

            // Add TSIG record
            var messageWithoutTsig = message.ToArray();
            var tsigRecord = BuildTsigRecord(messageWithoutTsig, transactionId);
            message.AddRange(tsigRecord);

            return message.ToArray();
        }

        /// <summary>
        /// Builds a TSIG record for authentication per RFC 2845.
        /// </summary>
        private byte[] BuildTsigRecord(byte[] messageData, byte[] transactionId)
        {
            var tsig = new List<byte>();

            // TSIG key name
            tsig.AddRange(EncodeDomainName(_tsigKeyName));

            // TYPE: TSIG (250)
            tsig.Add(0x00); tsig.Add(0xFA);

            // CLASS: ANY (255)
            tsig.Add(0x00); tsig.Add(0xFF);

            // TTL: 0
            tsig.Add(0x00); tsig.Add(0x00); tsig.Add(0x00); tsig.Add(0x00);

            // Build RDATA
            var rdata = new List<byte>();

            // Algorithm name
            rdata.AddRange(EncodeDomainName(_tsigAlgorithm));

            // Time signed (48-bit, seconds since epoch)
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            rdata.Add((byte)((now >> 40) & 0xFF));
            rdata.Add((byte)((now >> 32) & 0xFF));
            rdata.Add((byte)((now >> 24) & 0xFF));
            rdata.Add((byte)((now >> 16) & 0xFF));
            rdata.Add((byte)((now >> 8) & 0xFF));
            rdata.Add((byte)(now & 0xFF));

            // Fudge (300 seconds = 5 minutes)
            rdata.Add(0x01); rdata.Add(0x2C);

            // Calculate MAC
            var macData = BuildMacData(messageData, now);
            var mac = ComputeTsigMac(macData);

            // MAC size and MAC
            rdata.Add((byte)((mac.Length >> 8) & 0xFF));
            rdata.Add((byte)(mac.Length & 0xFF));
            rdata.AddRange(mac);

            // Original ID
            rdata.AddRange(transactionId);

            // Error (0 = NOERROR)
            rdata.Add(0x00); rdata.Add(0x00);

            // Other length (0)
            rdata.Add(0x00); rdata.Add(0x00);

            // RDLENGTH
            tsig.Add((byte)((rdata.Count >> 8) & 0xFF));
            tsig.Add((byte)(rdata.Count & 0xFF));
            tsig.AddRange(rdata);

            return tsig.ToArray();
        }

        /// <summary>
        /// Builds the data to be signed for TSIG MAC calculation.
        /// </summary>
        private byte[] BuildMacData(byte[] messageData, long timeSigned)
        {
            var data = new List<byte>();

            // Message data
            data.AddRange(messageData);

            // TSIG variables (without key name for signing)
            data.AddRange(EncodeDomainName(_tsigKeyName));
            data.Add(0x00); data.Add(0xFF); // CLASS: ANY
            data.Add(0x00); data.Add(0x00); data.Add(0x00); data.Add(0x00); // TTL: 0
            data.AddRange(EncodeDomainName(_tsigAlgorithm));

            // Time signed
            data.Add((byte)((timeSigned >> 40) & 0xFF));
            data.Add((byte)((timeSigned >> 32) & 0xFF));
            data.Add((byte)((timeSigned >> 24) & 0xFF));
            data.Add((byte)((timeSigned >> 16) & 0xFF));
            data.Add((byte)((timeSigned >> 8) & 0xFF));
            data.Add((byte)(timeSigned & 0xFF));

            // Fudge
            data.Add(0x01); data.Add(0x2C);

            // Error (0)
            data.Add(0x00); data.Add(0x00);

            // Other length (0)
            data.Add(0x00); data.Add(0x00);

            return data.ToArray();
        }

        /// <summary>
        /// Computes the TSIG MAC using the configured algorithm.
        /// </summary>
        private byte[] ComputeTsigMac(byte[] data)
        {
            HMAC hmac;
            if (_tsigAlgorithm.Contains("sha512", StringComparison.OrdinalIgnoreCase))
                hmac = new HMACSHA512(_tsigKey);
            else if (_tsigAlgorithm.Contains("sha384", StringComparison.OrdinalIgnoreCase))
                hmac = new HMACSHA384(_tsigKey);
            else if (_tsigAlgorithm.Contains("sha256", StringComparison.OrdinalIgnoreCase))
                hmac = new HMACSHA256(_tsigKey);
            else if (_tsigAlgorithm.Contains("sha1", StringComparison.OrdinalIgnoreCase))
                hmac = new HMACSHA1(_tsigKey);
            else if (_tsigAlgorithm.Contains("md5", StringComparison.OrdinalIgnoreCase))
                hmac = new HMACMD5(_tsigKey);
            else
                hmac = new HMACSHA256(_tsigKey); // Default

            using (hmac)
            {
                return hmac.ComputeHash(data);
            }
        }

        /// <summary>
        /// Encodes a domain name in DNS wire format.
        /// </summary>
        private byte[] EncodeDomainName(string name)
        {
            var result = new List<byte>();
            var labels = name.TrimEnd('.').Split('.');

            foreach (var label in labels)
            {
                if (label.Length > 63)
                    throw new ArgumentException($"DNS label too long: {label}");

                result.Add((byte)label.Length);
                result.AddRange(Encoding.ASCII.GetBytes(label));
            }

            result.Add(0x00); // Root label
            return result.ToArray();
        }

        /// <summary>
        /// Encodes a TXT record value.
        /// </summary>
        private byte[] EncodeTxtRecord(string value)
        {
            var result = new List<byte>();
            var bytes = Encoding.UTF8.GetBytes(value);

            // TXT records are split into 255-byte chunks
            for (int i = 0; i < bytes.Length; i += 255)
            {
                var chunkLength = Math.Min(255, bytes.Length - i);
                result.Add((byte)chunkLength);
                result.AddRange(bytes.Skip(i).Take(chunkLength));
            }

            return result.ToArray();
        }

        /// <summary>
        /// Sends a DNS UPDATE message to the server.
        /// </summary>
        private async Task<byte[]> SendDnsUpdateAsync(byte[] message)
        {
            // Resolve server address
            var addresses = await Dns.GetHostAddressesAsync(_serverHost);
            if (addresses.Length == 0)
                throw new InvalidOperationException($"Could not resolve DNS server: {_serverHost}");

            var serverAddress = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                ?? addresses[0];

            _logger?.LogDebug("[RFC2136] Sending DNS UPDATE to {Server}:{Port}", serverAddress, _serverPort);

            // Use TCP for updates (more reliable and handles larger messages)
            using (var client = new TcpClient())
            {
                await client.ConnectAsync(serverAddress, _serverPort);

                using (var stream = client.GetStream())
                {
                    // TCP DNS messages are prefixed with 2-byte length
                    var lengthPrefix = new byte[] { (byte)(message.Length >> 8), (byte)(message.Length & 0xFF) };
                    await stream.WriteAsync(lengthPrefix, 0, 2);
                    await stream.WriteAsync(message, 0, message.Length);

                    // Read response length
                    var responseLength = new byte[2];
                    await ReadExactAsync(stream, responseLength, 2);
                    var length = (responseLength[0] << 8) | responseLength[1];

                    // Read response
                    var response = new byte[length];
                    await ReadExactAsync(stream, response, length);

                    return response;
                }
            }
        }

        /// <summary>
        /// Reads exactly the specified number of bytes from a stream.
        /// </summary>
        private async Task ReadExactAsync(NetworkStream stream, byte[] buffer, int count)
        {
            int offset = 0;
            while (offset < count)
            {
                int read = await stream.ReadAsync(buffer, offset, count - offset);
                if (read == 0)
                    throw new InvalidOperationException("Connection closed while reading DNS response");
                offset += read;
            }
        }

        /// <summary>
        /// Normalizes a TSIG algorithm name to its canonical form.
        /// </summary>
        private string NormalizeTsigAlgorithm(string algorithm)
        {
            if (TsigAlgorithms.TryGetValue(algorithm, out var canonical))
                return canonical;

            // If already in canonical form, return as-is
            if (algorithm.Contains("."))
                return algorithm;

            // Default to hmac-sha256
            _logger?.LogWarning("[RFC2136] Unknown TSIG algorithm '{Algorithm}', defaulting to hmac-sha256", algorithm);
            return "hmac-sha256";
        }

        /// <summary>
        /// Gets a human-readable message for a DNS RCODE.
        /// </summary>
        private string GetRcodeMessage(int rcode)
        {
            return rcode switch
            {
                0 => "NOERROR",
                1 => "FORMERR - Format error",
                2 => "SERVFAIL - Server failure",
                3 => "NXDOMAIN - Name does not exist",
                4 => "NOTIMP - Not implemented",
                5 => "REFUSED - Operation refused",
                6 => "YXDOMAIN - Name exists when it should not",
                7 => "YXRRSET - RRset exists when it should not",
                8 => "NXRRSET - RRset does not exist when it should",
                9 => "NOTAUTH - Not authorized",
                10 => "NOTZONE - Name not contained in zone",
                16 => "BADSIG - TSIG signature failure",
                17 => "BADKEY - Key not recognized",
                18 => "BADTIME - Signature out of time window",
                _ => $"Unknown RCODE ({rcode})"
            };
        }

        public void Dispose()
        {
            // No resources to dispose
        }
    }
}
