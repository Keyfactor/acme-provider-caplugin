using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using DnsClient;

namespace Keyfactor.Extensions.CAPlugin.Acme.Clients.DNS
{
    /// <summary>
    /// Verifies DNS record propagation before submitting ACME challenges
    /// </summary>
    public class DnsVerificationHelper
    {
        private readonly ILogger _logger;
        private readonly List<IPAddress> _dnsServers;
        private const int MaxVerificationAttempts = 3;
        private const int VerificationDelaySeconds = 10;

        public DnsVerificationHelper(ILogger logger)
        {
            _logger = logger;

            // Use multiple public DNS servers for verification
            _dnsServers = new List<IPAddress>
            {
                IPAddress.Parse("8.8.8.8"),       // Google Primary
                IPAddress.Parse("8.8.4.4"),       // Google Secondary
                IPAddress.Parse("1.1.1.1"),       // Cloudflare Primary
                IPAddress.Parse("1.0.0.1"),       // Cloudflare Secondary
                IPAddress.Parse("208.67.222.222"), // OpenDNS
                IPAddress.Parse("9.9.9.9")        // Quad9
            };
        }

        /// <summary>
        /// Waits for DNS TXT record to propagate across multiple DNS servers
        /// </summary>
        /// <param name="recordName">DNS record name (e.g., _acme-challenge.example.com)</param>
        /// <param name="expectedValue">Expected TXT record value</param>
        /// <param name="minimumServers">Minimum number of DNS servers that must see the record</param>
        /// <returns>True if record propagated successfully</returns>
        public async Task<bool> WaitForDnsPropagationAsync(
            string recordName,
            string expectedValue,
            int minimumServers = 3)
        {
            _logger.LogInformation("Waiting for DNS propagation of {RecordName}", recordName);

            for (int attempt = 1; attempt <= MaxVerificationAttempts; attempt++)
            {
                var successCount = 0;
                var results = new List<string>();

                foreach (var dnsServer in _dnsServers)
                {
                    try
                    {
                        var hasRecord = await CheckDnsRecordAsync(recordName, expectedValue, dnsServer);
                        if (hasRecord)
                        {
                            successCount++;
                            results.Add($"✓ {dnsServer}");
                        }
                        else
                        {
                            results.Add($"✗ {dnsServer}");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning("DNS query failed for server {Server}: {Error}",
                            dnsServer, ex.Message);
                        results.Add($"? {dnsServer} (error)");
                    }
                }

                _logger.LogDebug("DNS verification attempt {Attempt}/{MaxAttempts}: {SuccessCount}/{TotalServers} servers confirmed record. Results: {Results}",
                    attempt, MaxVerificationAttempts, successCount, _dnsServers.Count, string.Join(", ", results));

                if (successCount >= minimumServers)
                {
                    _logger.LogInformation("DNS record propagated successfully! {SuccessCount}/{TotalServers} servers confirmed record after {Attempt} attempts",
                        successCount, _dnsServers.Count, attempt);
                    return true;
                }

                if (attempt < MaxVerificationAttempts)
                {
                    _logger.LogDebug("Waiting {Delay} seconds before next DNS verification attempt...", VerificationDelaySeconds);
                    await Task.Delay(TimeSpan.FromSeconds(VerificationDelaySeconds));
                }
            }

            _logger.LogWarning("DNS record did not propagate within {MaxAttempts} attempts ({TotalMinutes} minutes)",
                MaxVerificationAttempts, MaxVerificationAttempts * VerificationDelaySeconds / 60);
            return false;
        }

        /// <summary>
        /// Checks if a specific DNS server has the expected TXT record
        /// </summary>
        private async Task<bool> CheckDnsRecordAsync(string recordName, string expectedValue, IPAddress dnsServer)
        {
            var client = new LookupClient(dnsServer);

            try
            {
                var result = await client.QueryAsync(recordName, QueryType.TXT);

                if (result.Answers?.Any() != true)
                {
                    return false;
                }

                var txtRecords = result.Answers
                    .OfType<DnsClient.Protocol.TxtRecord>()
                    .SelectMany(r => r.Text)
                    .ToList();

                var hasExpectedValue = txtRecords.Any(txt =>
                    string.Equals(txt, expectedValue, StringComparison.OrdinalIgnoreCase));

                _logger.LogTrace("DNS server {Server} returned {Count} TXT records for {RecordName}. Expected: {Expected}, Found: {HasExpected}",
                    dnsServer, txtRecords.Count, recordName, expectedValue, hasExpectedValue);

                return hasExpectedValue;
            }
            catch (Exception ex)
            {
                _logger.LogTrace("DNS query to {Server} failed: {Error}", dnsServer, ex.Message);
                throw;
            }
        }

        /// <summary>
        /// Gets the authoritative DNS servers for a domain
        /// </summary>
        public async Task<List<IPAddress>> GetAuthoritativeDnsServersAsync(string domain)
        {
            var authServers = new List<IPAddress>();

            try
            {
                var client = new LookupClient();
                var result = await client.QueryAsync(domain, QueryType.NS);

                foreach (var nsRecord in result.Answers.OfType<DnsClient.Protocol.NsRecord>())
                {
                    try
                    {
                        var nsResult = await client.QueryAsync(nsRecord.NSDName, QueryType.A);
                        authServers.AddRange(
                            nsResult.Answers
                                .OfType<DnsClient.Protocol.ARecord>()
                                .Select(a => a.Address)
                        );
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning("Failed to resolve NS record {NSName}: {Error}",
                            nsRecord.NSDName, ex.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Failed to get authoritative DNS servers for {Domain}: {Error}",
                    domain, ex.Message);
            }

            return authServers.Distinct().ToList();
        }
    }
}