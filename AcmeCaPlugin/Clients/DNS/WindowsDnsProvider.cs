using System;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.CAPlugin.Acme
{
    /// <summary>
    /// Windows DNS Server provider using PowerShell cmdlets.
    /// Manages TXT records via Add-DnsServerResourceRecord and Remove-DnsServerResourceRecord.
    /// </summary>
    public class WindowsDnsProvider : IDnsProvider
    {
        private readonly string _dnsServer;
        private readonly string _zoneName;
        private readonly string _username;
        private readonly string _password;
        private readonly ILogger _logger;

        /// <summary>
        /// Creates a new Windows DNS provider.
        /// </summary>
        /// <param name="dnsServer">DNS server hostname (null for local server)</param>
        /// <param name="zoneName">The DNS zone to update (e.g., "test.local")</param>
        /// <param name="username">Optional username for remote server (domain\user format)</param>
        /// <param name="password">Optional password for remote server</param>
        /// <param name="logger">Optional logger</param>
        public WindowsDnsProvider(
            string dnsServer,
            string zoneName,
            string username = null,
            string password = null,
            ILogger logger = null)
        {
            _dnsServer = dnsServer; // Can be null for local server
            _zoneName = zoneName?.TrimEnd('.') ?? throw new ArgumentNullException(nameof(zoneName));
            _username = username;
            _password = password;
            _logger = logger;
        }

        /// <summary>
        /// Creates a TXT record for ACME DNS-01 challenge.
        /// </summary>
        public async Task<bool> CreateRecordAsync(string recordName, string txtValue)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var cleanName = recordName.TrimEnd('.');
                    _logger?.LogDebug("[WindowsDNS] Creating TXT record: {RecordName} = {TxtValue}", cleanName, txtValue);

                    // Extract the relative name from the FQDN
                    var relativeName = GetRelativeName(cleanName);

                    // First, delete any existing records with the same name
                    DeleteRecordInternal(relativeName);

                    using (var ps = PowerShell.Create())
                    {
                        // Build the command
                        var command = ps.AddCommand("Add-DnsServerResourceRecord")
                            .AddParameter("ZoneName", _zoneName)
                            .AddParameter("Name", relativeName)
                            .AddParameter("Txt")
                            .AddParameter("DescriptiveText", txtValue)
                            .AddParameter("TimeToLive", TimeSpan.FromSeconds(60));

                        // Add server parameter if specified
                        if (!string.IsNullOrEmpty(_dnsServer))
                        {
                            ps.AddParameter("ComputerName", _dnsServer);
                        }

                        // Add credentials if specified
                        if (!string.IsNullOrEmpty(_username) && !string.IsNullOrEmpty(_password))
                        {
                            var securePassword = new System.Security.SecureString();
                            foreach (char c in _password)
                            {
                                securePassword.AppendChar(c);
                            }
                            var credential = new PSCredential(_username, securePassword);
                            ps.AddParameter("Credential", credential);
                        }

                        ps.Invoke();

                        if (ps.HadErrors)
                        {
                            var errors = string.Join("; ", ps.Streams.Error.Select(e => e.ToString()));
                            _logger?.LogError("[WindowsDNS] Failed to create TXT record: {Errors}", errors);
                            throw new InvalidOperationException($"Windows DNS error: {errors}");
                        }

                        _logger?.LogInformation("[WindowsDNS] Successfully created TXT record: {RecordName}", cleanName);
                        return true;
                    }
                }
                catch (InvalidOperationException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "[WindowsDNS] Error creating TXT record for {RecordName}", recordName);
                    throw new InvalidOperationException($"Windows DNS provider error: {ex.Message}", ex);
                }
            });
        }

        /// <summary>
        /// Deletes a TXT record.
        /// </summary>
        public async Task<bool> DeleteRecordAsync(string recordName)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var cleanName = recordName.TrimEnd('.');
                    var relativeName = GetRelativeName(cleanName);
                    return DeleteRecordInternal(relativeName);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "[WindowsDNS] Error deleting TXT record for {RecordName}", recordName);
                    return false;
                }
            });
        }

        private bool DeleteRecordInternal(string relativeName)
        {
            _logger?.LogDebug("[WindowsDNS] Deleting TXT record: {RelativeName}", relativeName);

            using (var ps = PowerShell.Create())
            {
                // First, get existing TXT records
                ps.AddCommand("Get-DnsServerResourceRecord")
                    .AddParameter("ZoneName", _zoneName)
                    .AddParameter("Name", relativeName)
                    .AddParameter("RRType", "TXT")
                    .AddParameter("ErrorAction", "SilentlyContinue");

                if (!string.IsNullOrEmpty(_dnsServer))
                {
                    ps.AddParameter("ComputerName", _dnsServer);
                }

                if (!string.IsNullOrEmpty(_username) && !string.IsNullOrEmpty(_password))
                {
                    var securePassword = new System.Security.SecureString();
                    foreach (char c in _password)
                    {
                        securePassword.AppendChar(c);
                    }
                    var credential = new PSCredential(_username, securePassword);
                    ps.AddParameter("Credential", credential);
                }

                var records = ps.Invoke();

                if (records == null || records.Count == 0)
                {
                    _logger?.LogDebug("[WindowsDNS] No existing TXT records found for {RelativeName}", relativeName);
                    return true;
                }

                // Delete each record found
                foreach (var record in records)
                {
                    ps.Commands.Clear();
                    ps.AddCommand("Remove-DnsServerResourceRecord")
                        .AddParameter("ZoneName", _zoneName)
                        .AddParameter("InputObject", record)
                        .AddParameter("Force");

                    if (!string.IsNullOrEmpty(_dnsServer))
                    {
                        ps.AddParameter("ComputerName", _dnsServer);
                    }

                    if (!string.IsNullOrEmpty(_username) && !string.IsNullOrEmpty(_password))
                    {
                        var securePassword = new System.Security.SecureString();
                        foreach (char c in _password)
                        {
                            securePassword.AppendChar(c);
                        }
                        var credential = new PSCredential(_username, securePassword);
                        ps.AddParameter("Credential", credential);
                    }

                    ps.Invoke();

                    if (ps.HadErrors)
                    {
                        var errors = string.Join("; ", ps.Streams.Error.Select(e => e.ToString()));
                        _logger?.LogWarning("[WindowsDNS] Error deleting record: {Errors}", errors);
                    }
                }

                _logger?.LogInformation("[WindowsDNS] Successfully deleted TXT record(s): {RelativeName}", relativeName);
                return true;
            }
        }

        /// <summary>
        /// Extracts the relative record name from an FQDN.
        /// For example: "_acme-challenge.www.test.local" with zone "test.local" -> "_acme-challenge.www"
        /// </summary>
        private string GetRelativeName(string fqdn)
        {
            var cleanFqdn = fqdn.TrimEnd('.');
            var cleanZone = _zoneName.TrimEnd('.');

            if (cleanFqdn.EndsWith("." + cleanZone, StringComparison.OrdinalIgnoreCase))
            {
                return cleanFqdn.Substring(0, cleanFqdn.Length - cleanZone.Length - 1);
            }

            if (cleanFqdn.Equals(cleanZone, StringComparison.OrdinalIgnoreCase))
            {
                return "@";
            }

            // If FQDN doesn't end with zone, assume it's already relative
            return cleanFqdn;
        }

        public void Dispose()
        {
            // No resources to dispose
        }
    }
}
