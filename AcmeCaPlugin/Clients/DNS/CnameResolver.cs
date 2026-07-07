// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0
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
    /// Resolves ACME challenge record names through CNAME delegation.
    ///
    /// ACME DNS-01 validation requires a TXT record at _acme-challenge.&lt;domain&gt;. Many
    /// organizations delegate that name to a separate, isolated validation zone via a CNAME
    /// so that ACME automation never needs write access to the production zone. A TXT record
    /// cannot coexist with a CNAME at the same name (RFC 1034), so the record must be created
    /// at the CNAME's target, not at the original name.
    ///
    /// CNAME delegation can be chained multiple levels deep (A -> B -> C -> ...). This resolver
    /// follows the chain until it reaches the terminal name that has no further CNAME, and
    /// returns that name. If the original name has no CNAME at all, it returns the original
    /// name unchanged, preserving the pre-delegation behavior for non-delegated domains.
    ///
    /// In the plugin-based DNS model the resolved terminal name is also used to select the
    /// DNS provider plugin, so a challenge delegated into a zone on a different provider is
    /// routed to the plugin that actually owns that zone.
    /// </summary>
    public class CnameResolver
    {
        private readonly ILogger _logger;
        private readonly List<IPAddress> _dnsServers;

        /// <summary>
        /// Maximum number of CNAME hops to follow before giving up. Guards against
        /// misconfigured or malicious CNAME loops and unreasonably long chains.
        /// </summary>
        private const int MaxCnameDepth = 10;

        /// <summary>
        /// Creates a CNAME resolver.
        /// </summary>
        /// <param name="logger">Logger instance</param>
        /// <param name="verificationServer">Optional DNS server IP to query. For private/internal
        /// delegation zones, specify the authoritative DNS server. Leave null/empty to use public
        /// DNS servers.</param>
        public CnameResolver(ILogger logger, string verificationServer = null)
        {
            _logger = logger;
            _dnsServers = new List<IPAddress>();

            if (!string.IsNullOrWhiteSpace(verificationServer) && IPAddress.TryParse(verificationServer, out var privateServer))
            {
                _dnsServers.Add(privateServer);
                _logger.LogInformation("CNAME resolution will use private DNS server: {Server}", verificationServer);
            }
            else
            {
                // Public recursive resolvers. Any one that answers is sufficient.
                _dnsServers.Add(IPAddress.Parse("8.8.8.8"));       // Google
                _dnsServers.Add(IPAddress.Parse("1.1.1.1"));       // Cloudflare
                _dnsServers.Add(IPAddress.Parse("9.9.9.9"));       // Quad9
            }
        }

        /// <summary>
        /// Resolves the record name where the ACME TXT record must actually be created,
        /// following any chain of CNAME delegations to its terminal target.
        /// </summary>
        /// <param name="recordName">The ACME challenge record name from the CA
        /// (e.g., _acme-challenge.example.com)</param>
        /// <returns>The terminal record name to create the TXT record on. If no CNAME
        /// delegation exists, the original name is returned unchanged.</returns>
        public async Task<string> ResolveChallengeTargetAsync(string recordName)
        {
            if (string.IsNullOrWhiteSpace(recordName))
                return recordName;

            var original = Normalize(recordName);
            var current = original;
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { current };

            for (int depth = 0; depth < MaxCnameDepth; depth++)
            {
                var target = await QueryCnameTargetAsync(current);

                if (string.IsNullOrEmpty(target))
                {
                    // No further CNAME at this name -> this is the terminal target.
                    if (!string.Equals(current, original, StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogInformation(
                            "CNAME delegation resolved: {Original} -> {Target}", recordName, current);
                    }
                    else
                    {
                        _logger.LogDebug(
                            "No CNAME delegation found for {RecordName}; using original name", recordName);
                    }
                    return current;
                }

                target = Normalize(target);

                if (!visited.Add(target))
                {
                    _logger.LogWarning(
                        "CNAME loop detected while resolving {RecordName} (revisited {Target}). Stopping at {Current}.",
                        recordName, target, current);
                    return current;
                }

                _logger.LogDebug("Following CNAME hop: {Current} -> {Target}", current, target);
                current = target;
            }

            _logger.LogWarning(
                "CNAME chain for {RecordName} exceeded maximum depth of {MaxDepth}. Using last resolved name {Current}.",
                recordName, MaxCnameDepth, current);
            return current;
        }

        /// <summary>
        /// Queries a single CNAME hop for the given name. Returns the CNAME target if one
        /// exists at this exact name, otherwise null. Tries each configured DNS server until
        /// one answers.
        /// </summary>
        private async Task<string> QueryCnameTargetAsync(string name)
        {
            Exception lastError = null;

            foreach (var dnsServer in _dnsServers)
            {
                try
                {
                    var client = new LookupClient(dnsServer);
                    var result = await client.QueryAsync(name, QueryType.CNAME);

                    // A recursive resolver may return the entire CNAME chain in one answer.
                    // Take only the hop whose owner name matches the name we asked about so
                    // that the caller walks the chain one deterministic step at a time.
                    var cname = result.Answers
                        .OfType<DnsClient.Protocol.CNameRecord>()
                        .FirstOrDefault(r => string.Equals(
                            Normalize(r.DomainName.Value), name, StringComparison.OrdinalIgnoreCase));

                    if (cname != null)
                        return cname.CanonicalName.Value;

                    // Server answered but there is no CNAME at this name.
                    return null;
                }
                catch (Exception ex)
                {
                    lastError = ex;
                    _logger.LogTrace("CNAME query for {Name} against {Server} failed: {Error}",
                        name, dnsServer, ex.Message);
                }
            }

            // Every server errored. Treat as "no delegation discoverable" but warn, since a
            // real CNAME that we failed to see would cause record creation to fail downstream.
            _logger.LogWarning(
                "Unable to query CNAME for {Name} from any DNS server: {Error}. Proceeding as if no delegation exists.",
                name, lastError?.Message);
            return null;
        }

        /// <summary>
        /// Normalizes a DNS name for comparison: strips a single trailing dot and lowercases.
        /// </summary>
        private static string Normalize(string name)
        {
            if (string.IsNullOrEmpty(name))
                return name;

            return name.TrimEnd('.').ToLowerInvariant();
        }
    }
}
