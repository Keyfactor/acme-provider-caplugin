using Google.Apis.Auth.OAuth2;
using Google.Apis.Dns.v1;
using Google.Apis.Dns.v1.Data;
using Google.Apis.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

/// <summary>
/// Google Cloud DNS provider implementation for managing DNS TXT records.
/// Supports explicit Service Account key or Workload Identity (Application Default Credentials).
/// </summary>
public class GoogleDnsProvider : IDnsProvider
{
    private readonly DnsService _dnsService;
    private readonly string _projectId;

    /// <summary>
    /// Initializes a new instance of the GoogleDnsProvider class.
    /// If serviceAccountKeyPath is null or empty, uses Application Default Credentials.
    /// </summary>
    /// <param name="serviceAccountKeyPath">Path to the Service Account JSON key file (optional)</param>
    /// <param name="projectId">Google Cloud project ID containing the DNS zones</param>
    public GoogleDnsProvider(string? serviceAccountKeyPath, string projectId)
    {
        _projectId = projectId;

        GoogleCredential credential;

        if (!string.IsNullOrWhiteSpace(serviceAccountKeyPath))
        {
            Console.WriteLine("✅ Using explicit Service Account JSON key.");
            credential = GoogleCredential.FromFile(serviceAccountKeyPath);
        }
        else
        {
            Console.WriteLine("✅ Using Google Application Default Credentials (Workload Identity if on GCP).");
            credential = GoogleCredential.GetApplicationDefault();
        }

        _dnsService = new DnsService(new BaseClientService.Initializer
        {
            HttpClientInitializer = credential,
            ApplicationName = "Keyfactor-AcmeClient"
        });
    }

    /// <summary>
    /// Creates a new TXT record. Alias for UpsertRecordAsync.
    /// </summary>
    public async Task<bool> CreateRecordAsync(string recordName, string txtValue)
        => await UpsertRecordAsync(recordName, txtValue);

    /// <summary>
    /// Creates or updates a TXT record in Google Cloud DNS.
    /// If the record already exists, it will be replaced with the new value.
    /// </summary>
    public async Task<bool> UpsertRecordAsync(string recordName, string txtValue)
    {
        try
        {
            var zone = await GetZone(recordName);
            if (zone == null)
            {
                Console.WriteLine($"❌ No zone found for record: {recordName}");
                return false;
            }

            var formattedName = EnsureTrailingDot(recordName);

            // Get current records
            var rrsetsRequest = _dnsService.ResourceRecordSets.List(_projectId, zone.Name);
            var rrsets = await rrsetsRequest.ExecuteAsync();

            var existing = rrsets.Rrsets?.FirstOrDefault(r =>
                r.Type == "TXT" && r.Name.TrimEnd('.') == recordName.TrimEnd('.'));

            var newRrset = new ResourceRecordSet
            {
                Name = formattedName,
                Type = "TXT",
                Ttl = 60,
                Rrdatas = new List<string> { $"\"{txtValue}\"" }
            };

            var change = new Change();

            if (existing != null)
            {
                Console.WriteLine($"🔄 TXT record already exists. Replacing value for {recordName}.");
                change.Deletions = new List<ResourceRecordSet> { existing };
            }

            change.Additions = new List<ResourceRecordSet> { newRrset };

            var changeRequest = _dnsService.Changes.Create(change, _projectId, zone.Name);
            await changeRequest.ExecuteAsync();

            Console.WriteLine($"✅ Successfully upserted TXT record for {recordName}");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error upserting TXT record for {recordName}: {ex}");
            return false;
        }
    }

    /// <summary>
    /// Deletes a TXT record from Google Cloud DNS.
    /// </summary>
    public async Task<bool> DeleteRecordAsync(string recordName)
    {
        try
        {
            var zone = await GetZone(recordName);
            if (zone == null)
            {
                Console.WriteLine($"❌ No zone found for record: {recordName}");
                return false;
            }

            var formattedName = EnsureTrailingDot(recordName);

            var rrsetsRequest = _dnsService.ResourceRecordSets.List(_projectId, zone.Name);
            var rrsets = await rrsetsRequest.ExecuteAsync();

            var match = rrsets.Rrsets?.FirstOrDefault(r =>
                r.Type == "TXT" && r.Name.TrimEnd('.') == recordName.TrimEnd('.'));

            if (match == null)
            {
                Console.WriteLine($"⚠️ TXT record not found for deletion: {recordName}");
                return false;
            }

            var change = new Change
            {
                Deletions = new List<ResourceRecordSet> { match }
            };

            var deleteRequest = _dnsService.Changes.Create(change, _projectId, zone.Name);
            await deleteRequest.ExecuteAsync();

            Console.WriteLine($"✅ Successfully deleted TXT record for {recordName}");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error deleting TXT record for {recordName}: {ex}");
            return false;
        }
    }

    /// <summary>
    /// Finds the appropriate DNS zone for a given record name.
    /// </summary>
    private async Task<ManagedZone?> GetZone(string recordName)
    {
        try
        {
            var zonesRequest = _dnsService.ManagedZones.List(_projectId);
            var zonesResponse = await zonesRequest.ExecuteAsync();
            var zones = zonesResponse.ManagedZones;

            return zones?
                .Where(z => recordName.EndsWith(z.DnsName.TrimEnd('.')))
                .OrderByDescending(z => z.DnsName.Length)
                .FirstOrDefault();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error fetching DNS zones: {ex}");
            return null;
        }
    }

    /// <summary>
    /// Ensures record name is fully qualified (with trailing dot).
    /// </summary>
    private static string EnsureTrailingDot(string name)
        => name.EndsWith(".") ? name : name + ".";
}
