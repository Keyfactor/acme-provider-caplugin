using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Dns;
using Azure.ResourceManager.Dns.Models;
using Azure.ResourceManager.Resources;

/// <summary>
/// Azure DNS provider for ACME DNS-01 challenges.
/// Supports both Managed Identity and ClientSecret auth.
/// </summary>
public class AzureDnsProvider : IDnsProvider
{
    private readonly ArmClient _armClient;
    private readonly SubscriptionResource _subscription;

    /// <summary>
    /// Constructor that supports either explicit credentials or default credentials.
    /// If tenantId, clientId, clientSecret are provided, uses them.
    /// If not, uses DefaultAzureCredential (Managed Identity, env vars, VS sign-in, etc.)
    /// </summary>
    public AzureDnsProvider(string? tenantId, string? clientId, string? clientSecret, string subscriptionId)
    {
        TokenCredential credential;

        if (!string.IsNullOrWhiteSpace(tenantId) &&
            !string.IsNullOrWhiteSpace(clientId) &&
            !string.IsNullOrWhiteSpace(clientSecret))
        {
            Console.WriteLine("✅ Using explicit ClientSecretCredential.");
            credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
        }
        else
        {
            Console.WriteLine("✅ Using DefaultAzureCredential (Managed Identity, environment, VS sign-in, etc.).");
            credential = new DefaultAzureCredential();
        }

        _armClient = new ArmClient(credential, subscriptionId);
        _subscription = _armClient.GetSubscriptionResource(new ResourceIdentifier($"/subscriptions/{subscriptionId}"));
    }

    /// <summary>
    /// Creates or overwrites the TXT record with exactly one value.
    /// </summary>
    public async Task<bool> CreateRecordAsync(string recordName, string txtValue)
    {
        try
        {
            var zone = await GetDnsZoneAsync(recordName);
            if (zone == null)
            {
                Console.WriteLine($"Zone not found for {recordName}");
                return false;
            }

            var relativeName = GetRelativeRecordName(zone.Data.Name, recordName);
            var txtRecords = zone.GetDnsTxtRecords();

            DnsTxtRecordResource? existingResource = null;
            try
            {
                var response = await txtRecords.GetAsync(relativeName);
                existingResource = response.Value;
            }
            catch
            {
                // Not found — OK.
            }

            var newData = new DnsTxtRecordData
            {
                TtlInSeconds = 60,
                DnsTxtRecords = { new DnsTxtRecordInfo { Values = { txtValue } } }
            };

            await txtRecords.CreateOrUpdateAsync(Azure.WaitUntil.Completed, relativeName, newData);

            Console.WriteLine($"✅ TXT record upserted: {relativeName}.{zone.Data.Name} → \"{txtValue}\"");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Azure CreateRecordAsync exception: {ex}");
            return false;
        }
    }

    /// <summary>
    /// Deletes the specific TXT value or the whole record if empty.
    /// </summary>
    public async Task<bool> DeleteRecordAsync(string recordName, string txtValue)
    {
        try
        {
            var zone = await GetDnsZoneAsync(recordName);
            if (zone == null)
            {
                Console.WriteLine($"Zone not found for {recordName}");
                return false;
            }

            var relativeName = GetRelativeRecordName(zone.Data.Name, recordName);
            var txtRecords = zone.GetDnsTxtRecords();

            DnsTxtRecordResource txtResource;
            try
            {
                var response = await txtRecords.GetAsync(relativeName);
                txtResource = response.Value;
            }
            catch
            {
                Console.WriteLine($"TXT record not found for deletion: {relativeName}");
                return false;
            }

            var data = txtResource.Data;
            var toRemove = data.DnsTxtRecords.Where(r => r.Values.Contains(txtValue)).ToList();
            foreach (var r in toRemove)
                data.DnsTxtRecords.Remove(r);

            if (data.DnsTxtRecords.Count == 0)
            {
                await txtResource.DeleteAsync(Azure.WaitUntil.Completed);
                Console.WriteLine($"✅ Deleted empty TXT record: {relativeName}.{zone.Data.Name}");
            }
            else
            {
                await txtRecords.CreateOrUpdateAsync(Azure.WaitUntil.Completed, relativeName, data);
                Console.WriteLine($"✅ Removed value and updated TXT record: {relativeName}.{zone.Data.Name}");
            }

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Azure DeleteRecordAsync exception: {ex}");
            return false;
        }
    }

    public Task<bool> DeleteRecordAsync(string recordName)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Finds the most specific DNS zone by suffix.
    /// </summary>
    private async Task<DnsZoneResource?> GetDnsZoneAsync(string fqdn)
    {
        var zones = _subscription.GetDnsZonesAsync();
        var allZones = new List<DnsZoneResource>();
        await foreach (var z in zones)
        {
            allZones.Add(z);
        }

        return allZones
            .OrderByDescending(z => z.Data.Name.Length)
            .FirstOrDefault(z => fqdn.EndsWith(z.Data.Name, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Returns the relative record name inside the zone.
    /// </summary>
    private string GetRelativeRecordName(string zoneName, string fqdn)
    {
        if (fqdn.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase))
        {
            return fqdn.Substring(0, fqdn.Length - zoneName.Length - 1);
        }
        return fqdn;
    }
}
