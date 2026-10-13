using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

/// <summary>
/// NS1 DNS provider implementation for managing DNS TXT records.
/// Uses NS1's REST API with an API key.
/// </summary>
public class Ns1DnsProvider : IDnsProvider
{
    private readonly HttpClient _httpClient;
    private readonly string _apiKey;
    private List<string> _cachedZones;

    public Ns1DnsProvider(string apiKey)
    {
        _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
        _httpClient = new HttpClient
        {
            BaseAddress = new Uri("https://api.nsone.net/v1/")
        };
        _httpClient.DefaultRequestHeaders.Add("X-NSONE-Key", _apiKey);
    }

    /// <summary>
    /// Creates or updates a TXT record.
    /// </summary>
    public async Task<bool> CreateRecordAsync(string recordName, string txtValue)
        => await UpsertRecordAsync(recordName, txtValue);

    /// <summary>
    /// Creates or updates a TXT record.
    /// </summary>
    public async Task<bool> UpsertRecordAsync(string recordName, string txtValue)
    {
        try
        {
            var (zoneName, relativeName) = await ExtractZoneAndRelativeNameAsync(recordName);

            Console.WriteLine($"🔄 Upserting TXT record for {recordName} (zone: {zoneName}, relative: '{relativeName}')");

            // For NS1 API, the domain field should always be the full record name
            var fullDomain = recordName.TrimEnd('.');

            var record = new Ns1Record
            {
                zone = zoneName,
                domain = fullDomain,
                type = "TXT",
                answers = new List<Ns1Answer>
                {
                    new Ns1Answer { answer = new List<string> { txtValue } }
                },
                ttl = 60,
                use_client_subnet = true
            };

            // For NS1 API: zones/{zone}/{domain}/TXT where domain is the full record name
            var urlPath = $"zones/{zoneName}/{fullDomain}/TXT";

            Console.WriteLine($"🌐 API URL: {urlPath}");
            Console.WriteLine($"📄 Domain in body: {fullDomain}");

            // Use PUT for both create and update - NS1 API handles this automatically
            var response = await _httpClient.PutAsJsonAsync(urlPath, record);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"❌ NS1 API Error: {response.StatusCode} - {errorContent}");
                return false;
            }

            Console.WriteLine($"✅ Successfully upserted TXT record for {recordName}");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error upserting TXT record for {recordName}: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Deletes a TXT record.
    /// </summary>
    public async Task<bool> DeleteRecordAsync(string recordName)
    {
        try
        {
            var (zoneName, relativeName) = await ExtractZoneAndRelativeNameAsync(recordName);
            var fullDomain = recordName.TrimEnd('.');
            var urlPath = $"zones/{zoneName}/{fullDomain}/TXT";

            var response = await _httpClient.DeleteAsync(urlPath);

            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine($"✅ Successfully deleted TXT record for {recordName}");
                return true;
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                Console.WriteLine($"⚠️ TXT record not found for deletion: {recordName}");
                return true; // Consider it successful if already gone
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"❌ Error deleting TXT record: {response.StatusCode} - {errorContent}");
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error deleting TXT record for {recordName}: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Fetches a TXT record if it exists.
    /// </summary>
    private async Task<Ns1Record?> GetRecordAsync(string zoneName, string relativeName)
    {
        try
        {
            var fullDomain = $"{relativeName}.{zoneName}".TrimStart('.');
            var urlPath = $"zones/{zoneName}/{fullDomain}/TXT";

            var response = await _httpClient.GetAsync(urlPath);

            if (!response.IsSuccessStatusCode)
                return null;

            return await response.Content.ReadFromJsonAsync<Ns1Record>();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Gets all zones from NS1 API.
    /// </summary>
    private async Task<List<string>> GetZonesAsync()
    {
        if (_cachedZones != null)
            return _cachedZones;

        try
        {
            var response = await _httpClient.GetAsync("zones");
            response.EnsureSuccessStatusCode();

            var zones = await response.Content.ReadFromJsonAsync<List<Ns1Zone>>();
            _cachedZones = zones?.Select(z => z.zone).ToList() ?? new List<string>();

            return _cachedZones;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"⚠️ Warning: Could not fetch zones from NS1: {ex.Message}");
            return new List<string>();
        }
    }

    /// <summary>
    /// Extracts the zone name and relative record name by finding the longest matching zone.
    /// </summary>
    private async Task<(string zoneName, string relativeName)> ExtractZoneAndRelativeNameAsync(string fqdn)
    {
        var cleanFqdn = fqdn.TrimEnd('.');
        var labels = cleanFqdn.Split('.');

        // Get available zones
        var zones = await GetZonesAsync();

        // Find the longest matching zone
        for (int i = 0; i < labels.Length; i++)
        {
            var potentialZone = string.Join(".", labels.Skip(i));
            if (zones.Contains(potentialZone))
            {
                var relativeName = i == 0 ? "" : string.Join(".", labels.Take(i));
                Console.WriteLine($"🔍 Found zone: {potentialZone}, relative: '{relativeName}' for {fqdn}");
                return (potentialZone, relativeName);
            }
        }

        // Fallback: assume zone is last two labels (works for most cases)
        if (labels.Length >= 2)
        {
            var zoneName = string.Join(".", labels.TakeLast(2));
            var relativeName = labels.Length > 2 ? string.Join(".", labels.Take(labels.Length - 2)) : "";

            Console.WriteLine($"⚠️ Warning: Using fallback zone detection for {fqdn} -> zone: {zoneName}, relative: {relativeName}");
            return (zoneName, relativeName);
        }

        throw new InvalidOperationException($"Cannot determine zone for FQDN: {fqdn}");
    }

    /// <summary>
    /// NS1 Zone model for API responses.
    /// </summary>
    private class Ns1Zone
    {
        [JsonPropertyName("zone")]
        public string zone { get; set; }
    }

    /// <summary>
    /// NS1 Record model with all commonly required fields.
    /// </summary>
    private class Ns1Record
    {
        [JsonPropertyName("zone")]
        public string zone { get; set; }

        [JsonPropertyName("domain")]
        public string domain { get; set; }

        [JsonPropertyName("type")]
        public string type { get; set; }

        [JsonPropertyName("ttl")]
        public int ttl { get; set; }

        [JsonPropertyName("answers")]
        public List<Ns1Answer> answers { get; set; }

        [JsonPropertyName("use_client_subnet")]
        public bool? use_client_subnet { get; set; }
    }

    /// <summary>
    /// NS1 Answer model.
    /// </summary>
    private class Ns1Answer
    {
        [JsonPropertyName("answer")]
        public List<string> answer { get; set; }
    }

    /// <summary>
    /// Dispose of HttpClient resources.
    /// </summary>
    public void Dispose()
    {
        _httpClient?.Dispose();
    }
}