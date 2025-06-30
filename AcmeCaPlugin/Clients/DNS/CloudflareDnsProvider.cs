using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

public class CloudflareDnsProvider : IDnsProvider
{
    private readonly string _apiToken;
    private readonly HttpClient _httpClient;
    private readonly JsonSerializerOptions _jsonOptions;

    public CloudflareDnsProvider(string apiToken)
    {
        _apiToken = apiToken ?? throw new ArgumentNullException(nameof(apiToken));

        _httpClient = new HttpClient
        {
            BaseAddress = new Uri("https://api.cloudflare.com/client/v4/")
        };
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _apiToken);

        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
    }

    public async Task<bool> CreateRecordAsync(string recordName, string txtValue)
    {
        // 1) Determine apex zone
        var zoneName = ExtractZoneFromRecord(recordName);
        var zoneId = await GetZoneIdAsync(zoneName);
        if (zoneId == null) return false;

        // 2) Get the relative record name for Cloudflare
        var relativeName = GetRelativeRecordName(recordName, zoneName);

        var payload = new
        {
            type = "TXT",
            name = relativeName,
            content = txtValue,
            ttl = 1
        };

        // Manual JSON serialization instead of PostAsJsonAsync
        var json = JsonSerializer.Serialize(payload, _jsonOptions);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        var response = await _httpClient.PostAsync($"zones/{zoneId}/dns_records", content);
        var result = await response.Content.ReadAsStringAsync();

        Console.WriteLine($"Create TXT: {response.StatusCode} - {result}");
        return response.IsSuccessStatusCode;
    }

    public async Task<bool> DeleteRecordAsync(string recordName)
    {
        // 1) Determine apex zone
        var zoneName = ExtractZoneFromRecord(recordName);
        var zoneId = await GetZoneIdAsync(zoneName);
        if (zoneId == null) return false;

        // 2) Get the relative record name for Cloudflare
        var relativeName = GetRelativeRecordName(recordName, zoneName);

        var recordsResp = await _httpClient.GetAsync($"zones/{zoneId}/dns_records?type=TXT&name={relativeName}");
        if (!recordsResp.IsSuccessStatusCode) return false;

        var json = await recordsResp.Content.ReadAsStringAsync();
        var doc = JsonDocument.Parse(json);

        var recordId = doc.RootElement.GetProperty("result").EnumerateArray()
            .FirstOrDefault().GetProperty("id").GetString();

        if (recordId == null) return false;

        var deleteResp = await _httpClient.DeleteAsync($"zones/{zoneId}/dns_records/{recordId}");
        var result = await deleteResp.Content.ReadAsStringAsync();

        Console.WriteLine($"Delete TXT: {deleteResp.StatusCode} - {result}");
        return deleteResp.IsSuccessStatusCode;
    }

    private async Task<string?> GetZoneIdAsync(string zoneName)
    {
        var response = await _httpClient.GetAsync($"zones?name={zoneName}");
        if (!response.IsSuccessStatusCode) return null;

        var json = await response.Content.ReadAsStringAsync();
        var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("result").EnumerateArray()
            .FirstOrDefault().GetProperty("id").GetString();
    }

    private string ExtractZoneFromRecord(string recordName)
    {
        if (string.IsNullOrWhiteSpace(recordName))
            return string.Empty;

        var parts = recordName.TrimEnd('.').Split('.');
        if (parts.Length < 2)
            return recordName;

        // Use last two labels as default zone: e.g., "keyfactoracme.com"
        return string.Join(".", parts.Skip(parts.Length - 2));
    }

    private string GetRelativeRecordName(string recordName, string zoneName)
    {
        var cleanName = recordName.TrimEnd('.');
        var cleanZone = zoneName.TrimEnd('.');

        // The recordName should be something like "_acme-challenge.www.keyfactorcloudflareacme.com"
        // We need to return the name relative to the zone

        // If the record name ends with the zone name, remove the zone suffix
        if (cleanName.EndsWith("." + cleanZone, StringComparison.OrdinalIgnoreCase))
        {
            // Remove the zone suffix, keeping the subdomain part
            var relativePart = cleanName.Substring(0, cleanName.Length - cleanZone.Length - 1);
            return relativePart;
        }
        else if (cleanName.Equals(cleanZone, StringComparison.OrdinalIgnoreCase))
        {
            // If the record name is exactly the zone name, it's the root
            return "@";
        }

        // If we can't determine the relative name, return as-is
        return cleanName;
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
    }
}