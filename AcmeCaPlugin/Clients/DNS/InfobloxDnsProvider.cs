using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

public class InfobloxDnsProvider : IDnsProvider
{
    private readonly string _host;
    private readonly string _username;
    private readonly string _password;
    private readonly string _wapiVersion;
    private readonly HttpClient _httpClient;
    private readonly JsonSerializerOptions _jsonOptions;
    private readonly ILogger _logger;

    public InfobloxDnsProvider(string host, string username, string password, string wapiVersion = "2.12", bool ignoreSslErrors = false, ILogger logger = null)
    {
        _host = host?.TrimEnd('/') ?? throw new ArgumentNullException(nameof(host));
        _username = username ?? throw new ArgumentNullException(nameof(username));
        _password = password ?? throw new ArgumentNullException(nameof(password));
        _wapiVersion = wapiVersion ?? "2.12";
        _logger = logger;

        var handler = new HttpClientHandler();
        if (ignoreSslErrors)
        {
            handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;
        }

        _httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri($"{_host}/wapi/v{_wapiVersion}/")
        };

        var authValue = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{_username}:{_password}"));
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", authValue);

        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
    }

    public async Task<bool> CreateRecordAsync(string recordName, string txtValue)
    {
        try
        {
            var cleanName = recordName.TrimEnd('.');

            // Extract the zone from the record name
            var zoneName = ExtractZoneFromRecord(cleanName);
            _logger?.LogDebug("[Infoblox] Extracted zone: {ZoneName} from record: {RecordName}", zoneName, cleanName);

            // Verify zone exists first
            var zoneExists = await VerifyZoneExistsAsync(zoneName);
            if (!zoneExists)
            {
                var errorMsg = $"Infoblox zone '{zoneName}' not found or not accessible. Cannot create DNS record '{cleanName}'. Please verify the zone exists in Infoblox and is configured as an authoritative zone.";
                _logger?.LogError("[Infoblox] {ErrorMessage}", errorMsg);
                throw new InvalidOperationException(errorMsg);
            }

            // Delete any existing records with the same name first to ensure only one record exists
            var searchUrl = $"./record:txt?name={Uri.EscapeDataString(cleanName)}";
            _logger?.LogDebug("[Infoblox] Searching for existing records at: {SearchUrl}", searchUrl);

            var searchResponse = await _httpClient.GetAsync(searchUrl);
            _logger?.LogDebug("[Infoblox] Search response status: {StatusCode}", searchResponse.StatusCode);

            if (searchResponse.IsSuccessStatusCode)
            {
                var searchJson = await searchResponse.Content.ReadAsStringAsync();
                var records = JsonDocument.Parse(searchJson).RootElement;
                var recordCount = records.GetArrayLength();
                _logger?.LogDebug("[Infoblox] Found {RecordCount} existing records", recordCount);

                // Delete all existing records with this name
                foreach (var record in records.EnumerateArray())
                {
                    var recordRef = record.GetProperty("_ref").GetString();
                    if (!string.IsNullOrEmpty(recordRef))
                    {
                        var deleteResponse = await _httpClient.DeleteAsync(recordRef);
                        _logger?.LogDebug("[Infoblox] Deleted existing TXT record {RecordRef}: {StatusCode}", recordRef, deleteResponse.StatusCode);
                    }
                }
            }
            else
            {
                var searchErrorBody = await searchResponse.Content.ReadAsStringAsync();
                _logger?.LogWarning("[Infoblox] Search for existing records failed: {StatusCode}, Response: {Response}",
                    searchResponse.StatusCode, searchErrorBody);
            }

            // Create new record (zone is automatically determined by Infoblox from the FQDN)
            var payload = new
            {
                name = cleanName,
                text = txtValue,
                ttl = 60,
                view = "default"
            };

            var json = JsonSerializer.Serialize(payload);
            _logger?.LogDebug("[Infoblox] Creating new TXT record. Payload: {Payload}", json);

            var request = new HttpRequestMessage(HttpMethod.Post, "./record:txt");
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");

            _logger?.LogTrace("[Infoblox] Request URI: {RequestUri}", request.RequestUri);

            var response = await _httpClient.SendAsync(request);
            var result = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("[Infoblox] Status: {StatusCode}", response.StatusCode);
            _logger?.LogTrace("[Infoblox] Response: {Response}", result);

            if (!response.IsSuccessStatusCode)
            {
                // Include detailed error information in the exception
                var errorDetails = $"Infoblox API returned {response.StatusCode}. Zone: {zoneName}, Record: {cleanName}, Response: {result}";
                _logger?.LogError("[Infoblox] API Error: {ErrorDetails}", errorDetails);
                throw new InvalidOperationException(errorDetails);
            }

            // Verify the record was created by searching for it
            await Task.Delay(1000); // Brief delay to ensure record is committed
            var verifySuccess = await VerifyRecordExists(cleanName, txtValue);
            if (verifySuccess)
            {
                _logger?.LogDebug("[Infoblox] Verified TXT record exists: {RecordName}", cleanName);
            }
            else
            {
                _logger?.LogWarning("[Infoblox] Record creation returned success, but verification failed for {RecordName}", cleanName);
                throw new InvalidOperationException($"Infoblox record verification failed for {cleanName}. Record was created but could not be found when querying back.");
            }

            return true;
        }
        catch (InvalidOperationException)
        {
            // Re-throw our specific exceptions with detailed error messages
            throw;
        }
        catch (Exception ex)
        {
            // Wrap unexpected exceptions with context
            _logger?.LogError(ex, "[Infoblox] DNS provider error");
            throw new InvalidOperationException($"Infoblox DNS provider error: {ex.Message}", ex);
        }
    }

    public async Task<bool> DeleteRecordAsync(string recordName)
    {
        try
        {
            var cleanName = recordName.TrimEnd('.');
            var searchUrl = $"record:txt?name={Uri.EscapeDataString(cleanName)}";

            var searchResponse = await _httpClient.GetAsync(searchUrl);
            if (!searchResponse.IsSuccessStatusCode)
            {
                _logger?.LogDebug("[Infoblox] Failed to search for record: {StatusCode}", searchResponse.StatusCode);
                return false;
            }

            var searchJson = await searchResponse.Content.ReadAsStringAsync();
            var records = JsonDocument.Parse(searchJson).RootElement;

            if (records.GetArrayLength() == 0)
            {
                _logger?.LogDebug("[Infoblox] No TXT records found for {RecordName}", cleanName);
                return false;
            }

            var recordRef = records[0].GetProperty("_ref").GetString();
            if (string.IsNullOrEmpty(recordRef))
            {
                _logger?.LogDebug("[Infoblox] Record reference is null or empty");
                return false;
            }

            var deleteResponse = await _httpClient.DeleteAsync(recordRef);
            var result = await deleteResponse.Content.ReadAsStringAsync();

            _logger?.LogDebug("[Infoblox] Delete TXT: {StatusCode} - {Result}", deleteResponse.StatusCode, result);
            return deleteResponse.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "[Infoblox] Error deleting TXT record");
            return false;
        }
    }

    private string ExtractZoneFromRecord(string recordName)
    {
        if (string.IsNullOrWhiteSpace(recordName))
            return string.Empty;

        var parts = recordName.TrimEnd('.').Split('.');
        if (parts.Length < 2)
            return recordName;

        // Use last two labels as default zone: e.g., "keyfactortestb.com"
        return string.Join(".", parts.Skip(parts.Length - 2));
    }

    private async Task<bool> VerifyZoneExistsAsync(string zoneName)
    {
        try
        {
            var zoneUrl = $"zone_auth?fqdn={Uri.EscapeDataString(zoneName)}";
            var response = await _httpClient.GetAsync(zoneUrl);

            if (!response.IsSuccessStatusCode)
            {
                _logger?.LogDebug("[Infoblox] Zone lookup failed: {StatusCode}", response.StatusCode);
                return false;
            }

            var json = await response.Content.ReadAsStringAsync();
            var zones = JsonDocument.Parse(json).RootElement;
            var zoneExists = zones.GetArrayLength() > 0;

            _logger?.LogDebug("[Infoblox] Zone {ZoneName} exists: {ZoneExists}", zoneName, zoneExists);
            return zoneExists;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "[Infoblox] Error verifying zone");
            return false;
        }
    }

    private async Task<bool> VerifyRecordExists(string recordName, string expectedValue)
    {
        try
        {
            var searchUrl = $"./record:txt?name={Uri.EscapeDataString(recordName)}";
            var response = await _httpClient.GetAsync(searchUrl);

            if (!response.IsSuccessStatusCode)
            {
                return false;
            }

            var json = await response.Content.ReadAsStringAsync();
            var records = JsonDocument.Parse(json).RootElement;

            foreach (var record in records.EnumerateArray())
            {
                var text = record.GetProperty("text").GetString();
                if (text == expectedValue)
                {
                    return true;
                }
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "[Infoblox] Error verifying record");
            return false;
        }
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
    }
}
