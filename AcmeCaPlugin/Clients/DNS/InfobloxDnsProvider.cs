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

public class InfobloxDnsProvider : IDnsProvider
{
    private readonly string _host;
    private readonly string _username;
    private readonly string _password;
    private readonly string _wapiVersion;
    private readonly HttpClient _httpClient;
    private readonly JsonSerializerOptions _jsonOptions;

    public InfobloxDnsProvider(string host, string username, string password, string wapiVersion = "2.12", bool ignoreSslErrors = false)
    {
        _host = host?.TrimEnd('/') ?? throw new ArgumentNullException(nameof(host));
        _username = username ?? throw new ArgumentNullException(nameof(username));
        _password = password ?? throw new ArgumentNullException(nameof(password));
        _wapiVersion = wapiVersion ?? "2.12";

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

            // Check if record already exists with the same value
            var searchUrl = $"record:txt?name={Uri.EscapeDataString(cleanName)}&text={Uri.EscapeDataString(txtValue)}";
            var searchResponse = await _httpClient.GetAsync(searchUrl);

            if (searchResponse.IsSuccessStatusCode)
            {
                var searchJson = await searchResponse.Content.ReadAsStringAsync();
                var records = JsonDocument.Parse(searchJson).RootElement;

                if (records.GetArrayLength() > 0)
                {
                    Console.WriteLine($"[Infoblox] TXT record already exists for {cleanName} with value {txtValue}. Skipping creation.");
                    return true; // Record already exists, no need to create duplicate
                }
            }

            // Create new record if it doesn't exist
            var payload = new
            {
                name = cleanName,
                text = txtValue,
                ttl = 60,
                view = "default"
            };

            var json = JsonSerializer.Serialize(payload);
            Console.WriteLine($"[Infoblox] Creating new TXT record. Payload: {json}");

            var request = new HttpRequestMessage(HttpMethod.Post, "./record:txt");
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");

            Console.WriteLine($"[Infoblox] Request URI: {request.RequestUri}");

            var response = await _httpClient.SendAsync(request);
            var result = await response.Content.ReadAsStringAsync();

            Console.WriteLine($"[Infoblox] Status: {response.StatusCode}");
            Console.WriteLine($"[Infoblox] Response: {result}");

            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Infoblox] ERROR: {ex.Message}");
            return false;
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
                Console.WriteLine($"[Infoblox] Failed to search for record: {searchResponse.StatusCode}");
                return false;
            }

            var searchJson = await searchResponse.Content.ReadAsStringAsync();
            var records = JsonDocument.Parse(searchJson).RootElement;

            if (records.GetArrayLength() == 0)
            {
                Console.WriteLine($"[Infoblox] No TXT records found for {cleanName}");
                return false;
            }

            var recordRef = records[0].GetProperty("_ref").GetString();
            if (string.IsNullOrEmpty(recordRef))
            {
                Console.WriteLine($"[Infoblox] Record reference is null or empty");
                return false;
            }

            var deleteResponse = await _httpClient.DeleteAsync(recordRef);
            var result = await deleteResponse.Content.ReadAsStringAsync();

            Console.WriteLine($"[Infoblox] Delete TXT: {deleteResponse.StatusCode} - {result}");
            return deleteResponse.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Infoblox] Error deleting TXT record: {ex.Message}");
            return false;
        }
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
    }
}
