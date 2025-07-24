using Amazon;
using Amazon.Route53;
using Amazon.Route53.Model;
using Amazon.Runtime;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

/// <summary>
/// AWS Route 53 DNS provider implementation for ACME DNS-01 challenges.
/// This class handles creating and deleting TXT records for domain validation.
/// Supports explicit access key or automatic EC2 instance role credentials.
/// </summary>
public class AwsRoute53DnsProvider : IDnsProvider
{
    private readonly IAmazonRoute53 _route53Client;

    /// <summary>
    /// Initializes the Route 53 provider.
    /// If access key & secret key are provided, they are used.
    /// Otherwise, it uses the default AWS credentials chain (e.g., EC2 instance profile).
    /// </summary>
    /// <param name="awsAccessKeyId">AWS Access Key ID (optional)</param>
    /// <param name="awsSecretAccessKey">AWS Secret Access Key (optional)</param>
    /// <param name="region">Region endpoint (optional, Route 53 is global so usually us-east-1 works)</param>
    public AwsRoute53DnsProvider(string? awsAccessKeyId = null, string? awsSecretAccessKey = null, RegionEndpoint? region = null)
    {
        if (!string.IsNullOrEmpty(awsAccessKeyId) && !string.IsNullOrEmpty(awsSecretAccessKey))
        {
            Console.WriteLine("Using explicit AWS credentials.");
            var creds = new BasicAWSCredentials(awsAccessKeyId, awsSecretAccessKey);
            _route53Client = new AmazonRoute53Client(creds, region ?? RegionEndpoint.USEast1);
        }
        else
        {
            Console.WriteLine("Using default AWS credential chain (instance role, environment, or config).");
            _route53Client = new AmazonRoute53Client(region ?? RegionEndpoint.USEast1);
        }
    }

    /// <summary>
    /// Creates or updates a TXT record.
    /// </summary>
    public async Task<bool> CreateRecordAsync(string recordName, string txtValue)
        => await UpsertRecordAsync(recordName, txtValue);

    /// <summary>
    /// Creates or updates a TXT record in Route 53.
    /// </summary>
    public async Task<bool> UpsertRecordAsync(string recordName, string txtValue)
    {
        try
        {
            var zone = await FindHostedZoneAsync(recordName);
            if (zone == null)
            {
                Console.WriteLine($"No hosted zone found for {recordName}");
                return false;
            }

            var request = new ChangeResourceRecordSetsRequest
            {
                HostedZoneId = zone.Id,
                ChangeBatch = new ChangeBatch
                {
                    Changes = new List<Change>
                    {
                        new Change
                        {
                            Action = ChangeAction.UPSERT,
                            ResourceRecordSet = new ResourceRecordSet
                            {
                                Name = EnsureTrailingDot(recordName),
                                Type = RRType.TXT,
                                TTL = 60,
                                ResourceRecords = new List<ResourceRecord>
                                {
                                    new ResourceRecord { Value = $"\"{txtValue}\"" }
                                }
                            }
                        }
                    }
                }
            };

            var response = await _route53Client.ChangeResourceRecordSetsAsync(request);
            Console.WriteLine($"[UPsert] TXT record for {recordName} requested. Status: {response.HttpStatusCode}");
            return response.HttpStatusCode == System.Net.HttpStatusCode.OK;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Error] Upserting TXT record: {ex}");
            return false;
        }
    }

    /// <summary>
    /// Deletes a TXT record in Route 53.
    /// </summary>
    public async Task<bool> DeleteRecordAsync(string recordName)
    {
        try
        {
            var zone = await FindHostedZoneAsync(recordName);
            if (zone == null)
            {
                Console.WriteLine($"No hosted zone found for {recordName}");
                return false;
            }

            var listResponse = await _route53Client.ListResourceRecordSetsAsync(new ListResourceRecordSetsRequest
            {
                HostedZoneId = zone.Id,
                StartRecordName = EnsureTrailingDot(recordName),
                StartRecordType = RRType.TXT
            });

            var existing = listResponse.ResourceRecordSets.FirstOrDefault(r =>
                r.Name.TrimEnd('.') == recordName.TrimEnd('.') && r.Type == RRType.TXT);

            if (existing == null)
            {
                Console.WriteLine($"No existing TXT record found for {recordName}");
                return false;
            }

            var deleteRequest = new ChangeResourceRecordSetsRequest
            {
                HostedZoneId = zone.Id,
                ChangeBatch = new ChangeBatch
                {
                    Changes = new List<Change>
                    {
                        new Change
                        {
                            Action = ChangeAction.DELETE,
                            ResourceRecordSet = existing
                        }
                    }
                }
            };

            var deleteResponse = await _route53Client.ChangeResourceRecordSetsAsync(deleteRequest);
            Console.WriteLine($"[Delete] TXT record for {recordName} requested. Status: {deleteResponse.HttpStatusCode}");
            return deleteResponse.HttpStatusCode == System.Net.HttpStatusCode.OK;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Error] Deleting TXT record: {ex}");
            return false;
        }
    }

    /// <summary>
    /// Finds the most specific hosted zone matching the given record name.
    /// </summary>
    private async Task<HostedZone?> FindHostedZoneAsync(string recordName)
    {
        var response = await _route53Client.ListHostedZonesAsync();
        var zones = response.HostedZones;

        return zones
            .Where(z => recordName.EndsWith(z.Name.TrimEnd('.'), StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(z => z.Name.Length)
            .FirstOrDefault();
    }

    private static string EnsureTrailingDot(string name)
        => name.EndsWith(".") ? name : name + ".";
}
