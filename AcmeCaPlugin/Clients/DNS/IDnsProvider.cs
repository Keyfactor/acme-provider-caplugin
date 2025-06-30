using System.Threading.Tasks;

public interface IDnsProvider
{
    Task<bool> CreateRecordAsync(string recordName, string txtValue);
    Task<bool> DeleteRecordAsync(string recordName);
}
