using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;

namespace Keyfactor.Extensions.CAPlugin.Acme.Tests.Fakes
{
    /// <summary>
    /// Concrete IDomainValidator stub whose type name contains "rfc2136", matching the substring
    /// check ProcessAuthorizations uses to identify private/internal DNS providers (which skip the
    /// real-network public DNS propagation check entirely and just wait a fixed settle time). Using
    /// a real named class (rather than a Moq proxy, whose generated type name would not match) lets
    /// tests exercise that branch deterministically without any DNS network access.
    /// </summary>
    public class Rfc2136StyleDomainValidatorStub : IDomainValidator
    {
        public bool StageSucceeds { get; set; } = true;
        public bool ThrowOnCleanup { get; set; } = false;
        public int StageCallCount { get; private set; }
        public int CleanupCallCount { get; private set; }
        public string LastRecordName { get; private set; }
        public string LastRecordValue { get; private set; }

        public void Initialize(IDomainValidatorConfigProvider configProvider) { }

        public Task<DomainValidationResult> StageValidation(string recordName, string recordValue, CancellationToken cancellationToken)
        {
            StageCallCount++;
            LastRecordName = recordName;
            LastRecordValue = recordValue;
            return Task.FromResult(new DomainValidationResult
            {
                Success = StageSucceeds,
                ErrorMessage = StageSucceeds ? null : "stub staging failure"
            });
        }

        public Task<DomainValidationResult> CleanupValidation(string recordName, CancellationToken cancellationToken)
        {
            CleanupCallCount++;
            if (ThrowOnCleanup)
                throw new System.InvalidOperationException("stub cleanup failure");
            return Task.FromResult(new DomainValidationResult { Success = true });
        }

        public Task ValidateConfiguration(Dictionary<string, object> config) => Task.CompletedTask;

        public Dictionary<string, PropertyConfigInfo> GetDomainValidatorAnnotations() => new Dictionary<string, PropertyConfigInfo>();

        public string GetValidationType() => "dns-01";
    }
}
