using Keyfactor.AnyGateway.Extensions;
using System.Collections.Generic;

namespace Keyfactor.Extensions.CAPlugin.Acme
{
    public class DomainValidatorConfigProvider : IDomainValidatorConfigProvider
    {
        public Dictionary<string, object> DomainValidationConfiguration { get; }

        public DomainValidatorConfigProvider(Dictionary<string, object> config)
        {
            DomainValidationConfiguration = config;
        }
    }
}