using System;
using Xunit;

namespace Verifiable.Tests.TestInfrastructure
{
    public class SkipTpmTestOnCiFactAttribute: FactAttribute
    {
        public SkipTpmTestOnCiFactAttribute()
        {            
            if(Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT") == "CI")
            {
                Skip = "Skipping on CI since TPM is not supported at the moment.";
            }
        }
    }
}
