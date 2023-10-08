using System.Collections.Generic;
using System.Linq;
using Verifiable.Assessment;
using Verifiable.Jwt;
using Xunit;

namespace Verifiable.Tests.Jwt
{
    public class JwtValidationTests
    {
        [Fact]
        public void Test1()
        {
            //TODO: E.g. https://stackoverflow.com/questions/43291659/usage-of-nbf-in-json-web-tokens.            
            var headers = new Dictionary<string, object> { { JwkProperties.Alg, WellKnownJwaValues.None } };
            var validationResult = DefaultJwtValidationClaims.ValidateAlgIsNotNone(headers);

            Assert.False(validationResult.All(c => c.Outcome == ClaimOutcome.Success));
        }
    }
}
