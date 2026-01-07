using Verifiable.Core.Assessment;
using Verifiable.Jose;

namespace Verifiable.Tests.Jwt
{
    [TestClass]
    public sealed class JwtValidationTests
    {
        [TestMethod]
        public void Test1()
        {
            //TODO: E.g. https://stackoverflow.com/questions/43291659/usage-of-nbf-in-json-web-tokens.            
            var headers = new Dictionary<string, object> { { JwkProperties.Alg, WellKnownJwaValues.None } };
            var validationResult = DefaultJwtValidationClaims.ValidateAlgIsNotNone(headers);

            Assert.IsFalse(validationResult.All(c => c.Outcome == ClaimOutcome.Success));
        }
    }
}
