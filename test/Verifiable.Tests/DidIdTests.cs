using System.Linq;
using Verifiable.Assessment;
using Verifiable.Core.Did;
using Xunit;

namespace Verifiable.Core
{
    public class DidIdTests
    {
        /// <summary>
        /// All the known DID methods.
        /// </summary>
        private static DidIdFactoryDelegate DidFactoryDelegate { get; } = did =>
        {
            return did switch
            {
                "did:key:" => new KeyDidId(did),
                "did:web:" => new WebDidId(did),
                "did:ebsi:" => new EbsiDidId(did),
                "did:keri:" => new KeriDidId(did),
                "did:plc:" => new PlaceholderDidId(did),
                _ => new GenericDidId(did)
            };
        };


        [Fact]
        public void DidIdTest()
        {
            const string DidUrl = "did:example:123456/path?versionId=1#public-key-0";
            var didDocument = new DidDocument { Id = new GenericDidId(DidUrl) };

            var resultClaims = DidDocumentValidationRules.ValidatePrefix(didDocument);
            Assert.True(resultClaims.All(c => c.Outcome == ClaimOutcome.Success));
        }        
    }
}