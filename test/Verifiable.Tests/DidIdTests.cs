using System.Linq;
using Verifiable.Assessment;
using Verifiable.Core.Did;
using Verifiable.Core.Did.Methods;
using Xunit;

namespace Verifiable.Core
{
    public class DidIdTests
    {
        /// <summary>
        /// All the known DID methods.
        /// </summary>
        private static DidMethodFactoryDelegate DidFactoryDelegate { get; } = did =>
        {
            return did switch
            {
                "did:key:" => new KeyDidMethod(did),
                "did:web:" => new WebDidMethod(did),
                "did:ebsi:" => new EbsiDidMethod(did),
                "did:keri:" => new KeriDidMethod(did),
                "did:plc:" => new PlaceholderDidMethod(did),
                _ => new GenericDidMethod(did)
            };
        };


        [Fact]
        public void DidIdTest()
        {
            const string DidUrl = "did:example:123456/path?versionId=1#public-key-0";
            var didDocument = new DidDocument { Id = new GenericDidMethod(DidUrl) };

            var resultClaims = DidDocumentValidationRules.ValidatePrefix(didDocument);
            Assert.True(resultClaims.All(c => c.Outcome == ClaimOutcome.Success));
        }        
    }
}