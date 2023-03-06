using System.Linq;
using System.Threading.Tasks;
using Verifiable.Assessment;
using Verifiable.Core.Did;
using Xunit;

namespace Verifiable.Tests.ValidationRules
{
    /// <summary>
    /// Tests for <see cref="KeyDidValidationRules"/>.
    /// </summary>
    public class KeyDidValidationTests
    {
        [Fact]
        public async Task KeyDidCanStartOnlyWithDidKey()
        {
            //These are test vectors from https://w3c-ccg.github.io/did-method-key/#test-vectors.
            var keyDid = new DidDocument();
            keyDid.Id = new KeyDidId("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");            
            var successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid);
            Assert.True(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));
            
            keyDid.Id = new KeyDidId("did:key:zInvalidMkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
            successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid);
            Assert.False(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));

            keyDid.Id = new KeyDidId("did:key: zInvalidMkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
            successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid);
            Assert.False(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));

            keyDid.Id = new KeyDidId("did:key:zInvalidMkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp ");
            successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid);
            Assert.False(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));

            keyDid.Id = new KeyDidId("did:key:zInvalid6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
            successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid);
            Assert.False(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));

            keyDid.Id = new KeyDidId("did:key:6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
            successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid);
            Assert.False(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));
        }


        [Fact]
        public void KeyDidVerificationMethodMustContainHashtag()
        {

        }
    }
}
