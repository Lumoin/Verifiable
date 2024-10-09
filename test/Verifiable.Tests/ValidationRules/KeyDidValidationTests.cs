using Verifiable.Assessment;
using Verifiable.Core.Did;
using Verifiable.Core.Did.Methods;

namespace Verifiable.Tests.ValidationRules
{
    /// <summary>
    /// Tests for <see cref="KeyDidValidationRules"/>.
    /// </summary>
    [TestClass]
    public sealed class KeyDidValidationTests
    {
        [TestMethod]
        public async Task KeyDidCanStartOnlyWithDidKey()
        {
            //These are test vectors from https://w3c-ccg.github.io/did-method-key/#test-vectors.
            var keyDid = new DidDocument();
            keyDid.Id = new KeyDidMethod("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");            
            var successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid);
            Assert.IsTrue(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));
            
            keyDid.Id = new KeyDidMethod("did:key:zInvalidMkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
            successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid);
            Assert.IsFalse(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));

            keyDid.Id = new KeyDidMethod("did:key: zInvalidMkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
            successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid);
            Assert.IsFalse(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));

            keyDid.Id = new KeyDidMethod("did:key:zInvalidMkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp ");
            successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid);
            Assert.IsFalse(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));

            keyDid.Id = new KeyDidMethod("did:key:zInvalid6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
            successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid);
            Assert.IsFalse(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));

            keyDid.Id = new KeyDidMethod("did:key:6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
            successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid);
            Assert.IsFalse(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));
        }


        [TestMethod]
        public void KeyDidVerificationMethodMustContainHashtag()
        {

        }
    }
}
