using Verifiable.Assessment;
using Verifiable.Core.Did;


namespace Verifiable.Tests.Core
{
    public static class DidCoreValidation
    {
        public static Claim ValidateJsonLdUriAsFirst(Context obj)
        {            
            var firstContext = obj.Contexes?[0] as string;            
            bool isSuccess = firstContext?.Equals(DidCoreConstants.JsonLdContextFirstUri, StringComparison.OrdinalIgnoreCase) == true;

            return new Claim(ClaimId.DidCoreJsonLdUriAsFirst, isSuccess ? ClaimOutcome.Success : ClaimOutcome.Failure);
        }
    }


    /// <summary>
    /// Validation tests.
    /// </summary>
    [TestClass]
    public sealed class DidCoreValidationTests
    {
        /// <summary>
        /// Validates the validator for context first URI checking as defined by <a href="https://www.w3.org/TR/did-core/#json-ld"/>.
        /// </summary>
        [TestMethod]
        public void ContextFirstUriIsValidatedCorrectly()
        {
            var faultyContext = new Context();            
            var faultyValidationResult = DidCoreValidation.ValidateJsonLdUriAsFirst(faultyContext);
            Assert.IsFalse(faultyValidationResult.Outcome == ClaimOutcome.Success, "Faulty context validation should fail.");                        
            
            var correctContext = new Context() { Contexes = new List<object>(new string[] { DidCoreConstants.JsonLdContextFirstUri }) };            
            var correctValidationResult = DidCoreValidation.ValidateJsonLdUriAsFirst(correctContext);
            Assert.IsTrue(correctValidationResult.Outcome == ClaimOutcome.Success, "Correct context validation should not fail.");            
        }
    }
}
