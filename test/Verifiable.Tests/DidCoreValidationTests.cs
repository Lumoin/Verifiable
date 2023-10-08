using System;
using System.Collections.Generic;
using Verifiable.Assessment;
using Verifiable.Core.Did;
using Xunit;


namespace Verifiable.Core
{
    public static class DidCoreValidation
    {
        public static Claim ValidateJsonLdUriAsFirst(Context obj)
        {            
            var firstContext = obj.Contexes?[0] as string;            
            bool isSuccess = firstContext?.Equals(DidCoreConstants.JsonLdContextFirstUri, StringComparison.InvariantCultureIgnoreCase) == true;

            return new Claim(ClaimId.DidCoreJsonLdUriAsFirst, isSuccess ? ClaimOutcome.Success : ClaimOutcome.Failure);
        }
    }


    /// <summary>
    /// Validation tests.
    /// </summary>
    public class DidCoreValidationTests
    {
        /// <summary>
        /// Validates the validator for context first URI checking as defined by <a href="https://www.w3.org/TR/did-core/#json-ld"/>.
        /// </summary>
        [Fact]
        public void ContextFirstUriIsValidatedCorrectly()
        {
            var faultyContext = new Context();            
            var faultyValidationResult = DidCoreValidation.ValidateJsonLdUriAsFirst(faultyContext);
            Assert.False(faultyValidationResult.Outcome == ClaimOutcome.Success, "Faulty context validation should fail.");                        
            
            var correctContext = new Context() { Contexes = new List<object>(new string[] { DidCoreConstants.JsonLdContextFirstUri }) };            
            var correctValidationResult = DidCoreValidation.ValidateJsonLdUriAsFirst(correctContext);
            Assert.True(correctValidationResult.Outcome == ClaimOutcome.Success, "Correct context validation should not fail.");            
        }
    }
}
