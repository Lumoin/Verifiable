using DotDecentralized.Core;
using DotDecentralized.Core.Did;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using Xunit;

namespace DotDecentralized.Tests
{
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
            ICollection<ValidationResult> faultyValidationResults = new Collection<ValidationResult>();
            bool faultyResult = DidCoreValidation.TryValidJsonLdUriAsFirst(faultyContext, out faultyValidationResults);
            Assert.False(faultyResult, "Faulty context validation should fail.");
            Assert.NotEmpty(faultyValidationResults);
            Assert.True(faultyValidationResults.Count == 1, "There should be exactly one validation result for one validation error.");
            Assert.False(string.IsNullOrWhiteSpace(faultyValidationResults.ElementAt(0).ErrorMessage));

            var correctContext = new Context() { Contexes = new List<object>(new string[] { DidCoreConstants.JsonLdContextFirstUri }) };
            ICollection<ValidationResult> correctValidationResults = new Collection<ValidationResult>();
            bool correctResult = DidCoreValidation.TryValidJsonLdUriAsFirst(correctContext, out correctValidationResults);
            Assert.True(correctResult, "Correct context validation should not fail.");
            Assert.Empty(correctValidationResults);
        }
    }
}
