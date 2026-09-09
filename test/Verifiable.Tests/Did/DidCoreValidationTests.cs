using Verifiable.Core.Assessment;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Validation;


namespace Verifiable.Tests.Did
{
    /// <summary>
    /// Validation tests for the DID Core <c>@context</c> first-entry rule, exercised through
    /// <see cref="ContextValidationRules.ValidateFirstEntry"/>.
    /// </summary>
    [TestClass]
    internal sealed class DidCoreValidationTests
    {
        /// <summary>
        /// <see href="https://www.w3.org/TR/did-1.0/#x6-3-1-production">DID Core 1.0 §6.3.1
        /// Production</see>: an absent <c>@context</c> fails the claim rather than throwing.
        /// </summary>
        [TestMethod]
        public void ContextFirstUriFailsWhenContextIsAbsentForDidCore10()
        {
            Context? missingContext = null;
            Claim missingResult = ContextValidationRules.ValidateFirstEntry(missingContext, DidCoreConstants.JsonLdContextFirstUri);
            Assert.AreNotEqual(ClaimOutcome.Success, missingResult.Outcome, "A null context must fail, not throw.");
        }


        /// <summary>
        /// <see href="https://www.w3.org/TR/did-1.0/#x6-3-1-production">DID Core 1.0 §6.3.1
        /// Production</see>: a present but empty <c>@context</c> fails the claim rather than throwing.
        /// </summary>
        [TestMethod]
        public void ContextFirstUriFailsWhenContextIsEmptyForDidCore10()
        {
            var emptyContext = new Context([], ContextForm.Array);
            Claim emptyResult = ContextValidationRules.ValidateFirstEntry(emptyContext, DidCoreConstants.JsonLdContextFirstUri);
            Assert.AreNotEqual(ClaimOutcome.Success, emptyResult.Outcome, "A context with zero entries must fail, not throw.");
        }


        /// <summary>
        /// <see href="https://www.w3.org/TR/did-1.0/#x6-3-1-production">DID Core 1.0 §6.3.1
        /// Production</see>: the DID Core 1.1 context as the first entry fails against the 1.0
        /// expectation.
        /// </summary>
        [TestMethod]
        public void ContextFirstUriFailsWhenFirstEntryIsWrongContextForDidCore10()
        {
            var wrongFirstContext = Context.FromIris(Context.DidCore11);
            Claim wrongResult = ContextValidationRules.ValidateFirstEntry(wrongFirstContext, DidCoreConstants.JsonLdContextFirstUri);
            Assert.AreNotEqual(ClaimOutcome.Success, wrongResult.Outcome, "The DID Core 1.1 context is not the DID Core 1.0 context.");
        }


        /// <summary>
        /// <see href="https://www.w3.org/TR/did-1.0/#x6-3-1-production">DID Core 1.0 §6.3.1
        /// Production</see>: the DID Core 1.0 context as the sole/first entry succeeds.
        /// </summary>
        [TestMethod]
        public void ContextFirstUriSucceedsWhenFirstEntryIsCorrectContextForDidCore10()
        {
            var correctContext = Context.FromIris(DidCoreConstants.JsonLdContextFirstUri);
            Claim correctResult = ContextValidationRules.ValidateFirstEntry(correctContext, DidCoreConstants.JsonLdContextFirstUri);
            Assert.AreEqual(ClaimOutcome.Success, correctResult.Outcome, "The DID Core 1.0 context as the sole entry must succeed.");
        }


        /// <summary>
        /// <see href="https://www.w3.org/TR/did-1.1/#json-ld-processors">DID Core 1.1 §6.2.3 JSON-LD
        /// Processors</see>: <c>https://www.w3.org/ns/did/v1.1</c> as the first entry succeeds.
        /// </summary>
        [TestMethod]
        public void ContextFirstUriSucceedsForDidCore11()
        {
            var didCore11First = Context.FromIris(Context.DidCore11, Context.Multikey10);
            Claim successResult = ContextValidationRules.ValidateFirstEntry(didCore11First, Context.DidCore11);
            Assert.AreEqual(ClaimOutcome.Success, successResult.Outcome, "DID Core 1.1 as the first entry must succeed against the 1.1 expectation.");
        }


        /// <summary>
        /// <see href="https://www.w3.org/TR/did-1.1/#json-ld-processors">DID Core 1.1 §6.2.3 JSON-LD
        /// Processors</see>: the DID Core 1.0 context in that position fails against the 1.1
        /// expectation.
        /// </summary>
        [TestMethod]
        public void ContextFirstUriFailsWhenFirstEntryIsDidCore10ForDidCore11()
        {
            var didCore10First = Context.FromIris(Context.DidCore10);
            Claim failureResult = ContextValidationRules.ValidateFirstEntry(didCore10First, Context.DidCore11);
            Assert.AreEqual(ClaimOutcome.Failure, failureResult.Outcome, "DID Core 1.0 as the first entry must fail against the 1.1 expectation.");
        }
    }
}
