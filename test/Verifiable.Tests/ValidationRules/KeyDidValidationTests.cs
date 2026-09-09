using Verifiable.Core.Assessment;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Validation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.ValidationRules
{
    /// <summary>
    /// Tests for <see cref="KeyDidValidationRules"/>.
    /// </summary>
    [TestClass]
    internal sealed class KeyDidValidationTests
    {
        /// <summary>
        /// Test context providing test run information and cancellation support.
        /// </summary>
        public TestContext TestContext { get; set; } = null!;


        [TestMethod]
        public async Task KeyDidCanStartOnlyWithDidKey()
        {
            //These are test vectors from https://w3c-ccg.github.io/did-method-key/#test-vectors.
            var keyDid = new DidDocument();
            keyDid.Id = new KeyDidMethod("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");            
            var successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.IsTrue(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));
            
            keyDid.Id = new KeyDidMethod("did:key:zInvalidMkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
            successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.IsFalse(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));

            keyDid.Id = new KeyDidMethod("did:key: zInvalidMkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
            successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.IsFalse(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));

            keyDid.Id = new KeyDidMethod("did:key:zInvalidMkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp ");
            successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.IsFalse(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));

            keyDid.Id = new KeyDidMethod("did:key:zInvalid6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
            successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.IsFalse(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));

            keyDid.Id = new KeyDidMethod("did:key:6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
            successfulValidationResult = await KeyDidValidationRules.ValidateIdFormatAsync(keyDid, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.IsFalse(successfulValidationResult.All(c => c.Outcome == ClaimOutcome.Success));
        }


        [TestMethod]
        public void KeyDidVerificationMethodMustContainHashtag()
        {

        }


        /// <summary>
        /// DID Core 1.0 &#167;3.1 requires DIDs to be compared by exact string match. A verification
        /// method identifier that differs from the document identifier only by an inserted soft
        /// hyphen (U+00AD, a Unicode default-ignorable code point) is a byte-different string that a
        /// culture-aware comparison could still treat as sharing the document's prefix;
        /// <see cref="KeyDidValidationRules.ValidateIdPrefixMatchAsync"/> must reject it.
        /// </summary>
        [TestMethod]
        public async Task KeyDidIdPrefixMatchRejectsVerificationMethodIdWithIgnorableCodePoint()
        {
            //These are test vectors from https://w3c-ccg.github.io/did-method-key/#test-vectors.
            const string DocumentId = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
            string tamperedVerificationMethodId = DocumentId.InsertIgnorableCodePointAt(5) + "#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";

            var keyDid = new DidDocument
            {
                Id = new KeyDidMethod(DocumentId),
                VerificationMethod =
                [
                    new VerificationMethod { Id = tamperedVerificationMethodId, Type = "Ed25519VerificationKey2020" }
                ]
            };

            var claims = await KeyDidValidationRules.ValidateIdPrefixMatchAsync(keyDid, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.HasCount(1, claims);
            Assert.AreEqual(ClaimOutcome.Failure, claims[0].Outcome);
        }
    }
}
