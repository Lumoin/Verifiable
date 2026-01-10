using System.Text.Json;
using Verifiable.Core.Assessment;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;


namespace Verifiable.Tests.Builders
{
    /// <summary>
    /// Contains validation rules specific for <c>did:web</c> DID documents.
    /// </summary>
    public static class WebDidValidationRules
    {
        /// <summary>
        /// A collection of all the assessment rules that are applied to <c>did:web</c> DID documents.
        /// </summary>
        public static IList<ClaimDelegate<DidDocument>> AllRules { get; } =
        [
            new(ValidateKeyFormatAsync, [ClaimId.WebDidKeyFormat]),
        ];


        /// <summary>
        /// Validates the format of the key in the provided <c>did:web</c> DID document.
        /// </summary>
        /// <param name="document">The <c>did:web</c> DID document to validate.</param>
        /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
        /// <returns>Claims indicating the validation outcome.</returns>
        public static ValueTask<IList<Claim>> ValidateKeyFormatAsync(
            DidDocument document,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            IList<Claim> resultClaims = [];
            if(document.VerificationMethod?[0]?.KeyFormat is PublicKeyJwk keyFormat)
            {
                var headers = keyFormat.Header;
                var sublaims = JwtKeyTypeHeaderValidationUtilities.ValidateHeader(headers);
                var claimOutCome = sublaims.All(c => c.Outcome == ClaimOutcome.Success) ? ClaimOutcome.Success : ClaimOutcome.Failure;

                resultClaims.Add(new Claim(ClaimId.WebDidKeyFormat, claimOutCome, ClaimContext.None, sublaims));
            }
            else if(document.VerificationMethod?[0]?.KeyFormat is PublicKeyMultibase multiKeyFormat)
            {
                //TODO: This will be refactored to validate the multibase format.
                resultClaims.Add(new Claim(ClaimId.WebDidKeyFormat, ClaimOutcome.Success));
            }
            else
            {
                resultClaims.Add(new Claim(ClaimId.WebDidKeyFormat, ClaimOutcome.Failure));
            }

            return ValueTask.FromResult(resultClaims);
        }
    }

    /// <summary>
    /// Tests for <see cref="WebDidBuilder"/>.
    /// </summary>
    [TestClass]
    public sealed class WebDidBuilderTests
    {
        /// <summary>
        /// The one and only (stateless) builder for <c>did:web</c> DID used in the tests.
        /// </summary>
        private static WebDidBuilder WebDidBuilder { get; } = new WebDidBuilder();

        /// <summary>
        /// The test context.
        /// </summary>
        public TestContext TestContext { get; set; } = null!;


        /// <summary>
        /// The one and only (stateless) assessor for for <c>did:web</c> for the builder tests.
        /// </summary>
        private static ClaimAssessor<DidDocument> WebDidAssessor { get; } = new ClaimAssessor<DidDocument>(
            new ClaimIssuer<DidDocument>(
                issuerId: "DefaultWebDidIssuer",
                validationRules: WebDidValidationRules.AllRules,
                claimIdGenerator: (ct) => ValueTask.FromResult(string.Empty)),
            assessor: DefaultAssessors.DefaultWebDidAssessorAsync,
            assessorId: "DefaultWebDidAssessorId");



        [TestMethod]
        [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
        public async Task CanBuildWebDidFromRandomKeysAsync(DidWebTestData testData)
        {
            //This builds the did:web document with the given public key and crypto suite.
            string testDomain = "example.com";
            var webDidDocument = await WebDidBuilder.BuildAsync(
                testData.KeyPair.PublicKey,
                testData.VerificationMethodTypeInfo,
                testDomain,
                cancellationToken: TestContext.CancellationToken);

            //Assert that the KeyFormat exists and is of the expected type.
            var actualKeyFormat = webDidDocument.VerificationMethod![0].KeyFormat;
            Assert.IsNotNull(actualKeyFormat);
            Assert.AreEqual(testData.ExpectedKeyFormat, actualKeyFormat.GetType());

            //The builder produced DID identifier type should match WebDidMethod, as the type of the document is web DID.
            Assert.IsInstanceOfType<WebDidMethod>(webDidDocument.Id);

            //This catches if there is a mismatch in generated tag for the key format
            //AND if the identifier does not match the used crypto algorithm. In
            //did:web it is specified how the identifier is generated from the key
            //material and how it affects the key encoding to its string representation.
            var keyFormatValidator = new KeyFormatValidator();
            var alg = testData.KeyPair.PublicKey.Tag.Get<CryptoAlgorithm>();
            keyFormatValidator.AddValidator(typeof(PublicKeyJwk), TestOnlyKeyFormatValidators.KeyDidJwkValidator);
            keyFormatValidator.AddValidator(typeof(PublicKeyMultibase), TestOnlyKeyFormatValidators.KeyDidMultibaseValidator);
            bool res = keyFormatValidator.Validate(actualKeyFormat, alg);
            Assert.IsTrue(res, $"Key format validation failed for '{actualKeyFormat.GetType()}' for algorithm '{alg}'.");

            //This part runs the whole suite if did:web validation rules Verifiable library defines against the document.
            var assessmentResult = await WebDidAssessor.AssessAsync(webDidDocument, "some-test-supplied-correlationId", TestContext.CancellationToken);
            Assert.IsTrue(assessmentResult.IsSuccess, assessmentResult.ClaimsResult
                .Claims.Where(c => c.Outcome == ClaimOutcome.Failure)
                .Aggregate("Assessment failed. Failed claims: ", (acc, claim) => $"{acc}{claim.Id}, ").TrimEnd(',', '.'));

            string serializedDidDocument = JsonSerializer.Serialize(webDidDocument, TestSetup.DefaultSerializationOptions);
            var (deserializedDidDocument, reserializedDidDocument) = JsonTestingUtilities.PerformSerializationCycle<DidDocument>(serializedDidDocument, TestSetup.DefaultSerializationOptions);
            bool areJsonElementsEqual = JsonTestingUtilities.CompareJsonElements(serializedDidDocument, reserializedDidDocument);
            Assert.IsTrue(areJsonElementsEqual, $"JSON string '{serializedDidDocument}' did not pass roundtrip test.");
            Assert.IsNotNull(deserializedDidDocument);
            Assert.IsNotNull(deserializedDidDocument.Id);
            Assert.AreEqual(typeof(WebDidMethod), deserializedDidDocument.Id.GetType());
        }


        [TestMethod]
        [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
        public async Task CanBuildWebDidWithAllRepresentationTypes(DidWebTestData testData)
        {
            string webDomain = "example.com";
            var builder = new WebDidBuilder();

            //Test 1: JSON without context - minimal representation.
            var docWithoutContext = await builder.BuildAsync(
                testData.KeyPair.PublicKey,
                testData.VerificationMethodTypeInfo,
                webDomain,
                DidRepresentationType.JsonWithoutContext,
                cancellationToken: TestContext.CancellationToken);

            Assert.IsNull(docWithoutContext.Context, "JsonWithoutContext should not have @context");
            Assert.AreEqual($"did:web:{webDomain}", docWithoutContext.Id!);

            //Test 2: JSON with context - dual compatibility.
            var docWithContext = await builder.BuildAsync(
                testData.KeyPair.PublicKey,
                testData.VerificationMethodTypeInfo,
                webDomain,
                DidRepresentationType.JsonWithContext,
                cancellationToken: TestContext.CancellationToken);

            Assert.IsNotNull(docWithContext.Context, "JsonWithContext should have @context");
            Assert.AreEqual(Context.DidCore10, docWithContext.Context.Contexts![0]);

            //Test 3: JSON-LD - full semantic representation.
            var docJsonLd = await builder.BuildAsync(
                testData.KeyPair.PublicKey,
                testData.VerificationMethodTypeInfo,
                webDomain,
                DidRepresentationType.JsonLd,
                didCoreVersion: Context.DidCore11,
                additionalContexts: ["https://example.com/custom"],
                cancellationToken: TestContext.CancellationToken);

            Assert.IsNotNull(docJsonLd.Context, "JsonLd should have @context");
            Assert.HasCount(2, docJsonLd.Context.Contexts!);
            Assert.AreEqual(Context.DidCore11, docJsonLd.Context.Contexts![0]);
            Assert.AreEqual("https://example.com/custom", docJsonLd.Context.Contexts[1]);

            //Verify all three have the same core structure.
            Assert.AreEqual(docWithoutContext.Id, docWithContext.Id);
            Assert.AreEqual(docWithoutContext.Id, docJsonLd.Id);
            Assert.AreEqual(docWithoutContext.VerificationMethod![0].Type, docWithContext.VerificationMethod![0].Type);
            Assert.AreEqual(docWithoutContext.VerificationMethod![0].Type, docJsonLd.VerificationMethod![0].Type);
        }
    }
}