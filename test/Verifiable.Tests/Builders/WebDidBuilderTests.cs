using System.Text.Json;
using Verifiable.Assessment;
using Verifiable.Core.Builders;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Verifiable.Core.Did.Methods;
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
        /// A collection of all the assessment rules that are applied to <c>did:key</c> DID documents.
        /// </summary>        
        public static IList<ClaimDelegate<DidDocument>> AllRules { get; } =
        [
            //new(ValidateIdEncodingAsync, [ClaimId.KeyDidIdEncoding]),
            new(ValidateKeyFormatAsync, [ClaimId.WebDidKeyFormat]),
            //new(ValidateIdFormatAsync, [ClaimId.KeyDidIdFormat]),
            //new(ValidateSingleVerificationMethodAsync, [ClaimId.KeyDidSingleVerificationMethod]),
            //new(ValidateIdPrefixMatchAsync, [ClaimId.KeyDidIdPrefixMatch]),
            //new(ValidateFragmentIdentifierRepetitionAsync, [ClaimId.KeyDidFragmentIdentifierRepetition]),
        ];


        /// <summary>
        /// Validates the format of the key in the provided <c>did:web</c> DID document.
        /// </summary>
        /// <param name="document">The <c>did:web</c> DID document to validate.</param>
        /// <returns>Claims indicating the validation outcome.</returns>
        public static ValueTask<IList<Claim>> ValidateKeyFormatAsync(DidDocument document)
        {
            IList<Claim> resultClaims = new List<Claim>();
            if(document.VerificationMethod?[0]?.KeyFormat is PublicKeyJwk keyFormat)
            {                
                var headers = keyFormat.Header;
                var sublaims = JwtKeyTypeHeaderValidationUtilities.ValidateHeader(headers);
                var claimOutCome = sublaims.All(c => c.Outcome == ClaimOutcome.Success) ? ClaimOutcome.Success : ClaimOutcome.Failure;

                resultClaims.Add(new Claim(ClaimId.WebDidKeyFormat, claimOutCome, ClaimContext.None, sublaims));
            }
            else if(document.VerificationMethod?[0]?.KeyFormat is PublicKeyMultibase multiKeyFormat)
            {
                //TODO: This here will be refactored, since this does not validate the multibase format yet.
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
        /// The one and only (stateless) assessor for for <c>did:web</c> for the builder tests.
        /// </summary>
        private static ClaimAssessor<DidDocument> WebDidAssessor { get; } = new ClaimAssessor<DidDocument>(
            new ClaimIssuer<DidDocument>(
                issuerId: "DefaultWebDidIssuer",
                validationRules: WebDidValidationRules.AllRules,
                claimIdGenerator: () => ValueTask.FromResult(string.Empty)),
                assessor: DefaultAssessors.DefaultWebDidAssessorAsync,
                assessorId: "DefaultWebDidAssessorId");



        [TestMethod]
        [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData), DynamicDataSourceType.Method)]                
        public async Task CanBuildWebDidFromRandomKeysAsync(DidWebTestData testData)
        {
            //This builds the did:web document with the given public key and crypto suite.            

            /*_ =WebDidBuilder.WithService((doc, service) =>
            {
                service.Id = new System.Uri("did:web:example.com:wall#product");
                service.Type = "ProductPassport";
                service.ServiceEndpoint = "https://example.com/";
            });*/

            /*WebDidBuilder.WithVerificationMethod((doc, state, verificationMethod) =>
            {
                verificationMethod.Id = new System.Uri("did:web:example.com:wall#product");
                verificationMethod.Type = "ProductPassport";
                verificationMethod.ServiceEndpoint = "https://example.com/";
            });*/

            string testDomain = "example.com";

            // Define or obtain necessary parameters
            string verificationMethodId = $"did:web:{testDomain}#key-1";
            CryptoSuite cryptoSuite = testData.CryptoSuite;
            string controller = $"did:web:{testDomain}";
            PublicKeyMemory publicKey = testData.KeyPair.PublicKey;

            // Add the verification method
            //var builder = WebDidBuilder.WithVerificationMethod(verificationMethodId, cryptoSuite, controller, publicKey);

            var webDidDocument = WebDidBuilder.Build(testData.KeyPair.PublicKey, testData.CryptoSuite, testDomain);
            
            //Assert that the KeyFormat exists and is of the expected type
            var actualKeyFormat = webDidDocument.VerificationMethod![0].KeyFormat;
            Assert.IsNotNull(actualKeyFormat);
            Assert.AreEqual(testData.ExpectedKeyFormat, actualKeyFormat.GetType());

            //The builder produced DID identifier type should match KeyDidId, as the type of the document is key DID.                                               
            Assert.AreEqual(typeof(WebDidMethod), webDidDocument?.Id?.GetType());

            //This catches if there is a mismatch in generated tag for the key format
            //AND if the identifier does not match the used crypto algorithm. In
            //did:key it is specificed how the identifier is generated from the key
            //material and how it affects the key encoding to its string representation.
            var keyFormatValidator = new KeyFormatValidator();
            var alg = (CryptoAlgorithm)testData.KeyPair.PublicKey.Tag[typeof(CryptoAlgorithm)];
            keyFormatValidator.AddValidator(typeof(PublicKeyMultibase), TestOnlyKeyFormatValidators.KeyDidMultibaseValidator);
            keyFormatValidator.AddValidator(typeof(PublicKeyJwk), TestOnlyKeyFormatValidators.KeyDidJwkValidator);
            bool res = keyFormatValidator.Validate(actualKeyFormat, alg);
            Assert.IsTrue(res, $"Key format validation failed for {actualKeyFormat.GetType()} for algorithm {alg.Algorithm}.");

            //This part runs the whole suite if did:key validation rules Verifiable library defines against the document.
            Assert.IsNotNull(webDidDocument);
            var assessmentResult = await WebDidAssessor.AssessAsync(webDidDocument, "some-test-supplied-correlationId");
            Assert.IsTrue(assessmentResult.IsSuccess);

            string serializedDidDocument = JsonSerializer.Serialize(webDidDocument, TestSetup.DefaultSerializationOptions);
            var (deserializedDidDocument, reserializedDidDocument) = JsonTestingUtilities.PerformSerializationCycle<DidDocument>(serializedDidDocument, TestSetup.DefaultSerializationOptions);
            bool areJsonElementsEqual = JsonTestingUtilities.CompareJsonElements(serializedDidDocument, reserializedDidDocument);
            Assert.IsTrue(areJsonElementsEqual, $"JSON string \"{serializedDidDocument}\" did not pass roundtrip test.");
            Assert.AreEqual(typeof(WebDidMethod), deserializedDidDocument?.Id?.GetType());
        }
    }    
}
