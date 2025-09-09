using System.Text;
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
        /// A collection of all the assessment rules that are applied to <c>did:web</c> DID documents.
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
            string testDomain = "example.com";
            var webDidDocument = WebDidBuilder.Build(testData.KeyPair.PublicKey, testData.VerificationMethodTypeInfo, testDomain);

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
            var assessmentResult = await WebDidAssessor.AssessAsync(webDidDocument, "some-test-supplied-correlationId");
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
        [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData), DynamicDataSourceType.Method)]
        public async ValueTask CreateAndVerifySignatureUsingWebDid(DidWebTestData testData)
        {
            //Create DID document.
            string testDomain = "example.com";
            var webDidDocument = WebDidBuilder.Build(testData.KeyPair.PublicKey, testData.VerificationMethodTypeInfo, testDomain);

            //Sign data.
            var contentToSign = Encoding.UTF8.GetBytes("Hello, Web DID!");
            using var signature = await testData.KeyPair.PrivateKey.SignAsync(contentToSign, SensitiveMemoryPool<byte>.Shared);

            //Verify signature using the verification method by ID.
            var verificationMethodId = webDidDocument.VerificationMethod![0].Id!;
            var verificationMethod = webDidDocument.ResolveVerificationMethodReference(verificationMethodId);
            Assert.IsNotNull(verificationMethod, "Verification method should be found by ID.");

            bool verified = await verificationMethod.VerifySignatureAsync(contentToSign, signature, SensitiveMemoryPool<byte>.Shared);
            Assert.IsTrue(verified);
        }


        [TestMethod]
        [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData), DynamicDataSourceType.Method)]
        public async ValueTask CanBuildComplexWebDidWithServicesAndVerificationRelationships(DidWebTestData testData)
        {
            //Create DID document with path-based identifier using builder extensions.
            string webDomain = "placeholder.com:api:v1:entities:item-456";
            var builder = new WebDidBuilder()
                .With((didDocument, builder, buildState) =>
                {
                    //Add authentication using first verification method.
                    if(didDocument.VerificationMethod!.Length > 0)
                    {
                        var verificationMethodId = didDocument.VerificationMethod![0].Id!;
                        didDocument.WithAuthentication(verificationMethodId);
                    }
                    return didDocument;
                })
                .With((didDocument, builder, buildState) =>
                {
                    //Add assertion method using first verification method.
                    if(didDocument.VerificationMethod!.Length > 0)
                    {
                        var verificationMethodId = didDocument.VerificationMethod![0].Id!;
                        didDocument.WithAssertionMethod(verificationMethodId);
                    }
                    return didDocument;
                })
                .AddServices<WebDidBuilder, WebDidBuildState>(buildState =>
                [
                    new Service { Id = new Uri($"did:web:{buildState.WebDomain}#service-a"), Type = "ServiceTypeA", ServiceEndpoint = $"https://{buildState.WebDomain.Replace(":", "/", StringComparison.Ordinal)}/service-a" },
                    new Service { Id = new Uri($"did:web:{buildState.WebDomain}#service-b"), Type = "ServiceTypeB", ServiceEndpoint = $"https://{buildState.WebDomain.Replace(":", "/", StringComparison.Ordinal)}/service-b" },
                    new Service { Id = new Uri($"did:web:{buildState.WebDomain}#service-c"), Type = "ServiceTypeC", ServiceEndpoint = $"https://{buildState.WebDomain.Replace(":", "/", StringComparison.Ordinal)}/service-c" }
                ]);

            var webDidDocument = builder.Build(testData.KeyPair.PublicKey, testData.VerificationMethodTypeInfo, webDomain, DidRepresentationType.JsonLd);

            //Verify the DID structure.
            Assert.AreEqual("did:web:placeholder.com:api:v1:entities:item-456", webDidDocument.Id!);
            Assert.IsInstanceOfType<WebDidMethod>(webDidDocument.Id);

            //Verify context was added for JSON-LD representation.
            Assert.IsNotNull(webDidDocument.Context);
            Assert.IsNotNull(webDidDocument.Context.Contexes);
            Assert.HasCount(1, webDidDocument.Context.Contexes);
            Assert.AreEqual(Context.DidCore10, webDidDocument.Context.Contexes[0]);

            //Verify the verification method.
            var verificationMethod = webDidDocument.VerificationMethod![0];
            var verificationMethodId = verificationMethod.Id!;
            Assert.AreEqual("did:web:placeholder.com:api:v1:entities:item-456", verificationMethod.Controller);
            Assert.AreEqual(testData.VerificationMethodTypeInfo.TypeName, verificationMethod.Type);
            Assert.IsInstanceOfType(verificationMethod.KeyFormat, testData.ExpectedKeyFormat);

            //Verify verification relationships were added by builder.
            Assert.IsNotNull(webDidDocument.Authentication);
            Assert.AreEqual(1, webDidDocument.Authentication.Length);
            Assert.AreEqual(verificationMethodId, webDidDocument.Authentication[0].Id);

            Assert.IsNotNull(webDidDocument.AssertionMethod);
            Assert.AreEqual(1, webDidDocument.AssertionMethod.Length);
            Assert.AreEqual(verificationMethodId, webDidDocument.AssertionMethod[0].Id);

            //Verify no key agreement was added (since we only added auth and assertion).
            Assert.IsNull(webDidDocument.KeyAgreement);

            //Verify services were created with consistent domain.
            Assert.IsNotNull(webDidDocument.Service);
            Assert.AreEqual(3, webDidDocument.Service.Length);

            var serviceA = webDidDocument.Service.First(s => s.Type == "ServiceTypeA");
            Assert.AreEqual($"did:web:placeholder.com:api:v1:entities:item-456#service-a", serviceA.Id!.ToString());
            Assert.AreEqual("https://placeholder.com/api/v1/entities/item-456/service-a", serviceA.ServiceEndpoint);

            //Verify all services use the same domain pattern.
            string expectedPathBase = "https://placeholder.com/api/v1/entities/item-456/";
            foreach(var service in webDidDocument.Service)
            {
                Assert.StartsWith(expectedPathBase, service.ServiceEndpoint, $"Service endpoint {service.ServiceEndpoint} should start with {expectedPathBase}.");
            }

            //Test serialization to verify JSON structure.
            string serializedDidDocument = JsonSerializer.Serialize(webDidDocument, TestSetup.DefaultSerializationOptions);

            //Verify JSON contains expected elements.
            Assert.IsTrue(serializedDidDocument.Contains("\"@context\"", StringComparison.OrdinalIgnoreCase));
            Assert.IsTrue(serializedDidDocument.Contains(Context.DidCore10, StringComparison.OrdinalIgnoreCase));
            Assert.IsTrue(serializedDidDocument.Contains("did:web:placeholder.com:api:v1:entities:item-456", StringComparison.OrdinalIgnoreCase));
            Assert.AreEqual(testData.VerificationMethodTypeInfo.TypeName, verificationMethod.Type);
            Assert.IsTrue(serializedDidDocument.Contains("placeholder.com/api/v1/entities/item-456", StringComparison.OrdinalIgnoreCase));
            Assert.IsTrue(serializedDidDocument.Contains("ServiceTypeA", StringComparison.OrdinalIgnoreCase));
            Assert.IsTrue(serializedDidDocument.Contains("ServiceTypeB", StringComparison.OrdinalIgnoreCase));
            Assert.IsTrue(serializedDidDocument.Contains("ServiceTypeC", StringComparison.OrdinalIgnoreCase));

            //Verify roundtrip serialization.
            var (deserializedDidDocument, reserializedDidDocument) = JsonTestingUtilities.PerformSerializationCycle<DidDocument>(serializedDidDocument, TestSetup.DefaultSerializationOptions);
            bool areJsonElementsEqual = JsonTestingUtilities.CompareJsonElements(serializedDidDocument, reserializedDidDocument);
            Assert.IsTrue(areJsonElementsEqual, $"JSON string '{serializedDidDocument}' did not pass roundtrip test.");

            //Test signature creation and verification.
            var contentToSign = Encoding.UTF8.GetBytes("Test content for complex web DID");
            using var signature = await testData.KeyPair.PrivateKey.SignAsync(contentToSign, SensitiveMemoryPool<byte>.Shared);

            var resolvedVerificationMethod = webDidDocument.ResolveVerificationMethodReference(verificationMethodId);
            Assert.IsNotNull(resolvedVerificationMethod, "Verification method should be found by ID.");

            bool verified = await resolvedVerificationMethod.VerifySignatureAsync(contentToSign, signature, SensitiveMemoryPool<byte>.Shared);
            Assert.IsTrue(verified, "Signature should verify successfully.");
        }


        [TestMethod]
        [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData), DynamicDataSourceType.Method)]
        public void CanBuildWebDidWithAllRepresentationTypes(DidWebTestData testData)
        {
            string webDomain = "example.com";
            var builder = new WebDidBuilder();

            //Test 1: JSON without context - minimal representation.
            var docWithoutContext = builder.Build(
                testData.KeyPair.PublicKey,
                testData.VerificationMethodTypeInfo,
                webDomain,
                DidRepresentationType.JsonWithoutContext);

            Assert.IsNull(docWithoutContext.Context, "JsonWithoutContext should not have @context");
            Assert.AreEqual($"did:web:{webDomain}", docWithoutContext.Id!);

            //Test 2: JSON with context - dual compatibility.
            var docWithContext = builder.Build(
                testData.KeyPair.PublicKey,
                testData.VerificationMethodTypeInfo,
                webDomain,
                DidRepresentationType.JsonWithContext);

            Assert.IsNotNull(docWithContext.Context, "JsonWithContext should have @context");
            Assert.AreEqual(Context.DidCore10, docWithContext.Context.Contexes![0]);

            //Test 3: JSON-LD - full semantic representation.
            var docJsonLd = builder.Build(
                testData.KeyPair.PublicKey,
                testData.VerificationMethodTypeInfo,
                webDomain,
                DidRepresentationType.JsonLd,
                didCoreVersion: Context.DidCore11,
                additionalContexts: ["https://example.com/custom"]);

            Assert.IsNotNull(docJsonLd.Context, "JsonLd should have @context");
            Assert.HasCount(2, docJsonLd.Context.Contexes!);
            Assert.AreEqual(Context.DidCore11, docJsonLd.Context.Contexes![0]);
            Assert.AreEqual("https://example.com/custom", docJsonLd.Context.Contexes[1]);

            //Verify all three have the same core structure.
            Assert.AreEqual(docWithoutContext.Id, docWithContext.Id);
            Assert.AreEqual(docWithoutContext.Id, docJsonLd.Id);
            Assert.AreEqual(docWithoutContext.VerificationMethod![0].Type, docWithContext.VerificationMethod![0].Type);
            Assert.AreEqual(docWithoutContext.VerificationMethod![0].Type, docJsonLd.VerificationMethod![0].Type);
        }
    }
}
