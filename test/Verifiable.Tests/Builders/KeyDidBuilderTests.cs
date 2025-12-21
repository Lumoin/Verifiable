using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core.Assessment;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;


namespace Verifiable.Tests.Builders
{
    /// <summary>
    /// Tests for <see cref="KeyDidBuilder"/>.
    /// </summary>
    [TestClass]
    public sealed class KeyDidBuilderTests
    {
        /// <summary>
        /// The one and only (stateless) builder for KeyDID used in the tests.
        /// </summary>
        private static KeyDidBuilder KeyDidBuilder { get; } = new KeyDidBuilder();

        /// <summary>
        /// The test context.
        /// </summary>
        public TestContext TestContext { get; set; } = null!;


        /// <summary>
        /// The one and only (stateless) assessor for KeyDID for the builder tests.
        /// </summary>
        private static ClaimAssessor<DidDocument> KeyDidAssessor { get; } = new ClaimAssessor<DidDocument>(
            new ClaimIssuer<DidDocument>(
                issuerId: "DefaultKeyDidIssuer",
                validationRules: KeyDidValidationRules.AllRules,
                claimIdGenerator: (ct) => ValueTask.FromResult(string.Empty)),
            assessor: DefaultAssessors.DefaultKeyDidAssessorAsync,
            assessorId: "DefaultKeyDidAssessorId");



        [TestMethod]
        [DynamicData(nameof(DidKeyTheoryData.GetDidTheoryTestData), typeof(DidKeyTheoryData))]
        public async Task CanBuildKeyDidFromRandomKeys(DidKeyTestData testData)
        {
            //This builds the did:key document with the given public key and crypto suite.
            var keyDidDocument = await KeyDidBuilder.BuildAsync(
                testData.KeyPair.PublicKey,
                testData.VerificationMethodTypeInfo,
                cancellationToken: TestContext.CancellationToken);

            //Assert that the KeyFormat exists and is of the expected type
            var actualKeyFormat = keyDidDocument.VerificationMethod![0].KeyFormat;
            Assert.IsNotNull(actualKeyFormat);
            Assert.AreEqual(testData.ExpectedKeyFormat, actualKeyFormat.GetType());

            //The builder produced DID identifier type should match KeyDidId, as the type of the document is key DID.
            Assert.IsInstanceOfType<KeyDidMethod>(keyDidDocument.Id);
            string serializedDidDocumentx = JsonSerializer.Serialize(keyDidDocument, TestSetup.DefaultSerializationOptions);
            //This catches if there is a mismatch in generated tag for the key format
            //AND if the identifier does not match the used crypto algorithm. In
            //did:key it is specified how the identifier is generated from the key
            //material and how it affects the key encoding to its string representation.
            var keyFormatValidator = new KeyFormatValidator();
            var alg = testData.KeyPair.PublicKey.Tag.Get<CryptoAlgorithm>();
            keyFormatValidator.AddValidator(typeof(PublicKeyJwk), TestOnlyKeyFormatValidators.KeyDidJwkValidator);
            keyFormatValidator.AddValidator(typeof(PublicKeyMultibase), TestOnlyKeyFormatValidators.KeyDidMultibaseValidator);
            bool res = keyFormatValidator.Validate(actualKeyFormat, alg);
            Assert.IsTrue(res, $"Key format validation failed for '{actualKeyFormat.GetType()}' for algorithm '{alg}'.");

            //This part runs the whole suite if did:key validation rules Verifiable library defines against the document.
            var assessmentResult = await KeyDidAssessor.AssessAsync(keyDidDocument, "some-test-supplied-correlationId", TestContext.CancellationToken);
            Assert.IsTrue(assessmentResult.IsSuccess, assessmentResult.ClaimsResult
                .Claims.Where(c => c.Outcome == ClaimOutcome.Failure)
                .Aggregate("Assessment failed. Failed claims: ", (acc, claim) => $"{acc}{claim.Id}, ").TrimEnd(',', '.'));

            string serializedDidDocument = JsonSerializer.Serialize(keyDidDocument, TestSetup.DefaultSerializationOptions);
            var (deserializedDidDocument, reserializedDidDocument) = JsonTestingUtilities.PerformSerializationCycle<DidDocument>(serializedDidDocument, TestSetup.DefaultSerializationOptions);
            bool areJsonElementsEqual = JsonTestingUtilities.CompareJsonElements(serializedDidDocument, reserializedDidDocument);
            Assert.IsTrue(areJsonElementsEqual, $"JSON string '{serializedDidDocument}' did not pass roundtrip test.");
            Assert.IsNotNull(deserializedDidDocument);
            Assert.IsNotNull(deserializedDidDocument.Id);
            Assert.AreEqual(typeof(KeyDidMethod), deserializedDidDocument.Id.GetType());
        }


        [TestMethod]
        [DynamicData(nameof(DidKeyTheoryData.GetDidTheoryTestData), typeof(DidKeyTheoryData))]
        public async ValueTask CreateAndVerifySignatureUsingDidKey(DidKeyTestData testData)
        {
            if(testData.KeyPair.PublicKey.SupportsSigning())
            {
                Assert.Inconclusive($"Key pair {testData.KeyPair.PublicKey.Tag.Get<CryptoAlgorithm>()} does not support signing.");

                //Create DID document.
                var didDocument = await KeyDidBuilder.BuildAsync(
                    testData.KeyPair.PublicKey,
                    testData.VerificationMethodTypeInfo,
                    cancellationToken: TestContext.CancellationToken);

                //Sign data.
                var contentToSign = Encoding.UTF8.GetBytes("Hello, DID!");
                using var signature = await testData.KeyPair.PrivateKey.SignAsync(contentToSign, SensitiveMemoryPool<byte>.Shared);

                //Verify signature using the verification method by ID.
                var verificationMethodId = didDocument.VerificationMethod![0].Id!;
                var verificationMethod = didDocument.ResolveVerificationMethodReference(verificationMethodId);
                Assert.IsNotNull(verificationMethod, "Verification method should be found by ID.");

                bool verified = await verificationMethod.VerifySignatureAsync(contentToSign, signature, SensitiveMemoryPool<byte>.Shared);
                Assert.IsTrue(verified);
            }
        }


        [TestMethod]
        public async ValueTask CreateAndPerformKeyExchangeUsingDidKey()
        {
            //Generate X25519 key pair for key agreement.
            var keyPair = BouncyCastleKeyCreator.CreateX25519Keys(SensitiveMemoryPool<byte>.Shared);

            //Create DID document with the key agreement key.
            var didDocument = await KeyDidBuilder.BuildAsync(
                keyPair.PublicKey,
                X25519KeyAgreementKey2020VerificationMethodTypeInfo.Instance,
                cancellationToken: TestContext.CancellationToken);

            //Find the key agreement verification method.
            var keyAgreementMethodId = didDocument.KeyAgreement![0].Id!;
            var keyAgreementMethod = didDocument.ResolveVerificationMethodReference(keyAgreementMethodId);
            Assert.IsNotNull(keyAgreementMethod, "Key agreement method should be found by ID.");

            //Generate another X25519 key pair for the "other party".
            var otherPartyKeyPair = BouncyCastleKeyCreator.CreateX25519Keys(SensitiveMemoryPool<byte>.Shared);

            //Perform key agreement from both sides.
            using var sharedSecret1 = await BouncyCastleCryptographicFunctions.DeriveX25519SharedSecretAsync(
                keyPair.PrivateKey.AsReadOnlySpan(),
                otherPartyKeyPair.PublicKey.AsReadOnlySpan(),
                SensitiveMemoryPool<byte>.Shared);

            using var sharedSecret2 = await BouncyCastleCryptographicFunctions.DeriveX25519SharedSecretAsync(
                otherPartyKeyPair.PrivateKey.AsReadOnlySpan(),
                keyPair.PublicKey.AsReadOnlySpan(),
                SensitiveMemoryPool<byte>.Shared);

            //Verify both parties derived the same shared secret.
            Assert.IsTrue(sharedSecret1.Memory.Span.SequenceEqual(sharedSecret2.Memory.Span),
                "Both parties should derive the same shared secret.");

            //Also test key agreement using the verification method from the DID document.
            //This validates that the DID document's verification method contains the correct public key
            //and that our key format conversion pipeline works correctly. The verification method
            //stores the public key in a specific format (JWK or multibase), and we need to extract
            //it back to raw bytes to perform ECDH. This tests the round-trip conversion:
            //Raw bytes → KeyFormat → VerificationMethod → Raw bytes → ECDH
            using var sharedSecret3 = await DeriveSharedSecretAsync(
                keyAgreementMethod, otherPartyKeyPair.PrivateKey, SensitiveMemoryPool<byte>.Shared);

            Assert.IsTrue(sharedSecret1.Memory.Span.SequenceEqual(sharedSecret3.Memory.Span),
                "Shared secret from DID verification method should match direct key agreement. This proves the key format conversion pipeline preserves key material correctly.");

            //Clean up.
            keyPair.PublicKey.Dispose();
            keyPair.PrivateKey.Dispose();
            otherPartyKeyPair.PublicKey.Dispose();
            otherPartyKeyPair.PrivateKey.Dispose();
        }


        private static async ValueTask<IMemoryOwner<byte>> DeriveSharedSecretAsync(
            VerificationMethod verificationMethod,
            PrivateKeyMemory otherPartyPrivateKey,
            MemoryPool<byte> memoryPool)
        {
            //Extract public key from verification method.
            var (algorithm, purpose, scheme, publicKeyOwner) = VerificationMethodCryptoConversions.DefaultConverter(verificationMethod, memoryPool);
            using(publicKeyOwner)
            {
                if(algorithm.Equals(CryptoAlgorithm.X25519))
                {
                    return await BouncyCastleCryptographicFunctions.DeriveX25519SharedSecretAsync(
                        otherPartyPrivateKey.AsReadOnlySpan(),
                        publicKeyOwner.Memory.Span,
                        memoryPool);
                }

                throw new NotSupportedException($"Key agreement not supported for algorithm '{algorithm}'.");
            }
        }
    }
}