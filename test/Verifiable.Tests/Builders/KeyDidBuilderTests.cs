using Lucene.Net.Search;
using SimpleBase;
using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.Assessment;
using Verifiable.BouncyCastle;
using Verifiable.Core;
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
        /// The one and only (stateless) assessor for KeyDID for the builder tests.
        /// </summary>
        private static ClaimAssessor<DidDocument> KeyDidAssessor { get; } = new ClaimAssessor<DidDocument>(
            new ClaimIssuer<DidDocument>(
                issuerId: "DefaultKeyDidIssuer",
                validationRules: KeyDidValidationRules.AllRules,
                claimIdGenerator: () => ValueTask.FromResult(string.Empty)),
                assessor: DefaultAssessors.DefaultKeyDidAssessorAsync,
                assessorId: "DefaultKeyDidAssessorId");



        [TestMethod]
        [DynamicData(nameof(DidKeyTheoryData.GetDidTheoryTestData), typeof(DidKeyTheoryData), DynamicDataSourceType.Method)]
        public async Task CanBuildKeyDidFromRandomKeys(DidKeyTestData testData)
        {
            //This builds the did:key document with the given public key and crypto suite.
            var keyDidDocument = KeyDidBuilder.Build(testData.KeyPair.PublicKey, testData.CryptoSuite);

            //Assert that the KeyFormat exists and is of the expected type
            var actualKeyFormat = keyDidDocument.VerificationMethod![0].KeyFormat;
            Assert.IsNotNull(actualKeyFormat);
            Assert.AreEqual(testData.ExpectedKeyFormat, actualKeyFormat.GetType());

            //The builder produced DID identifier type should match KeyDidId, as the type of the document is key DID.                                               
            Assert.IsInstanceOfType<KeyDidMethod>(keyDidDocument.Id);

            //This catches if there is a mismatch in generated tag for the key format
            //AND if the identifier does not match the used crypto algorithm. In
            //did:key it is specified how the identifier is generated from the key
            //material and how it affects the key encoding to its string representation.
            var keyFormatValidator = new KeyFormatValidator();
            var alg = (CryptoAlgorithm)testData.KeyPair.PublicKey.Tag[typeof(CryptoAlgorithm)];
            keyFormatValidator.AddValidator(typeof(PublicKeyJwk), TestOnlyKeyFormatValidators.KeyDidJwkValidator);
            keyFormatValidator.AddValidator(typeof(PublicKeyMultibase), TestOnlyKeyFormatValidators.KeyDidMultibaseValidator);
            bool res = keyFormatValidator.Validate(actualKeyFormat, alg);
            Assert.IsTrue(res, $"Key format validation failed for {actualKeyFormat.GetType()} for algorithm {alg.Algorithm}.");

            //This part runs the whole suite if did:key validation rules Verifiable library defines against the document.
            var assessmentResult = await KeyDidAssessor.AssessAsync(keyDidDocument, "some-test-supplied-correlationId");
            Assert.IsTrue(assessmentResult.IsSuccess);

            string serializedDidDocument = JsonSerializer.Serialize(keyDidDocument, TestSetup.DefaultSerializationOptions);
            var (deserializedDidDocument, reserializedDidDocument) = JsonTestingUtilities.PerformSerializationCycle<DidDocument>(serializedDidDocument, TestSetup.DefaultSerializationOptions);
            bool areJsonElementsEqual = JsonTestingUtilities.CompareJsonElements(serializedDidDocument, reserializedDidDocument);
            Assert.IsTrue(areJsonElementsEqual, $"JSON string \"{serializedDidDocument}\" did not pass roundtrip test.");
            Assert.IsNotNull(deserializedDidDocument);
            Assert.IsNotNull(deserializedDidDocument.Id);
            Assert.AreEqual(typeof(KeyDidMethod), deserializedDidDocument.Id.GetType());
        }


        [TestMethod]
        [DynamicData(nameof(DidKeyTheoryData.GetDidTheoryTestData), typeof(DidKeyTheoryData), DynamicDataSourceType.Method)]
        public async ValueTask VerifySignatureUsingDidKeyVerificationMethod(DidKeyTestData testData)
        {
            if(testData.CryptoSuite is Multikey
                && testData.KeyPair.PublicKey.Tag != Tag.Rsa2048PublicKey
                && testData.KeyPair.PublicKey.Tag != Tag.Rsa4096PublicKey
                && testData.KeyPair.PublicKey.Tag != Tag.Secp256k1PublicKey
                && testData.KeyPair.PublicKey.Tag != Tag.X25519PublicKey)
            {
                // 1. Create Did:Key Document
                var keyDidDocument = KeyDidBuilder.Build(testData.KeyPair.PublicKey, testData.CryptoSuite);

                // 2. Extract Verification Method
                VerificationMethod? verificationMethod = keyDidDocument.VerificationMethod?.FirstOrDefault();
                Assert.IsNotNull(verificationMethod, "Verification method should not be null");

                // 3. Prepare content to sign
                var contentToSign = Encoding.UTF8.GetBytes("Hello, did:key signature!");

                // 4. Sign the content with the original private key
                var privateKey = CryptographicKeyFactory.CreatePrivateKey(testData.KeyPair.PrivateKey, verificationMethod.Id!, (CryptoAlgorithm)testData.KeyPair.PrivateKey.Tag[typeof(CryptoAlgorithm)], (Purpose)testData.KeyPair.PrivateKey.Tag[typeof(Purpose)]);
                using var signature = await privateKey.SignAsync(contentToSign, ExactSizeMemoryPool<byte>.Shared);
                //using var signature = await testData.KeyPair.PrivateKey.SignAsync(contentToSign, BouncyCastleAlgorithms.SignEd25519Async, MemoryPool<byte>.Shared);

                // 5. Reconstruct Public Key from Verification Method                                
                var multibasePublicKey = verificationMethod.Id;
                string multibasePublicKeyStripped = multibasePublicKey?.Split('#')[1] ?? string.Empty;

                var keyFormatSelected = SsiKeyFormatSelector.DefaultKeyFormatSelector(typeof(KeyDidMethod), testData.CryptoSuite);
                var keyFormat = SsiKeyFormatSelector.DefaultKeyFormatCreator(keyFormatSelected, testData.KeyPair.PublicKey);
                //var keyMaterial = VerificationMethodSelector.SelectKeyMaterial(verificationMethod);

                //TODO: The return values ought to be of type (Tag, IMemoryOwner<byte>) OR at least have EncodingScheme included!? AND with that PublicKeyMemory or PrivateKeyMemory can be constructed?
                var rawKeyMaterial = VerifiableCryptoFormatConversions.DefaultVerificationMethodToAlgorithmConverter(verificationMethod, ExactSizeMemoryPool<byte>.Shared);
                PublicKeyMemory publicKeyMemory = new (rawKeyMaterial.keyMaterial, new(new Dictionary<Type, object>
                {
                    [typeof(CryptoAlgorithm)] = rawKeyMaterial.Algorithm,
                    [typeof(Purpose)] = rawKeyMaterial.Purpose,
                    [typeof(EncodingScheme)] = rawKeyMaterial.Scheme
                }));                                
                Assert.IsNotNull(multibasePublicKey, "Multibase public key should not be null");
                Assert.IsNotNull(publicKeyMemory, "Multibase public key should not be null");


                // 6. Verify the signature using the reconstructed public key                                                                               
                if(testData.KeyPair.PublicKey.Tag == Tag.P384PublicKey)
                {                    
                    var signature2 = await MicrosoftCryptographicFunctions3.SignP384Async(testData.KeyPair.PrivateKey.AsReadOnlyMemory(), contentToSign, ExactSizeMemoryPool<byte>.Shared);
                    var publicKey2 = new PublicKey(testData.KeyPair.PublicKey, multibasePublicKey, MicrosoftCryptographicFunctions3.VerifyP384Async_2);
                    bool isVerified2 = await publicKey2.VerifyAsync(contentToSign, signature2);
                }

                var publicKey = CryptographicKeyFactory.CreatePublicKey(publicKeyMemory, multibasePublicKey, rawKeyMaterial.Algorithm, rawKeyMaterial.Purpose);
                bool isVerified = await publicKey.VerifyAsync(contentToSign, signature);
                Assert.IsTrue(isVerified, "Signature verification should succeed");                

                // 7. Additional verification method assertions
                Assert.IsNotNull(verificationMethod.Id, "Verification method should have an ID");
                Assert.IsNotNull(verificationMethod.Controller, "Verification method should have a controller");
            }
        }
    }
}