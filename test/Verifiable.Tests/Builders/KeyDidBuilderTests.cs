﻿using System.Text.Json;
using Verifiable.Assessment;
using Verifiable.Core.Builders;
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
            //did:key it is specificed how the identifier is generated from the key
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
            Assert.AreEqual(typeof(KeyDidMethod), deserializedDidDocument?.Id?.GetType());
        }
    }


    public class Version1
    {

    }

    public class Version2
    {

    }


    public static class Transformer
    {
        public static TTransformed Transform<TTransformed, TOriginal>(TOriginal toBeTransformed, Func<TOriginal, TTransformed> transformer)
        {
            return transformer(toBeTransformed);
        }
    }

    public static class GrainTransformer
    {
        public static Func<object, TTransformed> GetTransformer<TTransformed>(string grainId, string grainType, string siloId)
        {
            return grainState =>
            {
                return (TTransformed)grainState;
            };
        }
    }


    public class Test
    {
        public void TestMethod()
        {
            Version1 v1 = new();
            Version2 v2 = Transformer.Transform(v1, (v1) => new Version2());

            var transformer = GrainTransformer.GetTransformer<Version2>("grain1", "typeA", "siloX");
            Version2 transformedState = transformer(v1);
        }
    }
}