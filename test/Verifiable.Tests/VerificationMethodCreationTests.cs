using Verifiable.Core;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Tests.Builders;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests
{
    /// <summary>
    /// Represents the test data for creating verification methods. It encapsulates the necessary materials and expected outcomes for each test case.
    /// </summary>
    /// <param name="KeyPair">The public and private key materials used for creating the verification method.</param>
    /// <param name="CryptoSuite">The cryptographic suite associated with the verification method.</param>
    /// <param name="ExpectedKeyFormat">The expected format of the key once the verification method is created.</param>
    public record VerificationMethodTestData(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> KeyPair,
        CryptoSuite CryptoSuite,
        Type ExpectedKeyFormat)
    {
        /// <inheritdoc/>
        public override string ToString()
        {
            return $"Algorithm: {((CryptoAlgorithm)KeyPair.PublicKey.Tag[typeof(CryptoAlgorithm)]).Algorithm} CryptoSuite: {CryptoSuite.CryptoSuiteId}, ExpectedKeyFormat: {ExpectedKeyFormat.Name}";
        }
    }


    /// <summary>
    /// Theory data for verification method creation tests.
    /// </summary>
    public static class VerificationMethodTheoryData
    {
        public static IEnumerable<object[]> GetVerificationMethodTestData()
        {
            static void AddTestData(PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair, List<object[]> data)
            {
                data.Add([new VerificationMethodTestData(keyPair, JsonWebKey2020.DefaultInstance, typeof(PublicKeyJwk))]);
                data.Add([new VerificationMethodTestData(keyPair, Multikey.DefaultInstance, typeof(PublicKeyMultibase))]);
            }

            List<object[]> data = [];
            AddTestData(TestKeyMaterialProvider.P256KeyMaterial, data);
            AddTestData(TestKeyMaterialProvider.P384KeyMaterial, data);
            AddTestData(TestKeyMaterialProvider.P521KeyMaterial, data);
            AddTestData(TestKeyMaterialProvider.Secp256k1KeyMaterial, data);
            AddTestData(TestKeyMaterialProvider.Rsa2048KeyMaterial, data);
            AddTestData(TestKeyMaterialProvider.Rsa4096KeyMaterial, data);
            AddTestData(TestKeyMaterialProvider.Ed25519KeyMaterial, data);
            AddTestData(TestKeyMaterialProvider.X25519KeyMaterial, data);

            return data;
        }
    }


    /// <summary>
    /// Tests creating verification methods.
    /// </summary>
    [TestClass]
    public class VerificationMethodCreationTests
    {
        [TestMethod]
        [DynamicData(nameof(VerificationMethodTheoryData.GetVerificationMethodTestData), typeof(VerificationMethodTheoryData), DynamicDataSourceType.Method)]
        public void CreatesCorrectVerificationMethodWithLibraryDefaults(VerificationMethodTestData testData)
        {
            const string Id = "TestId";
            const string Controller = "TestController";            
            var verificationMethod = DidBuilderExtensions.CreateVerificationMethod(
                testData.KeyPair.PublicKey,
                testData.CryptoSuite,
                Id,
                Controller);

            var actualKeyFormat = verificationMethod.KeyFormat;
            Assert.IsInstanceOfType(actualKeyFormat, testData.ExpectedKeyFormat);

            Assert.AreEqual(Id, verificationMethod.Id);
            Assert.AreEqual(Controller, verificationMethod.Controller);
            Assert.AreEqual(testData.CryptoSuite.CryptoSuiteId, verificationMethod.Type);
        }


        /// <summary>
        /// Tests explicitly creation of a verification method in <see cref="PublicKeyMultibase"/> using <see cref="Ed25519VerificationKey2020"/>
        /// that is deprecated.
        /// </summary>
        [TestMethod]
        public void CanCreateEd25519VerificationKey2020InMultibase()
        {            
            const string Id = "Ed25519VerificationKey2020TestId";
            const string Controller = "Ed25519VerificationKey2020TestController";
            
            var verificationMethodInMultibase = DidBuilderExtensions.CreateVerificationMethod<GenericDidMethod>(
                TestKeyMaterialProvider.Ed25519KeyMaterial.PublicKey,
                Ed25519VerificationKey2020.DefaultInstance,
                Id,
                Controller,
                (didMethod, cryptoSuite, preferredFormat) => WellKnownKeyFormats.PublicKeyMultibase,
                SsiKeyFormatSelector.DefaultKeyFormatCreator);

            var actualMultibaseKeyFormat = verificationMethodInMultibase.KeyFormat;
            Assert.IsInstanceOfType(actualMultibaseKeyFormat, WellKnownKeyFormats.PublicKeyMultibase);
            Assert.AreEqual(Id, verificationMethodInMultibase.Id);
            Assert.AreEqual(Controller, verificationMethodInMultibase.Controller);
            Assert.AreEqual(Ed25519VerificationKey2020.DefaultInstance.CryptoSuiteId, verificationMethodInMultibase.Type);                       
        }


        /// <summary>
        /// Tests explicitly creation of a verification method <see cref="PublicKeyJwk"/> using <see cref="Ed25519VerificationKey2020"/>
        /// that is deprecated.
        /// </summary>
        [TestMethod]
        public void CanCreateEd25519VerificationKey2020InJwk()
        {
            const string Id = "Ed25519VerificationKey2020TestId";
            const string Controller = "Ed25519VerificationKey2020TestController";
                        
            var verificationMethodInJwk = DidBuilderExtensions.CreateVerificationMethod<GenericDidMethod>(
                TestKeyMaterialProvider.Ed25519KeyMaterial.PublicKey,
                Ed25519VerificationKey2020.DefaultInstance,
                Id,
                Controller,
                (didMethod, cryptoSuite, preferredFormat) => WellKnownKeyFormats.PublicKeyJwk,
                SsiKeyFormatSelector.DefaultKeyFormatCreator);

            var actualJwkKeyFormat = verificationMethodInJwk.KeyFormat;
            Assert.IsInstanceOfType(actualJwkKeyFormat, WellKnownKeyFormats.PublicKeyJwk);
            Assert.AreEqual(Id, verificationMethodInJwk.Id);
            Assert.AreEqual(Controller, verificationMethodInJwk.Controller);
            Assert.AreEqual(Ed25519VerificationKey2020.DefaultInstance.CryptoSuiteId, verificationMethodInJwk.Type);
        }
    }
}
