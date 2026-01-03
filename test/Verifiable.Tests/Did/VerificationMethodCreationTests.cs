using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestDataProviders;


namespace Verifiable.Tests.Did
{
    /// <summary>
    /// Represents the test data for creating verification methods. It encapsulates the necessary materials and expected outcomes for each test case.
    /// </summary>
    /// <param name="KeyPair">The public and private key materials used for creating the verification method.</param>
    /// <param name="VerificationMethodTypeInfo">The cryptographic suite associated with the verification method.</param>
    /// <param name="ExpectedKeyFormat">The expected format of the key once the verification method is created.</param>
    public record VerificationMethodTestData(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> KeyPair,
        VerificationMethodTypeInfo VerificationMethodTypeInfo,
        Type ExpectedKeyFormat)
    {
        /// <inheritdoc/>
        public override string ToString()
        {
            return $"Algorithm: {KeyPair.PublicKey.Tag.Get<CryptoAlgorithm>()} VerificationMethodTypeInfo: {VerificationMethodTypeInfo}, ExpectedKeyFormat: {ExpectedKeyFormat.Name}";
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
                data.Add([new VerificationMethodTestData(keyPair, JsonWebKey2020VerificationMethodTypeInfo.Instance, typeof(PublicKeyJwk))]);
                data.Add([new VerificationMethodTestData(keyPair, MultikeyVerificationMethodTypeInfo.Instance, typeof(PublicKeyMultibase))]);
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
        [DynamicData(nameof(VerificationMethodTheoryData.GetVerificationMethodTestData), typeof(VerificationMethodTheoryData))]
        public void CreatesCorrectVerificationMethodWithLibraryDefaults(VerificationMethodTestData testData)
        {
            const string Id = "TestId";
            const string Controller = "TestController";

            //Using the new extension method approach
            var verificationMethod = DidBuilderExtensions.CreateVerificationMethod(
                testData.KeyPair.PublicKey,
                testData.VerificationMethodTypeInfo,
                Id,
                Controller);

            var actualKeyFormat = verificationMethod.KeyFormat;
            Assert.IsInstanceOfType(actualKeyFormat, testData.ExpectedKeyFormat);

            Assert.AreEqual(Id, verificationMethod.Id);
            Assert.AreEqual(Controller, verificationMethod.Controller);
            Assert.AreEqual(testData.VerificationMethodTypeInfo.TypeName, verificationMethod.Type);
        }

        /// <summary>
        /// Tests explicitly creation of a verification method in <see cref="PublicKeyMultibase"/> using <see cref="Ed25519VerificationKey2020VerificationMethodTypeInfo"/>.
        /// This tests that the Ed25519 verification method defaults to multibase format.
        /// </summary>
        [TestMethod]
        public void CanCreateEd25519VerificationKey2020InMultibase()
        {
            const string Id = "Ed25519VerificationKey2020TestId";
            const string Controller = "Ed25519VerificationKey2020TestController";

            //Ed25519VerificationMethod should default to PublicKeyMultibase
            var verificationMethodInMultibase = DidBuilderExtensions.CreateVerificationMethod(
                TestKeyMaterialProvider.Ed25519KeyMaterial.PublicKey,
                Ed25519VerificationKey2020VerificationMethodTypeInfo.Instance,
                Id,
                Controller);

            var actualMultibaseKeyFormat = verificationMethodInMultibase.KeyFormat;
            Assert.IsInstanceOfType(actualMultibaseKeyFormat, WellKnownKeyFormats.PublicKeyMultibase);
            Assert.AreEqual(Id, verificationMethodInMultibase.Id);
            Assert.AreEqual(Controller, verificationMethodInMultibase.Controller);
            Assert.AreEqual(Ed25519VerificationKey2020VerificationMethodTypeInfo.Instance.TypeName, verificationMethodInMultibase.Type);
        }

        /// <summary>
        /// Tests explicitly creation of a verification method <see cref="PublicKeyJwk"/> using <see cref="Ed25519VerificationKey2020VerificationMethodTypeInfo"/>.
        /// This tests overriding the default format selection to use JWK instead of the default multibase.
        /// </summary>
        /// <remarks>
        /// This test temporarily modifies <see cref="VerificatioMethodTypeInfoKeyFormatSelector.Default"/>,
        /// which is global state. Parallel execution is disabled to prevent interference with other tests.
        /// </remarks>
        [TestMethod]
        [DoNotParallelize]
        public void CanCreateEd25519VerificationKey2020InJwk()
        {
            const string Id = "Ed25519VerificationKey2020TestId";
            const string Controller = "Ed25519VerificationKey2020TestController";

            //Override the format selector to force JWK for this test
            var originalSelector = VerificatioMethodTypeInfoKeyFormatSelector.Default;
            try
            {
                VerificatioMethodTypeInfoKeyFormatSelector.Default = (vmType, key) => WellKnownKeyFormats.PublicKeyJwk;

                var verificationMethodInJwk = DidBuilderExtensions.CreateVerificationMethod(
                    TestKeyMaterialProvider.Ed25519KeyMaterial.PublicKey,
                    Ed25519VerificationKey2020VerificationMethodTypeInfo.Instance,
                    Id,
                    Controller);

                var actualJwkKeyFormat = verificationMethodInJwk.KeyFormat;
                Assert.IsInstanceOfType(actualJwkKeyFormat, WellKnownKeyFormats.PublicKeyJwk);
                Assert.AreEqual(Id, verificationMethodInJwk.Id);
                Assert.AreEqual(Controller, verificationMethodInJwk.Controller);
                Assert.AreEqual(Ed25519VerificationKey2020VerificationMethodTypeInfo.Instance.TypeName, verificationMethodInJwk.Type);
            }
            finally
            {
                VerificatioMethodTypeInfoKeyFormatSelector.Default = originalSelector;
            }
        }
    }
}