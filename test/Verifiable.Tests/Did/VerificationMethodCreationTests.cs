using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Cryptography;
using Verifiable.Tests.TestDataProviders;


namespace Verifiable.Tests.Did
{
    /// <summary>
    /// Represents the test data for creating verification methods. It stores a factory
    /// delegate instead of live key material so that <see cref="DynamicDataAttribute"/>
    /// enumeration during test discovery does not create orphaned disposable instances.
    /// </summary>
    /// <param name="AlgorithmName">A human-readable name for the algorithm, used in test display.</param>
    /// <param name="KeyPairFactory">A factory that creates fresh, disposable key material per test invocation.</param>
    /// <param name="VerificationMethodTypeInfo">The cryptographic suite associated with the verification method.</param>
    /// <param name="ExpectedKeyFormat">The expected format of the key once the verification method is created.</param>
    internal record VerificationMethodTestData(
        string AlgorithmName,
        Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> KeyPairFactory,
        VerificationMethodTypeInfo VerificationMethodTypeInfo,
        Type ExpectedKeyFormat)
    {
        /// <inheritdoc/>
        public override string ToString()
        {
            return $"Algorithm: {AlgorithmName}, VerificationMethodTypeInfo: {VerificationMethodTypeInfo}, ExpectedKeyFormat: {ExpectedKeyFormat.Name}";
        }
    }

    /// <summary>
    /// Theory data for verification method creation tests.
    /// </summary>
    internal static class VerificationMethodTheoryData
    {
        /// <summary>
        /// Provides test data rows for all supported algorithm and verification method type combinations.
        /// Key material is created lazily by each test invocation to ensure proper disposal.
        /// </summary>
        public static IEnumerable<object[]> GetVerificationMethodTestData()
        {
            static void AddTestData(string algorithmName, Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> factory, List<object[]> data)
            {
                data.Add([new VerificationMethodTestData(algorithmName, factory, JsonWebKey2020VerificationMethodTypeInfo.Instance, typeof(PublicKeyJwk))]);
                data.Add([new VerificationMethodTestData(algorithmName, factory, MultikeyVerificationMethodTypeInfo.Instance, typeof(PublicKeyMultibase))]);
            }

            List<object[]> data = [];
            AddTestData("P-256", TestKeyMaterialProvider.CreateP256KeyMaterial, data);
            AddTestData("P-384", TestKeyMaterialProvider.CreateP384KeyMaterial, data);
            AddTestData("P-521", TestKeyMaterialProvider.CreateP521KeyMaterial, data);
            AddTestData("secp256k1", TestKeyMaterialProvider.CreateSecp256k1KeyMaterial, data);
            AddTestData("RSA-2048", TestKeyMaterialProvider.CreateRsa2048KeyMaterial, data);
            AddTestData("RSA-4096", TestKeyMaterialProvider.CreateRsa4096KeyMaterial, data);
            AddTestData("Ed25519", TestKeyMaterialProvider.CreateEd25519KeyMaterial, data);
            AddTestData("X25519", TestKeyMaterialProvider.CreateX25519KeyMaterial, data);

            return data;
        }
    }

    /// <summary>
    /// Tests creating verification methods.
    /// </summary>
    [TestClass]
    internal class VerificationMethodCreationTests
    {
        [TestMethod]
        [DynamicData(nameof(VerificationMethodTheoryData.GetVerificationMethodTestData), typeof(VerificationMethodTheoryData))]
        public void CreatesCorrectVerificationMethodWithLibraryDefaults(VerificationMethodTestData testData)
        {
            const string Id = "TestId";
            const string Controller = "TestController";

            var keyPair = testData.KeyPairFactory();
            using var publicKey = keyPair.PublicKey;
            using var privateKey = keyPair.PrivateKey;

            var verificationMethod = DidBuilderExtensions.CreateVerificationMethod(
                publicKey,
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
        /// Tests that an Ed25519 verification method created with
        /// <see cref="Ed25519VerificationKey2020VerificationMethodTypeInfo"/> defaults
        /// to <see cref="PublicKeyMultibase"/> format.
        /// </summary>
        [TestMethod]
        public void CanCreateEd25519VerificationKey2020InMultibase()
        {
            const string Id = "Ed25519VerificationKey2020TestId";
            const string Controller = "Ed25519VerificationKey2020TestController";

            var keyPair = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
            using var publicKey = keyPair.PublicKey;
            using var privateKey = keyPair.PrivateKey;

            var verificationMethodInMultibase = DidBuilderExtensions.CreateVerificationMethod(
                publicKey,
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
        /// Tests overriding the default format selection to use JWK instead of
        /// the default multibase for <see cref="Ed25519VerificationKey2020VerificationMethodTypeInfo"/>.
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

            var keyPair = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
            using var publicKey = keyPair.PublicKey;
            using var privateKey = keyPair.PrivateKey;

            var originalSelector = VerificatioMethodTypeInfoKeyFormatSelector.Default;
            try
            {
                VerificatioMethodTypeInfoKeyFormatSelector.Default = (vmType, key) => WellKnownKeyFormats.PublicKeyJwk;

                var verificationMethodInJwk = DidBuilderExtensions.CreateVerificationMethod(
                    publicKey,
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