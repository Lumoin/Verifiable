using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.TestDataProviders
{
    /// <summary>
    /// Test data for DID Key tests. Stores a factory delegate instead of live key material
    /// so that <see cref="DynamicDataAttribute"/> enumeration during test discovery does not
    /// create orphaned disposable instances.
    /// </summary>
    /// <param name="AlgorithmName">A human-readable name for the algorithm, used in test display.</param>
    /// <param name="KeyPairFactory">A factory that creates fresh, disposable key material per test invocation.</param>
    /// <param name="VerificationMethodTypeInfo">The cryptographic suite associated with the verification method.</param>
    /// <param name="ExpectedKeyFormat">The expected format of the key once the verification method is created.</param>
    internal record DidKeyTestData(
        string AlgorithmName,
        Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> KeyPairFactory,
        VerificationMethodTypeInfo VerificationMethodTypeInfo,
        Type ExpectedKeyFormat)
    {
        /// <inheritdoc/>
        public override string ToString()
        {
            return $"Algorithm: {AlgorithmName}, VerificationMethodTypeInfo: {VerificationMethodTypeInfo.TypeName}, ExpectedKeyFormat: {ExpectedKeyFormat.Name}";
        }
    }


    /// <summary>
    /// Provides theory data for DID Key creation tests.
    /// </summary>
    internal sealed class DidKeyTheoryData
    {
        /// <summary>
        /// Provides test data rows for all supported algorithm and verification method type combinations.
        /// Key material is created lazily by each test invocation to ensure proper disposal.
        /// </summary>
        public static IEnumerable<object[]> GetDidTheoryTestData()
        {
            static void AddTestData(string algorithmName, Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> factory, List<object[]> data)
            {
                data.Add([new DidKeyTestData(algorithmName, factory, JsonWebKey2020VerificationMethodTypeInfo.Instance, typeof(PublicKeyJwk))]);
                data.Add([new DidKeyTestData(algorithmName, factory, MultikeyVerificationMethodTypeInfo.Instance, typeof(PublicKeyMultibase))]);
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
}