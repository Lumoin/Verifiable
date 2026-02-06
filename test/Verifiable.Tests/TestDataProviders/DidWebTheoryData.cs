using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Cryptography;

namespace Verifiable.Tests.TestDataProviders
{
    /// <summary>
    /// Test data for DID Web tests. Stores a factory delegate instead of live key material
    /// so that <see cref="DynamicDataAttribute"/> enumeration during test discovery does not
    /// create orphaned disposable instances.
    /// </summary>
    /// <param name="AlgorithmName">A human-readable name for the algorithm, used in test display.</param>
    /// <param name="KeyPairFactory">A factory that creates fresh, disposable key material per test invocation.</param>
    /// <param name="VerificationMethodTypeInfo">The cryptographic suite associated with the verification method.</param>
    /// <param name="ExpectedKeyFormat">The expected format of the key once the verification method is created.</param>
    internal record DidWebTestData(
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
    /// Provides theory data for DID Web creation tests.
    /// </summary>
    internal sealed class DidWebTheoryData
    {
        /// <summary>
        /// Provides test data rows for Ed25519 verification method type combinations.
        /// Key material is created lazily by each test invocation to ensure proper disposal.
        /// </summary>
        public static IEnumerable<object[]> GetDidTheoryTestData()
        {
            static void AddTestData(string algorithmName, Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> factory, List<object[]> data)
            {
                data.Add([new DidWebTestData(algorithmName, factory, JsonWebKey2020VerificationMethodTypeInfo.Instance, typeof(PublicKeyJwk))]);
                data.Add([new DidWebTestData(algorithmName, factory, Ed25519VerificationKey2020VerificationMethodTypeInfo.Instance, typeof(PublicKeyMultibase))]);
            }

            List<object[]> data = [];
            AddTestData("Ed25519", TestKeyMaterialProvider.CreateEd25519KeyMaterial, data);

            return data;
        }
    }
}