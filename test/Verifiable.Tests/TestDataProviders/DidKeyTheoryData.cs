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
        /// Provides test data rows for all supported algorithm and verification method type
        /// combinations — both signature and key-agreement algorithms. Used by tests (e.g.
        /// document building) that apply to every algorithm regardless of key operation.
        /// Key material is created lazily by each test invocation to ensure proper disposal.
        /// </summary>
        public static IEnumerable<object[]> GetDidTheoryTestData() => BuildRows(signingOnly: false);


        /// <summary>
        /// Provides test data rows for the signature-capable algorithms only — the subset to
        /// which a sign/verify round-trip applies. The key-agreement-only <c>X25519</c> curve is
        /// excluded; its DID-key round-trip is covered by the key-exchange test instead. Feeding
        /// the signature test this set (rather than all algorithms with a runtime skip) keeps the
        /// data source the single source of truth for which algorithms a signature test applies to.
        /// </summary>
        public static IEnumerable<object[]> GetSigningDidTheoryTestData() => BuildRows(signingOnly: true);


        /// <summary>
        /// Builds the algorithm × verification-method-type rows, optionally restricted to
        /// signature-capable algorithms.
        /// </summary>
        /// <param name="signingOnly">When <see langword="true"/>, key-agreement-only algorithms are omitted.</param>
        private static List<object[]> BuildRows(bool signingOnly)
        {
            void AddTestData(string algorithmName, Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> factory, bool supportsSigning, List<object[]> data)
            {
                if(signingOnly && !supportsSigning)
                {
                    return;
                }

                data.Add([new DidKeyTestData(algorithmName, factory, JsonWebKey2020VerificationMethodTypeInfo.Instance, typeof(PublicKeyJwk))]);
                data.Add([new DidKeyTestData(algorithmName, factory, MultikeyVerificationMethodTypeInfo.Instance, typeof(PublicKeyMultibase))]);
            }

            List<object[]> data = [];
            AddTestData("P-256", TestKeyMaterialProvider.CreateP256KeyMaterial, supportsSigning: true, data);
            AddTestData("P-384", TestKeyMaterialProvider.CreateP384KeyMaterial, supportsSigning: true, data);
            AddTestData("P-521", TestKeyMaterialProvider.CreateP521KeyMaterial, supportsSigning: true, data);
            AddTestData("secp256k1", TestKeyMaterialProvider.CreateSecp256k1KeyMaterial, supportsSigning: true, data);
            AddTestData("RSA-2048", TestKeyMaterialProvider.CreateRsa2048KeyMaterial, supportsSigning: true, data);
            AddTestData("RSA-4096", TestKeyMaterialProvider.CreateRsa4096KeyMaterial, supportsSigning: true, data);
            AddTestData("Ed25519", TestKeyMaterialProvider.CreateEd25519KeyMaterial, supportsSigning: true, data);

            //X25519 is a key-agreement (ECDH) curve, not a signature algorithm: it appears in
            //the full set (document building) but never in the signing set.
            AddTestData("X25519", TestKeyMaterialProvider.CreateX25519KeyMaterial, supportsSigning: false, data);

            return data;
        }
    }
}
