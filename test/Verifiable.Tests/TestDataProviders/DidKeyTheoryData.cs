using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Verifiable.Core.Did.CryptographicSuites;

namespace Verifiable.Tests.TestDataProviders
{
    public record DidKeyTestData(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> KeyPair,
        VerificationMethodTypeInfo VerificationMethodTypeInfo,
        Type ExpectedKeyFormat)
    {

        public override string ToString()
        {
            return $"Algorithm: {((CryptoAlgorithm)KeyPair.PublicKey.Tag[typeof(CryptoAlgorithm)])} VerifictionMethodTypeInfo: {VerificationMethodTypeInfo.TypeName}, ExpectedKeyFormat: {ExpectedKeyFormat.Name}";
        }
    }


    public sealed class DidKeyTheoryData
    {
        public static IEnumerable<object[]> GetDidTheoryTestData()
        {
            static IEnumerable<object[]> AddTestData(PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair)
            {
                return new List<object[]>
                {
                    new object[] { new DidKeyTestData(keyPair, VerificationMethodTypeInfo.JsonWebKey2020, typeof(PublicKeyJwk)) },
                    new object[] { new DidKeyTestData(keyPair, VerificationMethodTypeInfo.Multikey, typeof(PublicKeyMultibase)) }
                };
            }

            var allData = new List<object[]>();
            allData.AddRange(AddTestData(TestKeyMaterialProvider.P256KeyMaterial));
            allData.AddRange(AddTestData(TestKeyMaterialProvider.P384KeyMaterial));
            allData.AddRange(AddTestData(TestKeyMaterialProvider.P521KeyMaterial));
            allData.AddRange(AddTestData(TestKeyMaterialProvider.Secp256k1KeyMaterial));
            allData.AddRange(AddTestData(TestKeyMaterialProvider.Rsa2048KeyMaterial));
            allData.AddRange(AddTestData(TestKeyMaterialProvider.Rsa4096KeyMaterial));
            allData.AddRange(AddTestData(TestKeyMaterialProvider.Ed25519KeyMaterial));
            allData.AddRange(AddTestData(TestKeyMaterialProvider.X25519KeyMaterial));

            return allData;
        }
    }
}
