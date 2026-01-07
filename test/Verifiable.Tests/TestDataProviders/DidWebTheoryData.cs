using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.TestDataProviders
{
    public record DidWebTestData(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> KeyPair,
        VerificationMethodTypeInfo VerificationMethodTypeInfo,
        Type ExpectedKeyFormat)
    {

        public override string ToString()
        {
            return $"Algorithm: {((CryptoAlgorithm)KeyPair.PublicKey.Tag[typeof(CryptoAlgorithm)]).Algorithm} verification method: {VerificationMethodTypeInfo}, ExpectedKeyFormat: {ExpectedKeyFormat.Name}";
        }
    }

    public sealed class DidWebTheoryData
    {
        public static IEnumerable<object[]> GetDidTheoryTestData()
        {
            static IEnumerable<object[]> AddTestData(PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair)
            {
                return new List<object[]>
                {
                    new object[] { new DidWebTestData(keyPair, VerificationMethodTypeInfo.JsonWebKey2020, typeof(PublicKeyJwk)) },
                    new object[] { new DidWebTestData(keyPair, VerificationMethodTypeInfo.Ed25519VerificationKey2020, typeof(PublicKeyMultibase)) }
                };
            }

            var allData = new List<object[]>();
            allData.AddRange(AddTestData(TestKeyMaterialProvider.Ed25519KeyMaterial));

            return allData;
        }
    };
}
