using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Verifiable.Core.Did.CryptographicSuites;

namespace Verifiable.Tests.TestDataProviders
{
    public record DidWebTestData(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> KeyPair,
        CryptographicSuite CryptoSuite,
        Type ExpectedKeyFormat)
    {

        public override string ToString()
        {
            return $"Algorithm: {((CryptoAlgorithm)KeyPair.PublicKey.Tag[typeof(CryptoAlgorithm)]).Algorithm} CryptographicSuite: {CryptoSuite.VerificationMethodType}, ExpectedKeyFormat: {ExpectedKeyFormat.Name}";
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
                    new object[] { new DidWebTestData(keyPair, JsonWebKey2020.Instance, typeof(PublicKeyJwk)) },
                    new object[] { new DidWebTestData(keyPair, Ed25519VerificationKey2020.Instance, typeof(PublicKeyMultibase)) }
                };
            }

            var allData = new List<object[]>();
            allData.AddRange(AddTestData(TestKeyMaterialProvider.Ed25519KeyMaterial));

            return allData;
        }
    };
}
