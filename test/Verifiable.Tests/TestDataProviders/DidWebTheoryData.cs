using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;

namespace Verifiable.Tests.TestDataProviders
{
    public record DidWebTestData(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> KeyPair,
        CryptoSuite CryptoSuite,
        Type ExpectedKeyFormat)
    {

        public override string ToString()
        {
            return $"Algorithm: {((CryptoAlgorithm)KeyPair.PublicKey.Tag[typeof(CryptoAlgorithm)]).Algorithm} CryptoSuite: {CryptoSuite.CryptoSuiteId}, ExpectedKeyFormat: {ExpectedKeyFormat.Name}";
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
                    new object[] { new DidWebTestData(keyPair, JsonWebKey2020.DefaultInstance, typeof(PublicKeyJwk)) },
                    new object[] { new DidWebTestData(keyPair, Ed25519VerificationKey2020.DefaultInstance, typeof(PublicKeyMultibase)) }
                };
            }

            var allData = new List<object[]>();
            allData.AddRange(AddTestData(TestKeyMaterialProvider.Ed25519KeyMaterial));

            return allData;
        }
    };
}
