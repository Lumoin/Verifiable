using System;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Xunit;

namespace Verifiable.Tests.TestDataProviders
{
    public record DidKeyTestData(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> KeyPair,
        CryptoSuite CryptoSuite,
        Type ExpectedKeyFormat)
    {

        public override string ToString()
        {
            return $"Algorithm: {((CryptoAlgorithm)KeyPair.PublicKey.Tag[typeof(CryptoAlgorithm)]).Algorithm} CryptoSuite: {CryptoSuite.CryptoSuiteId}, ExpectedKeyFormat: {ExpectedKeyFormat.Name}";
        }
    }


    public class DidKeyTheoryData: TheoryData<DidKeyTestData>
    {
        public DidKeyTheoryData()
        {
            void AddTestData(PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair)
            {
                Add(new DidKeyTestData(keyPair, JsonWebKey2020.DefaultInstance, typeof(PublicKeyJwk)));
                Add(new DidKeyTestData(keyPair, Multikey.DefaultInstance, typeof(PublicKeyMultibase)));
            }

            AddTestData(TestKeyMaterialProvider.P256KeyMaterial);
            AddTestData(TestKeyMaterialProvider.P384KeyMaterial);
            AddTestData(TestKeyMaterialProvider.P521KeyMaterial);
            AddTestData(TestKeyMaterialProvider.Secp256k1KeyMaterial);
            AddTestData(TestKeyMaterialProvider.Rsa2048KeyMaterial);
            AddTestData(TestKeyMaterialProvider.Rsa4096KeyMaterial);
            AddTestData(TestKeyMaterialProvider.Ed25519KeyMaterial);
            AddTestData(TestKeyMaterialProvider.X25519KeyMaterial);
        }
    }    
}
