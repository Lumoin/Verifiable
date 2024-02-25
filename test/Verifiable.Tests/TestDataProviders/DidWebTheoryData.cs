using System;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Xunit;

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

    public class DidWebTheoryData: TheoryData<DidWebTestData>
    {
        public DidWebTheoryData()
        {
            void AddTestData(PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair)
            {
                Add(new DidWebTestData(keyPair, JsonWebKey2020.DefaultInstance, typeof(PublicKeyJwk)));
                Add(new DidWebTestData(keyPair, Ed25519VerificationKey2020.DefaultInstance, typeof(PublicKeyMultibase)));
            }
            
            AddTestData(TestKeyMaterialProvider.Ed25519KeyMaterial);            
        }
    }
}
