using System.Text.Json;
using Verifiable.Core.Model.Credentials;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity
{
    internal class CredentialSecuringMaterial
    {
        public static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

        public static string UnsignedCredentialJson { get; } = /*lang=json,strict*/ """
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential"],
            "issuer": {
                "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
                "name": "Example University"
            },
            "validFrom": "2010-01-01T19:23:24Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                    "type": "ExampleBachelorDegree",
                    "name": "Bachelor of Science and Arts"
                }
            }
        }
        """;

        public static VerifiableCredential Credential { get; } = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        public static string Ed25519PublicKeyMultibase { get; } = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
        public static string Ed25519SecretKeyMultibase { get; } = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";
        public static string VerificationMethodId { get; } = "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";

        public static PrivateKeyMemory DecodeEd25519PrivateKey()
        {
            var bytes = MultibaseSerializer.Decode(
                Ed25519SecretKeyMultibase,
                MulticodecHeaders.Ed25519PrivateKey.Length,
                TestSetup.Base58Decoder,
                SensitiveMemoryPool<byte>.Shared);
            return new PrivateKeyMemory(bytes, CryptoTags.Ed25519PrivateKey);
        }

        public static PublicKeyMemory DecodeEd25519PublicKey()
        {
            var bytes = MultibaseSerializer.Decode(
                Ed25519PublicKeyMultibase,
                MulticodecHeaders.Ed25519PublicKey.Length,
                TestSetup.Base58Decoder,
                SensitiveMemoryPool<byte>.Shared);
            return new PublicKeyMemory(bytes, CryptoTags.Ed25519PublicKey);
        }
    }
}
