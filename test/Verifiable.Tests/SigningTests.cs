using SimpleBase;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Did;
using Verifiable.Jwt;
using Verifiable.Tests.TestDataProviders;
using Xunit;

namespace Verifiable.Tests
{
    public class SigningTests
    {
        //System.Buffers.Text.Base64: https://source.dot.net/#System.Private.CoreLib/src/libraries/System.Private.CoreLib/src/System/Buffers/Text/Base64Decoder.cs,72                

        [Fact]
        public void CanSignDidWeb()
        {
            var keys = TestKeyMaterialProvider.Ed25519KeyMaterial;
            var multibaseEncodedPublicKey = MultibaseSerializer.Encode(keys.PublicKey.AsReadOnlySpan(), MulticodecHeaders.Ed25519PublicKey, MultibaseAlgorithms.Base58Btc, Base58.Bitcoin.Encode);
            var multibaseEncodedPrivateKey = MultibaseSerializer.Encode(keys.PrivateKey.AsReadOnlySpan(), MulticodecHeaders.Ed25519PrivateKey, MultibaseAlgorithms.Base58Btc, Base58.Bitcoin.Encode);

            var btc58EncodedPublicKey = Base58.Bitcoin.Encode(keys.PublicKey.AsReadOnlySpan());
            var base64EncodedPublicKey = Base64Url.Encode(keys.PublicKey.AsReadOnlySpan());

            /*
            var keys = TestKeyMaterialProvider.Ed25519KeyMaterial;
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;*/

            //TODO: Check this before committing. <-- Check also this exact phrase in other test and fix it.            
            var multibaseDecodedPublicKey = MultibaseSerializer.Decode(Vc0PublicKey, ExactSizeMemoryPool<byte>.Shared, Base58.Bitcoin.Decode);
            var multibaseDecodedPrivateKey = MultibaseSerializer.Decode(Vc0PrivateKey, ExactSizeMemoryPool<byte>.Shared, Base58.Bitcoin.Decode);
            PublicKeyMemory publicKeyMemory = new(multibaseDecodedPublicKey, Tag.Ed25519PublicKey);
            PrivateKeyMemory privateKeyMemory = new(multibaseDecodedPrivateKey, Tag.Ed25519PrivateKey);

            var proofValueBytes = Base58.Bitcoin.Decode(Vc0ProofValue.AsSpan()[1..]);
            var pooledProofSignatureBytes = ExactSizeMemoryPool<byte>.Shared.Rent(proofValueBytes.Length);
            proofValueBytes.CopyTo(pooledProofSignatureBytes.Memory.Span);
            var proofSignature = new Signature(pooledProofSignatureBytes, Tag.Ed25519Signature);

            string canonocalizedDataWithoutProof = CanonicalVc0Document;
            var canonocalizedDataWithoutProofHashedData = SHA256.HashData(Encoding.UTF8.GetBytes(canonocalizedDataWithoutProof));
            var proofValueHash = SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalVc0ProofDocument));
            var combinedHashToVerify = proofValueHash.Concat(canonocalizedDataWithoutProofHashedData).ToArray();

            /*
            var ownSignature = privateKeyMemory.Sign(canonocalizedDataWithoutProofHashedData, BouncyCastleAlgorithms.SignEd25519, MemoryPool<byte>.Shared);
            string ownProof = 'z' + Base58.Bitcoin.Encode(ownSignature.AsReadOnlySpan());
            string reEncodedTestVector = 'z' + Base58.Bitcoin.Encode(proofValueBytes);
            Assert.Equal(Vc0ProofValue, reEncodedTestVector);*/

            //bool ownIsVerified = publicKeyMemory.Verify(canonocalizedDataWithoutProofHashedData, ownSignature, BouncyCastleAlgorithms.VerifyEd25519);

            var hex = BitConverter.ToString(combinedHashToVerify).Replace("-", "", StringComparison.InvariantCulture);
            bool isVerified = publicKeyMemory.Verify(combinedHashToVerify, proofSignature, BouncyCastleAlgorithms.VerifyEd25519);
            
            Assert.True(isVerified);
        }


        //https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/.
        public static string Vc0 = """
                      {
              "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
              ],
              "id": "http://example.gov/credentials/3732",
              "type": ["VerifiableCredential", "UniversityDegreeCredential"],
              "issuer": "https://example.com/issuer/123",
              "issuanceDate": "2020-03-10T04:24:12.164Z",
              "credentialSubject": {
                "id": "did:example:456",
                "degree": {
                  "type": "BachelorDegree",
                  "name": "Bachelor of Science and Arts"
                }
              },
              "proof": {
                "type": "Ed25519Signature2020",
                "created": "2019-12-11T03:50:55Z",
                "proofValue": "z5SpZtDGGz5a89PJbQT2sgbRUiyyAGhhgjcf86aJHfYcfvPjxn6vej5na6kUzmw1jMAR9PJU9mowshQFFdGmDN14D",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "https://example.com/issuer/123#key-0"
              }
            }
            """;

        public static string CanonicalVc0Document = "<did:example:456> <https://example.org/examples#degree> _:c14n0 .\n<http://example.gov/credentials/3732> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#UniversityDegreeCredential> .\n<http://example.gov/credentials/3732> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n<http://example.gov/credentials/3732> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:456> .\n<http://example.gov/credentials/3732> <https://www.w3.org/2018/credentials#issuanceDate> \"2020-03-10T04:24:12.164Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n<http://example.gov/credentials/3732> <https://www.w3.org/2018/credentials#issuer> <https://example.com/issuer/123> .\n_:c14n0 <http://schema.org/name> \"Bachelor of Science and Arts\"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .\n_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#BachelorDegree> .\n";
        public static string CanonicalVc0ProofDocument = "_:c14n0 <http://purl.org/dc/terms/created> \"2019-12-11T03:50:55Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Ed25519Signature2020> .\n_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .\n_:c14n0 <https://w3id.org/security#verificationMethod> <https://example.com/issuer/123#key-0> .\n";

        public static string Vc0PublicKey = "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP";
        public static string Vc0PrivateKey = "zrv3kJcnBP1RpYmvNZ9jcYpKBZg41iSobWxSg3ix2U7Cp59kjwQFCT4SZTgLSL3HP8iGMdJs3nedjqYgNn6ZJmsmjRm";
        public static string Vc0ProofValue = "z5SpZtDGGz5a89PJbQT2sgbRUiyyAGhhgjcf86aJHfYcfvPjxn6vej5na6kUzmw1jMAR9PJU9mowshQFFdGmDN14D";
    }
}
