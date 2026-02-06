using SimpleBase;
using System.Buffers.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests for the MultibaseSerializer2 implementation.
    /// </summary>
    [TestClass]
    internal sealed class MultibaseSerializer2Tests
    {
        /// <summary>
        /// Tests that encoding and decoding with explicit memory pools produces the expected round-trip result.
        /// </summary>
        [TestMethod]
        public void EncodeDecodeWithMemoryPoolSucceeds()
        {
            //Known test vector from W3C specifications.
            const string originalEncodedKey = "zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2";

            //Decode the entire key including the codec header.
            var decodedWithHeader = MultibaseSerializer.Decode(
                originalEncodedKey,
                codecHeaderLength: 0,  //Keep the codec header in the result.
                Base58.Bitcoin.Decode,
                SensitiveMemoryPool<byte>.Shared);

            //Extract just the key data by skipping the 2-byte codec header.
            byte[] keyDataOnly = decodedWithHeader.Memory.Span.Slice(2).ToArray();
            decodedWithHeader.Dispose();

            //Re-encode the key data with the appropriate codec header.
            string reencodedKey = MultibaseSerializer.Encode(
                keyDataOnly,
                MulticodecHeaders.Secp256k1PublicKey,
                MultibaseAlgorithms.Base58Btc,  //Use 'z' prefix for base58btc.
                Base58.Bitcoin.Encode,
                SensitiveMemoryPool<byte>.Shared);

            //The re-encoded result should match the original.
            Assert.AreEqual(originalEncodedKey, reencodedKey, "Round-trip encoding should produce the original key.");
        }


        /// <summary>
        /// Tests the high-level API with automatic algorithm detection.
        /// </summary>
        [TestMethod]
        public void HighLevelApiWithAutoDetectionSucceeds()
        {
            //Known Secp256k1 test vector.
            const string originalEncodedKey = "zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2";

            //Decode with automatic algorithm detection.
            var (decodedKeyData, detectedAlgorithm) = MultibaseSerializer.DecodeKey(originalEncodedKey, Base58.Bitcoin.Decode, SensitiveMemoryPool<byte>.Shared);

            //Verify the algorithm was correctly detected from the 'zQ3s' prefix.
            Assert.AreEqual(CryptoAlgorithm.Secp256k1, detectedAlgorithm, "Should detect Secp256k1 from the encoded prefix.");

            //Re-encode using the detected algorithm.
            string reencodedKey = MultibaseSerializer.EncodeKey(decodedKeyData.Memory.Span, detectedAlgorithm, Base58.Bitcoin.Encode);

            //Clean up the memory.
            decodedKeyData.Dispose();

            //The re-encoded result should match the original.
            Assert.AreEqual(originalEncodedKey, reencodedKey, "High-level API should produce identical round-trip results.");
        }


        /// <summary>
        /// Tests JWK encoding and decoding without multibase prefixes.
        /// </summary>
        [TestMethod]
        public void JwkEncodingWithoutPrefixSucceeds()
        {
            //Test data for JWK encoding.
            byte[] originalData = { 1, 2, 3, 4, 5, 6, 7, 8 };

            //Encode for JWK format (no prefix, no codec header).
            string jwkEncoded = MultibaseSerializer.EncodeForJwk(originalData, Base64Url.EncodeToString);

            //Verify no multibase prefix is present.
            Assert.DoesNotStartWith("u", jwkEncoded, "JWK encoding should not include multibase prefix.");

            //Decode the JWK data.
            var decodedData = MultibaseSerializer.DecodeFromJwk(jwkEncoded, Base64Url.DecodeFromChars, SensitiveMemoryPool<byte>.Shared);

            //Verify the decoded data matches the original.
            Assert.IsTrue(decodedData.Memory.Span.SequenceEqual(originalData), "JWK round-trip should preserve data integrity.");

            //Clean up the memory.
            decodedData.Dispose();
        }


        /// <summary>
        /// Tests algorithm detection for various key types based on their encoded prefixes.
        /// </summary>
        [TestMethod]
        public void AlgorithmDetectionForVariousKeyTypesSucceeds()
        {
            //Test vectors for different key types with their expected algorithms.
            var testCases = new[]
            {
                    ("zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2", CryptoAlgorithm.Secp256k1),
                    ("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", CryptoAlgorithm.Ed25519),
                    ("zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169", CryptoAlgorithm.P256),
                };

            foreach(var (encodedKey, expectedAlgorithm) in testCases)
            {
                //Decode and detect the algorithm.
                var (decodedData, detectedAlgorithm) = MultibaseSerializer.DecodeKey(encodedKey, Base58.Bitcoin.Decode, SensitiveMemoryPool<byte>.Shared);

                //Clean up the memory.
                decodedData.Dispose();

                //Verify the algorithm was correctly detected.
                Assert.AreEqual(expectedAlgorithm, detectedAlgorithm, $"Should correctly detect {expectedAlgorithm} from encoded prefix.");
            }
        }


        /// <summary>
        /// Tests that convenience overloads using shared memory pools work correctly.
        /// </summary>
        [TestMethod]
        public void ConvenienceOverloadsUseSharedPoolsSucceeds()
        {
            //Known Ed25519 test vector.
            const string knownEncodedKey = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

            //Decode using the convenience overload (uses shared pool).
            var (decodedData, detectedAlgorithm) = MultibaseSerializer.DecodeKey(knownEncodedKey, Base58.Bitcoin.Decode, SensitiveMemoryPool<byte>.Shared);

            //Extract the key data for re-encoding.
            byte[] keyData = decodedData.Memory.Span.ToArray();
            decodedData.Dispose();

            //Re-encode using the convenience overload.
            string reencodedKey = MultibaseSerializer.EncodeKey(keyData, detectedAlgorithm, Base58.Bitcoin.Encode);

            //The re-encoded key should match the original.
            Assert.AreEqual(knownEncodedKey, reencodedKey, "Convenience overloads should produce identical results.");

            //Verify round-trip by decoding again.
            var (decodedAgain, algorithmAgain) = MultibaseSerializer.DecodeKey(reencodedKey, Base58.Bitcoin.Decode, SensitiveMemoryPool<byte>.Shared);

            //Verify the data and algorithm are preserved.
            Assert.IsTrue(keyData.AsSpan().SequenceEqual(decodedAgain.Memory.Span), "Round-trip should preserve key data.");
            Assert.AreEqual(detectedAlgorithm, algorithmAgain, "Round-trip should preserve algorithm detection.");

            //Clean up the memory.
            decodedAgain.Dispose();
        }
    }
}