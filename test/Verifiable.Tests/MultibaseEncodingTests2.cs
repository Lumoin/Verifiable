using SimpleBase;
using System.Buffers;
using System.Buffers.Text;
using Verifiable.Core;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;

namespace Verifiable.Tests
{
    /// <summary>
    /// Delegate for encoding binary data to a string representation.
    /// </summary>
    /// <param name="data">The binary data to encode.</param>
    /// <returns>The encoded string representation.</returns>
    public delegate string EncoderDelegate(ReadOnlySpan<byte> data);

    /// <summary>
    /// Delegate for decoding character data to binary using a Try-pattern.
    /// </summary>
    /// <param name="source">The encoded character data to decode.</param>
    /// <param name="destination">The destination buffer for decoded bytes.</param>
    /// <param name="bytesWritten">The number of bytes written to the destination.</param>
    /// <returns>True if decoding succeeded; otherwise, false.</returns>
    public delegate bool TryDecodeDelegate(ReadOnlySpan<char> source, Span<byte> destination, out int bytesWritten);

    /// <summary>
    /// Provides multibase encoding and decoding operations with efficient memory usage.
    /// </summary>
    public static class MultibaseSerializer2
    {
        //Threshold for using stack allocation versus memory pool.
        private const int StackAllocationThreshold = 256;

        /// <summary>
        /// Encodes data with the specified codec header and multibase prefix.
        /// </summary>
        /// <param name="data">The raw data to encode.</param>
        /// <param name="codecHeader">The multicodec header to prepend to the data before encoding.</param>
        /// <param name="multibasePrefix">The multibase prefix character from <see cref="MultibaseAlgorithms"/>.</param>
        /// <param name="encoder">The encoder delegate that performs the actual encoding.</param>
        /// <param name="pool">The memory pool to use for temporary character allocations.</param>
        /// <returns>The multibase encoded string with the specified prefix.</returns>
        /// <remarks>
        /// This method combines the codec header with the data, encodes the combined bytes,
        /// and prepends the multibase prefix character to create the final encoded string.
        /// </remarks>
        public static string Encode(ReadOnlySpan<byte> data, ReadOnlySpan<byte> codecHeader, char multibasePrefix, EncoderDelegate encoder, MemoryPool<byte> pool)
        {
            //Calculate the total length of the combined data.
            int totalLength = codecHeader.Length + data.Length;

            //Choose allocation strategy based on size.
            if(totalLength <= StackAllocationThreshold)
            {
                //Small buffer path: use stack allocation for better performance.
                Span<byte> stackBuffer = stackalloc byte[StackAllocationThreshold];
                var combinedData = stackBuffer.Slice(0, totalLength);

                //Combine codec header and data into the buffer.
                codecHeader.CopyTo(combinedData);
                data.CopyTo(combinedData.Slice(codecHeader.Length));

                //Encode the combined data.
                string encodedPayload = encoder(combinedData);

                //Create the final string with the multibase prefix.
                return string.Create(encodedPayload.Length + 1, encodedPayload, (span, state) =>
                {
                    span[0] = multibasePrefix;
                    state.AsSpan().CopyTo(span.Slice(1));
                });
            }
            else
            {
                //Large buffer path: rent from the memory pool.
                IMemoryOwner<byte> rentedBuffer = pool.Rent(totalLength);
                try
                {
                    var combinedData = rentedBuffer.Memory.Span.Slice(0, totalLength);

                    //Combine codec header and data into the rented buffer.
                    codecHeader.CopyTo(combinedData);
                    data.CopyTo(combinedData.Slice(codecHeader.Length));

                    //Encode the combined data.
                    string encodedPayload = encoder(combinedData);

                    //Create the final string with the multibase prefix.
                    return string.Create(encodedPayload.Length + 1, encodedPayload, (span, state) =>
                    {
                        span[0] = multibasePrefix;
                        state.AsSpan().CopyTo(span.Slice(1));
                    });
                }
                finally
                {
                    //Always return the rented buffer to the pool.
                    rentedBuffer.Dispose();
                }
            }
        }


        /// <summary>
        /// Convenience overload that uses the default sensitive memory pool.
        /// </summary>
        /// <param name="data">The raw data to encode.</param>
        /// <param name="codecHeader">The multicodec header to prepend to the data before encoding.</param>
        /// <param name="multibasePrefix">The multibase prefix character from <see cref="MultibaseAlgorithms"/>.</param>
        /// <param name="encoder">The encoder delegate that performs the actual encoding.</param>
        /// <returns>The multibase encoded string with the specified prefix.</returns>
        public static string Encode(ReadOnlySpan<byte> data, ReadOnlySpan<byte> codecHeader, char multibasePrefix, EncoderDelegate encoder)
        {
            return Encode(data, codecHeader, multibasePrefix, encoder, SensitiveMemoryPool<byte>.Shared);
        }


        /// <summary>
        /// Decodes a multibase encoded string and returns an owned memory buffer.
        /// </summary>
        /// <param name="encoded">The multibase encoded string to decode.</param>
        /// <param name="codecHeaderLength">The length of the codec header to skip in the decoded data.</param>
        /// <param name="decoder">The decoder delegate that performs the actual decoding.</param>
        /// <param name="pool">The memory pool to use for allocating the result buffer.</param>
        /// <returns>An owned memory buffer containing the decoded data without the codec header.</returns>
        /// <exception cref="FormatException">Thrown when the input format is invalid or decoding fails.</exception>
        /// <remarks>
        /// This method removes the multibase prefix, decodes the remaining data,
        /// and then removes the codec header from the decoded bytes.
        /// </remarks>
        public static IMemoryOwner<byte> Decode(ReadOnlySpan<char> encoded, int codecHeaderLength, TryDecodeDelegate decoder, MemoryPool<byte> pool)
        {
            //Validate input length and multibase prefix.
            if(encoded.Length < 2 || encoded[0] != MultibaseAlgorithms.Base58Btc)
            {
                throw new FormatException("Input must start with 'z' for base58btc encoding.");
            }

            //Remove the multibase prefix to get the encoded payload.
            var encodedPayload = encoded.Slice(1);

            //Calculate the maximum possible decoded size.
            int maxDecodedSize = Base58.Bitcoin.GetSafeByteCountForDecoding(encodedPayload);

            //Rent a temporary buffer for decoding.
            var temporaryBuffer = pool.Rent(maxDecodedSize);

            try
            {
                //Attempt to decode into the temporary buffer.
                if(!decoder(encodedPayload, temporaryBuffer.Memory.Span, out int bytesWritten))
                {
                    throw new FormatException("Decoding failed.");
                }

                //Calculate the size of the result after removing the codec header.
                int resultLength = bytesWritten - codecHeaderLength;
                if(resultLength < 0)
                {
                    throw new FormatException($"Codec header length ({codecHeaderLength}) exceeds decoded data length ({bytesWritten}).");
                }

                //Rent a right-sized buffer for the final result.
                var resultBuffer = pool.Rent(resultLength);

                //Copy the decoded data without the codec header.
                temporaryBuffer.Memory.Span.Slice(codecHeaderLength, resultLength).CopyTo(resultBuffer.Memory.Span);

                return resultBuffer;
            }
            finally
            {
                //Always dispose the temporary buffer.
                temporaryBuffer.Dispose();
            }
        }


        /// <summary>
        /// Convenience overload that uses the default sensitive memory pool.
        /// </summary>
        /// <param name="encoded">The multibase encoded string to decode.</param>
        /// <param name="codecHeaderLength">The length of the codec header to skip in the decoded data.</param>
        /// <param name="decoder">The decoder delegate that performs the actual decoding.</param>
        /// <returns>An owned memory buffer containing the decoded data without the codec header.</returns>
        public static IMemoryOwner<byte> Decode(ReadOnlySpan<char> encoded, int codecHeaderLength, TryDecodeDelegate decoder)
        {
            return Decode(encoded, codecHeaderLength, decoder, SensitiveMemoryPool<byte>.Shared);
        }


        /// <summary>
        /// Encodes a cryptographic key with the appropriate codec header for the specified algorithm.
        /// </summary>
        /// <param name="keyData">The raw key data to encode.</param>
        /// <param name="algorithm">The cryptographic algorithm of the key.</param>
        /// <param name="encoder">The encoder delegate to use for encoding.</param>
        /// <returns>The multibase encoded key string with base58btc prefix.</returns>
        /// <exception cref="ArgumentException">Thrown when the algorithm is not supported.</exception>
        public static string EncodeKey(ReadOnlySpan<byte> keyData, CryptoAlgorithm algorithm, EncoderDelegate encoder)
        {
            //Select the appropriate multicodec header based on the algorithm.
            ReadOnlySpan<byte> codecHeader = algorithm switch
            {
                CryptoAlgorithm a when a.Equals(CryptoAlgorithm.Secp256k1) => MulticodecHeaders.Secp256k1PublicKey,
                CryptoAlgorithm a when a.Equals(CryptoAlgorithm.Ed25519) => MulticodecHeaders.Ed25519PublicKey,
                CryptoAlgorithm a when a.Equals(CryptoAlgorithm.P256) => MulticodecHeaders.P256PublicKey,
                CryptoAlgorithm a when a.Equals(CryptoAlgorithm.P384) => MulticodecHeaders.P384PublicKey,
                CryptoAlgorithm a when a.Equals(CryptoAlgorithm.P521) => MulticodecHeaders.P521PublicKey,
                CryptoAlgorithm a when a.Equals(CryptoAlgorithm.X25519) => MulticodecHeaders.X25519PublicKey,
                CryptoAlgorithm a when a.Equals(CryptoAlgorithm.Rsa2048) => MulticodecHeaders.RsaPublicKey,
                CryptoAlgorithm a when a.Equals(CryptoAlgorithm.Rsa4096) => MulticodecHeaders.RsaPublicKey,
                _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}")
            };


            //Encode with base58btc multibase prefix.
            return Encode(keyData, codecHeader, MultibaseAlgorithms.Base58Btc, encoder);
        }


        /// <summary>
        /// Decodes a multibase encoded key and automatically detects the algorithm type.
        /// </summary>
        /// <param name="encoded">The multibase encoded key string.</param>
        /// <param name="decoder">The decoder delegate to use for decoding.</param>
        /// <returns>A tuple containing the decoded key data and the detected algorithm.</returns>
        /// <exception cref="ArgumentException">Thrown when the key type cannot be detected.</exception>
        public static (IMemoryOwner<byte> keyData, CryptoAlgorithm algorithm) DecodeKey(ReadOnlySpan<char> encoded, TryDecodeDelegate decoder)
        {
            //Validate that this is a base58btc encoded string.
            if(encoded.Length < 2 || encoded[0] != MultibaseAlgorithms.Base58Btc)
            {
                throw new ArgumentException("Not a valid base58btc multibase string.");
            }

            //Detect the algorithm based on the encoded header prefix.
            CryptoAlgorithm detectedAlgorithm = encoded switch
            {
                _ when encoded.StartsWith(Base58BtcEncodedMulticodecHeaders.Secp256k1PublicKey, StringComparison.Ordinal) => CryptoAlgorithm.Secp256k1,
                _ when encoded.StartsWith(Base58BtcEncodedMulticodecHeaders.Ed25519PublicKey, StringComparison.Ordinal) => CryptoAlgorithm.Ed25519,
                _ when encoded.StartsWith(Base58BtcEncodedMulticodecHeaders.P256PublicKey, StringComparison.Ordinal) => CryptoAlgorithm.P256,
                _ when encoded.StartsWith(Base58BtcEncodedMulticodecHeaders.P384PublicKey, StringComparison.Ordinal) => CryptoAlgorithm.P384,
                _ when encoded.StartsWith(Base58BtcEncodedMulticodecHeaders.P521PublicKey, StringComparison.Ordinal) => CryptoAlgorithm.P521,
                _ when encoded.StartsWith(Base58BtcEncodedMulticodecHeaders.X25519PublicKey, StringComparison.Ordinal) => CryptoAlgorithm.X25519,
                _ when encoded.StartsWith(Base58BtcEncodedMulticodecHeaders.RsaPublicKey2048, StringComparison.Ordinal) => CryptoAlgorithm.Rsa2048,
                _ when encoded.StartsWith(Base58BtcEncodedMulticodecHeaders.RsaPublicKey4096, StringComparison.Ordinal) => CryptoAlgorithm.Rsa4096,
                _ => throw new ArgumentException("Unknown key type in encoded data.")
            };

            //Decode the key data, removing the standard 2-byte codec header.
            var decodedKeyData = Decode(encoded, codecHeaderLength: 2, decoder);

            return (decodedKeyData, detectedAlgorithm);
        }


        /// <summary>
        /// Encodes data for JWK format without any codec header or multibase prefix.
        /// </summary>
        /// <param name="data">The raw data to encode.</param>
        /// <param name="encoder">The encoder delegate to use for encoding.</param>
        /// <returns>The encoded string without any prefix or header.</returns>
        /// <remarks>
        /// JWK format uses raw base64url encoding without multibase prefixes.
        /// </remarks>
        public static string EncodeForJwk(ReadOnlySpan<byte> data, EncoderDelegate encoder)
        {
            //JWK uses raw encoding without any prefix or header.
            return encoder(data);
        }


        /// <summary>
        /// Decodes data from JWK format without any multibase prefix or codec header.
        /// </summary>
        /// <param name="encoded">The base64url encoded string.</param>
        /// <param name="decoder">The decoder delegate to use for decoding.</param>
        /// <returns>An owned memory buffer containing the decoded data.</returns>
        /// <exception cref="FormatException">Thrown when decoding fails.</exception>
        public static IMemoryOwner<byte> DecodeFromJwk(ReadOnlySpan<char> encoded, TryDecodeDelegate decoder)
        {
            //Calculate the maximum possible decoded size for base64url.
            int maxDecodedSize = Base64Url.GetMaxDecodedLength(encoded.Length);

            //Rent a temporary buffer for decoding.
            var temporaryBuffer = SensitiveMemoryPool<byte>.Shared.Rent(maxDecodedSize);
            try
            {
                //Attempt to decode the base64url data.
                if(!decoder(encoded, temporaryBuffer.Memory.Span, out int bytesWritten))
                {
                    throw new FormatException("JWK decoding failed.");
                }

                //Rent a right-sized buffer for the result.
                var resultBuffer = SensitiveMemoryPool<byte>.Shared.Rent(bytesWritten);

                //Copy the decoded data to the result buffer.
                temporaryBuffer.Memory.Span.Slice(0, bytesWritten).CopyTo(resultBuffer.Memory.Span);

                return resultBuffer;
            }
            finally
            {
                //Always dispose the temporary buffer.
                temporaryBuffer.Dispose();
            }
        }
    }


    /// <summary>
    /// Tests for the MultibaseSerializer2 implementation.
    /// </summary>
    [TestClass]
    public sealed class MultibaseSerializer2Tests
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
            var decodedWithHeader = MultibaseSerializer2.Decode(
                originalEncodedKey,
                codecHeaderLength: 0,  //Keep the codec header in the result.
                Base58.Bitcoin.TryDecode,
                SensitiveMemoryPool<byte>.Shared);

            //Extract just the key data by skipping the 2-byte codec header.
            byte[] keyDataOnly = decodedWithHeader.Memory.Span.Slice(2).ToArray();
            decodedWithHeader.Dispose();

            //Re-encode the key data with the appropriate codec header.
            string reencodedKey = MultibaseSerializer2.Encode(
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
            var (decodedKeyData, detectedAlgorithm) = MultibaseSerializer2.DecodeKey(originalEncodedKey, Base58.Bitcoin.TryDecode);

            //Verify the algorithm was correctly detected from the 'zQ3s' prefix.
            Assert.AreEqual(CryptoAlgorithm.Secp256k1, detectedAlgorithm, "Should detect Secp256k1 from the encoded prefix.");

            //Re-encode using the detected algorithm.
            string reencodedKey = MultibaseSerializer2.EncodeKey(decodedKeyData.Memory.Span, detectedAlgorithm, Base58.Bitcoin.Encode);

            //Clean up the memory.
            decodedKeyData.Dispose();

            //The re-encoded result should match the original.
            Assert.AreEqual(originalEncodedKey, reencodedKey,
                "High-level API should produce identical round-trip results.");
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
            string jwkEncoded = MultibaseSerializer2.EncodeForJwk(originalData, Base64Url.EncodeToString);

            //Verify no multibase prefix is present.
            Assert.IsFalse(jwkEncoded.StartsWith("u", StringComparison.Ordinal), "JWK encoding should not include multibase prefix.");

            //Decode the JWK data.
            var decodedData = MultibaseSerializer2.DecodeFromJwk(jwkEncoded, Base64Url.TryDecodeFromChars);

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
                var (decodedData, detectedAlgorithm) = MultibaseSerializer2.DecodeKey(encodedKey, Base58.Bitcoin.TryDecode);

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
            var (decodedData, detectedAlgorithm) = MultibaseSerializer2.DecodeKey(knownEncodedKey, Base58.Bitcoin.TryDecode);

            //Extract the key data for re-encoding.
            byte[] keyData = decodedData.Memory.Span.ToArray();
            decodedData.Dispose();

            //Re-encode using the convenience overload.
            string reencodedKey = MultibaseSerializer2.EncodeKey(keyData, detectedAlgorithm, Base58.Bitcoin.Encode);

            //The re-encoded key should match the original.
            Assert.AreEqual(knownEncodedKey, reencodedKey, "Convenience overloads should produce identical results.");

            //Verify round-trip by decoding again.
            var (decodedAgain, algorithmAgain) = MultibaseSerializer2.DecodeKey(reencodedKey, Base58.Bitcoin.TryDecode);

            //Verify the data and algorithm are preserved.
            Assert.IsTrue(keyData.AsSpan().SequenceEqual(decodedAgain.Memory.Span), "Round-trip should preserve key data.");
            Assert.AreEqual(detectedAlgorithm, algorithmAgain, "Round-trip should preserve algorithm detection.");

            //Clean up the memory.
            decodedAgain.Dispose();
        }
    }
}