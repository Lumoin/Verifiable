using System.Buffers;
using System.Buffers.Text;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography
{
    /// <summary>
    /// Delegate for encoding binary data to a string representation.
    /// </summary>
    /// <param name="data">The binary data to encode.</param>
    /// <returns>The encoded string representation.</returns>
    /// <remarks>
    /// This delegate matches common encoding method signatures like <see cref="Base58.Bitcoin.Encode"/>
    /// and <see cref="Base64Url.EncodeToString"/>, allowing them to be used directly.
    /// For better performance with large data, users can implement custom encoders using TryEncode patterns.
    /// <example>
    /// Direct usage with existing methods:
    /// <code>
    /// EncodeDelegate encoder = Base58.Bitcoin.Encode;
    /// string encoded = encoder(myData);
    /// </code>
    /// Custom implementation using TryEncode for better performance:
    /// <code>
    /// EncodeDelegate customEncoder = (ReadOnlySpan&lt;byte&gt; data) =>
    /// {
    ///     int bufferSize = Base58.Bitcoin.GetSafeCharCountForEncoding(data.Length);
    ///     Span&lt;char&gt; buffer = bufferSize &lt;= 1024 ? stackalloc char[bufferSize] : new char[bufferSize];
    ///     if(!Base58.Bitcoin.TryEncode(data, buffer, out int charsWritten))
    ///     {
    ///         throw new InvalidOperationException("Encoding failed");
    ///     }
    ///
    ///     return new string(buffer.Slice(0, charsWritten));
    /// };
    /// </code>
    /// </example>
    /// </remarks>
    public delegate string EncodeDelegate(ReadOnlySpan<byte> data);

    /// <summary>
    /// Delegate for decoding character data to binary using memory pool allocation.
    /// </summary>
    /// <param name="source">The encoded character data to decode.</param>
    /// <param name="pool">The memory pool to use for allocating the result buffer.</param>
    /// <returns>An owned memory buffer containing the decoded bytes.</returns>
    /// <remarks>
    /// This delegate requires implementations to handle buffer size calculation and allocation
    /// from the provided memory pool. The caller is responsible for disposing the returned
    /// <see cref="IMemoryOwner{T}"/> to return the buffer to the pool.
    /// Different encoding schemes require different size calculations, so this pattern allows
    /// each implementation to use the appropriate method.
    /// <example>
    /// Implementation for Base58 decoding:
    /// <code>
    /// DecodeDelegate base58Decoder = (ReadOnlySpan&lt;char&gt; source, MemoryPool&lt;byte&gt; pool) =>
    /// {
    ///     int maxSize = Base58.Bitcoin.GetSafeByteCountForDecoding(source.Length);
    ///     var buffer = pool.Rent(maxSize);
    ///     if(!Base58.Bitcoin.TryDecode(source, buffer.Memory.Span, out int bytesWritten))
    ///     {
    ///         buffer.Dispose();
    ///         throw new FormatException("Base58 decoding failed");
    ///     }
    ///
    ///     //Returning a right-sized buffer, important for cryptographic operations:
    ///     if(bytesWritten &lt; maxSize)
    ///     {
    ///         var rightSized = pool.Rent(bytesWritten);
    ///         buffer.Memory.Span.Slice(0, bytesWritten).CopyTo(rightSized.Memory.Span);
    ///         buffer.Dispose();
    ///         return rightSized;
    ///     }
    ///
    ///     return buffer;
    /// };
    /// </code>
    /// Implementation for Base64Url decoding:
    /// <code>
    /// DecodeDelegate base64Decoder = (ReadOnlySpan&lt;char&gt; source, MemoryPool&lt;byte&gt; pool) =>
    /// {
    ///     int maxSize = Base64Url.GetMaxDecodedLength(source.Length);
    ///     var buffer = pool.Rent(maxSize);
    ///     if(!Base64Url.TryDecodeFromChars(source, buffer.Memory.Span, out int bytesWritten))
    ///     {
    ///         buffer.Dispose();
    ///         throw new FormatException("Base64Url decoding failed");
    ///     }
    ///
    ///     return buffer;
    /// };
    /// </code>
    /// </example>
    /// </remarks>
    public delegate IMemoryOwner<byte> DecodeDelegate(ReadOnlySpan<char> source, MemoryPool<byte> pool);


    /// <summary>
    /// Delegate for simple decoding that returns a byte array.
    /// </summary>
    /// <param name="source">The encoded character data to decode.</param>
    /// <returns>The decoded byte array.</returns>
    public delegate byte[] SimpleDecodeDelegate(ReadOnlySpan<char> source);


    /// <summary>
    /// Provides multibase encoding and decoding operations with efficient memory usage.
    /// </summary>
    public static class MultibaseSerializer
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
        public static string Encode(ReadOnlySpan<byte> data, ReadOnlySpan<byte> codecHeader, char multibasePrefix, EncodeDelegate encoder, MemoryPool<byte> pool)
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
        public static string Encode(ReadOnlySpan<byte> data, ReadOnlySpan<byte> codecHeader, char multibasePrefix, EncodeDelegate encoder)
        {
            return Encode(data, codecHeader, multibasePrefix, encoder, SensitiveMemoryPool<byte>.Shared);
        }


        /// <summary>
        /// Encodes a cryptographic key with the appropriate codec header for the specified algorithm.
        /// </summary>
        /// <param name="keyData">The raw key data to encode.</param>
        /// <param name="algorithm">The cryptographic algorithm of the key.</param>
        /// <param name="encoder">The encoder delegate to use for encoding.</param>
        /// <returns>The multibase encoded key string with base58btc prefix.</returns>
        /// <exception cref="ArgumentException">Thrown when the algorithm is not supported.</exception>
        public static string EncodeKey(ReadOnlySpan<byte> keyData, CryptoAlgorithm algorithm, EncodeDelegate encoder)
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
        /// Encodes data for JWK format without any codec header or multibase prefix.
        /// </summary>
        /// <param name="data">The raw data to encode.</param>
        /// <param name="encoder">The encoder delegate to use for encoding.</param>
        /// <returns>The encoded string without any prefix or header.</returns>
        /// <remarks>
        /// JWK format uses raw base64url encoding without multibase prefixes.
        /// </remarks>
        public static string EncodeForJwk(ReadOnlySpan<byte> data, EncodeDelegate encoder)
        {
            //JWK uses raw encoding without any prefix or header.
            return encoder(data);
        }


        /// <summary>
        /// Convenience overload that uses the default sensitive memory pool.
        /// </summary>
        /// <param name="encoded">The multibase encoded string to decode.</param>
        /// <param name="codecHeaderLength">The length of the codec header to skip in the decoded data.</param>
        /// <param name="decoder">The decoder delegate that performs the actual decoding.</param>
        /// <returns>An owned memory buffer containing the decoded data without the codec header.</returns>
        public static IMemoryOwner<byte> Decode(ReadOnlySpan<char> encoded, int codecHeaderLength, DecodeDelegate decoder)
        {
            return Decode(encoded, codecHeaderLength, decoder, SensitiveMemoryPool<byte>.Shared);
        }


        /// <summary>
        /// Convenience overload that accepts a simple decode function and memory pool.
        /// </summary>
        /// <param name="encoded">The multibase encoded string to decode.</param>
        /// <param name="codecHeaderLength">The length of the codec header to skip in the decoded data.</param>
        /// <param name="simpleDecoder">A simple decoder that returns a byte array.</param>
        /// <param name="pool">The memory pool to use for allocating the result buffer.</param>
        /// <returns>An owned memory buffer containing the decoded data without the codec header.</returns>
        public static IMemoryOwner<byte> Decode(ReadOnlySpan<char> encoded, int codecHeaderLength, SimpleDecodeDelegate simpleDecoder, MemoryPool<byte> pool)
        {
            //Create a DecodeDelegate wrapper that uses the provided pool.
            IMemoryOwner<byte> decoder(ReadOnlySpan<char> source, MemoryPool<byte> decoderPool)
            {
                byte[] decoded = simpleDecoder(source);
                var buffer = decoderPool.Rent(decoded.Length);
                decoded.CopyTo(buffer.Memory.Span);

                return buffer;
            }

            return Decode(encoded, codecHeaderLength, decoder, pool);
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
        public static IMemoryOwner<byte> Decode(ReadOnlySpan<char> encoded, int codecHeaderLength, DecodeDelegate decoder, MemoryPool<byte> pool)
        {
            //Validate input length and multibase prefix.
            if(encoded.Length < 2 || encoded[0] != MultibaseAlgorithms.Base58Btc)
            {
                throw new FormatException("Input must start with 'z' for base58btc encoding.");
            }

            //Remove the multibase prefix to get the encoded payload.
            var encodedPayload = encoded.Slice(1);

            //Let the decoder handle its own size calculation and decoding.
            var decodedBuffer = decoder(encodedPayload, pool);

            try
            {
                //Check if we have enough data after removing the codec header.
                if(decodedBuffer.Memory.Length < codecHeaderLength)
                {
                    throw new FormatException($"Codec header length ({codecHeaderLength}) exceeds decoded data length ({decodedBuffer.Memory.Length}).");
                }

                //Calculate the size of the result after removing the codec header.
                int resultLength = decodedBuffer.Memory.Length - codecHeaderLength;

                //Rent a right-sized buffer for the final result.
                var resultBuffer = pool.Rent(resultLength);

                //Copy the decoded data without the codec header.
                decodedBuffer.Memory.Span.Slice(codecHeaderLength, resultLength).CopyTo(resultBuffer.Memory.Span);

                return resultBuffer;
            }
            finally
            {
                //Always dispose the decoded buffer.
                decodedBuffer.Dispose();
            }
        }


        /// <summary>
        /// Decodes a multibase encoded key and automatically detects the algorithm type.
        /// </summary>
        /// <param name="encoded">The multibase encoded key string.</param>
        /// <param name="simpleDecoder">A simple decoder that returns a byte array.</param>
        /// <param name="pool">The memory pool to use for allocating the result buffer.</param>
        /// <returns>A tuple containing the decoded key data and the detected algorithm.</returns>
        /// <exception cref="ArgumentException">Thrown when the key type cannot be detected.</exception>
        public static (IMemoryOwner<byte> keyData, CryptoAlgorithm algorithm) DecodeKey(ReadOnlySpan<char> encoded, SimpleDecodeDelegate simpleDecoder, MemoryPool<byte> pool)
        {
            //Create a DecodeDelegate wrapper.
            IMemoryOwner<byte> decoder(ReadOnlySpan<char> source, MemoryPool<byte> decoderPool)
            {
                byte[] decoded = simpleDecoder(source);
                var buffer = decoderPool.Rent(decoded.Length);
                decoded.CopyTo(buffer.Memory.Span);
                return buffer;
            }

            //Call the main DecodeKey overload.
            return DecodeKey(encoded, decoder, pool);
        }


        /// <summary>
        /// Decodes a multibase encoded key and automatically detects the algorithm type.
        /// </summary>
        /// <param name="encoded">The multibase encoded key string.</param>
        /// <param name="decoder">The decoder delegate to use for decoding.</param>
        /// <param name="pool">The memory pool to use for allocating the result buffer.</param>
        /// <returns>A tuple containing the decoded key data and the detected algorithm.</returns>
        /// <exception cref="ArgumentException">Thrown when the key type cannot be detected.</exception>
        public static (IMemoryOwner<byte> keyData, CryptoAlgorithm algorithm) DecodeKey(ReadOnlySpan<char> encoded, DecodeDelegate decoder, MemoryPool<byte> pool)
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
            var decodedKeyData = Decode(encoded, codecHeaderLength: 2, decoder, pool);

            return (decodedKeyData, detectedAlgorithm);
        }


        /// <summary>
        /// Decodes data from JWK format without any multibase prefix or codec header.
        /// </summary>
        /// <param name="encoded">The base64url encoded string.</param>
        /// <param name="simpleDecoder">A simple decoder that returns a byte array.</param>
        /// <param name="pool">The memory pool to use for allocating the result buffer.</param>
        /// <returns>An owned memory buffer containing the decoded data.</returns>
        /// <exception cref="FormatException">Thrown when decoding fails.</exception>
        public static IMemoryOwner<byte> DecodeFromJwk(ReadOnlySpan<char> encoded, SimpleDecodeDelegate simpleDecoder, MemoryPool<byte> pool)
        {
            //For JWK, we don't have a multibase prefix or codec header.
            //Just decode directly using the simple decoder.
            byte[] decoded = simpleDecoder(encoded);
            var buffer = pool.Rent(decoded.Length);
            decoded.CopyTo(buffer.Memory.Span);

            return buffer;
        }
    }
}
