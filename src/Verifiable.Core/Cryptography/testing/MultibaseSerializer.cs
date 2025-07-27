using SimpleBase;
using System;
using System.Buffers;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Did;

namespace Verifiable.Core
{
    /// <summary>
    /// Delegate for encoding data with support for multibase prefix allocation.
    /// This improved version allows the encoder to allocate space for a prefix character
    /// that will be written by the caller before the string is created.
    /// </summary>
    /// <param name="data">The data to encode.</param>
    /// <param name="prefixHeader">The codec header to prepend to the data before encoding.</param>
    /// <param name="reservePrefixSpace">If true, reserves one character at the beginning for a multibase prefix.</param>
    /// <param name="allocationPool">The memory pool for temporary allocations.</param>
    /// <param name="prefixWriter">Action to write the prefix character at position 0 of the buffer before string creation.</param>
    /// <returns>The encoded string, potentially with a reserved prefix character written by prefixWriter.</returns>
    public delegate string BufferAllocationEncodeDelegate2(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> prefixHeader,
        bool reservePrefixSpace,
        MemoryPool<char> allocationPool,
        Action<Span<char>> prefixWriter);



    public delegate TResult[] ArrayDecodeDelegate<T, TResult>(ReadOnlySpan<char> data);

    public delegate IMemoryOwner<TResult> DecodeDelegate<T, TResult>(ReadOnlySpan<T> data, MemoryPool<TResult> memoryPool);
    public delegate IMemoryOwner<byte> BufferAllocationDecodeDelegate(ReadOnlySpan<char> data, int codecHeaderLength, MemoryPool<byte> resultMemoryPool);




    //TODO: There should be a version for BaseUrl.Encoding as well.
    public delegate string BufferAllocationEncodeDelegate(ReadOnlySpan<byte> data, ReadOnlySpan<byte> codecHeader, MemoryPool<char> pool);


    public static class MultibaseSerializer
    {
        /// <summary>
        /// Base58 encoder that supports optional prefix space reservation.
        /// </summary>
        /// <remarks>
        /// This encoder demonstrates the key insight: strings in C# are immutable, so any prefix
        /// must be written to the character buffer BEFORE the string is created. The prefixWriter
        /// callback allows the caller to write the prefix character at the correct position.
        /// </remarks>
        public static BufferAllocationEncodeDelegate2 StackBase58EncoderV2 { get; } = (data, codecHeader, reservePrefixSpace, pool, prefixWriter) =>
        {
            //Combine codec header and data.
            int bufferLengthForDataToBeEncoded = codecHeader.Length + data.Length;
            Span<byte> dataWithEncodingHeaders = stackalloc byte[bufferLengthForDataToBeEncoded];

            codecHeader.CopyTo(dataWithEncodingHeaders);
            data.CopyTo(dataWithEncodingHeaders.Slice(codecHeader.Length));

            //Calculate the size needed for base58 encoding.
            int base58Size = Base58.Bitcoin.GetSafeCharCountForEncoding(dataWithEncodingHeaders);

            //Allocate buffer with optional extra space for prefix.
            int prefixOffset = reservePrefixSpace ? 1 : 0;
            int totalBufferSize = base58Size + prefixOffset;
            Span<char> buffer = totalBufferSize <= 512 ? stackalloc char[totalBufferSize] : pool.Rent(totalBufferSize).Memory.Span;

            //Encode the data, starting after the prefix position if space was reserved.
            if(!Base58.Bitcoin.TryEncode(dataWithEncodingHeaders, buffer.Slice(prefixOffset), out int bytesWritten))
            {
                throw new Exception("Encoding failed.");
            }

            //If prefix space was reserved, let the caller write the prefix.
            //This MUST happen before string creation due to string immutability.
            if(reservePrefixSpace && prefixWriter != null)
            {
                prefixWriter(buffer);
            }

            //Create and return the final immutable string.
            return new string(buffer.Slice(0, bytesWritten + prefixOffset));
        };


        public static IMemoryOwner<byte> Decode(ReadOnlySpan<char> data, MemoryPool<byte> resultMemoryPool, ArrayDecodeDelegate<char, byte> arrayDecoder)
        {
            //This just forwards the call to buffer delegate call.
            IMemoryOwner<byte> bufferAllocatorDecoder(ReadOnlySpan<char> inputData, int startIndex, MemoryPool<byte> memoryPool)
            {
                byte[] decodedArray = arrayDecoder(inputData);
                var actualBufferLength = decodedArray.Length - startIndex;
                var output = memoryPool.Rent(actualBufferLength);
                decodedArray.AsSpan(startIndex, actualBufferLength).CopyTo(output.Memory.Span);

                return output;
            }

            return Decode(data, resultMemoryPool, bufferAllocatorDecoder);
        }



        public static IMemoryOwner<byte> Decode(ReadOnlySpan<char> data, MemoryPool<byte> resultMemoryPool, BufferAllocationDecodeDelegate decoder)
        {
            if(data.Length == 0)
            {
                throw new ArgumentException("Encoded input cannot be empty.");
            }

            if(!data[0].Equals(MultibaseAlgorithms.Base58Btc))
            {
                throw new ArgumentException("Encoded input does not start with 'z', which is required for multibase 'z' encoding.");
            }

            //All acceptable codecs have a header length of 2 bytes in the Multicodec format. Here it is assumed there is 'z'
            //in front to denote multicodec encoding and that is stripped of.
            const int CodecHeaderLength = 2;
            var decodedBytes = decoder(data.Slice(1), CodecHeaderLength, resultMemoryPool);

            return decodedBytes;
        }


        public static IMemoryOwner<byte> Decode(ReadOnlySpan<char> data, MemoryPool<byte> resultMemoryPool, BufferAllocationDecodeDelegate decoder, int codecHeaderLength = 2)
        {
            if(data.Length == 0)
            {
                throw new ArgumentException("Encoded input cannot be empty.");
            }

            if(!data[0].Equals(MultibaseAlgorithms.Base58Btc))
            {
                throw new ArgumentException("Encoded input does not start with 'z', which is required for multibase 'z' encoding.");
            }

            //Here the 'z' is removed before doing further decoding.
            var decodedBytes = decoder(data.Slice(1), codecHeaderLength, resultMemoryPool);

            return decodedBytes;
        }


        public static IMemoryOwner<byte> DecodeWithMultibaseHeader(ReadOnlySpan<char> data, MemoryPool<byte> resultMemoryPool, BufferAllocationDecodeDelegate decoder)
        {
            //Having codeHeaderLength at 0 basically does not remove it and so consequently
            //it will be available for the caller.
            return Decode(data, resultMemoryPool, decoder, codecHeaderLength: 0);
        }


        public static string Encode(ReadOnlySpan<byte> data, ReadOnlySpan<byte> codecHeader, char codecId, ReadOnlySpanFunc<byte, string> arrayEncoder)
        {
            var pool = SensitiveMemoryPool<char>.Shared;
            int bufferLengthForDataToBeEncoded = codecHeader.Length + data.Length;
            Span<byte> dataWithEncodingHeaders = stackalloc byte[bufferLengthForDataToBeEncoded];

            codecHeader.CopyTo(dataWithEncodingHeaders);
            data.CopyTo(dataWithEncodingHeaders[codecHeader.Length..]);

            string bufferAllocatorEncoder(ReadOnlySpan<byte> inputData, ReadOnlySpan<byte> inputCodecHeader, MemoryPool<char> memoryPool)
            {
                string encodedString = arrayEncoder(inputData);
                return encodedString;
            }

            return Encode(dataWithEncodingHeaders, codecHeader, codecId, pool, bufferAllocatorEncoder);
        }


        public static string Encode(ReadOnlySpan<byte> data, ReadOnlySpan<byte> codecHeader, char multibasePrefix, MemoryPool<char> pool, BufferAllocationEncodeDelegate2 encoder)
        {
            return encoder(data, codecHeader, reservePrefixSpace: true, pool, prefixWriter: buffer => buffer[0] = multibasePrefix);
        }


        public static string Encode(ReadOnlySpan<byte> data, ReadOnlySpan<byte> codecHeader, char codecId, MemoryPool<char> pool, BufferAllocationEncodeDelegate encoder)
        {
            string encodedString = encoder(data, codecHeader, pool);
            return string.Create(encodedString.Length + 1, encodedString, (span, state) =>
            {
                span[0] = codecId;
                state.AsSpan().CopyTo(span[1..]);
            });
        }
    }
}
