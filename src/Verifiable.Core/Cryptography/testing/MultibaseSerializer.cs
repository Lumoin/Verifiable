using System;
using System.Buffers;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Did;

namespace Verifiable.Core
{
    public delegate TResult[] ArrayDecodeDelegate<T, TResult>(ReadOnlySpan<char> data);

    public delegate IMemoryOwner<TResult> DecodeDelegate<T, TResult>(ReadOnlySpan<T> data, MemoryPool<TResult> memoryPool);
    public delegate IMemoryOwner<byte> BufferAllocationDecodeDelegate(ReadOnlySpan<char> data, int codecHeaderLength, MemoryPool<byte> resultMemoryPool);
    

    //TODO: There should be a version for BaseUrl.Encoding as well.
    public delegate string BufferAllocationEncodeDelegate(ReadOnlySpan<byte> data, ReadOnlySpan<byte> codecHeader, MemoryPool<char> pool);

    
    public static class MultibaseSerializer
    {       
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
            var pool = ExactSizeMemoryPool<char>.Shared;
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
