using System;
using System.Buffers;
using Verifiable.Core.Cryptography;

namespace Verifiable.Core
{
    public delegate TResult[] ArrayDecodeDelegate<T, TResult>(ReadOnlySpan<char> data);

    public delegate IMemoryOwner<TResult> DecodeDelegate<T, TResult>(ReadOnlySpan<T> data, MemoryPool<TResult> memoryPool);
    public delegate IMemoryOwner<byte> BufferAllocationDecodeDelegate(ReadOnlySpan<char> data, int codecHeaderLength, MemoryPool<byte> resultMemoryPool);
    

    //TODO: There should be a version for BaseUrl.Encoding as well.
    public delegate string BufferAllocationEncodeDelegate(ReadOnlySpan<byte> data, ReadOnlySpan<byte> codecHeader, MemoryPool<char> pool);

    public delegate IMemoryOwner<TResult> MultibaseMatcherDelegate<T, TResult>(ReadOnlySpan<T> inputParam, MemoryPool<byte> resultMemoryPool, DecodeDelegate<char, byte> decoder);


    public static class MultibaseSerializer
    {
        public static MultibaseMatcherDelegate<char, byte> DefaultDecoderMatcher { get; set; } = (inputToDecode, memoryPool, decoder) =>
        {
            //TODO: There should probably be a second parameter, that being the corresponding MulticodecHeaders
            //for the string. This way the decoder function can do further logic, such as check the array length.
            IMemoryOwner<byte> result = null!;
            result = inputToDecode switch
            {
                var span when span.StartsWith(Base58BtcEncodedMulticodecHeaders.P256PublicKey) => decoder(span, memoryPool),
                var span when span.StartsWith(Base58BtcEncodedMulticodecHeaders.P384PublicKey) => decoder(span, memoryPool),
                var span when span.StartsWith(Base58BtcEncodedMulticodecHeaders.P521PublicKey) => decoder(span, memoryPool),
                var span when span.StartsWith(Base58BtcEncodedMulticodecHeaders.RsaPublicKey2048) => decoder(span, memoryPool),
                var span when span.StartsWith(Base58BtcEncodedMulticodecHeaders.RsaPublicKey4096) => decoder(span, memoryPool),
                var span when span.StartsWith(Base58BtcEncodedMulticodecHeaders.Secp256k1PublicKey) => decoder(span, memoryPool),
                var span when span.StartsWith(Base58BtcEncodedMulticodecHeaders.X25519PublicKey) => decoder(span, memoryPool),
                var span when span.StartsWith(Base58BtcEncodedMulticodecHeaders.Ed25519PublicKey) => decoder(span, memoryPool),
                var span when span.StartsWith(Base58BtcEncodedMulticodecHeaders.Bls12381G2PublicKey) => decoder(span, memoryPool),
                _ => null!//CustomMatcher(inputParam)
            };

            return result;
        };


        public static IMemoryOwner<byte> Decode(ReadOnlySpan<char> data, MemoryPool<byte> resultMemoryPool, ArrayDecodeDelegate<char, byte> arrayDecoder)
        {
            //This just forwards the call to buffer delegate call.
            IMemoryOwner<byte> bufferAllocatorDecoder(ReadOnlySpan<char> inputData, int codecHeaderLength, MemoryPool<byte> memoryPool)
            {
                byte[] decodedArray = arrayDecoder(inputData);
                var actualBufferLength = decodedArray.Length - codecHeaderLength;
                var output = memoryPool.Rent(actualBufferLength);
                decodedArray.AsSpan(codecHeaderLength, actualBufferLength).CopyTo(output.Memory.Span);

                return output;
            }

            return Decode(data, resultMemoryPool, bufferAllocatorDecoder);
        }



        public static IMemoryOwner<byte> Decode(ReadOnlySpan<char> data, MemoryPool<byte> resultMemoryPool, BufferAllocationDecodeDelegate decoder)
        {
            //All acceptable codecs have a header length of 2 bytes in the Multicodec format.
            const int CodecHeaderLength = 2;
            var decodedBytes = decoder(data.Slice(1), CodecHeaderLength, resultMemoryPool);

            return decodedBytes;
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
