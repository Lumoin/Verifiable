using SimpleBase;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Microsoft;

namespace Verifiable.Tests.TestInfrastructure
{
    /// <summary>
    /// Initializes structures needed in tests.
    /// </summary>
    public static class TestSetup
    {
        public static ArrayDecodeDelegate<char, byte> Base58ArrayDecoder { get; } = Base58.Bitcoin.Decode;

        /// <summary>
        /// The fixed Base58 encoder used in these tests. This is trusted to work properly.
        /// </summary>
        public static ReadOnlySpanFunc<byte, string> TestBase58ArrayEncoder { get; } = Base58.Bitcoin.Encode;
       

        public static BufferAllocationDecodeDelegate StackBase58Decoder { get; } = (dataWithoutMultibasePrefix, startIndex, resultMemoryPool) =>
        {            
            int safeEncodingBufferCount = Base58.Bitcoin.GetSafeByteCountForDecoding(dataWithoutMultibasePrefix);
            Span<byte> safeEncodingBuffer = safeEncodingBufferCount <= 512 ? stackalloc byte[safeEncodingBufferCount] : resultMemoryPool.Rent(safeEncodingBufferCount).Memory.Span;

            if(!Base58.Bitcoin.TryDecode(dataWithoutMultibasePrefix, safeEncodingBuffer, out int numBytesWritten))
            {
                throw new Exception("Decoding failed.");
            }

            var actualBufferLength = numBytesWritten - startIndex;
            var output = resultMemoryPool.Rent(actualBufferLength);
            safeEncodingBuffer.Slice(startIndex, actualBufferLength).CopyTo(output.Memory.Span);

            return output;
        };


        private static BufferAllocationDecodeDelegate MemoryBase58Decoder => (dataWithoutMultibasePrefix, startIndex, resultMemoryPool) =>
        {
            byte[] decodedArray = Base58.Bitcoin.Decode(dataWithoutMultibasePrefix);            
            var actualBufferLength = decodedArray.Length - startIndex;            
            var output = resultMemoryPool.Rent(actualBufferLength);            
            decodedArray.AsSpan(startIndex, actualBufferLength).CopyTo(output.Memory.Span);

            return output;
        };


        public static BufferAllocationEncodeDelegate StackBase58Encoder { get; } = (data, codecHeader, pool) =>
        {
            int bufferLengthForDataToBeEncoded = codecHeader.Length + data.Length;
            Span<byte> dataWithEncodingHeaders = stackalloc byte[bufferLengthForDataToBeEncoded];

            codecHeader.CopyTo(dataWithEncodingHeaders);
            data.CopyTo(dataWithEncodingHeaders.Slice(codecHeader.Length));

            int bufferSize = Base58.Bitcoin.GetSafeCharCountForEncoding(dataWithEncodingHeaders);
            Span<char> buffer = bufferSize <= 512 ? stackalloc char[bufferSize] : pool.Rent(bufferSize).Memory.Span;

            if(!Base58.Bitcoin.TryEncode(dataWithEncodingHeaders, buffer, out int bytesWritten))
            {
                throw new Exception("Encoding failed.");
            }

            return new string(buffer.Slice(0, bytesWritten));
        };


        /// <summary>
        /// The default serialization options to use in tests. These are the same that the library would
        /// use when serializing and deserializing SSI documents.
        /// </summary>
        public static JsonSerializerOptions DefaultSerializationOptions { get; } = new JsonSerializerOptions().ApplyVerifiableDefaults();


        /// <summary>
        /// Sets up encoders, decoders and other system wide functionality.
        /// </summary>
        [ModuleInitializer]
        public static void Setup()
        {
            CryptoLibrary.InitializeProviders(StackBase58Encoder, StackBase58Decoder, SHA256.HashData);            
        }
    }
}
