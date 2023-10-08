using SimpleBase;
using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;

namespace Verifiable.Tests.TestInfrastructure
{
    /// <summary>
    /// Initializes structures needed in tests.
    /// </summary>
    public static class TestSetup
    {
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
            CryptoLibrary.InitializeProviders(TestBase58Encoder, SHA256.HashData);
        }


        private static BufferAllocationDecodeDelegate TestBase58Decoder => (data, codecHeaderLength, resultMemoryPool) =>
        {
            ReadOnlySpan<char> dataWithoutMultibasePrefix = data;
            int safeEncodingBufferCount = Base58.Bitcoin.GetSafeByteCountForDecoding(dataWithoutMultibasePrefix);
            Span<byte> safeEncodingBuffer = safeEncodingBufferCount <= 512 ? stackalloc byte[safeEncodingBufferCount] : resultMemoryPool.Rent(safeEncodingBufferCount).Memory.Span;

            if(!Base58.Bitcoin.TryDecode(dataWithoutMultibasePrefix, safeEncodingBuffer, out int numBytesWritten))
            {
                throw new Exception("Decoding failed.");
            }

            var actualBufferLength = numBytesWritten - codecHeaderLength;
            var output = resultMemoryPool.Rent(actualBufferLength);
            safeEncodingBuffer.Slice(codecHeaderLength, actualBufferLength).CopyTo(output.Memory.Span);

            return output;
        };


        private static BufferAllocationEncodeDelegate TestBase58Encoder => (data, codecHeader, pool) =>
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
    }
}
