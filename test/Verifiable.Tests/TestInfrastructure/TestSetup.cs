using SimpleBase;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
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

            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.Initialize(
                (CryptoAlgorithm algorithm, Purpose purpose, string? qualifier = null) =>
                {
                    return (algorithm, purpose, qualifier) switch
                    {
                        var (alg, purp, q) when alg.Equals(CryptoAlgorithm.P256) && purp.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignP256Async,
                        var (alg, purp, q) when alg.Equals(CryptoAlgorithm.P384) && purp.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignP384Async,
                        var (alg, purp, q) when alg.Equals(CryptoAlgorithm.P521) && purp.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignP521Async,
                        var (alg, purp, q) when alg.Equals(CryptoAlgorithm.Secp256k1) && purp.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignSecp256k1Async,
                        var (alg, purp, q) when alg.Equals(CryptoAlgorithm.Rsa2048) && purp.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignRsa2048Async,
                        var (alg, purp, q) when alg.Equals(CryptoAlgorithm.Rsa4096) && purp.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignRsa4096Async,
                        var (alg, purp, q) when alg.Equals(CryptoAlgorithm.Ed25519) && purp.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignEd25519Async,
                        _ => throw new ArgumentException($"No signing function registered for {algorithm}, {purpose} with qualifier {qualifier}.")
                    };
                },
                (CryptoAlgorithm algorithm, Purpose purpose, string? qualifier = null) =>
                {
                    return (algorithm, purpose, qualifier) switch
                    {
                        var (alg, purp, q) when alg.Equals(CryptoAlgorithm.P256) && purp.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyP256Async,
                        var (alg, purp, q) when alg.Equals(CryptoAlgorithm.P384) && purp.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyP384Async,
                        var (alg, purp, q) when alg.Equals(CryptoAlgorithm.P521) && purp.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyP521Async,
                        var (alg, purp, q) when alg.Equals(CryptoAlgorithm.Secp256k1) && purp.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifySecp256k1Async,
                        var (alg, purp, q) when alg.Equals(CryptoAlgorithm.Rsa2048) && purp.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsa2048Async,
                        var (alg, purp, q) when alg.Equals(CryptoAlgorithm.Rsa4096) && purp.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsa4096Async,
                        var (alg, purp, q) when alg.Equals(CryptoAlgorithm.Ed25519) && purp.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyEd25519Async,
                        _ => throw new ArgumentException($"No verification function registered for {algorithm}, {purpose} with qualifier {qualifier}.")
                    };
                });

            CryptographicKeyFactory.Initialize(
                (Tag tag, string? qualifier) =>
                {
                    CryptoAlgorithm algorithm = tag.Get<CryptoAlgorithm>();
                    Purpose purpose = (Purpose)tag[typeof(Purpose)];
                    return (ReadOnlyMemory<byte> publicKeyBytes, ReadOnlyMemory<byte> dataToVerify, Signature signature) =>
                    {
                        var verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose, qualifier);
                        return verificationDelegate(dataToVerify.Span, signature.AsReadOnlySpan(), publicKeyBytes.Span);
                    };
                },
                (Tag tag, string? qualifier) =>
                {
                    CryptoAlgorithm algorithm = tag.Get<CryptoAlgorithm>();
                    Purpose purpose = (Purpose)tag[typeof(Purpose)];
                    return async (ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToVerify, MemoryPool<byte> signature) =>
                    {
                        var signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose, qualifier);
                        var ret = await signingDelegate(privateKeyBytes.Span, dataToVerify.Span, signature);

                        return new Signature(ret, tag);
                    };
                });
        }
    }
}
