using SimpleBase;
using System.Buffers;
using System.Buffers.Text;
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
        /// Base64Url encoder using System.Buffers.Text.Base64Url.
        /// </summary>
        public static BufferAllocationEncodeDelegate Base64UrlEncoder { get; } = (data, codecHeader, pool) =>
        {
            //Handle empty input early - return empty string.
            if(data.Length == 0 && codecHeader.Length == 0)
            {
                return string.Empty;
            }

            //If no codec header, encode data directly.
            if(codecHeader.Length == 0)
            {
                return Base64Url.EncodeToString(data);
            }

            //Need to combine codec header + data.
            int bufferLengthForDataToBeEncoded = codecHeader.Length + data.Length;
            Span<byte> dataWithEncodingHeaders = bufferLengthForDataToBeEncoded <= 512
                ? stackalloc byte[bufferLengthForDataToBeEncoded]
                : new byte[bufferLengthForDataToBeEncoded];

            codecHeader.CopyTo(dataWithEncodingHeaders);
            data.CopyTo(dataWithEncodingHeaders[codecHeader.Length..]);

            //Let Base64Url.EncodeToString handle the string creation efficiently.
            return Base64Url.EncodeToString(dataWithEncodingHeaders);
        };


        /// <summary>
        /// Base64Url decoder using System.Buffers.Text.Base64Url.
        /// </summary>
        public static BufferAllocationDecodeDelegate Base64UrlDecoder { get; } = (data, codecHeaderLength, resultMemoryPool) =>
        {
            if(data.Length == 0)
            {
                throw new ArgumentException("Encoded input cannot be empty.", nameof(data));
            }

            //Calculate maximum decoded length and rent temporary buffer.
            int maxDecodedLength = Base64Url.GetMaxDecodedLength(data.Length);
            using var tempOwner = MemoryPool<byte>.Shared.Rent(maxDecodedLength);

            //Decode directly into the temporary buffer.
            bool success = Base64Url.TryDecodeFromChars(data, tempOwner.Memory.Span, out int bytesWritten);
            if(!success)
            {
                throw new InvalidOperationException("Base64Url decoding failed.");
            }

            //For JWK, codecHeaderLength is typically 0 (no multicodec header).
            var actualBufferLength = bytesWritten - codecHeaderLength;
            if(actualBufferLength < 0)
            {
                throw new InvalidOperationException($"Codec header length ({codecHeaderLength}) is larger than decoded data length ({bytesWritten}).");
            }

            //Always rent a buffer of the exact final size from the result pool.
            var output = resultMemoryPool.Rent(actualBufferLength);
            tempOwner.Memory.Span.Slice(codecHeaderLength, actualBufferLength).CopyTo(output.Memory.Span);

            return output;
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
            //Use the old 3-parameter initialization method.
            CryptoLibrary.InitializeProviders(StackBase58Encoder, StackBase58Decoder, SHA256.HashData);

            //Manually configure the DefaultCoderSelector to handle both Base58 and Base64Url.
            DefaultCoderSelector.SelectEncoder = keyFormatType =>
            {
                return keyFormatType switch
                {
                    Type kt when kt == WellKnownKeyFormats.PublicKeyMultibase => StackBase58Encoder,
                    Type kt when kt == WellKnownKeyFormats.PublicKeyJwk => Base64UrlEncoder,
                    _ => throw new ArgumentException($"No encoder available for key format: {keyFormatType}")
                };
            };

            DefaultCoderSelector.SelectDecoder = keyFormatType =>
            {
                return keyFormatType switch
                {
                    Type kt when kt == WellKnownKeyFormats.PublicKeyMultibase => StackBase58Decoder,
                    Type kt when kt == WellKnownKeyFormats.PublicKeyJwk => Base64UrlDecoder,
                    _ => throw new ArgumentException($"No decoder available for key format: {keyFormatType}")
                };
            };

            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.Initialize(
                (CryptoAlgorithm algorithm, Purpose purpose, string? qualifier) =>
                {
                    return (algorithm, purpose, qualifier) switch
                    {
                        (CryptoAlgorithm a, Purpose p, string q) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignP256Async,
                        (CryptoAlgorithm a, Purpose p, string q) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignP384Async,
                        (CryptoAlgorithm a, Purpose p, string q) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignP521Async,
                        (CryptoAlgorithm a, Purpose p, string q) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignSecp256k1Async,
                        (CryptoAlgorithm a, Purpose p, string q) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignRsa2048Async,
                        (CryptoAlgorithm a, Purpose p, string q) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignRsa4096Async,
                        (CryptoAlgorithm a, Purpose p, string q) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignEd25519Async,
                        (CryptoAlgorithm a, Purpose p, null) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignP256Async,
                        (CryptoAlgorithm a, Purpose p, null) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignP384Async,
                        (CryptoAlgorithm a, Purpose p, null) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignP521Async,
                        (CryptoAlgorithm a, Purpose p, null) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignSecp256k1Async,
                        (CryptoAlgorithm a, Purpose p, null) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignRsa2048Async,
                        (CryptoAlgorithm a, Purpose p, null) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignRsa4096Async,
                        (CryptoAlgorithm a, Purpose p, null) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignEd25519Async,
                        _ => throw new ArgumentException($"No signing function registered for {algorithm}, {purpose} with qualifier {qualifier}.")
                    };
                },
                (CryptoAlgorithm algorithm, Purpose purpose, string? qualifier) =>
                {
                    return (algorithm, purpose, qualifier) switch
                    {
                        (CryptoAlgorithm a, Purpose p, string q) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyP256Async,
                        (CryptoAlgorithm a, Purpose p, string q) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyP384Async,
                        (CryptoAlgorithm a, Purpose p, string q) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyP521Async,
                        (CryptoAlgorithm a, Purpose p, string q) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifySecp256k1Async,
                        (CryptoAlgorithm a, Purpose p, string q) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsa2048Async,
                        (CryptoAlgorithm a, Purpose p, string q) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsa4096Async,
                        (CryptoAlgorithm a, Purpose p, string q) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyEd25519Async,
                        (CryptoAlgorithm a, Purpose p, null) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyP256Async,
                        (CryptoAlgorithm a, Purpose p, null) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyP384Async,
                        (CryptoAlgorithm a, Purpose p, null) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyP521Async,
                        (CryptoAlgorithm a, Purpose p, null) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifySecp256k1Async,
                        (CryptoAlgorithm a, Purpose p, null) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsa2048Async,
                        (CryptoAlgorithm a, Purpose p, null) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsa4096Async,
                        (CryptoAlgorithm a, Purpose p, null) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyEd25519Async,
                        _ => throw new ArgumentException($"No verification function registered for {algorithm}, {purpose} with qualifier {qualifier}.")
                    };
                });

            CryptographicKeyFactory.Initialize(
                (Tag tag, string? qualifier) =>
                {
                    CryptoAlgorithm algorithm = tag.Get<CryptoAlgorithm>();
                    Purpose purpose = tag.Get<Purpose>();
                    return (ReadOnlyMemory<byte> publicKeyBytes, ReadOnlyMemory<byte> dataToVerify, Signature signature) =>
                    {
                        var verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose, qualifier);
                        return verificationDelegate(dataToVerify.Span, signature.AsReadOnlySpan(), publicKeyBytes.Span);
                    };
                },
                (Tag tag, string? qualifier) =>
                {
                    CryptoAlgorithm algorithm = tag.Get<CryptoAlgorithm>();
                    Purpose purpose = tag.Get<Purpose>();
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