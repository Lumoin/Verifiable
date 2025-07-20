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
using Verifiable.Core.Cryptography.testing;
using Verifiable.Cryptography;
using Verifiable.Microsoft;

namespace Verifiable.Tests.TestInfrastructure
{
    /// <summary>
    /// Initializes structures needed in tests. This is basically the same as a any program setup for this library.
    /// </summary>
    public static class TestSetup
    {
        public static EncodeDelegate Base58Encoder { get; } = data =>
        {
            int bufferSize = Base58.Bitcoin.GetSafeCharCountForEncoding(data);
            Span<char> buffer = bufferSize <= 1024 ? stackalloc char[bufferSize] : new char[bufferSize];
            if(!Base58.Bitcoin.TryEncode(data, buffer, out int charsWritten))
            {
                throw new InvalidOperationException("Encoding failed");
            }

            return new string(buffer.Slice(0, charsWritten));
        };


        public static EncodeDelegate Base64UrlEncoder { get; } = data =>
        {
            //Use the built-in method to get the exact encoded length.
            int base64Length = Base64Url.GetEncodedLength(data.Length);

            //Base64Url encodes to bytes first, then convert to chars.
            Span<byte> byteBuffer = base64Length <= 512 ? stackalloc byte[base64Length] : new byte[base64Length];
            bool success = Base64Url.TryEncodeToUtf8(data, byteBuffer, out int bytesWritten);
            if(!success)
            {
                throw new InvalidOperationException("Base64Url encoding failed.");
            }

            //Convert the base64 bytes to chars.
            Span<char> charBuffer = bytesWritten <= 512 ? stackalloc char[bytesWritten] : new char[bytesWritten];
            for(int i = 0; i < bytesWritten; i++)
            {
                charBuffer[i] = (char)byteBuffer[i];
            }
            return new string(charBuffer);
        };


        public static DecodeDelegate Base58Decoder { get; } = (source, pool) =>
        {
            int safeEncodingBufferCount = Base58.Bitcoin.GetSafeByteCountForDecoding(source);
            var buffer = pool.Rent(safeEncodingBufferCount);

            if(!Base58.Bitcoin.TryDecode(source, buffer.Memory.Span, out int numBytesWritten))
            {
                buffer.Dispose();
                throw new FormatException("Base58 decoding failed.");
            }

            //Return right-sized buffer if needed.
            if(numBytesWritten < safeEncodingBufferCount)
            {
                var rightSized = pool.Rent(numBytesWritten);
                buffer.Memory.Span.Slice(0, numBytesWritten).CopyTo(rightSized.Memory.Span);
                buffer.Dispose();
                return rightSized;
            }

            return buffer;
        };


        /// <summary>
        /// Base64Url decoder using <see cref="Base64Url"/>.
        /// </summary>
        public static DecodeDelegate Base64UrlDecoder { get; } = (source, pool) =>
        {
            if(source.Length == 0)
            {
                throw new ArgumentException("Encoded input cannot be empty.", nameof(source));
            }

            //Calculate maximum decoded length.
            int maxDecodedLength = Base64Url.GetMaxDecodedLength(source.Length);
            var buffer = pool.Rent(maxDecodedLength);

            //Decode directly into the buffer.
            bool success = Base64Url.TryDecodeFromChars(source, buffer.Memory.Span, out int bytesWritten);
            if(!success)
            {
                buffer.Dispose();
                throw new FormatException("Base64Url decoding failed.");
            }

            //Return right-sized buffer if needed.
            if(bytesWritten < maxDecodedLength)
            {
                var rightSized = pool.Rent(bytesWritten);
                buffer.Memory.Span.Slice(0, bytesWritten).CopyTo(rightSized.Memory.Span);
                buffer.Dispose();
                return rightSized;
            }

            return buffer;
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
            CryptoLibrary.InitializeProviders(Base58Encoder, Base58Decoder, SHA256.HashData);

            //Manually configure the DefaultCoderSelector to handle both Base58 and Base64Url.
            DefaultCoderSelector.SelectEncoder = keyFormatType =>
            {
                return keyFormatType switch
                {
                    Type kt when kt == WellKnownKeyFormats.PublicKeyMultibase => Base58Encoder,
                    Type kt when kt == WellKnownKeyFormats.PublicKeyJwk => Base64UrlEncoder,
                    _ => throw new ArgumentException($"No encoder available for key format: {keyFormatType}")
                };
            };

            DefaultCoderSelector.SelectDecoder = keyFormatType =>
            {
                return keyFormatType switch
                {
                    Type kt when kt == WellKnownKeyFormats.PublicKeyMultibase => Base58Decoder,
                    Type kt when kt == WellKnownKeyFormats.PublicKeyJwk => Base64UrlDecoder,
                    _ => throw new ArgumentException($"No decoder available for key format: {keyFormatType}")
                };
            };

            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.Initialize((CryptoAlgorithm algorithm, Purpose purpose, string? qualifier) =>
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