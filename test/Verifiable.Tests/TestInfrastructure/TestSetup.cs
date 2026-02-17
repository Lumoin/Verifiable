using SimpleBase;
using System.Buffers.Text;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Microsoft;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Initializes structures needed in tests. This is basically the same as any program setup for this library.
/// </summary>
internal static class TestSetup
{
    /// <summary>
    /// Base58 BTC encoder using SimpleBase.
    /// </summary>
    public static EncodeDelegate Base58Encoder { get; } = data =>
    {
        int bufferSize = Base58.Bitcoin.GetSafeCharCountForEncoding(data);
        Span<char> buffer = bufferSize <= 1024 ? stackalloc char[bufferSize] : new char[bufferSize];
        if(!Base58.Bitcoin.TryEncode(data, buffer, out int charsWritten))
        {
            throw new InvalidOperationException("Encoding failed.");
        }

        return new string(buffer[..charsWritten]);
    };


    /// <summary>
    /// Base64 URL encoder using built-in .NET APIs.
    /// </summary>
    public static EncodeDelegate Base64UrlEncoder { get; } = data =>
    {
        int base64Length = Base64Url.GetEncodedLength(data.Length);
        Span<byte> byteBuffer = base64Length <= 512 ? stackalloc byte[base64Length] : new byte[base64Length];
        bool success = Base64Url.TryEncodeToUtf8(data, byteBuffer, out int bytesWritten);
        if(!success)
        {
            throw new InvalidOperationException("Base64Url encoding failed.");
        }

        Span<char> charBuffer = bytesWritten <= 512 ? stackalloc char[bytesWritten] : new char[bytesWritten];
        for(int i = 0; i < bytesWritten; i++)
        {
            charBuffer[i] = (char)byteBuffer[i];
        }

        return new string(charBuffer);
    };


    /// <summary>
    /// Base58 BTC decoder using SimpleBase.
    /// </summary>
    public static DecodeDelegate Base58Decoder { get; } = (source, pool) =>
    {
        int safeEncodingBufferCount = Base58.Bitcoin.GetSafeByteCountForDecoding(source);
        var buffer = pool.Rent(safeEncodingBufferCount);

        if(!Base58.Bitcoin.TryDecode(source, buffer.Memory.Span, out int numBytesWritten))
        {
            buffer.Dispose();
            throw new FormatException("Base58 decoding failed.");
        }

        if(numBytesWritten < safeEncodingBufferCount)
        {
            var rightSized = pool.Rent(numBytesWritten);
            buffer.Memory.Span[..numBytesWritten].CopyTo(rightSized.Memory.Span);
            buffer.Dispose();

            return rightSized;
        }

        return buffer;
    };


    /// <summary>
    /// Base64 URL decoder using built-in .NET APIs.
    /// </summary>
    public static DecodeDelegate Base64UrlDecoder { get; } = (source, pool) =>
    {
        if(source.Length == 0)
        {
            throw new ArgumentException("Encoded input cannot be empty.", nameof(source));
        }

        int maxDecodedLength = Base64Url.GetMaxDecodedLength(source.Length);
        var buffer = pool.Rent(maxDecodedLength);

        bool success = Base64Url.TryDecodeFromChars(source, buffer.Memory.Span, out int bytesWritten);
        if(!success)
        {
            buffer.Dispose();
            throw new FormatException("Base64Url decoding failed.");
        }

        if(bytesWritten < maxDecodedLength)
        {
            var rightSized = pool.Rent(bytesWritten);
            buffer.Memory.Span[..bytesWritten].CopyTo(rightSized.Memory.Span);
            buffer.Dispose();

            return rightSized;
        }

        return buffer;
    };


    /// <summary>
    /// The default serialization options to use in tests.
    /// </summary>
    public static JsonSerializerOptions DefaultSerializationOptions { get; } = new JsonSerializerOptions().ApplyVerifiableDefaults();


    /// <summary>
    /// Sets up encoders, decoders and other system wide functionality.
    /// </summary>
    [ModuleInitializer]
    public static void Setup()
    {
        InitializeCoders();
        InitializeCryptoFunctions();
        MulticodecHeaderRegistry.Initialize();
    }


    private static void InitializeCoders()
    {
        CryptoLibrary.InitializeProviders(
            keyFormatType => keyFormatType switch
            {
                Type kt when kt == WellKnownKeyFormats.PublicKeyMultibase => Base58Encoder,
                Type kt when kt == WellKnownKeyFormats.PublicKeyJwk => Base64UrlEncoder,
                _ => throw new ArgumentException($"No encoder available for key format: '{keyFormatType}'.")
            },
            keyFormatType => keyFormatType switch
            {
                Type kt when kt == WellKnownKeyFormats.PublicKeyMultibase => Base58Decoder,
                Type kt when kt == WellKnownKeyFormats.PublicKeyJwk => Base64UrlDecoder,
                _ => throw new ArgumentException($"No decoder available for key format: '{keyFormatType}'.")
            },
            hashAlgorithm =>
            {
                if(hashAlgorithm.Equals(HashAlgorithmName.SHA256))
                {
                    return SHA256.HashData;
                }

                throw new ArgumentException($"No hash function available for hash algorithm: '{hashAlgorithm}'.");
            });
    }


    private static void InitializeCryptoFunctions()
    {
        CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.Initialize(
            (CryptoAlgorithm algorithm, Purpose purpose, string? qualifier) =>
            {
                return (algorithm, purpose) switch
                {
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignP256Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignP384Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignP521Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignSecp256k1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignRsa2048Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignRsa4096Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignEd25519Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa44) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignMlDsa44Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa65) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignMlDsa65Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa87) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignMlDsa87Async,
                    _ => throw new ArgumentException($"No signing function registered for '{algorithm}', '{purpose}' with qualifier '{qualifier}'.")
                };
            },
            (CryptoAlgorithm algorithm, Purpose purpose, string? qualifier) =>
            {
                return (algorithm, purpose) switch
                {
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyP256Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyP384Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyP521Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifySecp256k1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyRsa2048Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyRsa4096Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyEd25519Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa44) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyMlDsa44Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa65) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyMlDsa65Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa87) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyMlDsa87Async,
                    _ => throw new ArgumentException($"No verification function registered for '{algorithm}', '{purpose}' with qualifier '{qualifier}'.")
                };
            });
    }
}