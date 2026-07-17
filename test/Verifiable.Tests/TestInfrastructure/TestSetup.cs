using SimpleBase;
using System.Buffers.Text;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.DidComm;
using Verifiable.JCose;
using Verifiable.Microsoft;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Initializes structures needed in tests. This is the same as application
/// startup wiring for this library.
/// </summary>
internal static class TestSetup
{
    /// <summary>Base58 BTC encoder using SimpleBase.</summary>
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


    /// <summary>Base64url encoder using built-in .NET APIs.</summary>
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


    /// <summary>Base58 BTC decoder using SimpleBase.</summary>
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
    /// A <see cref="HashFunctionSelector"/> for the DIDComm attachment resolver: it returns
    /// <c>SHA256.HashData</c> for the self-describing sha2-256 multihash code and <see langword="null"/> for
    /// every other code (the resolver then fails the hashed path closed). This is the application-side hash
    /// policy the resolver takes as a parameter — the library bakes in no default hash.
    /// </summary>
    public static HashFunctionSelector MultihashSha256Selector { get; } = static multihashCode =>
        multihashCode == MultihashHeaders.Sha2Bits256[0]
            ? (HashFunctionDelegate)System.Security.Cryptography.SHA256.HashData
            : null;


    /// <summary>Base64url decoder using built-in .NET APIs.</summary>
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


    /// <summary>The default serialization options used in tests.</summary>
    public static JsonSerializerOptions DefaultSerializationOptions { get; } =
        new JsonSerializerOptions().ApplyVerifiableDefaults();


    /// <summary>
    /// Sets up encoders, decoders, cryptographic functions, and entropy providers.
    /// </summary>
    [ModuleInitializer]
    public static void Setup()
    {
        InitializeCoders();
        InitializeCryptoFunctions();
        InitializeRecoverableSignatureFunctions();
        InitializeEntropyFunctions();
        InitializeHmacFunctions();
        InitializeSymmetricFunctions();
        InitializeEcPointFunctions();
        InitializeKeyAgreementFunctions();
        InitializeKeyCreationFunctions();
        MulticodecHeaderRegistry.Initialize();
    }


    private static void InitializeCoders()
    {
        CryptoLibrary.InitializeProviders(
            keyFormatType => keyFormatType switch
            {
                Type kt when kt == WellKnownKeyFormats.PublicKeyMultibase => Base58Encoder,
                Type kt when kt == WellKnownKeyFormats.PublicKeyJwk => Base64UrlEncoder,
                _ => throw new ArgumentException(
                    $"No encoder available for key format: '{keyFormatType}'.")
            },
            keyFormatType => keyFormatType switch
            {
                Type kt when kt == WellKnownKeyFormats.PublicKeyMultibase => Base58Decoder,
                Type kt when kt == WellKnownKeyFormats.PublicKeyJwk => Base64UrlDecoder,
                _ => throw new ArgumentException(
                    $"No decoder available for key format: '{keyFormatType}'.")
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
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha256) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignRsaSha256Pkcs1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha256Pss) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignRsaSha256PssAsync,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha384) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignRsaSha384Pkcs1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha384Pss) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignRsaSha384PssAsync,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha512) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignRsaSha512Pkcs1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha512Pss) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignRsaSha512PssAsync,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignEd25519Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa44) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignMlDsa44Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa65) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignMlDsa65Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa87) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignMlDsa87Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP224r1) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignBrainpoolP224r1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP256r1) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignBrainpoolP256r1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP320r1) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignBrainpoolP320r1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP384r1) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignBrainpoolP384r1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP512r1) && p.Equals(Purpose.Signing) => BouncyCastleCryptographicFunctions.SignBrainpoolP512r1Async,
                    _ => throw new ArgumentException(
                        $"No signing function registered for '{algorithm}', '{purpose}' with qualifier '{qualifier}'.")
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
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha256) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsaSha256Pkcs1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha256Pss) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsaSha256PssAsync,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha384) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsaSha384Pkcs1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha384Pss) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsaSha384PssAsync,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha512) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsaSha512Pkcs1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha512Pss) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsaSha512PssAsync,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyEd25519Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa44) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyMlDsa44Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa65) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyMlDsa65Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa87) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyMlDsa87Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP224r1) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyBrainpoolP224r1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP256r1) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyBrainpoolP256r1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP320r1) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyBrainpoolP320r1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP384r1) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyBrainpoolP384r1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP512r1) && p.Equals(Purpose.Verification) => BouncyCastleCryptographicFunctions.VerifyBrainpoolP512r1Async,
                    _ => throw new ArgumentException(
                        $"No verification function registered for '{algorithm}', '{purpose}' with qualifier '{qualifier}'.")
                };
            });
    }


    private static void InitializeRecoverableSignatureFunctions()
    {
        //ISO/IEC 9796-2 message-recovery RSA signatures (eMRTD RSA Active Authentication) are routed through
        //their own registry, the same way key agreement and AEAD are, because message recovery does not fit
        //the detached signing/verification contract. Only BouncyCastle implements ISO-9796-2.
        RecoverableSignatureFunctionRegistry<CryptoAlgorithm, Purpose>.Initialize(
            (CryptoAlgorithm algorithm, Purpose purpose, string? qualifier) =>
            {
                return (algorithm, purpose) switch
                {
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaIso9796d2) && p.Equals(Purpose.Signing) => BouncyCastleRecoverableSignatureFunctions.SignRsaIso9796d2Async,
                    _ => throw new ArgumentException(
                        $"No recoverable signing function registered for '{algorithm}', '{purpose}' with qualifier '{qualifier}'.")
                };
            },
            (CryptoAlgorithm algorithm, Purpose purpose, string? qualifier) =>
            {
                return (algorithm, purpose) switch
                {
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaIso9796d2) && p.Equals(Purpose.Verification) => BouncyCastleRecoverableSignatureFunctions.VerifyRsaIso9796d2Async,
                    _ => throw new ArgumentException(
                        $"No recoverable verification function registered for '{algorithm}', '{purpose}' with qualifier '{qualifier}'.")
                };
            });
    }


    private static void InitializeEntropyFunctions()
    {
        //Register .NET CSPRNG-backed implementations as the defaults.
        CryptographicKeyFactory.RegisterFunction(
            typeof(GenerateNonceDelegate),
            (GenerateNonceDelegate)MicrosoftEntropyFunctions.GenerateNonce);

        CryptographicKeyFactory.RegisterFunction(
            typeof(GenerateSaltDelegate),
            (GenerateSaltDelegate)MicrosoftEntropyFunctions.GenerateSalt);

        //The registered digest is algorithm-agile by tag: a BLAKE3 tag (CryptoAlgorithm.Blake3, e.g. did:webplus
        //self-hashes) routes to the BouncyCastle BLAKE3 backend; HashAlgorithmName-tagged SHA digests go to the
        //Microsoft backend. This is the default the registry-backed resolver overloads consume.
        CryptographicKeyFactory.RegisterFunction(
            typeof(ComputeDigestDelegate),
            (ComputeDigestDelegate)((input, outputByteLength, tag, pool, context, cancellationToken) =>
                tag.TryGet<CryptoAlgorithm>(out CryptoAlgorithm algorithm) && algorithm == CryptoAlgorithm.Blake3
                    ? BouncyCastleEntropyFunctions.ComputeBlake3DigestAsync(input, outputByteLength, tag, pool, context, cancellationToken)
                    : MicrosoftEntropyFunctions.ComputeDigestAsync(input, outputByteLength, tag, pool, context, cancellationToken)));

        //The synchronous SHA-family seam for hashes that are sync by nature (JWK thumbprint, PKCE S256, Concat KDF,
        //SD-JWT disclosure digests): public/local-data hashes with no hardware-async backend. SHA-256 is the
        //default; SHA-384/512 are registered under qualifiers for the algorithm-agile SD-JWT caller.
        CryptographicKeyFactory.RegisterFunction(
            typeof(HashFunctionDelegate),
            (HashFunctionDelegate)System.Security.Cryptography.SHA256.HashData);

        CryptographicKeyFactory.RegisterFunction(
            typeof(HashFunctionDelegate),
            (HashFunctionDelegate)System.Security.Cryptography.SHA384.HashData,
            qualifier: nameof(System.Security.Cryptography.HashAlgorithmName.SHA384));

        CryptographicKeyFactory.RegisterFunction(
            typeof(HashFunctionDelegate),
            (HashFunctionDelegate)System.Security.Cryptography.SHA512.HashData,
            qualifier: nameof(System.Security.Cryptography.HashAlgorithmName.SHA512));

        //CMS SignedData verification (eMRTD Passive Authentication and CAdES). The Microsoft backend is the
        //default; the BouncyCastle backend is registered under a qualifier so a cross-backend test can prove
        //the seam is provider-neutral (an independent backend produces the same verified content).
        CryptographicKeyFactory.RegisterFunction(
            typeof(Verifiable.Cryptography.Pki.VerifyCmsSignedDataDelegate),
            (Verifiable.Cryptography.Pki.VerifyCmsSignedDataDelegate)MicrosoftCmsFunctions.VerifyCmsSignedDataAsync);
        CryptographicKeyFactory.RegisterFunction(
            typeof(Verifiable.Cryptography.Pki.VerifyCmsSignedDataDelegate),
            (Verifiable.Cryptography.Pki.VerifyCmsSignedDataDelegate)BouncyCastleCmsFunctions.VerifyCmsSignedDataAsync,
            qualifier: "BouncyCastle");
        //The fully managed backend (own ASN.1 parse, delegates only the EC primitive to the registered seam).
        CryptographicKeyFactory.RegisterFunction(
            typeof(Verifiable.Cryptography.Pki.VerifyCmsSignedDataDelegate),
            (Verifiable.Cryptography.Pki.VerifyCmsSignedDataDelegate)Verifiable.Cryptography.Pki.ManagedCmsVerification.VerifyCmsSignedDataAsync,
            qualifier: "Managed");

        //The X.509 certificate-profile reader (eMRTD Passive Authentication enforces the ICAO Doc 9303 Part 12
        //Document Signer profile through it). The Microsoft backend is the default; the BouncyCastle backend is
        //registered under a qualifier so a cross-backend test can prove the seam is provider-neutral.
        CryptographicKeyFactory.RegisterFunction(
            typeof(Verifiable.Cryptography.Pki.ReadCertificateProfileDelegate),
            (Verifiable.Cryptography.Pki.ReadCertificateProfileDelegate)MicrosoftX509Functions.ReadCertificateProfile);
        CryptographicKeyFactory.RegisterFunction(
            typeof(Verifiable.Cryptography.Pki.ReadCertificateProfileDelegate),
            (Verifiable.Cryptography.Pki.ReadCertificateProfileDelegate)BouncyCastleX509Functions.ReadCertificateProfile,
            qualifier: "BouncyCastle");
    }


    private static void InitializeHmacFunctions()
    {
        CryptographicKeyFactory.RegisterFunction(
            typeof(ComputeHmacDelegate),
            (ComputeHmacDelegate)MicrosoftHmacFunctions.ComputeHmacAsync);

        CryptographicKeyFactory.RegisterFunction(
            typeof(VerifyHmacDelegate),
            (VerifyHmacDelegate)MicrosoftHmacFunctions.VerifyHmacAsync);
    }


    private static void InitializeSymmetricFunctions()
    {
        //BouncyCastle backs the unauthenticated block-cipher and block-cipher MAC primitives
        //(Triple-DES CBC + ISO 9797-1 Retail MAC for eMRTD), since the AOT-clean Microsoft
        //backend does not expose them.
        CryptographicKeyFactory.RegisterFunction(
            typeof(SymmetricEncryptDelegate),
            (SymmetricEncryptDelegate)BouncyCastleSymmetricFunctions.SymmetricEncryptAsync);

        CryptographicKeyFactory.RegisterFunction(
            typeof(SymmetricDecryptDelegate),
            (SymmetricDecryptDelegate)BouncyCastleSymmetricFunctions.SymmetricDecryptAsync);

        CryptographicKeyFactory.RegisterFunction(
            typeof(ComputeBlockCipherMacDelegate),
            (ComputeBlockCipherMacDelegate)BouncyCastleSymmetricFunctions.ComputeBlockCipherMacAsync);

        CryptographicKeyFactory.RegisterFunction(
            typeof(VerifyBlockCipherMacDelegate),
            (VerifyBlockCipherMacDelegate)BouncyCastleSymmetricFunctions.VerifyBlockCipherMacAsync);
    }


    private static void InitializeEcPointFunctions()
    {
        //BouncyCastle backs the encoded-point EC arithmetic seam (scalar*G, scalar*P, P+Q) that
        //protocols such as PACE Generic Mapping build on; a managed backend can replace it by
        //registering different implementations of the same delegates.
        CryptographicKeyFactory.RegisterFunction(
            typeof(EcMultiplyGeneratorDelegate),
            (EcMultiplyGeneratorDelegate)BouncyCastleEcPointFunctions.MultiplyGeneratorAsync);

        CryptographicKeyFactory.RegisterFunction(
            typeof(EcMultiplyPointDelegate),
            (EcMultiplyPointDelegate)BouncyCastleEcPointFunctions.MultiplyPointAsync);

        CryptographicKeyFactory.RegisterFunction(
            typeof(EcAddPointsDelegate),
            (EcAddPointsDelegate)BouncyCastleEcPointFunctions.AddPointsAsync);

        //The Integrated Mapping point encoding f_G (Doc 9303 App B), the fourth EC-arithmetic primitive.
        CryptographicKeyFactory.RegisterFunction(
            typeof(EcMap2PointDelegate),
            (EcMap2PointDelegate)BouncyCastleEcPointFunctions.Map2PointAsync);

        //The Chip Authentication Mapping data CA_IC = s_IC^-1 * s_Map,IC mod n (Doc 9303 Sec 4.4.3.5.1).
        CryptographicKeyFactory.RegisterFunction(
            typeof(EcChipAuthenticationDataDelegate),
            (EcChipAuthenticationDataDelegate)BouncyCastleEcPointFunctions.ChipAuthenticationDataAsync);
    }


    private static void InitializeKeyAgreementFunctions()
    {
        KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.Initialize(
            keyAgreementEncryptMatcher: static (algorithm, purpose, qualifier) =>
                (algorithm, purpose) switch
                {
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP384Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP521Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.BrainpoolP224r1) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptBrainpoolP224r1Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.BrainpoolP256r1) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptBrainpoolP256r1Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.BrainpoolP320r1) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptBrainpoolP320r1Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.BrainpoolP384r1) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptBrainpoolP384r1Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.BrainpoolP512r1) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptBrainpoolP512r1Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptX25519Async,
                    _ => throw new ArgumentException(
                        $"No key agreement encrypt function for algorithm '{algorithm}' purpose '{purpose}'.")
                },
            keyAgreementDecryptMatcher: static (algorithm, purpose, qualifier) =>
                (algorithm, purpose) switch
                {
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP384Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP521Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.BrainpoolP224r1) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptBrainpoolP224r1Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.BrainpoolP256r1) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptBrainpoolP256r1Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.BrainpoolP320r1) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptBrainpoolP320r1Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.BrainpoolP384r1) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptBrainpoolP384r1Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.BrainpoolP512r1) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptBrainpoolP512r1Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptX25519Async,
                    _ => throw new ArgumentException(
                        $"No key agreement decrypt function for algorithm '{algorithm}' purpose '{purpose}'.")
                },
            //ConcatKdf and AES-GCM are curve-independent — the field-sized shared secret
            //is the only curve-dependent input and the agreement delegates already produce
            //it. So derivation/AEAD accept every wired Exchange curve uniformly.
            derivationMatcher: static (algorithm, purpose, qualifier) =>
                (algorithm, purpose) switch
                {
                    (CryptoAlgorithm, Purpose p) when p.Equals(Purpose.Exchange) =>
                            ConcatKdf.DefaultKeyDerivationDelegate,
                    _ => throw new ArgumentException(
                        $"No key derivation function for algorithm '{algorithm}' purpose '{purpose}'.")
                },
            //The content AEAD is curve-independent, so it is selected by the content algorithm carried in
            //the resolution qualifier: a null/GCM qualifier keeps the anoncrypt default (AES-GCM); XC20P
            //resolves to XChaCha20-Poly1305 (the anoncrypt-only content cipher of C.3 example 1); and
            //authcrypt passes its `enc` so the AES_CBC_HMAC_SHA2 family it mandates (1PU §2.1) — which the
            //curve-keyed registry cannot tell apart from AES-GCM by curve alone — resolves to CBC-HMAC.
            encryptMatcher: static (algorithm, purpose, qualifier) =>
                (purpose, qualifier) switch
                {
                    (Purpose p, string q) when p.Equals(Purpose.Exchange) && WellKnownJweEncryptionAlgorithms.IsA256CbcHs512(q) =>
                            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
                    (Purpose p, string q) when p.Equals(Purpose.Exchange) && WellKnownJweEncryptionAlgorithms.IsXC20P(q) =>
                            BouncyCastleKeyAgreementFunctions.XChaCha20Poly1305EncryptAsync,
                    (Purpose p, _) when p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                    _ => throw new ArgumentException(
                        $"No AEAD encrypt function for algorithm '{algorithm}' purpose '{purpose}' (enc '{qualifier}').")
                },
            decryptMatcher: static (algorithm, purpose, qualifier) =>
                (purpose, qualifier) switch
                {
                    (Purpose p, string q) when p.Equals(Purpose.Exchange) && WellKnownJweEncryptionAlgorithms.IsA256CbcHs512(q) =>
                            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync,
                    (Purpose p, string q) when p.Equals(Purpose.Exchange) && WellKnownJweEncryptionAlgorithms.IsXC20P(q) =>
                            BouncyCastleKeyAgreementFunctions.XChaCha20Poly1305DecryptAsync,
                    (Purpose p, _) when p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
                    _ => throw new ArgumentException(
                        $"No AEAD decrypt function for algorithm '{algorithm}' purpose '{purpose}' (enc '{qualifier}').")
                },
            kemDecapsulationMatcher: null,
            authenticatedKeyAgreementEncryptMatcher: static (algorithm, purpose, qualifier) =>
                (algorithm, purpose) switch
                {
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementEncryptX25519Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Exchange) =>
                            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementEncryptP256Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Exchange) =>
                            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementEncryptP384Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Exchange) =>
                            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementEncryptP521Async,
                    _ => throw new ArgumentException(
                        $"No authenticated key agreement encrypt function for algorithm '{algorithm}' purpose '{purpose}'.")
                },
            authenticatedKeyAgreementDecryptMatcher: static (algorithm, purpose, qualifier) =>
                (algorithm, purpose) switch
                {
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Exchange) =>
                            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP256Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Exchange) =>
                            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP384Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Exchange) =>
                            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP521Async,
                    _ => throw new ArgumentException(
                        $"No authenticated key agreement decrypt function for algorithm '{algorithm}' purpose '{purpose}'.")
                },
            //The 1PU Concat KDF is curve-independent for the same reason as the ECDH-ES one:
            //the agreement delegates already produce the fixed-width Z = Ze || Zs.
            authenticatedKeyDerivationMatcher: static (algorithm, purpose, qualifier) =>
                (algorithm, purpose) switch
                {
                    (CryptoAlgorithm, Purpose p) when p.Equals(Purpose.Exchange) =>
                            ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
                    _ => throw new ArgumentException(
                        $"No authenticated key derivation function for algorithm '{algorithm}' purpose '{purpose}'.")
                },
            wrapMatcher: static (algorithm, purpose, qualifier) =>
                (algorithm, purpose) switch
                {
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.Aes256) && p.Equals(Purpose.Encryption) =>
                            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
                    _ => throw new ArgumentException(
                        $"No key wrap function for algorithm '{algorithm}' purpose '{purpose}'.")
                },
            unwrapMatcher: static (algorithm, purpose, qualifier) =>
                (algorithm, purpose) switch
                {
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.Aes256) && p.Equals(Purpose.Encryption) =>
                            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
                    _ => throw new ArgumentException(
                        $"No key unwrap function for algorithm '{algorithm}' purpose '{purpose}'.")
                },
            multiRecipientKeyAgreementEncryptMatcher: static (algorithm, purpose, qualifier) =>
                (algorithm, purpose) switch
                {
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptX25519Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Exchange) =>
                            MicrosoftKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptP256Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Exchange) =>
                            MicrosoftKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptP384Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Exchange) =>
                            MicrosoftKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptP521Async,
                    _ => throw new ArgumentException(
                        $"No multi-recipient key agreement encrypt function for algorithm '{algorithm}' purpose '{purpose}'.")
                },
            multiRecipientAuthenticatedKeyAgreementEncryptMatcher: static (algorithm, purpose, qualifier) =>
                (algorithm, purpose) switch
                {
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) =>
                            BouncyCastleKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptX25519Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Exchange) =>
                            MicrosoftKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptP256Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Exchange) =>
                            MicrosoftKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptP384Async,
                    (CryptoAlgorithm a, Purpose p)
                        when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Exchange) =>
                            MicrosoftKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptP521Async,
                    _ => throw new ArgumentException(
                        $"No multi-recipient authenticated key agreement encrypt function for algorithm '{algorithm}' purpose '{purpose}'.")
                });
    }


    /// <summary>
    /// Registers key-creation adapters for exactly the algorithm/purpose combinations
    /// <see cref="InitializeCryptoFunctions"/> and <see cref="InitializeKeyAgreementFunctions"/> already wire
    /// a signing or key-agreement consumer for: P-256/384/521, secp256k1, RSA-2048/4096, Ed25519, ML-DSA-44/65/87,
    /// and the five Brainpool signing curves for <see cref="Purpose.Signing"/>; P-256/384/521, the five
    /// Brainpool curves, and X25519 for <see cref="Purpose.Exchange"/>. Backend attribution matches
    /// <see cref="TestKeyMaterialProvider"/>'s own convention exactly (P-256/384/521 and RSA-2048/4096
    /// signing keys mint via the Microsoft backend; every other algorithm — including the P-256/384/521
    /// exchange keys, which mint via BouncyCastle even though their ECDH-ES <em>agreement</em> and 1PU
    /// counterparts are split across both backends — mints via BouncyCastle), so a test that asserts
    /// <see cref="KeyMaterialGeneratedEvent"/> provenance sees the same <c>Backend</c> string the cached
    /// <see cref="TestKeyMaterialProvider"/> sources would have produced.
    /// </summary>
    /// <remarks>
    /// Deliberately excludes ML-KEM-512/768/1024: <see cref="InitializeKeyAgreementFunctions"/> passes
    /// <c>kemDecapsulationMatcher: null</c>, so no consumer can bind a minted ML-KEM key today — registering
    /// its keygen would produce a <see cref="KeyMaterialGeneratedEvent"/> for a key nothing downstream uses.
    /// NSec is not registered either: despite <c>Verifiable.NSec</c> also implementing Ed25519/X25519 key
    /// creation, <see cref="TestKeyMaterialProvider"/> sources both exclusively from
    /// <c>BouncyCastleKeyMaterialCreator</c>, and neither <see cref="InitializeCryptoFunctions"/> nor
    /// <see cref="InitializeKeyAgreementFunctions"/> routes Ed25519/X25519 signing or exchange to NSec.
    /// </remarks>
    private static void InitializeKeyCreationFunctions()
    {
        KeyCreationFunctionRegistry<CryptoAlgorithm, Purpose>.Initialize(
            (CryptoAlgorithm algorithm, Purpose purpose, string? qualifier) =>
            {
                return (algorithm, purpose) switch
                {
                    //Signing keys.
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Signing) =>
                        pool => MicrosoftKeyMaterialCreator.CreateKeysWithEvent(MicrosoftKeyMaterialCreator.CreateP256Keys, CryptoAlgorithm.P256, Purpose.Signing, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Signing) =>
                        pool => MicrosoftKeyMaterialCreator.CreateKeysWithEvent(MicrosoftKeyMaterialCreator.CreateP384Keys, CryptoAlgorithm.P384, Purpose.Signing, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Signing) =>
                        pool => MicrosoftKeyMaterialCreator.CreateKeysWithEvent(MicrosoftKeyMaterialCreator.CreateP521Keys, CryptoAlgorithm.P521, Purpose.Signing, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Signing) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateSecp256k1Keys, CryptoAlgorithm.Secp256k1, Purpose.Signing, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Signing) =>
                        pool => MicrosoftKeyMaterialCreator.CreateKeysWithEvent(MicrosoftKeyMaterialCreator.CreateRsa2048Keys, CryptoAlgorithm.Rsa2048, Purpose.Signing, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Signing) =>
                        pool => MicrosoftKeyMaterialCreator.CreateKeysWithEvent(MicrosoftKeyMaterialCreator.CreateRsa4096Keys, CryptoAlgorithm.Rsa4096, Purpose.Signing, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Signing) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateEd25519Keys, CryptoAlgorithm.Ed25519, Purpose.Signing, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa44) && p.Equals(Purpose.Signing) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateMlDsa44Keys, CryptoAlgorithm.MlDsa44, Purpose.Signing, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa65) && p.Equals(Purpose.Signing) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateMlDsa65Keys, CryptoAlgorithm.MlDsa65, Purpose.Signing, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa87) && p.Equals(Purpose.Signing) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateMlDsa87Keys, CryptoAlgorithm.MlDsa87, Purpose.Signing, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP224r1) && p.Equals(Purpose.Signing) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateBrainpoolP224r1Keys, CryptoAlgorithm.BrainpoolP224r1, Purpose.Signing, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP256r1) && p.Equals(Purpose.Signing) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateBrainpoolP256r1Keys, CryptoAlgorithm.BrainpoolP256r1, Purpose.Signing, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP320r1) && p.Equals(Purpose.Signing) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateBrainpoolP320r1Keys, CryptoAlgorithm.BrainpoolP320r1, Purpose.Signing, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP384r1) && p.Equals(Purpose.Signing) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateBrainpoolP384r1Keys, CryptoAlgorithm.BrainpoolP384r1, Purpose.Signing, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP512r1) && p.Equals(Purpose.Signing) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateBrainpoolP512r1Keys, CryptoAlgorithm.BrainpoolP512r1, Purpose.Signing, pool),

                    //Exchange keys.
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Exchange) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys, CryptoAlgorithm.P256, Purpose.Exchange, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Exchange) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateP384ExchangeKeys, CryptoAlgorithm.P384, Purpose.Exchange, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Exchange) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateP521ExchangeKeys, CryptoAlgorithm.P521, Purpose.Exchange, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP224r1) && p.Equals(Purpose.Exchange) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateBrainpoolP224r1ExchangeKeys, CryptoAlgorithm.BrainpoolP224r1, Purpose.Exchange, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP256r1) && p.Equals(Purpose.Exchange) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateBrainpoolP256r1ExchangeKeys, CryptoAlgorithm.BrainpoolP256r1, Purpose.Exchange, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP320r1) && p.Equals(Purpose.Exchange) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateBrainpoolP320r1ExchangeKeys, CryptoAlgorithm.BrainpoolP320r1, Purpose.Exchange, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP384r1) && p.Equals(Purpose.Exchange) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateBrainpoolP384r1ExchangeKeys, CryptoAlgorithm.BrainpoolP384r1, Purpose.Exchange, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP512r1) && p.Equals(Purpose.Exchange) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateBrainpoolP512r1ExchangeKeys, CryptoAlgorithm.BrainpoolP512r1, Purpose.Exchange, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) =>
                        pool => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(BouncyCastleKeyMaterialCreator.CreateX25519Keys, CryptoAlgorithm.X25519, Purpose.Exchange, pool),

                    _ => throw new ArgumentException(
                        $"No key creation function registered for '{algorithm}', '{purpose}' with qualifier '{qualifier}'.")
                };
            });
    }
}
