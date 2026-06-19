using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;

namespace Verifiable.Microsoft;

/// <summary>
/// ECDH-ES key agreement and AES-GCM symmetric encryption and decryption using the
/// .NET platform cryptography library.
/// </summary>
/// <remarks>
/// Each method matches exactly one delegate from the split set in
/// <c>Verifiable.Cryptography.Aead</c>. See <c>BouncyCastleKeyAgreementFunctions</c>
/// for the corresponding BouncyCastle implementations.
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "Ownership of returned types transfers to the caller.")]
public static class MicrosoftKeyAgreementFunctions
{
    private const int AesGcmTagLength = 16;
    private const int AesGcmIvLength = 12;

    private static readonly ProviderLibrary ProviderLib = new(
        typeof(MicrosoftKeyAgreementFunctions).Assembly.GetName().Name
            ?? "Verifiable.Microsoft",
        typeof(MicrosoftKeyAgreementFunctions).Assembly.GetName().Version?.ToString()
            ?? "Unknown");

    private static readonly CryptoLibraryInfo CryptoLib = new(
        "System.Security.Cryptography",
        typeof(RandomNumberGenerator).Assembly.GetName().Version?.ToString()
            ?? System.Environment.Version.ToString());

    private static readonly ProviderClass ProviderCls =
        new(nameof(MicrosoftKeyAgreementFunctions));


    /// <summary>
    /// Performs ECDH key agreement on the encrypt side using P-256.
    /// Matches <see cref="KeyAgreementEncryptDelegate"/>.
    /// </summary>
    /// <param name="recipientPublicKey">
    /// The recipient's P-256 public key in uncompressed point encoding.
    /// </param>
    /// <param name="pool">Memory pool for shared secret and EPK coordinate allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The shared secret Z and ephemeral public key coordinates.
    /// </returns>
    public static async ValueTask<EphemeralKeyAgreementResult> EcdhKeyAgreementEncryptP256Async(
        PublicKeyMemory recipientPublicKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        ProviderOperation operation = new(nameof(EcdhKeyAgreementEncryptP256Async));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyAgreement);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Key.Algorithm, "ECDH");
            activity.SetTag(CryptoTelemetry.Key.Curve, MapCurveDisplay(ECCurve.NamedCurves.nistP256));
        }

        ReadOnlySpan<byte> recipientUncompressed = recipientPublicKey.AsReadOnlySpan();
        ReadOnlySpan<byte> recipientX = EllipticCurveUtilities.SliceXCoordinate(recipientUncompressed);
        ReadOnlySpan<byte> recipientY = EllipticCurveUtilities.SliceYCoordinate(recipientUncompressed);

        using ECDiffieHellman ephemeralEcdh =
            ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters ephemeralParams =
            ephemeralEcdh.ExportParameters(includePrivateParameters: false);

        using ECDiffieHellman recipientEcdh = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = recipientX.ToArray(),
                Y = recipientY.ToArray()
            }
        });

        byte[] sharedSecret = ephemeralEcdh.DeriveRawSecretAgreement(recipientEcdh.PublicKey);

        try
        {
            //The key agreement could be a remote call in hardware implementations —
            //this is the await point the async signature exists to support.
            await Task.CompletedTask.ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            IMemoryOwner<byte> zOwner = pool.Rent(sharedSecret.Length);
            sharedSecret.CopyTo(zOwner.Memory.Span);
            var z = new SharedSecret(zOwner, CryptoTags.P256ExchangePrivateKey);

            //Store the ephemeral public key as a single uncompressed point: 0x04 || X || Y.
            byte[] xBytes = ephemeralParams.Q.X!;
            byte[] yBytes = ephemeralParams.Q.Y!;
            IMemoryOwner<byte> epkOwner = pool.Rent(1 + xBytes.Length + yBytes.Length);
            epkOwner.Memory.Span[0] = 0x04;
            xBytes.CopyTo(epkOwner.Memory.Span[1..]);
            yBytes.CopyTo(epkOwner.Memory.Span[(1 + xBytes.Length)..]);

            PublicKeyMemory epk = new PublicKeyMemory(epkOwner, CryptoTags.P256ExchangePublicKey);

            return new EphemeralKeyAgreementResult(z, epk);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            CryptographicOperations.ZeroMemory(ephemeralParams.Q.X);
            CryptographicOperations.ZeroMemory(ephemeralParams.Q.Y);
        }
    }


    /// <summary>
    /// Performs ECDH key agreement on the decrypt side using P-256.
    /// Matches <see cref="KeyAgreementDecryptDelegate"/>.
    /// </summary>
    /// <param name="privateKeyBytes">
    /// The recipient's P-256 private key scalar (32 bytes, big-endian).
    /// </param>
    /// <param name="epk">
    /// The sender's ephemeral P-256 public key in uncompressed encoding:
    /// <c>0x04 || X (32 bytes) || Y (32 bytes)</c>.
    /// </param>
    /// <param name="pool">Memory pool for the shared secret allocation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The shared secret Z.</returns>
    public static ValueTask<SharedSecret> EcdhKeyAgreementDecryptP256Async(
        ReadOnlyMemory<byte> privateKeyBytes,
        PublicKeyMemory epk,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(epk);
        ArgumentNullException.ThrowIfNull(pool);

        ProviderOperation operation = new(nameof(EcdhKeyAgreementDecryptP256Async));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyAgreement);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Key.Algorithm, "ECDH");
            activity.SetTag(CryptoTelemetry.Key.Curve, MapCurveDisplay(ECCurve.NamedCurves.nistP256));
        }

        //Split the uncompressed point into X and Y coordinates.
        ReadOnlySpan<byte> point = epk.AsReadOnlySpan();
        const int coordinateLength = 32;
        ReadOnlySpan<byte> xSpan = point.Slice(1, coordinateLength);
        ReadOnlySpan<byte> ySpan = point.Slice(1 + coordinateLength, coordinateLength);

        using ECDiffieHellman recipientEcdh = CreateRecipientEcdh(P256CurveOid, privateKeyBytes.Span);

        using ECDiffieHellman senderEcdh = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = xSpan.ToArray(),
                Y = ySpan.ToArray()
            }
        });

        byte[] sharedSecret = recipientEcdh.DeriveRawSecretAgreement(senderEcdh.PublicKey);

        try
        {
            IMemoryOwner<byte> zOwner = pool.Rent(sharedSecret.Length);
            sharedSecret.CopyTo(zOwner.Memory.Span);

            return ValueTask.FromResult(
                new SharedSecret(zOwner, CryptoTags.P256ExchangePrivateKey));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }


    /// <summary>Performs ECDH key agreement (encrypt side) using NIST P-384 (RFC 7518 §6.2.1.2). Matches <see cref="KeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<EphemeralKeyAgreementResult> EcdhKeyAgreementEncryptP384Async(
        PublicKeyMemory recipientPublicKey, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhEncryptNistAsync(ECCurve.NamedCurves.nistP384, CryptoTags.P384ExchangePublicKey, CryptoTags.P384ExchangePrivateKey, recipientPublicKey, pool, cancellationToken);

    /// <summary>Performs ECDH key agreement (decrypt side) using NIST P-384 (RFC 7518 §6.2.1.2). Matches <see cref="KeyAgreementDecryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> EcdhKeyAgreementDecryptP384Async(
        ReadOnlyMemory<byte> privateKeyBytes, PublicKeyMemory epk, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhDecryptNistAsync(ECCurve.NamedCurves.nistP384, P384CurveOid, CryptoTags.P384ExchangePrivateKey, privateKeyBytes, epk, pool, cancellationToken);

    /// <summary>Performs ECDH key agreement (encrypt side) using NIST P-521 (RFC 7518 §6.2.1.3). Matches <see cref="KeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<EphemeralKeyAgreementResult> EcdhKeyAgreementEncryptP521Async(
        PublicKeyMemory recipientPublicKey, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhEncryptNistAsync(ECCurve.NamedCurves.nistP521, CryptoTags.P521ExchangePublicKey, CryptoTags.P521ExchangePrivateKey, recipientPublicKey, pool, cancellationToken);

    /// <summary>Performs ECDH key agreement (decrypt side) using NIST P-521 (RFC 7518 §6.2.1.3). Matches <see cref="KeyAgreementDecryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> EcdhKeyAgreementDecryptP521Async(
        ReadOnlyMemory<byte> privateKeyBytes, PublicKeyMemory epk, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhDecryptNistAsync(ECCurve.NamedCurves.nistP521, P521CurveOid, CryptoTags.P521ExchangePrivateKey, privateKeyBytes, epk, pool, cancellationToken);


    //Curve-parameterized ECDH (encrypt side) for the NIST curves P-384/P-521. Identical
    //to the inline P-256 path; the uncompressed EPK is sized from the exported coordinate
    //length (48 / 66) rather than a hardcoded 32.
    private static async ValueTask<EphemeralKeyAgreementResult> EcdhEncryptNistAsync(
        ECCurve namedCurve,
        Tag epkTag,
        Tag sharedSecretTag,
        PublicKeyMemory recipientPublicKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        ProviderOperation operation = new(nameof(EcdhEncryptNistAsync));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyAgreement);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Key.Algorithm, "ECDH");
            activity.SetTag(CryptoTelemetry.Key.Curve, MapCurveDisplay(namedCurve));
        }

        ReadOnlySpan<byte> recipientUncompressed = recipientPublicKey.AsReadOnlySpan();
        ReadOnlySpan<byte> recipientX = EllipticCurveUtilities.SliceXCoordinate(recipientUncompressed);
        ReadOnlySpan<byte> recipientY = EllipticCurveUtilities.SliceYCoordinate(recipientUncompressed);

        using ECDiffieHellman ephemeralEcdh = ECDiffieHellman.Create(namedCurve);
        ECParameters ephemeralParams = ephemeralEcdh.ExportParameters(includePrivateParameters: false);

        using ECDiffieHellman recipientEcdh = ECDiffieHellman.Create(new ECParameters
        {
            Curve = namedCurve,
            Q = new ECPoint
            {
                X = recipientX.ToArray(),
                Y = recipientY.ToArray()
            }
        });

        byte[] sharedSecret = ephemeralEcdh.DeriveRawSecretAgreement(recipientEcdh.PublicKey);

        try
        {
            //The key agreement could be a remote call in hardware implementations —
            //this is the await point the async signature exists to support.
            await Task.CompletedTask.ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            IMemoryOwner<byte> zOwner = pool.Rent(sharedSecret.Length);
            sharedSecret.CopyTo(zOwner.Memory.Span);
            var z = new SharedSecret(zOwner, sharedSecretTag);

            //Store the ephemeral public key as a single uncompressed point: 0x04 || X || Y.
            byte[] xBytes = ephemeralParams.Q.X!;
            byte[] yBytes = ephemeralParams.Q.Y!;
            IMemoryOwner<byte> epkOwner = pool.Rent(1 + xBytes.Length + yBytes.Length);
            epkOwner.Memory.Span[0] = 0x04;
            xBytes.CopyTo(epkOwner.Memory.Span[1..]);
            yBytes.CopyTo(epkOwner.Memory.Span[(1 + xBytes.Length)..]);

            var epk = new PublicKeyMemory(epkOwner, epkTag);

            return new EphemeralKeyAgreementResult(z, epk);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            CryptographicOperations.ZeroMemory(ephemeralParams.Q.X);
            CryptographicOperations.ZeroMemory(ephemeralParams.Q.Y);
        }
    }


    //Curve-parameterized ECDH (decrypt side) for the NIST curves P-384/P-521. The recipient
    //key is imported via SEC1 (CreateRecipientEcdh) so the platform derives a valid public
    //point; the sender's ephemeral public point comes off the wire (length-aware slicing).
    private static ValueTask<SharedSecret> EcdhDecryptNistAsync(
        ECCurve namedCurve,
        string curveOid,
        Tag sharedSecretTag,
        ReadOnlyMemory<byte> privateKeyBytes,
        PublicKeyMemory epk,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(epk);
        ArgumentNullException.ThrowIfNull(pool);

        ProviderOperation operation = new(nameof(EcdhDecryptNistAsync));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyAgreement);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Key.Algorithm, "ECDH");
            activity.SetTag(CryptoTelemetry.Key.Curve, MapCurveDisplay(namedCurve));
        }

        cancellationToken.ThrowIfCancellationRequested();

        //Split the uncompressed point into X and Y coordinates (length-aware per curve).
        ReadOnlySpan<byte> point = epk.AsReadOnlySpan();
        ReadOnlySpan<byte> xSpan = EllipticCurveUtilities.SliceXCoordinate(point);
        ReadOnlySpan<byte> ySpan = EllipticCurveUtilities.SliceYCoordinate(point);

        using ECDiffieHellman recipientEcdh = CreateRecipientEcdh(curveOid, privateKeyBytes.Span);

        using ECDiffieHellman senderEcdh = ECDiffieHellman.Create(new ECParameters
        {
            Curve = namedCurve,
            Q = new ECPoint
            {
                X = xSpan.ToArray(),
                Y = ySpan.ToArray()
            }
        });

        byte[] sharedSecret = recipientEcdh.DeriveRawSecretAgreement(senderEcdh.PublicKey);

        try
        {
            IMemoryOwner<byte> zOwner = pool.Rent(sharedSecret.Length);
            sharedSecret.CopyTo(zOwner.Memory.Span);

            return ValueTask.FromResult(new SharedSecret(zOwner, sharedSecretTag));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }


    private static string MapCurveDisplay(ECCurve curve) =>
        curve.Oid.FriendlyName switch
        {
            "nistP256" => "P-256",
            "nistP384" => "P-384",
            "nistP521" => "P-521",
            "secP256k1" => "secp256k1",
            _ => curve.Oid.FriendlyName ?? "Unknown"
        };


    //Named-curve OIDs for the SEC1 ECPrivateKey import in CreateRecipientEcdh.
    private const string P256CurveOid = "1.2.840.10045.3.1.7";
    private const string P384CurveOid = "1.3.132.0.34";
    private const string P521CurveOid = "1.3.132.0.35";


    /// <summary>
    /// Creates an <see cref="ECDiffieHellman"/> holding the recipient's private key by importing
    /// a SEC1 <c>ECPrivateKey</c> (RFC 5915) that carries only the named-curve OID and the
    /// private scalar, with the optional public key OMITTED so the provider derives it.
    /// </summary>
    /// <remarks>
    /// Building the key from <see cref="ECParameters"/> with a placeholder/zero public point Q
    /// works on Windows (CNG tolerates it) but is rejected by OpenSSL (Linux) and Apple Security
    /// (macOS), which validate Q against the curve. Importing SEC1 without the public key lets
    /// every provider compute the correct Q from the scalar, so the key is valid cross-platform.
    /// </remarks>
    private static ECDiffieHellman CreateRecipientEcdh(string curveOid, ReadOnlySpan<byte> privateScalar)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteInteger(1);
            writer.WriteOctetString(privateScalar);
            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                writer.WriteObjectIdentifier(curveOid);
            }
        }

        byte[] sec1 = writer.Encode();
        try
        {
            ECDiffieHellman ecdh = ECDiffieHellman.Create();
            ecdh.ImportECPrivateKey(sec1, out _);

            return ecdh;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sec1);
        }
    }


    /// <summary>
    /// Performs AES-GCM authenticated encryption.
    /// Matches <see cref="AeadEncryptDelegate"/>.
    /// </summary>
    public static async ValueTask<AeadEncryptResult> AesGcmEncryptAsync(
        ReadOnlyMemory<byte> plaintext,
        SymmetricKeyMemory key,
        AdditionalData aad,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(aad);
        ArgumentNullException.ThrowIfNull(pool);

        await Task.CompletedTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        IMemoryOwner<byte> ivOwner = pool.Rent(AesGcmIvLength);
        RandomNumberGenerator.Fill(ivOwner.Memory.Span[..AesGcmIvLength]);

        IMemoryOwner<byte> ciphertextOwner = pool.Rent(plaintext.Length);
        IMemoryOwner<byte> tagOwner = pool.Rent(AesGcmTagLength);

        using(var aesGcm = new AesGcm(key.AsReadOnlySpan(), AesGcmTagLength))
        {
            aesGcm.Encrypt(
                ivOwner.Memory.Span[..AesGcmIvLength],
                plaintext.Span,
                ciphertextOwner.Memory.Span[..plaintext.Length],
                tagOwner.Memory.Span[..AesGcmTagLength],
                aad.AsReadOnlySpan());
        }

        return new AeadEncryptResult(
            new Nonce(ivOwner, CryptoTags.AesGcmIv),
            new Ciphertext(ciphertextOwner, CryptoTags.AesGcmCiphertext),
            new AuthenticationTag(tagOwner, CryptoTags.AesGcmAuthTag));
    }


    /// <summary>
    /// Performs AES-GCM authenticated decryption.
    /// Matches <see cref="AeadDecryptDelegate"/>.
    /// </summary>
    /// <exception cref="CryptographicException">
    /// Thrown when authentication tag verification fails.
    /// </exception>
    public static async ValueTask<DecryptedContent> AesGcmDecryptAsync(
        Ciphertext ciphertext,
        SymmetricKeyMemory key,
        Nonce iv,
        AuthenticationTag tag,
        AdditionalData aad,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(iv);
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(aad);
        ArgumentNullException.ThrowIfNull(pool);

        await Task.CompletedTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        ReadOnlySpan<byte> ciphertextSpan = ciphertext.AsReadOnlySpan();
        IMemoryOwner<byte> plaintextOwner = pool.Rent(ciphertextSpan.Length);

        try
        {
            using var aesGcm = new AesGcm(key.AsReadOnlySpan(), AesGcmTagLength);
            aesGcm.Decrypt(
                iv.AsReadOnlySpan(),
                ciphertextSpan,
                tag.AsReadOnlySpan(),
                plaintextOwner.Memory.Span[..ciphertextSpan.Length],
                aad.AsReadOnlySpan());
        }
        catch
        {
            plaintextOwner.Dispose();
            throw;
        }

        return new DecryptedContent(plaintextOwner, CryptoTags.AesGcmDecryptedContent);
    }
}
