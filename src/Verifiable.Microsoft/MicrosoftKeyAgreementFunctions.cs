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
using Verifiable.Cryptography.Context;
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

    private static ProviderLibrary ProviderLib { get; } = new(
        typeof(MicrosoftKeyAgreementFunctions).Assembly.GetName().Name
            ?? "Verifiable.Microsoft",
        typeof(MicrosoftKeyAgreementFunctions).Assembly.GetName().Version?.ToString()
            ?? "Unknown");

    private static CryptoLibraryInfo CryptoLib { get; } = new(
        "System.Security.Cryptography",
        typeof(RandomNumberGenerator).Assembly.GetName().Version?.ToString()
            ?? System.Environment.Version.ToString());

    private static ProviderClass ProviderCls { get; } =
        new(nameof(MicrosoftKeyAgreementFunctions));


    //Returns a consumed public key as an uncompressed SEC1 point (0x04 || X || Y), decompressing a
    //compressed point with the curve carried by the key's Tag. DID-document-resolved EC keys arrive
    //compressed (the multibase and JWK decoders emit compressed SEC1), while generated and on-the-wire
    //keys are already uncompressed; every coordinate-slicing agreement below takes its public points
    //through this normalizer so both forms work uniformly.
    private static byte[] UncompressedPoint(PublicKeyMemory publicKey)
    {
        CryptoAlgorithm curve = publicKey.Tag.Get<CryptoAlgorithm>();

        return EllipticCurveUtilities.NormalizeToUncompressed(publicKey.AsReadOnlySpan(), EllipticCurveUtilities.CurveTypeFor(curve));
    }


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

        byte[] recipientUncompressed = UncompressedPoint(recipientPublicKey);
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
            epkOwner.Memory.Span[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
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

        //Normalize to an uncompressed point (decompressing a compressed epk via the tag's curve), then
        //split into X and Y — uniform with every other NIST agreement site (see UncompressedPoint).
        byte[] point = UncompressedPoint(epk);
        ReadOnlySpan<byte> xSpan = EllipticCurveUtilities.SliceXCoordinate(point);
        ReadOnlySpan<byte> ySpan = EllipticCurveUtilities.SliceYCoordinate(point);

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

        byte[] recipientUncompressed = UncompressedPoint(recipientPublicKey);
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
            epkOwner.Memory.Span[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
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

        //Normalize to an uncompressed point, then split into X and Y coordinates (length-aware per curve).
        byte[] point = UncompressedPoint(epk);
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


    /// <summary>Performs ECDH-1PU key agreement (encrypt side) using NIST P-256 (draft-madden-jose-ecdh-1pu-04 §2.3). Matches <see cref="AuthenticatedKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<EphemeralKeyAgreementResult> Ecdh1PuKeyAgreementEncryptP256Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> senderPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuEncryptNistAsync(ECCurve.NamedCurves.nistP256, P256CurveOid, CryptoTags.P256ExchangePublicKey, CryptoTags.P256ExchangePrivateKey, recipientPublicKey, senderPrivateKeyBytes, pool, cancellationToken);

    /// <summary>Performs ECDH-1PU key agreement (decrypt side) using NIST P-256 (draft-madden-jose-ecdh-1pu-04 §2.3). Matches <see cref="AuthenticatedKeyAgreementDecryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> Ecdh1PuKeyAgreementDecryptP256Async(
        ReadOnlyMemory<byte> recipientPrivateKeyBytes, PublicKeyMemory ephemeralPublicKey, PublicKeyMemory senderPublicKey, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuDecryptNistAsync(ECCurve.NamedCurves.nistP256, P256CurveOid, CryptoTags.P256ExchangePrivateKey, recipientPrivateKeyBytes, ephemeralPublicKey, senderPublicKey, pool, cancellationToken);

    /// <summary>Performs ECDH-1PU key agreement (encrypt side) using NIST P-384 (draft-madden-jose-ecdh-1pu-04 §2.3). Matches <see cref="AuthenticatedKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<EphemeralKeyAgreementResult> Ecdh1PuKeyAgreementEncryptP384Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> senderPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuEncryptNistAsync(ECCurve.NamedCurves.nistP384, P384CurveOid, CryptoTags.P384ExchangePublicKey, CryptoTags.P384ExchangePrivateKey, recipientPublicKey, senderPrivateKeyBytes, pool, cancellationToken);

    /// <summary>Performs ECDH-1PU key agreement (decrypt side) using NIST P-384 (draft-madden-jose-ecdh-1pu-04 §2.3). Matches <see cref="AuthenticatedKeyAgreementDecryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> Ecdh1PuKeyAgreementDecryptP384Async(
        ReadOnlyMemory<byte> recipientPrivateKeyBytes, PublicKeyMemory ephemeralPublicKey, PublicKeyMemory senderPublicKey, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuDecryptNistAsync(ECCurve.NamedCurves.nistP384, P384CurveOid, CryptoTags.P384ExchangePrivateKey, recipientPrivateKeyBytes, ephemeralPublicKey, senderPublicKey, pool, cancellationToken);

    /// <summary>Performs ECDH-1PU key agreement (encrypt side) using NIST P-521 (draft-madden-jose-ecdh-1pu-04 §2.3). Matches <see cref="AuthenticatedKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<EphemeralKeyAgreementResult> Ecdh1PuKeyAgreementEncryptP521Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> senderPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuEncryptNistAsync(ECCurve.NamedCurves.nistP521, P521CurveOid, CryptoTags.P521ExchangePublicKey, CryptoTags.P521ExchangePrivateKey, recipientPublicKey, senderPrivateKeyBytes, pool, cancellationToken);

    /// <summary>Performs ECDH-1PU key agreement (decrypt side) using NIST P-521 (draft-madden-jose-ecdh-1pu-04 §2.3). Matches <see cref="AuthenticatedKeyAgreementDecryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> Ecdh1PuKeyAgreementDecryptP521Async(
        ReadOnlyMemory<byte> recipientPrivateKeyBytes, PublicKeyMemory ephemeralPublicKey, PublicKeyMemory senderPublicKey, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuDecryptNistAsync(ECCurve.NamedCurves.nistP521, P521CurveOid, CryptoTags.P521ExchangePrivateKey, recipientPrivateKeyBytes, ephemeralPublicKey, senderPublicKey, pool, cancellationToken);


    //ECDH-1PU (encrypt side) for the NIST curves: Ze from a fresh ephemeral key against
    //the recipient's static public key, Zs from the sender's static private key against
    //the same recipient key, Z = Ze || Zs per NIST SP 800-56A §6.2.1.2.
    private static async ValueTask<EphemeralKeyAgreementResult> Ecdh1PuEncryptNistAsync(
        ECCurve namedCurve,
        string curveOid,
        Tag epkTag,
        Tag sharedSecretTag,
        PublicKeyMemory recipientPublicKey,
        ReadOnlyMemory<byte> senderPrivateKeyBytes,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] recipientUncompressed = UncompressedPoint(recipientPublicKey);
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

        using ECDiffieHellman senderEcdh = CreateRecipientEcdh(curveOid, senderPrivateKeyBytes.Span);

        byte[] ze = ephemeralEcdh.DeriveRawSecretAgreement(recipientEcdh.PublicKey);
        byte[] zs = senderEcdh.DeriveRawSecretAgreement(recipientEcdh.PublicKey);

        try
        {
            //The key agreement could be a remote call in hardware implementations —
            //this is the await point the async signature exists to support.
            await Task.CompletedTask.ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            IMemoryOwner<byte> zOwner = pool.Rent(ze.Length + zs.Length);
            ze.CopyTo(zOwner.Memory.Span);
            zs.CopyTo(zOwner.Memory.Span[ze.Length..]);
            var z = new SharedSecret(zOwner, sharedSecretTag);

            //Store the ephemeral public key as a single uncompressed point: 0x04 || X || Y.
            byte[] xBytes = ephemeralParams.Q.X!;
            byte[] yBytes = ephemeralParams.Q.Y!;
            IMemoryOwner<byte> epkOwner = pool.Rent(1 + xBytes.Length + yBytes.Length);
            epkOwner.Memory.Span[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
            xBytes.CopyTo(epkOwner.Memory.Span[1..]);
            yBytes.CopyTo(epkOwner.Memory.Span[(1 + xBytes.Length)..]);

            var epk = new PublicKeyMemory(epkOwner, epkTag);

            return new EphemeralKeyAgreementResult(z, epk);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ze);
            CryptographicOperations.ZeroMemory(zs);
            CryptographicOperations.ZeroMemory(ephemeralParams.Q.X);
            CryptographicOperations.ZeroMemory(ephemeralParams.Q.Y);
        }
    }


    //ECDH-1PU (decrypt side) for the NIST curves: Ze from the recipient's static private
    //key against the sender's ephemeral public key, Zs from the same private key against
    //the sender's static public key, Z = Ze || Zs — byte identical to the encrypt side.
    private static ValueTask<SharedSecret> Ecdh1PuDecryptNistAsync(
        ECCurve namedCurve,
        string curveOid,
        Tag sharedSecretTag,
        ReadOnlyMemory<byte> recipientPrivateKeyBytes,
        PublicKeyMemory ephemeralPublicKey,
        PublicKeyMemory senderPublicKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ephemeralPublicKey);
        ArgumentNullException.ThrowIfNull(senderPublicKey);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        byte[] epkPoint = UncompressedPoint(ephemeralPublicKey);
        byte[] senderPoint = UncompressedPoint(senderPublicKey);

        using ECDiffieHellman recipientEcdh = CreateRecipientEcdh(curveOid, recipientPrivateKeyBytes.Span);

        using ECDiffieHellman ephemeralEcdh = ECDiffieHellman.Create(new ECParameters
        {
            Curve = namedCurve,
            Q = new ECPoint
            {
                X = EllipticCurveUtilities.SliceXCoordinate(epkPoint).ToArray(),
                Y = EllipticCurveUtilities.SliceYCoordinate(epkPoint).ToArray()
            }
        });

        using ECDiffieHellman senderEcdh = ECDiffieHellman.Create(new ECParameters
        {
            Curve = namedCurve,
            Q = new ECPoint
            {
                X = EllipticCurveUtilities.SliceXCoordinate(senderPoint).ToArray(),
                Y = EllipticCurveUtilities.SliceYCoordinate(senderPoint).ToArray()
            }
        });

        byte[] ze = recipientEcdh.DeriveRawSecretAgreement(ephemeralEcdh.PublicKey);
        byte[] zs = recipientEcdh.DeriveRawSecretAgreement(senderEcdh.PublicKey);

        try
        {
            IMemoryOwner<byte> zOwner = pool.Rent(ze.Length + zs.Length);
            ze.CopyTo(zOwner.Memory.Span);
            zs.CopyTo(zOwner.Memory.Span[ze.Length..]);

            return ValueTask.FromResult(new SharedSecret(zOwner, sharedSecretTag));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ze);
            CryptographicOperations.ZeroMemory(zs);
        }
    }


    /// <summary>Performs multi-recipient ECDH-ES key agreement (encrypt side) with a caller-held ephemeral key using NIST P-256. Matches <see cref="MultiRecipientKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> EcdhEsMultiRecipientAgreementEncryptP256Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> ephemeralPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhEsMultiRecipientEncryptNistAsync(ECCurve.NamedCurves.nistP256, P256CurveOid, CryptoTags.P256ExchangePrivateKey, recipientPublicKey, ephemeralPrivateKeyBytes, pool, cancellationToken);

    /// <summary>Performs multi-recipient ECDH-ES key agreement (encrypt side) with a caller-held ephemeral key using NIST P-384. Matches <see cref="MultiRecipientKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> EcdhEsMultiRecipientAgreementEncryptP384Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> ephemeralPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhEsMultiRecipientEncryptNistAsync(ECCurve.NamedCurves.nistP384, P384CurveOid, CryptoTags.P384ExchangePrivateKey, recipientPublicKey, ephemeralPrivateKeyBytes, pool, cancellationToken);

    /// <summary>Performs multi-recipient ECDH-ES key agreement (encrypt side) with a caller-held ephemeral key using NIST P-521. Matches <see cref="MultiRecipientKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> EcdhEsMultiRecipientAgreementEncryptP521Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> ephemeralPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhEsMultiRecipientEncryptNistAsync(ECCurve.NamedCurves.nistP521, P521CurveOid, CryptoTags.P521ExchangePrivateKey, recipientPublicKey, ephemeralPrivateKeyBytes, pool, cancellationToken);

    /// <summary>Performs multi-recipient ECDH-1PU key agreement (encrypt side) with a caller-held ephemeral key using NIST P-256. Matches <see cref="MultiRecipientAuthenticatedKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> Ecdh1PuMultiRecipientAgreementEncryptP256Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> ephemeralPrivateKeyBytes, ReadOnlyMemory<byte> senderPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuMultiRecipientEncryptNistAsync(ECCurve.NamedCurves.nistP256, P256CurveOid, CryptoTags.P256ExchangePrivateKey, recipientPublicKey, ephemeralPrivateKeyBytes, senderPrivateKeyBytes, pool, cancellationToken);

    /// <summary>Performs multi-recipient ECDH-1PU key agreement (encrypt side) with a caller-held ephemeral key using NIST P-384. Matches <see cref="MultiRecipientAuthenticatedKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> Ecdh1PuMultiRecipientAgreementEncryptP384Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> ephemeralPrivateKeyBytes, ReadOnlyMemory<byte> senderPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuMultiRecipientEncryptNistAsync(ECCurve.NamedCurves.nistP384, P384CurveOid, CryptoTags.P384ExchangePrivateKey, recipientPublicKey, ephemeralPrivateKeyBytes, senderPrivateKeyBytes, pool, cancellationToken);

    /// <summary>Performs multi-recipient ECDH-1PU key agreement (encrypt side) with a caller-held ephemeral key using NIST P-521. Matches <see cref="MultiRecipientAuthenticatedKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> Ecdh1PuMultiRecipientAgreementEncryptP521Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> ephemeralPrivateKeyBytes, ReadOnlyMemory<byte> senderPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuMultiRecipientEncryptNistAsync(ECCurve.NamedCurves.nistP521, P521CurveOid, CryptoTags.P521ExchangePrivateKey, recipientPublicKey, ephemeralPrivateKeyBytes, senderPrivateKeyBytes, pool, cancellationToken);


    //Multi-recipient ECDH-ES (encrypt side) for the NIST curves: a SINGLE DH between the
    //caller-held ephemeral private key and this recipient's static public key, Z = Ze. The
    //ephemeral key is imported via SEC1 (CreateRecipientEcdh) so every provider derives a
    //valid public point from the scalar; the recipient point comes off the wire.
    private static async ValueTask<SharedSecret> EcdhEsMultiRecipientEncryptNistAsync(
        ECCurve namedCurve,
        string curveOid,
        Tag sharedSecretTag,
        PublicKeyMemory recipientPublicKey,
        ReadOnlyMemory<byte> ephemeralPrivateKeyBytes,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] recipientUncompressed = UncompressedPoint(recipientPublicKey);
        ReadOnlySpan<byte> recipientX = EllipticCurveUtilities.SliceXCoordinate(recipientUncompressed);
        ReadOnlySpan<byte> recipientY = EllipticCurveUtilities.SliceYCoordinate(recipientUncompressed);

        using ECDiffieHellman ephemeralEcdh = CreateRecipientEcdh(curveOid, ephemeralPrivateKeyBytes.Span);

        using ECDiffieHellman recipientEcdh = ECDiffieHellman.Create(new ECParameters
        {
            Curve = namedCurve,
            Q = new ECPoint
            {
                X = recipientX.ToArray(),
                Y = recipientY.ToArray()
            }
        });

        byte[] ze = ephemeralEcdh.DeriveRawSecretAgreement(recipientEcdh.PublicKey);

        try
        {
            await Task.CompletedTask.ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            IMemoryOwner<byte> zOwner = pool.Rent(ze.Length);
            ze.CopyTo(zOwner.Memory.Span);

            return new SharedSecret(zOwner, sharedSecretTag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ze);
        }
    }


    //Multi-recipient ECDH-1PU (encrypt side) for the NIST curves: Ze from the caller-held
    //ephemeral private key against this recipient's static public key, Zs from the sender's
    //static private key against the same recipient key, Z = Ze || Zs. Both private keys are
    //imported via SEC1 so the provider derives their public points.
    private static async ValueTask<SharedSecret> Ecdh1PuMultiRecipientEncryptNistAsync(
        ECCurve namedCurve,
        string curveOid,
        Tag sharedSecretTag,
        PublicKeyMemory recipientPublicKey,
        ReadOnlyMemory<byte> ephemeralPrivateKeyBytes,
        ReadOnlyMemory<byte> senderPrivateKeyBytes,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] recipientUncompressed = UncompressedPoint(recipientPublicKey);
        ReadOnlySpan<byte> recipientX = EllipticCurveUtilities.SliceXCoordinate(recipientUncompressed);
        ReadOnlySpan<byte> recipientY = EllipticCurveUtilities.SliceYCoordinate(recipientUncompressed);

        using ECDiffieHellman ephemeralEcdh = CreateRecipientEcdh(curveOid, ephemeralPrivateKeyBytes.Span);
        using ECDiffieHellman senderEcdh = CreateRecipientEcdh(curveOid, senderPrivateKeyBytes.Span);

        using ECDiffieHellman recipientEcdh = ECDiffieHellman.Create(new ECParameters
        {
            Curve = namedCurve,
            Q = new ECPoint
            {
                X = recipientX.ToArray(),
                Y = recipientY.ToArray()
            }
        });

        byte[] ze = ephemeralEcdh.DeriveRawSecretAgreement(recipientEcdh.PublicKey);
        byte[] zs = senderEcdh.DeriveRawSecretAgreement(recipientEcdh.PublicKey);

        try
        {
            await Task.CompletedTask.ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            IMemoryOwner<byte> zOwner = pool.Rent(ze.Length + zs.Length);
            ze.CopyTo(zOwner.Memory.Span);
            zs.CopyTo(zOwner.Memory.Span[ze.Length..]);

            return new SharedSecret(zOwner, sharedSecretTag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ze);
            CryptographicOperations.ZeroMemory(zs);
        }
    }


    //RFC 3394 §2.2.3: the fixed 64-bit initial value whose recovery proves key wrap integrity.
    private const ulong AesKwInitialValue = 0xA6A6A6A6A6A6A6A6UL;


    /// <summary>
    /// Wraps a key per <see href="https://www.rfc-editor.org/rfc/rfc3394">RFC 3394</see>
    /// AES Key Wrap. Matches <see cref="KeyWrapDelegate"/>.
    /// </summary>
    /// <remarks>
    /// The .NET platform exposes only the RFC 5649 padded variant
    /// (<c>EncryptKeyWrapPadded</c>); JOSE <c>A256KW</c> requires the unpadded RFC 3394
    /// algorithm, implemented here over single-block AES-ECB per RFC 3394 §2.2.1.
    /// </remarks>
    public static async ValueTask<Ciphertext> AesKeyWrapAsync(
        SymmetricKeyMemory keyEncryptionKey,
        SymmetricKeyMemory contentEncryptionKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyEncryptionKey);
        ArgumentNullException.ThrowIfNull(contentEncryptionKey);
        ArgumentNullException.ThrowIfNull(pool);

        await Task.CompletedTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        ReadOnlySpan<byte> keyData = contentEncryptionKey.AsReadOnlySpan();
        if(keyData.Length < 16 || keyData.Length % 8 != 0)
        {
            throw new ArgumentException(
                $"Key data to wrap must be at least 16 bytes and a multiple of 8 bytes. " +
                $"Received {keyData.Length} bytes.", nameof(contentEncryptionKey));
        }

        int n = keyData.Length / 8;
        IMemoryOwner<byte> wrappedOwner = pool.Rent(8 * (n + 1));
        Span<byte> wrapped = wrappedOwner.Memory.Span[..(8 * (n + 1))];

        //Register layout per RFC 3394 §2.2.1: A occupies the first block of the output
        //buffer, R[1]..R[n] the rest, so the final state is already the wrapped key.
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(wrapped, AesKwInitialValue);
        keyData.CopyTo(wrapped[8..]);

        Span<byte> block = stackalloc byte[16];
        try
        {
            using Aes aes = Aes.Create();

            //SetKey(ReadOnlySpan<byte>) copies the KEK into the AES instance's own key schedule — no
            //naked byte[] of key-encryption-key material for us to track and zero.
            aes.SetKey(keyEncryptionKey.AsReadOnlySpan());

            for(int j = 0; j <= 5; ++j)
            {
                for(int i = 1; i <= n; ++i)
                {
                    //B = AES(K, A | R[i]); A = MSB(B) ^ t where t = n*j + i; R[i] = LSB(B).
                    wrapped[..8].CopyTo(block);
                    wrapped.Slice(8 * i, 8).CopyTo(block[8..]);
                    aes.EncryptEcb(block, block, PaddingMode.None);

                    ulong t = (ulong)(n * j + i);
                    ulong a = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(block) ^ t;
                    System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(wrapped, a);
                    block[8..].CopyTo(wrapped.Slice(8 * i, 8));
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block);
        }

        return new Ciphertext(wrappedOwner, CryptoTags.AesKwWrappedKey);
    }


    /// <summary>
    /// Unwraps a key per <see href="https://www.rfc-editor.org/rfc/rfc3394">RFC 3394</see>
    /// AES Key Wrap. Matches <see cref="KeyUnwrapDelegate"/>.
    /// </summary>
    /// <exception cref="CryptographicException">
    /// Thrown when the RFC 3394 §2.2.3 integrity check fails.
    /// </exception>
    public static async ValueTask<SymmetricKeyMemory> AesKeyUnwrapAsync(
        SymmetricKeyMemory keyEncryptionKey,
        ReadOnlyMemory<byte> wrappedKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyEncryptionKey);
        ArgumentNullException.ThrowIfNull(pool);

        if(wrappedKey.Length < 24 || wrappedKey.Length % 8 != 0)
        {
            throw new ArgumentException(
                $"Wrapped key must be at least 24 bytes and a multiple of 8 bytes. " +
                $"Received {wrappedKey.Length} bytes.", nameof(wrappedKey));
        }

        await Task.CompletedTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        int n = wrappedKey.Length / 8 - 1;
        IMemoryOwner<byte> keyOwner = pool.Rent(8 * n);
        Span<byte> keyData = keyOwner.Memory.Span[..(8 * n)];
        wrappedKey.Span[8..].CopyTo(keyData);

        ulong a = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(wrappedKey.Span);

        Span<byte> block = stackalloc byte[16];
        try
        {
            using Aes aes = Aes.Create();

            //SetKey(ReadOnlySpan<byte>) copies the KEK into the AES instance's own key schedule — no
            //naked byte[] of key-encryption-key material for us to track and zero.
            aes.SetKey(keyEncryptionKey.AsReadOnlySpan());

            for(int j = 5; j >= 0; --j)
            {
                for(int i = n; i >= 1; --i)
                {
                    //B = AES-1(K, (A ^ t) | R[i]); A = MSB(B); R[i] = LSB(B).
                    ulong t = (ulong)(n * j + i);
                    System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(block, a ^ t);
                    keyData.Slice(8 * (i - 1), 8).CopyTo(block[8..]);
                    aes.DecryptEcb(block, block, PaddingMode.None);

                    a = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(block);
                    block[8..].CopyTo(keyData.Slice(8 * (i - 1), 8));
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block);
        }

        if(a != AesKwInitialValue)
        {
            keyData.Clear();
            keyOwner.Dispose();

            throw new CryptographicException("AES Key Wrap integrity check failed.");
        }

        return new SymmetricKeyMemory(keyOwner, CryptoTags.AesKwUnwrappedKey);
    }


    private const int AesCbcIvLength = 16;


    //RFC 7518 §5.2.3–§5.2.5 parameter sets for the AES_CBC_HMAC_SHA2 family. Each instance
    //states the composite key length K (MAC_KEY_LEN + ENC_KEY_LEN, equal halves), the truncated
    //tag length T_LEN, and the HMAC hash. One parameterized core (CbcHmacEncryptAsync /
    //CbcHmacDecryptAsync) services all three; the per-algorithm public entry points below bind a
    //parameter set so each matches the AeadEncryptDelegate / AeadDecryptDelegate shape.
    private readonly record struct AesCbcHmacParameters(int CompositeKeyLength, int TagLength, HashAlgorithmName Hmac);

    private static AesCbcHmacParameters A128CbcHs256Parameters { get; } = new(32, 16, HashAlgorithmName.SHA256);
    private static AesCbcHmacParameters A192CbcHs384Parameters { get; } = new(48, 24, HashAlgorithmName.SHA384);
    private static AesCbcHmacParameters A256CbcHs512Parameters { get; } = new(64, 32, HashAlgorithmName.SHA512);


    /// <summary>Performs A128CBC-HS256 authenticated encryption (RFC 7518 §5.2.3). Matches <see cref="AeadEncryptDelegate"/>.</summary>
    public static ValueTask<AeadEncryptResult> AesCbcHmacSha256EncryptAsync(
        ReadOnlyMemory<byte> plaintext, SymmetricKeyMemory key, AdditionalData aad, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        CbcHmacEncryptAsync(A128CbcHs256Parameters, plaintext, key, aad, pool, cancellationToken);

    /// <summary>Performs A128CBC-HS256 authenticated decryption (RFC 7518 §5.2.3). Matches <see cref="AeadDecryptDelegate"/>.</summary>
    public static ValueTask<DecryptedContent> AesCbcHmacSha256DecryptAsync(
        Ciphertext ciphertext, SymmetricKeyMemory key, Nonce iv, AuthenticationTag tag, AdditionalData aad, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        CbcHmacDecryptAsync(A128CbcHs256Parameters, ciphertext, key, iv, tag, aad, pool, cancellationToken);

    /// <summary>Performs A192CBC-HS384 authenticated encryption (RFC 7518 §5.2.4). Matches <see cref="AeadEncryptDelegate"/>.</summary>
    public static ValueTask<AeadEncryptResult> AesCbcHmacSha384EncryptAsync(
        ReadOnlyMemory<byte> plaintext, SymmetricKeyMemory key, AdditionalData aad, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        CbcHmacEncryptAsync(A192CbcHs384Parameters, plaintext, key, aad, pool, cancellationToken);

    /// <summary>Performs A192CBC-HS384 authenticated decryption (RFC 7518 §5.2.4). Matches <see cref="AeadDecryptDelegate"/>.</summary>
    public static ValueTask<DecryptedContent> AesCbcHmacSha384DecryptAsync(
        Ciphertext ciphertext, SymmetricKeyMemory key, Nonce iv, AuthenticationTag tag, AdditionalData aad, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        CbcHmacDecryptAsync(A192CbcHs384Parameters, ciphertext, key, iv, tag, aad, pool, cancellationToken);

    /// <summary>
    /// Performs A256CBC-HS512 authenticated encryption per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.2.5">RFC 7518 §5.2.5</see>.
    /// Matches <see cref="AeadEncryptDelegate"/>.
    /// </summary>
    /// <remarks>
    /// The 64-byte composite key splits per RFC 7518 §5.2.2.1 into the initial 32 bytes
    /// of HMAC-SHA-512 key and the final 32 bytes of AES-256-CBC key. The tag is the
    /// initial 32 bytes of HMAC over AAD || IV || ciphertext || AL, where AL is the
    /// 64-bit big-endian bit length of the AAD.
    /// </remarks>
    public static ValueTask<AeadEncryptResult> AesCbcHmacSha512EncryptAsync(
        ReadOnlyMemory<byte> plaintext, SymmetricKeyMemory key, AdditionalData aad, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        CbcHmacEncryptAsync(A256CbcHs512Parameters, plaintext, key, aad, pool, cancellationToken);

    /// <summary>
    /// Performs A256CBC-HS512 authenticated decryption per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.2.5">RFC 7518 §5.2.5</see>.
    /// Matches <see cref="AeadDecryptDelegate"/>.
    /// </summary>
    /// <exception cref="CryptographicException">
    /// Thrown when authentication tag verification fails. The tag is verified before
    /// any decryption is attempted.
    /// </exception>
    public static ValueTask<DecryptedContent> AesCbcHmacSha512DecryptAsync(
        Ciphertext ciphertext, SymmetricKeyMemory key, Nonce iv, AuthenticationTag tag, AdditionalData aad, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        CbcHmacDecryptAsync(A256CbcHs512Parameters, ciphertext, key, iv, tag, aad, pool, cancellationToken);


    //Parameterized AES_CBC_HMAC_SHA2 encryption (RFC 7518 §5.2.2.1) over a parameter set. The
    //composite key splits into the initial MAC_KEY_LEN MAC half and the final ENC_KEY_LEN AES
    //half (RFC 7518 §5.2.2.1 step 1); the IV is one AES block; the tag is the first T_LEN octets
    //of HMAC over AAD || IV || ciphertext || AL.
    private static async ValueTask<AeadEncryptResult> CbcHmacEncryptAsync(
        AesCbcHmacParameters parameters,
        ReadOnlyMemory<byte> plaintext,
        SymmetricKeyMemory key,
        AdditionalData aad,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(aad);
        ArgumentNullException.ThrowIfNull(pool);

        await Task.CompletedTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        ReadOnlySpan<byte> compositeKey = key.AsReadOnlySpan();
        if(compositeKey.Length != parameters.CompositeKeyLength)
        {
            throw new ArgumentException(
                $"{parameters.Hmac} AES_CBC_HMAC_SHA2 requires a {parameters.CompositeKeyLength}-byte " +
                $"composite key. Received {compositeKey.Length} bytes.", nameof(key));
        }

        int halfLength = parameters.CompositeKeyLength / 2;
        ReadOnlySpan<byte> macKey = compositeKey[..halfLength];
        ReadOnlySpan<byte> encKey = compositeKey[halfLength..];

        IMemoryOwner<byte> ivOwner = pool.Rent(AesCbcIvLength);
        RandomNumberGenerator.Fill(ivOwner.Memory.Span[..AesCbcIvLength]);

        //PKCS#7 always pads, so the ciphertext is the plaintext rounded up to the
        //next full 16-byte block boundary.
        int ciphertextLength = plaintext.Length - (plaintext.Length % 16) + 16;
        IMemoryOwner<byte> ciphertextOwner = pool.Rent(ciphertextLength);

        using(Aes aes = Aes.Create())
        {
            //SetKey(ReadOnlySpan<byte>) copies the AES half of the composite key into the AES
            //instance's own key schedule — encKey is already a span slice of the composite key, so no
            //array copy exists to zero.
            aes.SetKey(encKey);
            aes.EncryptCbc(
                plaintext.Span,
                ivOwner.Memory.Span[..AesCbcIvLength],
                ciphertextOwner.Memory.Span[..ciphertextLength],
                PaddingMode.PKCS7);
        }

        IMemoryOwner<byte> tagOwner = pool.Rent(parameters.TagLength);
        ComputeCbcHmacTag(
            parameters,
            macKey,
            aad.AsReadOnlySpan(),
            ivOwner.Memory.Span[..AesCbcIvLength],
            ciphertextOwner.Memory.Span[..ciphertextLength],
            tagOwner.Memory.Span[..parameters.TagLength]);

        return new AeadEncryptResult(
            new Nonce(ivOwner, CryptoTags.AesCbcHmacIv),
            new Ciphertext(ciphertextOwner, CryptoTags.AesCbcHmacCiphertext),
            new AuthenticationTag(tagOwner, CryptoTags.AesCbcHmacAuthTag));
    }


    //Parameterized AES_CBC_HMAC_SHA2 decryption (RFC 7518 §5.2.2.2). The tag is verified before
    //any decryption is attempted (step 2 precedes step 3); a mismatch returns no plaintext.
    private static async ValueTask<DecryptedContent> CbcHmacDecryptAsync(
        AesCbcHmacParameters parameters,
        Ciphertext ciphertext,
        SymmetricKeyMemory key,
        Nonce iv,
        AuthenticationTag tag,
        AdditionalData aad,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(iv);
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(aad);
        ArgumentNullException.ThrowIfNull(pool);

        await Task.CompletedTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        ReadOnlySpan<byte> compositeKey = key.AsReadOnlySpan();
        if(compositeKey.Length != parameters.CompositeKeyLength)
        {
            throw new ArgumentException(
                $"{parameters.Hmac} AES_CBC_HMAC_SHA2 requires a {parameters.CompositeKeyLength}-byte " +
                $"composite key. Received {compositeKey.Length} bytes.", nameof(key));
        }

        int halfLength = parameters.CompositeKeyLength / 2;
        ReadOnlySpan<byte> macKey = compositeKey[..halfLength];
        ReadOnlySpan<byte> encKey = compositeKey[halfLength..];
        ReadOnlySpan<byte> ciphertextSpan = ciphertext.AsReadOnlySpan();

        Span<byte> expectedTag = stackalloc byte[parameters.TagLength];
        ComputeCbcHmacTag(parameters, macKey, aad.AsReadOnlySpan(), iv.AsReadOnlySpan(), ciphertextSpan, expectedTag);

        bool isAuthentic = CryptographicOperations.FixedTimeEquals(expectedTag, tag.AsReadOnlySpan());
        CryptographicOperations.ZeroMemory(expectedTag);
        if(!isAuthentic)
        {
            throw new CryptographicException(
                $"{parameters.Hmac} AES_CBC_HMAC_SHA2 authentication tag verification failed.");
        }

        //CBC decryption removes PKCS#7 padding, so the plaintext is shorter than the
        //ciphertext by an amount known only after decryption. Decrypt into a scratch
        //buffer and copy into an exact-length allocation so the returned content
        //carries no padding residue.
        IMemoryOwner<byte> scratchOwner = pool.Rent(ciphertextSpan.Length);
        try
        {
            int plaintextLength;
            using(Aes aes = Aes.Create())
            {
                //SetKey(ReadOnlySpan<byte>) copies the AES half of the composite key into the AES
                //instance's own key schedule — encKey is already a span slice of the composite key, so
                //no array copy exists to zero.
                aes.SetKey(encKey);
                plaintextLength = aes.DecryptCbc(
                    ciphertextSpan,
                    iv.AsReadOnlySpan(),
                    scratchOwner.Memory.Span[..ciphertextSpan.Length],
                    PaddingMode.PKCS7);
            }

            IMemoryOwner<byte> plaintextOwner = pool.Rent(plaintextLength);
            scratchOwner.Memory.Span[..plaintextLength].CopyTo(plaintextOwner.Memory.Span);

            return new DecryptedContent(plaintextOwner, CryptoTags.AesCbcHmacDecryptedContent);
        }
        finally
        {
            scratchOwner.Memory.Span.Clear();
            scratchOwner.Dispose();
        }
    }


    //The RFC 7518 §5.2.2.1 MAC input is AAD || IV || ciphertext || AL with AL the
    //64-bit big-endian count of AAD bits; the tag is the initial T_LEN octets of the
    //parameter set's HMAC output.
    private static void ComputeCbcHmacTag(
        AesCbcHmacParameters parameters,
        ReadOnlySpan<byte> macKey,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> tagDestination)
    {
        Span<byte> al = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(al, (ulong)aad.Length * 8);

        Span<byte> fullMac = stackalloc byte[HMACSHA512.HashSizeInBytes];
        using(IncrementalHash hmac = IncrementalHash.CreateHMAC(parameters.Hmac, macKey))
        {
            hmac.AppendData(aad);
            hmac.AppendData(iv);
            hmac.AppendData(ciphertext);
            hmac.AppendData(al);
            int written = hmac.GetHashAndReset(fullMac);
            fullMac[..tagDestination.Length].CopyTo(tagDestination);
            CryptographicOperations.ZeroMemory(fullMac[..written]);
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