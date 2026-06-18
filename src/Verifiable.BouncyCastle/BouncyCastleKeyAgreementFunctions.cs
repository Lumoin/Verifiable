using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;

namespace Verifiable.BouncyCastle;

/// <summary>
/// ECDH-ES key agreement and AES-GCM symmetric encryption and decryption using the
/// BouncyCastle library.
/// </summary>
/// <remarks>
/// <para>
/// Each method matches exactly one delegate from the split set in
/// <c>Verifiable.Cryptography.Aead</c>:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see cref="EcdhKeyAgreementEncryptP256Async"/> →
/// <see cref="KeyAgreementEncryptDelegate"/>: ECDH only, returns
/// <see cref="EphemeralKeyAgreementResult"/>.
/// </description></item>
/// <item><description>
/// <see cref="EcdhKeyAgreementDecryptP256Async"/> →
/// <see cref="KeyAgreementDecryptDelegate"/>: ECDH only, returns
/// <see cref="SharedSecret"/>.
/// </description></item>
/// <item><description>
/// <see cref="AesGcmEncryptAsync"/> → <see cref="AeadEncryptDelegate"/>: AES-GCM only,
/// returns <see cref="AeadEncryptResult"/>.
/// </description></item>
/// <item><description>
/// <see cref="AesGcmDecryptAsync"/> → <see cref="AeadDecryptDelegate"/>: AES-GCM only,
/// returns <see cref="DecryptedContent"/>.
/// </description></item>
/// </list>
/// <para>
/// Key derivation uses <see cref="ConcatKdf"/> directly — it is pure software math
/// and does not require a backend-specific implementation.
/// </para>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "Ownership of returned types transfers to the caller.")]
public static class BouncyCastleKeyAgreementFunctions
{
    private const int AesGcmTagLength = 16;
    private const int AesGcmIvLength = 12;

    private static readonly ProviderLibrary ProviderLib = new(
        typeof(BouncyCastleKeyAgreementFunctions).Assembly.GetName().Name ?? "Verifiable.BouncyCastle",
        typeof(BouncyCastleKeyAgreementFunctions).Assembly.GetName().Version?.ToString() ?? "Unknown");

    //BouncyCastle is an independently versioned NuGet package — its assembly
    //version is the most meaningful CBOM identifier.
    private static readonly CryptoLibraryInfo CryptoLib = new(
        "Org.BouncyCastle.Cryptography",
        typeof(Org.BouncyCastle.Security.SecureRandom).Assembly.GetName().Version?.ToString() ?? "Unknown");

    private static readonly ProviderClass ProviderCls = new(nameof(BouncyCastleKeyAgreementFunctions));


    /// <summary>
    /// Performs ECDH key agreement on the encrypt side using P-256.
    /// Matches <see cref="KeyAgreementEncryptDelegate"/>.
    /// </summary>
    /// <remarks>
    /// Generates an ephemeral P-256 key pair, computes the shared secret Z via
    /// <c>ECDHBasicAgreement</c>, and returns Z together with the ephemeral public
    /// key coordinates. The caller derives the CEK separately using
    /// <see cref="ConcatKdf"/> and encrypts with <see cref="AesGcmEncryptAsync"/>.
    /// </remarks>
    /// <param name="recipientPublicKey">
    /// The recipient's P-256 public key in uncompressed point encoding
    /// (<c>0x04 || X || Y</c>) as produced by <c>CreateP256ExchangeKeys</c>.
    /// </param>
    /// <param name="pool">Memory pool for shared secret and EPK coordinate allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The shared secret Z and ephemeral public key coordinates. The caller must zero
    /// the shared secret and dispose immediately after CEK derivation.
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
            activity.SetTag(CryptoTelemetry.Key.Curve, "P-256");
        }

        var secCurve = SecNamedCurves.GetByName("secp256r1");
        var domainParams = new ECDomainParameters(
            secCurve.Curve, secCurve.G, secCurve.N, secCurve.H, secCurve.GetSeed());

        var keyPairGen = new ECKeyPairGenerator();
        keyPairGen.Init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));

        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair ephemeralPair =
            keyPairGen.GenerateKeyPair();
        var ephemeralPublic = (ECPublicKeyParameters)ephemeralPair.Public;
        var ephemeralPrivate = (ECPrivateKeyParameters)ephemeralPair.Private;

        //BouncyCastle's DecodePoint accepts both compressed (0x02/0x03 || X) and uncompressed
        //(0x04 || X || Y) SEC1 encoding — pass the key bytes directly in whatever format they
        //are stored in. The EncodingScheme tag is metadata for library routing, not a constraint
        //on what this function accepts.
        var recipientEcPoint = secCurve.Curve.DecodePoint(recipientPublicKey.AsReadOnlySpan().ToArray());
        var recipientParam = new ECPublicKeyParameters(recipientEcPoint, domainParams);

        var agreement = new ECDHBasicAgreement();
        agreement.Init(ephemeralPrivate);
        BigInteger z = agreement.CalculateAgreement(recipientParam);
        byte[] zRaw = z.ToByteArrayUnsigned();

        try
        {
            //The key agreement could be a remote TPM call in hardware implementations —
            //this is the await point the async signature exists to support.
            await Task.CompletedTask.ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            IMemoryOwner<byte> zOwner = pool.Rent(32);
            zOwner.Memory.Span.Clear();

            if(zRaw.Length < 32)
            {
                zRaw.CopyTo(zOwner.Memory.Span[(32 - zRaw.Length)..]);
            }
            else
            {
                zRaw.AsSpan(0, 32).CopyTo(zOwner.Memory.Span);
            }

            var sharedSecret = new SharedSecret(zOwner, CryptoTags.P256ExchangePrivateKey);

            //Store the ephemeral public key as a single uncompressed point: 0x04 || X || Y.
            byte[] ephemeralUncompressed = ephemeralPublic.Q.GetEncoded(compressed: false);
            IMemoryOwner<byte> epkOwner = pool.Rent(ephemeralUncompressed.Length);
            ephemeralUncompressed.AsSpan().CopyTo(epkOwner.Memory.Span);
            Array.Clear(ephemeralUncompressed, 0, ephemeralUncompressed.Length);

            PublicKeyMemory epk = new PublicKeyMemory(epkOwner, CryptoTags.P256ExchangePublicKey);

            return new EphemeralKeyAgreementResult(sharedSecret, epk);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(zRaw);
        }
    }


    /// <summary>
    /// Performs ECDH key agreement on the decrypt side using P-256.
    /// Matches <see cref="KeyAgreementDecryptDelegate"/>.
    /// </summary>
    /// <remarks>
    /// Computes the shared secret Z from the recipient's private key scalar and the
    /// sender's ephemeral public key. The caller derives the CEK separately using
    /// <see cref="ConcatKdf"/> and decrypts with <see cref="AesGcmDecryptAsync"/>.
    /// </remarks>
    /// <param name="privateKeyBytes">
    /// The recipient's P-256 private key scalar (32 bytes, big-endian), unwrapped from
    /// <see cref="PrivateKeyMemory"/>. Must not be stored after this method returns.
    /// </param>
    /// <param name="epk">
    /// The sender's ephemeral P-256 public key in uncompressed encoding:
    /// <c>0x04 || X (32 bytes) || Y (32 bytes)</c>.
    /// </param>
    /// <param name="pool">Memory pool for the shared secret allocation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The shared secret Z. The caller must zero and dispose immediately after CEK derivation.
    /// </returns>
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
            activity.SetTag(CryptoTelemetry.Key.Curve, "P-256");
        }

        var curve = SecNamedCurves.GetByName("secp256r1");
        var domainParams = new ECDomainParameters(
            curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

        //Feed the caller's scalar span straight to BigInteger, which copies it into its
        //own immutable magnitude — no naked byte[] copy of private-key material for us to
        //track and zero, and the caller's buffer is never touched.
        var privateKeyParam = new ECPrivateKeyParameters(
            new BigInteger(1, privateKeyBytes.Span),
            domainParams);

        //Decode the uncompressed point directly — no need to split X and Y first.
        var ecPoint = curve.Curve.DecodePoint(epk.AsReadOnlySpan().ToArray());
        var epkParam = new ECPublicKeyParameters(ecPoint, domainParams);

        var agreement = new ECDHBasicAgreement();
        agreement.Init(privateKeyParam);
        BigInteger z = agreement.CalculateAgreement(epkParam);
        byte[] zRaw = z.ToByteArrayUnsigned();

        IMemoryOwner<byte> zOwner = pool.Rent(32);
        zOwner.Memory.Span.Clear();

        if(zRaw.Length < 32)
        {
            zRaw.CopyTo(zOwner.Memory.Span[(32 - zRaw.Length)..]);
        }
        else
        {
            zRaw.AsSpan(0, 32).CopyTo(zOwner.Memory.Span);
        }

        CryptographicOperations.ZeroMemory(zRaw);

        return ValueTask.FromResult(
            new SharedSecret(zOwner, CryptoTags.P256ExchangePrivateKey));
    }


    /// <summary>Performs ECDH key agreement (encrypt side) using Brainpool P-256r1 (RFC 5639). Matches <see cref="KeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<EphemeralKeyAgreementResult> EcdhKeyAgreementEncryptBrainpoolP256r1Async(
        PublicKeyMemory recipientPublicKey, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhEncryptBrainpoolAsync("brainpoolP256r1", 32, CryptoTags.BrainpoolP256r1ExchangePublicKey, CryptoTags.BrainpoolP256r1ExchangePrivateKey, recipientPublicKey, pool, cancellationToken);

    /// <summary>Performs ECDH key agreement (decrypt side) using Brainpool P-256r1 (RFC 5639). Matches <see cref="KeyAgreementDecryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> EcdhKeyAgreementDecryptBrainpoolP256r1Async(
        ReadOnlyMemory<byte> privateKeyBytes, PublicKeyMemory epk, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhDecryptBrainpoolAsync("brainpoolP256r1", 32, CryptoTags.BrainpoolP256r1ExchangePrivateKey, privateKeyBytes, epk, pool, cancellationToken);

    /// <summary>Performs ECDH key agreement (encrypt side) using Brainpool P-320r1 (RFC 5639). Matches <see cref="KeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<EphemeralKeyAgreementResult> EcdhKeyAgreementEncryptBrainpoolP320r1Async(
        PublicKeyMemory recipientPublicKey, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhEncryptBrainpoolAsync("brainpoolP320r1", 40, CryptoTags.BrainpoolP320r1ExchangePublicKey, CryptoTags.BrainpoolP320r1ExchangePrivateKey, recipientPublicKey, pool, cancellationToken);

    /// <summary>Performs ECDH key agreement (decrypt side) using Brainpool P-320r1 (RFC 5639). Matches <see cref="KeyAgreementDecryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> EcdhKeyAgreementDecryptBrainpoolP320r1Async(
        ReadOnlyMemory<byte> privateKeyBytes, PublicKeyMemory epk, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhDecryptBrainpoolAsync("brainpoolP320r1", 40, CryptoTags.BrainpoolP320r1ExchangePrivateKey, privateKeyBytes, epk, pool, cancellationToken);

    /// <summary>Performs ECDH key agreement (encrypt side) using Brainpool P-384r1 (RFC 5639). Matches <see cref="KeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<EphemeralKeyAgreementResult> EcdhKeyAgreementEncryptBrainpoolP384r1Async(
        PublicKeyMemory recipientPublicKey, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhEncryptBrainpoolAsync("brainpoolP384r1", 48, CryptoTags.BrainpoolP384r1ExchangePublicKey, CryptoTags.BrainpoolP384r1ExchangePrivateKey, recipientPublicKey, pool, cancellationToken);

    /// <summary>Performs ECDH key agreement (decrypt side) using Brainpool P-384r1 (RFC 5639). Matches <see cref="KeyAgreementDecryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> EcdhKeyAgreementDecryptBrainpoolP384r1Async(
        ReadOnlyMemory<byte> privateKeyBytes, PublicKeyMemory epk, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhDecryptBrainpoolAsync("brainpoolP384r1", 48, CryptoTags.BrainpoolP384r1ExchangePrivateKey, privateKeyBytes, epk, pool, cancellationToken);

    /// <summary>Performs ECDH key agreement (encrypt side) using Brainpool P-512r1 (RFC 5639). Matches <see cref="KeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<EphemeralKeyAgreementResult> EcdhKeyAgreementEncryptBrainpoolP512r1Async(
        PublicKeyMemory recipientPublicKey, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhEncryptBrainpoolAsync("brainpoolP512r1", 64, CryptoTags.BrainpoolP512r1ExchangePublicKey, CryptoTags.BrainpoolP512r1ExchangePrivateKey, recipientPublicKey, pool, cancellationToken);

    /// <summary>Performs ECDH key agreement (decrypt side) using Brainpool P-512r1 (RFC 5639). Matches <see cref="KeyAgreementDecryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> EcdhKeyAgreementDecryptBrainpoolP512r1Async(
        ReadOnlyMemory<byte> privateKeyBytes, PublicKeyMemory epk, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhDecryptBrainpoolAsync("brainpoolP512r1", 64, CryptoTags.BrainpoolP512r1ExchangePrivateKey, privateKeyBytes, epk, pool, cancellationToken);


    /// <summary>Performs ECDH key agreement (encrypt side) using NIST P-384 (RFC 7518 §6.2.1.2). Matches <see cref="KeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<EphemeralKeyAgreementResult> EcdhKeyAgreementEncryptP384Async(
        PublicKeyMemory recipientPublicKey, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhEncryptNistAsync("secp384r1", 48, CryptoTags.P384ExchangePublicKey, CryptoTags.P384ExchangePrivateKey, recipientPublicKey, pool, cancellationToken);

    /// <summary>Performs ECDH key agreement (decrypt side) using NIST P-384 (RFC 7518 §6.2.1.2). Matches <see cref="KeyAgreementDecryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> EcdhKeyAgreementDecryptP384Async(
        ReadOnlyMemory<byte> privateKeyBytes, PublicKeyMemory epk, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhDecryptNistAsync("secp384r1", 48, CryptoTags.P384ExchangePrivateKey, privateKeyBytes, epk, pool, cancellationToken);

    /// <summary>Performs ECDH key agreement (encrypt side) using NIST P-521 (RFC 7518 §6.2.1.3). Matches <see cref="KeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<EphemeralKeyAgreementResult> EcdhKeyAgreementEncryptP521Async(
        PublicKeyMemory recipientPublicKey, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhEncryptNistAsync("secp521r1", 66, CryptoTags.P521ExchangePublicKey, CryptoTags.P521ExchangePrivateKey, recipientPublicKey, pool, cancellationToken);

    /// <summary>Performs ECDH key agreement (decrypt side) using NIST P-521 (RFC 7518 §6.2.1.3). Matches <see cref="KeyAgreementDecryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> EcdhKeyAgreementDecryptP521Async(
        ReadOnlyMemory<byte> privateKeyBytes, PublicKeyMemory epk, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhDecryptNistAsync("secp521r1", 66, CryptoTags.P521ExchangePrivateKey, privateKeyBytes, epk, pool, cancellationToken);


    /// <summary>
    /// Performs X25519 key agreement (encrypt side) per RFC 7748 / RFC 8037. Matches
    /// <see cref="KeyAgreementEncryptDelegate"/>.
    /// </summary>
    /// <remarks>
    /// Generates an ephemeral X25519 key pair, computes the 32-byte shared secret, and
    /// returns it together with the raw 32-byte ephemeral public key (OKP — no point
    /// prefix or second coordinate). Montgomery-curve agreement clamps the scalar, so
    /// there is no separate point-on-curve validation step.
    /// </remarks>
    public static async ValueTask<EphemeralKeyAgreementResult> EcdhKeyAgreementEncryptX25519Async(
        PublicKeyMemory recipientPublicKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        ProviderOperation operation = new(nameof(EcdhKeyAgreementEncryptX25519Async));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyAgreement);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Key.Algorithm, "X25519");
        }

        var keyPairGenerator = new X25519KeyPairGenerator();
        keyPairGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom()));
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair ephemeralPair = keyPairGenerator.GenerateKeyPair();
        var ephemeralPrivate = (X25519PrivateKeyParameters)ephemeralPair.Private;
        var ephemeralPublic = (X25519PublicKeyParameters)ephemeralPair.Public;

        var recipientPublic = new X25519PublicKeyParameters(recipientPublicKey.AsReadOnlySpan());

        var agreement = new X25519Agreement();
        agreement.Init(ephemeralPrivate);

        await Task.CompletedTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        //Write the 32-byte shared secret straight into pooled memory the SharedSecret owns
        //and zeroes on dispose — no naked byte[] of secret material at any point.
        IMemoryOwner<byte> zOwner = pool.Rent(agreement.AgreementSize);
        agreement.CalculateAgreement(recipientPublic, zOwner.Memory.Span[..agreement.AgreementSize]);
        var sharedSecret = new SharedSecret(zOwner, CryptoTags.X25519PrivateKey);

        //The ephemeral public key is the raw 32-byte OKP key (public, not sensitive).
        byte[] ephemeralEncoded = ephemeralPublic.GetEncoded();
        IMemoryOwner<byte> epkOwner = pool.Rent(ephemeralEncoded.Length);
        ephemeralEncoded.AsSpan().CopyTo(epkOwner.Memory.Span);

        var epk = new PublicKeyMemory(epkOwner, CryptoTags.X25519PublicKey);
        return new EphemeralKeyAgreementResult(sharedSecret, epk);
    }


    /// <summary>
    /// Performs X25519 key agreement (decrypt side) per RFC 7748 / RFC 8037. Matches
    /// <see cref="KeyAgreementDecryptDelegate"/>.
    /// </summary>
    public static ValueTask<SharedSecret> EcdhKeyAgreementDecryptX25519Async(
        ReadOnlyMemory<byte> privateKeyBytes,
        PublicKeyMemory epk,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(epk);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        ProviderOperation operation = new(nameof(EcdhKeyAgreementDecryptX25519Async));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyAgreement);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Key.Algorithm, "X25519");
        }

        //The span ctor copies the scalar into BouncyCastle's own buffer — no naked
        //byte[] of private-key material for us to track, and the caller's buffer is untouched.
        var privateKeyParam = new X25519PrivateKeyParameters(privateKeyBytes.Span);
        var epkParam = new X25519PublicKeyParameters(epk.AsReadOnlySpan());

        var agreement = new X25519Agreement();
        agreement.Init(privateKeyParam);

        //Write the 32-byte shared secret straight into pooled memory — no naked byte[].
        IMemoryOwner<byte> zOwner = pool.Rent(agreement.AgreementSize);
        agreement.CalculateAgreement(epkParam, zOwner.Memory.Span[..agreement.AgreementSize]);

        return ValueTask.FromResult(new SharedSecret(zOwner, CryptoTags.X25519PrivateKey));
    }


    //Curve-parameterized ECDH for the NIST SEC curves (P-384/P-521). Same
    //ECDHBasicAgreement math as the inline P-256 path; the curve resolves through
    //SecNamedCurves and the shared secret Z is left-padded to the curve's field size
    //(48 / 66 bytes) so both sides derive byte-identical input to the KDF. The 521-bit
    //field rounds up to 66 bytes, which is the place an off-by-one pad would bite.
    private static async ValueTask<EphemeralKeyAgreementResult> EcdhEncryptNistAsync(
        string curveName,
        int sharedSecretSize,
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
            activity.SetTag(CryptoTelemetry.Key.Curve, MapCurveDisplay(curveName));
        }

        X9ECParameters curve = SecNamedCurves.GetByName(curveName)
            ?? throw new NotSupportedException($"NIST curve '{curveName}' is not registered in BouncyCastle.");
        var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

        var keyPairGen = new ECKeyPairGenerator();
        keyPairGen.Init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair ephemeralPair = keyPairGen.GenerateKeyPair();
        var ephemeralPrivate = (ECPrivateKeyParameters)ephemeralPair.Private;
        var ephemeralPublic = (ECPublicKeyParameters)ephemeralPair.Public;

        var recipientPoint = curve.Curve.DecodePoint(recipientPublicKey.AsReadOnlySpan().ToArray());
        var recipientParam = new ECPublicKeyParameters(recipientPoint, domainParams);

        var agreement = new ECDHBasicAgreement();
        agreement.Init(ephemeralPrivate);
        BigInteger z = agreement.CalculateAgreement(recipientParam);
        byte[] zRaw = z.ToByteArrayUnsigned();

        try
        {
            await Task.CompletedTask.ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            IMemoryOwner<byte> zOwner = pool.Rent(sharedSecretSize);
            zOwner.Memory.Span[..sharedSecretSize].Clear();
            CopyLeftPadded(zRaw, zOwner.Memory.Span[..sharedSecretSize]);
            var sharedSecret = new SharedSecret(zOwner, sharedSecretTag);

            byte[] ephemeralUncompressed = ephemeralPublic.Q.GetEncoded(compressed: false);
            IMemoryOwner<byte> epkOwner = pool.Rent(ephemeralUncompressed.Length);
            ephemeralUncompressed.AsSpan().CopyTo(epkOwner.Memory.Span);
            Array.Clear(ephemeralUncompressed, 0, ephemeralUncompressed.Length);

            var epk = new PublicKeyMemory(epkOwner, epkTag);
            return new EphemeralKeyAgreementResult(sharedSecret, epk);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(zRaw);
        }
    }


    private static ValueTask<SharedSecret> EcdhDecryptNistAsync(
        string curveName,
        int sharedSecretSize,
        Tag sharedSecretTag,
        ReadOnlyMemory<byte> privateKeyBytes,
        PublicKeyMemory epk,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(epk);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        ProviderOperation operation = new(nameof(EcdhDecryptNistAsync));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyAgreement);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Key.Algorithm, "ECDH");
            activity.SetTag(CryptoTelemetry.Key.Curve, MapCurveDisplay(curveName));
        }

        X9ECParameters curve = SecNamedCurves.GetByName(curveName)
            ?? throw new NotSupportedException($"NIST curve '{curveName}' is not registered in BouncyCastle.");
        var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

        //Feed the caller's scalar span straight to BigInteger, which copies it into its
        //own immutable magnitude — no naked byte[] copy of private-key material for us to
        //track and zero, and the caller's buffer is never touched.
        var privateKeyParam = new ECPrivateKeyParameters(
            new BigInteger(1, privateKeyBytes.Span), domainParams);
        var ecPoint = curve.Curve.DecodePoint(epk.AsReadOnlySpan().ToArray());
        var epkParam = new ECPublicKeyParameters(ecPoint, domainParams);

        var agreement = new ECDHBasicAgreement();
        agreement.Init(privateKeyParam);
        BigInteger z = agreement.CalculateAgreement(epkParam);
        byte[] zRaw = z.ToByteArrayUnsigned();

        IMemoryOwner<byte> zOwner = pool.Rent(sharedSecretSize);
        zOwner.Memory.Span[..sharedSecretSize].Clear();
        CopyLeftPadded(zRaw, zOwner.Memory.Span[..sharedSecretSize]);
        CryptographicOperations.ZeroMemory(zRaw);

        return ValueTask.FromResult(new SharedSecret(zOwner, sharedSecretTag));
    }


    //Curve-parameterized ECDH for the RFC 5639 Brainpool r1 curves. Same
    //ECDHBasicAgreement math as the P-256 path; the curve resolves through
    //ECNamedCurveTable (TeleTrust namespace) and the shared secret Z is padded
    //to the curve's field size so both sides derive byte-identical input to the KDF.
    private static async ValueTask<EphemeralKeyAgreementResult> EcdhEncryptBrainpoolAsync(
        string curveName,
        int sharedSecretSize,
        Tag epkTag,
        Tag sharedSecretTag,
        PublicKeyMemory recipientPublicKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        ProviderOperation operation = new(nameof(EcdhEncryptBrainpoolAsync));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyAgreement);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Key.Algorithm, "ECDH");
            activity.SetTag(CryptoTelemetry.Key.Curve, MapCurveDisplay(curveName));
        }

        X9ECParameters curve = ECNamedCurveTable.GetByName(curveName)
            ?? throw new NotSupportedException($"Brainpool curve '{curveName}' is not registered in BouncyCastle.");
        var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

        var keyPairGen = new ECKeyPairGenerator();
        keyPairGen.Init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair ephemeralPair = keyPairGen.GenerateKeyPair();
        var ephemeralPrivate = (ECPrivateKeyParameters)ephemeralPair.Private;
        var ephemeralPublic = (ECPublicKeyParameters)ephemeralPair.Public;

        var recipientPoint = curve.Curve.DecodePoint(recipientPublicKey.AsReadOnlySpan().ToArray());
        var recipientParam = new ECPublicKeyParameters(recipientPoint, domainParams);

        var agreement = new ECDHBasicAgreement();
        agreement.Init(ephemeralPrivate);
        BigInteger z = agreement.CalculateAgreement(recipientParam);
        byte[] zRaw = z.ToByteArrayUnsigned();

        try
        {
            await Task.CompletedTask.ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            IMemoryOwner<byte> zOwner = pool.Rent(sharedSecretSize);
            zOwner.Memory.Span[..sharedSecretSize].Clear();
            CopyLeftPadded(zRaw, zOwner.Memory.Span[..sharedSecretSize]);
            var sharedSecret = new SharedSecret(zOwner, sharedSecretTag);

            byte[] ephemeralUncompressed = ephemeralPublic.Q.GetEncoded(compressed: false);
            IMemoryOwner<byte> epkOwner = pool.Rent(ephemeralUncompressed.Length);
            ephemeralUncompressed.AsSpan().CopyTo(epkOwner.Memory.Span);
            Array.Clear(ephemeralUncompressed, 0, ephemeralUncompressed.Length);

            var epk = new PublicKeyMemory(epkOwner, epkTag);
            return new EphemeralKeyAgreementResult(sharedSecret, epk);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(zRaw);
        }
    }


    private static ValueTask<SharedSecret> EcdhDecryptBrainpoolAsync(
        string curveName,
        int sharedSecretSize,
        Tag sharedSecretTag,
        ReadOnlyMemory<byte> privateKeyBytes,
        PublicKeyMemory epk,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(epk);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        ProviderOperation operation = new(nameof(EcdhDecryptBrainpoolAsync));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyAgreement);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Key.Algorithm, "ECDH");
            activity.SetTag(CryptoTelemetry.Key.Curve, MapCurveDisplay(curveName));
        }

        X9ECParameters curve = ECNamedCurveTable.GetByName(curveName)
            ?? throw new NotSupportedException($"Brainpool curve '{curveName}' is not registered in BouncyCastle.");
        var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

        //Feed the caller's scalar span straight to BigInteger, which copies it into its
        //own immutable magnitude — no naked byte[] copy of private-key material for us to
        //track and zero, and the caller's buffer is never touched.
        var privateKeyParam = new ECPrivateKeyParameters(
            new BigInteger(1, privateKeyBytes.Span), domainParams);
        var ecPoint = curve.Curve.DecodePoint(epk.AsReadOnlySpan().ToArray());
        var epkParam = new ECPublicKeyParameters(ecPoint, domainParams);

        var agreement = new ECDHBasicAgreement();
        agreement.Init(privateKeyParam);
        BigInteger z = agreement.CalculateAgreement(epkParam);
        byte[] zRaw = z.ToByteArrayUnsigned();

        IMemoryOwner<byte> zOwner = pool.Rent(sharedSecretSize);
        zOwner.Memory.Span[..sharedSecretSize].Clear();
        CopyLeftPadded(zRaw, zOwner.Memory.Span[..sharedSecretSize]);
        CryptographicOperations.ZeroMemory(zRaw);

        return ValueTask.FromResult(new SharedSecret(zOwner, sharedSecretTag));
    }


    //Left-pads the unsigned big-endian Z into a fixed-width field (truncating any
    //leading sign byte BouncyCastle may emit when the high bit is set).
    private static void CopyLeftPadded(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if(source.Length < destination.Length)
        {
            source.CopyTo(destination[(destination.Length - source.Length)..]);
        }
        else
        {
            source.Slice(source.Length - destination.Length, destination.Length).CopyTo(destination);
        }
    }


    //Maps a SEC/Brainpool curve name to the JOSE display form used in telemetry.
    //NIST secpNNNr1 names map to the P-NNN display form; the Brainpool curves
    //pass through unchanged.
    private static string MapCurveDisplay(string curveName) => curveName switch
    {
        "secp256r1" => "P-256",
        "secp384r1" => "P-384",
        "secp521r1" => "P-521",
        _ => curveName
    };


    /// <summary>
    /// Performs AES-GCM authenticated encryption.
    /// Matches <see cref="AeadEncryptDelegate"/>.
    /// </summary>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <param name="key">The symmetric key to encrypt under. Must be disposed by the caller after this method returns.</param>
    /// <param name="aad">The additional authenticated data.</param>
    /// <param name="pool">Memory pool for IV, ciphertext, and tag allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The IV, ciphertext, and authentication tag. The caller owns and must dispose.</returns>
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

        //The encryption could run in a remote HSM in hardware implementations —
        //this is the await point the async signature exists to support.
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
    /// <param name="ciphertext">The encrypted bytes to decrypt.</param>
    /// <param name="key">The symmetric key to decrypt under. Must be disposed by the caller after this method returns.</param>
    /// <param name="iv">The initialization vector nonce.</param>
    /// <param name="tag">The authentication tag to verify.</param>
    /// <param name="aad">The additional authenticated data to verify.</param>
    /// <param name="pool">Memory pool for the plaintext allocation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The decrypted plaintext. The caller owns and must dispose.</returns>
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

        //The decryption could run in a remote HSM in hardware implementations —
        //this is the await point the async signature exists to support.
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
