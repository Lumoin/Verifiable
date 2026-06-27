using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Provider;
using static System.Numerics.BitOperations;

//ChaCha20-Poly1305 is aliased to the BouncyCastle modes type because the BCL also defines a
//System.Security.Cryptography.ChaCha20Poly1305 (which requires platform CNG support); the
//BouncyCastle implementation is pure-managed and always available.
using BcChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;
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

    //XChaCha20-Poly1305 (the JOSE "XC20P" content encryption algorithm) geometry per
    //draft-irtf-cfrg-xchacha-03 §2.3: a 256-bit key, a 192-bit extended nonce, and a 128-bit
    //Poly1305 tag. The construction derives a 256-bit subkey with HChaCha20 from the first 128 bits
    //of the extended nonce and then runs RFC 8439 ChaCha20-Poly1305 (a 96-bit nonce) over that subkey.
    private const int XChaCha20KeyLength = 32;
    private const int XChaCha20NonceLength = 24;
    private const int XChaCha20TagLength = 16;
    private const int ChaCha20Poly1305NonceLength = 12;


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


    /// <summary>Performs ECDH key agreement (encrypt side) using Brainpool P-224r1 (RFC 5639). Matches <see cref="KeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<EphemeralKeyAgreementResult> EcdhKeyAgreementEncryptBrainpoolP224r1Async(
        PublicKeyMemory recipientPublicKey, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhEncryptBrainpoolAsync("brainpoolP224r1", 28, CryptoTags.BrainpoolP224r1ExchangePublicKey, CryptoTags.BrainpoolP224r1ExchangePrivateKey, recipientPublicKey, pool, cancellationToken);

    /// <summary>Performs ECDH key agreement (decrypt side) using Brainpool P-224r1 (RFC 5639). Matches <see cref="KeyAgreementDecryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> EcdhKeyAgreementDecryptBrainpoolP224r1Async(
        ReadOnlyMemory<byte> privateKeyBytes, PublicKeyMemory epk, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhDecryptBrainpoolAsync("brainpoolP224r1", 28, CryptoTags.BrainpoolP224r1ExchangePrivateKey, privateKeyBytes, epk, pool, cancellationToken);

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


    //RFC 7748 §6.1: an all-zero X25519 shared secret arises from a low-order (small-subgroup) public point; an
    //implementation MAY reject it. Screening the agreement on the consume path rejects a contributory /
    //invalid-point epk before the secret feeds key derivation (defense-in-depth: for ECDH-1PU the static half
    //still binds, and anoncrypt asserts no authenticity, but a degenerate secret is never legitimate). The
    //scan is over a degenerate (already non-secret) value, so a simple accumulate is sufficient.
    private static bool IsAllZeroX25519Secret(ReadOnlySpan<byte> sharedSecret)
    {
        byte accumulator = 0;
        for(int i = 0; i < sharedSecret.Length; ++i)
        {
            accumulator |= sharedSecret[i];
        }

        return accumulator == 0;
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

        //Reject a degenerate (all-zero) secret from a low-order epk before it derives a key (RFC 7748 §6.1).
        if(IsAllZeroX25519Secret(zOwner.Memory.Span[..agreement.AgreementSize]))
        {
            zOwner.Dispose();

            throw new CryptographicException("The X25519 shared secret is all-zero (a low-order ephemeral public key).");
        }

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


    /// <summary>
    /// Performs XChaCha20-Poly1305 authenticated encryption (the JOSE <c>XC20P</c> content encryption
    /// algorithm). Matches <see cref="AeadEncryptDelegate"/>.
    /// </summary>
    /// <remarks>
    /// A fresh 192-bit extended nonce is generated per operation; XChaCha20's nonce is large enough that
    /// random generation carries no birthday-bound concern, unlike AES-GCM's 96-bit nonce. The 256-bit
    /// subkey and the RFC 8439 96-bit nonce are derived per draft-irtf-cfrg-xchacha-03 §2.3 and the AEAD
    /// itself is BouncyCastle's RFC 8439 ChaCha20-Poly1305 over the subkey.
    /// </remarks>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <param name="key">The 256-bit content encryption key. Must be disposed by the caller after this method returns.</param>
    /// <param name="aad">The additional authenticated data.</param>
    /// <param name="pool">Memory pool for IV, ciphertext, and tag allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The 24-byte nonce, ciphertext, and 16-byte authentication tag. The caller owns and must dispose.</returns>
    public static async ValueTask<AeadEncryptResult> XChaCha20Poly1305EncryptAsync(
        ReadOnlyMemory<byte> plaintext,
        SymmetricKeyMemory key,
        AdditionalData aad,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(aad);
        ArgumentNullException.ThrowIfNull(pool);

        if(key.AsReadOnlySpan().Length != XChaCha20KeyLength)
        {
            throw new ArgumentException($"XChaCha20-Poly1305 requires a {XChaCha20KeyLength}-byte key.", nameof(key));
        }

        //The encryption could run in a remote HSM in hardware implementations —
        //this is the await point the async signature exists to support.
        await Task.CompletedTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        IMemoryOwner<byte> ivOwner = pool.Rent(XChaCha20NonceLength);
        IMemoryOwner<byte> ciphertextOwner = pool.Rent(plaintext.Length);
        IMemoryOwner<byte> tagOwner = pool.Rent(XChaCha20TagLength);

        Span<byte> subkey = stackalloc byte[XChaCha20KeyLength];
        Span<byte> innerNonce = stackalloc byte[ChaCha20Poly1305NonceLength];

        //The transient combined buffer is rented inside the try so a failed rent disposes the result owners
        //through the catch rather than leaking them.
        IMemoryOwner<byte>? combinedOwner = null;
        try
        {
            RandomNumberGenerator.Fill(ivOwner.Memory.Span[..XChaCha20NonceLength]);
            DeriveXChaCha20SubkeyAndNonce(key.AsReadOnlySpan(), ivOwner.Memory.Span[..XChaCha20NonceLength], subkey, innerNonce);

            combinedOwner = pool.Rent(plaintext.Length + XChaCha20TagLength);

            var aead = new BcChaCha20Poly1305();
            aead.Init(true, new ParametersWithIV(new KeyParameter(subkey), innerNonce));
            aead.ProcessAadBytes(aad.AsReadOnlySpan());

            //ChaCha20-Poly1305 emits ciphertext (1:1 with plaintext) then the 16-byte tag; the combined
            //buffer splits at the plaintext length regardless of how the calls partition their writes.
            int written = aead.ProcessBytes(plaintext.Span, combinedOwner.Memory.Span);
            written += aead.DoFinal(combinedOwner.Memory.Span[written..]);

            combinedOwner.Memory.Span.Slice(0, plaintext.Length).CopyTo(ciphertextOwner.Memory.Span[..plaintext.Length]);
            combinedOwner.Memory.Span.Slice(plaintext.Length, XChaCha20TagLength).CopyTo(tagOwner.Memory.Span[..XChaCha20TagLength]);
        }
        catch
        {
            ivOwner.Dispose();
            ciphertextOwner.Dispose();
            tagOwner.Dispose();
            throw;
        }
        finally
        {
            subkey.Clear();
            combinedOwner?.Dispose();
        }

        return new AeadEncryptResult(
            new Nonce(ivOwner, CryptoTags.Xc20pIv),
            new Ciphertext(ciphertextOwner, CryptoTags.Xc20pCiphertext),
            new AuthenticationTag(tagOwner, CryptoTags.Xc20pAuthTag));
    }


    /// <summary>
    /// Performs XChaCha20-Poly1305 authenticated decryption (the JOSE <c>XC20P</c> content encryption
    /// algorithm). Matches <see cref="AeadDecryptDelegate"/>.
    /// </summary>
    /// <param name="ciphertext">The encrypted bytes to decrypt.</param>
    /// <param name="key">The 256-bit content encryption key. Must be disposed by the caller after this method returns.</param>
    /// <param name="iv">The 24-byte extended nonce.</param>
    /// <param name="tag">The 16-byte Poly1305 authentication tag to verify.</param>
    /// <param name="aad">The additional authenticated data to verify.</param>
    /// <param name="pool">Memory pool for the plaintext allocation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The decrypted plaintext. The caller owns and must dispose.</returns>
    /// <exception cref="CryptographicException">
    /// Thrown when authentication tag verification fails. BouncyCastle signals this with an
    /// <see cref="InvalidCipherTextException"/>, which is translated here so the
    /// <see cref="AeadDecryptDelegate"/> tag-failure contract holds across backends.
    /// </exception>
    public static async ValueTask<DecryptedContent> XChaCha20Poly1305DecryptAsync(
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

        if(iv.AsReadOnlySpan().Length != XChaCha20NonceLength)
        {
            throw new ArgumentException($"XChaCha20-Poly1305 requires a {XChaCha20NonceLength}-byte nonce.", nameof(iv));
        }

        if(key.AsReadOnlySpan().Length != XChaCha20KeyLength)
        {
            throw new ArgumentException($"XChaCha20-Poly1305 requires a {XChaCha20KeyLength}-byte key.", nameof(key));
        }

        //The decryption could run in a remote HSM in hardware implementations —
        //this is the await point the async signature exists to support.
        await Task.CompletedTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        ReadOnlySpan<byte> ciphertextSpan = ciphertext.AsReadOnlySpan();
        ReadOnlySpan<byte> tagSpan = tag.AsReadOnlySpan();
        IMemoryOwner<byte> plaintextOwner = pool.Rent(ciphertextSpan.Length);

        Span<byte> subkey = stackalloc byte[XChaCha20KeyLength];
        Span<byte> innerNonce = stackalloc byte[ChaCha20Poly1305NonceLength];

        //BouncyCastle's ChaCha20-Poly1305 verifies the tag from the ciphertext||tag input at DoFinal, so the
        //two wire components are concatenated into one input buffer rented inside the try — a failed rent then
        //disposes the plaintext owner through the catch rather than leaking it.
        IMemoryOwner<byte>? combinedInputOwner = null;
        try
        {
            DeriveXChaCha20SubkeyAndNonce(key.AsReadOnlySpan(), iv.AsReadOnlySpan(), subkey, innerNonce);

            combinedInputOwner = pool.Rent(ciphertextSpan.Length + tagSpan.Length);
            ciphertextSpan.CopyTo(combinedInputOwner.Memory.Span);
            tagSpan.CopyTo(combinedInputOwner.Memory.Span[ciphertextSpan.Length..]);

            var aead = new BcChaCha20Poly1305();
            aead.Init(false, new ParametersWithIV(new KeyParameter(subkey), innerNonce));
            aead.ProcessAadBytes(aad.AsReadOnlySpan());

            int written = aead.ProcessBytes(
                combinedInputOwner.Memory.Span[..(ciphertextSpan.Length + tagSpan.Length)],
                plaintextOwner.Memory.Span);
            aead.DoFinal(plaintextOwner.Memory.Span[written..]);
        }
        catch(InvalidCipherTextException invalidCipherText)
        {
            plaintextOwner.Dispose();

            //The AeadDecryptDelegate contract requires CryptographicException on tag-verification failure.
            throw new CryptographicException("XChaCha20-Poly1305 authentication tag verification failed.", invalidCipherText);
        }
        catch
        {
            plaintextOwner.Dispose();
            throw;
        }
        finally
        {
            subkey.Clear();
            combinedInputOwner?.Dispose();
        }

        return new DecryptedContent(plaintextOwner, CryptoTags.Xc20pDecryptedContent);
    }


    //Derives the XChaCha20-Poly1305 256-bit subkey and 96-bit RFC 8439 nonce from the 256-bit key and the
    //192-bit extended nonce (draft-irtf-cfrg-xchacha-03 §2.3): subkey = HChaCha20(key, nonce[0..16]); the
    //inner nonce is four zero bytes followed by nonce[16..24].
    private static void DeriveXChaCha20SubkeyAndNonce(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> extendedNonce,
        Span<byte> subkey,
        Span<byte> innerNonce)
    {
        HChaCha20(key, extendedNonce[..16], subkey);

        innerNonce[..4].Clear();
        extendedNonce.Slice(16, 8).CopyTo(innerNonce[4..]);
    }


    //HChaCha20 (draft-irtf-cfrg-xchacha-03 §2.2): runs the ChaCha20 permutation (20 rounds) over the
    //"expand 32-byte k" constants, the 256-bit key, and the 128-bit nonce, then returns the first and last
    //rows of the permuted state as the 256-bit subkey. Unlike the ChaCha20 block function it does NOT add
    //the initial state back in. BouncyCastle 2.6.2 ships RFC 8439 ChaCha20-Poly1305 but not XChaCha20, so
    //this subkey-derivation step — and only this step — is implemented here and pinned to the draft's
    //§2.2.1 test vector. Internal so that known-answer test can exercise it directly.
    internal static void HChaCha20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, Span<byte> subkey)
    {
        Span<uint> state = stackalloc uint[16];
        state[0] = 0x61707865u;
        state[1] = 0x3320646eu;
        state[2] = 0x79622d32u;
        state[3] = 0x6b206574u;
        for(int i = 0; i < 8; i++)
        {
            state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4, 4));
        }

        for(int i = 0; i < 4; i++)
        {
            state[12 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(i * 4, 4));
        }

        //Twenty rounds = ten interleaved column-then-diagonal double rounds.
        for(int round = 0; round < 10; round++)
        {
            ChaChaQuarterRound(state, 0, 4, 8, 12);
            ChaChaQuarterRound(state, 1, 5, 9, 13);
            ChaChaQuarterRound(state, 2, 6, 10, 14);
            ChaChaQuarterRound(state, 3, 7, 11, 15);
            ChaChaQuarterRound(state, 0, 5, 10, 15);
            ChaChaQuarterRound(state, 1, 6, 11, 12);
            ChaChaQuarterRound(state, 2, 7, 8, 13);
            ChaChaQuarterRound(state, 3, 4, 9, 14);
        }

        for(int i = 0; i < 4; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(subkey.Slice(i * 4, 4), state[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(subkey.Slice(16 + i * 4, 4), state[12 + i]);
        }
    }


    //The ChaCha quarter-round (RFC 8439 §2.1) operating in place on four state words.
    private static void ChaChaQuarterRound(Span<uint> state, int a, int b, int c, int d)
    {
        state[a] += state[b];
        state[d] = RotateLeft(state[d] ^ state[a], 16);
        state[c] += state[d];
        state[b] = RotateLeft(state[b] ^ state[c], 12);
        state[a] += state[b];
        state[d] = RotateLeft(state[d] ^ state[a], 8);
        state[c] += state[d];
        state[b] = RotateLeft(state[b] ^ state[c], 7);
    }


    private const int X25519SharedSecretSize = 32;


    /// <summary>
    /// Performs ECDH-1PU key agreement (encrypt side) using X25519 per
    /// draft-madden-jose-ecdh-1pu-04 §2.3. Matches
    /// <see cref="AuthenticatedKeyAgreementEncryptDelegate"/>.
    /// </summary>
    /// <remarks>
    /// Computes Ze from a fresh ephemeral key against the recipient's static public key
    /// and Zs from the sender's static private key against the same recipient key, and
    /// returns Z = Ze || Zs per NIST SP 800-56A §6.2.1.2. The sender's static
    /// contribution is what authenticates the sender — the DIDComm v2 authcrypt primitive.
    /// </remarks>
    public static async ValueTask<EphemeralKeyAgreementResult> Ecdh1PuKeyAgreementEncryptX25519Async(
        PublicKeyMemory recipientPublicKey,
        ReadOnlyMemory<byte> senderPrivateKeyBytes,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        await Task.CompletedTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        var keyPairGenerator = new X25519KeyPairGenerator();
        keyPairGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom()));
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair ephemeralPair = keyPairGenerator.GenerateKeyPair();
        var ephemeralPrivate = (X25519PrivateKeyParameters)ephemeralPair.Private;
        var ephemeralPublic = (X25519PublicKeyParameters)ephemeralPair.Public;

        var recipientPublic = new X25519PublicKeyParameters(recipientPublicKey.AsReadOnlySpan());

        //The span ctor copies the scalar into BouncyCastle's own buffer — no naked
        //byte[] of private-key material for us to track.
        var senderPrivate = new X25519PrivateKeyParameters(senderPrivateKeyBytes.Span);

        var ephemeralAgreement = new X25519Agreement();
        ephemeralAgreement.Init(ephemeralPrivate);
        var staticAgreement = new X25519Agreement();
        staticAgreement.Init(senderPrivate);

        //Z = Ze || Zs written straight into pooled memory the SharedSecret owns and
        //zeroes on dispose — no naked byte[] of secret material at any point.
        IMemoryOwner<byte> zOwner = pool.Rent(2 * X25519SharedSecretSize);
        ephemeralAgreement.CalculateAgreement(recipientPublic, zOwner.Memory.Span[..X25519SharedSecretSize]);
        staticAgreement.CalculateAgreement(recipientPublic, zOwner.Memory.Span[X25519SharedSecretSize..(2 * X25519SharedSecretSize)]);
        var sharedSecret = new SharedSecret(zOwner, CryptoTags.X25519PrivateKey);

        //The ephemeral public key is the raw 32-byte OKP key (public, not sensitive).
        byte[] ephemeralEncoded = ephemeralPublic.GetEncoded();
        IMemoryOwner<byte> epkOwner = pool.Rent(ephemeralEncoded.Length);
        ephemeralEncoded.AsSpan().CopyTo(epkOwner.Memory.Span);

        var epk = new PublicKeyMemory(epkOwner, CryptoTags.X25519PublicKey);

        return new EphemeralKeyAgreementResult(sharedSecret, epk);
    }


    /// <summary>
    /// Performs ECDH-1PU key agreement (decrypt side) using X25519 per
    /// draft-madden-jose-ecdh-1pu-04 §2.3. Matches
    /// <see cref="AuthenticatedKeyAgreementDecryptDelegate"/>.
    /// </summary>
    /// <remarks>
    /// Computes Ze from the recipient's static private key against the sender's
    /// ephemeral public key and Zs from the same private key against the sender's
    /// static public key, and returns Z = Ze || Zs — byte identical to the encrypt side.
    /// </remarks>
    public static ValueTask<SharedSecret> Ecdh1PuKeyAgreementDecryptX25519Async(
        ReadOnlyMemory<byte> recipientPrivateKeyBytes,
        PublicKeyMemory ephemeralPublicKey,
        PublicKeyMemory senderPublicKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ephemeralPublicKey);
        ArgumentNullException.ThrowIfNull(senderPublicKey);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        var privateKeyParam = new X25519PrivateKeyParameters(recipientPrivateKeyBytes.Span);
        var epkParam = new X25519PublicKeyParameters(ephemeralPublicKey.AsReadOnlySpan());
        var senderParam = new X25519PublicKeyParameters(senderPublicKey.AsReadOnlySpan());

        var agreement = new X25519Agreement();
        agreement.Init(privateKeyParam);

        IMemoryOwner<byte> zOwner = pool.Rent(2 * X25519SharedSecretSize);
        agreement.CalculateAgreement(epkParam, zOwner.Memory.Span[..X25519SharedSecretSize]);

        //The ephemeral half (Ze) is derived from the attacker-supplied epk; reject a degenerate (all-zero)
        //value from a low-order epk before either half feeds key derivation (RFC 7748 §6.1).
        if(IsAllZeroX25519Secret(zOwner.Memory.Span[..X25519SharedSecretSize]))
        {
            zOwner.Dispose();

            throw new CryptographicException("The ECDH-1PU ephemeral X25519 shared secret is all-zero (a low-order ephemeral public key).");
        }

        agreement.CalculateAgreement(senderParam, zOwner.Memory.Span[X25519SharedSecretSize..(2 * X25519SharedSecretSize)]);

        return ValueTask.FromResult(new SharedSecret(zOwner, CryptoTags.X25519PrivateKey));
    }


    /// <summary>Performs ECDH-1PU key agreement (encrypt side) using NIST P-256 (draft-madden-jose-ecdh-1pu-04 §2.3). Matches <see cref="AuthenticatedKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<EphemeralKeyAgreementResult> Ecdh1PuKeyAgreementEncryptP256Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> senderPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuEncryptNistAsync("secp256r1", 32, CryptoTags.P256ExchangePublicKey, CryptoTags.P256ExchangePrivateKey, recipientPublicKey, senderPrivateKeyBytes, pool, cancellationToken);

    /// <summary>Performs ECDH-1PU key agreement (decrypt side) using NIST P-256 (draft-madden-jose-ecdh-1pu-04 §2.3). Matches <see cref="AuthenticatedKeyAgreementDecryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> Ecdh1PuKeyAgreementDecryptP256Async(
        ReadOnlyMemory<byte> recipientPrivateKeyBytes, PublicKeyMemory ephemeralPublicKey, PublicKeyMemory senderPublicKey, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuDecryptNistAsync("secp256r1", 32, CryptoTags.P256ExchangePrivateKey, recipientPrivateKeyBytes, ephemeralPublicKey, senderPublicKey, pool, cancellationToken);

    /// <summary>Performs ECDH-1PU key agreement (encrypt side) using NIST P-384 (draft-madden-jose-ecdh-1pu-04 §2.3). Matches <see cref="AuthenticatedKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<EphemeralKeyAgreementResult> Ecdh1PuKeyAgreementEncryptP384Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> senderPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuEncryptNistAsync("secp384r1", 48, CryptoTags.P384ExchangePublicKey, CryptoTags.P384ExchangePrivateKey, recipientPublicKey, senderPrivateKeyBytes, pool, cancellationToken);

    /// <summary>Performs ECDH-1PU key agreement (decrypt side) using NIST P-384 (draft-madden-jose-ecdh-1pu-04 §2.3). Matches <see cref="AuthenticatedKeyAgreementDecryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> Ecdh1PuKeyAgreementDecryptP384Async(
        ReadOnlyMemory<byte> recipientPrivateKeyBytes, PublicKeyMemory ephemeralPublicKey, PublicKeyMemory senderPublicKey, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuDecryptNistAsync("secp384r1", 48, CryptoTags.P384ExchangePrivateKey, recipientPrivateKeyBytes, ephemeralPublicKey, senderPublicKey, pool, cancellationToken);

    /// <summary>Performs ECDH-1PU key agreement (encrypt side) using NIST P-521 (draft-madden-jose-ecdh-1pu-04 §2.3). Matches <see cref="AuthenticatedKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<EphemeralKeyAgreementResult> Ecdh1PuKeyAgreementEncryptP521Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> senderPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuEncryptNistAsync("secp521r1", 66, CryptoTags.P521ExchangePublicKey, CryptoTags.P521ExchangePrivateKey, recipientPublicKey, senderPrivateKeyBytes, pool, cancellationToken);

    /// <summary>Performs ECDH-1PU key agreement (decrypt side) using NIST P-521 (draft-madden-jose-ecdh-1pu-04 §2.3). Matches <see cref="AuthenticatedKeyAgreementDecryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> Ecdh1PuKeyAgreementDecryptP521Async(
        ReadOnlyMemory<byte> recipientPrivateKeyBytes, PublicKeyMemory ephemeralPublicKey, PublicKeyMemory senderPublicKey, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuDecryptNistAsync("secp521r1", 66, CryptoTags.P521ExchangePrivateKey, recipientPrivateKeyBytes, ephemeralPublicKey, senderPublicKey, pool, cancellationToken);


    //ECDH-1PU (encrypt side) for the NIST SEC curves: same ECDHBasicAgreement math as
    //the ECDH-ES helpers, run twice — Ze from a fresh ephemeral key and Zs from the
    //sender's static key, both against the recipient's static public key. Both halves
    //are left-padded to the field size so Z = Ze || Zs is byte identical on both sides.
    private static async ValueTask<EphemeralKeyAgreementResult> Ecdh1PuEncryptNistAsync(
        string curveName,
        int sharedSecretSize,
        Tag epkTag,
        Tag sharedSecretTag,
        PublicKeyMemory recipientPublicKey,
        ReadOnlyMemory<byte> senderPrivateKeyBytes,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

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

        //Feed the caller's scalar span straight to BigInteger, which copies it into its
        //own immutable magnitude — no naked byte[] copy of private-key material for us to
        //track and zero, and the caller's buffer is never touched.
        var senderPrivate = new ECPrivateKeyParameters(
            new BigInteger(1, senderPrivateKeyBytes.Span), domainParams);

        var ephemeralAgreement = new ECDHBasicAgreement();
        ephemeralAgreement.Init(ephemeralPrivate);
        byte[] zeRaw = ephemeralAgreement.CalculateAgreement(recipientParam).ToByteArrayUnsigned();

        var staticAgreement = new ECDHBasicAgreement();
        staticAgreement.Init(senderPrivate);
        byte[] zsRaw = staticAgreement.CalculateAgreement(recipientParam).ToByteArrayUnsigned();

        try
        {
            await Task.CompletedTask.ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            IMemoryOwner<byte> zOwner = pool.Rent(2 * sharedSecretSize);
            zOwner.Memory.Span[..(2 * sharedSecretSize)].Clear();
            CopyLeftPadded(zeRaw, zOwner.Memory.Span[..sharedSecretSize]);
            CopyLeftPadded(zsRaw, zOwner.Memory.Span[sharedSecretSize..(2 * sharedSecretSize)]);
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
            CryptographicOperations.ZeroMemory(zeRaw);
            CryptographicOperations.ZeroMemory(zsRaw);
        }
    }


    //ECDH-1PU (decrypt side) for the NIST SEC curves: Ze from the recipient's static
    //private key against the sender's ephemeral public key, Zs from the same private
    //key against the sender's static public key.
    private static ValueTask<SharedSecret> Ecdh1PuDecryptNistAsync(
        string curveName,
        int sharedSecretSize,
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

        X9ECParameters curve = SecNamedCurves.GetByName(curveName)
            ?? throw new NotSupportedException($"NIST curve '{curveName}' is not registered in BouncyCastle.");
        var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

        var privateKeyParam = new ECPrivateKeyParameters(
            new BigInteger(1, recipientPrivateKeyBytes.Span), domainParams);
        var epkParam = new ECPublicKeyParameters(
            curve.Curve.DecodePoint(ephemeralPublicKey.AsReadOnlySpan().ToArray()), domainParams);
        var senderParam = new ECPublicKeyParameters(
            curve.Curve.DecodePoint(senderPublicKey.AsReadOnlySpan().ToArray()), domainParams);

        var agreement = new ECDHBasicAgreement();
        agreement.Init(privateKeyParam);
        byte[] zeRaw = agreement.CalculateAgreement(epkParam).ToByteArrayUnsigned();
        byte[] zsRaw = agreement.CalculateAgreement(senderParam).ToByteArrayUnsigned();

        IMemoryOwner<byte> zOwner = pool.Rent(2 * sharedSecretSize);
        zOwner.Memory.Span[..(2 * sharedSecretSize)].Clear();
        CopyLeftPadded(zeRaw, zOwner.Memory.Span[..sharedSecretSize]);
        CopyLeftPadded(zsRaw, zOwner.Memory.Span[sharedSecretSize..(2 * sharedSecretSize)]);
        CryptographicOperations.ZeroMemory(zeRaw);
        CryptographicOperations.ZeroMemory(zsRaw);

        return ValueTask.FromResult(new SharedSecret(zOwner, sharedSecretTag));
    }


    /// <summary>
    /// Performs multi-recipient ECDH-ES key agreement (encrypt side) with a caller-held
    /// ephemeral key using X25519 per RFC 7748 / RFC 8037. Matches
    /// <see cref="MultiRecipientKeyAgreementEncryptDelegate"/>.
    /// </summary>
    /// <remarks>
    /// A single X25519 agreement between the caller-held ephemeral private key and this
    /// recipient's static public key, Z = Ze. The same ephemeral key is reused across all
    /// recipients on the curve and carried once in the JWE Protected Header.
    /// </remarks>
    public static ValueTask<SharedSecret> EcdhEsMultiRecipientAgreementEncryptX25519Async(
        PublicKeyMemory recipientPublicKey,
        ReadOnlyMemory<byte> ephemeralPrivateKeyBytes,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        //The span ctor copies the scalar into BouncyCastle's own buffer — no naked
        //byte[] of private-key material for us to track.
        var ephemeralPrivate = new X25519PrivateKeyParameters(ephemeralPrivateKeyBytes.Span);
        var recipientPublic = new X25519PublicKeyParameters(recipientPublicKey.AsReadOnlySpan());

        var agreement = new X25519Agreement();
        agreement.Init(ephemeralPrivate);

        //Write the shared secret straight into pooled memory — no naked byte[].
        IMemoryOwner<byte> zOwner = pool.Rent(X25519SharedSecretSize);
        agreement.CalculateAgreement(recipientPublic, zOwner.Memory.Span[..X25519SharedSecretSize]);

        return ValueTask.FromResult(new SharedSecret(zOwner, CryptoTags.X25519PrivateKey));
    }


    /// <summary>
    /// Performs multi-recipient ECDH-1PU key agreement (encrypt side) with a caller-held
    /// ephemeral key using X25519 per draft-madden-jose-ecdh-1pu-04 §2.1. Matches
    /// <see cref="MultiRecipientAuthenticatedKeyAgreementEncryptDelegate"/>.
    /// </summary>
    /// <remarks>
    /// Ze from the caller-held ephemeral private key against this recipient's static
    /// public key, Zs from the sender's static private key against the same recipient key,
    /// Z = Ze || Zs. The ephemeral key is shared across recipients; Z is per-recipient
    /// because both halves depend on the recipient.
    /// </remarks>
    public static ValueTask<SharedSecret> Ecdh1PuMultiRecipientAgreementEncryptX25519Async(
        PublicKeyMemory recipientPublicKey,
        ReadOnlyMemory<byte> ephemeralPrivateKeyBytes,
        ReadOnlyMemory<byte> senderPrivateKeyBytes,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        var ephemeralPrivate = new X25519PrivateKeyParameters(ephemeralPrivateKeyBytes.Span);
        var senderPrivate = new X25519PrivateKeyParameters(senderPrivateKeyBytes.Span);
        var recipientPublic = new X25519PublicKeyParameters(recipientPublicKey.AsReadOnlySpan());

        var ephemeralAgreement = new X25519Agreement();
        ephemeralAgreement.Init(ephemeralPrivate);
        var staticAgreement = new X25519Agreement();
        staticAgreement.Init(senderPrivate);

        //Z = Ze || Zs written straight into pooled memory — no naked byte[] of secret material.
        IMemoryOwner<byte> zOwner = pool.Rent(2 * X25519SharedSecretSize);
        ephemeralAgreement.CalculateAgreement(recipientPublic, zOwner.Memory.Span[..X25519SharedSecretSize]);
        staticAgreement.CalculateAgreement(recipientPublic, zOwner.Memory.Span[X25519SharedSecretSize..(2 * X25519SharedSecretSize)]);

        return ValueTask.FromResult(new SharedSecret(zOwner, CryptoTags.X25519PrivateKey));
    }


    /// <summary>Performs multi-recipient ECDH-ES key agreement (encrypt side) with a caller-held ephemeral key using NIST P-256. Matches <see cref="MultiRecipientKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> EcdhEsMultiRecipientAgreementEncryptP256Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> ephemeralPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhEsMultiRecipientEncryptNistAsync("secp256r1", 32, CryptoTags.P256ExchangePrivateKey, recipientPublicKey, ephemeralPrivateKeyBytes, pool, cancellationToken);

    /// <summary>Performs multi-recipient ECDH-ES key agreement (encrypt side) with a caller-held ephemeral key using NIST P-384. Matches <see cref="MultiRecipientKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> EcdhEsMultiRecipientAgreementEncryptP384Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> ephemeralPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhEsMultiRecipientEncryptNistAsync("secp384r1", 48, CryptoTags.P384ExchangePrivateKey, recipientPublicKey, ephemeralPrivateKeyBytes, pool, cancellationToken);

    /// <summary>Performs multi-recipient ECDH-ES key agreement (encrypt side) with a caller-held ephemeral key using NIST P-521. Matches <see cref="MultiRecipientKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> EcdhEsMultiRecipientAgreementEncryptP521Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> ephemeralPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        EcdhEsMultiRecipientEncryptNistAsync("secp521r1", 66, CryptoTags.P521ExchangePrivateKey, recipientPublicKey, ephemeralPrivateKeyBytes, pool, cancellationToken);

    /// <summary>Performs multi-recipient ECDH-1PU key agreement (encrypt side) with a caller-held ephemeral key using NIST P-256. Matches <see cref="MultiRecipientAuthenticatedKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> Ecdh1PuMultiRecipientAgreementEncryptP256Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> ephemeralPrivateKeyBytes, ReadOnlyMemory<byte> senderPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuMultiRecipientEncryptNistAsync("secp256r1", 32, CryptoTags.P256ExchangePrivateKey, recipientPublicKey, ephemeralPrivateKeyBytes, senderPrivateKeyBytes, pool, cancellationToken);

    /// <summary>Performs multi-recipient ECDH-1PU key agreement (encrypt side) with a caller-held ephemeral key using NIST P-384. Matches <see cref="MultiRecipientAuthenticatedKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> Ecdh1PuMultiRecipientAgreementEncryptP384Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> ephemeralPrivateKeyBytes, ReadOnlyMemory<byte> senderPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuMultiRecipientEncryptNistAsync("secp384r1", 48, CryptoTags.P384ExchangePrivateKey, recipientPublicKey, ephemeralPrivateKeyBytes, senderPrivateKeyBytes, pool, cancellationToken);

    /// <summary>Performs multi-recipient ECDH-1PU key agreement (encrypt side) with a caller-held ephemeral key using NIST P-521. Matches <see cref="MultiRecipientAuthenticatedKeyAgreementEncryptDelegate"/>.</summary>
    public static ValueTask<SharedSecret> Ecdh1PuMultiRecipientAgreementEncryptP521Async(
        PublicKeyMemory recipientPublicKey, ReadOnlyMemory<byte> ephemeralPrivateKeyBytes, ReadOnlyMemory<byte> senderPrivateKeyBytes, MemoryPool<byte> pool, CancellationToken cancellationToken = default) =>
        Ecdh1PuMultiRecipientEncryptNistAsync("secp521r1", 66, CryptoTags.P521ExchangePrivateKey, recipientPublicKey, ephemeralPrivateKeyBytes, senderPrivateKeyBytes, pool, cancellationToken);


    //Multi-recipient ECDH-ES (encrypt side) for the NIST SEC curves: a single
    //ECDHBasicAgreement between the caller-held ephemeral private key and this recipient's
    //static public key, Z = Ze left-padded to the field size.
    private static ValueTask<SharedSecret> EcdhEsMultiRecipientEncryptNistAsync(
        string curveName,
        int sharedSecretSize,
        Tag sharedSecretTag,
        PublicKeyMemory recipientPublicKey,
        ReadOnlyMemory<byte> ephemeralPrivateKeyBytes,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        X9ECParameters curve = SecNamedCurves.GetByName(curveName)
            ?? throw new NotSupportedException($"NIST curve '{curveName}' is not registered in BouncyCastle.");
        var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

        var ephemeralPrivate = new ECPrivateKeyParameters(
            new BigInteger(1, ephemeralPrivateKeyBytes.Span), domainParams);
        var recipientPoint = curve.Curve.DecodePoint(recipientPublicKey.AsReadOnlySpan().ToArray());
        var recipientParam = new ECPublicKeyParameters(recipientPoint, domainParams);

        var agreement = new ECDHBasicAgreement();
        agreement.Init(ephemeralPrivate);
        byte[] zeRaw = agreement.CalculateAgreement(recipientParam).ToByteArrayUnsigned();

        IMemoryOwner<byte> zOwner = pool.Rent(sharedSecretSize);
        zOwner.Memory.Span[..sharedSecretSize].Clear();
        CopyLeftPadded(zeRaw, zOwner.Memory.Span[..sharedSecretSize]);
        CryptographicOperations.ZeroMemory(zeRaw);

        return ValueTask.FromResult(new SharedSecret(zOwner, sharedSecretTag));
    }


    //Multi-recipient ECDH-1PU (encrypt side) for the NIST SEC curves: Ze from the
    //caller-held ephemeral private key, Zs from the sender's static private key, both
    //against this recipient's static public key, Z = Ze || Zs left-padded to the field size.
    private static ValueTask<SharedSecret> Ecdh1PuMultiRecipientEncryptNistAsync(
        string curveName,
        int sharedSecretSize,
        Tag sharedSecretTag,
        PublicKeyMemory recipientPublicKey,
        ReadOnlyMemory<byte> ephemeralPrivateKeyBytes,
        ReadOnlyMemory<byte> senderPrivateKeyBytes,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        X9ECParameters curve = SecNamedCurves.GetByName(curveName)
            ?? throw new NotSupportedException($"NIST curve '{curveName}' is not registered in BouncyCastle.");
        var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

        var ephemeralPrivate = new ECPrivateKeyParameters(
            new BigInteger(1, ephemeralPrivateKeyBytes.Span), domainParams);
        var senderPrivate = new ECPrivateKeyParameters(
            new BigInteger(1, senderPrivateKeyBytes.Span), domainParams);
        var recipientPoint = curve.Curve.DecodePoint(recipientPublicKey.AsReadOnlySpan().ToArray());
        var recipientParam = new ECPublicKeyParameters(recipientPoint, domainParams);

        var ephemeralAgreement = new ECDHBasicAgreement();
        ephemeralAgreement.Init(ephemeralPrivate);
        byte[] zeRaw = ephemeralAgreement.CalculateAgreement(recipientParam).ToByteArrayUnsigned();

        var staticAgreement = new ECDHBasicAgreement();
        staticAgreement.Init(senderPrivate);
        byte[] zsRaw = staticAgreement.CalculateAgreement(recipientParam).ToByteArrayUnsigned();

        IMemoryOwner<byte> zOwner = pool.Rent(2 * sharedSecretSize);
        zOwner.Memory.Span[..(2 * sharedSecretSize)].Clear();
        CopyLeftPadded(zeRaw, zOwner.Memory.Span[..sharedSecretSize]);
        CopyLeftPadded(zsRaw, zOwner.Memory.Span[sharedSecretSize..(2 * sharedSecretSize)]);
        CryptographicOperations.ZeroMemory(zeRaw);
        CryptographicOperations.ZeroMemory(zsRaw);

        return ValueTask.FromResult(new SharedSecret(zOwner, sharedSecretTag));
    }


    /// <summary>
    /// Wraps a key per <see href="https://www.rfc-editor.org/rfc/rfc3394">RFC 3394</see>
    /// AES Key Wrap using the BouncyCastle <c>AesWrapEngine</c>.
    /// Matches <see cref="KeyWrapDelegate"/>.
    /// </summary>
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

        if(contentEncryptionKey.AsReadOnlySpan().Length < 16 || contentEncryptionKey.AsReadOnlySpan().Length % 8 != 0)
        {
            throw new ArgumentException(
                $"Key data to wrap must be at least 16 bytes and a multiple of 8 bytes. " +
                $"Received {contentEncryptionKey.AsReadOnlySpan().Length} bytes.", nameof(contentEncryptionKey));
        }

        byte[] kekArray = keyEncryptionKey.AsReadOnlySpan().ToArray();
        byte[] keyArray = contentEncryptionKey.AsReadOnlySpan().ToArray();
        try
        {
            var engine = new Org.BouncyCastle.Crypto.Engines.AesWrapEngine();
            engine.Init(forWrapping: true, new KeyParameter(kekArray));
            byte[] wrapped = engine.Wrap(keyArray, 0, keyArray.Length);

            IMemoryOwner<byte> wrappedOwner = pool.Rent(wrapped.Length);
            wrapped.CopyTo(wrappedOwner.Memory.Span);

            return new Ciphertext(wrappedOwner, CryptoTags.AesKwWrappedKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kekArray);
            CryptographicOperations.ZeroMemory(keyArray);
        }
    }


    /// <summary>
    /// Unwraps a key per <see href="https://www.rfc-editor.org/rfc/rfc3394">RFC 3394</see>
    /// AES Key Wrap using the BouncyCastle <c>AesWrapEngine</c>.
    /// Matches <see cref="KeyUnwrapDelegate"/>.
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

        byte[] kekArray = keyEncryptionKey.AsReadOnlySpan().ToArray();
        byte[] wrappedArray = wrappedKey.ToArray();
        byte[]? unwrapped = null;
        try
        {
            var engine = new Org.BouncyCastle.Crypto.Engines.AesWrapEngine();
            engine.Init(forWrapping: false, new KeyParameter(kekArray));

            try
            {
                unwrapped = engine.Unwrap(wrappedArray, 0, wrappedArray.Length);
            }
            catch(Org.BouncyCastle.Crypto.InvalidCipherTextException e)
            {
                throw new CryptographicException("AES Key Wrap integrity check failed.", e);
            }

            IMemoryOwner<byte> keyOwner = pool.Rent(unwrapped.Length);
            unwrapped.CopyTo(keyOwner.Memory.Span);

            return new SymmetricKeyMemory(keyOwner, CryptoTags.AesKwUnwrappedKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kekArray);
            if(unwrapped is not null)
            {
                CryptographicOperations.ZeroMemory(unwrapped);
            }
        }
    }


    //The Ed25519 / Curve25519 field prime p = 2^255 - 19 (RFC 7748 §4.1).
    private static readonly BigInteger Curve25519FieldPrime =
        BigInteger.Two.Pow(255).Subtract(BigInteger.ValueOf(19));


    /// <summary>
    /// Derives the X25519 (Montgomery <c>u</c>) public key birationally equivalent to an Ed25519
    /// (twisted Edwards) public key, per the map <c>u = (1 + y) / (1 - y) (mod p)</c> in RFC 7748 §4.1
    /// and [OSCORE] §2.4.2 (the conversion the <c>did:key</c> Decode Public Key Algorithm references for a
    /// <c>0xed</c> multicodec value). The result is the raw 32-byte little-endian X25519 public key.
    /// </summary>
    /// <param name="ed25519PublicKey">The Ed25519 public key — the 32-byte compressed Edwards point.</param>
    /// <param name="pool">Memory pool for the derived 32-byte public key.</param>
    /// <returns>The derived raw X25519 public key as 32 little-endian bytes. The caller owns and must dispose.</returns>
    /// <remarks>
    /// The Ed25519 public key encodes the Edwards <c>y</c> coordinate little-endian with the sign bit of
    /// <c>x</c> in the most-significant bit of the final byte; that sign bit is cleared before reading
    /// <c>y</c> because the Montgomery <c>u</c> coordinate depends on <c>y</c> alone.
    /// </remarks>
    public static IMemoryOwner<byte> DeriveX25519PublicKeyFromEd25519(
        ReadOnlySpan<byte> ed25519PublicKey,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(ed25519PublicKey.Length != X25519SharedSecretSize)
        {
            throw new ArgumentException($"An Ed25519 public key MUST be {X25519SharedSecretSize} bytes.", nameof(ed25519PublicKey));
        }

        //Copy to a little-endian buffer and clear the x-sign bit (the MSB of the last byte) so the
        //remaining 255 bits are the Edwards y coordinate.
        Span<byte> yLittleEndian = stackalloc byte[X25519SharedSecretSize];
        ed25519PublicKey.CopyTo(yLittleEndian);
        yLittleEndian[X25519SharedSecretSize - 1] &= 0x7F;

        //BouncyCastle BigInteger reads big-endian, so reverse the little-endian field element.
        Span<byte> yBigEndian = stackalloc byte[X25519SharedSecretSize];
        for(int i = 0; i < X25519SharedSecretSize; i++)
        {
            yBigEndian[i] = yLittleEndian[X25519SharedSecretSize - 1 - i];
        }

        BigInteger y = new BigInteger(1, yBigEndian);

        //u = (1 + y) / (1 - y) (mod p) = (1 + y) * (1 - y)^{-1} (mod p).
        BigInteger one = BigInteger.One;
        BigInteger numerator = one.Add(y).Mod(Curve25519FieldPrime);
        BigInteger denominator = one.Subtract(y).Mod(Curve25519FieldPrime);

        //The identity Edwards point (y == 1) makes the denominator (1 - y) zero, where the birational map is
        //undefined (u would be the point at infinity). ModInverse of zero throws ArithmeticException; reject the
        //degenerate point as an ArgumentException so the did:key resolver maps it to InvalidDid rather than fault.
        if(denominator.Equals(BigInteger.Zero))
        {
            throw new ArgumentException(
                "The Ed25519 public key is the identity point (y == 1); it has no birationally equivalent X25519 key.",
                nameof(ed25519PublicKey));
        }

        BigInteger u = numerator.Multiply(denominator.ModInverse(Curve25519FieldPrime)).Mod(Curve25519FieldPrime);

        //Encode u as 32 little-endian bytes.
        byte[] uBigEndian = u.ToByteArrayUnsigned();
        IMemoryOwner<byte> result = pool.Rent(X25519SharedSecretSize);
        Span<byte> output = result.Memory.Span[..X25519SharedSecretSize];
        output.Clear();
        for(int i = 0; i < uBigEndian.Length && i < X25519SharedSecretSize; i++)
        {
            output[i] = uBigEndian[uBigEndian.Length - 1 - i];
        }

        return result;
    }
}
