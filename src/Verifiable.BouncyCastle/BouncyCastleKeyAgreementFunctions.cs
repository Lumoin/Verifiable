using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

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

        var curve = SecNamedCurves.GetByName("secp256r1");
        var domainParams = new ECDomainParameters(
            curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

        byte[] scalarBytes = privateKeyBytes.Span.ToArray();

        try
        {
            var privateKeyParam = new ECPrivateKeyParameters(
                new BigInteger(1, scalarBytes),
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
        finally
        {
            CryptographicOperations.ZeroMemory(scalarBytes);
        }
    }


    /// <summary>
    /// Performs AES-GCM authenticated encryption.
    /// Matches <see cref="AeadEncryptDelegate"/>.
    /// </summary>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <param name="cek">The content encryption key. Must be disposed by the caller after this method returns.</param>
    /// <param name="aad">The additional authenticated data.</param>
    /// <param name="pool">Memory pool for IV, ciphertext, and tag allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The IV, ciphertext, and authentication tag. The caller owns and must dispose.</returns>
    public static async ValueTask<AeadEncryptResult> AesGcmEncryptAsync(
        ReadOnlyMemory<byte> plaintext,
        ContentEncryptionKey cek,
        AdditionalData aad,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(cek);
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

        using(var aesGcm = new AesGcm(cek.AsReadOnlySpan(), AesGcmTagLength))
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
    /// <param name="cek">The content encryption key. Must be disposed by the caller after this method returns.</param>
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
        ContentEncryptionKey cek,
        Nonce iv,
        AuthenticationTag tag,
        AdditionalData aad,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(cek);
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
            using var aesGcm = new AesGcm(cek.AsReadOnlySpan(), AesGcmTagLength);
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
