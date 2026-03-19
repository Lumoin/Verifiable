using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

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

        //Split the uncompressed point into X and Y coordinates.
        ReadOnlySpan<byte> point = epk.AsReadOnlySpan();
        const int coordinateLength = 32;
        ReadOnlySpan<byte> xSpan = point.Slice(1, coordinateLength);
        ReadOnlySpan<byte> ySpan = point.Slice(1 + coordinateLength, coordinateLength);

        using ECDiffieHellman recipientEcdh = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = privateKeyBytes.Span.ToArray(),
            Q = new ECPoint
            {
                X = new byte[32],
                Y = new byte[32]
            }
        });

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


    /// <summary>
    /// Performs AES-GCM authenticated encryption.
    /// Matches <see cref="AeadEncryptDelegate"/>.
    /// </summary>
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
