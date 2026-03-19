using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;

namespace Verifiable.JCose;

/// <summary>
/// Extension methods for encrypting <see cref="UnencryptedJwe"/> instances and
/// decrypting <see cref="AeadMessage"/> instances.
/// </summary>
/// <remarks>
/// <para>
/// Encrypt and decrypt are two directions of the same JWE operation, so they
/// live in one class. This parallels <see cref="JwtSigningExtensions"/> which
/// covers signing on <see cref="UnsignedJwt"/>.
/// </para>
/// <para>
/// The encrypt flow orchestrates four steps:
/// </para>
/// <list type="number">
/// <item><description>
/// ECDH key agreement (<see cref="KeyAgreementEncryptDelegate"/>) — may run in TPM or HSM.
/// Produces <see cref="EphemeralKeyAgreementResult"/>.
/// </description></item>
/// <item><description>
/// Header assembly — pure software. The <c>epk</c> parameter is added to the header
/// using the ephemeral public key coordinates, then the header is encoded to produce
/// the AAD. This step must happen between key agreement and symmetric encryption so
/// that the ciphertext is bound to the actual EPK.
/// </description></item>
/// <item><description>
/// Key derivation (<see cref="KeyDerivationDelegate"/>) — pure software math.
/// Derives the <see cref="ContentEncryptionKey"/> from the shared secret.
/// </description></item>
/// <item><description>
/// Symmetric encryption (<see cref="AeadEncryptDelegate"/>) — may run in HSM.
/// Produces <see cref="AeadEncryptResult"/> bound to the AAD from step 2.
/// </description></item>
/// </list>
/// <para>
/// The decrypt flow orchestrates three steps:
/// </para>
/// <list type="number">
/// <item><description>
/// ECDH key agreement (<see cref="KeyAgreementDecryptDelegate"/>) — may run in TPM or HSM.
/// Produces <see cref="SharedSecret"/>.
/// </description></item>
/// <item><description>
/// Key derivation (<see cref="KeyDerivationDelegate"/>) — pure software math.
/// Derives the <see cref="ContentEncryptionKey"/> from the shared secret.
/// </description></item>
/// <item><description>
/// Symmetric decryption (<see cref="AeadDecryptDelegate"/>) — may run in HSM.
/// Verifies the authentication tag and produces <see cref="DecryptedContent"/>.
/// </description></item>
/// </list>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "The caller takes ownership of the returned JweMessage or DecryptedContent and is responsible for disposing it.")]
public static class JweMessageExtensions
{
    /// <summary>
    /// Encrypts the <see cref="UnencryptedJwe"/> using explicit delegates for each step.
    /// </summary>
    /// <param name="unencryptedJwe">The plaintext and partial header to encrypt.</param>
    /// <param name="recipientPublicKey">The recipient's public key for ECDH key agreement.</param>
    /// <param name="headerSerializer">
    /// Delegate for serializing the completed <see cref="JwtHeader"/> to UTF-8 JSON bytes.
    /// </param>
    /// <param name="base64UrlEncoder">Delegate for Base64url encoding.</param>
    /// <param name="tagToCrvConverter">
    /// Delegate that maps the EPK key's <see cref="Tag"/> to a JWK curve name string.
    /// Pass <see cref="CryptoFormatConversions.DefaultTagToEpkCrvConverter"/> for standard curves.
    /// </param>
    /// <param name="agreementDelegate">The ECDH key agreement delegate.</param>
    /// <param name="keyDerivationDelegate">The key derivation delegate.</param>
    /// <param name="aeadEncryptDelegate">The symmetric encryption delegate.</param>
    /// <param name="pool">Memory pool for all allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A <see cref="JweMessage"/> containing all encrypted components. The caller owns
    /// and must dispose it.
    /// </returns>
    public static async ValueTask<JweMessage> EncryptAsync(
        this UnencryptedJwe unencryptedJwe,
        PublicKeyMemory recipientPublicKey,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        KeyAgreementEncryptDelegate agreementDelegate,
        KeyDerivationDelegate keyDerivationDelegate,
        AeadEncryptDelegate aeadEncryptDelegate,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(unencryptedJwe);
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(tagToCrvConverter);
        ArgumentNullException.ThrowIfNull(agreementDelegate);
        ArgumentNullException.ThrowIfNull(keyDerivationDelegate);
        ArgumentNullException.ThrowIfNull(aeadEncryptDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        //Step 1: ECDH key agreement — may be a remote TPM/HSM call.
        using EphemeralKeyAgreementResult agreement = await agreementDelegate(
            recipientPublicKey, pool, cancellationToken).ConfigureAwait(false);

        //Step 2: Complete the header by adding the epk parameter, then encode it.
        //The encoded header is the AAD — it must be computed before symmetric encryption
        //so the ciphertext is bound to the actual EPK and algorithm parameters.
        //Split the uncompressed point (0x04 || X || Y) into the JWK x and y coordinates.
        //Copy the point into pooled memory now — ReadOnlySpan<byte> cannot cross an await boundary.
        ReadOnlySpan<byte> pointSpan = agreement.EphemeralPublicKey.AsReadOnlySpan();
        int coordinateLength = (pointSpan.Length - 1) / 2;
        string crv = tagToCrvConverter(agreement.EphemeralPublicKey.Tag);
        string epkXB64 = base64UrlEncoder(pointSpan.Slice(1, coordinateLength));
        string epkYB64 = base64UrlEncoder(pointSpan.Slice(1 + coordinateLength, coordinateLength));

        IMemoryOwner<byte> epkOwner = pool.Rent(pointSpan.Length);
        pointSpan.CopyTo(epkOwner.Memory.Span);
        Tag epkTag = agreement.EphemeralPublicKey.Tag;

        var completeHeader = new JwtHeader(unencryptedJwe.Header)
        {
            [WellKnownJwkValues.Epk] = new Dictionary<string, object>(4)
            {
                [WellKnownJwkValues.Kty] = WellKnownKeyTypeValues.Ec,
                [WellKnownJwkValues.Crv] = crv,
                [WellKnownJwkValues.X] = epkXB64,
                [WellKnownJwkValues.Y] = epkYB64
            }
        };

        ReadOnlySpan<byte> headerJsonSpan = headerSerializer(completeHeader);
        using IMemoryOwner<byte> headerJsonOwner = pool.Rent(headerJsonSpan.Length);
        headerJsonSpan.CopyTo(headerJsonOwner.Memory.Span);

        string headerEncoded = base64UrlEncoder(headerJsonOwner.Memory.Span);

        int aadByteCount = Encoding.ASCII.GetByteCount(headerEncoded);
        IMemoryOwner<byte> aadRawOwner = pool.Rent(aadByteCount);
        Encoding.ASCII.GetBytes(headerEncoded, aadRawOwner.Memory.Span);
        using AdditionalData aad = new AdditionalData(aadRawOwner, CryptoTags.AesGcmAad);

        //Step 3: Key derivation — pure software math, synchronous.
        string encryptionAlgorithm = (string)unencryptedJwe.Header[WellKnownJwkValues.Enc];
        int keydataLenBits = WellKnownJweEncryptionAlgorithms.IsA128Gcm(encryptionAlgorithm) ? 128 : 256;

        using ContentEncryptionKey cek = keyDerivationDelegate(
            agreement.SharedSecret,
            encryptionAlgorithm,
            ReadOnlySpan<byte>.Empty,
            ReadOnlySpan<byte>.Empty,
            keydataLenBits,
            pool);

        //Step 4: Symmetric encryption with the derived CEK and the encoded header as AAD.
        AeadEncryptResult encryptResult = await aeadEncryptDelegate(
            unencryptedJwe.Plaintext,
            cek,
            aad,
            pool,
            cancellationToken).ConfigureAwait(false);

        PublicKeyMemory epk = new PublicKeyMemory(epkOwner, epkTag);

        return new JweMessage(completeHeader, headerEncoded, epk, encryptResult, encryptionAlgorithm);
    }


    /// <summary>
    /// Decrypts the <see cref="AeadMessage"/> using explicit delegates for each step.
    /// </summary>
    /// <param name="message">The parsed and validated AEAD message to decrypt.</param>
    /// <param name="privateKey">The recipient's private key for ECDH key agreement.</param>
    /// <param name="agreementDelegate">The ECDH key agreement delegate.</param>
    /// <param name="keyDerivationDelegate">The key derivation delegate.</param>
    /// <param name="aeadDecryptDelegate">The symmetric decryption delegate.</param>
    /// <param name="pool">Memory pool for all allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The decrypted plaintext. The caller owns and must dispose it.
    /// </returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// Thrown when authentication tag verification fails.
    /// </exception>
    public static async ValueTask<DecryptedContent> DecryptAsync(
        this AeadMessage message,
        PrivateKeyMemory privateKey,
        KeyAgreementDecryptDelegate agreementDelegate,
        KeyDerivationDelegate keyDerivationDelegate,
        AeadDecryptDelegate aeadDecryptDelegate,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(agreementDelegate);
        ArgumentNullException.ThrowIfNull(keyDerivationDelegate);
        ArgumentNullException.ThrowIfNull(aeadDecryptDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        //Step 1: ECDH key agreement — may be a remote TPM/HSM call.
        using SharedSecret sharedSecret = await privateKey.WithKeyBytesAsync(
            static (keyBytes, state) =>
                state.Delegate(keyBytes, state.Epk, state.Pool, state.CancellationToken),
            (Delegate: agreementDelegate,
             Epk: message.Epk,
             Pool: pool,
             CancellationToken: cancellationToken)).ConfigureAwait(false);

        //Step 2: Key derivation — pure software math, synchronous.
        int keydataLenBits = WellKnownJweEncryptionAlgorithms.IsA128Gcm(message.EncryptionAlgorithm)
            ? 128
            : 256;

        using ContentEncryptionKey cek = keyDerivationDelegate(
            sharedSecret,
            message.EncryptionAlgorithm,
            ReadOnlySpan<byte>.Empty,
            ReadOnlySpan<byte>.Empty,
            keydataLenBits,
            pool);

        //Step 3: Symmetric decryption — may be a remote HSM call.
        return await aeadDecryptDelegate(
            message.EncryptedBytes,
            cek,
            message.Iv,
            message.Tag,
            message.Aad,
            pool,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Decrypts the <see cref="AeadMessage"/> by resolving all delegates from the
    /// registry using the private key's <see cref="Tag"/>.
    /// </summary>
    /// <param name="message">The parsed and validated AEAD message to decrypt.</param>
    /// <param name="privateKey">The recipient's private key for ECDH key agreement.</param>
    /// <param name="pool">Memory pool for all allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The decrypted plaintext. The caller owns and must dispose it.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the registry has not been initialized.
    /// </exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// Thrown when authentication tag verification fails.
    /// </exception>
    public static ValueTask<DecryptedContent> DecryptAsync(
        this AeadMessage message,
        PrivateKeyMemory privateKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(pool);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();

        KeyAgreementDecryptDelegate agreementDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAgreementDecrypt(
                algorithm, purpose);
        KeyDerivationDelegate keyDerivationDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveKeyDerivation(
                algorithm, purpose);
        AeadDecryptDelegate aeadDecryptDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAeadDecrypt(
                algorithm, purpose);

        return message.DecryptAsync(
            privateKey,
            agreementDelegate,
            keyDerivationDelegate,
            aeadDecryptDelegate,
            pool,
            cancellationToken);
    }
}
