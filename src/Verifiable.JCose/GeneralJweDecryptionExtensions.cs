using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.JCose;

/// <summary>
/// Decrypt-side orchestration for multi-recipient JWE in General JSON Serialization —
/// anoncrypt (ECDH-ES+A*KW) and authcrypt (ECDH-1PU+A*KW) for DIDComm v2.
/// </summary>
/// <remarks>
/// <para>
/// A recipient selects its own <c>recipients</c> entry by <c>kid</c>, agrees with the
/// shared ephemeral public key (and, for authcrypt, the sender's static public key), derives
/// the key encryption key, unwraps the CEK, and decrypts the shared ciphertext.
/// </para>
/// <para>
/// <strong>Verify-before-trust.</strong> In authcrypt the JWE Authentication Tag is committed
/// into the key derivation (1PU §2.1). A tampered tag therefore derives a different key
/// encryption key, so the RFC 3394 unwrap integrity check fails before any AEAD tag check is
/// reached — a tampered tag cannot produce a usable CEK. The AEAD tag is additionally
/// verified during content decryption.
/// </para>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "The caller takes ownership of the returned DecryptedContent and is responsible for disposing it.")]
public static class GeneralJweDecryptionExtensions
{
    /// <summary>
    /// Decrypts an anoncrypt (ECDH-ES+A*KW) recipient entry from a parsed multi-recipient JWE.
    /// </summary>
    /// <param name="message">The parsed and validated General JSON JWE.</param>
    /// <param name="recipientKeyId">The <c>kid</c> of the recipient entry to decrypt.</param>
    /// <param name="recipientPrivateKey">The recipient's static private key.</param>
    /// <param name="agreementDelegate">The decrypt-side ECDH-ES agreement delegate.</param>
    /// <param name="keyDerivationDelegate">The Concat KDF delegate (no tag commitment for ECDH-ES).</param>
    /// <param name="keyUnwrapDelegate">The RFC 3394 key unwrap delegate.</param>
    /// <param name="aeadDecryptDelegate">The content decryption delegate.</param>
    /// <param name="pool">Memory pool for all allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The decrypted plaintext. The caller owns and must dispose it.</returns>
    /// <exception cref="FormatException">Thrown when no recipient entry matches <paramref name="recipientKeyId"/>.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when the unwrap or AEAD tag check fails.</exception>
    public static async ValueTask<DecryptedContent> DecryptAnoncryptAsync(
        this AeadGeneralMessage message,
        string recipientKeyId,
        PrivateKeyMemory recipientPrivateKey,
        KeyAgreementDecryptDelegate agreementDelegate,
        KeyDerivationDelegate keyDerivationDelegate,
        KeyUnwrapDelegate keyUnwrapDelegate,
        AeadDecryptDelegate aeadDecryptDelegate,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentException.ThrowIfNullOrWhiteSpace(recipientKeyId);
        ArgumentNullException.ThrowIfNull(recipientPrivateKey);
        ArgumentNullException.ThrowIfNull(agreementDelegate);
        ArgumentNullException.ThrowIfNull(keyDerivationDelegate);
        ArgumentNullException.ThrowIfNull(keyUnwrapDelegate);
        ArgumentNullException.ThrowIfNull(aeadDecryptDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        AeadGeneralRecipient recipient = RequireRecipient(message, recipientKeyId);

        using SharedSecret sharedSecret = await recipientPrivateKey.WithKeyBytesAsync(
            static (keyBytes, state) =>
                state.Agreement(keyBytes, state.Epk, state.Pool, state.CancellationToken),
            (Agreement: agreementDelegate,
             Epk: message.Epk,
             Pool: pool,
             CancellationToken: cancellationToken)).ConfigureAwait(false);

        //apv/apu are consumed as the JWE PartyV/PartyUInfo. At this generic-JWE layer apv is an OPAQUE octet
        //string (a JWE may carry any PartyVInfo — e.g. the RFC 7516 Appendix B vector). The DIDComm profile's
        //apv = SHA-256(sorted recipient kids) recipient-binding is verified at the DIDComm unpack layer, not
        //here, so a non-DIDComm JWE is not rejected for a non-conforming apv.
        using IMemoryOwner<byte>? apuOwner = DecodeAgreementInfo(message.Header, WellKnownJoseHeaderNames.Apu, pool, out int apuLength);
        using IMemoryOwner<byte>? apvOwner = DecodeAgreementInfo(message.Header, WellKnownJoseHeaderNames.Apv, pool, out int apvLength);

        int keydataLenBits = JweKeyManagement.RequireKeyWrapBits(message.KeyManagementAlgorithm);

        using ContentEncryptionKey kek = keyDerivationDelegate(
            sharedSecret,
            message.KeyManagementAlgorithm,
            apuOwner is null ? ReadOnlySpan<byte>.Empty : apuOwner.Memory.Span[..apuLength],
            apvOwner is null ? ReadOnlySpan<byte>.Empty : apvOwner.Memory.Span[..apvLength],
            keydataLenBits,
            pool);

        return await UnwrapAndDecryptAsync(
            message, recipient, kek, keyUnwrapDelegate, aeadDecryptDelegate, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Decrypts an authcrypt (ECDH-1PU+A*KW) recipient entry from a parsed multi-recipient JWE.
    /// </summary>
    /// <param name="message">The parsed and validated General JSON JWE.</param>
    /// <param name="recipientKeyId">The <c>kid</c> of the recipient entry to decrypt.</param>
    /// <param name="recipientPrivateKey">The recipient's static private key.</param>
    /// <param name="senderStaticPublicKey">The sender's static public key for the authenticating agreement (Zs).</param>
    /// <param name="agreementDelegate">The decrypt-side ECDH-1PU agreement delegate.</param>
    /// <param name="authenticatedKeyDerivationDelegate">The tag-committed Concat KDF delegate.</param>
    /// <param name="keyUnwrapDelegate">The RFC 3394 key unwrap delegate.</param>
    /// <param name="aeadDecryptDelegate">The AES_CBC_HMAC_SHA2 content decryption delegate.</param>
    /// <param name="pool">Memory pool for all allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The decrypted plaintext. The caller owns and must dispose it.</returns>
    /// <exception cref="FormatException">Thrown when no recipient entry matches <paramref name="recipientKeyId"/>.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// Thrown when the unwrap (including the tag-commitment check) or the AEAD tag check fails.
    /// </exception>
    public static async ValueTask<DecryptedContent> DecryptAuthcryptAsync(
        this AeadGeneralMessage message,
        string recipientKeyId,
        PrivateKeyMemory recipientPrivateKey,
        PublicKeyMemory senderStaticPublicKey,
        AuthenticatedKeyAgreementDecryptDelegate agreementDelegate,
        AuthenticatedKeyDerivationDelegate authenticatedKeyDerivationDelegate,
        KeyUnwrapDelegate keyUnwrapDelegate,
        AeadDecryptDelegate aeadDecryptDelegate,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentException.ThrowIfNullOrWhiteSpace(recipientKeyId);
        ArgumentNullException.ThrowIfNull(recipientPrivateKey);
        ArgumentNullException.ThrowIfNull(senderStaticPublicKey);
        ArgumentNullException.ThrowIfNull(agreementDelegate);
        ArgumentNullException.ThrowIfNull(authenticatedKeyDerivationDelegate);
        ArgumentNullException.ThrowIfNull(keyUnwrapDelegate);
        ArgumentNullException.ThrowIfNull(aeadDecryptDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        AeadGeneralRecipient recipient = RequireRecipient(message, recipientKeyId);

        using SharedSecret sharedSecret = await recipientPrivateKey.WithKeyBytesAsync(
            static (keyBytes, state) =>
                state.Agreement(keyBytes, state.Epk, state.SenderPublic, state.Pool, state.CancellationToken),
            (Agreement: agreementDelegate,
             Epk: message.Epk,
             SenderPublic: senderStaticPublicKey,
             Pool: pool,
             CancellationToken: cancellationToken)).ConfigureAwait(false);

        //apv/apu are consumed as the JWE PartyV/PartyUInfo. At this generic-JWE layer apv is an OPAQUE octet
        //string (a JWE may carry any PartyVInfo — e.g. the RFC 7516 Appendix B vector). The DIDComm profile's
        //apv = SHA-256(sorted recipient kids) recipient-binding is verified at the DIDComm unpack layer, not
        //here, so a non-DIDComm JWE is not rejected for a non-conforming apv.
        using IMemoryOwner<byte>? apuOwner = DecodeAgreementInfo(message.Header, WellKnownJoseHeaderNames.Apu, pool, out int apuLength);
        using IMemoryOwner<byte>? apvOwner = DecodeAgreementInfo(message.Header, WellKnownJoseHeaderNames.Apv, pool, out int apvLength);

        int keydataLenBits = JweKeyManagement.RequireKeyWrapBits(message.KeyManagementAlgorithm);

        //The JWE Authentication Tag is committed into the derivation (1PU §2.1). A tampered
        //tag derives a different key encryption key, so the unwrap below fails before any
        //content decryption is attempted. Take the tag span after the await so it does not
        //cross an await boundary.
        ReadOnlySpan<byte> committedTag = message.Tag.AsReadOnlySpan();

        using ContentEncryptionKey kek = authenticatedKeyDerivationDelegate(
            sharedSecret,
            message.KeyManagementAlgorithm,
            apuOwner is null ? ReadOnlySpan<byte>.Empty : apuOwner.Memory.Span[..apuLength],
            apvOwner is null ? ReadOnlySpan<byte>.Empty : apvOwner.Memory.Span[..apvLength],
            keydataLenBits,
            committedTag,
            pool);

        return await UnwrapAndDecryptAsync(
            message, recipient, kek, keyUnwrapDelegate, aeadDecryptDelegate, pool, cancellationToken).ConfigureAwait(false);
    }


    private static async ValueTask<DecryptedContent> UnwrapAndDecryptAsync(
        AeadGeneralMessage message,
        AeadGeneralRecipient recipient,
        ContentEncryptionKey kek,
        KeyUnwrapDelegate keyUnwrapDelegate,
        AeadDecryptDelegate aeadDecryptDelegate,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        using SymmetricKeyMemory kekKey = kek.UseKey();

        //RFC 3394 unwrap verifies the embedded integrity value: a wrong key encryption key
        //(for instance because a tampered authcrypt tag derived a wrong KEK) throws here.
        using SymmetricKeyMemory cek = await keyUnwrapDelegate(
            kekKey, recipient.WrappedKey, pool, cancellationToken).ConfigureAwait(false);

        return await aeadDecryptDelegate(
            message.EncryptedBytes,
            cek,
            message.Iv,
            message.Tag,
            message.Aad,
            pool,
            cancellationToken).ConfigureAwait(false);
    }


    private static AeadGeneralRecipient RequireRecipient(AeadGeneralMessage message, string recipientKeyId)
    {
        AeadGeneralRecipient? recipient = message.FindRecipient(recipientKeyId);
        if(recipient is null)
        {
            throw new FormatException(
                $"No recipient entry in the General JSON JWE carries kid '{recipientKeyId}'.");
        }

        return recipient;
    }


    private static IMemoryOwner<byte>? DecodeAgreementInfo(
        IReadOnlyDictionary<string, object> header,
        string parameterName,
        MemoryPool<byte> pool,
        out int length)
    {
        length = 0;
        if(!header.TryGetValue(parameterName, out object? value) || value is not string encoded || encoded.Length == 0)
        {
            return null;
        }

        int maxLength = System.Buffers.Text.Base64Url.GetMaxDecodedLength(encoded.Length);
        IMemoryOwner<byte> owner = pool.Rent(maxLength);
        if(!System.Buffers.Text.Base64Url.TryDecodeFromChars(encoded, owner.Memory.Span, out int written))
        {
            owner.Dispose();
            throw new FormatException($"Header parameter '{parameterName}' is not valid base64url.");
        }

        length = written;

        return owner;
    }


}
