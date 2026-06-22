using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.JCose;

/// <summary>
/// One element of the <c>recipients</c> array in a JWE General JSON Serialization
/// per <see href="https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1">RFC 7516 §7.2.1</see>:
/// a per-recipient unprotected header carrying the recipient's <c>kid</c> and the CEK
/// wrapped for that recipient (the <c>encrypted_key</c>).
/// </summary>
/// <remarks>
/// <para>
/// The shared CEK is wrapped once per recipient with a key encryption key derived from
/// that recipient's own ECDH agreement, so each <see cref="EncryptedKey"/> differs while
/// the protected header, IV, ciphertext, and tag are shared across all recipients.
/// </para>
/// <para>
/// This type owns the <see cref="EncryptedKey"/> ciphertext and must be disposed.
/// </para>
/// </remarks>
[DebuggerDisplay("GeneralJweRecipient KeyId={KeyId}")]
public sealed class GeneralJweRecipient: IDisposable
{
    private bool disposed;

    /// <summary>
    /// The recipient's <c>kid</c> from the per-recipient unprotected <c>header</c>. In
    /// DIDComm v2 this is a DID URL to a <c>keyAgreement</c> verification method.
    /// </summary>
    public string KeyId { get; }

    /// <summary>The CEK wrapped for this recipient (the <c>encrypted_key</c> value).</summary>
    public Ciphertext EncryptedKey { get; }


    /// <summary>
    /// Initializes a <see cref="GeneralJweRecipient"/>. Ownership of
    /// <paramref name="encryptedKey"/> transfers to this instance.
    /// </summary>
    public GeneralJweRecipient(string keyId, Ciphertext encryptedKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentNullException.ThrowIfNull(encryptedKey);

        KeyId = keyId;
        EncryptedKey = encryptedKey;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            EncryptedKey.Dispose();
            disposed = true;
        }
    }
}
