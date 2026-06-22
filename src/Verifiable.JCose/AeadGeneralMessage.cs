using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.JCose;

/// <summary>
/// A parsed and validated multi-recipient JWE in General JSON Serialization, produced by
/// <see cref="GeneralJweParsing.ParseGeneralJson"/> and consumed by the decrypt flow.
/// </summary>
/// <remarks>
/// <para>
/// This is the multi-recipient counterpart to <see cref="Verifiable.Cryptography.Aead.AeadMessage"/>:
/// it carries the shared protected header, ephemeral public key, IV, ciphertext,
/// authentication tag, and AAD, plus the parsed <c>recipients</c> array. A consumer
/// selects its own entry by <c>kid</c>, unwraps the CEK with the key encryption key
/// derived from its ECDH agreement, and decrypts the shared ciphertext.
/// </para>
/// <para>
/// All owned components are allocated from a memory pool and cleared on disposal.
/// </para>
/// </remarks>
[DebuggerDisplay("AeadGeneralMessage EncryptionAlgorithm={EncryptionAlgorithm} Recipients={Recipients.Count}")]
public sealed class AeadGeneralMessage: IDisposable
{
    private bool disposed;

    /// <summary>
    /// The parsed protected header entries. Contains at minimum <c>alg</c>, <c>enc</c>,
    /// and <c>epk</c>, and for authcrypt the <c>apu</c>/<c>apv</c> agreement info.
    /// </summary>
    public IReadOnlyDictionary<string, object> Header { get; }

    /// <summary>The sender's shared ephemeral public key. The <see cref="Tag"/> identifies the curve and encoding.</summary>
    public PublicKeyMemory Epk { get; }

    /// <summary>The shared initialization vector nonce.</summary>
    public Nonce Iv { get; }

    /// <summary>The shared ciphertext bytes.</summary>
    public Ciphertext EncryptedBytes { get; }

    /// <summary>The shared authentication tag.</summary>
    public AuthenticationTag Tag { get; }

    /// <summary>
    /// The additional authenticated data — the ASCII-encoded Base64url protected header
    /// exactly as it appeared on the wire, per RFC 7516 §5.1 step 14.
    /// </summary>
    public AdditionalData Aad { get; }

    /// <summary>The parsed per-recipient entries, each carrying a <c>kid</c> and a wrapped CEK.</summary>
    public IReadOnlyList<AeadGeneralRecipient> Recipients { get; }

    /// <summary>The content encryption algorithm identifier, e.g. <c>A256CBC-HS512</c>.</summary>
    public string EncryptionAlgorithm { get; }

    /// <summary>The key management algorithm identifier, e.g. <c>ECDH-1PU+A256KW</c>.</summary>
    public string KeyManagementAlgorithm { get; }


    /// <summary>
    /// Initializes an <see cref="AeadGeneralMessage"/> from fully parsed JWE components.
    /// Ownership of all disposable components transfers to this object.
    /// </summary>
    public AeadGeneralMessage(
        IReadOnlyDictionary<string, object> header,
        PublicKeyMemory epk,
        Nonce iv,
        Ciphertext encryptedBytes,
        AuthenticationTag tag,
        AdditionalData aad,
        IReadOnlyList<AeadGeneralRecipient> recipients,
        string encryptionAlgorithm,
        string keyManagementAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(epk);
        ArgumentNullException.ThrowIfNull(iv);
        ArgumentNullException.ThrowIfNull(encryptedBytes);
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(aad);
        ArgumentNullException.ThrowIfNull(recipients);
        ArgumentException.ThrowIfNullOrWhiteSpace(encryptionAlgorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyManagementAlgorithm);

        if(recipients.Count == 0)
        {
            throw new ArgumentException(
                "A General JSON JWE must have at least one recipient.", nameof(recipients));
        }

        Header = header;
        Epk = epk;
        Iv = iv;
        EncryptedBytes = encryptedBytes;
        Tag = tag;
        Aad = aad;
        Recipients = recipients;
        EncryptionAlgorithm = encryptionAlgorithm;
        KeyManagementAlgorithm = keyManagementAlgorithm;
    }


    /// <summary>
    /// Finds the <c>recipients</c> entry matching <paramref name="keyId"/>, or
    /// <see langword="null"/> when no entry carries that <c>kid</c>.
    /// </summary>
    /// <param name="keyId">The recipient <c>kid</c> to select.</param>
    public AeadGeneralRecipient? FindRecipient(string keyId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);

        for(int i = 0; i < Recipients.Count; ++i)
        {
            if(string.Equals(Recipients[i].KeyId, keyId, StringComparison.Ordinal))
            {
                return Recipients[i];
            }
        }

        return null;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            Epk.Dispose();
            Iv.Dispose();
            EncryptedBytes.Dispose();
            Tag.Dispose();
            Aad.Dispose();
            for(int i = 0; i < Recipients.Count; ++i)
            {
                Recipients[i].Dispose();
            }

            disposed = true;
        }
    }
}
