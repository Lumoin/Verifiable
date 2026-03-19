using System.Diagnostics;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// A parsed and validated AEAD message, produced by <see cref="JweParsing.ParseCompact"/>
/// and consumed by the decrypt flow.
/// </summary>
/// <remarks>
/// <para>
/// This type holds the components extracted from a compact JWE string after structural
/// and security validation. All fields are always populated — there is no partial state.
/// </para>
/// <para>
/// The encrypt flow produces <see cref="EphemeralKeyAgreementResult"/> and
/// <see cref="AeadEncryptResult"/> as separate types. This type is purely the
/// decrypt-input side.
/// </para>
/// <para>
/// All owned components are allocated from a memory pool and cleared on disposal.
/// Dispose promptly once decryption completes.
/// </para>
/// </remarks>
[DebuggerDisplay("AeadMessage EncryptionAlgorithm={EncryptionAlgorithm} CiphertextLength={EncryptedBytes.Length}")]
public sealed class AeadMessage: IDisposable
{
    private bool disposed;

    /// <summary>
    /// The parsed protected header entries. Contains at minimum <c>alg</c>, <c>enc</c>,
    /// and <c>epk</c>.
    /// </summary>
    public IReadOnlyDictionary<string, object> Header { get; }

    /// <summary>
    /// The sender's ephemeral public key in uncompressed encoding: <c>0x04 || X || Y</c>.
    /// The <see cref="Tag"/> identifies the curve and encoding.
    /// </summary>
    public PublicKeyMemory Epk { get; }

    /// <summary>The initialization vector nonce.</summary>
    public Nonce Iv { get; }

    /// <summary>The ciphertext bytes.</summary>
    public Ciphertext EncryptedBytes { get; }

    /// <summary>The AES-GCM authentication tag.</summary>
    public AuthenticationTag Tag { get; }

    /// <summary>
    /// The additional authenticated data — the ASCII-encoded Base64url protected header
    /// exactly as it appeared on the wire, per RFC 7516 §5.1 step 14.
    /// </summary>
    public AdditionalData Aad { get; }

    /// <summary>
    /// The content encryption algorithm identifier, e.g. <c>A128GCM</c>.
    /// </summary>
    public string EncryptionAlgorithm { get; }


    /// <summary>
    /// Initializes an <see cref="AeadMessage"/> from fully parsed JWE components.
    /// Ownership of all disposable components transfers to this object.
    /// </summary>
    public AeadMessage(
        IReadOnlyDictionary<string, object> header,
        PublicKeyMemory epk,
        Nonce iv,
        Ciphertext encryptedBytes,
        AuthenticationTag tag,
        AdditionalData aad,
        string encryptionAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(epk);
        ArgumentNullException.ThrowIfNull(iv);
        ArgumentNullException.ThrowIfNull(encryptedBytes);
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(aad);
        ArgumentException.ThrowIfNullOrWhiteSpace(encryptionAlgorithm);

        Header = header;
        Epk = epk;
        Iv = iv;
        EncryptedBytes = encryptedBytes;
        Tag = tag;
        Aad = aad;
        EncryptionAlgorithm = encryptionAlgorithm;
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
            disposed = true;
        }
    }
}
