using System.Buffers;
using System.Diagnostics;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.JCose;

/// <summary>
/// A complete multi-recipient JWE produced by the encrypt flow, serialized with the JWE
/// General JSON Serialization of
/// <see href="https://www.rfc-editor.org/rfc/rfc7516#section-7.2">RFC 7516 §7.2</see>.
/// </summary>
/// <remarks>
/// <para>
/// The General JSON Serialization shares one protected header, one IV, one ciphertext, and
/// one authentication tag across all recipients; only the per-recipient <c>encrypted_key</c>
/// (the CEK wrapped under each recipient's derived key encryption key) and the per-recipient
/// <c>kid</c> differ. This is the wire form for DIDComm v2 encrypted messages — anoncrypt
/// (ECDH-ES+A*KW) and authcrypt (ECDH-1PU+A*KW with the AES_CBC_HMAC_SHA2 content
/// encryption family).
/// </para>
/// <para>
/// This type is the multi-recipient counterpart to <see cref="JweMessage"/> (which carries
/// the single-recipient compact serialization). It owns all encrypted components and must
/// be disposed to return memory to the pool.
/// </para>
/// </remarks>
[DebuggerDisplay("GeneralJweMessage EncryptionAlgorithm={EncryptionAlgorithm} Recipients={Recipients.Count}")]
public sealed class GeneralJweMessage: IDisposable
{
    private bool disposed;

    /// <summary>The fully assembled protected header, including <c>alg</c>, <c>enc</c>, and <c>epk</c>.</summary>
    public JwtHeader Header { get; }

    /// <summary>The Base64url-encoded protected header string used as AAD per RFC 7516 §5.1 step 14.</summary>
    public string HeaderEncoded { get; }

    /// <summary>
    /// The sender's shared ephemeral public key in uncompressed encoding (<c>0x04 || X || Y</c>)
    /// or raw OKP encoding. The same ephemeral key is used for every recipient.
    /// </summary>
    public PublicKeyMemory EphemeralPublicKey { get; }

    /// <summary>The shared symmetric encryption result: IV, ciphertext, and authentication tag.</summary>
    public AeadEncryptResult EncryptResult { get; }

    /// <summary>The per-recipient entries, each carrying a <c>kid</c> and a wrapped CEK.</summary>
    public IReadOnlyList<GeneralJweRecipient> Recipients { get; }

    /// <summary>The content encryption algorithm identifier, e.g. <c>A256CBC-HS512</c>.</summary>
    public string EncryptionAlgorithm { get; }


    /// <summary>
    /// Initializes a <see cref="GeneralJweMessage"/>. Ownership of all disposable components
    /// transfers to this instance.
    /// </summary>
    public GeneralJweMessage(
        JwtHeader header,
        string headerEncoded,
        PublicKeyMemory ephemeralPublicKey,
        AeadEncryptResult encryptResult,
        IReadOnlyList<GeneralJweRecipient> recipients,
        string encryptionAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentException.ThrowIfNullOrWhiteSpace(headerEncoded);
        ArgumentNullException.ThrowIfNull(ephemeralPublicKey);
        ArgumentNullException.ThrowIfNull(encryptResult);
        ArgumentNullException.ThrowIfNull(recipients);
        ArgumentException.ThrowIfNullOrWhiteSpace(encryptionAlgorithm);

        if(recipients.Count == 0)
        {
            throw new ArgumentException(
                "A General JSON JWE must have at least one recipient.", nameof(recipients));
        }

        Header = header;
        HeaderEncoded = headerEncoded;
        EphemeralPublicKey = ephemeralPublicKey;
        EncryptResult = encryptResult;
        Recipients = recipients;
        EncryptionAlgorithm = encryptionAlgorithm;
    }


    /// <summary>
    /// Serializes this message to a JWE General JSON Serialization string per
    /// RFC 7516 §7.2.1.
    /// </summary>
    /// <remarks>
    /// The output is a JSON object with members <c>protected</c>, <c>recipients</c>,
    /// <c>iv</c>, <c>ciphertext</c>, and <c>tag</c>. The <c>protected</c> member carries the
    /// already-base64url-encoded protected header exactly as it appeared in the AAD; the
    /// IV, ciphertext, tag, and each <c>encrypted_key</c> are base64url-encoded here.
    /// </remarks>
    /// <param name="base64UrlEncoder">Delegate for Base64url encoding.</param>
    /// <returns>The JWE General JSON Serialization string.</returns>
    public string ToGeneralJson(EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        StringBuilder builder = new();
        builder.Append("{\"protected\":");
        JweJsonString.Append(builder, HeaderEncoded);
        builder.Append(",\"recipients\":[");

        for(int i = 0; i < Recipients.Count; ++i)
        {
            if(i > 0)
            {
                builder.Append(',');
            }

            GeneralJweRecipient recipient = Recipients[i];
            builder.Append("{\"header\":{\"kid\":");
            JweJsonString.Append(builder, recipient.KeyId);
            builder.Append("},\"encrypted_key\":");
            JweJsonString.Append(builder, base64UrlEncoder(recipient.EncryptedKey.AsReadOnlySpan()));
            builder.Append('}');
        }

        builder.Append("],\"iv\":");
        JweJsonString.Append(builder, base64UrlEncoder(EncryptResult.Iv.AsReadOnlySpan()));
        builder.Append(",\"ciphertext\":");
        JweJsonString.Append(builder, base64UrlEncoder(EncryptResult.Ciphertext.AsReadOnlySpan()));
        builder.Append(",\"tag\":");
        JweJsonString.Append(builder, base64UrlEncoder(EncryptResult.Tag.AsReadOnlySpan()));
        builder.Append('}');

        return builder.ToString();
    }


    /// <summary>
    /// Marks this message's components as transferred to another owner, so that
    /// <see cref="Dispose"/> becomes a no-op. Used when adapting to
    /// <see cref="FlattenedJweMessage"/>, which takes over the same disposable components:
    /// after the transfer this instance must not dispose them, or they would be disposed twice.
    /// </summary>
    internal void MarkOwnershipTransferred() => disposed = true;


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            EphemeralPublicKey.Dispose();
            EncryptResult.Dispose();
            for(int i = 0; i < Recipients.Count; ++i)
            {
                Recipients[i].Dispose();
            }

            disposed = true;
        }
    }
}
