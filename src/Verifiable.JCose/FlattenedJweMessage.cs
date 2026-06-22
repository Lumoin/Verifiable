using System.Buffers;
using System.Diagnostics;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.JCose;

/// <summary>
/// A complete single-recipient JWE produced by the encrypt flow, serialized with the JWE
/// Flattened JSON Serialization of
/// <see href="https://www.rfc-editor.org/rfc/rfc7516#section-7.2.2">RFC 7516 §7.2.2</see>.
/// </summary>
/// <remarks>
/// <para>
/// The Flattened JSON Serialization is the General JSON Serialization optimized for the
/// single-recipient case: the <c>recipients</c> array is removed and that single recipient's
/// <c>header</c> and <c>encrypted_key</c> members are placed in the top-level object alongside
/// <c>protected</c>, <c>iv</c>, <c>ciphertext</c>, and <c>tag</c>. RFC 7516 §7.2.2: "The
/// 'recipients' member MUST NOT be present when using this syntax. Other than this syntax
/// difference, JWE JSON Serialization objects using the flattened syntax are processed
/// identically to those using the general syntax."
/// </para>
/// <para>
/// This type is the single-recipient counterpart to <see cref="GeneralJweMessage"/>. It owns
/// all encrypted components and must be disposed to return memory to the pool. Parsing a
/// flattened serialization with <see cref="GeneralJweParsing.ParseFlattenedJson"/> yields the
/// same <see cref="AeadGeneralMessage"/> a single-recipient general serialization would, so a
/// flattened message decrypts identically through the General decrypt extensions.
/// </para>
/// </remarks>
[DebuggerDisplay("FlattenedJweMessage EncryptionAlgorithm={EncryptionAlgorithm} KeyId={Recipient.KeyId}")]
public sealed class FlattenedJweMessage: IDisposable
{
    private bool disposed;

    /// <summary>The fully assembled protected header, including <c>alg</c>, <c>enc</c>, and <c>epk</c>.</summary>
    public JwtHeader Header { get; }

    /// <summary>The Base64url-encoded protected header string used as AAD per RFC 7516 §5.1 step 14.</summary>
    public string HeaderEncoded { get; }

    /// <summary>The sender's ephemeral public key in uncompressed or raw OKP encoding.</summary>
    public PublicKeyMemory EphemeralPublicKey { get; }

    /// <summary>The shared symmetric encryption result: IV, ciphertext, and authentication tag.</summary>
    public AeadEncryptResult EncryptResult { get; }

    /// <summary>The single recipient entry carrying the <c>kid</c> and the wrapped CEK.</summary>
    public GeneralJweRecipient Recipient { get; }

    /// <summary>The content encryption algorithm identifier, e.g. <c>A256CBC-HS512</c>.</summary>
    public string EncryptionAlgorithm { get; }


    /// <summary>
    /// Initializes a <see cref="FlattenedJweMessage"/>. Ownership of all disposable components
    /// transfers to this instance.
    /// </summary>
    public FlattenedJweMessage(
        JwtHeader header,
        string headerEncoded,
        PublicKeyMemory ephemeralPublicKey,
        AeadEncryptResult encryptResult,
        GeneralJweRecipient recipient,
        string encryptionAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentException.ThrowIfNullOrWhiteSpace(headerEncoded);
        ArgumentNullException.ThrowIfNull(ephemeralPublicKey);
        ArgumentNullException.ThrowIfNull(encryptResult);
        ArgumentNullException.ThrowIfNull(recipient);
        ArgumentException.ThrowIfNullOrWhiteSpace(encryptionAlgorithm);

        Header = header;
        HeaderEncoded = headerEncoded;
        EphemeralPublicKey = ephemeralPublicKey;
        EncryptResult = encryptResult;
        Recipient = recipient;
        EncryptionAlgorithm = encryptionAlgorithm;
    }


    /// <summary>
    /// Adapts a single-recipient <see cref="GeneralJweMessage"/> to its flattened form,
    /// transferring ownership of the general message's components to the returned instance.
    /// </summary>
    /// <remarks>
    /// The transfer is enforced: the source <paramref name="generalMessage"/> is neutralized so
    /// its <see cref="GeneralJweMessage.Dispose"/> becomes a no-op. This makes the idiomatic
    /// double-<c>using</c> (<c>using GeneralJweMessage g = ...; using FlattenedJweMessage f =
    /// FlattenedJweMessage.FromGeneral(g);</c>) safe — the shared components are disposed exactly
    /// once, by the returned flattened message.
    /// </remarks>
    /// <param name="generalMessage">A General JSON JWE with exactly one recipient.</param>
    /// <returns>The equivalent <see cref="FlattenedJweMessage"/>.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="generalMessage"/> does not have exactly one recipient — the
    /// flattened syntax is single-recipient only (RFC 7516 §7.2.2).
    /// </exception>
    public static FlattenedJweMessage FromGeneral(GeneralJweMessage generalMessage)
    {
        ArgumentNullException.ThrowIfNull(generalMessage);

        if(generalMessage.Recipients.Count != 1)
        {
            throw new ArgumentException(
                "The JWE Flattened JSON Serialization is single-recipient only (RFC 7516 §7.2.2); "
                + $"the general message has {generalMessage.Recipients.Count} recipients.",
                nameof(generalMessage));
        }

        FlattenedJweMessage flattened = new(
            generalMessage.Header,
            generalMessage.HeaderEncoded,
            generalMessage.EphemeralPublicKey,
            generalMessage.EncryptResult,
            generalMessage.Recipients[0],
            generalMessage.EncryptionAlgorithm);

        //The components now belong to the flattened message; neutralize the source so a
        //double-using does not dispose them twice.
        generalMessage.MarkOwnershipTransferred();

        return flattened;
    }


    /// <summary>
    /// Serializes this message to a JWE Flattened JSON Serialization string per
    /// RFC 7516 §7.2.2: a JSON object with <c>protected</c>, top-level <c>header</c> and
    /// <c>encrypted_key</c>, <c>iv</c>, <c>ciphertext</c>, and <c>tag</c> members and no
    /// <c>recipients</c> array.
    /// </summary>
    /// <param name="base64UrlEncoder">Delegate for Base64url encoding.</param>
    /// <returns>The JWE Flattened JSON Serialization string.</returns>
    public string ToFlattenedJson(EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        StringBuilder builder = new();
        builder.Append("{\"protected\":");
        JweJsonString.Append(builder, HeaderEncoded);
        builder.Append(",\"header\":{\"kid\":");
        JweJsonString.Append(builder, Recipient.KeyId);
        builder.Append("},\"encrypted_key\":");
        JweJsonString.Append(builder, base64UrlEncoder(Recipient.EncryptedKey.AsReadOnlySpan()));
        builder.Append(",\"iv\":");
        JweJsonString.Append(builder, base64UrlEncoder(EncryptResult.Iv.AsReadOnlySpan()));
        builder.Append(",\"ciphertext\":");
        JweJsonString.Append(builder, base64UrlEncoder(EncryptResult.Ciphertext.AsReadOnlySpan()));
        builder.Append(",\"tag\":");
        JweJsonString.Append(builder, base64UrlEncoder(EncryptResult.Tag.AsReadOnlySpan()));
        builder.Append('}');

        return builder.ToString();
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            EphemeralPublicKey.Dispose();
            EncryptResult.Dispose();
            Recipient.Dispose();
            disposed = true;
        }
    }
}
