using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.JCose;

/// <summary>
/// A complete JWE (JSON Web Encryption) message produced by the encrypt flow.
/// </summary>
/// <remarks>
/// <para>
/// This type owns the encrypted components and must be disposed to return memory
/// to the pool.
/// </para>
/// <para>
/// The protected header is fully assembled — it includes <c>alg</c>, <c>enc</c>,
/// and <c>epk</c>. Call <see cref="ToCompactJwe"/> to serialize to the five-part
/// compact representation defined in RFC 7516 §3.1.
/// </para>
/// </remarks>
[DebuggerDisplay("JweMessage EncryptionAlgorithm={EncryptionAlgorithm} CiphertextLength={EncryptResult.Ciphertext.Length}")]
public sealed class JweMessage: IDisposable
{
    private bool disposed;

    /// <summary>
    /// The fully assembled protected header, including <c>alg</c>, <c>enc</c>, and <c>epk</c>.
    /// </summary>
    public JwtHeader Header { get; }

    /// <summary>The Base64url-encoded protected header string used as AAD.</summary>
    public string HeaderEncoded { get; }

    /// <summary>
    /// The sender's ephemeral public key in uncompressed encoding: <c>0x04 || X || Y</c>.
    /// The X and Y coordinates are split from this point when writing the JWK <c>epk</c>
    /// header parameter.
    /// </summary>
    public PublicKeyMemory EphemeralPublicKey { get; }

    /// <summary>The symmetric encryption result: IV, ciphertext, and authentication tag.</summary>
    public AeadEncryptResult EncryptResult { get; }

    /// <summary>The content encryption algorithm identifier, e.g. <c>A128GCM</c>.</summary>
    public string EncryptionAlgorithm { get; }


    /// <summary>
    /// Initializes a <see cref="JweMessage"/>. Ownership of all disposable components
    /// transfers to this instance.
    /// </summary>
    public JweMessage(
        JwtHeader header,
        string headerEncoded,
        PublicKeyMemory ephemeralPublicKey,
        AeadEncryptResult encryptResult,
        string encryptionAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentException.ThrowIfNullOrWhiteSpace(headerEncoded);
        ArgumentNullException.ThrowIfNull(ephemeralPublicKey);
        ArgumentNullException.ThrowIfNull(encryptResult);
        ArgumentException.ThrowIfNullOrWhiteSpace(encryptionAlgorithm);

        Header = header;
        HeaderEncoded = headerEncoded;
        EphemeralPublicKey = ephemeralPublicKey;
        EncryptResult = encryptResult;
        EncryptionAlgorithm = encryptionAlgorithm;
    }


    /// <summary>
    /// Serializes this message to a compact JWE string per RFC 7516 §3.1.
    /// The encrypted key slot is empty because ECDH-ES derives the CEK directly.
    /// </summary>
    /// <param name="base64UrlEncoder">Delegate for Base64url encoding.</param>
    /// <returns>The compact JWE string.</returns>
    public string ToCompactJwe(EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        return
            $"{HeaderEncoded}.." +
            $"{base64UrlEncoder(EncryptResult.Iv.AsReadOnlySpan())}" +
            $".{base64UrlEncoder(EncryptResult.Ciphertext.AsReadOnlySpan())}" +
            $".{base64UrlEncoder(EncryptResult.Tag.AsReadOnlySpan())}";
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            EphemeralPublicKey.Dispose();
            EncryptResult.Dispose();
            disposed = true;
        }
    }
}
