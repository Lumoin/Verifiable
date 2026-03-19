using System.Diagnostics;

namespace Verifiable.JCose;

/// <summary>
/// An unencrypted JWE consisting of a protected header and plaintext, ready for encryption.
/// </summary>
/// <remarks>
/// <para>
/// This type is the JWE counterpart to <see cref="UnsignedJwt"/>. It is the anchor for
/// <see cref="JweEncryptionExtensions.EncryptAsync"/> and makes the intent explicit in the
/// type system — an <see cref="UnencryptedJwe"/> must be encrypted to produce a
/// <see cref="JweMessage"/>, just as an <see cref="UnsignedJwt"/> must be signed to
/// produce a <see cref="JwsMessage"/>.
/// </para>
/// <para>
/// The header at construction time contains <c>alg</c> and <c>enc</c> but not <c>epk</c>.
/// The ephemeral public key is added by <see cref="JweEncryptionExtensions.EncryptAsync"/>
/// after key agreement completes, because the EPK is generated fresh per encryption
/// operation and is not known until then.
/// </para>
/// <para>
/// The plaintext is stored as <see cref="ReadOnlyMemory{T}"/> so it can cross async
/// boundaries without copying.
/// </para>
/// </remarks>
[DebuggerDisplay("UnencryptedJwe(Header: {Header.Count} entries, Plaintext: {Plaintext.Length} bytes)")]
public sealed class UnencryptedJwe
{
    /// <summary>
    /// The JWE protected header. Contains <c>alg</c> and <c>enc</c> at minimum.
    /// The <c>epk</c> parameter is absent — it is added during encryption.
    /// </summary>
    public JwtHeader Header { get; }

    /// <summary>The plaintext bytes to encrypt.</summary>
    public ReadOnlyMemory<byte> Plaintext { get; }


    /// <summary>
    /// Creates an <see cref="UnencryptedJwe"/> from an explicit header and plaintext.
    /// </summary>
    /// <param name="header">
    /// The JWE protected header. Must contain at minimum <c>alg</c> and <c>enc</c>.
    /// </param>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    public UnencryptedJwe(JwtHeader header, ReadOnlyMemory<byte> plaintext)
    {
        ArgumentNullException.ThrowIfNull(header);

        Header = header;
        Plaintext = plaintext;
    }


    /// <summary>
    /// Creates an <see cref="UnencryptedJwe"/> for ECDH-ES content encryption,
    /// populating the header with <c>alg</c> and <c>enc</c> from the supplied constants.
    /// </summary>
    /// <param name="keyManagementAlgorithm">
    /// The key management algorithm identifier for the <c>alg</c> parameter,
    /// e.g. <see cref="WellKnownJweAlgorithms.EcdhEs"/>.
    /// </param>
    /// <param name="contentEncryptionAlgorithm">
    /// The content encryption algorithm identifier for the <c>enc</c> parameter,
    /// e.g. <see cref="WellKnownJweEncryptionAlgorithms.A128Gcm"/>.
    /// </param>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <returns>An <see cref="UnencryptedJwe"/> ready for encryption.</returns>
    public static UnencryptedJwe ForEcdhEs(
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm,
        ReadOnlyMemory<byte> plaintext)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyManagementAlgorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentEncryptionAlgorithm);

        var header = new JwtHeader(capacity: 2)
        {
            [WellKnownJwkValues.Alg] = keyManagementAlgorithm,
            [WellKnownJwkValues.Enc] = contentEncryptionAlgorithm
        };

        return new UnencryptedJwe(header, plaintext);
    }
}
