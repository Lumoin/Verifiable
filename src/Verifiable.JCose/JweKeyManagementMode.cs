namespace Verifiable.JCose;

/// <summary>
/// The Key Management Mode of a JWE key management (<c>alg</c>) algorithm per
/// <see href="https://www.rfc-editor.org/rfc/rfc7516#section-2">RFC 7516 §2</see>.
/// </summary>
/// <remarks>
/// <para>
/// RFC 7516 §2 enumerates exactly five Key Management Modes — the method by which a JWE
/// determines the Content Encryption Key. The mode is a property of the <c>alg</c> value,
/// so it is carried on <see cref="JweAlgorithm"/> and dispatched on once at the orchestration
/// boundary rather than re-derived from <c>alg</c> string comparisons scattered through the
/// encrypt and decrypt paths.
/// </para>
/// <para>
/// The mode determines the structural shape of the JWE: whether a <c>JWE Encrypted Key</c>
/// slot is populated (<see cref="KeyWrapping"/>, <see cref="KeyEncryption"/>,
/// <see cref="KeyAgreementWithKeyWrapping"/>) or MUST be the empty octet sequence
/// (<see cref="DirectKeyAgreement"/>, <see cref="DirectEncryption"/>) per RFC 7516 §5.1
/// steps 4–6 and §5.2 step 10.
/// </para>
/// </remarks>
public enum JweKeyManagementMode
{
    /// <summary>
    /// Direct Key Agreement (RFC 7516 §2): a key agreement algorithm agrees the CEK directly.
    /// The JWE Encrypted Key is the empty octet sequence. Used by <c>ECDH-ES</c>.
    /// </summary>
    DirectKeyAgreement,

    /// <summary>
    /// Key Agreement with Key Wrapping (RFC 7516 §2): a key agreement algorithm agrees a
    /// symmetric key encryption key that wraps the CEK. The JWE Encrypted Key carries the
    /// wrapped CEK. Used by <c>ECDH-ES+A*KW</c> and <c>ECDH-1PU+A*KW</c>.
    /// </summary>
    KeyAgreementWithKeyWrapping,

    /// <summary>
    /// Key Wrapping (RFC 7516 §2): a pre-shared symmetric key wraps the CEK with a symmetric
    /// key wrapping algorithm. The JWE Encrypted Key carries the wrapped CEK. Used by
    /// <c>A128KW</c>/<c>A192KW</c>/<c>A256KW</c>.
    /// </summary>
    KeyWrapping,

    /// <summary>
    /// Direct Encryption (RFC 7516 §2): the CEK is the pre-shared symmetric key value. The JWE
    /// Encrypted Key is the empty octet sequence. Used by <c>dir</c>.
    /// </summary>
    DirectEncryption,

    /// <summary>
    /// Key Encryption (RFC 7516 §2): an asymmetric encryption algorithm encrypts the CEK to the
    /// recipient. The JWE Encrypted Key carries the encrypted CEK. Used by <c>RSA-OAEP</c> and
    /// <c>RSA-OAEP-256</c>, which are not yet implemented.
    /// </summary>
    KeyEncryption
}
