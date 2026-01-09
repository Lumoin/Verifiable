namespace Verifiable.JCose;

/// <summary>
/// CBOR tags for COSE structures as defined in
/// <see href="https://www.iana.org/assignments/cose/cose.xhtml#cose-types">IANA COSE Types</see>.
/// </summary>
/// <remarks>
/// <para>
/// COSE messages use CBOR tags to identify the structure type.
/// Each tag corresponds to a specific COSE message format.
/// </para>
/// <para>
/// See <see href="https://www.rfc-editor.org/rfc/rfc9052">RFC 9052 - COSE Structures</see>.
/// </para>
/// </remarks>
public static class CoseTags
{
    /// <summary>
    /// COSE_Encrypt0 - Encrypted message with implicit key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Single recipient, key is determined implicitly.
    /// Structure: [protected, unprotected, ciphertext].
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9052#section-5.2">RFC 9052 §5.2</see>.
    /// </para>
    /// </remarks>
    public const int Encrypt0 = 16;

    /// <summary>
    /// COSE_Mac0 - MAC message with implicit key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Single recipient, key is determined implicitly.
    /// Structure: [protected, unprotected, payload, tag].
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9052#section-6.2">RFC 9052 §6.2</see>.
    /// </para>
    /// </remarks>
    public const int Mac0 = 17;

    /// <summary>
    /// COSE_Sign1 - Single signature message.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Message with exactly one signature.
    /// Structure: [protected, unprotected, payload, signature].
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.2">RFC 9052 §4.2</see>.
    /// </para>
    /// </remarks>
    public const int Sign1 = 18;

    /// <summary>
    /// COSE_Encrypt - Encrypted message with explicit recipients.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Multiple recipients supported, each with key material.
    /// Structure: [protected, unprotected, ciphertext, recipients].
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9052#section-5.1">RFC 9052 §5.1</see>.
    /// </para>
    /// </remarks>
    public const int Encrypt = 96;

    /// <summary>
    /// COSE_Mac - MAC message with explicit recipients.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Multiple recipients supported.
    /// Structure: [protected, unprotected, payload, tag, recipients].
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9052#section-6.1">RFC 9052 §6.1</see>.
    /// </para>
    /// </remarks>
    public const int Mac = 97;

    /// <summary>
    /// COSE_Sign - Multi-signature message.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Message with multiple signatures.
    /// Structure: [protected, unprotected, payload, signatures].
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.1">RFC 9052 §4.1</see>.
    /// </para>
    /// </remarks>
    public const int Sign = 98;


    /// <summary>
    /// Determines if the tag is <see cref="Sign1"/>.
    /// </summary>
    /// <param name="tag">The CBOR tag.</param>
    /// <returns><see langword="true"/> if the tag is COSE_Sign1; otherwise, <see langword="false"/>.</returns>
    public static bool IsSign1(int tag) => tag == Sign1;


    /// <summary>
    /// Determines if the tag is <see cref="Sign"/>.
    /// </summary>
    /// <param name="tag">The CBOR tag.</param>
    /// <returns><see langword="true"/> if the tag is COSE_Sign; otherwise, <see langword="false"/>.</returns>
    public static bool IsSign(int tag) => tag == Sign;


    /// <summary>
    /// Determines if the tag is <see cref="Encrypt0"/>.
    /// </summary>
    /// <param name="tag">The CBOR tag.</param>
    /// <returns><see langword="true"/> if the tag is COSE_Encrypt0; otherwise, <see langword="false"/>.</returns>
    public static bool IsEncrypt0(int tag) => tag == Encrypt0;


    /// <summary>
    /// Determines if the tag is <see cref="Encrypt"/>.
    /// </summary>
    /// <param name="tag">The CBOR tag.</param>
    /// <returns><see langword="true"/> if the tag is COSE_Encrypt; otherwise, <see langword="false"/>.</returns>
    public static bool IsEncrypt(int tag) => tag == Encrypt;


    /// <summary>
    /// Determines if the tag is <see cref="Mac0"/>.
    /// </summary>
    /// <param name="tag">The CBOR tag.</param>
    /// <returns><see langword="true"/> if the tag is COSE_Mac0; otherwise, <see langword="false"/>.</returns>
    public static bool IsMac0(int tag) => tag == Mac0;


    /// <summary>
    /// Determines if the tag is <see cref="Mac"/>.
    /// </summary>
    /// <param name="tag">The CBOR tag.</param>
    /// <returns><see langword="true"/> if the tag is COSE_Mac; otherwise, <see langword="false"/>.</returns>
    public static bool IsMac(int tag) => tag == Mac;


    /// <summary>
    /// Gets the structure name for a COSE tag.
    /// </summary>
    /// <param name="tag">The CBOR tag.</param>
    /// <returns>The structure name, or null if unknown.</returns>
    public static string? GetStructureName(int tag) => tag switch
    {
        Sign1 => "COSE_Sign1",
        Sign => "COSE_Sign",
        Encrypt0 => "COSE_Encrypt0",
        Encrypt => "COSE_Encrypt",
        Mac0 => "COSE_Mac0",
        Mac => "COSE_Mac",
        _ => null
    };
}