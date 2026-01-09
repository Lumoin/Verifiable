namespace Verifiable.JCose;

/// <summary>
/// JOSE serialization formats per RFC 7515 (JWS) and RFC 7516 (JWE).
/// </summary>
public enum JoseSerializationFormat
{
    /// <summary>
    /// Compact serialization: URL-safe string, single signature/recipient.
    /// </summary>
    /// <remarks>
    /// <para>JWS: header.payload.signature (3 parts)</para>
    /// <para>JWE: header.encrypted_key.iv.ciphertext.tag (5 parts)</para>
    /// </remarks>
    Compact,

    /// <summary>
    /// Flattened JSON serialization: single signature/recipient, JSON object.
    /// </summary>
    FlattenedJson,

    /// <summary>
    /// General JSON serialization: multiple signatures/recipients, JSON object.
    /// </summary>
    GeneralJson
}