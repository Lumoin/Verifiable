namespace Verifiable.OAuth.Siop;

/// <summary>
/// The Subject Syntax Type of a Self-Issued ID Token's <c>sub</c> claim per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-8">SIOPv2 §8</see>,
/// identified from the URI of the <c>sub</c> claim value (SIOPv2 §11.1).
/// </summary>
public enum SiopSubjectSyntaxType
{
    /// <summary>
    /// The <c>sub</c> claim value matches no Subject Syntax Type defined in SIOPv2 §8.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// JWK Thumbprint Subject Syntax Type: <c>sub</c> is an RFC 9278 JWK Thumbprint URI
    /// carrying the RFC 7638 thumbprint of the key in the <c>sub_jwk</c> claim, which
    /// MUST be present.
    /// </summary>
    JwkThumbprint = 1,

    /// <summary>
    /// Decentralized Identifier Subject Syntax Type: <c>sub</c> is a DID, the signing
    /// key is obtained from the resolved DID Document, and <c>sub_jwk</c> MUST NOT be
    /// present.
    /// </summary>
    DecentralizedIdentifier = 2
}
