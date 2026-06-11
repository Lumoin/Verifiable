using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Siop;

/// <summary>
/// Subject Syntax Type identifier values per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-8">SIOPv2 §8</see>,
/// used in the <c>subject_syntax_types_supported</c> RP / OP metadata parameter and to
/// classify the <c>sub</c> claim of a Self-Issued ID Token (§11.1).
/// </summary>
[DebuggerDisplay("SiopSubjectSyntaxTypes")]
public static class SiopSubjectSyntaxTypes
{
    /// <summary>The UTF-8 source literal of <see cref="JwkThumbprint"/>.</summary>
    public static ReadOnlySpan<byte> JwkThumbprintUtf8 => "urn:ietf:params:oauth:jwk-thumbprint"u8;

    /// <summary>
    /// The JWK Thumbprint Subject Syntax Type identifier,
    /// <c>urn:ietf:params:oauth:jwk-thumbprint</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9278">RFC 9278</see>.
    /// </summary>
    public static readonly string JwkThumbprint = Utf8Constants.ToInternedString(JwkThumbprintUtf8);

    /// <summary>The UTF-8 source literal of <see cref="JwkThumbprintSha256Prefix"/>.</summary>
    public static ReadOnlySpan<byte> JwkThumbprintSha256PrefixUtf8 => "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"u8;

    /// <summary>
    /// The RFC 9278 JWK Thumbprint URI prefix for SHA-256 thumbprints. A <c>sub</c>
    /// claim of the JWK Thumbprint Subject Syntax Type carries the base64url-encoded
    /// RFC 7638 thumbprint after this prefix:
    /// <c>urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8…</c>.
    /// </summary>
    public static readonly string JwkThumbprintSha256Prefix = Utf8Constants.ToInternedString(JwkThumbprintSha256PrefixUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DidPrefix"/>.</summary>
    public static ReadOnlySpan<byte> DidPrefixUtf8 => "did:"u8;

    /// <summary>
    /// The Decentralized Identifier scheme prefix. A <c>subject_syntax_types_supported</c>
    /// entry is <c>did:</c> followed by a method name (<c>did:example</c>), or bare
    /// <c>did</c> for all methods; a <c>sub</c> claim of this type is a full DID.
    /// </summary>
    public static readonly string DidPrefix = Utf8Constants.ToInternedString(DidPrefixUtf8);


    /// <summary>
    /// Identifies the Subject Syntax Type of a <c>sub</c> claim value from its URI per
    /// SIOPv2 §11.1: <c>urn:ietf:params:oauth:jwk-thumbprint</c> for JWK Thumbprint,
    /// <c>did:</c> for Decentralized Identifier, otherwise
    /// <see cref="SiopSubjectSyntaxType.Unknown"/>.
    /// </summary>
    /// <param name="sub">The <c>sub</c> claim value.</param>
    /// <returns>The identified Subject Syntax Type.</returns>
    public static SiopSubjectSyntaxType Classify(string sub)
    {
        ArgumentNullException.ThrowIfNull(sub);

        return sub switch
        {
            _ when sub.StartsWith(JwkThumbprint, StringComparison.Ordinal) => SiopSubjectSyntaxType.JwkThumbprint,
            _ when sub.StartsWith(DidPrefix, StringComparison.Ordinal) => SiopSubjectSyntaxType.DecentralizedIdentifier,
            _ => SiopSubjectSyntaxType.Unknown
        };
    }
}
