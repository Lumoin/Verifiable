using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Reads the JOSE <c>x5c</c> header parameter from an SD-JWT VC issuer JWS, per
/// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.6">RFC 7515, Section 4.1.6</see> —
/// the certificate chain evidence
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.1">
/// OID4VP 1.0, Section 6.1.1.1</see> <c>aki</c> matching reads when the credential's issuer identity
/// is carried by a certificate rather than, or alongside, the <c>iss</c> claim.
/// </summary>
/// <remarks>
/// Reads the compact JWS's protected header with the same span-based, allocation-narrow approach as
/// <see cref="JwkJsonReader"/> — Core parses no JSON through <c>System.Text.Json</c>; only the leaf
/// serializers (<c>Verifiable.Json</c>) do.
/// </remarks>
public static class SdJwtIssuerHeader
{
    /// <summary>
    /// Reads the <c>x5c</c> header member from <paramref name="issuerSignedCompactJws"/>'s protected
    /// header.
    /// </summary>
    /// <param name="issuerSignedCompactJws">The compact-serialized issuer JWS — <c>SdToken{TEnvelope}.IssuerSigned</c> for the JWT envelope.</param>
    /// <param name="base64UrlDecoder">Decodes the base64url-encoded protected header segment.</param>
    /// <param name="pool">Memory pool for the decoded header bytes.</param>
    /// <param name="x5c">The <c>x5c</c> chain's base64-encoded DER certificate strings (leaf first), in header order; empty when the header carries no <c>x5c</c> member.</param>
    /// <returns><see langword="true"/> when the header carries a non-empty <c>x5c</c> member; otherwise <see langword="false"/>.</returns>
    public static bool TryReadX5c(
        string issuerSignedCompactJws,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool pool,
        out IReadOnlyList<string> x5c)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerSignedCompactJws);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        x5c = [];

        int firstDot = issuerSignedCompactJws.IndexOf('.', StringComparison.Ordinal);
        if(firstDot < 0)
        {
            return false;
        }

        using IMemoryOwner<byte> headerBytes = base64UrlDecoder(issuerSignedCompactJws.AsSpan(0, firstDot), pool);
        List<string>? values = JwkJsonReader.ExtractStringArrayProperty(headerBytes.Memory.Span, WellKnownJwkMemberNames.X5cUtf8);
        if(values is not { Count: > 0 })
        {
            return false;
        }

        x5c = values;

        return true;
    }


    /// <summary>
    /// Reads the <c>kid</c> header member from <paramref name="issuerSignedCompactJws"/>'s protected
    /// header, per <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4">RFC 7515, Section
    /// 4.1.4</see> — the key identifier SD-JWT VC draft-19 §4.2 recommends the Issuer-signed JWT carry
    /// so a Verifier can select the matching key from the JWT VC Issuer Metadata's JWK Set.
    /// </summary>
    /// <param name="issuerSignedCompactJws">The compact-serialized issuer JWS — <c>SdToken{TEnvelope}.IssuerSigned</c> for the JWT envelope.</param>
    /// <param name="base64UrlDecoder">Decodes the base64url-encoded protected header segment.</param>
    /// <param name="pool">Memory pool for the decoded header bytes.</param>
    /// <param name="kid">The header's <c>kid</c> value; <see langword="null"/> when the header carries none.</param>
    /// <returns><see langword="true"/> when the header carries a <c>kid</c> member; otherwise <see langword="false"/>.</returns>
    public static bool TryReadKid(
        string issuerSignedCompactJws,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool pool,
        out string? kid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerSignedCompactJws);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        kid = null;

        int firstDot = issuerSignedCompactJws.IndexOf('.', StringComparison.Ordinal);
        if(firstDot < 0)
        {
            return false;
        }

        using IMemoryOwner<byte> headerBytes = base64UrlDecoder(issuerSignedCompactJws.AsSpan(0, firstDot), pool);
        kid = JwkJsonReader.ExtractStringValue(headerBytes.Memory.Span, WellKnownJwkMemberNames.KidUtf8);

        return kid is not null;
    }
}
