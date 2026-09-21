using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// Reads the body of an OID4VCI 1.0 Appendix D.1 key attestation (<c>key-attestation+jwt</c>)
/// into a <see cref="KeyAttestation"/>, validating the REQUIRED <c>typ</c> header and the
/// REQUIRED <c>attested_keys</c> body member. This is a STRUCTURAL parse only: the signature and
/// the Wallet-Provider trust chain are the application's to verify (its trust anchors are
/// deployment data), as is the §F.2 rule that a <c>jwt</c> proof's key appears in
/// <c>attested_keys</c>. The body is scanned with <see cref="JwkJsonReader"/>, keeping the
/// <c>Verifiable.OAuth</c> serialization firewall intact.
/// </summary>
public static class KeyAttestationParser
{
    /// <summary>
    /// Parses <paramref name="compactAttestation"/> (a compact <c>key-attestation+jwt</c>) into
    /// <paramref name="attestation"/>. Returns <see langword="false"/> when the input is not a
    /// two-or-three-part JWT, the <c>typ</c> header does not name the <c>key-attestation+jwt</c>
    /// media type — the long form <c>application/key-attestation+jwt</c> and any casing of either
    /// spelling name that same media type per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 §4.1.9</see> — or
    /// the REQUIRED <c>attested_keys</c> array is absent.
    /// </summary>
    /// <param name="compactAttestation">The compact JWS key attestation.</param>
    /// <param name="base64UrlDecoder">Base64url decoder for the header and body segments.</param>
    /// <param name="pool">Memory pool for the decoded segments.</param>
    /// <param name="attestation">The parsed attestation on success; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> on a well-typed attestation carrying attested keys.</returns>
    public static bool TryParse(
        string compactAttestation,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool pool,
        out KeyAttestation? attestation)
    {
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        attestation = null;
        if(string.IsNullOrEmpty(compactAttestation))
        {
            return false;
        }

        string[] segments = compactAttestation.Split('.');
        if(segments.Length is < 2 or > 3)
        {
            return false;
        }

        using IMemoryOwner<byte> headerOwner = base64UrlDecoder(segments[0], pool);
        ReadOnlySpan<byte> header = headerOwner.Memory.Span;

        using IMemoryOwner<byte> bodyOwner = base64UrlDecoder(segments[1], pool);
        ReadOnlySpan<byte> body = bodyOwner.Memory.Span;

        //RFC 7515 §4 / RFC 7519 §4: gate both the header and the body for well-formedness — a repeated
        //name at any nesting depth — before extracting a single field from either, so typ/attested_keys
        //selection below never runs against a first occurrence while a duplicate second occurrence goes
        //unnoticed.
        if(!JwkJsonReader.IsWellFormedJsonDocument(header) || !JwkJsonReader.IsWellFormedJsonDocument(body))
        {
            return false;
        }

        //RFC 7515 §4.1.9: the typ compares as the media type it is — case insensitive, and with the
        //implicit "application/" prefix when the wire value carries no '/' of its own. A missing typ
        //is a refusal, checked before the media-type comparison so a null header is never handed to it.
        string? typ = JwkJsonReader.ExtractStringValue(header, WellKnownJoseHeaderNames.TypUtf8);
        if(typ is null || !AttestationProofParameterNames.IsKeyAttestationJwtType(typ))
        {
            return false;
        }

        string? attestedKeys = JwkJsonReader.ExtractArrayAsString(
            body, AttestationProofParameterNames.AttestedKeysUtf8);
        if(attestedKeys is null)
        {
            return false;
        }

        attestation = new KeyAttestation
        {
            AttestedKeysJson = attestedKeys,
            KeyStorageJson = JwkJsonReader.ExtractArrayAsString(
                body, AttestationProofParameterNames.KeyStorageUtf8),
            UserAuthenticationJson = JwkJsonReader.ExtractArrayAsString(
                body, AttestationProofParameterNames.UserAuthenticationUtf8),
            Nonce = JwkJsonReader.ExtractStringValue(body, WellKnownJwtClaimNames.NonceUtf8),
            Certification = JwkJsonReader.ExtractStringValue(
                body, AttestationProofParameterNames.CertificationUtf8),
            IssuedAt = ReadInstant(body, WellKnownJwtClaimNames.IatUtf8),
            ExpiresAt = ReadInstant(body, WellKnownJwtClaimNames.ExpUtf8)
        };

        return true;
    }


    private static DateTimeOffset? ReadInstant(ReadOnlySpan<byte> body, ReadOnlySpan<byte> key) =>
        JwkJsonReader.TryExtractLongValue(body, key, out long seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
}
