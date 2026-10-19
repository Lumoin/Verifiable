using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Validation;

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
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 §4.1.9</see> — the
    /// REQUIRED <c>attested_keys</c> array is absent, the body is not one JSON object naming each
    /// member once and naming Unicode text throughout, the REQUIRED <c>iat</c> is absent, or the body
    /// carries an <c>iat</c> or an <c>exp</c> that is no NumericDate (RFC 7519 Section 2) or is one
    /// with a fraction, where Appendix D.1 has each an integer: a present date that is malformed is a
    /// malformed attestation, never one read as carrying no date, and a fraction is refused as written,
    /// never truncated. The <c>exp</c> Appendix D.1 requires where the attestation is used with a JWT
    /// proof is judged by <see cref="KeyAttestationVerifier"/>, which is told the attestation's use. A segment the decoder refuses
    /// as no base64url text is answered as no attestation; this method answers every malformed input by its return value, while
    /// a fault of the decoder or of the allocator beyond that refusal surfaces as the exception it is.
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

        //The segments are client-supplied wire input: one the decoder refuses as no base64url text is no attestation, answered as
        //such; any other failure of the decoder is a fault and surfaces as one.
        using var headerOwner = JwsSegmentDecoding.DecodedOrNone(segments[0], base64UrlDecoder, pool);
        using var bodyOwner = JwsSegmentDecoding.DecodedOrNone(segments[1], base64UrlDecoder, pool);

        if(headerOwner is null || bodyOwner is null)
        {
            return false;
        }

        ReadOnlySpan<byte> header = headerOwner.Memory.Span;
        ReadOnlySpan<byte> body = bodyOwner.Memory.Span;

        //RFC 7515 §4 / RFC 7519 §4: gate both the header and the body for well-formedness — a repeated
        //name at any nesting depth — before extracting a single field from either, so typ/attested_keys
        //selection below never runs against a first occurrence while a duplicate second occurrence goes
        //unnoticed. The body is read as the one JSON object it is, so its dates are read as its members.
        if(!JwkJsonReader.IsWellFormedJsonDocument(header) || JwkJsonReader.ReadTopLevelMembers(body) is not JsonTopLevelMembers bodyMembers)
        {
            return false;
        }

        //Appendix D.1: iat is REQUIRED and exp OPTIONAL, each an "Integer for the time ... using the syntax defined in [RFC7519]".
        //An omitted iat, a date that is no NumericDate - a string of digits, another kind of value, a count no clock represents -
        //and a NumericDate that is no integer make the attestation malformed: a fraction is refused as written, never truncated
        //to the second before it, and a present date is never read as an omitted one, so a present exp is always enforced.
        if(NumericDateClaims.Read(bodyMembers, WellKnownJwtClaimNames.Iat, out var issuedAt) is not NumericDateReadResult.Value
            || issuedAt is not { Seconds.IsInteger: true } integralIssuedAt
            || NumericDateClaims.Read(bodyMembers, WellKnownJwtClaimNames.Exp, out var expiresAt) is NumericDateReadResult.Malformed
            || expiresAt is { Seconds.IsInteger: false })
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
            IssuedAt = integralIssuedAt,
            ExpiresAt = expiresAt
        };

        return true;
    }
}
