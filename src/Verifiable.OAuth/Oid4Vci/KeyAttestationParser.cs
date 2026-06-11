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
    /// two-or-three-part JWT, the <c>typ</c> header is not <c>key-attestation+jwt</c>, or the
    /// REQUIRED <c>attested_keys</c> array is absent.
    /// </summary>
    /// <param name="compactAttestation">The compact JWS key attestation.</param>
    /// <param name="base64UrlDecoder">Base64url decoder for the header and body segments.</param>
    /// <param name="pool">Memory pool for the decoded segments.</param>
    /// <param name="attestation">The parsed attestation on success; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> on a well-typed attestation carrying attested keys.</returns>
    public static bool TryParse(
        string compactAttestation,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool,
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
        string? typ = JwkJsonReader.ExtractStringValue(headerOwner.Memory.Span, WellKnownJoseHeaderNames.TypUtf8);
        if(!string.Equals(typ, AttestationProofParameterNames.KeyAttestationJwtType, StringComparison.Ordinal))
        {
            return false;
        }

        using IMemoryOwner<byte> bodyOwner = base64UrlDecoder(segments[1], pool);
        ReadOnlySpan<byte> body = bodyOwner.Memory.Span;

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
