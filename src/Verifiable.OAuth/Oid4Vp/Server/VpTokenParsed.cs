using System.Diagnostics;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.StatusList;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Raw results from parsing and cryptographically verifying a VP token.
/// Produced by <see cref="SdJwtVpTokenVerification"/>, consumed by the executor
/// to construct a <see cref="Validation.ValidationContext"/> for library-side
/// validation.
/// </summary>
[DebuggerDisplay("VpTokenParsed KbJwtSignatureValid={KbJwtSignatureValid} CredentialSignatureValid={CredentialSignatureValid}")]
public sealed record VpTokenParsed
{
    /// <summary>The <c>nonce</c> claim extracted from the KB-JWT.</summary>
    public string? KbJwtNonce { get; init; }

    /// <summary>The <c>aud</c> claim extracted from the KB-JWT.</summary>
    public string? KbJwtAud { get; init; }

    /// <summary>The <c>iat</c> claim extracted from the KB-JWT.</summary>
    public DateTimeOffset? KbJwtIat { get; init; }

    /// <summary>Whether the KB-JWT signature was cryptographically valid.</summary>
    public bool KbJwtSignatureValid { get; init; }

    /// <summary>Whether the credential issuer signature was cryptographically valid.</summary>
    public bool CredentialSignatureValid { get; init; }

    /// <summary>
    /// The verified credential issuer identifier — the SD-JWT <c>iss</c> the verifier
    /// resolved to find the issuer signing key — or <see langword="null"/> when the
    /// format does not surface a string issuer. Carried here so the verifier's
    /// <see cref="AssessVpDisclosureDelegate"/> seam can enforce a DCQL
    /// <c>trusted_authorities</c> constraint (the Core <c>DcqlEvaluator</c> only runs
    /// that check when an issuer is supplied to its metadata extractor).
    /// </summary>
    /// <remarks>
    /// Populated for <c>dc+sd-jwt</c> and <c>dc+sd-cwt</c> from the string <c>iss</c> (matched
    /// against a <c>trusted_authorities</c> entry of type <c>openid_federation</c>), and for
    /// <c>mso_mdoc</c> from the IssuerAuth leaf certificate's AuthorityKeyIdentifier (base64url,
    /// type <c>aki</c>) when the verifier wires
    /// <see cref="MdocVpVerificationSeams.ExtractAuthorityIdentifier"/>. <see langword="null"/>
    /// when the format / wiring surfaces no authority identifier, in which case a
    /// <c>trusted_authorities</c> constraint on that credential goes unenforced (the evaluator
    /// skips a check it has no value for).
    /// </remarks>
    public string? CredentialIssuer { get; init; }

    /// <summary>Whether the <c>sd_hash</c> matched the presented disclosures (SD-JWT).</summary>
    public bool SdHashValid { get; init; }

    /// <summary>Whether the session transcript was correctly computed (mdoc).</summary>
    public bool SessionTranscriptValid { get; init; }

    /// <summary>
    /// The <c>transaction_data_hashes</c> array extracted from the KB-JWT
    /// payload per OID4VP 1.0 §8.4, or <see langword="null"/> when the KB-JWT
    /// did not carry the claim. Each entry is a base64url-encoded digest the
    /// Wallet computed over the corresponding transaction_data string the
    /// Verifier sent in the Authorization Request.
    /// </summary>
    public IReadOnlyList<string>? KbJwtTransactionDataHashes { get; init; }

    /// <summary>
    /// The <c>transaction_data_hashes_alg</c> claim extracted from the KB-JWT,
    /// or <see langword="null"/> when absent. When absent and
    /// <see cref="KbJwtTransactionDataHashes"/> is present, the Wallet implicitly
    /// chose SHA-256 per OID4VP 1.0 §8.4.
    /// </summary>
    public string? KbJwtTransactionDataHashesAlg { get; init; }

    /// <summary>
    /// The extracted credential claims, keyed by DCQL credential query identifier.
    /// Each inner dictionary maps claim name to claim value.
    /// </summary>
    public required IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> ExtractedClaims { get; init; }

    /// <summary>
    /// The disclosed claims keyed by DCQL credential query identifier, then by the
    /// claim's full canonical <see cref="CredentialPath"/> (RFC 6901 JSON Pointer —
    /// SD-JWT/SD-CWT <c>/claimName</c>, mdoc <c>/{namespace}/{elementIdentifier}</c>)
    /// with its native disclosed value.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the engine-facing view: the executor hands it (via the
    /// <see cref="AssessVpDisclosureDelegate"/> seam) to the Core disclosure engine
    /// to derive DCQL satisfaction and over-disclosure. It is distinct from
    /// <see cref="ExtractedClaims"/>, which is the relying-party-facing string
    /// projection keyed by claim name. Keying by full path keeps the assessment
    /// unambiguous when claims share a leaf name across namespaces or nesting levels.
    /// </para>
    /// </remarks>
    public required IReadOnlyDictionary<string, IReadOnlyDictionary<CredentialPath, object?>> DisclosedClaimPaths { get; init; }

    /// <summary>
    /// The shortest disclosure salt length, in bytes, across the presentation's disclosures, or
    /// <see langword="null"/> when the format carries no disclosure salts (mdoc) or there were none.
    /// Captured here because the parse step holds the <c>SdToken</c> disclosures; the executor copies it
    /// onto <see cref="Validation.ValidationContext.MinimumDisclosureSaltLengthBytes"/> for the
    /// salt-length signal. RFC 9901 §9.3 RECOMMENDS at least 16 bytes (128 bits).
    /// </summary>
    public int? MinimumDisclosureSaltLengthBytes { get; init; }

    /// <summary>
    /// Whether any disclosure salt in this presentation was already seen by the application's
    /// salt-reuse store — a correlation/replay signal (RFC 9901 §9.4 requires unique salts). Only ever
    /// <see langword="true"/> when a salt-reuse seam was wired and a reuse was found, so it is the
    /// verifier's opt-in equivalent of DPoP-JTI replay. <see langword="false"/> when no seam was wired
    /// or no reuse occurred.
    /// </summary>
    public bool SaltReused { get; init; }

    /// <summary>
    /// The IETF Token Status List reference (<c>status.status_list = {idx, uri}</c>) extracted from
    /// the credential's issuer payload, or <see langword="null"/> when the credential carries no
    /// status claim. A verifier — RP server, peer wallet, or agent — passes this to
    /// <see cref="StatusList.CredentialStatusGate"/> to check revocation; surfacing it here keeps
    /// the fetch and trust of the status list the caller's concern, not the parser's.
    /// </summary>
    public StatusListReference? CredentialStatus { get; init; }
}
