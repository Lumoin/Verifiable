using Verifiable.Core.StatusList;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// The parsed and cryptographically verified contents of an SD-CWT Key Binding
/// Token (KBT) per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt §7.1</see>. The serialization-neutral result of
/// <c>KbCwtVerification.VerifyAsync</c>.
/// </summary>
/// <remarks>
/// <para>
/// Unlike the SD-JWT KB-JWT there is <strong>no <c>sd_hash</c></strong> in SD-CWT:
/// the binding is that the holder signs over the embedded presentation SD-CWT, so a
/// valid holder signature (<see cref="HolderSignatureValid"/>) <em>is</em> the binding.
/// The embedded SD-CWT's issuer signature and per-disclosure digest binding are reported
/// in <see cref="CredentialSignatureValid"/>; the disclosed claims recovered from the
/// presentation are in <see cref="DisclosedClaims"/>.
/// </para>
/// </remarks>
public sealed record SdCwtKbtVerificationResult
{
    /// <summary>
    /// Whether the KBT holder signature verified against the holder public key
    /// reconstructed from the embedded SD-CWT <c>cnf</c> COSE_Key.
    /// </summary>
    public bool HolderSignatureValid { get; init; }

    /// <summary>
    /// Whether the embedded presentation SD-CWT verified in full: the issuer
    /// COSE_Sign1 signature plus the per-disclosure digest binding.
    /// </summary>
    public bool CredentialSignatureValid { get; init; }

    /// <summary>
    /// The embedded SD-CWT's verified <c>iss</c> claim (CWT claim 1) — the issuer
    /// identifier the verifier resolved to find the issuer key — or <see langword="null"/>
    /// when the credential carries none. Surfaced so a verifier can enforce a DCQL
    /// <c>trusted_authorities</c> constraint of type <c>openid_federation</c> against it.
    /// </summary>
    public string? Issuer { get; init; }

    /// <summary>
    /// The embedded SD-CWT's <c>vct</c> claim (CWT claim 11 =
    /// <see cref="Verifiable.JCose.WellKnownCwtClaimNames.Vct"/>) — the credential's own declared
    /// type — or <see langword="null"/> when the credential carries none. Surfaced so a verifier
    /// can supply it to the Core DCQL metadata extractor:
    /// <see cref="Verifiable.Core.Dcql.DcqlEvaluator"/> fails a <c>meta.vct_values</c> constraint
    /// closed when the credential declares no type at all.
    /// </summary>
    public string? CredentialType { get; init; }

    /// <summary>
    /// The embedded SD-CWT's <c>status</c> claim (CWT claim 65535) — the Token Status List Status
    /// structure the issuer stated, decoded into the mechanisms it names and the <c>status_list</c>
    /// reference when that mechanism is among them — or <see langword="null"/> when the credential
    /// carries no such claim. Decoded at the parse boundary, so it describes what the issuer wrote
    /// whatever <see cref="CredentialSignatureValid"/> says; acting on it (resolving and fetching the
    /// Status List Token) is the verifier's own later step, which runs only over a credential whose
    /// signature held.
    /// </summary>
    public StatusClaim? Status { get; init; }

    /// <summary>
    /// The issuer public key the embedded SD-CWT's COSE_Sign1 signature verified under, or
    /// <see langword="null"/> when no key resolved or the signature did not hold. BORROWED from the
    /// issuer-key resolver: the resolver owns its lifetime, nothing here disposes it, and a reader
    /// must not retain it past the verification step that produced this result.
    /// </summary>
    public PublicKeyMemory? IssuerVerificationKey { get; init; }

    /// <summary>The <c>aud</c> claim (CWT claim 3) identifying the Verifier.</summary>
    public string? Audience { get; init; }

    /// <summary>The <c>cnonce</c> claim (CWT claim 39), or <see langword="null"/> when omitted.</summary>
    public string? Cnonce { get; init; }

    /// <summary>The <c>iat</c> claim (CWT claim 6), or <see langword="null"/> when absent.</summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>
    /// The disclosed claims recovered from the embedded SD-CWT presentation, keyed by each
    /// disclosure's real <see cref="Verifiable.Core.Model.SelectiveDisclosure.CredentialPath"/>
    /// in the issuer-signed structure (the embedded token's own
    /// <see cref="SdToken{TEnvelope}.DisclosurePaths"/> resolution) with its native disclosed
    /// value, rather than the leaf claim name — two disclosures sharing a name at different
    /// depths (RFC 9901 §9.3: the Issuer chooses an independent salt for each) stay distinguishable.
    /// </summary>
    public IReadOnlyDictionary<CredentialPath, object?> DisclosedClaims { get; init; } =
        new Dictionary<CredentialPath, object?>();

    /// <summary>
    /// The embedded SD-CWT's unconditionally disclosed claims — the nodes present without releasing
    /// any disclosure (the credential's <c>vct</c>, <c>iss</c> and any non-disclosable business claim),
    /// keyed by their <see cref="Verifiable.Core.Model.SelectiveDisclosure.CredentialPath"/>. These
    /// are part of <see cref="DisclosedClaims"/> so a relying-party query naming one resolves, but a
    /// verifier separates them here because
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4">
    /// OpenID for Verifiable Presentations 1.0 §6.4</see>'s over-disclosure rule governs only what the
    /// wallet <em>chose</em> to send, never what the issuer signed unconditionally.
    /// </summary>
    public IReadOnlySet<CredentialPath> UnconditionallyDisclosedPaths { get; init; } =
        new HashSet<CredentialPath>();

    /// <summary>
    /// The shortest disclosure salt length, in bytes, across the embedded SD-CWT's disclosures, or
    /// <see langword="null"/> when there were no disclosures. Observed for the verifier salt-length
    /// signal — RFC 9901 §9.3 RECOMMENDS at least 16 bytes (128 bits).
    /// </summary>
    public int? MinimumDisclosureSaltLengthBytes { get; init; }

    /// <summary>
    /// Whether any embedded-SD-CWT disclosure salt was already seen by the application's salt-reuse
    /// store (RFC 9901 §9.4 — unique salts; a repeat is a correlation/replay signal). Only ever
    /// <see langword="true"/> when a salt-reuse seam was wired and a reuse was found; <see langword="false"/>
    /// otherwise. The verifier mirror of DPoP-JTI replay.
    /// </summary>
    public bool SaltReused { get; init; }
}
