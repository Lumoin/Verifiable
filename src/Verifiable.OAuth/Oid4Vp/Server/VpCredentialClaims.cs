using System.Collections.Frozen;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.StatusList;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// The facts a relying party or an <see cref="AssessVpDisclosureDelegate"/> reads about one
/// verified credential: what it claims, what it disclosed, who issued it, and the status its
/// issuer stated. One instance per <see cref="CredentialQueryId"/> — one record per credential,
/// one map per presentation.
/// </summary>
[DebuggerDisplay("Type={CredentialType} Issuer={Issuer} Extracted={Extracted.Count}")]
public sealed record VpCredentialClaims
{
    /// <summary>The shared empty <see cref="UnconditionallyDisclosed"/> default for a format that surfaces none.</summary>
    private static IReadOnlySet<CredentialPath> EmptyUnconditionallyDisclosed { get; } = FrozenSet<CredentialPath>.Empty;

    /// <summary>The shared empty <see cref="AdditionalTypes"/> default for a format that surfaces none.</summary>
    private static IReadOnlySet<string> EmptyAdditionalTypes { get; } = FrozenSet<string>.Empty;

    /// <summary>
    /// The extracted credential claims, keyed by the claim's full canonical
    /// <see cref="CredentialPath"/> (RFC 6901 JSON Pointer — SD-JWT/SD-CWT the disclosure's real
    /// position in the issuer-signed structure, mdoc <c>/{namespace}/{elementIdentifier}</c>) with
    /// its string projection. Keying by the real path — rather than the leaf claim name — is what
    /// keeps two disclosures that share a name at different depths (RFC 9901 §9.3: the Issuer
    /// chooses an independent salt for each) distinguishable instead of one overwriting the other.
    /// </summary>
    public required IReadOnlyDictionary<CredentialPath, string> Extracted { get; init; }

    /// <summary>
    /// Everything the presentation puts in front of the Verifier, keyed by <see cref="CredentialPath"/>,
    /// carrying the native value rather than its string projection: the claims the holder released by
    /// selecting a Disclosure together with the ones the credential carries unconditionally.
    /// </summary>
    /// <remarks>
    /// This is the engine-facing view: the executor hands it (via the
    /// <see cref="AssessVpDisclosureDelegate"/> seam) to the Core disclosure engine to derive DCQL
    /// satisfaction. It is the same addressable structure the holder's own adapter resolves a
    /// query over, which is why an unconditionally disclosed claim belongs in it — a query naming
    /// <c>vct</c> must match a presentation that plainly carries <c>vct</c>. For the
    /// over-disclosure question, which is about what the holder CHOSE to send, read
    /// <see cref="UnconditionallyDisclosed"/> to tell the two apart.
    /// </remarks>
    public required IReadOnlyDictionary<CredentialPath, object?> Disclosed { get; init; }

    /// <summary>
    /// The subset of <see cref="Disclosed"/> the credential could not have withheld: the claims the
    /// Issuer did not make selectively disclosable.
    /// </summary>
    /// <remarks>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4</see> constrains only what a wallet chooses to
    /// send — "Wallets MUST NOT send selectively disclosable claims that have not been selected
    /// according to the rules below" — so a claim named here is never over-disclosure, however the
    /// query is written. Empty for a format whose parse surfaces only released claims.
    /// </remarks>
    public IReadOnlySet<CredentialPath> UnconditionallyDisclosed { get; init; } = EmptyUnconditionallyDisclosed;

    /// <summary>
    /// The credential's own declared type — the SD-JWT VC <c>vct</c> claim
    /// (defined in
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-2.2.2.1">
    /// SD-JWT VC §2.2.2.1</see> and designated REQUIRED in
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-2.2.2.3">
    /// §2.2.2.3</see>) — or <see langword="null"/> for a
    /// plain SD-JWT that carries none. Carried here so the verifier's
    /// <see cref="AssessVpDisclosureDelegate"/> seam can supply it to the Core metadata
    /// extractor: <see cref="Verifiable.Core.Dcql.DcqlEvaluator"/> fails a
    /// <c>meta.vct_values</c> constraint closed when the credential declares no type at all
    /// (<see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4.2">
    /// OpenID for Verifiable Presentations 1.0 §6.4.2</see>).
    /// </summary>
    public string? CredentialType { get; init; }

    /// <summary>
    /// The credential's other declared types — the SD-JWT VC <c>aka_vcts</c> claim
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-2.2.2.2">
    /// SD-JWT VC §2.2.2.2</see>, OPTIONAL) — empty when the credential carries none. Carried here so
    /// the verifier's <see cref="AssessVpDisclosureDelegate"/> seam can supply it to the Core metadata
    /// extractor: <see cref="Verifiable.Core.Dcql.DcqlEvaluator"/> answers a <c>meta.vct_values</c>
    /// constraint against <see cref="CredentialType"/> OR any of these, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.5">
    /// OpenID for Verifiable Presentations 1.0 Appendix B.3.5</see>'s inheritance MAY.
    /// </summary>
    public IReadOnlySet<string> AdditionalTypes { get; init; } = EmptyAdditionalTypes;

    /// <summary>
    /// The verified credential issuer identifier — the SD-JWT/SD-CWT <c>iss</c> the verifier
    /// resolved to find the issuer signing key — or <see langword="null"/> for <c>mso_mdoc</c>,
    /// which carries no <c>iss</c> claim.
    /// </summary>
    public string? Issuer { get; init; }

    /// <summary>
    /// The credential's OID4VP 1.0 §6.1.1 trust evidence, or <see langword="null"/> when the
    /// format or wiring surfaces none. Carried here so the verifier's
    /// <see cref="AssessVpDisclosureDelegate"/> seam can enforce a DCQL <c>trusted_authorities</c>
    /// constraint (<see cref="Verifiable.Core.Dcql.DcqlEvaluator"/> fails the constraint closed
    /// when no evidence is supplied to its metadata extractor).
    /// </summary>
    /// <remarks>
    /// Populated for <c>dc+sd-jwt</c> when the verifier wires a <c>parseX5c</c> +
    /// <c>resolveTrustedAuthorityEvidence</c> pair, for <c>dc+sd-cwt</c> when it wires a COSE
    /// <c>x5chain</c> extractor + resolver on <see cref="SdCwtVpVerificationSeams"/>, and for
    /// <c>mso_mdoc</c> when it wires
    /// <see cref="MdocVpVerificationSeams.ExtractTrustedAuthorityEvidence"/>. <see langword="null"/>
    /// when the format or wiring surfaces none, in which case a <c>trusted_authorities</c>
    /// constraint on that credential fails closed.
    /// </remarks>
    public TrustedAuthorityEvidence? TrustedAuthorityEvidence { get; init; }

    /// <summary>
    /// The credential's IETF Token Status List <c>status</c> claim as its issuer stated it, or
    /// <see langword="null"/> when the credential carries no status claim at all.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Three states, not two.
    /// <see langword="null"/> — the credential carries no <c>status</c> claim, so its issuer gated
    /// nothing on a status mechanism.
    /// Non-null with <see cref="StatusClaim.StatusList"/> <see langword="null"/> — the issuer named
    /// mechanisms (<see cref="StatusClaim.Mechanisms"/>) none of which this library evaluates, so no
    /// statement about the credential's status can be made here.
    /// Non-null with <see cref="StatusClaim.StatusList"/> populated — the reference the verifier's
    /// status step resolves and checks.
    /// </para>
    /// <para>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">
    /// Token Status List, Section 8.3</see> step 1: "Check for the existence of a status claim, check
    /// for the existence of a status_list claim within the status claim and validate that the content
    /// of status_list adheres to the rules defined in Section 6.2 for JOSE-based Referenced Tokens
    /// and Section 6.3 for COSE-based Referenced Tokens." Existence is the discriminator that
    /// separates the first state from the other two, and the <c>status_list</c> check separates the
    /// second from the third; collapsing them would make a credential whose status cannot be read
    /// indistinguishable from one that never had a status to read.
    /// </para>
    /// </remarks>
    public StatusClaim? Status { get; init; }
}
