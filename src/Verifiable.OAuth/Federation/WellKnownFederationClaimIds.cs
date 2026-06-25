using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Federation <see cref="ClaimId"/> instances for OpenID Federation 1.0
/// validation steps. Codes 1100–1199 are reserved for Federation per
/// <see cref="Verifiable.OAuth.Validation.ValidationClaimIds"/>'s
/// sub-range reservation header.
/// </summary>
/// <remarks>
/// <para>
/// Sub-ranges (only IDs with active consumers are populated; unused ranges
/// are reserved for future federation steps):
/// </para>
/// <list type="bullet">
///   <item><description>1100–1119: Entity Statement validation per
///     <see href="https://openid.net/specs/openid-federation-1_0.html#section-3.2">Federation §3.2</see>.</description></item>
///   <item><description>1120–1139: Trust chain validation per
///     <see href="https://openid.net/specs/openid-federation-1_0.html#section-4.3">§4.3</see>
///     (inline) and
///     <see href="https://openid.net/specs/openid-federation-1_0.html#section-10">§10</see>
///     (HTTP).</description></item>
///   <item><description>1140–1159: Metadata policy merge and application per
///     <see href="https://openid.net/specs/openid-federation-1_0.html#section-6.1.4">§6.1.4</see>.</description></item>
///   <item><description>1160–1169: Party approval gate (consumed by
///     <c>ApprovePartyDelegate</c>).</description></item>
///   <item><description>1170–1189: Trust Mark validation per
///     <see href="https://openid.net/specs/openid-federation-1_0.html#section-7.3">§7.3</see>.</description></item>
///   <item><description>1190–1199: Reserved for future Federation extensions
///     (Wallet 1.0, Extended Subordinate Listing 1.0).</description></item>
/// </list>
/// <para>
/// The precise
/// decomposition of Federation §3.2's 27 validation steps into named
/// <see cref="ClaimId"/> entries is realised by the
/// <c>FederationValidationProfiles.EntityStatementRules()</c> list against
/// these IDs and the spec text. Spec analysis may add IDs in the
/// 1110–1119 sub-range or split aggregated checks (e.g.
/// <see cref="AuthorityHintsWellFormed"/>) into per-element checks.
/// </para>
/// </remarks>
public static class WellKnownFederationClaimIds
{
    //Entity Statement validation per Federation §3.2 (codes 1100–1119).

    /// <summary>
    /// The JWS protected header carries an <c>alg</c> claim and it is not
    /// <c>none</c>.
    /// </summary>
    public static ClaimId AlgPresent { get; } = ClaimId.Create(1100, "AlgPresent");

    /// <summary>
    /// The JWS protected header's <c>typ</c> equals
    /// <see cref="WellKnownFederationMediaTypes.EntityStatementJwt"/> per
    /// RFC 8725 §3.11 explicit typing.
    /// </summary>
    public static ClaimId TypMatchesEntityStatement { get; } = ClaimId.Create(1101, "TypMatchesEntityStatement");

    /// <summary>
    /// The JWS payload carries an <c>iss</c> claim.
    /// </summary>
    public static ClaimId IssPresent { get; } = ClaimId.Create(1102, "IssPresent");

    /// <summary>
    /// The JWS payload carries a <c>sub</c> claim.
    /// </summary>
    public static ClaimId SubPresent { get; } = ClaimId.Create(1103, "SubPresent");

    /// <summary>
    /// The <c>iat</c> claim is within the clock-skew window relative to
    /// <see cref="TimeProvider.GetUtcNow"/>.
    /// </summary>
    public static ClaimId IatInRange { get; } = ClaimId.Create(1104, "IatInRange");

    /// <summary>
    /// The <c>exp</c> claim is in the future (with clock-skew tolerance).
    /// </summary>
    public static ClaimId ExpInFuture { get; } = ClaimId.Create(1105, "ExpInFuture");

    /// <summary>
    /// The <c>exp</c> claim is strictly after <c>iat</c> — mutual temporal
    /// consistency, independent of the clock. <c>exp</c> at or before <c>iat</c>
    /// is a non-positive lifetime.
    /// </summary>
    public static ClaimId ExpAfterIat { get; } = ClaimId.Create(1110, "ExpAfterIat");

    /// <summary>
    /// The JWS signature verifies against the key resolved for this
    /// statement (per-statement key resolution lives in the trust chain
    /// validator; this check confirms the signature itself).
    /// </summary>
    public static ClaimId SignatureVerifies { get; } = ClaimId.Create(1106, "SignatureVerifies");

    /// <summary>
    /// For an Entity Configuration (<c>iss</c> == <c>sub</c>), the
    /// <c>jwks</c> claim is present and carries at least one key.
    /// </summary>
    public static ClaimId JwksPresentWhenSelfSigned { get; } = ClaimId.Create(1107, "JwksPresentWhenSelfSigned");

    /// <summary>
    /// The <c>authority_hints</c> claim (when present) is a well-formed
    /// array of <see cref="EntityIdentifier"/> values.
    /// </summary>
    public static ClaimId AuthorityHintsWellFormed { get; } = ClaimId.Create(1108, "AuthorityHintsWellFormed");

    /// <summary>
    /// The <c>metadata</c> claim (when present) is a well-formed object
    /// keyed by <see cref="EntityTypeIdentifier"/> with no <see langword="null"/>
    /// value — Federation §5 prohibits <c>null</c> metadata values.
    /// </summary>
    public static ClaimId MetadataWellFormed { get; } = ClaimId.Create(1109, "MetadataWellFormed");

    /// <summary>
    /// When <c>jwks</c> is present, none of its keys carry private (<c>d</c>,
    /// <c>p</c>, <c>q</c>, <c>dp</c>, <c>dq</c>, <c>qi</c>, <c>oth</c>) or
    /// symmetric (<c>k</c>) key material — a published Entity Statement JWKS
    /// must contain public keys only per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-3.1">Federation §3.1</see>.
    /// </summary>
    public static ClaimId JwksContainsNoPrivateOrSymmetricKeys { get; } = ClaimId.Create(1111, "JwksContainsNoPrivateOrSymmetricKeys");

    /// <summary>
    /// When <c>jwks</c> is present, the <c>kid</c> values across its keys are
    /// distinct (keys without a <c>kid</c> are ignored) — a duplicate
    /// <c>kid</c> makes key selection ambiguous, contrary to the JWK Set
    /// <c>kid</c> uniqueness expectation of
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see>.
    /// </summary>
    public static ClaimId JwksKeyIdsDistinct { get; } = ClaimId.Create(1112, "JwksKeyIdsDistinct");

    /// <summary>
    /// When <c>jwks</c> is present, every RSA key carries a modulus of at
    /// least 2048 bits — a published Entity Statement must not advertise
    /// signing keys below contemporary minimum strength
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.3">RFC 7518 §6.3</see>
    /// RSA; the floor follows
    /// <see href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf">NIST SP 800-57</see>).
    /// Non-RSA keys are governed by their curve and do not constrain this check.
    /// </summary>
    public static ClaimId JwksKeysMeetMinimumKeyLength { get; } = ClaimId.Create(1113, "JwksKeysMeetMinimumKeyLength");

    /// <summary>
    /// Conditional claim placement per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-3.2">Federation §3.2</see>
    /// (steps deriving from §3.1.2 / §3.1.3): the Entity-Configuration-only
    /// claims (<c>authority_hints</c>, <c>trust_anchor_hints</c>,
    /// <c>trust_marks</c>, <c>trust_mark_issuers</c>, <c>trust_mark_owners</c>)
    /// appear only when <c>iss</c> == <c>sub</c>, and the
    /// Subordinate-Statement-only claims (<c>metadata_policy</c>,
    /// <c>metadata_policy_crit</c>, <c>constraints</c>, <c>source_endpoint</c>)
    /// appear only when <c>iss</c> != <c>sub</c>. A misplaced claim fails this
    /// check and the statement MUST be rejected.
    /// </summary>
    public static ClaimId ClaimPlacementValid { get; } = ClaimId.Create(1114, "ClaimPlacementValid");

    /// <summary>
    /// The <c>crit</c> (critical) payload claim, when present, is well-formed
    /// and every extension Claim Name it lists is present in the payload and
    /// understood by the consumer, per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-13.4">Federation §13.4</see>
    /// (§3.1.1 usage). A <c>crit</c> that is empty, lists a duplicate, lists a
    /// name absent from the payload, or names an extension the consumer does
    /// not understand invalidates the statement.
    /// <see cref="ClaimOutcome.NotApplicable"/> when <c>crit</c> is absent.
    /// </summary>
    public static ClaimId CritClaimsUnderstood { get; } = ClaimId.Create(1115, "CritClaimsUnderstood");

    /// <summary>
    /// The statement does not carry a <c>trust_chain</c> or
    /// <c>peer_trust_chain</c> JWS header parameter, per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-4.3">Federation §4.3</see>
    /// and §4.4: an Entity Configuration or Subordinate Statement is itself a
    /// component of a Trust Chain and MUST NOT embed one in its header.
    /// </summary>
    public static ClaimId NoChainHeaderInStatement { get; } = ClaimId.Create(1116, "NoChainHeaderInStatement");

    /// <summary>
    /// When the statement's <c>metadata</c> carries a <c>federation_entity</c>
    /// block, each federation endpoint URL it declares
    /// (<c>federation_fetch_endpoint</c>, <c>federation_list_endpoint</c>,
    /// <c>federation_resolve_endpoint</c>,
    /// <c>federation_trust_mark_status_endpoint</c>,
    /// <c>federation_trust_mark_list_endpoint</c>,
    /// <c>federation_trust_mark_endpoint</c>,
    /// <c>federation_historical_keys_endpoint</c>) uses the <c>https</c> scheme
    /// and contains no fragment component, per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-5.1.1">Federation §5.1.1</see>.
    /// </summary>
    public static ClaimId FederationEntityEndpointsWellFormed { get; } = ClaimId.Create(1117, "FederationEntityEndpointsWellFormed");

    /// <summary>
    /// When the statement's <c>metadata</c> carries a <c>federation_entity</c>
    /// block whose <c>endpoint_auth_signing_alg_values_supported</c> is present,
    /// none of its listed algorithms is <c>none</c>, per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-5.1.1">Federation §5.1.1</see>
    /// (the value <c>none</c> MUST NOT be used).
    /// </summary>
    public static ClaimId FederationEntityEndpointAuthAlgsNotNone { get; } = ClaimId.Create(1118, "FederationEntityEndpointAuthAlgsNotNone");

    /// <summary>
    /// When the statement's <c>metadata</c> carries a <c>federation_entity</c>
    /// block, none of the §5.2.1 JWK-set parameters (<c>jwks</c>,
    /// <c>jwks_uri</c>, <c>signed_jwks_uri</c>) appears in it, per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-5.2.1">Federation §5.2.1</see>
    /// (those parameters MUST NOT be used in <c>federation_entity</c> metadata —
    /// the Federation Entity Keys live in the Entity Statement's top-level
    /// <c>jwks</c> Claim instead).
    /// </summary>
    public static ClaimId FederationEntityHasNoJwkSetParams { get; } = ClaimId.Create(1119, "FederationEntityHasNoJwkSetParams");


    //Trust chain validation per Federation §4.3 / §10 (codes 1120–1139).

    /// <summary>
    /// Position 0 of the chain is the Entity Configuration of the subject
    /// (the leaf the chain is built for).
    /// </summary>
    public static ClaimId ChainStartsAtSubject { get; } = ClaimId.Create(1120, "ChainStartsAtSubject");

    /// <summary>
    /// The final position of the chain is an Entity Configuration whose
    /// <c>iss</c> appears in the application-supplied trust anchor list.
    /// </summary>
    public static ClaimId ChainTerminatesAtTrustAnchor { get; } = ClaimId.Create(1121, "ChainTerminatesAtTrustAnchor");

    /// <summary>
    /// No Entity Identifier appears more than once in the chain
    /// (cycle defense).
    /// </summary>
    public static ClaimId ChainNoCycles { get; } = ClaimId.Create(1122, "ChainNoCycles");

    /// <summary>
    /// The chain length does not exceed the <c>max_path_length</c>
    /// constraint accumulated up the chain.
    /// </summary>
    public static ClaimId ChainWithinMaxPathLength { get; } = ClaimId.Create(1123, "ChainWithinMaxPathLength");

    /// <summary>
    /// Every link in the chain (every Subordinate Statement plus the
    /// Trust Anchor's Entity Configuration) passes Entity Statement
    /// validation against the appropriate key.
    /// </summary>
    public static ClaimId ChainAllLinksVerified { get; } = ClaimId.Create(1124, "ChainAllLinksVerified");

    /// <summary>
    /// The chain's effective <c>exp</c> equals the minimum <c>exp</c>
    /// across all statements in the chain per Federation §10.4.
    /// </summary>
    public static ClaimId ChainExpIsMinOfLinks { get; } = ClaimId.Create(1125, "ChainExpIsMinOfLinks");

    /// <summary>
    /// Every subordinate Entity Identifier in the chain satisfies the
    /// <c>naming_constraints</c> (<c>permitted</c> / <c>excluded</c> URI name
    /// subtrees) carried by any superior Subordinate Statement above it, per
    /// Federation §6.2.2 (RFC 5280 §4.2.1.10 host-name constraint syntax). An
    /// <c>excluded</c> match invalidates the chain regardless of <c>permitted</c>.
    /// </summary>
    public static ClaimId ChainSatisfiesNamingConstraints { get; } = ClaimId.Create(1126, "ChainSatisfiesNamingConstraints");

    /// <summary>
    /// Adjacent statements in the chain are properly linked per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-10.2">Federation §10.2</see>:
    /// for every position <c>j</c> below the Trust Anchor,
    /// <c>Statements[j].iss</c> equals <c>Statements[j+1].sub</c> — each
    /// statement is issued by the entity the statement above it is about. A
    /// break in this chain means the statements do not form a single path from
    /// subject to anchor.
    /// </summary>
    public static ClaimId ChainProperlyLinked { get; } = ClaimId.Create(1127, "ChainProperlyLinked");


    //Metadata policy per Federation §6.1.4 (codes 1140–1159).

    /// <summary>
    /// All metadata policy operator combinations encountered up the chain
    /// are legal per Federation §6.1.3.1.8.
    /// </summary>
    public static ClaimId MetadataPolicyOperatorCombinationLegal { get; } = ClaimId.Create(1140, "MetadataPolicyOperatorCombinationLegal");

    /// <summary>
    /// The merged metadata policy applied cleanly to the subject's
    /// metadata; no operator produced a conflict or invalid value per
    /// Federation §6.1.4.2.
    /// </summary>
    public static ClaimId MetadataPolicyAppliedCleanly { get; } = ClaimId.Create(1141, "MetadataPolicyAppliedCleanly");

    /// <summary>
    /// The resulting subject metadata satisfies the chain's accumulated
    /// constraints (<c>max_path_length</c>, <c>naming_constraints</c>,
    /// <c>allowed_entity_types</c>) per Federation §6.2.
    /// </summary>
    public static ClaimId MetadataPolicyConstraintSatisfied { get; } = ClaimId.Create(1142, "MetadataPolicyConstraintSatisfied");

    /// <summary>
    /// Every operator named in the chain's accumulated
    /// <c>metadata_policy_crit</c> claims is understood by the receiver
    /// per Federation §6.1.3.2. When any listed operator is unknown,
    /// emitted with <see cref="Verifiable.Core.Assessment.ClaimOutcome.Failure"/>
    /// and a <see cref="MetadataPolicyCritFailureContext"/> listing the
    /// unknown operators.
    /// </summary>
    public static ClaimId MetadataPolicyCritOperatorsUnderstood { get; } = ClaimId.Create(1143, "MetadataPolicyCritOperatorsUnderstood");


    //Party approval gate (codes 1160–1169).

    /// <summary>
    /// The <c>ApprovePartyDelegate</c> approved the resolved party. Emitted
    /// by <c>FederationDefaultHooks.ApproveParty</c> after chain validation
    /// succeeds; deployment-supplied delegates may emit failure with
    /// <see cref="ClaimOutcome.Failure"/> outcome and a context subclass
    /// carrying the rejection reason.
    /// </summary>
    public static ClaimId PartyApproved { get; } = ClaimId.Create(1160, "PartyApproved");


    //Trust Mark validation per Federation §7.3 (codes 1170–1189).

    /// <summary>
    /// The trust mark JWS signature verifies against the trust mark
    /// issuer's key.
    /// </summary>
    public static ClaimId TrustMarkSignatureVerifies { get; } = ClaimId.Create(1170, "TrustMarkSignatureVerifies");

    /// <summary>
    /// The trust mark issuer is authorised to issue trust marks of this
    /// type per the chain's <c>trust_mark_issuers</c> claim.
    /// </summary>
    public static ClaimId TrustMarkIssuerAuthorized { get; } = ClaimId.Create(1171, "TrustMarkIssuerAuthorized");

    /// <summary>
    /// The trust mark's <c>exp</c> claim is in the future (with clock-skew
    /// tolerance).
    /// </summary>
    public static ClaimId TrustMarkExpInFuture { get; } = ClaimId.Create(1172, "TrustMarkExpInFuture");

    /// <summary>
    /// The trust mark's delegation chain (when present) validates per
    /// Federation §7.2.2.
    /// </summary>
    public static ClaimId TrustMarkDelegationValid { get; } = ClaimId.Create(1173, "TrustMarkDelegationValid");

    /// <summary>
    /// The trust mark's <c>exp</c> claim, when present, is strictly after
    /// <c>iat</c> — mutual temporal consistency, independent of the clock.
    /// <see cref="ClaimOutcome.NotApplicable"/> when the mark omits <c>exp</c>.
    /// </summary>
    public static ClaimId TrustMarkExpAfterIat { get; } = ClaimId.Create(1174, "TrustMarkExpAfterIat");

    /// <summary>
    /// The trust mark's JWS protected header carries an <c>alg</c> that is not
    /// <c>none</c>, per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-7.3">Federation §7.3</see>
    /// — an unsigned (<c>alg=none</c>) trust mark is rejected.
    /// </summary>
    public static ClaimId TrustMarkAlgPresent { get; } = ClaimId.Create(1175, "TrustMarkAlgPresent");

    /// <summary>
    /// The trust mark's <c>iat</c> claim is within the clock-skew window
    /// relative to now — its issuance time is in the past — per Federation
    /// §7.3 ("the current time MUST be after the time represented by the
    /// <c>iat</c> Claim").
    /// </summary>
    public static ClaimId TrustMarkIatInRange { get; } = ClaimId.Create(1176, "TrustMarkIatInRange");
}
