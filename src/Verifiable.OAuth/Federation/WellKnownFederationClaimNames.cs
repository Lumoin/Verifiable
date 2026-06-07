using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Federation-specific JWT claim names per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-3">Federation §3</see>,
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-6.2">§6.2 (Constraints)</see>,
/// and
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-7">§7 (Trust Marks)</see>.
/// </summary>
/// <remarks>
/// Standard JWT claims (<c>sub</c>, <c>iss</c>, <c>exp</c>, <c>iat</c>,
/// <c>aud</c>, <c>jti</c>) live on
/// <see cref="Verifiable.JCose.WellKnownJwtClaimNames"/> and are not
/// duplicated here; Federation reuses those names with Federation-specific
/// semantics (e.g. for an Entity Configuration, <c>iss</c> == <c>sub</c>).
/// </remarks>
[DebuggerDisplay("WellKnownFederationClaimNames")]
public static class WellKnownFederationClaimNames
{
    /// <summary>
    /// <c>jwks</c> — JSON Web Key Set carrying the entity's signing keys
    /// per Federation §3.1.
    /// </summary>
    public static readonly string Jwks = "jwks";

    /// <summary>
    /// <c>keys</c> — array of JWK objects carrying the entity's historical
    /// (rotated and revoked) Federation Entity Keys in the signed JWK Set a
    /// <c>federation_historical_keys_endpoint</c> returns per Federation
    /// §8.7.2 (per-key revocation reasons per §8.7.3).
    /// </summary>
    public static readonly string Keys = "keys";

    /// <summary>
    /// <c>authority_hints</c> — array of <see cref="EntityIdentifier"/>
    /// values naming the entity's immediate superiors in the federation
    /// hierarchy per Federation §3.1.1.
    /// </summary>
    public static readonly string AuthorityHints = "authority_hints";

    /// <summary>
    /// <c>metadata</c> — per-entity-type metadata object per
    /// Federation §3.1.1. Keyed by <see cref="EntityTypeIdentifier"/>.
    /// </summary>
    public static readonly string Metadata = "metadata";

    /// <summary>
    /// <c>client_registration_types_supported</c> — the registration types an
    /// OpenID Provider supports per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-12">Federation §12</see>.
    /// An array drawn from <see cref="WellKnownFederationRegistrationTypeValues"/>
    /// (<c>automatic</c> and/or <c>explicit</c>), emitted inside the
    /// <c>openid_provider</c> metadata block of an Entity Configuration.
    /// </summary>
    public static readonly string ClientRegistrationTypesSupported = "client_registration_types_supported";

    /// <summary>
    /// <c>metadata_policy</c> — per-entity-type metadata policy operators
    /// applied by superiors per Federation §6.1.
    /// </summary>
    public static readonly string MetadataPolicy = "metadata_policy";

    /// <summary>
    /// <c>metadata_policy_crit</c> — names of critical metadata-policy
    /// operators a relying party MUST understand per Federation §6.1.3.2.
    /// </summary>
    public static readonly string MetadataPolicyCrit = "metadata_policy_crit";

    /// <summary>
    /// <c>constraints</c> — chain-level constraints (<c>max_path_length</c>,
    /// <c>naming_constraints</c>, <c>allowed_entity_types</c>) per
    /// Federation §6.2.
    /// </summary>
    public static readonly string Constraints = "constraints";

    /// <summary>
    /// <c>max_path_length</c> — maximum number of intermediate entities
    /// between the issuer and the leaf per Federation §6.2.
    /// </summary>
    public static readonly string MaxPathLength = "max_path_length";

    /// <summary>
    /// <c>naming_constraints</c> — DNS-name-style permitted / excluded
    /// subordinate identifiers per Federation §6.2.
    /// </summary>
    public static readonly string NamingConstraints = "naming_constraints";

    /// <summary>
    /// <c>allowed_entity_types</c> — restricts the set of
    /// <see cref="EntityTypeIdentifier"/> values a subordinate may declare
    /// per Federation §6.2.
    /// </summary>
    public static readonly string AllowedEntityTypes = "allowed_entity_types";

    /// <summary>
    /// <c>trust_marks</c> — array of Trust Mark JWTs the subject presents
    /// per Federation §7.
    /// </summary>
    public static readonly string TrustMarks = "trust_marks";

    /// <summary>
    /// <c>trust_mark_issuers</c> — map naming the entities authorised to
    /// issue specific trust marks per Federation §3.1.2.
    /// </summary>
    public static readonly string TrustMarkIssuers = "trust_mark_issuers";

    /// <summary>
    /// <c>trust_mark_owners</c> — map identifying owners and their JWKS
    /// for delegated trust marks per Federation §3.1.2.
    /// </summary>
    public static readonly string TrustMarkOwners = "trust_mark_owners";

    /// <summary>
    /// <c>source_endpoint</c> — endpoint URL from which the statement was
    /// fetched per Federation §3.1.2.
    /// </summary>
    public static readonly string SourceEndpoint = "source_endpoint";

    /// <summary>
    /// <c>trust_chain</c> — JWS header parameter carrying an inline trust
    /// chain per Federation §4.3.
    /// </summary>
    public static readonly string TrustChain = "trust_chain";

    /// <summary>
    /// <c>trust_anchor</c> — the Entity Identifier of the Trust Anchor the
    /// issuer selected when producing a Resolve Response (§8.3) or an
    /// Explicit Registration Response (§12.2 / §3.1.5).
    /// </summary>
    public static readonly string TrustAnchor = "trust_anchor";

    /// <summary>
    /// <c>peer_trust_chain</c> — JWS header parameter for peer-supplied
    /// trust chains per Federation §4.4.
    /// </summary>
    public static readonly string PeerTrustChain = "peer_trust_chain";

    /// <summary>
    /// <c>trust_mark_type</c> — the Trust Mark type identifier carried in a Trust
    /// Mark JWT payload and in the subject's <see cref="TrustMarks"/> array entry
    /// pointing to the JWT (the two MUST match). REQUIRED per OpenID Federation 1.0
    /// final §3.1.2 / §7.1; the draft-era name for this claim was <c>id</c>.
    /// </summary>
    public static readonly string TrustMarkType = "trust_mark_type";

    /// <summary>
    /// <c>delegation</c> — JWS-encoded delegation chain inside a Trust Mark
    /// JWT, present when the issuing entity holds the mark under delegation
    /// from a Trust Mark Owner per Federation §7.2.2.
    /// </summary>
    public static readonly string Delegation = "delegation";

    /// <summary>
    /// <c>logo_uri</c> — optional URI pointing to a visual representation of the
    /// trust mark per OpenID Federation 1.0 final §7.1 / §13.7; the draft-era name
    /// for this claim was <c>mark</c>.
    /// </summary>
    public static readonly string LogoUri = "logo_uri";

    /// <summary>
    /// <c>ref</c> — optional URI pointing to human-readable documentation of
    /// the trust mark per Federation §7.1.1.
    /// </summary>
    public static readonly string Ref = "ref";
}
