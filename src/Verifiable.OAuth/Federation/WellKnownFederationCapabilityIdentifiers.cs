using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Library-shipped <see cref="CapabilityIdentifier"/> instances for OpenID
/// Federation 1.0 sub-capabilities. Lives in the
/// <c>Verifiable.OAuth.Federation</c> namespace per the
/// <see cref="WellKnownCapabilityIdentifiers"/> remark: track-specific
/// capability identifiers are colocated with their consuming code rather
/// than extending the master class.
/// </summary>
/// <remarks>
/// <para>
/// Each capability is a URN of the form
/// <c>urn:verifiable:capability:federation:&lt;name&gt;</c>. The umbrella
/// <see cref="WellKnownCapabilityIdentifiers.FederationBase"/> remains the
/// "deployment plays a federation role" marker; the entries here name
/// individual surfaces a deployment may opt into (or out of) independently.
/// </para>
/// <para>
/// Capability identifiers flow into the
/// <see cref="AuthorizationServer"/> capability set and propagate to
/// metadata documents. Adding an entry here implies the library ships an
/// implementation; chunks that introduce only a delegate slot (without a
/// default) defer their capability identifier to later chunks.
/// </para>
/// </remarks>
[DebuggerDisplay("WellKnownFederationCapabilityIdentifiers")]
public static class WellKnownFederationCapabilityIdentifiers
{
    /// <summary>
    /// Validates an OpenID Federation 1.0 Entity Statement against the
    /// §3.2 rule set. Implemented by
    /// <see cref="EntityStatementValidator"/>.
    /// </summary>
    public static CapabilityIdentifier ValidateEntityStatement { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:federation:validate_entity_statement");

    /// <summary>
    /// Validates an inline OpenID Federation 1.0 trust chain against the
    /// §4.3 / §10 rule set (excluding HTTP fetch, which is the
    /// <see cref="FetchEntityStatement"/> capability). Implemented by
    /// <see cref="TrustChainValidator"/>.
    /// </summary>
    public static CapabilityIdentifier ValidateTrustChain { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:federation:validate_trust_chain");

    /// <summary>
    /// Fetches an Entity Statement from a superior's
    /// <c>federation_fetch_endpoint</c> per Federation §8.1. Deferred to
    /// chunk 5's HTTP path; the identifier reserves the URN so the
    /// capability set's shape is fixed when chunks 6–10 wire surrounding
    /// concerns.
    /// </summary>
    public static CapabilityIdentifier FetchEntityStatement { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:federation:fetch_entity_statement");

    /// <summary>
    /// Lists subordinates of a federation entity via its
    /// <c>federation_list_endpoint</c> per Federation §8.2.
    /// </summary>
    public static CapabilityIdentifier ListSubordinates { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:federation:list_subordinates");

    /// <summary>
    /// Resolves a subject's trust chain via a federation resolver's
    /// <c>federation_resolve_endpoint</c> per Federation §8.3.
    /// </summary>
    public static CapabilityIdentifier ResolveTrustChain { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:federation:resolve_trust_chain");

    /// <summary>
    /// Merges and applies an accumulated metadata policy to a subject's
    /// declared metadata per Federation §6.1.4.
    /// </summary>
    public static CapabilityIdentifier ApplyMetadataPolicy { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:federation:apply_metadata_policy");

    /// <summary>
    /// Validates a Federation 1.0 Trust Mark against the issuing entity's
    /// authorisation per Federation §7.3.
    /// </summary>
    public static CapabilityIdentifier ValidateTrustMark { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:federation:validate_trust_mark");

    /// <summary>
    /// Lists subjects holding a given Trust Mark via the issuer's
    /// <c>federation_trust_mark_list_endpoint</c> per Federation §7.2.3.
    /// </summary>
    public static CapabilityIdentifier ListTrustMarkSubjects { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:federation:list_trust_mark_subjects");

    /// <summary>
    /// Queries the status of a Trust Mark via the issuer's
    /// <c>federation_trust_mark_status_endpoint</c> per Federation §7.2.2.
    /// </summary>
    public static CapabilityIdentifier TrustMarkStatus { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:federation:trust_mark_status");

    /// <summary>
    /// Publishes the entity's own Entity Configuration at
    /// <c>/.well-known/openid-federation</c> per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-9">Federation §9</see>.
    /// A registration carrying this capability and a non-null
    /// <see cref="ClientRecord.FederationEntityId"/> serves a signed Entity
    /// Configuration JWT. The signing key comes from
    /// <see cref="Cryptography.Context.KeyUsageContext.FederationEntitySignature"/>
    /// in <see cref="ClientRecord.SigningKeys"/>. Per-tenant — each
    /// registration carrying this capability serves its own EC under its
    /// own resolved URL.
    /// </summary>
    public static CapabilityIdentifier PublishEntityConfiguration { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:federation:publish_entity_configuration");

    /// <summary>
    /// Publishes Subordinate Statements about the entity's subordinates at
    /// the <c>federation_fetch_endpoint</c> per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.1">Federation §8.1</see>.
    /// A registration carrying this capability serves <c>GET ?sub=&lt;subject&gt;</c>
    /// queries by signing an Entity Statement (iss = this entity, sub =
    /// queried subject) with the same federation signing key used for the
    /// entity's own EC. The per-subject statement body comes from the
    /// application's
    /// <see cref="AuthorizationServerIntegration.ResolveSubordinateStatementAsync"/>
    /// delegate.
    /// </summary>
    public static CapabilityIdentifier PublishSubordinateStatement { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:federation:publish_subordinate_statement");

    /// <summary>
    /// Serves the explicit client registration endpoint
    /// (<c>federation_registration_endpoint</c>) per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-12.2">Federation §12.2</see>.
    /// A registration carrying this capability accepts a Relying Party's
    /// signed Entity Configuration via POST and returns a signed Explicit
    /// Registration Response (an Entity Statement about the RP). Signed with
    /// the same federation signing key the entity's own EC uses; the
    /// per-request registration result comes from the application's
    /// <see cref="AuthorizationServerIntegration.ResolveExplicitRegistrationAsync"/>
    /// delegate.
    /// </summary>
    public static CapabilityIdentifier RegisterClientsExplicitly { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:federation:register_clients_explicitly");

    /// <summary>
    /// Admits a Relying Party via automatic registration from an inline trust
    /// chain on the Authorization Request per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-12.1">Federation §12.1</see>,
    /// without prior registration. Implemented by
    /// <see cref="FederationAutomaticRegistration"/>. A registration carrying
    /// this capability advertises <c>automatic</c> in its Entity Configuration's
    /// <see cref="WellKnownFederationClaimNames.ClientRegistrationTypesSupported"/>;
    /// pair it with <see cref="RegisterClientsExplicitly"/> to advertise both.
    /// </summary>
    public static CapabilityIdentifier RegisterClientsAutomatically { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:federation:register_clients_automatically");

    /// <summary>
    /// Publishes the entity's historical (rotated and revoked) Federation
    /// Entity Keys at the <c>federation_historical_keys_endpoint</c> per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.7">Federation §8.7</see>.
    /// A registration carrying this capability serves a signed JWT
    /// (<c>typ = jwk-set+jwt</c>) whose <c>keys</c> array lists the entity's
    /// past keys with their <c>iat</c> / <c>exp</c> / <c>revoked</c> metadata,
    /// so a verifier can validate signatures made with a key that is no longer
    /// in the current Entity Configuration's <c>jwks</c>. Signed with the same
    /// federation signing key the entity's own EC uses
    /// (<see cref="Cryptography.Context.KeyUsageContext.FederationEntitySignature"/>);
    /// the historical <c>keys</c> array comes from the application's
    /// <see cref="AuthorizationServerIntegration.ResolveHistoricalKeysAsync"/>
    /// delegate.
    /// </summary>
    public static CapabilityIdentifier PublishHistoricalKeys { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:federation:publish_historical_keys");
}
