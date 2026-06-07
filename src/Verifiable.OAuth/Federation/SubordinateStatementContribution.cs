using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Application-supplied body of a Subordinate Statement served at the
/// <c>federation_fetch_endpoint</c> per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.1">Federation §8.1</see>.
/// The library produces the structural envelope claims (<c>iss</c>,
/// <c>sub</c>, <c>iat</c>, <c>exp</c>) and signs the JWT; everything else
/// — the subject's <c>jwks</c>, any per-subject <c>metadata_policy</c>,
/// <c>metadata</c>, <c>constraints</c>, or extension claims — comes from
/// the application's
/// <see cref="Server.AuthorizationServerIntegration.ResolveSubordinateStatementAsync"/>
/// delegate.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Jwks"/> is required: a Subordinate Statement that does not
/// declare the subject's federation signing keys cannot be the bridge link
/// of a trust chain. The remaining slots are optional and mirror the
/// per-claim shape of <see cref="FederationEntityConfigurationContribution"/>.
/// </para>
/// <para>
/// The application returns <see langword="null"/> from the resolver
/// delegate when the queried subject is not a known subordinate; the
/// library then returns HTTP 404.
/// </para>
/// </remarks>
[DebuggerDisplay("SubordinateStatementContribution")]
public sealed record SubordinateStatementContribution
{
    /// <summary>
    /// The subject's <c>jwks</c> claim — the keys the subject uses to sign
    /// its own Entity Statements. Required: chain validation pulls
    /// <c>jwks</c> off each Subordinate Statement to verify the signature
    /// on the next link toward the subject.
    /// </summary>
    public required IReadOnlyDictionary<string, object> Jwks { get; init; }

    /// <summary>
    /// Optional <c>metadata_policy</c> claim. The metadata-policy operators
    /// the issuing entity applies to the subject's declared metadata per
    /// Federation §6.1.
    /// </summary>
    public IReadOnlyDictionary<string, object>? MetadataPolicy { get; init; }

    /// <summary>
    /// Optional <c>metadata</c> claim. Per-entity-type metadata blocks the
    /// issuer asserts about the subject (typically used for declarative
    /// metadata flow rather than policy).
    /// </summary>
    public IReadOnlyDictionary<string, object>? Metadata { get; init; }

    /// <summary>
    /// Optional <c>constraints</c> claim per Federation §6.2 —
    /// <c>max_path_length</c>, <c>naming_constraints</c>,
    /// <c>allowed_entity_types</c>.
    /// </summary>
    public IReadOnlyDictionary<string, object>? Constraints { get; init; }

    /// <summary>
    /// Additional top-level claims to merge into the SS payload after the
    /// library's structural claims and the dedicated slots above. Use for
    /// <c>trust_marks</c>, <c>crit</c>, or deployment-specific federation
    /// extensions. Keys that collide with library-emitted structural claims
    /// (<c>iss</c>, <c>sub</c>, <c>iat</c>, <c>exp</c>, <c>jwks</c>) are
    /// dropped — the library wins.
    /// </summary>
    public IReadOnlyDictionary<string, object>? AdditionalClaims { get; init; }
}
