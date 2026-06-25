using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Per-entity-type metadata-policy block within a single statement's
/// <c>metadata_policy</c> claim per OpenID Federation 1.0 §6.1.2.
/// </summary>
/// <remarks>
/// <para>
/// A statement's <c>metadata_policy</c> claim is keyed by
/// <see cref="EntityTypeIdentifier"/> (e.g. <c>openid_relying_party</c>,
/// <c>openid_provider</c>); each per-type block carries a dictionary of
/// parameter-name to <see cref="ParameterPolicy"/>. This record holds one
/// such block in typed form so consumers walk
/// <see cref="ParameterPolicies"/> rather than re-parsing the loose
/// payload.
/// </para>
/// </remarks>
[DebuggerDisplay("EntityTypeMetadataPolicy {EntityType.Value,nq} ({ParameterPolicies.Count} params)")]
public sealed record EntityTypeMetadataPolicy
{
    /// <summary>The entity type the contained parameter policies scope to.</summary>
    public required EntityTypeIdentifier EntityType { get; init; }

    /// <summary>The per-parameter policies, keyed by parameter name.</summary>
    public required IReadOnlyDictionary<string, ParameterPolicy> ParameterPolicies { get; init; }
}
