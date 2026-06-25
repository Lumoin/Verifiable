using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Typed snapshot of a single statement's <c>metadata_policy</c> claim
/// per OpenID Federation 1.0 §6.1. Produced by
/// <see cref="MetadataPolicyParser.Parse(IReadOnlyDictionary{string, object})"/>.
/// </summary>
/// <remarks>
/// <para>
/// The wire shape of <c>metadata_policy</c> is a two-level nested object:
/// outer keys are entity types (<c>openid_relying_party</c>,
/// <c>openid_provider</c>, etc.); inner keys are parameter names
/// (<c>grant_types</c>, <c>id_token_signed_response_alg</c>, etc.); leaf
/// values are operator-keyed dictionaries (<c>value</c>, <c>subset_of</c>,
/// <c>essential</c>, etc.). This record carries the parsed result so
/// downstream merge / apply walks pre-typed entries rather than
/// repeatedly traversing the loose dictionary.
/// </para>
/// <para>
/// A snapshot reflects exactly one statement's policy. Combining policies
/// across a trust chain is the responsibility of the merge algorithm,
/// which produces a new snapshot from two inputs.
/// </para>
/// </remarks>
[DebuggerDisplay("MetadataPolicySnapshot ({EntityTypes.Count} entity types)")]
public sealed record MetadataPolicySnapshot
{
    /// <summary>The per-entity-type policy blocks, keyed by entity-type identifier.</summary>
    public required IReadOnlyDictionary<EntityTypeIdentifier, EntityTypeMetadataPolicy> EntityTypes { get; init; }


    /// <summary>An empty snapshot — no per-entity-type policies declared.</summary>
    public static MetadataPolicySnapshot Empty { get; } = new()
    {
        EntityTypes = new Dictionary<EntityTypeIdentifier, EntityTypeMetadataPolicy>()
    };
}
