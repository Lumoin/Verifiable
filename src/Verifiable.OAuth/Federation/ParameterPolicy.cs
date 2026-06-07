using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Per-parameter metadata-policy entry per OpenID Federation 1.0 §6.1.2.
/// Pairs a metadata parameter name (e.g. <c>grant_types</c>,
/// <c>id_token_signed_response_alg</c>) with the operators a single
/// statement declares for it.
/// </summary>
/// <remarks>
/// <para>
/// One <see cref="ParameterPolicy"/> per (statement, entity-type,
/// parameter) tuple. The <see cref="Operators"/> dictionary uses
/// <see cref="MetadataPolicyOperator"/> as the key, so equality across
/// well-known and extension operators is direct ordinal-string compare.
/// </para>
/// <para>
/// The operator values are the raw payload-side objects:
/// <see cref="WellKnownMetadataPolicyOperators.Value"/> carries the
/// replacement value as-is; <see cref="WellKnownMetadataPolicyOperators.Add"/>,
/// <see cref="WellKnownMetadataPolicyOperators.OneOf"/>,
/// <see cref="WellKnownMetadataPolicyOperators.SubsetOf"/>,
/// <see cref="WellKnownMetadataPolicyOperators.SupersetOf"/> carry
/// <c>IReadOnlyList&lt;object&gt;</c>;
/// <see cref="WellKnownMetadataPolicyOperators.Essential"/> carries
/// <see cref="bool"/>. Downstream consumers do not pre-cast — they
/// inspect the value at use-site so the inevitable shape mismatches
/// surface as targeted exceptions rather than at parsing time.
/// </para>
/// </remarks>
[DebuggerDisplay("ParameterPolicy {ParameterName,nq} ({Operators.Count} ops)")]
public sealed record ParameterPolicy
{
    /// <summary>The metadata parameter this policy applies to.</summary>
    public required string ParameterName { get; init; }

    /// <summary>The operators declared for this parameter.</summary>
    public required IReadOnlyDictionary<MetadataPolicyOperator, object> Operators { get; init; }
}
