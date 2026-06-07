using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Identifies a metadata-policy operator per OpenID Federation 1.0 §6.1.2.
/// The library ships the seven standard operators on
/// <see cref="WellKnownMetadataPolicyOperators"/>; deployments register
/// extension operators via the constructor and declare them in
/// <c>metadata_policy_crit</c> per §6.1.3.2.
/// </summary>
/// <remarks>
/// <para>
/// Value-type wrapper around the operator's wire string (e.g. <c>value</c>,
/// <c>subset_of</c>). Canonical identity is ordinal-string equality. Same
/// shape as <see cref="EntityTypeIdentifier"/> and
/// <see cref="EntityIdentifier"/>; flows opaquely through the policy
/// merge / apply pipeline.
/// </para>
/// </remarks>
[DebuggerDisplay("{Value,nq}")]
public readonly struct MetadataPolicyOperator: IEquatable<MetadataPolicyOperator>
{
    /// <summary>
    /// The operator's wire string. Canonical identity; equality and hashing
    /// compare on this value with <see cref="StringComparison.Ordinal"/>.
    /// </summary>
    public string Value { get; }


    /// <summary>
    /// Constructs an operator from its wire string.
    /// </summary>
    /// <param name="value">The operator name. Required to be non-null and non-whitespace.</param>
    /// <exception cref="ArgumentException">When <paramref name="value"/> is null or whitespace.</exception>
    public MetadataPolicyOperator(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value;
    }


    /// <inheritdoc/>
    public bool Equals(MetadataPolicyOperator other) =>
        string.Equals(Value, other.Value, StringComparison.Ordinal);


    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is MetadataPolicyOperator other && Equals(other);


    /// <inheritdoc/>
    public override int GetHashCode() =>
        Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);


    /// <inheritdoc/>
    public override string ToString() => Value ?? string.Empty;


    /// <summary>Equality operator.</summary>
    public static bool operator ==(MetadataPolicyOperator left, MetadataPolicyOperator right) => left.Equals(right);


    /// <summary>Inequality operator.</summary>
    public static bool operator !=(MetadataPolicyOperator left, MetadataPolicyOperator right) => !left.Equals(right);
}
