using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// Represents trusted authority constraints for a credential query.
/// </summary>
/// <remarks>
/// Restricts which authorities (e.g., certificate issuers or AKI values)
/// are acceptable for a given credential. The <see cref="Type"/> identifies
/// the authority identification scheme, and <see cref="Values"/> lists the
/// acceptable identifiers.
/// </remarks>
[DebuggerDisplay("Type={Type} Values={Values.Count}")]
public record TrustedAuthoritiesQuery
{
    /// <summary>
    /// The JSON property name for <see cref="Type"/>.
    /// </summary>
    public const string TypePropertyName = "type";

    /// <summary>
    /// The JSON property name for <see cref="Values"/>.
    /// </summary>
    public const string ValuesPropertyName = "values";

    /// <summary>
    /// The type of authority identifier (e.g., "aki" for Authority Key Identifier).
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// The list of acceptable authority identifiers.
    /// </summary>
    public required IReadOnlyList<string> Values { get; init; }

    /// <summary>
    /// Gets a value indicating whether any authorities are specified.
    /// </summary>
    public bool HasAuthorities => Values.Count > 0;
}