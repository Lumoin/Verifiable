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
    /// The authority identification scheme — one of the registered values on
    /// <see cref="DcqlTrustedAuthorityTypes"/> (<c>aki</c>, <c>etsi_tl</c>,
    /// <c>openid_federation</c>) per OID4VP 1.0 §6.1.1.
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
