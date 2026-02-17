using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// Represents alternative sets of claims that can satisfy a credential query.
/// </summary>
/// <remarks>
/// <para>
/// A claim set query allows the verifier to specify multiple acceptable combinations
/// of claims. The credential satisfies the query if it can provide at least one
/// of the specified claim sets.
/// </para>
/// <para>
/// The options are evaluated in order. The wallet should prefer earlier options
/// when multiple are satisfiable, as they represent the verifier's preference order.
/// </para>
/// <example>
/// A verifier might accept either:
/// <list type="bullet">
///   <item><description>Full name (given_name + family_name).</description></item>
///   <item><description>Just a display name.</description></item>
/// </list>
/// This would be expressed as two options in the claim set.
/// </example>
/// </remarks>
[DebuggerDisplay("Options={OptionCount} Required={Required}")]
public record ClaimSetQuery
{
    /// <summary>
    /// Alternative sets of claim identifiers that can satisfy this query.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each inner list represents a set of claim IDs that must all be present
    /// for that option to be satisfied (AND within each set).
    /// </para>
    /// <para>
    /// The outer list represents alternatives (OR between sets).
    /// </para>
    /// <para>
    /// Claim IDs reference either the <see cref="ClaimsQuery.Id"/> property
    /// or, if not set, are derived from the claim path.
    /// </para>
    /// </remarks>
    public IReadOnlyList<IReadOnlyList<string>>? Options { get; set; }

    /// <summary>
    /// Indicates whether satisfying this claim set is required.
    /// Defaults to <see langword="true"/>.
    /// </summary>
    public bool Required { get; init; } = true;

    /// <summary>
    /// Gets the number of alternative options in this claim set.
    /// </summary>
    public int OptionCount => Options?.Count ?? 0;
}