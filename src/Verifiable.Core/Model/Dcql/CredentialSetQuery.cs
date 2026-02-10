using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// Specifies constraints on combinations of credentials that must be presented together.
/// </summary>
/// <remarks>
/// <para>
/// A credential set query defines which combinations of credentials (identified by their
/// <see cref="CredentialQuery.Id"/>) can satisfy the overall presentation request.
/// </para>
/// <para>
/// This enables scenarios like:
/// <list type="bullet">
///   <item><description>Requiring both an ID card AND a proof of address.</description></item>
///   <item><description>Accepting either a passport OR a national ID card.</description></item>
///   <item><description>Accepting (passport AND visa) OR (national ID for EU citizens).</description></item>
/// </list>
/// </para>
/// <para>
/// The options are evaluated in preference order. When multiple options are satisfiable,
/// the wallet should prefer earlier options.
/// </para>
/// </remarks>
[DebuggerDisplay("Options={OptionCount} Required={Required}")]
public record CredentialSetQuery
{
    /// <summary>
    /// The JSON property name for <see cref="Options"/>.
    /// </summary>
    public const string OptionsPropertyName = "options";

    /// <summary>
    /// The JSON property name for <see cref="Required"/>.
    /// </summary>
    public const string RequiredPropertyName = "required";

    /// <summary>
    /// The JSON property name for <see cref="Purpose"/>.
    /// </summary>
    public const string PurposePropertyName = "purpose";

    /// <summary>
    /// Alternative sets of credential IDs that can satisfy this query.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each inner list represents a set of credential query IDs that must all be
    /// satisfied for that option to be valid (AND within each set).
    /// </para>
    /// <para>
    /// The outer list represents alternatives (OR between sets).
    /// </para>
    /// <example>
    /// <c>Options = [["passport", "visa"], ["national_id"]]</c>
    /// means: (passport AND visa) OR (national_id).
    /// </example>
    /// </remarks>
    public required IReadOnlyList<IReadOnlyList<string>> Options { get; set; }

    /// <summary>
    /// Indicates whether satisfying this credential set is required.
    /// Defaults to <see langword="true"/>.
    /// </summary>
    public bool Required { get; set; } = true;

    /// <summary>
    /// An optional explanation of why this credential combination is requested.
    /// </summary>
    public string? Purpose { get; set; }

    /// <summary>
    /// Gets the number of alternative options in this credential set.
    /// </summary>
    public int OptionCount => Options.Count;
}