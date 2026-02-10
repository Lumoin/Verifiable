using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// Format-specific metadata constraints for a credential query.
/// </summary>
/// <remarks>
/// <para>
/// Different credential formats use different mechanisms to identify credential types.
/// This class provides properties for the common type identifiers used across formats.
/// </para>
/// <para>
/// For SD-JWT VC (<c>dc+sd-jwt</c>), the <see cref="VctValues"/> property specifies
/// acceptable Verifiable Credential Type values.
/// </para>
/// <para>
/// For ISO mdoc (<c>mso_mdoc</c>), the <see cref="DoctypeValue"/> property specifies
/// the required document type (e.g., "org.iso.18013.5.1.mDL").
/// </para>
/// </remarks>
[DebuggerDisplay("VctValues={VctValues?.Count ?? 0} Doctype={DoctypeValue}")]
public record CredentialQueryMeta
{
    /// <summary>
    /// The JSON property name for <see cref="VctValues"/>.
    /// </summary>
    public const string VctValuesPropertyName = "vct_values";

    /// <summary>
    /// The JSON property name for <see cref="DoctypeValue"/>.
    /// </summary>
    public const string DoctypeValuePropertyName = "doctype_value";

    /// <summary>
    /// Acceptable Verifiable Credential Type (vct) values for SD-JWT VC format.
    /// </summary>
    public IReadOnlyList<string>? VctValues { get; init; }

    /// <summary>
    /// The required document type for ISO mdoc format.
    /// </summary>
    public string? DoctypeValue { get; init; }

    /// <summary>
    /// Gets the effective credential type constraint, preferring vct for SD-JWT
    /// and doctype for mdoc.
    /// </summary>
    /// <param name="format">The credential format identifier.</param>
    /// <returns>The type constraint values, or null if none specified.</returns>
    public IReadOnlyList<string>? GetTypeConstraints(string format)
    {
        return format switch
        {
            "dc+sd-jwt" or "dc+sd-cwt" => VctValues,
            "mso_mdoc" when DoctypeValue is not null => [DoctypeValue],
            _ => VctValues ?? (DoctypeValue is not null ? [DoctypeValue] : null)
        };
    }

    /// <summary>
    /// Gets a value indicating whether any type constraints are specified.
    /// </summary>
    public bool HasTypeConstraints => VctValues is { Count: > 0 } || DoctypeValue is not null;
}