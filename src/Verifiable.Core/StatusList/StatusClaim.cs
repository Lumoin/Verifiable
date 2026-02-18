using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.StatusList;

/// <summary>
/// The <c>status</c> claim container that holds references to one or more status mechanisms.
/// </summary>
/// <remarks>
/// <para>
/// Per the Token Status List specification, the <c>status</c> claim in a Referenced Token
/// can contain references to different status mechanisms. This type currently supports
/// <c>status_list</c> but is extensible for future mechanisms, analogous to the
/// <c>cnf</c> claim in RFC 7800.
/// </para>
/// </remarks>
/// <remarks>
/// Creates a status claim with a Status List reference.
/// </remarks>
/// <param name="statusList">The reference to an entry in a Status List Token.</param>
[DebuggerDisplay("StatusClaim[{HasStatusList ? \"status_list\" : \"empty\"}]")]
public sealed class StatusClaim(StatusListReference statusList)
{
    /// <summary>
    /// Gets the Status List reference, if present.
    /// </summary>
    public StatusListReference? StatusList { get; } = statusList;

    /// <summary>
    /// Gets a value indicating whether this claim contains a Status List reference.
    /// </summary>
    public bool HasStatusList => StatusList.HasValue;

    /// <summary>
    /// Creates a status claim from an index and URI.
    /// </summary>
    /// <param name="index">The zero-based index within the Status List.</param>
    /// <param name="uri">The URI of the Status List Token.</param>
    /// <returns>A new <see cref="StatusClaim"/> instance.</returns>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "The specification defines this as a string claim value serialized directly in JWT and CWT formats.")]
    public static StatusClaim FromStatusList(int index, string uri)
    {
        return new StatusClaim(new StatusListReference(index, uri));
    }
}