using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.StatusList;

/// <summary>
/// Represents a Status List Aggregation containing URIs of multiple Status List Tokens.
/// </summary>
/// <remarks>
/// <para>
/// A Status List Aggregation provides a list of Status List Token URIs published by
/// an Issuer, enabling Relying Parties to pre-fetch and cache tokens for offline
/// validation. The aggregation endpoint returns JSON with media type <c>application/json</c>.
/// </para>
/// </remarks>
[DebuggerDisplay("StatusListAggregation[Count={StatusLists.Count}]")]
public sealed class StatusListAggregation
{
    /// <summary>
    /// Gets the list of URIs linking to Status List Tokens.
    /// </summary>
    public IReadOnlyList<string> StatusLists { get; }

    /// <summary>
    /// Creates a new Status List Aggregation.
    /// </summary>
    /// <param name="statusLists">The URIs of the Status List Tokens. Must not be empty.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="statusLists"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="statusLists"/> is empty.</exception>
    public StatusListAggregation(IReadOnlyList<string> statusLists)
    {
        ArgumentNullException.ThrowIfNull(statusLists);
        if(statusLists.Count == 0)
        {
            throw new ArgumentException("Status list URIs must not be empty.", nameof(statusLists));
        }

        StatusLists = statusLists;
    }
}