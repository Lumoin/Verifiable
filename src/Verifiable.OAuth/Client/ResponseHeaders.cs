using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Headers returned with an HTTP response. Surfaces protocol-relevant
/// headers up to library handler code — for example RFC 9449 §10.1
/// <c>DPoP-Nonce</c> challenges and OID4VCI §9 <c>Retry-After</c> for
/// deferred credential polling.
/// </summary>
/// <remarks>
/// Phase 5 doesn't consume this slot — it ships with an empty default
/// and the test transport populates it as zero entries. The slot is
/// added now so the committed-future work (DPoP, OID4VCI) doesn't
/// require a transport-shape refactor.
/// </remarks>
[DebuggerDisplay("ResponseHeaders ({Values.Count} headers)")]
public sealed record ResponseHeaders
{
    /// <summary>The header name-to-value map.</summary>
    public ImmutableDictionary<string, string> Values { get; init; } =
        ImmutableDictionary<string, string>.Empty;

    /// <summary>The empty header set.</summary>
    public static ResponseHeaders Empty { get; } = new();

    /// <summary>
    /// Returns the value for <paramref name="name"/> if present, otherwise
    /// <see langword="null"/>. Name comparison is case-insensitive per
    /// RFC 9110 §5.1.
    /// </summary>
    public string? TryGetSingle(string name)
    {
        foreach(KeyValuePair<string, string> pair in Values)
        {
            if(string.Equals(pair.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                return pair.Value;
            }
        }
        return null;
    }
}
