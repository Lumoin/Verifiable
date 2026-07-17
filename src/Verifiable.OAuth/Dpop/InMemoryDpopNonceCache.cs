using System.Collections.Concurrent;
using System.Diagnostics;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// In-process default backing for the client-side DPoP nonce cache. Maps
/// authority (scheme + host + port) to the most recently observed nonce.
/// </summary>
/// <remarks>
/// <para>
/// Single-instance clients use this default directly. Distributed clients
/// (browser-based with shared workers, server-side agents in a cluster)
/// wire a different backing through the delegate slots on
/// <see cref="Verifiable.OAuth.Client.OAuthClientInfrastructure"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("InMemoryDpopNonceCache Count={entries.Count}")]
public sealed class InMemoryDpopNonceCache
{
    private ConcurrentDictionary<string, string> Entries { get; } =
        new(StringComparer.Ordinal);


    /// <summary>
    /// Returns the most recently stored nonce for <paramref name="authority"/>,
    /// or <see langword="null"/> when no nonce has been cached.
    /// </summary>
    public string? Lookup(string authority)
    {
        ArgumentException.ThrowIfNullOrEmpty(authority);
        return Entries.TryGetValue(authority, out string? nonce) ? nonce : null;
    }


    /// <summary>
    /// Stores <paramref name="nonce"/> against <paramref name="authority"/>,
    /// overwriting any previously cached value for that authority.
    /// </summary>
    public void Store(string authority, string nonce)
    {
        ArgumentException.ThrowIfNullOrEmpty(authority);
        ArgumentException.ThrowIfNullOrEmpty(nonce);
        Entries[authority] = nonce;
    }


    /// <summary>
    /// Computes the authority key for a given request URI — the scheme,
    /// host, and port without path or query.
    /// </summary>
    public static string AuthorityFor(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        return $"{uri.Scheme}://{uri.Authority}";
    }
}
