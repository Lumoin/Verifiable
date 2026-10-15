using System.Collections.Concurrent;
using System.Diagnostics;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// In-process default backing for the client-side DPoP nonce cache. Maps an endpoint (its scheme, authority and
/// path, the text a proof sent there names as <c>htu</c>) to the most recent nonce that endpoint supplied, so a
/// nonce is used only at the endpoint that issued it.
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "a nonce issued by any
/// of them should be used only at the issuing server."
/// </summary>
/// <remarks>
/// <para>
/// Single-instance clients use this default directly. Distributed clients
/// (browser-based with shared workers, server-side agents in a cluster)
/// wire a different backing through the delegate slots on
/// <see cref="Verifiable.OAuth.Client.OAuthClientInfrastructure"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("InMemoryDpopNonceCache Count={Entries.Count}")]
public sealed class InMemoryDpopNonceCache
{
    /// <summary>
    /// The most recent nonce per endpoint, compared ordinally, safe for concurrent reads and writes.
    /// </summary>
    private ConcurrentDictionary<string, string> Entries { get; } =
        new(StringComparer.Ordinal);


    /// <summary>
    /// Returns the most recently stored nonce for <paramref name="endpoint"/>,
    /// or <see langword="null"/> when no nonce has been cached for it.
    /// </summary>
    /// <param name="endpoint">The endpoint's scheme, authority and path.</param>
    /// <returns>The nonce stored for the endpoint, or <see langword="null"/>.</returns>
    public string? Lookup(string endpoint)
    {
        ArgumentException.ThrowIfNullOrEmpty(endpoint);

        return Entries.TryGetValue(endpoint, out string? nonce) switch
        {
            true => nonce,
            _ => null
        };
    }


    /// <summary>
    /// Stores <paramref name="nonce"/> against <paramref name="endpoint"/>, so the endpoint
    /// holds the most recent nonce it supplied and that nonce alone.
    /// </summary>
    /// <param name="endpoint">The endpoint's scheme, authority and path that supplied the nonce.</param>
    /// <param name="nonce">The nonce the endpoint supplied.</param>
    public void Store(string endpoint, string nonce)
    {
        ArgumentException.ThrowIfNullOrEmpty(endpoint);
        ArgumentException.ThrowIfNullOrEmpty(nonce);
        Entries[endpoint] = nonce;
    }
}
