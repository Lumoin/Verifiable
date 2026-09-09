using System;

namespace Verifiable.Core.StatusList;

/// <summary>
/// A verified Status List Token together with the instant its resolution reports it as valid from,
/// and whether this resolution owns <see cref="Token"/>'s pooled <see cref="StatusListToken.StatusList"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ResolvedAt"/> is the reference point Section 8.3 step 4.d needs — "retrieve a fresh copy
/// if (time status was resolved + ttl &lt; current time)" — and the value
/// <see cref="StatusListValidation.ShouldRefresh"/> reads it against. A resolver that always fetches
/// fresh reports its own fetch instant; a resolver backed by a cache reports the instant the cached
/// copy was originally resolved, not the instant of this particular read.
/// </para>
/// <para>
/// <see cref="IsTokenOwned"/> declares who releases <see cref="Token"/>'s pooled Status List back to
/// the pool. A resolver that mints a fresh <see cref="StatusListToken"/> on every call (a per-call
/// fetch-and-verify, e.g. <see cref="Verifiable.OAuth.StatusList.StatusListTokenResolvers.BuildResolving"/>)
/// hands back an OWNED resolution: nothing else holds a reference to that Status List, so
/// <see cref="Dispose"/> — called by <see cref="CredentialStatusGate.CheckAsync"/> once it has read
/// the status and freshness verdicts — is the only release it gets. A caching resolver that answers
/// many calls with the same cached <see cref="StatusListToken"/> hands back a NOT-owned resolution: the
/// cache itself owns the list's lifetime and disposes it on eviction, so <see cref="Dispose"/> here is
/// a no-op and every caller of that cache keeps working off the same live carrier.
/// </para>
/// <para>
/// A carrier with reference identity, not a value: it owns a disposal decision and a mutable
/// disposal state, and an equality synthesized over that state would change what an instance equals
/// and hashes to at the moment <see cref="Dispose"/> runs. Two resolutions of the same Status List
/// Token are two distinct lifetimes and compare as such.
/// </para>
/// See <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-8.3">Token Status List, Section 8.3</see>.
/// </remarks>
public sealed class ResolvedStatusListToken: IDisposable
{
    /// <summary>The already-verified Status List Token.</summary>
    public required StatusListToken Token { get; init; }

    /// <summary>The instant this resolution was made — fetched fresh, or read from a cache at this time.</summary>
    public required DateTimeOffset ResolvedAt { get; init; }

    /// <summary>
    /// Whether this resolution owns <see cref="Token"/>'s pooled <see cref="StatusListToken.StatusList"/>
    /// and must release it on <see cref="Dispose"/>. <see langword="false"/> when a caching resolver
    /// shares <see cref="Token"/> across resolutions and disposes it itself.
    /// </summary>
    public required bool IsTokenOwned { get; init; }

    /// <summary>
    /// Whether <see cref="Dispose"/> has already run on this resolution, so a second call releases
    /// nothing.
    /// </summary>
    private bool isDisposed;

    /// <summary>
    /// Releases <see cref="Token"/>'s pooled Status List back to its pool when <see cref="IsTokenOwned"/>
    /// is <see langword="true"/>; otherwise a no-op. Idempotent — safe to call more than once.
    /// </summary>
    public void Dispose()
    {
        if(!isDisposed && IsTokenOwned)
        {
            Token.StatusList.Dispose();
        }

        isDisposed = true;
    }
}
