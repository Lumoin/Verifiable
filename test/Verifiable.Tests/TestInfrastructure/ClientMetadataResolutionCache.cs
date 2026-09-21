using System.Collections.Concurrent;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A reference application-side cache over the library's two stateless attempts,
/// <see cref="ClientIdMetadataDocuments.ResolveAsync"/> and <see cref="JwksUriResolver.ResolveAsync"/>:
/// a process dictionary per attempt, keyed by URL, storing only what the reported
/// <see cref="HttpCacheFreshness"/> allows, serving a fresh entry without dialling, re-attempting once
/// stale, and never serving a stale entry after a failed re-attempt
/// (<see href="https://www.rfc-editor.org/rfc/rfc9111#section-4.2.4">RFC 9111 §4.2.4</see>). A
/// discovered key set is refreshed on ITS OWN schedule via
/// <see cref="ClientIdMetadataDocuments.RefreshJwksAsync"/> whenever a document cache hit's
/// <see cref="ClientIdMetadataResolution.HasJwksUriKeySet"/> is set, so a rotated key becomes visible
/// while the document itself stays cached.
/// </summary>
/// <remarks>
/// The two process dictionaries this cache keeps are what an application swaps for whatever store it
/// already runs — a distributed cache, a grain, a database row — and its own retry-floor interval for
/// its own hold-off policy after a <c>jwks_uri</c> fetch brings back nothing cacheable: the key-set
/// attempt is consulted on every document resolution whose key set was discovered, including a cached
/// document hit, so without a floor a failing or uncacheable <c>jwks_uri</c> would take one outbound
/// request per authorization request that reaches it.
/// </remarks>
internal sealed class ClientMetadataResolutionCache
{
    /// <summary>The single-hop transport both attempts' guarded fetch drives.</summary>
    private OutboundTransportDelegate Transport { get; }

    /// <summary>The document attempt's byte caps, validation hooks, and key-set resolution seam.</summary>
    private ClientIdMetadataDocumentResolverOptions DocumentOptions { get; }

    /// <summary>The key-set attempt's byte cap.</summary>
    private JwksUriResolverOptions JwksOptions { get; }

    /// <summary>The clock this cache's staleness decisions read.</summary>
    private TimeProvider Clock { get; }

    /// <summary>The lower bound this cache clamps a document's header-derived lifetime to.</summary>
    private TimeSpan? DocumentMinimumCacheLifetime { get; }

    /// <summary>The upper bound this cache clamps a document's header-derived lifetime to.</summary>
    private TimeSpan? DocumentMaximumCacheLifetime { get; }

    /// <summary>The lower bound this cache clamps a key set's OWN header-derived lifetime to.</summary>
    private TimeSpan? JwksMinimumCacheLifetime { get; }

    /// <summary>The upper bound this cache clamps a key set's OWN header-derived lifetime to.</summary>
    private TimeSpan? JwksMaximumCacheLifetime { get; }

    /// <summary>
    /// The shortest interval between two dials of the same <c>jwks_uri</c> after an attempt that
    /// brought back nothing cacheable.
    /// </summary>
    private TimeSpan JwksRetryFloor { get; }

    /// <summary>The document store, keyed by the Client Identifier URL's <see cref="Uri.OriginalString"/>.</summary>
    private ConcurrentDictionary<string, DocumentCacheEntry> Documents { get; } = new(StringComparer.Ordinal);

    /// <summary>The key-set store, keyed by the <c>jwks_uri</c>'s <see cref="Uri.OriginalString"/>.</summary>
    private ConcurrentDictionary<string, JwksCacheEntry> JwksSets { get; } = new(StringComparer.Ordinal);


    /// <summary>
    /// Creates a cache over the two library attempts.
    /// </summary>
    /// <param name="transport">The single-hop transport both attempts' guarded fetch drives.</param>
    /// <param name="documentOptions">
    /// The document attempt's byte caps and validation hooks; its
    /// <see cref="ClientIdMetadataDocumentResolverOptions.ResolveJwksUri"/> is overridden to this
    /// cache's own <see cref="ResolveJwksAsync"/> regardless of what it carries, so the key-set side of
    /// this cache is always the one consulted.
    /// </param>
    /// <param name="jwksOptions">The key-set attempt's byte cap.</param>
    /// <param name="timeProvider">The clock cache staleness decisions read. Never the wall clock in tests.</param>
    /// <param name="documentMinimumCacheLifetime">The lower bound this cache clamps a document's header-derived lifetime to.</param>
    /// <param name="documentMaximumCacheLifetime">The upper bound this cache clamps a document's header-derived lifetime to.</param>
    /// <param name="jwksMinimumCacheLifetime">The lower bound this cache clamps a key set's OWN header-derived lifetime to.</param>
    /// <param name="jwksMaximumCacheLifetime">The upper bound this cache clamps a key set's OWN header-derived lifetime to.</param>
    /// <param name="jwksRetryFloor">
    /// The shortest interval between two dials of the same <c>jwks_uri</c> after an attempt that
    /// brought back nothing cacheable. Defaults to 30 seconds.
    /// </param>
    public ClientMetadataResolutionCache(
        OutboundTransportDelegate transport,
        ClientIdMetadataDocumentResolverOptions documentOptions,
        JwksUriResolverOptions jwksOptions,
        TimeProvider timeProvider,
        TimeSpan? documentMinimumCacheLifetime = null,
        TimeSpan? documentMaximumCacheLifetime = null,
        TimeSpan? jwksMinimumCacheLifetime = null,
        TimeSpan? jwksMaximumCacheLifetime = null,
        TimeSpan? jwksRetryFloor = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(documentOptions);
        ArgumentNullException.ThrowIfNull(jwksOptions);
        ArgumentNullException.ThrowIfNull(timeProvider);

        Transport = transport;
        DocumentOptions = documentOptions with { ResolveJwksUri = ResolveJwksAsync };
        JwksOptions = jwksOptions;
        Clock = timeProvider;
        DocumentMinimumCacheLifetime = documentMinimumCacheLifetime;
        DocumentMaximumCacheLifetime = documentMaximumCacheLifetime;
        JwksMinimumCacheLifetime = jwksMinimumCacheLifetime;
        JwksMaximumCacheLifetime = jwksMaximumCacheLifetime;
        JwksRetryFloor = jwksRetryFloor ?? TimeSpan.FromSeconds(30);
    }


    /// <summary>
    /// The <see cref="ResolveClientMetadataDelegate"/>-shaped entry point over this cache's document
    /// store: a fresh entry is served without dialling; a cache hit whose key set was discovered from
    /// a <c>jwks_uri</c> is refreshed through <see cref="ClientIdMetadataDocuments.RefreshJwksAsync"/>
    /// on that key set's own schedule before being returned.
    /// </summary>
    public async ValueTask<ClientIdMetadataResolution> ResolveDocumentAsync(
        Uri clientMetadataUri, ExchangeContext context, CancellationToken cancellationToken)
    {
        string cacheKey = clientMetadataUri.OriginalString;
        DateTimeOffset now = Clock.GetUtcNow();

        if(Documents.TryGetValue(cacheKey, out DocumentCacheEntry? cached) && cached.FreshUntil > now)
        {
            return cached.Resolution.HasJwksUriKeySet
                ? await ClientIdMetadataDocuments.RefreshJwksAsync(
                    cached.Resolution, ResolveJwksAsync, context, cancellationToken).ConfigureAwait(false)
                : cached.Resolution;
        }

        ClientIdMetadataResolution resolution = await ClientIdMetadataDocuments.ResolveAsync(
            clientMetadataUri, context, Transport, DocumentOptions, cancellationToken).ConfigureAwait(false);

        TimeSpan lifetime = resolution.IsResolved && resolution.Freshness.IsStorable && !resolution.Freshness.MustRevalidate
            ? resolution.Freshness.Clamp(DocumentMinimumCacheLifetime, DocumentMaximumCacheLifetime)
            : TimeSpan.Zero;

        if(lifetime > TimeSpan.Zero)
        {
            Documents[cacheKey] = new DocumentCacheEntry(resolution, now + lifetime);
        }
        else
        {
            _ = Documents.TryRemove(cacheKey, out _);
        }

        return resolution;
    }


    /// <summary>
    /// The <see cref="ResolveJwksUriDelegate"/>-shaped entry point over this cache's key-set store: a
    /// fresh entry is served without dialling; an attempt that brings back nothing cacheable is held
    /// off for this cache's own retry-floor interval rather than dialled again on the next resolution;
    /// a failed re-attempt drops whatever was cached rather than keep answering with it (RFC 9111
    /// §4.2.4).
    /// </summary>
    public async ValueTask<JwksUriResolution> ResolveJwksAsync(
        Uri jwksUri, ExchangeContext context, CancellationToken cancellationToken)
    {
        string cacheKey = jwksUri.OriginalString;
        DateTimeOffset now = Clock.GetUtcNow();

        if(JwksSets.TryGetValue(cacheKey, out JwksCacheEntry? cached) && cached.FreshUntil > now)
        {
            return cached.Resolution;
        }

        JwksUriResolution resolution = await JwksUriResolver.ResolveAsync(
            jwksUri, context, Transport, JwksOptions, cancellationToken).ConfigureAwait(false);

        TimeSpan lifetime = resolution.IsResolved && resolution.Freshness.IsStorable && !resolution.Freshness.MustRevalidate
            ? resolution.Freshness.Clamp(JwksMinimumCacheLifetime, JwksMaximumCacheLifetime)
            : TimeSpan.Zero;

        if(lifetime > TimeSpan.Zero)
        {
            JwksSets[cacheKey] = new JwksCacheEntry(resolution, now + lifetime);
        }
        else if(resolution.IsResolved)
        {
            //A key set that arrived but carries headers forbidding its storage is outside the retry
            //floor and is fetched again on the next resolution, which is what those headers ask for.
            _ = JwksSets.TryRemove(cacheKey, out _);
        }
        else
        {
            //RFC 9111 §4.2.4: "A cache MUST NOT generate a stale response unless it is disconnected
            //or doing so is explicitly permitted." A failed re-attempt replaces whatever was cached
            //with a floored refusal rather than keep answering with the stale entry.
            JwksSets[cacheKey] = new JwksCacheEntry(
                new JwksUriResolution
                {
                    Outcome = JwksUriResolutionOutcome.NotRefreshed,
                    Defect = "The previous attempt produced nothing cacheable and the retry floor has not elapsed."
                },
                now + JwksRetryFloor);
        }

        return resolution;
    }


    /// <summary>A cached document resolution and when it goes stale.</summary>
    /// <param name="Resolution">The cached, previously resolved outcome.</param>
    /// <param name="FreshUntil">The instant this entry stops being served without re-fetching.</param>
    private sealed record DocumentCacheEntry(ClientIdMetadataResolution Resolution, DateTimeOffset FreshUntil);


    /// <summary>A cached key-set resolution and when it goes stale.</summary>
    /// <param name="Resolution">The cached, previously resolved outcome.</param>
    /// <param name="FreshUntil">The instant this entry stops being served without re-fetching.</param>
    private sealed record JwksCacheEntry(JwksUriResolution Resolution, DateTimeOffset FreshUntil);
}
