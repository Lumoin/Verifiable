using System.Collections.Concurrent;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A reference application-side cache over the library's stateless attempt,
/// <see cref="AuthorizationServerMetadataDocuments.ResolveAsync"/>: a process dictionary keyed by
/// issuer, storing only what the reported <see cref="HttpCacheFreshness"/> allows, serving a fresh
/// entry without dialling, and re-attempting once stale.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ResolveAuthorizationServerMetadataDelegate"/> reports a typed
/// <see cref="AuthorizationServerMetadataResolution"/> outcome, the same contract
/// <see cref="ResolveClientMetadataDelegate"/> and
/// <see cref="Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate"/> state for their own
/// resolutions. A stale entry whose re-attempt fails is therefore DROPPED rather than served — RFC
/// 9111 §4.2.4 forbids generating a stale response without permission neither the client nor the
/// origin granted here — and the non-resolved resolution is returned as a value, letting the caller
/// inspect <see cref="AuthorizationServerMetadataResolution.Outcome"/> without catching an exception.
/// This is what an application starts from, swapping the store for whatever its own call sites
/// expect (a distributed cache, a grain).
/// </para>
/// </remarks>
internal sealed class AuthorizationServerMetadataResolutionCache
{
    /// <summary>The single-hop transport the attempt's guarded fetch drives.</summary>
    private OutboundTransportDelegate Transport { get; }

    /// <summary>The well-known suffix this cache resolves the issuer's metadata URL through.</summary>
    private WellKnownPath WellKnownPath { get; }

    /// <summary>The attempt's byte cap.</summary>
    private AuthorizationServerMetadataResolverOptions Options { get; }

    /// <summary>The clock this cache's staleness decisions read.</summary>
    private TimeProvider Clock { get; }

    /// <summary>The lower bound this cache clamps a document's header-derived lifetime to.</summary>
    private TimeSpan? MinimumCacheLifetime { get; }

    /// <summary>The upper bound this cache clamps a document's header-derived lifetime to.</summary>
    private TimeSpan? MaximumCacheLifetime { get; }

    /// <summary>The document store, keyed by the issuer's <see cref="Uri.OriginalString"/>.</summary>
    private ConcurrentDictionary<string, CacheEntry> Documents { get; } = new(StringComparer.Ordinal);


    /// <summary>
    /// Creates a cache over the library's attempt.
    /// </summary>
    /// <param name="transport">The single-hop transport the attempt's guarded fetch drives.</param>
    /// <param name="wellKnownPath">The well-known suffix this cache resolves the issuer's metadata URL through.</param>
    /// <param name="options">The attempt's byte cap.</param>
    /// <param name="timeProvider">The clock this cache's staleness decisions read. Never the wall clock in tests.</param>
    /// <param name="minimumCacheLifetime">The lower bound this cache clamps a document's header-derived lifetime to.</param>
    /// <param name="maximumCacheLifetime">The upper bound this cache clamps a document's header-derived lifetime to.</param>
    public AuthorizationServerMetadataResolutionCache(
        OutboundTransportDelegate transport,
        WellKnownPath wellKnownPath,
        AuthorizationServerMetadataResolverOptions options,
        TimeProvider timeProvider,
        TimeSpan? minimumCacheLifetime = null,
        TimeSpan? maximumCacheLifetime = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(wellKnownPath);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        Transport = transport;
        WellKnownPath = wellKnownPath;
        Options = options;
        Clock = timeProvider;
        MinimumCacheLifetime = minimumCacheLifetime;
        MaximumCacheLifetime = maximumCacheLifetime;
    }


    /// <summary>
    /// The <see cref="ResolveAuthorizationServerMetadataDelegate"/>-shaped entry point over this
    /// cache's store: a fresh entry is served without dialling; a stale or absent entry re-attempts
    /// and, on success, is cached for the freshness the response headers imply. A non-resolved
    /// re-attempt drops the stale entry and returns the non-resolved resolution — RFC 9111 §4.2.4
    /// forbids generating a stale response without permission neither the client nor the origin
    /// granted here, so the caller never observes the dropped record through this call.
    /// </summary>
    public async ValueTask<AuthorizationServerMetadataResolution> ResolveAsync(
        Uri issuer, ExchangeContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(context);

        string cacheKey = issuer.OriginalString;
        DateTimeOffset now = Clock.GetUtcNow();

        if(Documents.TryGetValue(cacheKey, out CacheEntry? cached) && cached.FreshUntil > now)
        {
            return new AuthorizationServerMetadataResolution
            {
                Outcome = AuthorizationServerMetadataResolutionOutcome.Resolved,
                Metadata = cached.Metadata
            };
        }

        AuthorizationServerMetadataResolution resolution = await AuthorizationServerMetadataDocuments.ResolveAsync(
            issuer, WellKnownPath, context, Transport, Options, cancellationToken).ConfigureAwait(false);

        if(!resolution.IsResolved)
        {
            _ = Documents.TryRemove(cacheKey, out _);

            return resolution;
        }

        TimeSpan lifetime = resolution.Freshness.IsStorable && !resolution.Freshness.MustRevalidate
            ? resolution.Freshness.Clamp(MinimumCacheLifetime, MaximumCacheLifetime)
            : TimeSpan.Zero;

        if(lifetime > TimeSpan.Zero)
        {
            Documents[cacheKey] = new CacheEntry(resolution.Metadata!, now + lifetime);
        }
        else
        {
            _ = Documents.TryRemove(cacheKey, out _);
        }

        return resolution;
    }


    /// <summary>A cached document and when it goes stale.</summary>
    /// <param name="Metadata">The cached, previously resolved metadata.</param>
    /// <param name="FreshUntil">The instant this entry stops being served without re-fetching.</param>
    private sealed record CacheEntry(AuthorizationServerMetadata Metadata, DateTimeOffset FreshUntil);
}
