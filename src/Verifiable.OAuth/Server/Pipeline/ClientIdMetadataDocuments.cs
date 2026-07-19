using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.JCose;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// Builds the library-default <see cref="ResolveClientMetadataDelegate"/>: the Client ID
/// Metadata Document fetch-validate-cache pipeline per
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-5">
/// draft-ietf-oauth-client-id-metadata-document-02 Section 5</see>.
/// </summary>
/// <remarks>
/// Mirrors the composition idiom of <see cref="Verifiable.WebFinger.WebFingerClient.BuildResolving"/>
/// and <see cref="Verifiable.Core.Did.Methods.Web.WebDidResolver.BuildResolving"/>: the returned
/// delegate closes over the injected transport and options, and every caller-visible failure is
/// a typed <see cref="ClientIdMetadataResolutionOutcome"/> rather than a thrown exception —
/// <see cref="OperationCanceledException"/> is the only exception that propagates.
/// </remarks>
[DebuggerDisplay("ClientIdMetadataDocuments")]
public static class ClientIdMetadataDocuments
{
    private const string ContentTypeHeaderName = "Content-Type";
    private const string JsonMediaType = "application/json";
    private const string JsonStructuredSuffix = "+json";

    /// <summary>
    /// The span event name recorded on a non-fatal <c>logo_uri</c> prefetch failure
    /// (draft-ietf-oauth-client-id-metadata-document-02 Section 8.8, CIMD-060).
    /// </summary>
    private const string LogoPrefetchFailedEventName = "oauth.cimd.resolve.logo_prefetch_failed";

    /// <summary>
    /// The span event name recorded when a private_key_jwt client's <c>jwks_uri</c> could not be
    /// discovered (draft-ietf-oauth-client-id-metadata-document-02 Section 8.2, CIMD-048/050). The
    /// resolution still succeeds; the token endpoint rejects the client for want of a key.
    /// </summary>
    private const string JwksDiscoveryFailedEventName = "oauth.cimd.resolve.jwks_discovery_failed";


    /// <summary>
    /// Builds a <see cref="ResolveClientMetadataDelegate"/> that fetches, validates, and caches
    /// Client ID Metadata Documents through the guarded <see cref="OutboundFetch"/> chokepoint.
    /// </summary>
    /// <param name="transport">
    /// The application-supplied single-hop transport the guarded fetch drives.
    /// <see cref="Verifiable.OAuth"/> takes no <c>System.Net.Http</c> dependency, so the network
    /// primitive is injected.
    /// </param>
    /// <param name="options">The resolver's byte caps, cache bounds, and validation hooks.</param>
    /// <param name="timeProvider">
    /// The clock the resolver's cache staleness decisions read. Never the wall clock in tests —
    /// inject the pinned test clock.
    /// </param>
    /// <returns>A resolve delegate closing over an in-process cache keyed by client_id string.</returns>
    public static ResolveClientMetadataDelegate BuildResolving(
        OutboundTransportDelegate transport,
        ClientIdMetadataDocumentResolverOptions options,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        ConcurrentDictionary<string, CacheEntry> cache = new(StringComparer.Ordinal);

        return async (clientMetadataUri, context, cancellationToken) =>
        {
            ArgumentNullException.ThrowIfNull(clientMetadataUri);
            ArgumentNullException.ThrowIfNull(context);

            string cacheKey = clientMetadataUri.OriginalString;
            DateTimeOffset now = timeProvider.GetUtcNow();

            if(cache.TryGetValue(cacheKey, out CacheEntry? cached) && cached.FreshUntil > now)
            {
                return cached.Resolution;
            }

            //Step 1 (CIMD-001/002/004/005/006/007/011): Section 3 validation on the raw
            //candidate string — System.Uri normalization would erase exactly the distinctions
            //Section 3 depends on. A MUST-tier defect never contacts the network; a SHOULD/NOT-
            //RECOMMENDED-tier advisory does the same only when the deployment opts in.
            ClientIdentifierUrlValidationResult urlValidation =
                ClientIdentifierUrl.Validate(clientMetadataUri.OriginalString);
            bool hasAdvisory = urlValidation.HasQueryComponent || urlValidation.IsRootPath;
            if(!urlValidation.IsValid || (options.TreatAdvisoriesAsErrors && hasAdvisory))
            {
                return new ClientIdMetadataResolution
                {
                    Outcome = ClientIdMetadataResolutionOutcome.InvalidDocument,
                    Defect = "The Client Identifier URL fails Section 3 validation."
                };
            }

            OutboundRequest request = new()
            {
                Target = clientMetadataUri,
                Method = "GET",
                MaxResponseBytes = options.MaximumDocumentBytes
            };

            OutboundFetchResult fetch;
            try
            {
                //Fully qualified: within Verifiable.* the bare name binds to the OutboundFetch
                //namespace, not the static class of the same leaf name.
                fetch = await Verifiable.Core.OutboundFetch.OutboundFetch.FetchAsync(
                    request, context, transport, cancellationToken).ConfigureAwait(false);
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return new ClientIdMetadataResolution
                {
                    Outcome = ClientIdMetadataResolutionOutcome.FetchFailed,
                    Defect = "Transport failure while fetching the Client ID Metadata Document."
                };
            }

            //Step 2 (CIMD-001/034/054): a policy denial (special-use IP, disallowed scheme,
            //host list) is distinct from an unfollowed or excessive redirect chain — both are
            //non-fetched, but only the former is a policy denial for the caller's diagnostics.
            if(!fetch.IsFetched || fetch.Response is null)
            {
                return new ClientIdMetadataResolution
                {
                    Outcome = fetch.Outcome == OutboundFetchOutcome.DeniedByPolicy
                        ? ClientIdMetadataResolutionOutcome.PolicyDenied
                        : ClientIdMetadataResolutionOutcome.FetchFailed,
                    Defect = fetch.DenyReason
                };
            }

            OutboundResponse response = fetch.Response;

            //Step 3 (CIMD-018/032/033): only exactly 200 is a successful fetch.
            if(response.StatusCode != 200)
            {
                return new ClientIdMetadataResolution
                {
                    Outcome = ClientIdMetadataResolutionOutcome.FetchFailed,
                    Defect = $"The document fetch returned HTTP status {response.StatusCode}."
                };
            }

            //Step 4 (CIMD-019): application/json or an application/<AS-defined>+json suffix.
            response.TryGetHeader(ContentTypeHeaderName, out string? contentType);
            if(!IsAcceptableContentType(contentType))
            {
                return new ClientIdMetadataResolution
                {
                    Outcome = ClientIdMetadataResolutionOutcome.InvalidDocument,
                    Defect = $"The document content type '{contentType}' is not application/json or a +json suffix."
                };
            }

            //Step 5 (CIMD-059): the authoritative post-read size check — MaxResponseBytes above
            //is only a transport hint a hostile or non-conforming transport may not honor.
            if(response.Body.Length > options.MaximumDocumentBytes)
            {
                return new ClientIdMetadataResolution
                {
                    Outcome = ClientIdMetadataResolutionOutcome.FetchFailed,
                    Defect = "The document exceeds the configured maximum size."
                };
            }

            //Step 6: library-owned span parsing (CIMD-013/021/022/023/058 conformance checks).
            ClientIdMetadataDocumentReadResult parsed = ClientIdMetadataDocumentReader.Parse(response.Body.Span);
            if(parsed.HasDefects || parsed.ClientId is null || parsed.Metadata is null)
            {
                return new ClientIdMetadataResolution
                {
                    Outcome = ClientIdMetadataResolutionOutcome.InvalidDocument,
                    DocumentClientId = parsed.ClientId,
                    Defect = $"The document has conformance defects: {parsed.Defects}."
                };
            }

            string documentClientId = parsed.ClientId;
            ClientMetadata metadata = parsed.Metadata;

            //Step 7 (CIMD-013/014/015/016): the document's client_id MUST ordinal-equal the URL
            //used to fetch it — mirrors AuthorizationServerMetadataValidation.IsIssuerMatch's
            //OriginalString-ordinal pattern.
            if(!ClientIdentifierUrl.IsMatch(documentClientId, clientMetadataUri.OriginalString))
            {
                return new ClientIdMetadataResolution
                {
                    Outcome = ClientIdMetadataResolutionOutcome.InvalidDocument,
                    DocumentClientId = documentClientId,
                    Defect = "The document's client_id does not match the URL it was fetched from."
                };
            }

            //Step 8 (CIMD-020): an application-supplied additional restriction.
            if(options.AdditionalDocumentValidation is not null
                && !await options.AdditionalDocumentValidation(
                    metadata, clientMetadataUri, context, cancellationToken).ConfigureAwait(false))
            {
                return new ClientIdMetadataResolution
                {
                    Outcome = ClientIdMetadataResolutionOutcome.InvalidDocument,
                    DocumentClientId = documentClientId,
                    Defect = "The document was rejected by an application-supplied additional restriction."
                };
            }

            //Step 9a (CIMD-048/050, §8.2): a confidential client that advertises private_key_jwt with a
            //jwks_uri instead of an inline jwks publishes its key material at that URL — the spec's own
            //§8.2 example. Discover it through the SAME guarded fetch (CIMD-054 "URLs contained within a
            //Client ID Metadata Document") and fold the JWKS inline so the token endpoint's client
            //authentication has "the corresponding key discovered from the client's metadata document."
            //A discovery failure is fail-closed but non-fatal to the resolution: the authorization front
            //channel proceeds, and the token endpoint rejects the client for want of a key.
            if(metadata.TokenEndpointAuthMethod == ClientAuthenticationMethod.PrivateKeyJwt
                && metadata.Jwks is null
                && metadata.JwksUri is not null)
            {
                string? discoveredJwks = await ResolveJwksUriAsync(
                    metadata.JwksUri, options, context, transport, cancellationToken).ConfigureAwait(false);
                if(discoveredJwks is not null)
                {
                    metadata = metadata with { Jwks = discoveredJwks };
                }
            }

            //Step 9b (CIMD-060): logo prefetch through the same guarded policy; SHOULD-tier —
            //failure never fails the resolution.
            ReadOnlyMemory<byte>? logo = null;
            string? logoContentType = null;
            if(options.PrefetchLogo && metadata.LogoUri is not null)
            {
                (logo, logoContentType) = await PrefetchLogoAsync(
                    metadata.LogoUri, options, context, transport, cancellationToken).ConfigureAwait(false);
            }

            ClientIdMetadataResolution resolution = new()
            {
                Outcome = ClientIdMetadataResolutionOutcome.Resolved,
                Document = metadata,
                DocumentClientId = documentClientId,
                PrefetchedLogo = logo,
                PrefetchedLogoContentType = logoContentType
            };

            //Step 10 (CIMD-030/036/037/038/039/040/061): only a Resolved outcome is cached, and
            //only when the response is storable and not must-revalidate — a Cache-Control: no-store
            //response is never cached, and a no-cache response is never served fresh (the options
            //lower bound must not manufacture freshness the headers denied, per RFC 9111 §5.2.2.4).
            HttpCacheFreshness freshness = HttpCacheFreshness.Compute(response);
            TimeSpan lifetime = freshness.IsStorable && !freshness.MustRevalidate
                ? ClampLifetime(freshness.FreshnessLifetime, options)
                : TimeSpan.Zero;

            if(lifetime > TimeSpan.Zero)
            {
                cache[cacheKey] = new CacheEntry(resolution, now + lifetime);
            }
            else
            {
                cache.TryRemove(cacheKey, out _);
            }

            return resolution;
        };
    }


    //Fetches logo_uri through the same guarded policy path (CIMD-054 "URLs contained within"
    //applies to it exactly as to the document URL itself); every failure mode collapses to
    //(null, null) rather than a thrown exception, since a prefetch failure is SHOULD-tier and
    //must never fail the surrounding document resolution.
    private static async ValueTask<(ReadOnlyMemory<byte>? Logo, string? ContentType)> PrefetchLogoAsync(
        Uri logoUri,
        ClientIdMetadataDocumentResolverOptions options,
        ExchangeContext context,
        OutboundTransportDelegate transport,
        CancellationToken cancellationToken)
    {
        OutboundRequest request = new()
        {
            Target = logoUri,
            Method = "GET",
            MaxResponseBytes = options.MaximumLogoBytes
        };

        OutboundFetchResult fetch;
        try
        {
            fetch = await Verifiable.Core.OutboundFetch.OutboundFetch.FetchAsync(
                request, context, transport, cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch
        {
            Activity.Current?.AddEvent(new ActivityEvent(LogoPrefetchFailedEventName));

            return (null, null);
        }

        if(!fetch.IsFetched || fetch.Response is null || fetch.Response.StatusCode != 200
            || fetch.Response.Body.Length > options.MaximumLogoBytes)
        {
            Activity.Current?.AddEvent(new ActivityEvent(LogoPrefetchFailedEventName));

            return (null, null);
        }

        fetch.Response.TryGetHeader(ContentTypeHeaderName, out string? contentType);

        return (fetch.Response.Body.Memory, contentType);
    }


    //Discovers a private_key_jwt client's JWKS from its jwks_uri through the same guarded policy path
    //(CIMD-054 applies to URLs contained within the document exactly as to the document URL); returns
    //the JWKS JSON text on a 200 JSON response carrying a "keys" member, or null on any failure. Every
    //failure mode collapses to null rather than a thrown exception — a discovery failure is fail-closed
    //but non-fatal to the surrounding resolution.
    private static async ValueTask<string?> ResolveJwksUriAsync(
        Uri jwksUri,
        ClientIdMetadataDocumentResolverOptions options,
        ExchangeContext context,
        OutboundTransportDelegate transport,
        CancellationToken cancellationToken)
    {
        OutboundRequest request = new()
        {
            Target = jwksUri,
            Method = "GET",
            MaxResponseBytes = options.MaximumDocumentBytes
        };

        OutboundFetchResult fetch;
        try
        {
            fetch = await Verifiable.Core.OutboundFetch.OutboundFetch.FetchAsync(
                request, context, transport, cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch
        {
            Activity.Current?.AddEvent(new ActivityEvent(JwksDiscoveryFailedEventName));

            return null;
        }

        if(!fetch.IsFetched || fetch.Response is null || fetch.Response.StatusCode != 200
            || fetch.Response.Body.Length > options.MaximumDocumentBytes)
        {
            Activity.Current?.AddEvent(new ActivityEvent(JwksDiscoveryFailedEventName));

            return null;
        }

        OutboundResponse jwksResponse = fetch.Response;
        jwksResponse.TryGetHeader(ContentTypeHeaderName, out string? contentType);
        if(!IsAcceptableContentType(contentType)
            || JwkJsonReader.IndexOfKey(jwksResponse.Body.Span, WellKnownJwkMemberNames.KeysUtf8) < 0)
        {
            Activity.Current?.AddEvent(new ActivityEvent(JwksDiscoveryFailedEventName));

            return null;
        }

        return Encoding.UTF8.GetString(jwksResponse.Body.Span);
    }


    private static TimeSpan ClampLifetime(TimeSpan lifetime, ClientIdMetadataDocumentResolverOptions options)
    {
        if(options.MinimumCacheLifetime is TimeSpan minimum && lifetime < minimum)
        {
            lifetime = minimum;
        }

        if(options.MaximumCacheLifetime is TimeSpan maximum && lifetime > maximum)
        {
            lifetime = maximum;
        }

        return lifetime;
    }


    //application/json exactly, or any application/<AS-defined>+json structured suffix
    //(CIMD-019); parameters (e.g. ;charset=utf-8) are stripped before comparison.
    private static bool IsAcceptableContentType(string? contentType)
    {
        if(string.IsNullOrWhiteSpace(contentType))
        {
            return false;
        }

        ReadOnlySpan<char> value = contentType.AsSpan().Trim();
        int parameterDelimiter = value.IndexOf(';');
        ReadOnlySpan<char> mediaType = (parameterDelimiter >= 0 ? value[..parameterDelimiter] : value).Trim();

        return mediaType.Equals(JsonMediaType, StringComparison.OrdinalIgnoreCase)
            || mediaType.EndsWith(JsonStructuredSuffix, StringComparison.OrdinalIgnoreCase);
    }


    private sealed record CacheEntry(ClientIdMetadataResolution Resolution, DateTimeOffset FreshUntil);
}
