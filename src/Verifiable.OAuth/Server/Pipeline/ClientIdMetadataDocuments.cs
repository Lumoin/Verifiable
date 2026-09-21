using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.OAuth.Client;
using Verifiable.JCose;

namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// Performs the library's one Client ID Metadata Document attempt: the fetch-validate pipeline per
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-5">
/// draft-ietf-oauth-client-id-metadata-document-02 Section 5</see>. It performs no caching and
/// retains no state between calls — see <see cref="ResolveClientMetadataDelegate"/> for why that is
/// the calling application's concern, not this library's.
/// </summary>
public static class ClientIdMetadataDocuments
{
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
    /// Fetches, validates, and — when <see cref="ClientIdMetadataDocumentResolverOptions.ResolveJwksUri"/>
    /// is wired — discovers a <c>private_key_jwt</c> client's <c>jwks_uri</c> key set, through the
    /// guarded <see cref="OutboundFetch"/> chokepoint.
    /// </summary>
    /// <param name="clientMetadataUri">The Client Identifier URL to fetch the document from.</param>
    /// <param name="context">
    /// The per-request context; the guarded fetch reads its
    /// <see cref="Verifiable.Core.OutboundFetch.OutboundFetchPolicy"/> from here.
    /// </param>
    /// <param name="transport">
    /// The application-supplied single-hop transport the guarded fetch drives.
    /// <see cref="Verifiable.OAuth"/> takes no <c>System.Net.Http</c> dependency, so the network
    /// primitive is injected.
    /// </param>
    /// <param name="options">The resolver's byte caps, validation hooks, and key-set resolution seam.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The typed outcome and, for a <see cref="ClientIdMetadataResolutionOutcome.Resolved"/> answer,
    /// the <see cref="HttpCacheFreshness"/> the document response headers imply. Every other outcome
    /// leaves <see cref="ClientIdMetadataResolution.Freshness"/> at its default value, which reports
    /// nothing storable — storing a resolved document, and deciding what follows a failure, is the
    /// caller's own <see cref="ResolveClientMetadataDelegate"/> implementation's concern.
    /// </returns>
    public static async ValueTask<ClientIdMetadataResolution> ResolveAsync(
        Uri clientMetadataUri,
        ExchangeContext context,
        OutboundTransportDelegate transport,
        ClientIdMetadataDocumentResolverOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientMetadataUri);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(options);

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
        _ = response.Headers.TryGetValue(WellKnownHttpHeaderNames.ContentType, out string? contentType);
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
        //§8.2 example. Discover it through the wired seam (CIMD-054 "URLs contained within a Client
        //ID Metadata Document") and fold the JWKS inline so the token endpoint's client
        //authentication has "the corresponding key discovered from the client's metadata document."
        //A discovery failure is fail-closed but non-fatal to the resolution: the authorization front
        //channel proceeds, and the token endpoint rejects the client for want of a key. With no seam
        //wired, the jwks_uri is never dereferenced.
        bool hasJwksUriKeySet = metadata.TokenEndpointAuthMethod == ClientAuthenticationMethod.PrivateKeyJwt
            && metadata.Jwks is null
            && metadata.JwksUri is not null;

        ClientIdMetadataResolution resolution = new()
        {
            Outcome = ClientIdMetadataResolutionOutcome.Resolved,
            Document = metadata,
            DocumentClientId = documentClientId,
            HasJwksUriKeySet = hasJwksUriKeySet
        };

        if(hasJwksUriKeySet && options.ResolveJwksUri is not null)
        {
            resolution = await RefreshJwksAsync(resolution, options.ResolveJwksUri, context, cancellationToken)
                .ConfigureAwait(false);
        }

        //Step 9b (CIMD-060): logo prefetch through the same guarded policy; SHOULD-tier —
        //failure never fails the resolution.
        if(options.PrefetchLogo && resolution.Document!.LogoUri is not null)
        {
            (ReadOnlyMemory<byte>? logo, string? logoContentType) = await PrefetchLogoAsync(
                resolution.Document.LogoUri, options, context, transport, cancellationToken).ConfigureAwait(false);

            resolution = resolution with { PrefetchedLogo = logo, PrefetchedLogoContentType = logoContentType };
        }

        //Step 10 (CIMD-030/036/037/038/039/040/061): the document response's own freshness, per
        //RFC 9111 §5.2 — the caller's own ResolveClientMetadataDelegate implementation decides
        //whether and for how long to store this resolution.
        return resolution with { Freshness = HttpCacheFreshness.Compute(response) };
    }


    /// <summary>
    /// Resolves a <c>private_key_jwt</c> client's <c>jwks_uri</c> key set through
    /// <paramref name="resolveJwksUri"/> and returns <paramref name="resolution"/> with the key set
    /// replaced when the delegate resolves it — Step 9a of <see cref="ResolveAsync"/>, and reusable by
    /// a caller's own cache to refresh a discovered key set on ITS OWN schedule when serving a fresh
    /// document from a cache hit, per
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.2">
    /// draft-ietf-oauth-client-id-metadata-document-02 Section 8.2</see> — so a rotated key becomes
    /// visible while the enclosing document stays cached. A discovery failure is fail-closed but
    /// non-fatal: <paramref name="resolution"/> is returned unchanged rather than losing whatever key
    /// material it already carried, as is a resolution whose document names no <c>jwks_uri</c>.
    /// </summary>
    /// <param name="resolution">The resolution whose <see cref="ClientIdMetadataResolution.Document"/> is refreshed.</param>
    /// <param name="resolveJwksUri">The key-set resolution seam.</param>
    /// <param name="context">The per-request context the guarded fetch reads its policy from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<ClientIdMetadataResolution> RefreshJwksAsync(
        ClientIdMetadataResolution resolution,
        ResolveJwksUriDelegate resolveJwksUri,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resolution);
        ArgumentNullException.ThrowIfNull(resolveJwksUri);
        ArgumentNullException.ThrowIfNull(context);

        if(resolution.Document is not { JwksUri: Uri jwksUri })
        {
            return resolution;
        }

        JwksUriResolution jwksResolution = await resolveJwksUri(jwksUri, context, cancellationToken).ConfigureAwait(false);
        if(!jwksResolution.IsResolved)
        {
            _ = (Activity.Current?.AddEvent(new ActivityEvent(JwksDiscoveryFailedEventName)));

            return resolution;
        }

        return resolution with { Document = resolution.Document with { Jwks = jwksResolution.Jwks } };
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
            //A transport-level failure prefetching the logo is fail-soft: the caller treats a null result
            //as "logo unavailable", cancellation excepted above; recorded via the observability seam.
            _ = (Activity.Current?.AddEvent(new ActivityEvent(LogoPrefetchFailedEventName)));

            return (null, null);
        }

        if(!fetch.IsFetched || fetch.Response is null || fetch.Response.StatusCode != 200
            || fetch.Response.Body.Length > options.MaximumLogoBytes)
        {
            _ = (Activity.Current?.AddEvent(new ActivityEvent(LogoPrefetchFailedEventName)));

            return (null, null);
        }

        _ = fetch.Response.Headers.TryGetValue(WellKnownHttpHeaderNames.ContentType, out string? contentType);

        return (fetch.Response.Body.Memory, contentType);
    }


    /// <summary>
    /// Whether <paramref name="contentType"/> is <c>application/json</c> exactly, or any
    /// <c>application/&lt;AS-defined&gt;+json</c> structured suffix (CIMD-019); parameters (e.g.
    /// <c>;charset=utf-8</c>) are stripped before comparison.
    /// </summary>
    private static bool IsAcceptableContentType(string? contentType)
    {
        ReadOnlySpan<char> mediaType = ContentTypeReader.ReadMediaType(contentType);

        return mediaType.Equals(WellKnownMediaTypes.Application.Json, StringComparison.OrdinalIgnoreCase)
            || mediaType.EndsWith(JsonStructuredSuffix, StringComparison.OrdinalIgnoreCase);
    }
}
