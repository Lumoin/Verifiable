using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.JCose;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// The client side of <see href="https://www.rfc-editor.org/rfc/rfc9728">RFC 9728</see>: the library's one attempt at the
/// protected resource metadata document a <c>WWW-Authenticate</c> challenge points to, validated for the request the
/// challenge answered. It caches nothing and retains no state between calls.
/// </summary>
public static class ProtectedResourceMetadataDocuments
{
    /// <summary>
    /// Resolves the protected resource metadata document the <c>resource_metadata</c> parameter of a challenge named,
    /// for the request that challenge answered
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.1">RFC 9728 Section 5.1</see>: "resource_metadata:
    /// The URL of the protected resource metadata."), as seven decisions in order, each answered by one case of
    /// <see cref="ProtectedResourceMetadataResolution"/>:
    /// (1) the pointer must be the location formed from the URL the client used to make the request or the root location
    /// of that URL's own origin, or no request is sent (<see cref="ProtectedResourceMetadataPointerNotDerivedFromRequest"/>);
    /// (2) the document is fetched once through the guarded <see cref="OutboundFetch"/> under the context's
    /// <see cref="OutboundFetchPolicy"/> with an HTTP GET and the byte cap, a fetch that ends without a response answered
    /// by its shared case (<see cref="MetadataDocumentUnreachable"/>, <see cref="MetadataDocumentTooLarge"/>,
    /// <see cref="MetadataDocumentRedirectRefused"/>, <see cref="MetadataDocumentPolicyDenied"/>);
    /// (3) the status must be 200 (<see cref="MetadataDocumentNotAnswered"/>);
    /// (4) the media type must be exactly <c>application/json</c> (<see cref="MetadataDocumentUnsupportedMediaType"/>);
    /// (5) the application's parser must read a document (<see cref="ProtectedResourceMetadataUnreadable"/>);
    /// (6) the document's <c>resource</c> must satisfy an identity rule of the location the pointer was admitted at, code
    /// point for code point (<see cref="ProtectedResourceMetadataResourceMismatch"/>);
    /// (7) otherwise the document is answered with the rule it satisfied and the response's HTTP freshness
    /// (<see cref="ProtectedResourceMetadataResolved"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Decision (1). <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>: "The
    /// resource value returned MUST be identical to the protected resource's resource identifier value into which the
    /// well-known URI path suffix was inserted to create the URL used to retrieve the metadata." and "If the protected
    /// resource metadata was retrieved from a URL returned by the protected resource via the WWW-Authenticate
    /// resource_metadata parameter, then the resource value returned MUST be identical to the URL that the client used to
    /// make the request to the resource server." Both hold when the pointer is the location formed by inserting the
    /// application's suffix into that URL, the first location admitted (<see cref="ProtectedResourceMetadataPointerNotDerivedFromRequest.ExpectedPointer"/>):
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-7.3">Section 7.3</see>, "the client MUST ensure that the
    /// resource identifier URL it is using as the prefix for the metadata request exactly matches the value of the
    /// resource metadata parameter in the protected resource metadata document received by the client". The second
    /// location admitted is the root location of the request URL's own origin
    /// (<see cref="ProtectedResourceMetadataPointerNotDerivedFromRequest.RootFormPointer"/>): the same scheme, host and
    /// port, the path exactly <c>/.well-known/</c> and the suffix, no query and no fragment, the location of an identifier
    /// with no path component (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.1">Section 3.1</see>: "since
    /// the resource identifier contains no path component: GET /.well-known/oauth-protected-resource"), which the MCP
    /// authorization specification names as a location an MCP server hosts its metadata at
    /// (<see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery#protected-resource-metadata-discovery-requirements">MCP
    /// 2026-07-28, Protected Resource Metadata Discovery Requirements</see>: "At the root:
    /// <c>https://example.com/.well-known/oauth-protected-resource</c>", and "MCP clients MUST support both discovery
    /// mechanisms and use the resource metadata URL from the parsed WWW-Authenticate headers when present"); a document
    /// there at an endpoint with a path or a query can satisfy one paragraph of Section 3.3 and departs from the other,
    /// which decision (6) names. A pointer that is neither location can yield no usable document, and the library sends no
    /// request to it: <see href="https://www.rfc-editor.org/rfc/rfc9728#section-7.7">Section 7.7</see>, "Clients SHOULD
    /// take appropriate precautions against SSRF attacks". The one text form compared: the pointer is admitted when
    /// <paramref name="resourceMetadata"/>'s <see cref="Uri.OriginalString"/> equals, ordinally, the
    /// <see cref="Uri.OriginalString"/> of <paramref name="wellKnownPath"/>'s <see cref="WellKnownPath.ComputeUri"/> of
    /// <paramref name="requestUri"/>'s <see cref="Uri.OriginalString"/>, or of that <see cref="WellKnownPath.ComputeUri"/>
    /// of the origin's text. For <see cref="WellKnownPaths.OAuthProtectedResource"/> that location is formed from the URL
    /// as <see cref="Uri"/> reads it: the scheme and host in lower case, no default port, no userinfo or fragment, the
    /// path's dot segments removed and its terminating slashes trimmed, the percent-encodings of unreserved characters
    /// decoded, an internationalized host in its IDNA ASCII form, and the query kept after the inserted suffix; so a
    /// request URL spelled with a Unicode host and the same URL spelled in its IDNA form derive the same location. The
    /// origin is read by that same URI-form rule (<see cref="WellKnownPaths.OriginOf"/>), whatever suffix
    /// <paramref name="wellKnownPath"/> names: its scheme and authority, written without a trailing slash. For
    /// <see cref="WellKnownPaths.OAuthProtectedResource"/> the one rule is applied to the request URL and to its origin,
    /// the request URL's text parsed once for the origin and once for the location formed from it, two parses of one
    /// text, deterministic and equal. For a request URL with no path and no query the two locations are the same text,
    /// and one pointer is admitted. The caller passes the request URL in the form the resource names itself by, which is
    /// the form the locations are formed from.
    /// </para>
    /// <para>
    /// A fragment in the request URL is dropped from both locations, while the rules of decision (6) that compare the
    /// request URL compare its <see cref="Uri.OriginalString"/>, the fragment kept, so only a document whose
    /// <c>resource</c> carries the same fragment matches them, a <c>resource</c>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 Section 2</see> excludes: "The URI MUST NOT
    /// include a fragment component." The locations are defined for <c>http</c> and <c>https</c> request URLs; for a
    /// request URL of another scheme a location is formed that an outbound policy whose
    /// <see cref="OutboundFetchPolicy.AllowedSchemes"/> does not name that scheme refuses before any request, as
    /// <see cref="OutboundFetchPolicy.SecureDefault"/> names <c>https</c> alone.
    /// </para>
    /// <para>
    /// Decisions (2) to (5). <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.1">Section 3.1</see>: "A protected
    /// resource metadata document MUST be queried using an HTTP GET request at the previously specified URL."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">Section 3.2</see>: "A successful response MUST use
    /// the 200 OK HTTP status code and return a JSON object using the application/json content type", the media type
    /// compared without its parameters and with no <c>+json</c> structured-suffix allowance, and "any metadata parameters
    /// that are not understood MUST be ignored", which <paramref name="parseDocument"/> holds. The fetch's failures are
    /// mapped in the order <see cref="AuthorizationServerMetadataDocuments.ResolveAsync"/> maps them: the transport's
    /// failure kind, the size refusal, the refused redirect, then a fetch that ended without a terminal response. A
    /// redirect the context's <see cref="OutboundFetchPolicy"/> permits is followed by the guarded fetch, each hop
    /// checked under that policy, and the <c>MetadataLocation</c> a case then reports is the final URL the body came
    /// from; under a policy that follows no redirect, as <see cref="OutboundFetchPolicy.SecureDefault"/> follows none, a
    /// redirect is answered <see cref="MetadataDocumentRedirectRefused"/>.
    /// </para>
    /// <para>
    /// Decision (6). The document's <c>resource</c> is judged by the location the pointer was admitted at, each
    /// comparison <see cref="ProtectedResourceMetadataValidation.IsResourceMatch"/> of the document and one text:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-6">Section 6</see>, "Unicode Normalization [USA15] MUST
    /// NOT be applied at any point to either the JSON string or the string it is to be compared against." and
    /// "Comparisons between the two strings MUST be performed as a Unicode code-point-to-code-point equality comparison."
    /// The rules, in order, each named by its case of <see cref="ProtectedResourceIdentity"/> in
    /// <see cref="ProtectedResourceMetadataResolved.Identity"/>: at the location formed from the request URL, the
    /// <c>resource</c> is <paramref name="requestUri"/>'s <see cref="Uri.OriginalString"/>
    /// (<see cref="ResourceNamesTheRequestUrl"/>, both paragraphs of Section 3.3 met); at the root location of an endpoint
    /// with a path or a query, the <c>resource</c> is that same text (<see cref="ResourceNamesTheRequestUrlAtTheRootLocation"/>,
    /// the paragraph for a URL a challenge returned met); at the root location, the <c>resource</c> is the origin written
    /// without a trailing slash, or with one (<see cref="ResourceNamesTheOrigin"/>, the paragraph for the identifier the
    /// suffix was inserted into met). Both spellings of the origin are compared, each code point for code point, because
    /// both are the origin
    /// (<see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#canonical-server-uri">MCP
    /// 2026-07-28, Canonical Server URI</see>: "While both <c>https://mcp.example.com/</c> (with trailing slash) and
    /// <c>https://mcp.example.com</c> (without trailing slash) are technically valid absolute URIs according to RFC
    /// 3986"); its "SHOULD consistently use the form without the trailing slash" binds the spelling a server publishes. A
    /// <c>resource</c> satisfying no rule is <see cref="ProtectedResourceMetadataResourceMismatch"/>. The library decides
    /// nothing about which rule an application accepts: the application reads
    /// <see cref="ProtectedResourceMetadataResolved.Identity"/> with a switch expression and applies its own policy. The
    /// request URL is compared as the caller wrote it, so the caller passes the URL text it made the request to as the
    /// resource names itself: a resource writing its identifier in the URI form is matched by a caller passing that form,
    /// and a Unicode spelling of the same host is a <see cref="ProtectedResourceMetadataResourceMismatch"/>.
    /// </para>
    /// <para>
    /// A request without a challenge. The application that requests the locations of
    /// <see cref="CandidateLocationsOf"/> resolves a document it fetched from a candidate by this method with the candidate
    /// as <paramref name="resourceMetadata"/>; a candidate no challenge named is held to the same decisions and the same
    /// identity rules. The paragraph of Section 3.3 for a URL a challenge returned binds a pointer a challenge named alone;
    /// the paragraph that binds every document
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">Section 3.3</see>: "The resource value returned
    /// MUST be identical to the protected resource's resource identifier value into which the well-known URI path suffix
    /// was inserted to create the URL used to retrieve the metadata.") is the rule
    /// <see cref="ResourceNamesTheRequestUrl"/> and <see cref="ResourceNamesTheOrigin"/> name;
    /// <see cref="ResourceNamesTheRequestUrlAtTheRootLocation"/> departs from it for a candidate as for a pointer a
    /// challenge named, and an application that accepts no departure for a candidate refuses that case.
    /// </para>
    /// <para>
    /// The library's one attempt. It caches nothing and retries nothing: the application's resolver composing this call
    /// is the caching layer, as <see cref="ResolveAuthorizationServerMetadataDelegate"/> states for the authorization
    /// server's document, and <see href="https://www.rfc-editor.org/rfc/rfc9728#section-7.10">Section 7.10</see>'s "Normal
    /// HTTP caching behaviors apply" is reported through <see cref="ProtectedResourceMetadataResolved.Freshness"/>, never
    /// applied. <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.2">Section 5.2</see>: "If the client receives
    /// such a WWW-Authenticate response, it SHOULD retrieve the updated protected resource metadata and use the new
    /// metadata values obtained, after validating them as described in Section 3.3."; that re-retrieval is the
    /// application's resolver's, on each pointer a challenge names, each through this call.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2.2">Section 2.2</see>: "Consumers of the metadata MAY
    /// ignore the signed metadata if they do not support this feature."; this resolution ignores it and carries
    /// <see cref="ProtectedResourceMetadata.SignedMetadata"/> as the unverified string the document holds, and a consumer
    /// that honours it validates it as Section 3.3 states: "The recipient MUST validate that any signed metadata was
    /// signed by a key belonging to the issuer and that the signature is valid."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-7.3">Section 7.3</see>: "TLS certificate checking MUST be
    /// performed by the client as described in [RFC9525] when making a protected resource metadata request."; that check
    /// is the injected <paramref name="transport"/>'s.
    /// </para>
    /// </remarks>
    /// <param name="requestUri">The absolute URL the client used to make the request the challenge answered.</param>
    /// <param name="resourceMetadata">The absolute <c>resource_metadata</c> URL the challenge named.</param>
    /// <param name="wellKnownPath">
    /// The well-known suffix the application uses, typically <see cref="WellKnownPaths.OAuthProtectedResource"/>:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3">RFC 9728 Section 3</see>, "An OAuth 2.0 application
    /// using this specification MUST specify what well-known URI suffix it will use for this purpose."
    /// </param>
    /// <param name="context">The per-request context; the guarded fetch reads its <see cref="OutboundFetchPolicy"/> from here.</param>
    /// <param name="transport">
    /// The application-supplied single-hop transport the guarded fetch drives, which performs the TLS certificate check.
    /// </param>
    /// <param name="parseDocument">The complete-document parser supplied by the serialization adapter.</param>
    /// <param name="maximumDocumentBytes">The largest response body read, in bytes; positive.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The resolution: exactly one case of <see cref="ProtectedResourceMetadataResolution"/> carrying its evidence.</returns>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="requestUri"/> or <paramref name="resourceMetadata"/> is relative.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maximumDocumentBytes"/> is zero or negative.</exception>
    /// <exception cref="UriFormatException">
    /// <paramref name="requestUri"/>'s host has no IDNA ASCII form, so no location can be formed from it
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3987#section-3.1">RFC 3987 Section 3.1</see>: "The ToASCII operation
    /// may fail, but this would mean that the IRI cannot be resolved.").
    /// </exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> is cancelled.</exception>
    public static async ValueTask<ProtectedResourceMetadataResolution> ResolveFromChallengeAsync(
        Uri requestUri,
        Uri resourceMetadata,
        WellKnownPath wellKnownPath,
        ExchangeContext context,
        OutboundTransportDelegate transport,
        ParseProtectedResourceMetadataDelegate parseDocument,
        long maximumDocumentBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestUri);
        ArgumentNullException.ThrowIfNull(resourceMetadata);
        ArgumentNullException.ThrowIfNull(wellKnownPath);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(parseDocument);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumDocumentBytes);
        if(!requestUri.IsAbsoluteUri)
        {
            throw new ArgumentException("The request URL must be absolute.", nameof(requestUri));
        }

        if(!resourceMetadata.IsAbsoluteUri)
        {
            throw new ArgumentException("The resource metadata URL must be absolute.", nameof(resourceMetadata));
        }

        cancellationToken.ThrowIfCancellationRequested();

        //Decision (1), RFC 9728 Section 3.3 and Section 7.3, and the MCP root location (RFC 9728 Section 3.1): only the
        //location formed from the request URL and the root location of its own origin are admitted, so any other pointer
        //is refused before a request is sent (Section 7.7).
        (Uri requestLocation, Uri rootLocation, string origin) = AdmittedLocationsOf(requestUri, wellKnownPath);
        bool isAtRequestLocation = string.Equals(resourceMetadata.OriginalString, requestLocation.OriginalString, StringComparison.Ordinal);
        bool isAtRootLocation = string.Equals(resourceMetadata.OriginalString, rootLocation.OriginalString, StringComparison.Ordinal);
        if(!isAtRequestLocation && !isAtRootLocation)
        {
            return new ProtectedResourceMetadataPointerNotDerivedFromRequest
            {
                RequestUri = requestUri,
                Pointer = resourceMetadata,
                ExpectedPointer = requestLocation,
                RootFormPointer = rootLocation
            };
        }

        //Decision (2), RFC 9728 Section 3.1: "A protected resource metadata document MUST be queried using an HTTP GET
        //request at the previously specified URL.", through the guarded fetch under the context's outbound policy.
        OutboundRequest request = new()
        {
            Target = resourceMetadata,
            Method = WellKnownHttpMethods.Get,
            MaxResponseBytes = maximumDocumentBytes
        };

        OutboundFetchResult fetch = await OutboundFetch.FetchAsync(request, context, transport, cancellationToken).ConfigureAwait(false);

        if(fetch.FailureKind is Type failureKind)
        {
            return new MetadataDocumentUnreachable { FailureKind = failureKind };
        }

        if(fetch.TooLarge is OutboundResponseTooLarge tooLarge)
        {
            return new MetadataDocumentTooLarge { Evidence = tooLarge };
        }

        if(fetch.RefusedRedirect is OutboundRedirectRefusal redirect)
        {
            return new MetadataDocumentRedirectRefused
            {
                StatusCode = redirect.StatusCode,
                Location = redirect.Location
            };
        }

        if(!fetch.IsFetched || fetch.Response is null)
        {
            return new MetadataDocumentPolicyDenied { Target = fetch.FinalUri };
        }

        OutboundResponse response = fetch.Response;

        //Decision (3), RFC 9728 Section 3.2: "A successful response MUST use the 200 OK HTTP status code".
        if(response.StatusCode != 200)
        {
            return new MetadataDocumentNotAnswered { StatusCode = response.StatusCode };
        }

        //Decision (4), RFC 9728 Section 3.2: "return a JSON object using the application/json content type".
        _ = response.Headers.TryGetValue(WellKnownHttpHeaderNames.ContentType, out string? contentType);
        if(!IsAcceptableContentType(contentType))
        {
            return new MetadataDocumentUnsupportedMediaType { ContentType = contentType };
        }

        //Decision (5): the application's strict reading, which ignores members it does not understand (Section 3.2).
        if(parseDocument(response.Body.Memory) is not ProtectedResourceMetadata metadata)
        {
            return new ProtectedResourceMetadataUnreadable { MetadataLocation = fetch.FinalUri };
        }

        //Decision (6), RFC 9728 Section 3.3 and Section 6: the resource satisfies an identity rule of the location the
        //pointer was admitted at, code point for code point.
        ProtectedResourceIdentity identity = IdentityOf(metadata, requestUri, origin, isAtRequestLocation, isAtRootLocation);
        if(identity.Value is null)
        {
            return new ProtectedResourceMetadataResourceMismatch
            {
                RequestUri = requestUri,
                PublishedResource = metadata.Resource,
                MetadataLocation = fetch.FinalUri
            };
        }

        //Decision (7): the document, with the rule it satisfied and the HTTP freshness reported for the application's
        //cache (Section 7.10).
        return new ProtectedResourceMetadataResolved
        {
            Identity = identity,
            Metadata = metadata,
            MetadataLocation = fetch.FinalUri,
            Freshness = HttpCacheFreshness.Compute(response)
        };
    }


    /// <summary>
    /// The locations a protected resource metadata document for <paramref name="requestUri"/> is looked for at when no
    /// challenge named one, in the order the MCP authorization specification states
    /// (<see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery#protected-resource-metadata-discovery-requirements">MCP
    /// 2026-07-28, Protected Resource Metadata Discovery Requirements</see>: "MCP clients MUST support both discovery
    /// mechanisms and use the resource metadata URL from the parsed WWW-Authenticate headers when present; otherwise, they
    /// MUST fall back to constructing and requesting the well-known URIs in the order listed above."): first the location
    /// formed from the request URL ("At the path of the server's MCP endpoint"), then the root location of the request
    /// URL's origin ("At the root: <c>https://example.com/.well-known/oauth-protected-resource</c>"); one entry when the two
    /// are the same text, as for a request URL with no path and no query, the case the specification's diagram marks on
    /// the path-inserted request
    /// (<see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery">MCP
    /// 2026-07-28, Authorization Server Discovery</see>: "Not applicable if the MCP server is at the root").
    /// </summary>
    /// <remarks>
    /// <para>
    /// A pure derivation: it sends nothing and decides nothing. The requests, the order they are sent in, when to stop and
    /// what a failure means are the application's. A document the application fetches from a candidate is resolved by
    /// <see cref="ResolveFromChallengeAsync"/> with the candidate as the pointer, which holds it to the same decisions as
    /// a pointer a challenge named.
    /// </para>
    /// <para>
    /// Each location is formed by <paramref name="wellKnownPath"/>'s <see cref="WellKnownPath.ComputeUri"/>, the first from
    /// <paramref name="requestUri"/>'s <see cref="Uri.OriginalString"/> and the second from its origin, the scheme, host
    /// and port as that location reads them (the scheme and host in lower case, an internationalized host in its IDNA
    /// ASCII form, no default port), so the two entries are the two pointers
    /// <see cref="ResolveFromChallengeAsync"/> admits.
    /// </para>
    /// <para>
    /// A fragment in the request URL is dropped from both locations, while the rules of
    /// <see cref="ResolveFromChallengeAsync"/> that compare the request URL compare its <see cref="Uri.OriginalString"/>,
    /// the fragment kept, so only a document whose <c>resource</c> carries the same fragment matches them, a
    /// <c>resource</c> <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 Section 2</see> excludes: "The
    /// URI MUST NOT include a fragment component." The locations are defined for <c>http</c> and <c>https</c> request
    /// URLs; for a request URL of another scheme a location is formed that an outbound policy whose
    /// <see cref="OutboundFetchPolicy.AllowedSchemes"/> does not name that scheme refuses before any request, as
    /// <see cref="OutboundFetchPolicy.SecureDefault"/> names <c>https</c> alone.
    /// </para>
    /// </remarks>
    /// <param name="requestUri">The absolute URL of the request the client makes or made to the resource.</param>
    /// <param name="wellKnownPath">The well-known suffix the application uses, typically <see cref="WellKnownPaths.OAuthProtectedResource"/>.</param>
    /// <returns>The candidate locations, in the order they are to be requested.</returns>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="requestUri"/> is relative.</exception>
    /// <exception cref="UriFormatException"><paramref name="requestUri"/>'s host has no IDNA ASCII form.</exception>
    public static IReadOnlyList<Uri> CandidateLocationsOf(Uri requestUri, WellKnownPath wellKnownPath)
    {
        ArgumentNullException.ThrowIfNull(requestUri);
        ArgumentNullException.ThrowIfNull(wellKnownPath);
        if(!requestUri.IsAbsoluteUri)
        {
            throw new ArgumentException("The request URL must be absolute.", nameof(requestUri));
        }

        (Uri requestLocation, Uri rootLocation, _) = AdmittedLocationsOf(requestUri, wellKnownPath);

        return string.Equals(requestLocation.OriginalString, rootLocation.OriginalString, StringComparison.Ordinal) switch
        {
            true => [requestLocation],
            false => [requestLocation, rootLocation]
        };
    }


    /// <summary>
    /// The two locations a protected resource metadata document for <paramref name="requestUri"/> is admitted at and the
    /// origin the second is formed from: the location formed from <paramref name="requestUri"/>'s
    /// <see cref="Uri.OriginalString"/> by <paramref name="wellKnownPath"/>'s <see cref="WellKnownPath.ComputeUri"/>, and
    /// the root location formed by that <see cref="WellKnownPath.ComputeUri"/> from the origin's text
    /// (<see cref="WellKnownPaths.OriginOf"/>: the scheme and authority of the URL's URI form, without a trailing slash),
    /// the location <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.1">RFC 9728 Section 3.1</see> states for
    /// an identifier with no path component. The origin is read by the URI-form rule of
    /// <see cref="WellKnownPaths.OAuthProtectedResource"/>'s location whatever suffix <paramref name="wellKnownPath"/>
    /// names, and for that suffix the one rule forms both locations, applied to the request URL and to its origin: the
    /// request URL's text is parsed for the origin and again for the location formed from it, two parses of one text,
    /// deterministic and equal.
    /// </summary>
    /// <param name="requestUri">The absolute URL the client used or uses to make the request.</param>
    /// <param name="wellKnownPath">The well-known suffix the application uses.</param>
    /// <returns>The location formed from the request URL, the root location and the origin's text.</returns>
    private static (Uri RequestLocation, Uri RootLocation, string Origin) AdmittedLocationsOf(Uri requestUri, WellKnownPath wellKnownPath)
    {
        string origin = WellKnownPaths.OriginOf(requestUri.OriginalString);

        return (wellKnownPath.ComputeUri(requestUri.OriginalString), wellKnownPath.ComputeUri(origin), origin);
    }


    /// <summary>
    /// The identity rule <paramref name="metadata"/>'s <c>resource</c> satisfies at the location the pointer was admitted
    /// at, the rules tried in order, each comparison <see cref="ProtectedResourceMetadataValidation.IsResourceMatch"/>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-6">RFC 9728 Section 6</see>, code point for code point):
    /// at the location formed from the request URL, the request URL (<see cref="ResourceNamesTheRequestUrl"/>); at the
    /// root location alone, the request URL (<see cref="ResourceNamesTheRequestUrlAtTheRootLocation"/>); at the root
    /// location, the origin written without a trailing slash or with one (<see cref="ResourceNamesTheOrigin"/>).
    /// </summary>
    /// <param name="metadata">The document read.</param>
    /// <param name="requestUri">The URL the client used to make the request.</param>
    /// <param name="origin">The origin's text the root location was formed from, without a trailing slash.</param>
    /// <param name="isAtRequestLocation">Whether the pointer is the location formed from the request URL.</param>
    /// <param name="isAtRootLocation">Whether the pointer is the root location of the request URL's origin.</param>
    /// <returns>The rule satisfied, or <c>default</c>, holding no case, when the <c>resource</c> satisfies none.</returns>
    private static ProtectedResourceIdentity IdentityOf(
        ProtectedResourceMetadata metadata, Uri requestUri, string origin, bool isAtRequestLocation, bool isAtRootLocation)
    {
        bool isRequestUrl = ProtectedResourceMetadataValidation.IsResourceMatch(metadata, requestUri.OriginalString);
        bool isOrigin = ProtectedResourceMetadataValidation.IsResourceMatch(metadata, origin)
            || ProtectedResourceMetadataValidation.IsResourceMatch(metadata, $"{origin}/");

        return (isAtRequestLocation, isAtRootLocation, isRequestUrl, isOrigin) switch
        {
            (true, _, true, _) => new ResourceNamesTheRequestUrl { RequestUri = requestUri },
            (false, true, true, _) => new ResourceNamesTheRequestUrlAtTheRootLocation { RequestUri = requestUri, Origin = new Uri(origin) },
            (_, true, _, true) => new ResourceNamesTheOrigin { RequestUri = requestUri, Origin = new Uri(origin), PublishedResource = metadata.Resource },
            _ => default
        };
    }


    /// <summary>
    /// Whether <paramref name="contentType"/> names exactly the <c>application/json</c> media type
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC 9728 Section 3.2</see> requires ("return a
    /// JSON object using the application/json content type"): its parameters stripped, the type and subtype compared
    /// case-insensitively as <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1">RFC 9110 Section
    /// 8.3.1</see> states ("The type and subtype tokens are case-insensitive."), no <c>+json</c> structured suffix
    /// accepted.
    /// </summary>
    /// <param name="contentType">The received <c>Content-Type</c> field value, or <see langword="null"/> when absent.</param>
    /// <returns><see langword="true"/> when the media type is <c>application/json</c>.</returns>
    private static bool IsAcceptableContentType(string? contentType)
    {
        return ContentTypeReader.ReadMediaType(contentType).Equals(
            WellKnownMediaTypes.Application.Json, StringComparison.OrdinalIgnoreCase);
    }
}
