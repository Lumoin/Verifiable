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
    /// (1) the pointer must be the location formed from the URL the client used to make the request, or no request is
    /// sent (<see cref="ProtectedResourceMetadataPointerNotDerivedFromRequest"/>);
    /// (2) the document is fetched once through the guarded <see cref="OutboundFetch"/> under the context's
    /// <see cref="OutboundFetchPolicy"/> with an HTTP GET and the byte cap, a fetch that ends without a response answered
    /// by its shared case (<see cref="MetadataDocumentUnreachable"/>, <see cref="MetadataDocumentTooLarge"/>,
    /// <see cref="MetadataDocumentRedirectRefused"/>, <see cref="MetadataDocumentPolicyDenied"/>);
    /// (3) the status must be 200 (<see cref="MetadataDocumentNotAnswered"/>);
    /// (4) the media type must be exactly <c>application/json</c> (<see cref="MetadataDocumentUnsupportedMediaType"/>);
    /// (5) the application's parser must read a document (<see cref="ProtectedResourceMetadataUnreadable"/>);
    /// (6) the document's <c>resource</c> must be the URL the client used, code point for code point
    /// (<see cref="ProtectedResourceMetadataResourceMismatch"/>);
    /// (7) otherwise the document is answered with the response's HTTP freshness
    /// (<see cref="ProtectedResourceMetadataResolved"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Decision (1). <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>: "The
    /// resource value returned MUST be identical to the protected resource's resource identifier value into which the
    /// well-known URI path suffix was inserted to create the URL used to retrieve the metadata." and "If the protected
    /// resource metadata was retrieved from a URL returned by the protected resource via the WWW-Authenticate
    /// resource_metadata parameter, then the resource value returned MUST be identical to the URL that the client used to
    /// make the request to the resource server." Both hold only when the pointer is the location formed by inserting the
    /// application's suffix into that URL, so a pointer that is not that location can yield no usable document, and the
    /// library sends no request to it: <see href="https://www.rfc-editor.org/rfc/rfc9728#section-7.3">Section 7.3</see>,
    /// "the client MUST ensure that the resource identifier URL it is using as the prefix for the metadata request exactly
    /// matches the value of the resource metadata parameter in the protected resource metadata document received by the
    /// client", and <see href="https://www.rfc-editor.org/rfc/rfc9728#section-7.7">Section 7.7</see>, "Clients SHOULD take
    /// appropriate precautions against SSRF attacks". The one text form compared: the pointer is derived when
    /// <paramref name="resourceMetadata"/>'s <see cref="Uri.OriginalString"/> equals, ordinally, the
    /// <see cref="Uri.OriginalString"/> of <paramref name="wellKnownPath"/>'s <see cref="WellKnownPath.ComputeUri"/> of
    /// <paramref name="requestUri"/>'s <see cref="Uri.OriginalString"/>. For
    /// <see cref="WellKnownPaths.OAuthProtectedResource"/> that location is formed from the URL as <see cref="Uri"/> reads
    /// it: the scheme and host in lower case, no default port, no userinfo or fragment, the path's dot segments removed
    /// and its terminating slashes trimmed, the percent-encodings of unreserved characters decoded, an internationalized
    /// host in its IDNA ASCII form, and the query kept after the inserted suffix; so a request URL spelled with a Unicode
    /// host and the same URL spelled in its IDNA form derive the same location. The caller passes the request URL in the
    /// form the resource names itself by, which is the form the location is formed from.
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
    /// Decision (6). <see cref="ProtectedResourceMetadataValidation.IsResourceMatch"/> of the document and
    /// <paramref name="requestUri"/>'s <see cref="Uri.OriginalString"/>:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-6">Section 6</see>, "Unicode Normalization [USA15] MUST
    /// NOT be applied at any point to either the JSON string or the string it is to be compared against." and
    /// "Comparisons between the two strings MUST be performed as a Unicode code-point-to-code-point equality comparison."
    /// The request URL is compared as the caller wrote it, so the caller passes the URL text it made the request to as
    /// the resource names itself: a resource writing its identifier in the URI form is matched by a caller passing that
    /// form, and a Unicode spelling of the same host is a <see cref="ProtectedResourceMetadataResourceMismatch"/>.
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

        //Decision (1), RFC 9728 Section 3.3 and Section 7.3: only the location formed from the request URL can yield a
        //usable document, so any other pointer is refused before a request is sent (Section 7.7).
        Uri expectedPointer = wellKnownPath.ComputeUri(requestUri.OriginalString);
        if(!string.Equals(resourceMetadata.OriginalString, expectedPointer.OriginalString, StringComparison.Ordinal))
        {
            return new ProtectedResourceMetadataPointerNotDerivedFromRequest
            {
                RequestUri = requestUri,
                Pointer = resourceMetadata,
                ExpectedPointer = expectedPointer
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

        //Decision (6), RFC 9728 Section 3.3 and Section 6: the resource is the request URL code point for code point.
        if(!ProtectedResourceMetadataValidation.IsResourceMatch(metadata, requestUri.OriginalString))
        {
            return new ProtectedResourceMetadataResourceMismatch
            {
                RequestUri = requestUri,
                PublishedResource = metadata.Resource,
                MetadataLocation = fetch.FinalUri
            };
        }

        //Decision (7): the document, with the HTTP freshness reported for the application's cache (Section 7.10).
        return new ProtectedResourceMetadataResolved
        {
            Metadata = metadata,
            MetadataLocation = fetch.FinalUri,
            Freshness = HttpCacheFreshness.Compute(response)
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
