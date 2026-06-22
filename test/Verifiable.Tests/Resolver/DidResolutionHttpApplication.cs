using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.Resolvers;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// A test-only Kestrel host skin implementing the W3C DID Resolution HTTP(S) binding over the loopback
/// socket. It mounts <c>GET /1.0/identifiers/{did-or-did-url}</c>, drives the composed
/// <see cref="DidResolver"/>, and renders the response per the spec's content-negotiation and
/// error-to-status rules.
/// </summary>
/// <remarks>
/// <para>
/// Modeled on <see cref="Verifiable.Tests.Vcalm.VcalmConformanceHttpApplication"/>: the body buffering
/// and <c>StatusCode</c>/<c>Content-Type</c>/<c>Location</c> response shaping are the same. The library
/// does not reference Kestrel; a production binding writes its own host adapter, which is why this skin
/// lives in the test project.
/// </para>
/// <para>
/// The binding handler is transport-agnostic. The spec's "All HTTPS bindings MUST use TLS" is a
/// deployment transport requirement satisfied by terminating TLS in front of the handler; this test
/// drives it over the plain http loopback socket (the repo convention for real-socket binding tests),
/// so no certificate or TLS plumbing is wired here.
/// </para>
/// </remarks>
internal sealed class DidResolutionHttpApplication: IHttpApplication<HttpContext>
{
    private readonly DidResolver resolver;
    private readonly DidResolutionResultSerializer serializeResolution;
    private readonly DidDereferencingResultSerializer serializeDereferencing;
    private readonly DidDocumentSerializer serializeDocument;
    private readonly DidContentStreamSerializer serializeContentStream;
    private readonly OutboundFetchPolicy fetchPolicy;

    public DidResolutionHttpApplication(
        DidResolver resolver,
        DidResolutionResultSerializer serializeResolution,
        DidDereferencingResultSerializer serializeDereferencing,
        DidDocumentSerializer serializeDocument,
        DidContentStreamSerializer serializeContentStream,
        OutboundFetchPolicy fetchPolicy)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(serializeResolution);
        ArgumentNullException.ThrowIfNull(serializeDereferencing);
        ArgumentNullException.ThrowIfNull(serializeDocument);
        ArgumentNullException.ThrowIfNull(serializeContentStream);
        ArgumentNullException.ThrowIfNull(fetchPolicy);

        this.resolver = resolver;
        this.serializeResolution = serializeResolution;
        this.serializeDereferencing = serializeDereferencing;
        this.serializeDocument = serializeDocument;
        this.serializeContentStream = serializeContentStream;
        this.fetchPolicy = fetchPolicy;
    }


    public HttpContext CreateContext(IFeatureCollection contextFeatures) =>
        new DefaultHttpContext(contextFeatures);


    public async Task ProcessRequestAsync(HttpContext context)
    {
        HttpResponse httpResponse = context.Response;

        //Only GET is implemented (GET is MUST; POST is MAY and not implemented here).
        if(!HttpMethods.IsGet(context.Request.Method))
        {
            httpResponse.StatusCode = StatusCodes.Status405MethodNotAllowed;

            return;
        }

        string path = context.Request.Path.HasValue ? context.Request.Path.Value! : string.Empty;
        if(!path.StartsWith(WellKnownDidResolutionMediaTypes.IdentifiersBasePath, StringComparison.Ordinal))
        {
            httpResponse.StatusCode = StatusCodes.Status404NotFound;

            return;
        }

        string encoded = path[WellKnownDidResolutionMediaTypes.IdentifiersBasePath.Length..];
        string didOrUrl = Uri.UnescapeDataString(encoded);
        string accept = context.Request.Headers.Accept.ToString();

        ExchangeContext exchangeContext = new();
        exchangeContext.SetOutboundFetchPolicy(fetchPolicy);

        BindingResponse binding = await HandleAsync(didOrUrl, accept, exchangeContext, context.RequestAborted)
            .ConfigureAwait(false);

        await WriteResponseAsync(binding, httpResponse, context.RequestAborted).ConfigureAwait(false);
    }


    public void DisposeContext(HttpContext context, Exception? exception) { }


    private async ValueTask<BindingResponse> HandleAsync(
        string didOrUrl,
        string accept,
        ExchangeContext exchangeContext,
        CancellationToken cancellationToken)
    {
        //A DID URL carrying a path, query, or fragment is dereferenced; a bare DID is resolved.
        if(DidUrl.TryParse(didOrUrl, out DidUrl? parsed)
            && !parsed.IsRelative
            && (parsed.Path is not null || parsed.Query is not null || parsed.Fragment is not null))
        {
            DidDereferencingResult dereferencing = await resolver.DereferenceAsync(
                didOrUrl, exchangeContext, cancellationToken: cancellationToken).ConfigureAwait(false);

            return RenderDereferencing(dereferencing, accept);
        }

        DidResolutionResult resolution = await resolver.ResolveAsync(
            didOrUrl, exchangeContext, cancellationToken: cancellationToken).ConfigureAwait(false);

        return RenderResolution(resolution, accept);
    }


    private BindingResponse RenderResolution(DidResolutionResult result, string accept)
    {
        if(!result.IsSuccessful)
        {
            return ErrorResponse(
                result.ResolutionMetadata.Error,
                WellKnownDidResolutionMediaTypes.DidResolution,
                serializeResolution(result));
        }

        //A deactivated DID is signalled with HTTP 410 Gone (MUST), still carrying the full envelope.
        if(result.DocumentMetadata.Deactivated)
        {
            return new BindingResponse(
                StatusCodes.Status410Gone,
                WellKnownDidResolutionMediaTypes.DidResolution,
                serializeResolution(result));
        }

        //A resolution can serve either the full resolution-result envelope (preferred) or only the DID
        //document, labelled with the resolution-metadata contentType (defaulting to application/did+json). The
        //Accept header selects between them by q-value; no acceptable offer is a 406 (RFC 9110).
        //The document representation is offered under both its concrete content type and the abstract
        //application/did type a client may request; selecting either serves the document, labelled with the
        //concrete content type.
        string documentContentType = result.ResolutionMetadata.ContentType ?? WellKnownDidResolutionMediaTypes.DidJson;
        string? selected = HttpAcceptHeader.Parse(accept).SelectBest(
        [
            WellKnownDidResolutionMediaTypes.DidResolution,
            documentContentType,
            WellKnownDidResolutionMediaTypes.DidAbstract
        ]);

        if(selected is null)
        {
            return NotAcceptable();
        }

        if(string.Equals(selected, WellKnownDidResolutionMediaTypes.DidResolution, StringComparison.OrdinalIgnoreCase))
        {
            return new BindingResponse(
                StatusCodes.Status200OK,
                WellKnownDidResolutionMediaTypes.DidResolution,
                serializeResolution(result));
        }

        return new BindingResponse(
            StatusCodes.Status200OK,
            documentContentType,
            result.Document is null ? "null" : serializeDocument(result.Document));
    }


    private BindingResponse RenderDereferencing(DidDereferencingResult result, string accept)
    {
        if(!result.IsSuccessful)
        {
            return ErrorResponse(
                result.DereferencingMetadata.Error,
                WellKnownDidResolutionMediaTypes.DidUrlDereferencing,
                serializeDereferencing(result));
        }

        if(result.ContentMetadata?.Deactivated == true)
        {
            return new BindingResponse(
                StatusCodes.Status410Gone,
                WellKnownDidResolutionMediaTypes.DidUrlDereferencing,
                serializeDereferencing(result));
        }

        //A dereference can serve either the full dereferencing-result envelope (preferred) or the dereferenced
        //resource itself, labelled with the dereferencing contentType. The Accept header selects between them by
        //q-value; no acceptable offer is a 406 (RFC 9110).
        string contentType = result.DereferencingMetadata.ContentType ?? WellKnownDidResolutionMediaTypes.DidJson;
        string? selected = HttpAcceptHeader.Parse(accept).SelectBest(
        [
            WellKnownDidResolutionMediaTypes.DidUrlDereferencing,
            contentType
        ]);

        if(selected is null)
        {
            return NotAcceptable();
        }

        if(string.Equals(selected, WellKnownDidResolutionMediaTypes.DidUrlDereferencing, StringComparison.OrdinalIgnoreCase))
        {
            return new BindingResponse(
                StatusCodes.Status200OK,
                WellKnownDidResolutionMediaTypes.DidUrlDereferencing,
                serializeDereferencing(result));
        }

        //A text/uri-list content stream is a service-endpoint URL: answer 303 with a Location header
        //and an empty body.
        if(string.Equals(contentType, WellKnownDidResolutionMediaTypes.TextUriList, StringComparison.OrdinalIgnoreCase)
            && result.ContentStream is string serviceEndpoint)
        {
            return new BindingResponse(StatusCodes.Status303SeeOther, ContentType: null, Body: string.Empty)
            {
                Location = serviceEndpoint
            };
        }

        //A bare media type selects the dereferenced resource ITSELF (not the envelope), labelled with the
        //dereferencing contentType (spec: "the HTTP response body MUST contain the contentStream"). A binary
        //resource is rendered by the content-stream serializer as a base64 JSON string; a production binding
        //serving raw binary would stream the bytes directly with the resource's media type.
        return new BindingResponse(
            StatusCodes.Status200OK,
            contentType,
            serializeContentStream(result.ContentStream));
    }


    //Wraps the already-serialized failure envelope (which carries the error in its metadata) in a binding
    //response whose HTTP status comes from the spec's binding table and which is labelled with the result
    //form's media type.
    private static BindingResponse ErrorResponse(DidProblemDetails? error, string contentType, string body)
    {
        return new BindingResponse(MapErrorToStatus(error), contentType, body);
    }


    //Maps a DID error type URI to the HTTP status the spec's binding table mandates. The error types differ
    //only in their URI fragment, and System.Uri value-equality IGNORES the fragment, so the comparison is on
    //the AbsoluteUri string. An absent error or an unrecognized type URI is treated as an internal error (500).
    internal static int MapErrorToStatus(DidProblemDetails? error)
    {
        return error?.Type.AbsoluteUri switch
        {
            var type when type == DidErrorTypes.InvalidDid.AbsoluteUri => StatusCodes.Status400BadRequest,
            var type when type == DidErrorTypes.InvalidDidUrl.AbsoluteUri => StatusCodes.Status400BadRequest,
            var type when type == DidErrorTypes.InvalidOptions.AbsoluteUri => StatusCodes.Status400BadRequest,
            var type when type == DidErrorTypes.NotFound.AbsoluteUri => StatusCodes.Status404NotFound,
            var type when type == DidErrorTypes.RepresentationNotSupported.AbsoluteUri => StatusCodes.Status406NotAcceptable,
            var type when type == DidErrorTypes.InvalidDidDocument.AbsoluteUri => StatusCodes.Status500InternalServerError,
            var type when type == DidErrorTypes.MethodNotSupported.AbsoluteUri => StatusCodes.Status501NotImplemented,
            var type when type == DidErrorTypes.FeatureNotSupported.AbsoluteUri => StatusCodes.Status501NotImplemented,
            var type when type == DidErrorTypes.InternalError.AbsoluteUri => StatusCodes.Status500InternalServerError,
            _ => StatusCodes.Status500InternalServerError
        };
    }


    //No offered representation is acceptable under the request's Accept header: answer 406 Not Acceptable with
    //an empty body (RFC 9110 content negotiation).
    private static BindingResponse NotAcceptable() =>
        new(StatusCodes.Status406NotAcceptable, ContentType: null, Body: string.Empty);


    private static async ValueTask WriteResponseAsync(
        BindingResponse response,
        HttpResponse httpResponse,
        CancellationToken cancellationToken)
    {
        httpResponse.StatusCode = response.StatusCode;

        if(!string.IsNullOrEmpty(response.ContentType))
        {
            httpResponse.ContentType = response.ContentType;
        }

        if(!string.IsNullOrEmpty(response.Location))
        {
            httpResponse.Headers.Location = response.Location;
        }

        if(!string.IsNullOrEmpty(response.Body))
        {
            byte[] bodyBytes = Encoding.UTF8.GetBytes(response.Body);
            await httpResponse.Body.WriteAsync(bodyBytes, cancellationToken).ConfigureAwait(false);
        }
    }


    //The shaped binding response: the HTTP status, the optional Content-Type and Location, and the
    //body text.
    private sealed record BindingResponse(int StatusCode, string? ContentType, string Body)
    {
        public string? Location { get; init; }
    }
}
