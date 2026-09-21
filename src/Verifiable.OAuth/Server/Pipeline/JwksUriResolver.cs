using System.Text;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.JCose;

namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// Performs the library's one JWK Set attempt: fetches a <c>jwks_uri</c> through the guarded
/// <see cref="OutboundFetch"/> chokepoint and validates the response is a well-formed
/// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5">RFC 7517 §5</see> JWK Set. It
/// performs no caching and retains no state between calls — see <see cref="ResolveJwksUriDelegate"/>
/// for why that is the calling application's concern, not this library's.
/// </summary>
public static class JwksUriResolver
{
    private const string JsonStructuredSuffix = "+json";


    /// <summary>
    /// Fetches and validates a client's JWK Set through the guarded <see cref="OutboundFetch"/>
    /// chokepoint.
    /// </summary>
    /// <param name="jwksUri">The client's <c>jwks_uri</c> to fetch the key set from.</param>
    /// <param name="context">
    /// The per-request context; the guarded fetch reads its
    /// <see cref="Verifiable.Core.Outbound.OutboundFetchPolicy"/> from here.
    /// </param>
    /// <param name="transport">The application-supplied single-hop transport the guarded fetch drives.</param>
    /// <param name="options">The resolver's byte cap.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The typed outcome and, for a <see cref="JwksUriResolutionOutcome.Resolved"/> answer, the
    /// <see cref="HttpCacheFreshness"/> the response's own headers imply. Every other outcome leaves
    /// <see cref="JwksUriResolution.Freshness"/> at its default value, which reports nothing
    /// storable — storing a resolved key set, and deciding what follows a failure, is the caller's
    /// own <see cref="ResolveJwksUriDelegate"/> implementation's concern.
    /// </returns>
    public static async ValueTask<JwksUriResolution> ResolveAsync(
        Uri jwksUri,
        ExchangeContext context,
        OutboundTransportDelegate transport,
        JwksUriResolverOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(jwksUri);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(options);

        OutboundRequest request = new()
        {
            Target = jwksUri,
            Method = "GET",
            MaxResponseBytes = options.MaximumDocumentBytes
        };

        OutboundFetchResult fetch;
        try
        {
            fetch = await Verifiable.Core.Outbound.OutboundFetch.FetchAsync(
                request, context, transport, cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return new JwksUriResolution
            {
                Outcome = JwksUriResolutionOutcome.FetchFailed,
                Defect = "Transport failure while fetching the JWK Set."
            };
        }

        if(!fetch.IsFetched || fetch.Response is null)
        {
            return new JwksUriResolution
            {
                Outcome = fetch.Outcome == OutboundFetchOutcome.DeniedByPolicy
                    ? JwksUriResolutionOutcome.PolicyDenied
                    : JwksUriResolutionOutcome.FetchFailed,
                Defect = fetch.DenyReason
            };
        }

        OutboundResponse response = fetch.Response;

        if(response.StatusCode != 200)
        {
            return new JwksUriResolution
            {
                Outcome = JwksUriResolutionOutcome.FetchFailed,
                Defect = $"The JWK Set fetch returned HTTP status {response.StatusCode}."
            };
        }

        if(response.Body.Length > options.MaximumDocumentBytes)
        {
            return new JwksUriResolution
            {
                Outcome = JwksUriResolutionOutcome.FetchFailed,
                Defect = "The JWK Set exceeds the configured maximum size."
            };
        }

        _ = response.Headers.TryGetValue(WellKnownHttpHeaderNames.ContentType, out string? contentType);

        //RFC 7517 §5: "A JWK Set is a JSON object that represents a set of JWKs. The JSON object
        //MUST have a 'keys' member, with its value being an array of JWKs." Well-formedness is
        //checked before the member lookup per JwkJsonReader's own first-match-scan contract.
        bool isWellFormedJwkSet = IsAcceptableContentType(contentType)
            && JwkJsonReader.IsWellFormedJsonDocument(response.Body.Span)
            && JwkJsonReader.ContainsKey(response.Body.Span, WellKnownJwkMemberNames.KeysUtf8);

        if(!isWellFormedJwkSet)
        {
            return new JwksUriResolution
            {
                Outcome = JwksUriResolutionOutcome.InvalidDocument,
                Defect = "The response is not a well-formed RFC 7517 JWK Set document."
            };
        }

        return new JwksUriResolution
        {
            Outcome = JwksUriResolutionOutcome.Resolved,
            Jwks = Encoding.UTF8.GetString(response.Body.Span),
            Freshness = HttpCacheFreshness.Compute(response)
        };
    }


    /// <summary>
    /// Whether <paramref name="contentType"/> is <c>application/json</c> exactly, or any
    /// <c>application/&lt;AS-defined&gt;+json</c> structured suffix; parameters (e.g.
    /// <c>;charset=utf-8</c>) are stripped before comparison. Mirrors
    /// <c>ClientIdMetadataDocuments.IsAcceptableContentType</c>'s rule for the same content-type
    /// family.
    /// </summary>
    private static bool IsAcceptableContentType(string? contentType)
    {
        ReadOnlySpan<char> mediaType = ContentTypeReader.ReadMediaType(contentType);

        return mediaType.Equals(WellKnownMediaTypes.Application.Json, StringComparison.OrdinalIgnoreCase)
            || mediaType.EndsWith(JsonStructuredSuffix, StringComparison.OrdinalIgnoreCase);
    }
}
