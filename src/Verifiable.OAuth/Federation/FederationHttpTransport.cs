using System.Text;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Adapts an application's single-hop HTTP transport into a
/// <see cref="FetchEntityStatementDelegate"/> that retrieves an Entity
/// Statement from a federation entity's <c>federation_fetch_endpoint</c> per
/// OpenID Federation 1.0 §8.1, routed through the SSRF-policed
/// <see cref="OutboundFetch"/>.
/// </summary>
/// <remarks>
/// <para>
/// Like the rest of the library this type carries no <c>System.Net</c>: the
/// actual send is the application's injected
/// <see cref="OutboundTransportDelegate"/> (typically wrapping an
/// <c>HttpClient</c>). The fetch endpoint is discovered from another entity's
/// metadata and is therefore untrusted, so every hop is checked against the
/// <see cref="OutboundFetchPolicy"/> the <see cref="ExchangeContext"/> carries.
/// </para>
/// <para>
/// The transport encodes only the §8.1 conventions: an HTTP <c>GET</c> with
/// the subject in the <c>sub</c> query parameter, a 2xx response treated as
/// success, and the body parsed as a compact JWS Entity Statement. A policy
/// denial, a transport error, a non-2xx status, or an unparseable body all
/// surface as a <see langword="null"/> result, matching the
/// <see cref="FetchEntityStatementDelegate"/> contract.
/// </para>
/// </remarks>
public static class FederationHttpTransport
{
    /// <summary>
    /// Builds a <see cref="FetchEntityStatementDelegate"/> over the supplied
    /// transport and parse seams.
    /// </summary>
    /// <param name="transport">The application's single-hop HTTP transport.</param>
    /// <param name="headerDeserializer">Deserializes the fetched statement's protected-header bytes.</param>
    /// <param name="payloadDeserializer">Deserializes the fetched statement's payload bytes.</param>
    /// <param name="base64UrlDecoder">Decodes the base64url segments of the fetched compact JWS.</param>
    /// <returns>The composed fetch delegate.</returns>
    public static FetchEntityStatementDelegate BuildFetchEntityStatement(
        OutboundTransportDelegate transport,
        JwtHeaderDeserializer headerDeserializer,
        JwtPayloadDeserializer payloadDeserializer,
        DecodeDelegate base64UrlDecoder)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(payloadDeserializer);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);

        return (subject, fetchEndpoint, context, cancellationToken) =>
        {
            ArgumentNullException.ThrowIfNull(fetchEndpoint);
            ArgumentNullException.ThrowIfNull(context);

            //§8.1: the subject the requester is asking about rides the sub query
            //parameter on the GET to the issuer's federation_fetch_endpoint.
            UriBuilder builder = new(fetchEndpoint)
            {
                Query = $"sub={Uri.EscapeDataString(subject.Value)}"
            };

            return GetAndParseAsync(
                builder.Uri, transport, headerDeserializer, payloadDeserializer, base64UrlDecoder,
                context, cancellationToken);
        };
    }


    /// <summary>
    /// Builds a <see cref="FetchEntityConfigurationDelegate"/> that GETs an
    /// entity's <c>/.well-known/openid-federation</c> Entity Configuration per
    /// §9, over the supplied transport and parse seams.
    /// </summary>
    /// <param name="transport">The application's single-hop HTTP transport.</param>
    /// <param name="headerDeserializer">Deserializes the fetched statement's protected-header bytes.</param>
    /// <param name="payloadDeserializer">Deserializes the fetched statement's payload bytes.</param>
    /// <param name="base64UrlDecoder">Decodes the base64url segments of the fetched compact JWS.</param>
    /// <returns>The composed Entity Configuration fetch delegate.</returns>
    public static FetchEntityConfigurationDelegate BuildFetchEntityConfiguration(
        OutboundTransportDelegate transport,
        JwtHeaderDeserializer headerDeserializer,
        JwtPayloadDeserializer payloadDeserializer,
        DecodeDelegate base64UrlDecoder)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(payloadDeserializer);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);

        return (entity, context, cancellationToken) =>
        {
            ArgumentNullException.ThrowIfNull(context);

            //§9: the Entity Configuration is published at the entity's
            ///.well-known/openid-federation, derived from its identifier with no
            //sub query parameter (an entity self-issues its own configuration).
            Uri target = WellKnownPaths.OpenIdFederation.ComputeUri(entity.Value);

            return GetAndParseAsync(
                target, transport, headerDeserializer, payloadDeserializer, base64UrlDecoder,
                context, cancellationToken);
        };
    }


    /// <summary>
    /// GETs <paramref name="target"/> through the SSRF-policed
    /// <see cref="OutboundFetch"/> and parses a 2xx body as a compact JWS Entity
    /// Statement. A policy denial, transport error, non-2xx status, or
    /// unparseable body all return <see langword="null"/>.
    /// </summary>
    private static async ValueTask<FetchedEntityStatement?> GetAndParseAsync(
        Uri target,
        OutboundTransportDelegate transport,
        JwtHeaderDeserializer headerDeserializer,
        JwtPayloadDeserializer payloadDeserializer,
        DecodeDelegate base64UrlDecoder,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        OutboundRequest request = new() { Target = target, Method = "GET" };

        OutboundFetchResult result;
        try
        {
            result = await OutboundFetch
                .FetchAsync(request, context, transport, cancellationToken)
                .ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch
        {
            //A transport-level failure (socket / DNS / connection), or a policy
            //denial surfaced as a throw, is fail-soft: the caller treats a null
            //fetch as "statement unavailable".
            return null;
        }

        if(!result.IsFetched
            || result.Response is not { } response
            || response.StatusCode is < 200 or > 299
            || response.Body.Span.IsEmpty)
        {
            return null;
        }

        string compactJws = Encoding.UTF8.GetString(response.Body.Span);
        return EntityStatementJwsReader.TryRead(
            compactJws, headerDeserializer, payloadDeserializer, base64UrlDecoder, BaseMemoryPool.Shared);
    }
}
