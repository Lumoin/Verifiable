using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.Http;
using System.Text;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;

namespace Verifiable.Tests.OAuth.Hosting;

/// <summary>
/// Implements the <see cref="OAuthClient"/> transport delegates against a
/// real <see cref="HttpClient"/>. Used by <see cref="TestHostShell"/> for
/// AS-touching tests that want wire fidelity — the real HTTP round-trip
/// exercises wire-level emission and parsing in both directions.
/// </summary>
/// <remarks>
/// <para>
/// Each method constructs an <see cref="HttpRequestMessage"/>, sends it
/// via <see cref="HttpClient.SendAsync(HttpRequestMessage, System.Threading.CancellationToken)"/>,
/// and maps the resulting <see cref="HttpResponseMessage"/> into the
/// library's <see cref="HttpResponseData"/>. The methods are <c>static</c>
/// so that the test fixture composes them as transport-delegate values by
/// closing over the shared <see cref="HttpClient"/> instance.
/// </para>
/// <para>
/// <see cref="HttpClient.SendAsync(HttpRequestMessage, System.Threading.CancellationToken)"/>
/// is used directly without retry, redirect-following, or any policy
/// wrapping. The OAuth client's flow logic handles protocol-level retries
/// (DPoP nonce challenge, etc.). Transport-level retries belong in a real
/// deployment's HTTP-client factory, not in a test transport.
/// </para>
/// </remarks>
internal static class HttpClientTransport
{
    public static async ValueTask<HttpResponseData> SendFormPostAsync(
        HttpClient httpClient,
        Uri endpoint,
        IReadOnlyDictionary<string, string> formFields,
        OutgoingHeaders headers,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(formFields);

        using FormUrlEncodedContent content = new(formFields);

        using HttpRequestMessage request = new(HttpMethod.Post, endpoint)
        {
            Content = content
        };
        AddOutgoingHeaders(request, headers);

        using HttpResponseMessage response = await httpClient
            .SendAsync(request, cancellationToken).ConfigureAwait(false);

        return await BuildHttpResponseDataAsync(response, cancellationToken)
            .ConfigureAwait(false);
    }


    public static async ValueTask<HttpResponseData> SendJsonPostAsync(
        HttpClient httpClient,
        Uri endpoint,
        string jsonBody,
        OutgoingHeaders headers,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(jsonBody);

        using StringContent content = new(
            jsonBody, Encoding.UTF8, WellKnownMediaTypes.Application.Json);

        using HttpRequestMessage request = new(HttpMethod.Post, endpoint)
        {
            Content = content
        };
        AddOutgoingHeaders(request, headers);

        using HttpResponseMessage response = await httpClient
            .SendAsync(request, cancellationToken).ConfigureAwait(false);

        return await BuildHttpResponseDataAsync(response, cancellationToken)
            .ConfigureAwait(false);
    }


    public static async ValueTask<HttpResponseData> SendJsonGetAsync(
        HttpClient httpClient,
        Uri endpoint,
        OutgoingHeaders headers,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(endpoint);

        using HttpRequestMessage request = new(HttpMethod.Get, endpoint);
        AddOutgoingHeaders(request, headers);

        using HttpResponseMessage response = await httpClient
            .SendAsync(request, cancellationToken).ConfigureAwait(false);

        return await BuildHttpResponseDataAsync(response, cancellationToken)
            .ConfigureAwait(false);
    }


    public static async ValueTask<HttpResponseData> SendJsonPutAsync(
        HttpClient httpClient,
        Uri endpoint,
        string jsonBody,
        OutgoingHeaders headers,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(jsonBody);

        using StringContent content = new(
            jsonBody, Encoding.UTF8, WellKnownMediaTypes.Application.Json);

        using HttpRequestMessage request = new(HttpMethod.Put, endpoint)
        {
            Content = content
        };
        AddOutgoingHeaders(request, headers);

        using HttpResponseMessage response = await httpClient
            .SendAsync(request, cancellationToken).ConfigureAwait(false);

        return await BuildHttpResponseDataAsync(response, cancellationToken)
            .ConfigureAwait(false);
    }


    public static async ValueTask<HttpResponseData> SendJsonDeleteAsync(
        HttpClient httpClient,
        Uri endpoint,
        OutgoingHeaders headers,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(endpoint);

        using HttpRequestMessage request = new(HttpMethod.Delete, endpoint);
        AddOutgoingHeaders(request, headers);

        using HttpResponseMessage response = await httpClient
            .SendAsync(request, cancellationToken).ConfigureAwait(false);

        return await BuildHttpResponseDataAsync(response, cancellationToken)
            .ConfigureAwait(false);
    }


    private static void AddOutgoingHeaders(HttpRequestMessage request, OutgoingHeaders headers)
    {
        foreach(KeyValuePair<string, string> header in headers.Values)
        {
            //TryAddWithoutValidation accepts any syntactically-valid header
            //value. The OAuth flow's headers (DPoP proofs, Authorization
            //bearer/dpop schemes, custom RFC 9457 fields) are not all on
            //HttpClient's known-header set; the without-validation path
            //avoids spurious rejections at the transport layer.
            if(!request.Headers.TryAddWithoutValidation(header.Key, header.Value)
                && request.Content is not null)
            {
                //Some header names (Content-Type, Content-Length) live on
                //the content's headers rather than the request's. Try the
                //content collection as a fallback so values like
                //Content-Type that the OAuth client occasionally surfaces
                //land in the right place.
                request.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }
    }


    private static async ValueTask<HttpResponseData> BuildHttpResponseDataAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        string body = await response.Content
            .ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        ImmutableDictionary<string, string>.Builder headerBuilder =
            ImmutableDictionary.CreateBuilder<string, string>(StringComparer.OrdinalIgnoreCase);

        //Both response.Headers and response.Content.Headers carry headers
        //the OAuth client may want to read — Cache-Control and DPoP-Nonce
        //come back on response.Headers; Content-Type comes back on
        //response.Content.Headers. Iterate both and merge; duplicate keys
        //take last-write-wins (rare in practice for OAuth flows).
        foreach(KeyValuePair<string, IEnumerable<string>> header in response.Headers)
        {
            headerBuilder[header.Key] = string.Join(", ", header.Value);
        }
        foreach(KeyValuePair<string, IEnumerable<string>> header in response.Content.Headers)
        {
            headerBuilder[header.Key] = string.Join(", ", header.Value);
        }

        return new HttpResponseData
        {
            Body = body,
            StatusCode = (int)response.StatusCode,
            Headers = new ResponseHeaders { Values = headerBuilder.ToImmutable() }
        };
    }
}
