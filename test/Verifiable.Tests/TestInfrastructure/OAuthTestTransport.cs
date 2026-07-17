using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.OAuth.Client;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The single real-wire <c>application/x-www-form-urlencoded</c> POST helper every OAuth grant test
/// category uses to drive a Kestrel-hosted authorization server, replacing what were four independently
/// hand-rolled per-file copies (<c>ClientCredentialsGrantTests</c>, <c>IdJagGrantTests</c>,
/// <c>JwtBearerGrantTests</c>, <c>TokenExchangeGrantTests</c>) plus the copies the client-builder tests
/// added on top (<c>ClientSecretAttachHelperTests</c>, <c>JwtBearerRequestBuilderTests</c>,
/// <c>TokenExchangeRequestBuilderTests</c>) — the DCQL-fixture-extraction convention of hosting a
/// cross-category test helper once in <c>TestInfrastructure</c> rather than reinventing it per category.
/// </summary>
internal static class OAuthTestTransport
{
    /// <summary>
    /// Posts <paramref name="formFields"/> as <c>application/x-www-form-urlencoded</c> to
    /// <paramref name="endpoint"/>, attaching <paramref name="headers"/> when supplied — the shape a
    /// <c>client_secret_basic</c> (RFC 6749 §2.3.1) <c>Authorization</c> header needs, since the
    /// no-content overload of <see cref="HttpClient.PostAsync(string?, HttpContent?)"/> cannot carry an
    /// extra request header.
    /// </summary>
    /// <param name="httpClient">The real, Kestrel-connected client the test host exposes.</param>
    /// <param name="endpoint">The token (or other form-posting) endpoint URL.</param>
    /// <param name="formFields">The decoded key/value pairs; this helper owns the wire's percent-encoding.</param>
    /// <param name="headers">Additional request headers (for example an <c>Authorization</c> header), or <see langword="null"/> for none.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public static async Task<HttpResponseMessage> PostFormAsync(
        HttpClient httpClient,
        Uri endpoint,
        IReadOnlyDictionary<string, string> formFields,
        OutgoingHeaders? headers,
        CancellationToken cancellationToken)
    {
        using FormUrlEncodedContent content = new(formFields);
        using HttpRequestMessage request = new(HttpMethod.Post, endpoint) { Content = content };
        if(headers is not null)
        {
            foreach((string name, string value) in headers.Values)
            {
                request.Headers.TryAddWithoutValidation(name, value);
            }
        }

        return await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>The header-less convenience overload of <see cref="PostFormAsync(HttpClient, Uri, IReadOnlyDictionary{string, string}, OutgoingHeaders?, CancellationToken)"/> for the common case of no extra request headers.</summary>
    /// <param name="httpClient">The real, Kestrel-connected client the test host exposes.</param>
    /// <param name="endpoint">The token (or other form-posting) endpoint URL.</param>
    /// <param name="formFields">The decoded key/value pairs; this helper owns the wire's percent-encoding.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public static Task<HttpResponseMessage> PostFormAsync(
        HttpClient httpClient,
        Uri endpoint,
        IReadOnlyDictionary<string, string> formFields,
        CancellationToken cancellationToken) =>
        PostFormAsync(httpClient, endpoint, formFields, headers: null, cancellationToken);
}
