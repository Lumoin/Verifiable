using System.Net;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;

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
        IReadOnlyCollection<KeyValuePair<string, string>> formFields,
        OutgoingHeaders? headers,
        CancellationToken cancellationToken)
    {
        using FormUrlEncodedContent content = new(formFields);
        using HttpRequestMessage request = new(HttpMethod.Post, endpoint) { Content = content };
        if(headers is not null)
        {
            foreach((string name, string value) in headers.Values)
            {
                _ = request.Headers.TryAddWithoutValidation(name, value);
            }
        }

        return await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>The header-less convenience overload of <see cref="PostFormAsync(HttpClient, Uri, IReadOnlyCollection{KeyValuePair{string, string}}, OutgoingHeaders?, CancellationToken)"/> for the common case of no extra request headers.</summary>
    /// <param name="httpClient">The real, Kestrel-connected client the test host exposes.</param>
    /// <param name="endpoint">The token (or other form-posting) endpoint URL.</param>
    /// <param name="formFields">The decoded key/value pairs; this helper owns the wire's percent-encoding.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public static Task<HttpResponseMessage> PostFormAsync(
        HttpClient httpClient,
        Uri endpoint,
        IReadOnlyCollection<KeyValuePair<string, string>> formFields,
        CancellationToken cancellationToken) =>
        PostFormAsync(httpClient, endpoint, formFields, headers: null, cancellationToken);


    /// <summary>
    /// Posts a DPoP-proved form request, honouring the single server nonce policy every grant at
    /// <c>/token</c> applies uniformly
    /// (<see cref="Verifiable.OAuth.AuthCode.Server.DpopTokenEndpointValidation"/>): a proof
    /// carrying no nonce is ALWAYS challenged with <c>use_dpop_nonce</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>), whatever
    /// the grant or the registration's profile. Builds a nonce-less proof first via
    /// <paramref name="buildProofAsync"/>; when the server challenges it, rebuilds the proof
    /// carrying the echoed <c>DPoP-Nonce</c> and retries exactly once.
    /// </summary>
    /// <param name="httpClient">The real, Kestrel-connected client the test host exposes.</param>
    /// <param name="endpoint">The token endpoint URL.</param>
    /// <param name="formFields">The decoded key/value pairs; this helper owns the wire's percent-encoding.</param>
    /// <param name="buildProofAsync">Builds a compact DPoP proof for the given nonce (<see langword="null"/> on the first attempt).</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The retried response and its body when a challenge was answered; the first response and its body otherwise.</returns>
    public static async Task<(HttpResponseMessage Response, string Body)> PostFormWithDpopNonceRetryAsync(
        HttpClient httpClient,
        Uri endpoint,
        IReadOnlyCollection<KeyValuePair<string, string>> formFields,
        Func<string?, Task<string>> buildProofAsync,
        CancellationToken cancellationToken)
    {
        string firstProof = await buildProofAsync(null).ConfigureAwait(false);
        HttpResponseMessage firstResponse = await PostFormAsync(
            httpClient, endpoint, formFields, OutgoingHeaders.Empty.WithDpop(firstProof), cancellationToken)
            .ConfigureAwait(false);
        string firstBody = await firstResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if(firstResponse.StatusCode != HttpStatusCode.BadRequest
            || !firstBody.Contains(OAuthErrors.UseDpopNonce, StringComparison.Ordinal))
        {
            return (firstResponse, firstBody);
        }

        string? serverNonce = firstResponse.Headers.TryGetValues(WellKnownHttpHeaderNames.DPoPNonce, out var values)
            ? values.FirstOrDefault()
            : null;
        if(serverNonce is null)
        {
            return (firstResponse, firstBody);
        }

        firstResponse.Dispose();
        string retryProof = await buildProofAsync(serverNonce).ConfigureAwait(false);
        HttpResponseMessage retryResponse = await PostFormAsync(
            httpClient, endpoint, formFields, OutgoingHeaders.Empty.WithDpop(retryProof), cancellationToken)
            .ConfigureAwait(false);
        string retryBody = await retryResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        return (retryResponse, retryBody);
    }


    /// <summary>
    /// The STRICT counterpart of <see cref="PostFormWithDpopNonceRetryAsync"/>: ASSERTS that the
    /// FIRST response is the mandatory <c>use_dpop_nonce</c> challenge, with a non-empty
    /// <c>DPoP-Nonce</c> header, before retrying — proving the single server nonce policy
    /// actually fired for this request, rather than merely tolerating either outcome the way the
    /// permissive overload does. A test whose whole point is to prove the policy (as opposed to a
    /// migrated success/binding-refusal test, whose assertions describe binding, not the policy)
    /// uses this overload instead.
    /// </summary>
    /// <param name="httpClient">The real, Kestrel-connected client the test host exposes.</param>
    /// <param name="endpoint">The token endpoint URL.</param>
    /// <param name="formFields">The decoded key/value pairs; this helper owns the wire's percent-encoding.</param>
    /// <param name="buildProofAsync">Builds a compact DPoP proof for the given nonce (<see langword="null"/> on the first attempt).</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The retried response and its body.</returns>
    public static async Task<(HttpResponseMessage Response, string Body)> PostFormWithMandatoryDpopNonceChallengeAsync(
        HttpClient httpClient,
        Uri endpoint,
        IReadOnlyCollection<KeyValuePair<string, string>> formFields,
        Func<string?, Task<string>> buildProofAsync,
        CancellationToken cancellationToken)
    {
        string firstProof = await buildProofAsync(null).ConfigureAwait(false);
        HttpResponseMessage firstResponse = await PostFormAsync(
            httpClient, endpoint, formFields, OutgoingHeaders.Empty.WithDpop(firstProof), cancellationToken)
            .ConfigureAwait(false);
        string firstBody = await firstResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.BadRequest, firstResponse.StatusCode, firstBody);
        Assert.Contains(OAuthErrors.UseDpopNonce, firstBody, StringComparison.Ordinal,
            "RFC 9449 §8: a nonce-less proof is ALWAYS challenged, whatever the grant or the registration's profile.");
        string? serverNonce = firstResponse.Headers.TryGetValues(WellKnownHttpHeaderNames.DPoPNonce, out var values)
            ? values.FirstOrDefault()
            : null;
        Assert.IsFalse(string.IsNullOrEmpty(serverNonce),
            "The use_dpop_nonce challenge must carry a non-empty DPoP-Nonce header to retry with.");

        firstResponse.Dispose();
        string retryProof = await buildProofAsync(serverNonce).ConfigureAwait(false);
        HttpResponseMessage retryResponse = await PostFormAsync(
            httpClient, endpoint, formFields, OutgoingHeaders.Empty.WithDpop(retryProof), cancellationToken)
            .ConfigureAwait(false);
        string retryBody = await retryResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        return (retryResponse, retryBody);
    }
}
