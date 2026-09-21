namespace Verifiable.OAuth.Dpop;

/// <summary>
/// Sends a DPoP-bound request once and retries it exactly one further time with a fresh proof
/// when the answer is a <c>use_dpop_nonce</c> challenge carrying a <c>DPoP-Nonce</c> response
/// header. Shared by the AuthCode token-endpoint handler
/// (<see cref="Verifiable.OAuth.AuthCode.AuthCodeFlowHandlers"/>) and the OID4VCI Wallet client
/// (<see cref="Verifiable.OAuth.Oid4Vci.Wallet.Oid4VciWalletClient"/>) so the one-retry rule and
/// the nonce-cache read/write sequence live in exactly one place.
/// </summary>
/// <remarks>
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>: "the
/// authorization server responds to requests that do not include a nonce with an HTTP 400 (Bad
/// Request) error response ... using use_dpop_nonce as the error code value ... The client will
/// typically retry the request with the new nonce value." §9 extends the same mechanism to
/// resource servers, which "use an HTTP 401 (Unauthorized) error code with an accompanying
/// WWW-Authenticate: DPoP value and DPoP-Nonce value" instead of the token endpoint's JSON error
/// body — <c>isNonceChallenge</c> on <see cref="SendWithNonceRetryAsync"/> is how a
/// caller names which of the two forms its endpoint uses. Neither section defines a second retry
/// or a backoff, so a repeated challenge after the retry is returned to the caller as-is.
/// </remarks>
public static class DpopNonceRetry
{
    /// <summary>
    /// Sends once with the nonce currently cached for <paramref name="authority"/> (or none), and
    /// — only when <paramref name="isNonceChallenge"/> recognises the answer as a
    /// <c>use_dpop_nonce</c> challenge carrying a <c>DPoP-Nonce</c> response header — stores that
    /// nonce and sends exactly once more with it embedded in a fresh proof.
    /// </summary>
    /// <param name="sendOnceAsync">
    /// Mints a fresh DPoP proof embedding the given nonce (<see langword="null"/> for the first
    /// attempt when none is cached) and sends the request, returning the response.
    /// </param>
    /// <param name="isNonceChallenge">
    /// Recognises a <c>use_dpop_nonce</c> challenge on a response — the token endpoint's HTTP 400
    /// JSON-body form (RFC 9449 §8.1) or the resource server's HTTP 401
    /// <c>WWW-Authenticate</c> form (RFC 9449 §9, <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see>).
    /// </param>
    /// <param name="authority">The scheme+host+port the nonce is cached against.</param>
    /// <param name="lookupDpopNonce">
    /// Reads the nonce cached for <paramref name="authority"/>, or <see langword="null"/> to skip
    /// reading a cached nonce (the first attempt always carries none).
    /// </param>
    /// <param name="storeDpopNonce">
    /// Caches a fresh nonce for <paramref name="authority"/>, or <see langword="null"/> to skip
    /// caching (the retry still happens; only persistence across calls is skipped).
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The first response, unless a recognised nonce challenge triggered one retry.</returns>
    public static async ValueTask<HttpResponseData> SendWithNonceRetryAsync(
        Func<string?, CancellationToken, ValueTask<HttpResponseData>> sendOnceAsync,
        Func<HttpResponseData, bool> isNonceChallenge,
        string authority,
        DpopNonceLookupDelegate? lookupDpopNonce,
        DpopNonceStoreDelegate? storeDpopNonce,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sendOnceAsync);
        ArgumentNullException.ThrowIfNull(isNonceChallenge);
        ArgumentException.ThrowIfNullOrEmpty(authority);

        string? cachedNonce = lookupDpopNonce?.Invoke(authority);
        HttpResponseData response = await sendOnceAsync(cachedNonce, cancellationToken).ConfigureAwait(false);

        if(!isNonceChallenge(response))
        {
            return response;
        }

        string? freshNonce = response.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce);
        if(freshNonce is null)
        {
            return response;
        }

        storeDpopNonce?.Invoke(authority, freshNonce);

        return await sendOnceAsync(freshNonce, cancellationToken).ConfigureAwait(false);
    }
}
