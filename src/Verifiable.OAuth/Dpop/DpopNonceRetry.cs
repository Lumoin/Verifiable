using System.Buffers;
using System.Text;
using Verifiable.JCose;
using Verifiable.OAuth.ProtectedResource;

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
/// caller names which of the two forms its endpoint uses. Each form is recognised by its error code
/// alone, read where the form carries it: <see cref="IsErrorBodyNonceChallenge"/> reads the JSON
/// object's top-level <c>error</c> member and <see cref="IsWwwAuthenticateNonceChallenge"/> the
/// <c>DPoP</c> challenge's <c>error</c> auth-param. Neither section defines a second retry
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
    /// JSON-body form (RFC 9449 Section 8) or the resource server's HTTP 401
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
    /// <remarks>
    /// The challenge's nonce is the one <c>DPoP-Nonce</c> field the answer carries.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "there MUST NOT be more
    /// than one DPoP-Nonce header"; the clause binds the server, and the library's own rule reads an answer carrying
    /// none or two or more such field lines as no nonce challenge, since it names no one nonce.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.2">Section 8.2</see>: "The DPoP-Nonce HTTP header
    /// field uses the nonce syntax defined in Section 8.1", Figure 22: <c>nonce = 1*NQCHAR</c>; a value outside that
    /// syntax is no nonce, and it is neither stored nor embedded in a proof.
    /// </remarks>
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

        IReadOnlyList<string> nonceLines = response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce);
        if(nonceLines.Count != 1)
        {
            return response;
        }

        string freshNonce = nonceLines[0];
        if(!IsNonceSyntax(freshNonce))
        {
            return response;
        }

        storeDpopNonce?.Invoke(authority, freshNonce);

        return await sendOnceAsync(freshNonce, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Whether <paramref name="response"/> is the nonce challenge in its error response form: HTTP 400 whose JSON
    /// object carries <c>use_dpop_nonce</c> as its own top-level <c>error</c> member.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "the authorization
    /// server responds to requests that do not include a nonce with an HTTP 400 (Bad Request) error response per
    /// Section 5.2 of [RFC6749] using use_dpop_nonce as the error code value."
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>: "The parameters are
    /// serialized into a JSON structure by adding each parameter at the highest structure level."
    /// </summary>
    /// <remarks>
    /// The body is read as a document, never searched as text: it is held to
    /// <see cref="JwkJsonReader.IsWellFormedJsonDocument"/> (so a repeated <c>error</c> member cannot make this
    /// reader and another consumer of the same body read different codes), and the <c>error</c> member is then read
    /// at the top level with <see cref="JwkJsonReader.ExtractStringValue"/>. The text <c>use_dpop_nonce</c> in an
    /// <c>error_description</c>, in a nested object or in a body that is not one JSON document is no error code, so
    /// such an answer is no nonce challenge and is returned to the caller as the refusal it is. The UTF-8 copy of the
    /// body is rented from <paramref name="memoryPool"/>.
    /// </remarks>
    /// <param name="response">The answer to read.</param>
    /// <param name="memoryPool">The pool the body's UTF-8 copy is rented from.</param>
    /// <returns><see langword="true"/> when the answer is the error response form of the nonce challenge.</returns>
    internal static bool IsErrorBodyNonceChallenge(HttpResponseData response, BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(response.StatusCode != BadRequestStatusCode || string.IsNullOrEmpty(response.Body))
        {
            return false;
        }

        //RFC 8259 Section 9: a body over the document limit is refused before any buffer is rented. A char count
        //is never more than its UTF-8 byte count, so the char count is tested first.
        if(response.Body.Length > JwkJsonReader.MaximumDocumentLength)
        {
            return false;
        }

        int byteCount = Encoding.UTF8.GetByteCount(response.Body);
        if(byteCount > JwkJsonReader.MaximumDocumentLength)
        {
            return false;
        }

        using IMemoryOwner<byte> bodyUtf8 = memoryPool.Rent(byteCount);
        Span<byte> destination = bodyUtf8.Memory.Span;
        int written = Encoding.UTF8.GetBytes(response.Body, destination);
        ReadOnlySpan<byte> json = destination[..written];

        return JwkJsonReader.IsWellFormedJsonDocument(json)
            && string.Equals(
                JwkJsonReader.ExtractStringValue(json, OAuthRequestParameterNames.ErrorUtf8),
                OAuthErrors.UseDpopNonce,
                StringComparison.Ordinal);
    }


    /// <summary>
    /// Whether <paramref name="response"/> is the nonce challenge in its resource server form: HTTP 401 whose
    /// <c>WWW-Authenticate</c> field lines hold one <c>DPoP</c> challenge whose <c>error</c> auth-param is
    /// <c>use_dpop_nonce</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "Resource servers use
    /// an HTTP 401 (Unauthorized) error code with an accompanying WWW-Authenticate: DPoP value and DPoP-Nonce value
    /// to accomplish this." and <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">Section 7.1</see>: "The
    /// value use_dpop_nonce can be used as described in Section 9 to signal that a nonce is needed" and "unknown
    /// parameters MUST be ignored by recipients."
    /// </summary>
    /// <remarks>
    /// The <c>WWW-Authenticate</c> field lines, combined into one field value as
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110 Section 5.3</see> combines them, are read
    /// as the challenge list <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section
    /// 11.6.1</see> defines, "WWW-Authenticate = #challenge", by the library's challenge reader,
    /// <see cref="BearerTokenChallenge.TryReadChallenge"/>, which selects the one <c>DPoP</c> challenge wherever the
    /// list places it, beside a <c>Bearer</c> challenge or on another field line
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>). The reader holds
    /// the <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see> grammar,
    /// "auth-param = token BWS "=" BWS ( token / quoted-string )", the name "matched case-insensitively", each name
    /// once per challenge. Only the <c>error</c> parameter's value is compared; the value of a parameter the reader does
    /// not know is ignored, so <c>DPoP error="invalid_token", x="use_dpop_nonce"</c> is the <c>invalid_token</c>
    /// refusal it states. A field value outside the grammar, no <c>DPoP</c> challenge, or two of them is no nonce
    /// challenge, and the answer is returned to the caller as the refusal it is.
    /// </remarks>
    /// <param name="response">The answer to read.</param>
    /// <returns><see langword="true"/> when the answer is the resource server form of the nonce challenge.</returns>
    internal static bool IsWwwAuthenticateNonceChallenge(HttpResponseData response)
    {
        if(response.StatusCode != UnauthorizedStatusCode)
        {
            return false;
        }

        IReadOnlyList<string> challengeLines = response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate);

        return BearerTokenChallenge.TryReadChallenge(challengeLines, WellKnownAuthenticationSchemes.DPoP, out BearerTokenChallengeParameters parameters)
            && string.Equals(parameters.Error, OAuthErrors.UseDpopNonce, StringComparison.Ordinal);
    }


    /// <summary>
    /// Whether <paramref name="value"/> is a nonce by
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.1">RFC 9449 Section 8.1</see>, Figure 22,
    /// <c>nonce = 1*NQCHAR</c>, with <c>NQCHAR = %x21 / %x23-5B / %x5D-7E</c> as
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A">RFC 6749 Appendix A</see> defines it.
    /// </summary>
    /// <param name="value">The <c>DPoP-Nonce</c> field value.</param>
    /// <returns><see langword="true"/> when the value is one or more NQCHAR.</returns>
    private static bool IsNonceSyntax(string value)
    {
        if(value.Length == 0)
        {
            return false;
        }

        foreach(char c in value)
        {
            bool isNqChar = c is '!' or (>= '#' and <= '[') or (>= ']' and <= '~');
            if(!isNqChar)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>The HTTP 400 (Bad Request) status of the error response form of the nonce challenge (RFC 9449 Section 8).</summary>
    private static int BadRequestStatusCode { get; } = 400;

    /// <summary>The HTTP 401 (Unauthorized) status of the resource server form of the nonce challenge (RFC 9449 Section 9).</summary>
    private static int UnauthorizedStatusCode { get; } = 401;
}
