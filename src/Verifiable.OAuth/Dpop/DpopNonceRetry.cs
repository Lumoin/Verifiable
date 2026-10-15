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
/// (<see cref="Verifiable.OAuth.Oid4Vci.Wallet.Oid4VciWalletClient"/>) so the library's one-retry rule
/// (one retry, never a second, no backoff), the nonce-cache read/write sequence and the endpoint
/// (scheme, authority and path) a nonce is kept under live in exactly one place.
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
/// <c>DPoP</c> challenge's <c>error</c> auth-param. The sections name the occasion of a retry and
/// no bound on it; the bound is this library's rule: one retry, never a second, no backoff, so a
/// repeated challenge after the retry is returned to the caller as-is.
/// </remarks>
public static class DpopNonceRetry
{
    /// <summary>
    /// Sends once with the nonce currently cached for <paramref name="endpoint"/> (or none), keeps the
    /// nonce the answer supplies whatever its status, and, only when <paramref name="isNonceChallenge"/>
    /// recognises the answer as a <c>use_dpop_nonce</c> challenge that supplied a nonce, sends exactly
    /// once more with that nonce embedded in a fresh proof, keeping the nonce the retry's answer supplies
    /// the same way.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>: "When the
    /// authentication server or resource server provides a DPoP-Nonce HTTP header in a response (see Sections 8 and
    /// 9), the DPoP proof MUST also contain the following claim: nonce: A recent nonce provided via the DPoP-Nonce
    /// HTTP header."; <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">Section 8</see>: "The rejection
    /// response MAY include a DPoP-Nonce HTTP header providing a new nonce value to use for subsequent requests.";
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.2">Section 8.2</see>: "The client MUST use the new
    /// nonce value supplied for the next token request and for all subsequent token requests until the authorization
    /// server supplies a new nonce."; <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">Section 9</see>:
    /// "should a client use multiple authorization servers and/or resource servers, a nonce issued by any of them
    /// should be used only at the issuing server."
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
    /// <param name="endpoint">
    /// The absolute URI the request is sent to. The nonce is kept under its scheme, authority and path
    /// (<see cref="Uri.GetLeftPart(UriPartial)"/> with <see cref="UriPartial.Path"/>), the text a proof sent
    /// there names as <c>htu</c>, so a nonce is used only at the endpoint that supplied it.
    /// </param>
    /// <param name="lookupDpopNonce">
    /// Reads the nonce cached for the endpoint, or <see langword="null"/> to skip
    /// reading a cached nonce (the first attempt always carries none).
    /// </param>
    /// <param name="storeDpopNonce">
    /// Caches a fresh nonce for the endpoint, or <see langword="null"/> to skip
    /// caching (the retry still happens; only persistence across calls is skipped).
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The first response, unless a recognised nonce challenge triggered one retry.</returns>
    /// <remarks>
    /// The nonce an answer supplies is the one <c>DPoP-Nonce</c> field the answer carries
    /// (<see cref="ReadSuppliedNonce"/>), for a nonce challenge and for every other answer alike.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "Other HTTP headers and
    /// JSON fields MAY also be included in the error response, but there MUST NOT be more than one DPoP-Nonce header.";
    /// the clause binds the server, and the library's own rule reads an answer carrying none or two or more such field
    /// lines as supplying no nonce and a nonce challenge carrying them as no nonce challenge, since they name no one
    /// nonce. <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.2">Section 8.2</see>: "The DPoP-Nonce HTTP
    /// header field uses the nonce syntax defined in Section 8.1", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.1">Section 8.1</see>, Figure 22: <c>nonce =
    /// 1*NQCHAR</c>; a value outside that syntax is no nonce, and it is neither stored nor embedded in a proof. Section 8
    /// names the occasion of the retry ("The client will typically retry the request with the new nonce value supplied
    /// upon receiving a use_dpop_nonce error with an accompanying nonce value."), and no bound on it; the bound is this
    /// library's rule: one retry, never a second, and no backoff. The application's transport bounds the length of a
    /// <c>DPoP-Nonce</c> field line and decides whether a redirect is followed; the library stores what the transport
    /// delivers within the one-field <c>1*NQCHAR</c> rule and never parses the value.
    /// </remarks>
    public static async ValueTask<HttpResponseData> SendWithNonceRetryAsync(
        Func<string?, CancellationToken, ValueTask<HttpResponseData>> sendOnceAsync,
        Func<HttpResponseData, bool> isNonceChallenge,
        Uri endpoint,
        DpopNonceLookupDelegate? lookupDpopNonce,
        DpopNonceStoreDelegate? storeDpopNonce,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sendOnceAsync);
        ArgumentNullException.ThrowIfNull(isNonceChallenge);
        ArgumentNullException.ThrowIfNull(endpoint);
        if(!endpoint.IsAbsoluteUri)
        {
            throw new ArgumentException("The endpoint must be an absolute URI.", nameof(endpoint));
        }

        //RFC 9449 Section 9: a nonce is used only at the server that issued it. The endpoint's scheme, authority and
        //path, the text a proof sent there names as htu (Section 4.2), keys the nonce, so no endpoint is handed
        //another endpoint's nonce.
        string nonceEndpoint = endpoint.GetLeftPart(UriPartial.Path);
        string? cachedNonce = lookupDpopNonce?.Invoke(nonceEndpoint);
        HttpResponseData response = await sendOnceAsync(cachedNonce, cancellationToken).ConfigureAwait(false);

        //RFC 9449 Sections 4.2, 8 and 8.2: a nonce the answer supplies is kept whatever the answer's status, a 200,
        //a refusal and a nonce challenge alike, so the next proof sent to this endpoint carries it.
        string? suppliedNonce = ReadSuppliedNonce(response);
        if(suppliedNonce is not null)
        {
            storeDpopNonce?.Invoke(nonceEndpoint, suppliedNonce);
        }

        if(suppliedNonce is null || !isNonceChallenge(response))
        {
            return response;
        }

        HttpResponseData retryResponse = await sendOnceAsync(suppliedNonce, cancellationToken).ConfigureAwait(false);
        string? retrySuppliedNonce = ReadSuppliedNonce(retryResponse);
        if(retrySuppliedNonce is not null)
        {
            storeDpopNonce?.Invoke(nonceEndpoint, retrySuppliedNonce);
        }

        return retryResponse;
    }


    /// <summary>
    /// The nonce <paramref name="response"/> supplies: the value of its one <c>DPoP-Nonce</c> field line when that
    /// value is in the nonce syntax, and <see langword="null"/> when the answer carries no such field line, two or
    /// more, or one whose value is outside the syntax.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "Other HTTP headers and
    /// JSON fields MAY also be included in the error response, but there MUST NOT be more than one DPoP-Nonce header.";
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.2">Section 8.2</see>: "The DPoP-Nonce HTTP header
    /// field uses the nonce syntax defined in Section 8.1."; <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.1">Section
    /// 8.1</see>, Figure 22: <c>nonce = 1*NQCHAR</c>.
    /// </summary>
    /// <remarks>
    /// The clause on the field count binds the server; the library's own rule reads two or more field lines as
    /// supplying no nonce, since they name no one nonce. One reading decides both what is kept and whether a nonce
    /// challenge is retried.
    /// </remarks>
    /// <param name="response">The answer to read.</param>
    /// <returns>The supplied nonce, or <see langword="null"/>.</returns>
    private static string? ReadSuppliedNonce(HttpResponseData response)
    {
        IReadOnlyList<string> nonceLines = response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce);

        return nonceLines switch
        {
            [string nonce] when IsNonceSyntax(nonce) => nonce,
            _ => null
        };
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
