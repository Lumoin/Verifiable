using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// Enforces the RFC 9449 DPoP sender constraint at the protected resource endpoints: the OID4VCI
/// Credential, Deferred and Notification endpoints and the OpenID Connect UserInfo endpoint
/// (<see cref="Oidc.UserInfoEndpoints"/>), and composes the <c>WWW-Authenticate</c> challenges those
/// endpoints answer a refused presentation with.
/// </summary>
/// <remarks>
/// <para>
/// When the validated Access Token carries a <c>cnf.jkt</c> binding, a DPoP proof bound to the SAME
/// key MUST accompany it: the proof-of-possession the token endpoint minted is verified at the
/// resource, not ignored. A bound token is never accepted as a plain bearer: presented under the
/// <c>Bearer</c> scheme it is rejected (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC
/// 9449 §7.2</see>: "such a protected resource MUST reject a DPoP-bound access token received as a
/// bearer token per [RFC6750]."), and a missing DPoP delegate is a configuration error rather than a
/// silent downgrade. A <c>cnf</c> claim whose confirmation method this resource cannot check (no
/// usable <c>jkt</c>) is refused rather than served as a bearer token, and an unbound token presented
/// under the <c>DPoP</c> scheme is refused, since that scheme carries a DPoP-bound access token
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 §7.1</see>: "A DPoP-bound
/// access token is sent using the Authorization request header field per Section 11.6.2 of [RFC9110]
/// with an authentication scheme of DPoP.").
/// </para>
/// <para>
/// The resource requires its nonce in every proof. <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.3">RFC
/// 9449 §11.3</see>: "A server MUST NOT accept any DPoP proofs without the nonce claim when a DPoP
/// nonce has been provided to the client." The resource issues a nonce whenever a proof lacks a
/// valid one and keeps no per-client record of which client it provided one to, so it accepts no
/// proof without its nonce; the first request is answered with the <c>use_dpop_nonce</c> challenge
/// and a fresh <c>DPoP-Nonce</c>, the shape of
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 §9</see>'s Figure 24.
/// </para>
/// <para>
/// Every refusal of a presented token is a 401 carrying one challenge, in the scheme the request was
/// authenticated under. Sending a single challenge is this library's choice; RFC 9449 §7.2 governs a
/// resource that elects to send several ("If a protected resource supporting both Bearer and DPoP
/// schemes elects to respond with multiple WWW-Authenticate challenges, attention should be paid to
/// which challenge(s) should deliver the actual error information.") and says which one carries the
/// error: "If the mechanism used to attempt authentication could be established unambiguously, then
/// the corresponding challenge SHOULD be used to deliver error information". The single challenge
/// sent is that corresponding one. A <c>DPoP</c> challenge carries the <c>error</c> RFC 9449 §7.1 names
/// (<c>invalid_token</c> for the token or its binding, <c>invalid_dpop_proof</c> for a proof that
/// fails a §4.3 check, <c>use_dpop_nonce</c> for a missing or stale nonce) and the <c>algs</c>
/// parameter §7.1 says SHOULD be included, listing
/// <see cref="WellKnownDpopValues.SupportedSigningAlgorithms"/>. The resource-server shape mirrors
/// <c>DpopTokenEndpointValidation</c> but adds the <c>ath</c> binding and computes <c>htm</c> and
/// <c>htu</c> from the request being served, so one enforcement serves an endpoint that answers more
/// than one HTTP method.
/// </para>
/// </remarks>
internal static class CredentialEndpointDpopValidation
{
    /// <summary>
    /// The value of the <c>algs</c> challenge parameter: the space-delimited
    /// <see cref="WellKnownDpopValues.SupportedSigningAlgorithms"/>, per RFC 9449 §7.1 "An algs parameter
    /// SHOULD be included to signal to the client the JWS algorithms that are acceptable for the DPoP
    /// proof JWT. The value of the parameter is a space-delimited list of JWS alg (Algorithm) header
    /// values".
    /// </summary>
    private static string AcceptedProofAlgorithms { get; } =
        string.Join(' ', WellKnownDpopValues.SupportedSigningAlgorithms);


    /// <summary>
    /// Returns the failure response to return, or <see langword="null"/> when the sender
    /// constraint is satisfied or the token is an ordinary bearer token presented under the
    /// <c>Bearer</c> scheme.
    /// </summary>
    /// <param name="server">The authorization server holding the DPoP delegates and the issuer resolver.</param>
    /// <param name="context">The per-request context carrying the inbound request.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="accessToken">The validated Access Token's payload.</param>
    /// <param name="rawAccessToken">The Access Token exactly as presented, the value <c>ath</c> hashes.</param>
    /// <param name="isDpopPresentation">Whether the token was presented under the <c>DPoP</c> scheme.</param>
    /// <param name="now">The instant the proof's <c>jti</c> record is kept from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The refusal, or <see langword="null"/> to proceed.</returns>
    public static async ValueTask<ServerHttpResponse?> EnforceAsync(
        EndpointServer server,
        ExchangeContext context,
        ClientRecord registration,
        JwtPayload accessToken,
        string rawAccessToken,
        bool isDpopPresentation,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();

        if(!accessToken.TryGetValue(WellKnownJwtClaimNames.Cnf, out object? confirmation))
        {
            //RFC 9449 §7.1: the DPoP scheme carries a DPoP-bound access token. An unbound token
            //presented under it names no key a proof could be checked against, so it is refused;
            //under the Bearer scheme it is an ordinary bearer token.
            return isDpopPresentation
                ? RefuseUnderScheme(isDpopPresentation, OAuthErrors.InvalidToken,
                    "The Access Token is not bound to a DPoP key and cannot be presented under the DPoP scheme.")
                : null;
        }

        string? boundThumbprint = ReadConfirmationThumbprint(confirmation);
        if(boundThumbprint is null)
        {
            //The token is sender-constrained by a confirmation method this resource does not check
            //(cnf without a usable jkt). Serving it as a bearer token would drop that constraint.
            return RefuseUnderScheme(isDpopPresentation, OAuthErrors.InvalidToken,
                "The Access Token carries a confirmation method this resource cannot enforce.");
        }

        //RFC 9449 §7.2: a DPoP-bound token received as a bearer token is rejected. Accepting it
        //under Bearer would strip the binding the token endpoint established.
        if(!isDpopPresentation)
        {
            return RefuseUnderScheme(isDpopPresentation, OAuthErrors.InvalidToken,
                "The Access Token is sender-constrained and must be presented under the DPoP scheme.");
        }

        //A bound token with no DPoP enforcement wired is a misconfiguration — fail loud rather
        //than fall back to bearer, which would silently drop the proof-of-possession check.
        if(oauth.ValidateDpopProofAsync is null
            || oauth.IssueDpopNonceAsync is null
            || oauth.ValidateDpopNonceAsync is null)
        {
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "The Access Token is DPoP-bound but DPoP validation is not configured.");
        }

        Uri issuerUri = await ResolveIssuerAsync(server, registration, context, cancellationToken)
            .ConfigureAwait(false);

        string? dpopProof = null;
        _ = (context.IncomingRequest?.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoP, out dpopProof));
        if(dpopProof is null)
        {
            return await ChallengeForNonceAsync(
                server, registration, context, issuerUri,
                "A DPoP proof carrying this resource's nonce is required for the sender-constrained Access Token.",
                cancellationToken).ConfigureAwait(false);
        }

        //RFC 9449 §4.3: the htm claim matches the HTTP method of the current request, and the htu
        //claim its target URI; both are read from the request this endpoint is serving.
        IncomingRequest request = context.IncomingRequest!;
        string htu = $"{issuerUri.GetLeftPart(UriPartial.Authority)}{request.Path}";
        DpopProofValidationResult proofResult = await oauth.ValidateDpopProofAsync(
            new DpopProofValidationRequest
            {
                Proof = dpopProof,
                HttpMethod = request.Method,
                HttpUrl = htu,
                //ath binds the proof to THIS access token (RFC 9449 §4.2 / §7).
                AccessToken = rawAccessToken,
                NonceRequired = false
            },
            cancellationToken).ConfigureAwait(false);

        if(!proofResult.IsSuccess)
        {
            return proofResult.FailureReason is DpopProofValidationFailureReason.NonceMissing
                or DpopProofValidationFailureReason.NonceMismatch
                ? await ChallengeForNonceAsync(
                    server, registration, context, issuerUri, "DPoP nonce required.", cancellationToken)
                    .ConfigureAwait(false)
                : RefuseUnderScheme(isDpopPresentation, OAuthErrors.InvalidDpopProof,
                    $"DPoP proof validation failed: {proofResult.FailureReason}.");
        }

        //RFC 9449 §4.3 item 12 and §7.1: the proving key MUST be the one the token was bound to.
        //Constant-time — the thumbprint is matched, not merely compared. The refusal is the
        //invalid_token of §7.1's Figure 16, the binding of the token being what fails.
        if(!FixedTimeComparison.AreEqual(proofResult.JwkThumbprint, boundThumbprint))
        {
            return RefuseUnderScheme(isDpopPresentation, OAuthErrors.InvalidToken,
                "The DPoP proof key does not match the Access Token's cnf.jkt binding.");
        }

        //RFC 9449 §11.3: no proof without the nonce claim is accepted once a nonce has been
        //provided, and this resource provides one to every client it challenges.
        if(proofResult.Claims!.Nonce is null)
        {
            return await ChallengeForNonceAsync(
                server, registration, context, issuerUri, "DPoP nonce required.", cancellationToken)
                .ConfigureAwait(false);
        }

        DpopNonceValidationResult nonceResult = await oauth.ValidateDpopNonceAsync(
            proofResult.Claims.Nonce, issuerUri, registration.TenantId, context, cancellationToken)
            .ConfigureAwait(false);
        if(!nonceResult.IsSuccess)
        {
            return await ChallengeForNonceAsync(
                server, registration, context, issuerUri,
                $"DPoP nonce invalid: {nonceResult.FailureReason}.", cancellationToken).ConfigureAwait(false);
        }

        //jti replay — the same shared correlation store, the proof's jti recorded in the context of
        //the target URI this request is served at (RFC 9449 §11.1).
        JtiReplayOutcome jtiOutcome = await JtiReplayGuard.ConsultDpopProofAsync(
            server, context, registration.TenantId,
            issuerUri.OriginalString, htu, proofResult.Claims.Jti,
            now + WellKnownDpopValues.DefaultReplayWindow,
            cancellationToken).ConfigureAwait(false);

        return jtiOutcome switch
        {
            JtiReplayOutcome.FirstUse => null,
            JtiReplayOutcome.Replayed => RefuseUnderScheme(isDpopPresentation,
                OAuthErrors.InvalidDpopProof, "The DPoP proof jti has been presented previously."),
            JtiReplayOutcome.Unacceptable => RefuseUnderScheme(isDpopPresentation,
                OAuthErrors.InvalidDpopProof, "DPoP proof jti exceeds the length the replay guard can track."),
            JtiReplayOutcome.StoreUnavailable => ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "DPoP proof jti replay defense is required by policy but no jti store is configured."),

            _ => null
        };
    }


    /// <summary>
    /// Composes the <c>DPoP</c> challenge
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 §7.1</see> describes:
    /// "The scheme name is DPoP.", "An error parameter ([RFC6750], Section 3) SHOULD be included to
    /// indicate the reason why the request was declined, if the request included an access token but
    /// failed authentication.", "A scope authentication parameter MAY be included as defined in
    /// [RFC6750], Section 3." and "An algs parameter SHOULD be included". The <paramref name="error"/>
    /// and <paramref name="scope"/> are the library's own OAuth error and scope tokens, within the
    /// RFC 6750 §3 attribute charsets, so they need no quoted-pair escaping.
    /// </summary>
    /// <param name="error">The error code, for example <see cref="OAuthErrors.InvalidToken"/>.</param>
    /// <param name="scope">The scope the resource requires, or <see langword="null"/> for none.</param>
    /// <returns>The <c>WWW-Authenticate</c> value.</returns>
    internal static string BuildDpopChallenge(string error, string? scope = null) =>
        scope is null
            ? $"{WellKnownAuthenticationSchemes.DPoP} error=\"{error}\", algs=\"{AcceptedProofAlgorithms}\""
            : $"{WellKnownAuthenticationSchemes.DPoP} error=\"{error}\", scope=\"{scope}\", algs=\"{AcceptedProofAlgorithms}\"";


    /// <summary>
    /// Composes the challenge a request that carries no usable <c>Authorization</c> header is answered
    /// with: one value naming both schemes the resource accepts,
    /// <c>Bearer &lt;parameter&gt;, DPoP algs="…"</c>, with no <c>error</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>: "If the
    /// request lacks any authentication information (e.g., the client was unaware that authentication
    /// is necessary or attempted using an unsupported authentication method), the resource server
    /// SHOULD NOT include an error code or other error information." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 §7.2</see>: "If no
    /// authentication information has been included with the request, then the challenges SHOULD NOT
    /// include an error code or other error information". The <c>Bearer</c> challenge keeps the auth-param
    /// RFC 6750 §3 requires ("This scheme MUST be followed by one or more auth-param values"): the
    /// <c>scope</c> the resource requires when it names one, and otherwise the <c>realm</c> of the
    /// issuer the request is served under.
    /// </summary>
    /// <param name="bearerParameter">The <c>Bearer</c> challenge, <c>scope</c> or <c>realm</c>, composed by <see cref="BearerTokenChallenge.BuildChallenge"/>.</param>
    /// <returns>The <c>WWW-Authenticate</c> value.</returns>
    internal static string BuildMissingCredentialsChallenge(string bearerParameter) =>
        $"{bearerParameter}, {WellKnownAuthenticationSchemes.DPoP} algs=\"{AcceptedProofAlgorithms}\"";


    /// <summary>
    /// Answers a request to an OID4VCI protected endpoint that carries no usable <c>Authorization</c>
    /// header: 401 with an empty body, since
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see> says the
    /// resource server "SHOULD NOT include an error code or other error information", and the challenge
    /// of <see cref="BuildMissingCredentialsChallenge"/> whose <c>Bearer</c> part names the issuer the
    /// request is served under as its <c>realm</c> (the endpoints require no single scope).
    /// </summary>
    /// <param name="server">The authorization server whose issuer resolver names the realm.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The 401 refusal.</returns>
    internal static async ValueTask<ServerHttpResponse> RefuseMissingCredentialsAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        Uri issuerUri = await ResolveIssuerAsync(server, registration, context, cancellationToken)
            .ConfigureAwait(false);
        string challenge = BuildMissingCredentialsChallenge(
            BearerTokenChallenge.BuildChallenge(realm: HeaderSafeIssuer(issuerUri)));

        return ServerHttpResponse.Unauthorized()
            .WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, challenge);
    }


    /// <summary>
    /// The issuer in a form the <c>realm</c> quoted-string can carry. The realm's value is an
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4">RFC 9110 §5.6.4</see>
    /// quoted-string, whose characters are HTAB, SP and visible US-ASCII ("qdtext = HTAB / SP / %x21 /
    /// %x23-5B / %x5D-7E / obs-text", <c>"</c> and <c>\</c> through quoted-pair), while an issuer accepted by
    /// <see cref="IssuerIdentifier.Parse"/> may hold Unicode text. An issuer written
    /// in that repertoire is used as written. Otherwise it is mapped to its URI form as
    /// <see href="https://www.rfc-editor.org/rfc/rfc3987#section-3.1">RFC 3987 §3.1</see> maps an IRI: a
    /// non-ASCII host is written in its IDNA ASCII form ("Replace the ireg-name part of the IRI by the
    /// part converted using the ToASCII operation specified in section 4.1 of [RFC3490] on each
    /// dot-separated label"), and every other non-ASCII character is written as the percent-encoding of
    /// its UTF-8 octets ("Convert the character to a sequence of one or more octets using UTF-8" and
    /// "Convert each octet to %HH, where HH is the hexadecimal notation of the octet value").
    /// </summary>
    /// <param name="issuerUri">The issuer the request is served under.</param>
    /// <returns>The issuer text, in visible US-ASCII.</returns>
    private static string HeaderSafeIssuer(Uri issuerUri)
    {
        string original = issuerUri.OriginalString;
        if(IsVisibleAscii(original))
        {
            return original;
        }

        Uri asciiHost = IsVisibleAscii(issuerUri.Host)
            ? issuerUri
            : new UriBuilder(issuerUri) { Host = issuerUri.IdnHost }.Uri;

        return asciiHost.AbsoluteUri;
    }


    /// <summary>Whether every character of <paramref name="value"/> is a visible US-ASCII character (%x21-7E).</summary>
    /// <param name="value">The text.</param>
    /// <returns><see langword="true"/> when the text holds visible US-ASCII only.</returns>
    private static bool IsVisibleAscii(string value)
    {
        foreach(char c in value)
        {
            if(c is < '!' or > '~')
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Puts a refusal of a presented access token in the scheme the token was presented under: a 401
    /// that <see cref="BearerTokenValidation"/> built with its <c>Bearer error="invalid_token"</c>
    /// challenge is answered, for a <c>DPoP</c>-scheme presentation, with the <c>DPoP</c> challenge
    /// carrying the same error instead (RFC 9449 §7.2, "the corresponding challenge SHOULD be used to
    /// deliver error information"). Any other response is returned unchanged; a 500 server fault
    /// carries no challenge.
    /// </summary>
    /// <param name="refusal">The refusal <see cref="BearerTokenValidation"/> returned.</param>
    /// <param name="isDpopPresentation">Whether the token was presented under the <c>DPoP</c> scheme.</param>
    /// <returns>The refusal with the challenge of the presentation's scheme.</returns>
    internal static ServerHttpResponse InPresentationScheme(ServerHttpResponse refusal, bool isDpopPresentation) =>
        isDpopPresentation && refusal.StatusCode == 401
            ? refusal.WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, BuildDpopChallenge(OAuthErrors.InvalidToken))
            : refusal;


    /// <summary>
    /// Builds a 401 refusal carrying <paramref name="error"/> in the body and a challenge in the
    /// presentation's scheme: the <c>DPoP</c> challenge with the same error, or
    /// <c>Bearer error="invalid_token"</c> for a <c>Bearer</c> presentation (whose refusals here are all
    /// <c>invalid_token</c>).
    /// </summary>
    /// <param name="isDpopPresentation">Whether the token was presented under the <c>DPoP</c> scheme.</param>
    /// <param name="error">The error code.</param>
    /// <param name="description">The <c>error_description</c> the body carries.</param>
    /// <returns>The 401 response.</returns>
    private static ServerHttpResponse RefuseUnderScheme(bool isDpopPresentation, string error, string description) =>
        ServerHttpResponse.Unauthorized(error, description)
            .WithHeader(
                WellKnownHttpHeaderNames.WwwAuthenticate,
                isDpopPresentation ? BuildDpopChallenge(error) : BearerTokenValidation.InvalidTokenChallenge);


    /// <summary>
    /// Issues a fresh resource nonce and answers with the
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 §9</see> challenge: 401,
    /// <c>use_dpop_nonce</c> in the body and in the <c>DPoP</c> challenge, and the nonce in the
    /// <c>DPoP-Nonce</c> header: "Resource servers use an HTTP 401 (Unauthorized) error code with an
    /// accompanying WWW-Authenticate: DPoP value and DPoP-Nonce value to accomplish this."
    /// </summary>
    /// <param name="server">The authorization server holding the nonce issuance delegate.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="issuerUri">The issuer the nonce is bound to.</param>
    /// <param name="description">The <c>error_description</c> the body carries.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The 401 nonce challenge.</returns>
    private static async ValueTask<ServerHttpResponse> ChallengeForNonceAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        Uri issuerUri,
        string description,
        CancellationToken cancellationToken)
    {
        string freshNonce = await server.OAuth().IssueDpopNonceAsync!(
            issuerUri, registration.TenantId, context, cancellationToken).ConfigureAwait(false);

        return ServerHttpResponse
            .Unauthorized(OAuthErrors.UseDpopNonce, description)
            .WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, BuildDpopChallenge(OAuthErrors.UseDpopNonce))
            .WithHeader(WellKnownHttpHeaderNames.DPoPNonce, freshNonce);
    }


    /// <summary>
    /// Resolves the issuer the request is served under, through the application's
    /// <c>ResolveIssuerAsync</c> seam when wired and the default resolver otherwise; its authority is
    /// the one the proof's <c>htu</c> is compared against.
    /// </summary>
    /// <param name="server">The authorization server holding the resolver seam.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The issuer.</returns>
    private static async ValueTask<Uri> ResolveIssuerAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();

        return oauth.ResolveIssuerAsync is not null
            ? (await oauth.ResolveIssuerAsync(registration, context, cancellationToken)
                .ConfigureAwait(false))!
            : await DefaultIssuerResolver.ResolveAsync(registration, context, cancellationToken)
                .ConfigureAwait(false);
    }


    /// <summary>
    /// Reads <c>jkt</c> off a present <c>cnf</c> claim value, tolerating either dictionary view, or
    /// <see langword="null"/> when the value holds no non-blank string <c>jkt</c> (another confirmation
    /// method, or a value that is not an object).
    /// </summary>
    /// <param name="confirmation">The <c>cnf</c> claim's value.</param>
    /// <returns>The bound thumbprint, or <see langword="null"/>.</returns>
    private static string? ReadConfirmationThumbprint(object? confirmation)
    {
        if(confirmation is IReadOnlyDictionary<string, object> readOnly
            && readOnly.TryGetValue(WellKnownJwtClaimNames.JwkThumbprint, out object? jktValue)
            && jktValue is string jkt
            && !string.IsNullOrWhiteSpace(jkt))
        {
            return jkt;
        }

        if(confirmation is IDictionary<string, object> writable
            && writable.TryGetValue(WellKnownJwtClaimNames.JwkThumbprint, out object? jktValue2)
            && jktValue2 is string jkt2
            && !string.IsNullOrWhiteSpace(jkt2))
        {
            return jkt2;
        }

        return null;
    }
}
