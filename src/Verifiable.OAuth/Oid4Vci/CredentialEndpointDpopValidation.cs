using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth.AuthCode.Server;
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
/// Each endpoint issues its nonces for the target URI it serves and accepts only those
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "Note that the nonces
/// provided by an authorization server and a resource server are different and should not be confused with one
/// another since nonces will be only accepted by the server that issued them."), so a nonce the token endpoint
/// issued, or another resource endpoint's, is answered with the nonce challenge and a nonce of this endpoint's own.
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
/// fails a Section 4.3 check, <c>use_dpop_nonce</c> for a missing or stale nonce). The resource-server shape mirrors
/// <c>DpopTokenEndpointValidation</c> but adds the <c>ath</c> binding and computes <c>htm</c> and
/// <c>htu</c> from the request being served, so one enforcement serves an endpoint that answers more
/// than one HTTP method. The checks run in the one order of <see cref="DpopResourceAccess.DecideCoreAsync"/>, which an
/// application's own resource runs through <see cref="DpopResourceAccess.DecideAsync"/>; <see cref="EnforceAsync"/> is
/// the adapter over the authorization server's slots.
/// </para>
/// <para>
/// Every <c>DPoP</c> challenge of one request carries the parameters of its <see cref="ResourceChallengeContext"/>,
/// written by <see cref="DpopChallenge.BuildChallenge"/> in the order <c>realm</c>, <c>error</c>, <c>scope</c>,
/// <c>algs</c>: the <c>realm</c> of the protection space the resource serves, the issuer the request is served under
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "The authentication
/// parameter realm MAY be included to indicate the scope of protection in the manner described in [RFC9110], Section
/// 11.5."), the <c>scope</c> the resource requires when it names one ("A scope authentication parameter MAY be
/// included as defined in [RFC6750], Section 3."), and the <c>algs</c> the authorization server accepts for a DPoP
/// proof, the one slot <see cref="DpopTokenEndpointValidation.ResolveAcceptedProofAlgorithmsAsync"/> answers ("An algs
/// parameter SHOULD be included to signal to the client the JWS algorithms that are acceptable for the DPoP proof
/// JWT."), which the resource holds every proof to. No <c>error_description</c> is written into a challenge; the body
/// carries it. Every answer carrying a <c>DPoP</c> challenge carries the field
/// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c> (<see cref="WithDpopChallenge"/>; Section 7.1:
/// "the server needs to make it available to the application by including WWW-Authenticate in the
/// Access-Control-Expose-Headers response header list value").
/// </para>
/// </remarks>
internal static class CredentialEndpointDpopValidation
{
    /// <summary>
    /// The parameters every <c>DPoP</c> challenge of one request to a library resource carries, resolved once per
    /// request by <see cref="ResolveChallengeContextAsync"/>.
    /// </summary>
    /// <param name="Realm">
    /// The <c>realm</c>, the issuer the request is served under in its <see cref="HeaderSafeIssuer"/> form, or
    /// <see langword="null"/> when no issuer resolves or the issuer has no such form (<see cref="HeaderSafeRealm"/>),
    /// the challenge then sent without it.
    /// </param>
    /// <param name="Scope">The <c>scope</c> the resource requires, or <see langword="null"/> when it names none.</param>
    /// <param name="Algorithms">
    /// The JWS <c>alg</c> values the authorization server accepts for a DPoP proof, held to every proof the resource
    /// validates and written as <c>algs</c> where a proof can be accepted under them
    /// (<see cref="DpopProofValidator.AcceptableProofAlgorithms"/>); <see langword="null"/> when the host's resolver answered no list or a list
    /// holding a name outside the token grammar the library holds every <c>algs</c> name to
    /// (<see cref="DpopChallenge.IsToken"/>), the challenge then sent without <c>algs</c> and a presented proof answered
    /// <c>server_error</c>.
    /// </param>
    /// <param name="IsAlgorithmListUnusable">
    /// Whether <see cref="Algorithms"/> is <see langword="null"/> because the host's resolver answered a list holding a
    /// name that is no RFC 9110 Section 5.6.2 token, so a presented proof is answered with
    /// <see cref="DpopTokenEndpointValidation.AlgorithmResolverAnsweredUnusableListDescription"/> rather than
    /// <see cref="DpopTokenEndpointValidation.AlgorithmResolverAnsweredNoListDescription"/>.
    /// </param>
    internal sealed record ResourceChallengeContext(
        string? Realm, string? Scope, IReadOnlyList<string>? Algorithms, bool IsAlgorithmListUnusable);


    /// <summary>
    /// The reading of a request's <c>Authorization</c> field at a library resource: the access token and the scheme it
    /// was presented under, or the refusal a request without one token is answered with, beside the parameters of the
    /// <c>DPoP</c> challenges the request is answered with.
    /// </summary>
    /// <param name="AccessToken">The access token as presented, or <see langword="null"/> when <paramref name="Refusal"/> is set.</param>
    /// <param name="IsDpopPresentation">Whether the token was presented under the <c>DPoP</c> scheme.</param>
    /// <param name="Challenge">The parameters of every <c>DPoP</c> challenge of the request.</param>
    /// <param name="Refusal">The answer to a request that carries no one usable token, or <see langword="null"/>.</param>
    internal sealed record LibraryResourcePresentation(
        string? AccessToken, bool IsDpopPresentation, ResourceChallengeContext Challenge, ServerHttpResponse? Refusal);


    /// <summary>
    /// Resolves the parameters every <c>DPoP</c> challenge of the request carries: the <c>realm</c>, the
    /// <see cref="HeaderSafeIssuer"/> form of the issuer the request is served under; the <c>scope</c> the resource
    /// requires; and the <c>algs</c>, the algorithms the authorization server accepts for a DPoP proof
    /// (<see cref="DpopTokenEndpointValidation.ResolveAcceptedProofAlgorithmsAsync"/>, the one slot the token endpoint
    /// and the metadata read). An issuer that does not resolve, by the default resolver's refusal or by an application
    /// resolver that answers nothing, leaves the <c>realm</c> out and the challenge is still sent:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see>, "A server
    /// generating a 401 (Unauthorized) response MUST send a WWW-Authenticate header field containing at least one
    /// challenge."
    /// </summary>
    /// <remarks>
    /// <para>
    /// The issuer and the slot are the host's configuration, not the request's, and three of their answers are answered
    /// here by a decision rather than by an exception escaping the endpoint. An issuer that does not resolve
    /// (<see cref="TryResolveIssuerAsync"/>) leaves the <c>realm</c> out. An issuer that resolves to a value with no
    /// <see cref="HeaderSafeIssuer"/> form, a relative URI or one whose host the IDNA ToASCII operation does not map,
    /// leaves the <c>realm</c> out the same way (<see cref="HeaderSafeRealm"/>), the library's own reading. A slot answer
    /// holding a name that is no <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.2">RFC 9110 Section
    /// 5.6.2</see> token ("token = 1*tchar", each name non-empty and every character a tchar,
    /// <see cref="DpopChallenge.IsToken"/>) is read as no list, so the challenge is sent without <c>algs</c> and a
    /// presented proof is answered <c>server_error</c> with
    /// <see cref="DpopTokenEndpointValidation.AlgorithmResolverAnsweredUnusableListDescription"/>
    /// (<see cref="ResourceChallengeContext.IsAlgorithmListUnusable"/>), as a slot that answers no list is; the
    /// builder's refusal of a caller's argument (<see cref="DpopChallenge.BuildChallenge"/>) therefore never meets the
    /// slot's names. An empty list is a usable answer under which no proof is acceptable. Any other exception the
    /// issuer resolver or the slot's resolver raises passes to the caller.
    /// </para>
    /// <para>
    /// The token bound on an <c>algs</c> name is the library's chosen bound. The clauses that exclude any other name are
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>, "alg: An identifier
    /// for a JWS asymmetric digital signature algorithm from [IANA.JOSE.ALGS]", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>, check 5, the alg "indicates a
    /// registered asymmetric digital signature algorithm": every registered name is made of tchar only. A quoted-string
    /// could carry a Collision-Resistant Name
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515 Section 4.1.1</see>), which no DPoP
    /// proof may carry.
    /// </para>
    /// </remarks>
    /// <param name="server">The authorization server holding the issuer resolver and the algorithm slot.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="requiredScope">The scope the resource requires, or <see langword="null"/> when it names none.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The challenge parameters of the request.</returns>
    internal static async ValueTask<ResourceChallengeContext> ResolveChallengeContextAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        string? requiredScope,
        CancellationToken cancellationToken)
    {
        Uri? issuer = await TryResolveIssuerAsync(server, registration, context, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<string>? algorithms = await DpopTokenEndpointValidation.ResolveAcceptedProofAlgorithmsAsync(
            server.OAuth(), registration, context, cancellationToken).ConfigureAwait(false);
        bool isAlgorithmListUnusable = algorithms is not null && !algorithms.All(DpopChallenge.IsToken);

        return new ResourceChallengeContext(
            issuer is null ? null : HeaderSafeRealm(issuer),
            requiredScope,
            isAlgorithmListUnusable ? null : algorithms,
            isAlgorithmListUnusable);
    }


    /// <summary>
    /// Resolves the issuer the request is served under through <see cref="ResolveIssuerAsync"/>, answering
    /// <see langword="null"/> where none resolves: the default resolver refuses with
    /// <see cref="InvalidOperationException"/> and an application resolver may answer nothing. An application resolver's
    /// own <see cref="InvalidOperationException"/>, its subclass <see cref="ObjectDisposedException"/> included, is read
    /// the same way, as no issuer; any other exception the resolver raises passes to the caller.
    /// </summary>
    /// <param name="server">The authorization server holding the resolver seam.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The issuer, or <see langword="null"/>.</returns>
    private static async ValueTask<Uri?> TryResolveIssuerAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            Uri? issuer = await ResolveIssuerAsync(server, registration, context, cancellationToken).ConfigureAwait(false);

            return issuer;
        }
        catch(InvalidOperationException)
        {
            return null;
        }
    }


    /// <summary>
    /// The <c>realm</c> the issuer the request is served under is written as, <see cref="HeaderSafeIssuer"/>'s text, or
    /// <see langword="null"/> where the issuer has no such form: a relative URI, which names no host, and an issuer whose
    /// host the IDNA ToASCII operation does not map (<see href="https://www.rfc-editor.org/rfc/rfc3987#section-3.1">RFC
    /// 3987 Section 3.1</see>: the ireg-name "converted using the ToASCII operation specified in section 4.1 of
    /// [RFC3490]"), for which <see cref="Uri.IdnHost"/> raises <see cref="UriFormatException"/>. The issuer is the
    /// host's configuration, and the library reads such an issuer as no realm, its own reading, as it reads an issuer
    /// that does not resolve: the challenge is still sent without <c>realm</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see>: "A server
    /// generating a 401 (Unauthorized) response MUST send a WWW-Authenticate header field containing at least one
    /// challenge.").
    /// </summary>
    /// <param name="issuer">The issuer the request is served under.</param>
    /// <returns>The realm text in visible US-ASCII, or <see langword="null"/> where the issuer has no such form.</returns>
    private static string? HeaderSafeRealm(Uri issuer)
    {
        if(!issuer.IsAbsoluteUri)
        {
            return null;
        }

        try
        {
            return HeaderSafeIssuer(issuer);
        }
        catch(UriFormatException)
        {
            return null;
        }
    }


    /// <summary>
    /// Attaches the <c>DPoP</c> challenge <paramref name="challenge"/> to <paramref name="response"/> as its
    /// <c>WWW-Authenticate</c> field, with the field <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>
    /// (<see cref="WellKnownDpopValues.ExposedDpopResponseFields"/>), through <see cref="DpopResourceAccess.WithDpopChallenge"/>,
    /// the one place a <c>DPoP</c> challenge is attached, so every such answer exposes its fields to a browser application.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "In order for the
    /// application to obtain and use the WWW-Authenticate HTTP response header value, the server needs to make it
    /// available to the application by including WWW-Authenticate in the Access-Control-Expose-Headers response header
    /// list value." and <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">Section 8</see>: "including
    /// DPoP-Nonce in the Access-Control-Expose-Headers response header list value", which
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">Section 9</see> carries to resource servers.
    /// </summary>
    /// <param name="response">The answer the challenge is attached to.</param>
    /// <param name="challenge">The <c>WWW-Authenticate</c> value, holding a <c>DPoP</c> challenge.</param>
    /// <returns>The answer with its challenge and the exposure field.</returns>
    internal static ServerHttpResponse WithDpopChallenge(ServerHttpResponse response, string challenge) =>
        DpopResourceAccess.WithDpopChallenge(response, challenge);


    /// <summary>
    /// Reads the presentation of a request to a library resource, UserInfo and the OID4VCI Credential, Deferred
    /// Credential and Notification endpoints: resolves the challenge parameters once
    /// (<see cref="ResolveChallengeContextAsync"/>), reads the <c>Authorization</c> field once, answers a field sent on
    /// two or more lines through <see cref="RefuseRepeatedField"/>, a line naming <c>Bearer</c> or <c>DPoP</c> with
    /// credentials outside token68 through <see cref="RefuseCredentialOutsideToken68"/> (400 <c>invalid_request</c> under
    /// the named scheme's challenge alone), a field carrying no access token through
    /// <see cref="RefuseMissingCredentials"/>, and otherwise answers the token and the scheme it was presented under.
    /// </summary>
    /// <remarks>
    /// When the server's resources require DPoP-bound access tokens
    /// (<see cref="AuthorizationServerIntegration.IsDpopBoundAccessTokenRequiredAtResources"/>), the resource is a
    /// protection space requiring DPoP authentication
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>;
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>,
    /// <c>dpop_bound_access_tokens_required</c>) and the <c>DPoP</c> scheme is the one mechanism it accepts, so every
    /// answer here carries the <c>DPoP</c> challenge alone, before any token is validated: a <c>DPoP</c> credential outside
    /// token68 is answered 400 <c>invalid_request</c> as without the requirement, and a <c>Bearer</c> credential of any
    /// shape as a <c>Bearer</c> presentation
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "Upon receipt of a
    /// request to a protected resource within the protection space requiring DPoP authentication, the server can respond
    /// with a challenge to the client to provide DPoP authentication information if the request does not include valid
    /// credentials or does not contain an access token sufficient for access."): a request carrying no access token and
    /// one presenting a token under the <c>Bearer</c> scheme 401 with an empty body and no <c>error</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "If the request
    /// lacks any authentication information (e.g., the client was unaware that authentication is necessary or attempted
    /// using an unsupported authentication method), the resource server SHOULD NOT include an error code or other error
    /// information."), and a field sent on two or more lines 400 <c>invalid_request</c> (RFC 6750 Section 3.1:
    /// "invalid_request The request is missing a required parameter, includes an unsupported parameter or parameter value,
    /// repeats the same parameter, uses more than one method for including an access token, or is otherwise malformed.
    /// The resource server SHOULD respond with the HTTP 400 (Bad Request) status code.").
    /// </remarks>
    /// <param name="server">The authorization server holding the issuer resolver and the algorithm slot.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="context">The per-request context carrying the inbound request.</param>
    /// <param name="requiredScope">The scope the resource requires, or <see langword="null"/> when it names none.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The presentation, or the refusal it is answered with.</returns>
    internal static async ValueTask<LibraryResourcePresentation> ReadPresentationAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        string? requiredScope,
        CancellationToken cancellationToken)
    {
        ResourceChallengeContext challenge = await ResolveChallengeContextAsync(
            server, registration, context, requiredScope, cancellationToken).ConfigureAwait(false);
        bool isDpopBoundAccessTokenRequired = server.OAuth().IsDpopBoundAccessTokenRequiredAtResources;
        AuthorizationFieldReading authorization = BearerTokenValidation.ReadAuthorizationField(context);
        if(authorization.IsRepeated)
        {
            ServerHttpResponse repeatedFieldRefusal = isDpopBoundAccessTokenRequired switch
            {
                true => WithDpopChallenge(
                    ServerHttpResponse.BadRequest(OAuthErrors.InvalidRequest, WellKnownOAuthErrorDescriptions.MalformedAuthorizationField),
                    BuildDpopChallenge(OAuthErrors.InvalidRequest, challenge)),
                false => RefuseRepeatedField(authorization, challenge.Realm, challenge)
            };

            return new LibraryResourcePresentation(null, false, challenge, repeatedFieldRefusal);
        }

        //RFC 6750 Section 3.1: a credential of an access token scheme outside the token68 form is "otherwise malformed",
        //invalid_request; RFC 9449 Section 7.2: the scheme the line names establishes the mechanism, whose challenge
        //delivers the error. Under the requirement a Bearer credential of any shape attempted a method the resource does
        //not accept and is answered below with the DPoP challenge alone.
        bool isDpopScheme = authorization.IsScheme(WellKnownAuthenticationSchemes.DPoP);
        if(IsAccessTokenCredentialOutsideToken68(authorization) && (isDpopScheme || !isDpopBoundAccessTokenRequired))
        {
            return new LibraryResourcePresentation(null, false, challenge, RefuseCredentialOutsideToken68(isDpopScheme, challenge));
        }

        bool hasAccessToken = BearerTokenValidation.TryExtractAccessToken(authorization, out string? accessToken, out bool isDpopPresentation);
        if(isDpopBoundAccessTokenRequired && (!hasAccessToken || !isDpopPresentation))
        {
            return new LibraryResourcePresentation(
                null, false, challenge, WithDpopChallenge(ServerHttpResponse.Unauthorized(), BuildDpopChallenge(null, challenge)));
        }

        if(!hasAccessToken)
        {
            return new LibraryResourcePresentation(null, false, challenge, RefuseMissingCredentials(challenge));
        }

        return new LibraryResourcePresentation(accessToken, isDpopPresentation, challenge, null);
    }


    /// <summary>
    /// Whether the one <c>Authorization</c> field line names an access token scheme, <c>Bearer</c> or <c>DPoP</c>
    /// compared case-insensitively, with credentials that are no token68: "credentials = "Bearer" 1*SP b64token"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>) and "credentials =
    /// "DPoP" 1*SP token68" (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>).
    /// A line naming the scheme alone carries no credentials and is no such attempt.
    /// </summary>
    /// <param name="authorization">The request's <c>Authorization</c> field reading, a single line or none.</param>
    /// <returns><see langword="true"/> when the line attempts an access token scheme with a malformed credential.</returns>
    private static bool IsAccessTokenCredentialOutsideToken68(AuthorizationFieldReading authorization) =>
        (authorization.IsScheme(WellKnownAuthenticationSchemes.Bearer) || authorization.IsScheme(WellKnownAuthenticationSchemes.DPoP))
        && authorization.Credentials is { Length: > 0 }
        && !authorization.HasToken68Credentials;


    /// <summary>
    /// The answer to an access token credential outside the token68 form: 400 <c>invalid_request</c> with
    /// <see cref="WellKnownOAuthErrorDescriptions.CredentialOutsideToken68"/>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_request The
    /// request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same
    /// parameter, uses more than one method for including an access token, or is otherwise malformed. The resource server
    /// SHOULD respond with the HTTP 400 (Bad Request) status code."), and the challenge of the scheme the line names alone
    /// carrying that error (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>:
    /// "If the mechanism used to attempt authentication could be established unambiguously, then the corresponding
    /// challenge SHOULD be used to deliver error information (Figure 18)."): the <c>DPoP</c> challenge through
    /// <see cref="WithDpopChallenge"/>, or the <c>Bearer</c> challenge with the realm where the resource has one.
    /// </summary>
    /// <param name="isDpopScheme">Whether the line names the <c>DPoP</c> scheme.</param>
    /// <param name="challenge">The parameters every <c>DPoP</c> challenge of the request carries.</param>
    /// <returns>The 400 refusal with its challenge.</returns>
    private static ServerHttpResponse RefuseCredentialOutsideToken68(bool isDpopScheme, ResourceChallengeContext challenge)
    {
        ServerHttpResponse refusal = ServerHttpResponse.BadRequest(OAuthErrors.InvalidRequest, WellKnownOAuthErrorDescriptions.CredentialOutsideToken68);

        return isDpopScheme switch
        {
            true => WithDpopChallenge(refusal, BuildDpopChallenge(OAuthErrors.InvalidRequest, challenge)),
            false => refusal.WithHeader(
                WellKnownHttpHeaderNames.WwwAuthenticate,
                BearerTokenChallenge.BuildChallenge(realm: challenge.Realm, error: OAuthErrors.InvalidRequest))
        };
    }


    /// <summary>
    /// Returns the failure response to return, or <see langword="null"/> when the sender
    /// constraint is satisfied or the token is an ordinary bearer token presented under the
    /// <c>Bearer</c> scheme: the library resources' adapter over <see cref="DpopResourceAccess.DecideCoreAsync"/>, the
    /// one order of the RFC 9449 Section 7.1 checks an application's resource runs through
    /// <see cref="DpopResourceAccess.DecideAsync"/>. The presentation is the token's <c>cnf</c>
    /// (<see cref="ReadConfirmationThumbprint"/>), the request's method and every <c>DPoP</c> field line; the checks are
    /// the authorization server's slots (the proof validation <see cref="DpopRequestReading.ValidateProofAsync"/> runs,
    /// <see cref="AuthorizationServerIntegration.IssueDpopNonceAsync"/> and
    /// <see cref="AuthorizationServerIntegration.ValidateDpopNonceAsync"/> under the registration's tenant), the
    /// replay guard's atomic claim (<see cref="JtiReplayGuard.ConsultDpopProofAsync"/>, the issuer's text and the target
    /// URI) and the <c>Bearer</c> refusal's <see cref="BearerTokenValidation.InvalidTokenChallenge"/>. The target URI is
    /// composed by <see cref="DpopRequestReading.ComposeTargetUri"/> from the issuer resolved only once the checks reach
    /// the proof, and is the audience of the resource's nonces
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "nonces will be only
    /// accepted by the server that issued them"). A token whose <c>cnf</c> carries a blank <c>jkt</c>
    /// (<see cref="JwsAccessTokenValidator.IsBlankJwkThumbprint"/>, the rule the token validator refuses it by as
    /// malformed) is refused 401 <c>invalid_token</c> with <see cref="JwsAccessTokenValidator.BlankJwkThumbprintDescription"/>
    /// in the challenge of the scheme it was presented under (<see cref="InPresentationScheme"/>), before the checks run.
    /// </summary>
    /// <param name="server">The authorization server holding the DPoP delegates and the issuer resolver.</param>
    /// <param name="context">The per-request context carrying the inbound request.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="accessToken">The validated Access Token's payload.</param>
    /// <param name="rawAccessToken">The Access Token exactly as presented, the value <c>ath</c> hashes.</param>
    /// <param name="isDpopPresentation">Whether the token was presented under the <c>DPoP</c> scheme.</param>
    /// <param name="challenge">
    /// The parameters every <c>DPoP</c> challenge of the request carries; its <see cref="ResourceChallengeContext.Algorithms"/>
    /// are the algorithms a proof is held to (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449
    /// Section 4.3</see>, check 5: the alg "is supported by the application, and is acceptable per local policy").
    /// </param>
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
        ResourceChallengeContext challenge,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        IncomingRequest? request = context.IncomingRequest;
        bool isSenderConstrained = accessToken.TryGetValue(WellKnownJwtClaimNames.Cnf, out object? confirmation);

        //RFC 9449 Section 6.1: a jkt "MUST be the base64url encoding (as defined in [RFC7515]) of the JWK SHA-256
        //Thumbprint"; a blank one binds the token to no key and the token is malformed (RFC 6750 Section 3.1,
        //invalid_token), refused in the scheme it was presented under before any proof is judged, under the one rule the
        //token validator holds a cnf to.
        if(isSenderConstrained && JwsAccessTokenValidator.IsBlankJwkThumbprint(confirmation))
        {
            return InPresentationScheme(
                ServerHttpResponse.Unauthorized(OAuthErrors.InvalidToken, JwsAccessTokenValidator.BlankJwkThumbprintDescription)
                    .WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, BearerTokenValidation.InvalidTokenChallenge),
                isDpopPresentation,
                challenge);
        }

        IReadOnlyList<string>? dpopFieldLines = null;
        _ = request?.Headers.TryGetAll(WellKnownHttpHeaderNames.DPoP, out dpopFieldLines);

        DpopResourceAccess.DpopResourcePresentation presentation = new(
            rawAccessToken,
            isDpopPresentation,
            isSenderConstrained,
            isSenderConstrained ? ReadConfirmationThumbprint(confirmation) : null,
            request?.Method ?? string.Empty,
            dpopFieldLines ?? [],
            oauth.IsDpopBoundAccessTokenRequiredAtResources);

        //RFC 9449 Section 4.3: the htm claim matches the HTTP method of the current request, and the htu claim its
        //target URI, its authority the listener authority the host stamped when it names one and the issuer's otherwise
        //(RFC 9110 Section 7.1). The issuer is resolved once, when the checks reach the proof, and its text keys the
        //proof's jti record beside the target.
        Uri? resolvedIssuer = null;
        IssueDpopNonceDelegate? issueNonce = oauth.IssueDpopNonceAsync;
        ValidateDpopNonceDelegate? validateNonce = oauth.ValidateDpopNonceAsync;
        DpopResourceAccess.DpopResourceChecks checks = new()
        {
            ResolveTargetUriAsync = async ct =>
            {
                resolvedIssuer = await ResolveIssuerAsync(server, registration, context, ct).ConfigureAwait(false);

                return new Uri(DpopRequestReading.ComposeTargetUri(context.IncomingRequest!, resolvedIssuer));
            },
            ValidateProofAsync = DpopRequestReading.IsProofValidationWired(oauth)
                ? (proofRequest, ct) => DpopRequestReading.ValidateProofAsync(oauth, server.TimeProvider, proofRequest, ct)
                : null,
            IssueNonceAsync = issueNonce is null
                ? null
                : (audience, ct) => issueNonce(audience, registration.TenantId, context, ct),
            ValidateNonceAsync = validateNonce is null
                ? null
                : (nonce, audience, ct) => validateNonce(nonce, audience, registration.TenantId, context, ct),
            //The guard keeps the record for the replay window from the request's instant, as the token endpoint does, so
            //the proof's iat is not read here.
            ConsultJtiAsync = (target, jti, _, ct) => JtiReplayGuard.ConsultDpopProofAsync(
                server, context, registration.TenantId, resolvedIssuer!.OriginalString, target.OriginalString, jti,
                now + WellKnownDpopValues.DefaultReplayWindow, ct),
            AcceptedAlgorithms = challenge.Algorithms,
            AlgorithmListFailureDescription = challenge.IsAlgorithmListUnusable switch
            {
                true => DpopTokenEndpointValidation.AlgorithmResolverAnsweredUnusableListDescription,
                false => DpopTokenEndpointValidation.AlgorithmResolverAnsweredNoListDescription
            },
            JtiStoreUnavailableDescription = DpopResourceAccess.JtiReplayDefenseCouldNotRecordDescription,
            BearerChallenge = BearerTokenValidation.InvalidTokenChallenge,
            Realm = challenge.Realm,
            Scope = challenge.Scope
        };

        DpopResourceDecision decision = await DpopResourceAccess.DecideCoreAsync(presentation, checks, cancellationToken).ConfigureAwait(false);

        return decision.Response;
    }


    /// <summary>
    /// Composes the <c>DPoP</c> challenge
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see> describes through
    /// <see cref="DpopChallenge.BuildChallenge"/>: "The scheme name is DPoP.", the <c>realm</c> and the <c>scope</c> of
    /// <paramref name="challenge"/>, "An error parameter ([RFC6750], Section 3) SHOULD be included to indicate the reason
    /// why the request was declined, if the request included an access token but failed authentication." and "An algs
    /// parameter SHOULD be included to signal to the client the JWS algorithms that are acceptable for the DPoP proof
    /// JWT.", the algorithms of <paramref name="challenge"/> a proof can be accepted under
    /// (<see cref="DpopProofValidator.AcceptableProofAlgorithms"/>), the parameter absent when none remains. The
    /// <paramref name="error"/> is one of the library's own OAuth error codes, within the RFC 6750 Section 3 attribute
    /// charset.
    /// </summary>
    /// <param name="error">The error code, for example <see cref="OAuthErrors.InvalidToken"/>, or <see langword="null"/> for none.</param>
    /// <param name="challenge">The parameters every <c>DPoP</c> challenge of the request carries.</param>
    /// <returns>The <c>WWW-Authenticate</c> value.</returns>
    internal static string BuildDpopChallenge(string? error, ResourceChallengeContext challenge) =>
        DpopChallenge.BuildChallenge(
            challenge.Realm,
            error,
            challenge.Scope,
            challenge.Algorithms is IReadOnlyList<string> algorithms ? DpopProofValidator.AcceptableProofAlgorithms(algorithms) : null);


    /// <summary>
    /// Composes the challenge a request that carries no usable <c>Authorization</c> header is answered
    /// with: one value naming both schemes the resource accepts,
    /// <c>Bearer &lt;parameter&gt;, DPoP realm="...", algs="..."</c>, with no <c>error</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>: "If the
    /// request lacks any authentication information (e.g., the client was unaware that authentication
    /// is necessary or attempted using an unsupported authentication method), the resource server
    /// SHOULD NOT include an error code or other error information." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 §7.2</see>: "If no
    /// authentication information has been included with the request, then the challenges SHOULD NOT
    /// include an error code or other error information". The <c>Bearer</c> challenge keeps the auth-param
    /// RFC 6750 §3 requires ("This scheme MUST be followed by one or more auth-param values"): the
    /// <c>scope</c> the resource requires when it names one, and otherwise the <c>realm</c> of the
    /// issuer the request is served under. The <c>DPoP</c> challenge is <see cref="BuildDpopChallenge"/>'s with no
    /// <c>error</c>.
    /// </summary>
    /// <param name="bearerChallenge">The <c>Bearer</c> challenge, <c>scope</c> or <c>realm</c>, composed by <see cref="BearerTokenChallenge.BuildChallenge"/>.</param>
    /// <param name="challenge">The parameters every <c>DPoP</c> challenge of the request carries.</param>
    /// <returns>The <c>WWW-Authenticate</c> value.</returns>
    internal static string BuildMissingCredentialsChallenge(string bearerChallenge, ResourceChallengeContext challenge) =>
        $"{bearerChallenge}, {BuildDpopChallenge(null, challenge)}";


    /// <summary>
    /// Answers a request to a library resource that carries no usable <c>Authorization</c> field: 401 with an empty
    /// body, since <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see> says the resource
    /// server "SHOULD NOT include an error code or other error information", and the challenge of
    /// <see cref="BuildMissingCredentialsChallenge"/>, attached through <see cref="WithDpopChallenge"/>, whose
    /// <c>Bearer</c> part names the scope the resource requires or, where it names none, the realm. A resource that names
    /// no scope at a server where no issuer resolves leaves the <c>Bearer</c> challenge no auth-param to carry
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see>: "This scheme MUST be
    /// followed by one or more auth-param values."): the fault is the server's own wiring, and the request is answered
    /// 500 <c>server_error</c> with <see cref="WellKnownOAuthErrorDescriptions.ServerNotReady"/> and no challenge, as a
    /// token validation answers an issuer that does not resolve.
    /// </summary>
    /// <param name="challenge">The parameters every <c>DPoP</c> challenge of the request carries.</param>
    /// <returns>The 401 refusal, or the 500 answer to an unresolved issuer.</returns>
    private static ServerHttpResponse RefuseMissingCredentials(ResourceChallengeContext challenge)
    {
        string? bearerChallenge = challenge switch
        {
            { Scope: string scope } => BearerTokenChallenge.BuildChallenge(scope: scope),
            { Realm: string realm } => BearerTokenChallenge.BuildChallenge(realm: realm),

            _ => null
        };

        return bearerChallenge is null
            ? ServerHttpResponse.ServerError(OAuthErrors.ServerError, WellKnownOAuthErrorDescriptions.ServerNotReady)
            : WithDpopChallenge(ServerHttpResponse.Unauthorized(), BuildMissingCredentialsChallenge(bearerChallenge, challenge));
    }


    /// <summary>
    /// The issuer in a form the <c>realm</c> quoted-string can carry. The realm's value is an
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4">RFC 9110 §5.6.4</see>
    /// quoted-string, whose characters are HTAB, SP and visible US-ASCII ("qdtext = HTAB / SP / %x21 /
    /// %x23-5B / %x5D-7E / obs-text", <c>"</c> and <c>\</c> through quoted-pair), while an issuer accepted by
    /// <see cref="IssuerIdentifier.Parse"/> may hold Unicode text. An issuer written
    /// in that repertoire is used as written. Otherwise it is mapped to its URI form as
    /// <see href="https://www.rfc-editor.org/rfc/rfc3987#section-3.1">RFC 3987 Section 3.1</see> maps an IRI. A
    /// non-ASCII host is written in its IDNA ASCII form, the conversion of the ireg-name the section
    /// permits a system accepting IRIs to apply before its step 2: "Replace the ireg-name part of the IRI
    /// by the part converted using the ToASCII operation specified in section 4.1 of [RFC3490] on each
    /// dot-separated label, and by using U+002E (FULL STOP) as a label separator, with the flag
    /// UseSTD3ASCIIRules set to TRUE, and with the flag AllowUnassigned set to FALSE for creating IRIs and
    /// set to TRUE otherwise." Every other non-ASCII character is written as the percent-encoding of its
    /// UTF-8 octets, the section's steps 2.1 and 2.2: "Convert the character to a sequence of one or more
    /// octets using UTF-8 [RFC3629]." and "Convert each octet to %HH, where HH is the hexadecimal notation
    /// of the octet value."
    /// </summary>
    /// <param name="issuerUri">The issuer the request is served under.</param>
    /// <returns>The issuer text, in visible US-ASCII.</returns>
    internal static string HeaderSafeIssuer(Uri issuerUri)
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
    internal static bool IsVisibleAscii(string value)
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
    /// deliver error information"), attached through <see cref="WithDpopChallenge"/>. Any other response is returned
    /// unchanged; a 500 server fault carries no challenge.
    /// </summary>
    /// <param name="refusal">The refusal <see cref="BearerTokenValidation"/> returned.</param>
    /// <param name="isDpopPresentation">Whether the token was presented under the <c>DPoP</c> scheme.</param>
    /// <param name="challenge">The parameters every <c>DPoP</c> challenge of the request carries.</param>
    /// <returns>The refusal with the challenge of the presentation's scheme.</returns>
    internal static ServerHttpResponse InPresentationScheme(
        ServerHttpResponse refusal, bool isDpopPresentation, ResourceChallengeContext challenge) =>
        isDpopPresentation && refusal.StatusCode == 401
            ? WithDpopChallenge(refusal, BuildDpopChallenge(OAuthErrors.InvalidToken, challenge))
            : refusal;


    /// <summary>
    /// Attaches to <paramref name="refusal"/> the <c>WWW-Authenticate</c> challenge
    /// <c>Bearer realm="&lt;issuer&gt;"</c>, with <c>error="&lt;error&gt;"</c> when
    /// <paramref name="error"/> is given and <c>resource_metadata="&lt;URL&gt;"</c> when
    /// <paramref name="resourceMetadata"/> is given, built by <see cref="BearerTokenChallenge.BuildChallenge"/>.
    /// The realm is <see cref="HeaderSafeIssuer"/> of the resolved <paramref name="issuer"/>, so an
    /// internationalized issuer is written in its URI form; <see cref="HeaderSafeIssuer"/> throws for an issuer
    /// whose host IDNA cannot map, and that issuer is the application's own configuration, the one its tokens are
    /// issued under. The caller resolves the issuer once for the refusal, through <see cref="ChallengedAsync"/> or
    /// <see cref="ResolveIssuerAsync"/>, so every parameter the challenge derives from the issuer is read from that
    /// one resolution. The Bearer refusals of <see cref="Logout.GlobalTokenRevocationEndpoints"/>,
    /// <see cref="Server.Registration.RegistrationEndpoints"/> and <see cref="Ssf.SsfTransmitterEndpoints"/> are
    /// challenged through this one body.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2">RFC 9110 Section 15.5.2</see>:
    /// "The server generating a 401 response MUST send a WWW-Authenticate header field (Section 11.6.1)
    /// containing at least one challenge applicable to the target resource."
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see>: "All
    /// challenges defined by this specification MUST use the auth-scheme value "Bearer"." The
    /// <c>error</c> is the <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750
    /// Section 3.1</see> code of the refusal, the same code its body carries.
    /// </summary>
    /// <param name="refusal">The 401 or 403 refusal the challenge is attached to.</param>
    /// <param name="error">The RFC 6750 Section 3.1 error code, or <see langword="null"/> when the request carried no access token.</param>
    /// <param name="issuer">The issuer the request is served under, resolved once for the refusal; the realm.</param>
    /// <param name="resourceMetadata">
    /// The <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.1">RFC 9728 Section 5.1</see> protected
    /// resource metadata URL the challenge names, or <see langword="null"/> for none.
    /// </param>
    /// <returns>The refusal with its challenge.</returns>
    internal static ServerHttpResponse Challenged(
        ServerHttpResponse refusal,
        string? error,
        Uri issuer,
        Uri? resourceMetadata = null)
    {
        string challenge = BearerTokenChallenge.BuildChallenge(
            realm: HeaderSafeIssuer(issuer), error: error, resourceMetadata: resourceMetadata);

        return refusal.WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, challenge);
    }


    /// <summary>
    /// Resolves the issuer the request is served under once, through <see cref="ResolveIssuerAsync"/>, and attaches
    /// the challenge through <see cref="Challenged"/>, the one body. The default issuer resolver throws
    /// <see cref="InvalidOperationException"/> when no issuer resolves.
    /// </summary>
    /// <param name="refusal">The 401 or 403 refusal the challenge is attached to.</param>
    /// <param name="error">The RFC 6750 Section 3.1 error code, or <see langword="null"/> when the request carried no access token.</param>
    /// <param name="server">The authorization server whose issuer resolver names the realm.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The refusal with its challenge.</returns>
    internal static async ValueTask<ServerHttpResponse> ChallengedAsync(
        ServerHttpResponse refusal,
        string? error,
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        Uri issuer = await ResolveIssuerAsync(
            server, registration, context, cancellationToken).ConfigureAwait(false);

        return Challenged(refusal, error, issuer);
    }


    /// <summary>
    /// Answers a request to the client configuration endpoint (<see cref="Server.Registration.RegistrationEndpoints"/>),
    /// which reads a Bearer token only, whose <c>Authorization</c> field is sent on two or more field lines
    /// (<see cref="AuthorizationFieldReading.IsRepeated"/>): 400 <c>invalid_request</c>,
    /// <see cref="WellKnownOAuthErrorDescriptions.MalformedAuthorizationField"/> and the one challenge
    /// <c>Bearer realm="&lt;issuer&gt;", error="invalid_request"</c> (<see cref="RefuseRepeatedField"/> with no
    /// <c>DPoP</c> challenge), the realm the issuer <see cref="ResolveIssuerAsync"/> resolves.
    /// <c>Authorization = credentials</c> is no list
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC 9110 Section 11.6.2</see>). UserInfo and the
    /// OID4VCI resources, which accept the <c>DPoP</c> scheme, answer a repeated field through
    /// <see cref="ReadPresentationAsync"/>, which reads the scope they require.
    /// </summary>
    /// <param name="server">The authorization server whose issuer resolver names the realm.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The 400 refusal with its challenge.</returns>
    internal static async ValueTask<ServerHttpResponse> RefuseRepeatedAuthorizationAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        AuthorizationFieldReading authorization = BearerTokenValidation.ReadAuthorizationField(context);
        Uri issuer = await ResolveIssuerAsync(server, registration, context, cancellationToken).ConfigureAwait(false);

        return RefuseRepeatedField(authorization, HeaderSafeIssuer(issuer), dpopChallenge: null);
    }


    /// <summary>
    /// The 400 <c>invalid_request</c> answer to an <c>Authorization</c> field sent on two or more field lines, with
    /// <see cref="WellKnownOAuthErrorDescriptions.MalformedAuthorizationField"/> and the challenge of the mechanism the
    /// lines attempt. <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see> names
    /// the code: "invalid_request The request is missing a required parameter, includes an unsupported parameter or
    /// parameter value, repeats the same parameter, uses more than one method for including an access token, or is
    /// otherwise malformed.  The resource server SHOULD respond with the HTTP 400 (Bad Request) status code."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see> says which challenge
    /// carries the error: "If the mechanism used to attempt authentication could be established unambiguously, then the
    /// corresponding challenge SHOULD be used to deliver error information (Figure 18)." and "Otherwise, both Bearer and
    /// DPoP challenges MAY be used to deliver error information (Figure 19)." At a resource that accepts the
    /// <c>DPoP</c> scheme, lines that all name <c>DPoP</c> (<see cref="AuthorizationFieldReading.RepeatedScheme"/>) are
    /// answered with the <c>DPoP</c> challenge alone, lines that all name <c>Bearer</c> with the <c>Bearer</c> challenge
    /// alone, and any other lines with both, the <c>Bearer</c> one first; a <c>DPoP</c> challenge is attached through
    /// <see cref="WithDpopChallenge"/>. Without a <c>DPoP</c> challenge the <c>Bearer</c> one is sent alone.
    /// </summary>
    /// <param name="authorization">The request's <c>Authorization</c> field reading, a repeated field.</param>
    /// <param name="bearerRealm">The <c>realm</c> of the <c>Bearer</c> challenge, or <see langword="null"/> where no issuer resolves.</param>
    /// <param name="dpopChallenge">The parameters of the <c>DPoP</c> challenge, or <see langword="null"/> at a resource that accepts no <c>DPoP</c> scheme.</param>
    /// <returns>The 400 refusal with its challenge.</returns>
    private static ServerHttpResponse RefuseRepeatedField(
        AuthorizationFieldReading authorization, string? bearerRealm, ResourceChallengeContext? dpopChallenge)
    {
        ServerHttpResponse refusal = ServerHttpResponse.BadRequest(
            OAuthErrors.InvalidRequest, WellKnownOAuthErrorDescriptions.MalformedAuthorizationField);
        string bearerChallenge = BearerTokenChallenge.BuildChallenge(realm: bearerRealm, error: OAuthErrors.InvalidRequest);
        if(dpopChallenge is null)
        {
            return refusal.WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, bearerChallenge);
        }

        string challenge = BuildDpopChallenge(OAuthErrors.InvalidRequest, dpopChallenge);

        return authorization.RepeatedScheme switch
        {
            string scheme when WellKnownAuthenticationSchemes.Equals(scheme, WellKnownAuthenticationSchemes.DPoP) =>
                WithDpopChallenge(refusal, challenge),
            string scheme when WellKnownAuthenticationSchemes.Equals(scheme, WellKnownAuthenticationSchemes.Bearer) =>
                refusal.WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, bearerChallenge),

            _ => WithDpopChallenge(refusal, $"{bearerChallenge}, {challenge}")
        };
    }


    /// <summary>
    /// Resolves the issuer the request is served under, through the application's
    /// <c>ResolveIssuerAsync</c> seam when wired and the default resolver otherwise; its authority is
    /// the one the proof's <c>htu</c> is compared against, its <see cref="HeaderSafeIssuer"/> form is
    /// the <c>realm</c> of the challenges this class answers with and <see cref="Challenged"/>
    /// attaches, and <see cref="Ssf.SsfTransmitterEndpoints"/> reads it for its configuration document
    /// and, once per refusal, for the realm and the <c>resource_metadata</c> URL of its challenge.
    /// </summary>
    /// <param name="server">The authorization server holding the resolver seam.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The issuer.</returns>
    internal static async ValueTask<Uri> ResolveIssuerAsync(
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
