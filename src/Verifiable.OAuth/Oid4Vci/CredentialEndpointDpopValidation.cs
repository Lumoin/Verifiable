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
/// than one HTTP method.
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
    /// The JWS <c>alg</c> values the authorization server accepts for a DPoP proof, written as <c>algs</c> and held to
    /// every proof the resource validates; <see langword="null"/> when the host's resolver answered no list or a list
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
    /// (<see cref="WellKnownDpopValues.ExposedDpopResponseFields"/>): the one place a library resource attaches a
    /// <c>DPoP</c> challenge, so every such answer exposes its fields to a browser application.
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
        response
            .WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, challenge)
            .WithHeader(WellKnownHttpHeaderNames.AccessControlExposeHeaders, WellKnownDpopValues.ExposedDpopResponseFields);


    /// <summary>
    /// Reads the presentation of a request to a library resource, UserInfo and the OID4VCI Credential, Deferred
    /// Credential and Notification endpoints: resolves the challenge parameters once
    /// (<see cref="ResolveChallengeContextAsync"/>), reads the <c>Authorization</c> field once, answers a field sent on
    /// two or more lines through <see cref="RefuseRepeatedField"/>, a field carrying no access token through
    /// <see cref="RefuseMissingCredentials"/>, and otherwise answers the token and the scheme it was presented under.
    /// </summary>
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
        AuthorizationFieldReading authorization = BearerTokenValidation.ReadAuthorizationField(context);
        if(authorization.IsRepeated)
        {
            return new LibraryResourcePresentation(null, false, challenge, RefuseRepeatedField(authorization, challenge.Realm, challenge));
        }

        if(!BearerTokenValidation.TryExtractAccessToken(authorization, out string? accessToken, out bool isDpopPresentation))
        {
            return new LibraryResourcePresentation(null, false, challenge, RefuseMissingCredentials(challenge));
        }

        return new LibraryResourcePresentation(accessToken, isDpopPresentation, challenge, null);
    }


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

        if(!accessToken.TryGetValue(WellKnownJwtClaimNames.Cnf, out object? confirmation))
        {
            //RFC 9449 §7.1: the DPoP scheme carries a DPoP-bound access token. An unbound token
            //presented under it names no key a proof could be checked against, so it is refused;
            //under the Bearer scheme it is an ordinary bearer token.
            return isDpopPresentation
                ? RefuseUnderScheme(isDpopPresentation, OAuthErrors.InvalidToken,
                    "The Access Token is not bound to a DPoP key and cannot be presented under the DPoP scheme.", challenge)
                : null;
        }

        string? boundThumbprint = ReadConfirmationThumbprint(confirmation);
        if(boundThumbprint is null)
        {
            //The token is sender-constrained by a confirmation method this resource does not check
            //(cnf without a usable jkt). Serving it as a bearer token would drop that constraint.
            return RefuseUnderScheme(isDpopPresentation, OAuthErrors.InvalidToken,
                "The Access Token carries a confirmation method this resource cannot enforce.", challenge);
        }

        //RFC 9449 §7.2: a DPoP-bound token received as a bearer token is rejected. Accepting it
        //under Bearer would strip the binding the token endpoint established.
        if(!isDpopPresentation)
        {
            return RefuseUnderScheme(isDpopPresentation, OAuthErrors.InvalidToken,
                "The Access Token is sender-constrained and must be presented under the DPoP scheme.", challenge);
        }

        //A bound token with no DPoP enforcement wired (no validator assigned and no parser for the library
        //default, or no nonce delegates) is a misconfiguration: fail loud rather than fall back to bearer,
        //which would silently drop the proof-of-possession check.
        if(!DpopRequestReading.IsProofValidationWired(oauth)
            || oauth.IssueDpopNonceAsync is null
            || oauth.ValidateDpopNonceAsync is null)
        {
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "The Access Token is DPoP-bound but DPoP validation is not configured.");
        }

        Uri issuerUri = await ResolveIssuerAsync(server, registration, context, cancellationToken)
            .ConfigureAwait(false);

        //RFC 9449 Section 4.3: the htm claim matches the HTTP method of the current request, and the htu
        //claim its target URI; both are read from the request this endpoint is serving, its
        //authority the listener authority the host stamped when it names one and the issuer's
        //otherwise (RFC 9110 Section 7.1). RFC 9449 Section 9: a resource's nonce is accepted only at
        //the endpoint that issued it, so its nonces are issued for and validated against that same
        //target URI, never the issuer the token endpoint's nonces are issued for.
        IncomingRequest request = context.IncomingRequest!;
        string htu = DpopRequestReading.ComposeTargetUri(request, issuerUri);
        Uri nonceAudience = new(htu);

        //RFC 9449 Section 4.3, check 1: "There is not more than one DPoP HTTP request header field."
        //Two field lines are an invalid proof (Section 7.1: "invalid_dpop_proof is used to indicate
        //that the DPoP proof itself was deemed invalid based on the criteria of Section 4.3"), refused
        //before the nonce challenge a request with no proof is answered with.
        (string? dpopProof, bool isDpopFieldRepeated) = DpopRequestReading.ReadDpopField(context.IncomingRequest);
        if(isDpopFieldRepeated)
        {
            return RefuseUnderScheme(isDpopPresentation, OAuthErrors.InvalidDpopProof,
                DpopRequestReading.MoreThanOneDpopFieldDescription, challenge);
        }

        if(dpopProof is null)
        {
            return await ChallengeForNonceAsync(
                server, registration, context, nonceAudience,
                "A DPoP proof carrying this resource's nonce is required for the sender-constrained Access Token.",
                challenge, cancellationToken).ConfigureAwait(false);
        }

        //RFC 9449 Section 4.3, check 5: the alg is held to the algorithms the authorization server accepts, the one
        //slot the token endpoint reads. A host resolver that answered no list, or a list holding a name no challenge
        //can carry, leaves no usable policy to hold it to, so the request fails closed as a server error, as the token
        //endpoint answers a resolver that answered no list.
        if(challenge.Algorithms is not IReadOnlyList<string> acceptedAlgorithms)
        {
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                challenge.IsAlgorithmListUnusable switch
                {
                    true => DpopTokenEndpointValidation.AlgorithmResolverAnsweredUnusableListDescription,
                    false => DpopTokenEndpointValidation.AlgorithmResolverAnsweredNoListDescription
                });
        }

        DpopProofValidationResult proofResult = await DpopRequestReading.ValidateProofAsync(
            oauth,
            server.TimeProvider,
            new DpopProofValidationRequest
            {
                Proof = dpopProof,
                HttpMethod = request.Method,
                HttpUrl = htu,
                //ath binds the proof to THIS access token (RFC 9449 §4.2 / §7).
                AccessToken = rawAccessToken,
                NonceRequired = false,
                AcceptedAlgorithms = acceptedAlgorithms
            },
            cancellationToken).ConfigureAwait(false);

        if(!proofResult.IsSuccess)
        {
            return proofResult.FailureReason is DpopProofValidationFailureReason.NonceMissing
                or DpopProofValidationFailureReason.NonceMismatch
                ? await ChallengeForNonceAsync(
                    server, registration, context, nonceAudience, "DPoP nonce required.", challenge, cancellationToken)
                    .ConfigureAwait(false)
                : RefuseUnderScheme(isDpopPresentation, OAuthErrors.InvalidDpopProof,
                    $"DPoP proof validation failed: {proofResult.FailureReason}.", challenge);
        }

        //A validation that answers success names the base64url JWK SHA-256 Thumbprint of the proof's
        //public key (DpopProofValidationResult.JwkThumbprint; RFC 9449 Section 6.1, the jkt member;
        //RFC 7638 Section 3), the value Section 7.1 has the resource match against the token's
        //binding. An application's validator answering success with no value or text of another
        //spelling leaves nothing to match, a fault of the server's own validator rather than of the
        //client's proof, so the request fails closed as a server error before the binding compare,
        //never as the invalid_token that compare answers.
        if(proofResult.JwkThumbprint is not string proofThumbprint
            || !DpopJwkUtilities.IsJwkSha256ThumbprintSpelling(proofThumbprint))
        {
            return ServerHttpResponse.ServerError(OAuthErrors.ServerError, DpopRequestReading.ValidatedProofWithoutThumbprintDescription);
        }

        //A validation that answers success carries the proof's claims, the nonce and the jti the
        //checks below read (RFC 9449 Section 4.3, checks 10 and 11; Section 11.1). An application's
        //validator answering success without them leaves neither to check, so the request fails
        //closed as a server error, as for a missing thumbprint.
        if(proofResult.Claims is not DpopProofClaims proofClaims)
        {
            return ServerHttpResponse.ServerError(OAuthErrors.ServerError, DpopRequestReading.ValidatedProofWithoutClaimsDescription);
        }

        //RFC 9449 §4.3 item 12 and §7.1: the proving key MUST be the one the token was bound to.
        //Constant-time — the thumbprint is matched, not merely compared. The refusal is the
        //invalid_token of §7.1's Figure 16, the binding of the token being what fails.
        if(!FixedTimeComparison.AreEqual(proofThumbprint, boundThumbprint))
        {
            return RefuseUnderScheme(isDpopPresentation, OAuthErrors.InvalidToken,
                "The DPoP proof key does not match the Access Token's cnf.jkt binding.", challenge);
        }

        //RFC 9449 §11.3: no proof without the nonce claim is accepted once a nonce has been
        //provided, and this resource provides one to every client it challenges.
        if(proofClaims.Nonce is null)
        {
            return await ChallengeForNonceAsync(
                server, registration, context, nonceAudience, "DPoP nonce required.", challenge, cancellationToken)
                .ConfigureAwait(false);
        }

        DpopNonceValidationResult nonceResult = await oauth.ValidateDpopNonceAsync(
            proofClaims.Nonce, nonceAudience, registration.TenantId, context, cancellationToken)
            .ConfigureAwait(false);
        if(!nonceResult.IsSuccess)
        {
            return await ChallengeForNonceAsync(
                server, registration, context, nonceAudience,
                $"DPoP nonce invalid: {nonceResult.FailureReason}.", challenge, cancellationToken).ConfigureAwait(false);
        }

        //jti replay — the same shared correlation store, the proof's jti recorded in the context of
        //the target URI this request is served at (RFC 9449 §11.1).
        JtiReplayOutcome jtiOutcome = await JtiReplayGuard.ConsultDpopProofAsync(
            server, context, registration.TenantId,
            issuerUri.OriginalString, htu, proofClaims.Jti,
            now + WellKnownDpopValues.DefaultReplayWindow,
            cancellationToken).ConfigureAwait(false);

        return jtiOutcome switch
        {
            JtiReplayOutcome.FirstUse => null,
            JtiReplayOutcome.Replayed => RefuseUnderScheme(isDpopPresentation,
                OAuthErrors.InvalidDpopProof, "The DPoP proof jti has been presented previously.", challenge),
            JtiReplayOutcome.Unacceptable => RefuseUnderScheme(isDpopPresentation,
                OAuthErrors.InvalidDpopProof, "DPoP proof jti is too long or carries a character the replay guard cannot store.", challenge),
            JtiReplayOutcome.StoreUnavailable => ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "DPoP proof jti replay defense is required by policy but no jti store is configured."),

            _ => null
        };
    }


    /// <summary>
    /// Composes the <c>DPoP</c> challenge
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see> describes through
    /// <see cref="DpopChallenge.BuildChallenge"/>: "The scheme name is DPoP.", the <c>realm</c> and the <c>scope</c> of
    /// <paramref name="challenge"/>, "An error parameter ([RFC6750], Section 3) SHOULD be included to indicate the reason
    /// why the request was declined, if the request included an access token but failed authentication." and "An algs
    /// parameter SHOULD be included", the algorithms of <paramref name="challenge"/>. The <paramref name="error"/> is one
    /// of the library's own OAuth error codes, within the RFC 6750 Section 3 attribute charset.
    /// </summary>
    /// <param name="error">The error code, for example <see cref="OAuthErrors.InvalidToken"/>, or <see langword="null"/> for none.</param>
    /// <param name="challenge">The parameters every <c>DPoP</c> challenge of the request carries.</param>
    /// <returns>The <c>WWW-Authenticate</c> value.</returns>
    internal static string BuildDpopChallenge(string? error, ResourceChallengeContext challenge) =>
        DpopChallenge.BuildChallenge(challenge.Realm, error, challenge.Scope, challenge.Algorithms);


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
    /// Builds a 401 refusal carrying <paramref name="error"/> in the body and a challenge in the
    /// presentation's scheme: the <c>DPoP</c> challenge with the same error, attached through
    /// <see cref="WithDpopChallenge"/>, or <c>Bearer error="invalid_token"</c> for a <c>Bearer</c> presentation (whose
    /// refusals here are all <c>invalid_token</c>).
    /// </summary>
    /// <param name="isDpopPresentation">Whether the token was presented under the <c>DPoP</c> scheme.</param>
    /// <param name="error">The error code.</param>
    /// <param name="description">The <c>error_description</c> the body carries.</param>
    /// <param name="challenge">The parameters every <c>DPoP</c> challenge of the request carries.</param>
    /// <returns>The 401 response.</returns>
    private static ServerHttpResponse RefuseUnderScheme(
        bool isDpopPresentation, string error, string description, ResourceChallengeContext challenge) =>
        isDpopPresentation
            ? WithDpopChallenge(ServerHttpResponse.Unauthorized(error, description), BuildDpopChallenge(error, challenge))
            : ServerHttpResponse.Unauthorized(error, description)
                .WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, BearerTokenValidation.InvalidTokenChallenge);


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
    /// <param name="nonceAudience">
    /// The target URI of the endpoint serving the request, the one endpoint the nonce is accepted at
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "nonces will be only
    /// accepted by the server that issued them").
    /// </param>
    /// <param name="description">The <c>error_description</c> the body carries.</param>
    /// <param name="challenge">The parameters every <c>DPoP</c> challenge of the request carries.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The 401 nonce challenge.</returns>
    private static async ValueTask<ServerHttpResponse> ChallengeForNonceAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        Uri nonceAudience,
        string description,
        ResourceChallengeContext challenge,
        CancellationToken cancellationToken)
    {
        string freshNonce = await server.OAuth().IssueDpopNonceAsync!(
            nonceAudience, registration.TenantId, context, cancellationToken).ConfigureAwait(false);

        return WithDpopChallenge(
                ServerHttpResponse.Unauthorized(OAuthErrors.UseDpopNonce, description),
                BuildDpopChallenge(OAuthErrors.UseDpopNonce, challenge))
            .WithHeader(WellKnownHttpHeaderNames.DPoPNonce, freshNonce);
    }


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
