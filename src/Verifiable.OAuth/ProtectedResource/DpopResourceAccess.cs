using Verifiable.Core;
using Verifiable.OAuth.AuthCode.Server;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// The checks a protected resource runs on one presentation of an access token, as
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see> states them: "For such an
/// access token, a resource server MUST check that a DPoP proof was also received in the DPoP header field of the HTTP
/// request, check the DPoP proof according to the rules in Section 4.3, and check that the public key of the DPoP proof
/// matches the public key to which the access token is bound per Section 6." and "The resource server MUST NOT grant
/// access to the resource unless all checks are successful." <see cref="DecideAsync"/> runs them for an application's
/// own resource over a <see cref="ResourceServerIntegration"/>; the library's own resources, UserInfo and the OID4VCI
/// endpoints, run the same checks in the same order.
/// </summary>
/// <remarks>
/// <para>
/// The order: a resource requiring DPoP-bound access tokens refuses a <c>Bearer</c> presentation with the <c>DPoP</c>
/// challenge alone and no error (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>,
/// <c>dpop_bound_access_tokens_required</c>; <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750
/// Section 3.1</see>: "If the request lacks any authentication information (e.g., the client was unaware that
/// authentication is necessary or attempted using an unsupported authentication method), the resource server SHOULD NOT
/// include an error code or other error information."); an unbound token is permitted under <c>Bearer</c> and refused
/// under <c>DPoP</c>; a token bound by a confirmation method other than <c>jkt</c> is refused; a bound token under
/// <c>Bearer</c> is refused with the <c>Bearer</c> challenge (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">Section
/// 7.2</see>: "such a protected resource MUST reject a DPoP-bound access token received as a bearer token per
/// [RFC6750]."); a check not wired is a server error; a missing proof is answered with the resource's nonce challenge and
/// a repeated <c>DPoP</c> field refused; the proof is validated against the method, the target URI, the token's hash and
/// the accepted algorithms; its public key's thumbprint is compared with the token's binding in fixed time; at an
/// application's resource its <c>iat</c> is held to <see cref="ResourceServerIntegration.DpopFreshnessWindow"/> of the
/// integration's clock either way, whatever tolerance the wired proof validation applies
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">Section 11.1</see>: "servers MUST only accept DPoP
/// proofs for a limited time after their creation"); its nonce is required and
/// validated against the target URI; its <c>jti</c>, one a record can hold, is recorded for as long as the proof is
/// accepted (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">Section 11.1</see>: "In the context of the
/// target URI, servers can store the jti value of each DPoP proof for the time window in which the respective DPoP proof
/// JWT would be accepted to prevent multiple uses of the same DPoP proof."), with one atomic claim in the context of the
/// target URI: the library's own resources through the replay guard, an application's resource through
/// <see cref="ResourceServerIntegration.ConsultDpopProofJtiAsync"/> (<see cref="Dpop.InMemoryDpopReplayCache"/> keys
/// its records by the target URI and the <c>jti</c>).
/// </para>
/// <para>
/// Every <c>DPoP</c> challenge is written by <see cref="DpopChallenge.BuildChallenge"/> with the resource's realm, scope,
/// accepted algorithms and metadata URL, and every answer carrying one carries
/// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">Section 7.1</see>: "the server needs to make it
/// available to the application by including WWW-Authenticate in the Access-Control-Expose-Headers response header list
/// value").
/// </para>
/// </remarks>
public static class DpopResourceAccess
{
    /// <summary>
    /// The description a DPoP-bound access token is answered with under <c>server_error</c> when the resource validates
    /// no DPoP proof, issues or validates no nonce, or records no <c>jti</c>: its binding cannot be checked, and serving it
    /// as a bearer token would drop the proof of possession.
    /// </summary>
    internal static string DpopChecksNotWiredDescription { get; } = "The Access Token is DPoP-bound but DPoP validation is not configured.";


    /// <summary>
    /// The description a presentation is answered with under <c>server_error</c> when the <c>jti</c> consultation answers
    /// an outcome the checks do not name: no outcome but a first use grants access, so an unrecognized one fails closed
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "The resource server
    /// MUST NOT grant access to the resource unless all checks are successful.").
    /// </summary>
    internal static string UnrecognizedJtiOutcomeDescription { get; } = "The DPoP proof jti consultation answered an outcome this resource does not recognize.";


    /// <summary>
    /// The description an application's resource answers under <c>server_error</c> when its wired <c>jti</c> store
    /// answers <see cref="JtiReplayOutcome.StoreUnavailable"/>: the application's own store was consulted and could not
    /// record the proof's first use or resolve what it recorded, so the proof cannot be held to one use and is not served
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "The resource server
    /// MUST NOT grant access to the resource unless all checks are successful.").
    /// </summary>
    internal static string JtiStoreCouldNotRecordDescription { get; } = "The DPoP proof jti store could not record the proof.";


    /// <summary>
    /// The description every library endpoint that consults the replay guard for a DPoP proof's <c>jti</c> answers under
    /// <c>server_error</c> when the guard answers <see cref="JtiReplayOutcome.StoreUnavailable"/>: the library's own
    /// resources and the token endpoint. The guard answers it for three causes, one text true for each: no replay store is
    /// wired under <see cref="JtiReplayPolicy.Required"/>; a wired store has no atomic claim; a wired store cannot resolve
    /// what it recorded (<see cref="JtiReplayGuard.ConsultDpopProofAsync"/>). In each the proof cannot be held to one use
    /// and is not served (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "The
    /// resource server MUST NOT grant access to the resource unless all checks are successful.").
    /// </summary>
    internal static string JtiReplayDefenseCouldNotRecordDescription { get; } = "The DPoP proof jti replay defense could not record the proof.";


    /// <summary>
    /// Decides on one presentation of an access token at an application's own protected resource, running the checks of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see> over the slots of
    /// <paramref name="integration"/>: <see cref="ResourceServerIntegration.ValidateDpopProofAsync"/>, the nonce
    /// issuance and validation (<see cref="ResourceServerIntegration.IssueDpopNonceAsync"/>,
    /// <see cref="ResourceServerIntegration.ValidateDpopNonceAsync"/>, both called with the default
    /// <see cref="TenantId"/> and with <see cref="DpopResourceRequest.TargetUri"/> as the nonce's audience),
    /// <see cref="ResourceServerIntegration.AcceptedDpopProofAlgorithms"/> and the <c>jti</c> claim
    /// (<see cref="ResourceServerIntegration.ConsultDpopProofJtiAsync"/>, called once with
    /// <see cref="DpopResourceRequest.TargetUri"/> and kept for the proof's whole acceptance window: past the later of the
    /// integration's clock and the proof's <c>iat</c> plus <see cref="ResourceServerIntegration.DpopFreshnessWindow"/>),
    /// holding a validated proof's <c>iat</c> to
    /// <see cref="ResourceServerIntegration.DpopFreshnessWindow"/> of the integration's clock either way, whatever
    /// tolerance the wired proof validation applies.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The caller validates the access token first and presents its binding. A protection space requiring DPoP-bound
    /// access tokens (<see cref="DpopResourceRequest.IsDpopBoundAccessTokenRequired"/>) answers a request without
    /// credentials and any <c>Bearer</c> presentation with the <c>DPoP</c> challenge alone and no <c>error</c>, before
    /// validating the token, as the library's resources do
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "Upon receipt of a
    /// request to a protected resource within the protection space requiring DPoP authentication, the server can respond
    /// with a challenge to the client to provide DPoP authentication information if the request does not include valid
    /// credentials or does not contain an access token sufficient for access."; RFC 6750 Section 3.1: "If the request
    /// lacks any authentication information (e.g., the client was unaware that authentication is necessary or attempted
    /// using an unsupported authentication method), the resource server SHOULD NOT include an error code or other error
    /// information."). This method answers a <c>Bearer</c> presentation of a validated token so; a request without
    /// credentials, an <c>Authorization</c> field naming a scheme alone or a scheme other than <c>Bearer</c> and
    /// <c>DPoP</c>, and a <c>Bearer</c> presentation of any shape the caller refuses before validating its token never
    /// reach it, and the caller answers them with the same challenge (<see cref="DpopChallenge.BuildChallenge"/> with no
    /// error), whatever its own refusal of a token would say. A single <c>Authorization</c> field line naming the
    /// <c>DPoP</c> scheme with non-empty credentials that are no token68 is no missing credential: it never reaches this
    /// method, and the caller answers it 400 <c>invalid_request</c> with the <c>DPoP</c> challenge carrying that error,
    /// under the requirement as without it; without the requirement a <c>Bearer</c> line so is answered the same way with
    /// the <c>Bearer</c> challenge alone, as the library's resources answer both
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>: "credentials =
    /// "Bearer" 1*SP b64token"; RFC 9449 Section 7.1: "credentials = "DPoP" 1*SP token68"; RFC 6750 Section 3.1:
    /// "invalid_request ... or is otherwise malformed."; RFC 9449 Section 7.2: "If the mechanism used to attempt
    /// authentication could be established unambiguously, then the corresponding challenge SHOULD be used to deliver error
    /// information (Figure 18)."). An
    /// <c>Authorization</c> field sent on two or more lines never reaches it either: the caller answers it 400
    /// <c>invalid_request</c> before any token is validated, as the library's resources answer it
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_request The
    /// request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same
    /// parameter, uses more than one method for including an access token, or is otherwise malformed. The resource
    /// server SHOULD respond with the HTTP 400 (Bad Request) status code."). Where the resource requires DPoP-bound
    /// access tokens the answer carries the <c>DPoP</c> challenge alone with that error; otherwise it carries the
    /// challenge of the mechanism the lines attempt: the <c>DPoP</c> challenge alone where every line names <c>DPoP</c>,
    /// the <c>Bearer</c> challenge alone where every line names <c>Bearer</c>, and both challenges in one field line
    /// where the lines name two schemes
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If the mechanism
    /// used to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be
    /// used to deliver error information (Figure 18)." and "Otherwise, both Bearer and DPoP challenges MAY be used to
    /// deliver error information (Figure 19).").
    /// </para>
    /// <para>
    /// A validated proof whose <c>iat</c> lies more than <see cref="ResourceServerIntegration.DpopFreshnessWindow"/>
    /// from the integration's clock either way, the bounds admitted, is refused <c>invalid_dpop_proof</c> after the
    /// thumbprint comparison and before the nonce, whatever tolerance the wired proof validation applies
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "servers MUST only
    /// accept DPoP proofs for a limited time after their creation"; Section 7.1: "The resource server MUST NOT grant
    /// access to the resource unless all checks are successful."), so the <c>jti</c> record, kept past the later of the
    /// clock and the <c>iat</c> plus that window, covers every instant the proof is accepted at.
    /// </para>
    /// <para>
    /// The resource requires its own nonce in every proof. <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC
    /// 9449 Section 9</see> makes the nonce the resource's choice ("Resource servers can also choose to provide a nonce
    /// value to be included in DPoP proofs sent to them."), and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.3">Section 11.3</see> holds a server that provides one
    /// to it: "A server MUST NOT accept any DPoP proofs without the nonce claim when a DPoP nonce has been provided to the
    /// client." This composition keeps no record of which client was provided a nonce, so a proof without one is
    /// answered with the nonce challenge; a resource that wants no nonce does not use it.
    /// </para>
    /// <para>
    /// The <c>jti</c> is consulted once, with one atomic claim in the context of
    /// <see cref="DpopResourceRequest.TargetUri"/> (<see cref="ResourceServerIntegration.ConsultDpopProofJtiAsync"/>),
    /// handed in the one normalized form the <c>htu</c> comparison reads, stated once at
    /// <see cref="ConsultDpopProofJtiDelegate"/>, so every spelling of one target URI names one record, of concurrent
    /// presentations of one proof at one target URI one is served and the others are refused as replays, and the same
    /// <c>jti</c> in a proof for another target URI is another proof's. The claim's
    /// <see cref="JtiReplayOutcome.Replayed"/> is refused <c>invalid_dpop_proof</c> with the description "The DPoP proof
    /// jti has been presented previously.", its <see cref="JtiReplayOutcome.Unacceptable"/> <c>invalid_dpop_proof</c>
    /// with the description below, and its <see cref="JtiReplayOutcome.StoreUnavailable"/> fails closed as
    /// <see cref="DpopResourceDecisionKind.IndeterminateDeny"/>, 500 <c>server_error</c> with the description "The DPoP
    /// proof jti store could not record the proof.". A <c>jti</c> no record can hold, one that is empty,
    /// longer than <see cref="JtiReplayGuard.MaxJtiLength"/> UTF-16 code units, or holding a character of general
    /// category Cc or an unpaired surrogate, is refused <c>invalid_dpop_proof</c> with the description "DPoP proof jti is
    /// empty, too long or carries a character the replay guard cannot store." before the slot is called: the rule the
    /// library's resources hold a <c>jti</c> to wherever the replay guard reads it, which under
    /// <see cref="JtiReplayPolicy.Disabled"/> it does not, answering a first use before the rule. A slot left unwired,
    /// the proof validation, either nonce slot or the <c>jti</c> claim, answers a DPoP-bound token
    /// <see cref="DpopResourceDecisionKind.IndeterminateDeny"/>.
    /// </para>
    /// <para>
    /// Every refusal of the presentation is a decision, never an exception. The caller's own arguments throw: a
    /// <see langword="null"/> argument <see cref="ArgumentNullException"/>; a realm, scope, metadata URL or accepted
    /// algorithm name no <c>DPoP</c> challenge can carry, or a <see cref="DpopResourceRequest.TargetUri"/> that is not an
    /// absolute http or https URI without userinfo, query and fragment, <see cref="ArgumentException"/> naming
    /// <paramref name="request"/>; a negative <see cref="ResourceServerIntegration.DpopFreshnessWindow"/>,
    /// <see cref="ArgumentException"/> naming <paramref name="integration"/>; each checked before any decision. An
    /// exception raised by a slot of <paramref name="integration"/> passes to the caller, and the request then fails
    /// closed with no permit.
    /// </para>
    /// </remarks>
    /// <param name="integration">The resource server's slots.</param>
    /// <param name="request">The presentation, its binding read by the caller's own validation of the token.</param>
    /// <param name="context">The per-request context the slots are called with.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The decision: a permit, or the refusal to send.</returns>
    public static ValueTask<DpopResourceDecision> DecideAsync(
        ResourceServerIntegration integration,
        DpopResourceRequest request,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(integration);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(request.AccessToken, nameof(request));
        ArgumentNullException.ThrowIfNull(request.HttpMethod, nameof(request));
        ArgumentNullException.ThrowIfNull(request.TargetUri, nameof(request));
        ArgumentNullException.ThrowIfNull(request.DpopFieldLines, nameof(request));

        //RFC 9449 Section 4.2: htu is "The HTTP target URI (Section 7.1 of [RFC9110]) of the request to which the JWT is
        //attached, without query and fragment parts.", and Section 4.3 holds a proof's htu to it "ignoring any query and
        //fragment parts"; RFC 9110 Section 4.2.4: "A sender MUST NOT generate the userinfo subcomponent (and its "@"
        //delimiter) when an "http" or "https" URI reference is generated within a message as a target URI". The
        //resource's nonces are issued for the target URI. It is the application's own configuration, so one no proof can
        //name is the caller's argument, refused before any decision rather than answered as a refusal of every proof.
        if(!IsTargetUriShape(request.TargetUri))
        {
            throw new ArgumentException(
                "The request's TargetUri must be an absolute http or https URI with no userinfo, query or fragment.", nameof(request));
        }

        //RFC 9449 Section 11.1: "servers MUST only accept DPoP proofs for a limited time after their creation". The
        //window is read once, for the iat check and the jti record alike; a negative one names no time at all and is the
        //caller's argument.
        TimeSpan freshnessWindow = integration.DpopFreshnessWindow;
        if(freshnessWindow < TimeSpan.Zero)
        {
            throw new ArgumentException(
                "The integration's DpopFreshnessWindow must not be negative.", nameof(integration));
        }

        IReadOnlyList<string> acceptedAlgorithms = integration.AcceptedDpopProofAlgorithms ?? WellKnownDpopValues.SupportedSigningAlgorithms;

        //The challenge's values are the application's own: a realm, scope, metadata URL or algorithm name no challenge
        //can carry throws here, before any decision, rather than only on the refusal that first writes it.
        _ = DpopChallenge.BuildChallenge(request.Realm, null, request.Scope, acceptedAlgorithms, request.ResourceMetadata);

        DpopResourcePresentation presentation = new(
            request.AccessToken,
            request.IsDpopPresentation,
            request.IsSenderConstrained || request.BoundThumbprint is not null,
            request.BoundThumbprint,
            request.HttpMethod,
            request.DpopFieldLines,
            request.IsDpopBoundAccessTokenRequired);

        ValidateDpopProofDelegate? validateProof = integration.ValidateDpopProofAsync;
        IssueDpopNonceDelegate? issueNonce = integration.IssueDpopNonceAsync;
        ValidateDpopNonceDelegate? validateNonce = integration.ValidateDpopNonceAsync;
        ConsultDpopProofJtiDelegate? consultJti = integration.ConsultDpopProofJtiAsync;
        TenantId tenantId = default;

        DpopResourceChecks checks = new()
        {
            ResolveTargetUriAsync = _ => ValueTask.FromResult(request.TargetUri),
            ValidateProofAsync = validateProof is null
                ? null
                : (proofRequest, ct) => validateProof(proofRequest, ct),
            IssueNonceAsync = issueNonce is null
                ? null
                : (audience, ct) => issueNonce(audience, tenantId, context, ct),
            ValidateNonceAsync = validateNonce is null
                ? null
                : (nonce, audience, ct) => validateNonce(nonce, audience, tenantId, context, ct),
            ConsultJtiAsync = consultJti is null
                ? null
                : (targetUri, jti, issuedAt, ct) => ClaimJtiAsync(
                    integration, consultJti, targetUri, jti, issuedAt, freshnessWindow, context, ct),
            IsIssuedAtWithinFreshnessWindow = issuedAt => IsWithinFreshnessWindow(
                integration.TimeProvider.GetUtcNow(), issuedAt, freshnessWindow),
            AcceptedAlgorithms = acceptedAlgorithms,
            AlgorithmListFailureDescription = DpopTokenEndpointValidation.AlgorithmResolverAnsweredNoListDescription,
            JtiStoreUnavailableDescription = JtiStoreCouldNotRecordDescription,
            BearerChallenge = BearerTokenChallenge.BuildChallenge(
                realm: request.Realm, error: OAuthErrors.InvalidToken, resourceMetadata: request.ResourceMetadata),
            Realm = request.Realm,
            Scope = request.Scope,
            ResourceMetadata = request.ResourceMetadata
        };

        return DecideCoreAsync(presentation, checks, cancellationToken);
    }


    /// <summary>
    /// Whether <paramref name="targetUri"/> is a target URI a DPoP proof's <c>htu</c> can name: an absolute <c>http</c>
    /// or <c>https</c> URI with no userinfo, no query and no fragment
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>: "htu: The HTTP target
    /// URI (Section 7.1 of [RFC9110]) of the request to which the JWT is attached, without query and fragment parts.";
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>: "The htu claim matches the HTTP
    /// URI value for the HTTP request in which the JWT was received, ignoring any query and fragment parts.";
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.4">RFC 9110 Section 4.2.4</see>: "A sender MUST NOT
    /// generate the userinfo subcomponent (and its "@" delimiter) when an "http" or "https" URI reference is generated
    /// within a message as a target URI or field value.").
    /// </summary>
    /// <param name="targetUri">The target URI the application names its resource by.</param>
    /// <returns><see langword="true"/> when the target URI has that shape.</returns>
    private static bool IsTargetUriShape(Uri targetUri) =>
        targetUri.IsAbsoluteUri
        && (string.Equals(targetUri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
            || string.Equals(targetUri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal))
        && targetUri.UserInfo.Length == 0
        && targetUri.Query.Length == 0
        && targetUri.Fragment.Length == 0;


    /// <summary>
    /// Whether <paramref name="issuedAt"/>, a validated proof's <c>iat</c>, lies within
    /// <paramref name="freshnessWindow"/> of <paramref name="now"/> either way, the bounds included: the time
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see> limits acceptance to
    /// ("servers MUST only accept DPoP proofs for a limited time after their creation"), which the <c>jti</c> record
    /// (<see cref="RecordExpiry"/>) covers. The difference of two instants a <see cref="DateTimeOffset"/> holds always
    /// fits a <see cref="TimeSpan"/>, so no input overflows.
    /// </summary>
    /// <param name="now">The resource server's clock.</param>
    /// <param name="issuedAt">The proof's <c>iat</c>.</param>
    /// <param name="freshnessWindow">The window, <see cref="ResourceServerIntegration.DpopFreshnessWindow"/>, not negative.</param>
    /// <returns><see langword="true"/> when the <c>iat</c> lies within the window.</returns>
    private static bool IsWithinFreshnessWindow(DateTimeOffset now, DateTimeOffset issuedAt, TimeSpan freshnessWindow) =>
        (issuedAt - now).Duration() <= freshnessWindow;


    /// <summary>
    /// The facts of one presentation the checks are run on: what the caller read of the request and of its own
    /// validation of the token.
    /// </summary>
    /// <param name="AccessToken">The access token as presented, the value a proof's <c>ath</c> hashes.</param>
    /// <param name="IsDpopPresentation">Whether the token was presented under the <c>DPoP</c> scheme.</param>
    /// <param name="IsSenderConstrained">Whether the token carries a <c>cnf</c> claim.</param>
    /// <param name="BoundThumbprint">The token's <c>cnf.jkt</c>, or <see langword="null"/>.</param>
    /// <param name="HttpMethod">The request's method, the value a proof's <c>htm</c> names.</param>
    /// <param name="DpopFieldLines">Every <c>DPoP</c> field line of the request in received order.</param>
    /// <param name="IsDpopBoundAccessTokenRequired">Whether the resource requires DPoP-bound access tokens.</param>
    internal sealed record DpopResourcePresentation(
        string AccessToken,
        bool IsDpopPresentation,
        bool IsSenderConstrained,
        string? BoundThumbprint,
        string HttpMethod,
        IReadOnlyList<string> DpopFieldLines,
        bool IsDpopBoundAccessTokenRequired);


    /// <summary>
    /// The checks <see cref="DecideCoreAsync"/> runs and the parameters of the challenges it writes, each check a
    /// function the caller composes over its own slots: <see cref="DecideAsync"/> over a
    /// <see cref="ResourceServerIntegration"/>, the library's own resources over the authorization server's slots.
    /// </summary>
    internal sealed record DpopResourceChecks
    {
        /// <summary>
        /// Answers the target URI of the request, the value a proof's <c>htu</c> is held to, the audience of the
        /// resource's nonces and the target <see cref="ConsultJtiAsync"/> is handed. Read only once the checks reach the
        /// proof, so a presentation decided before it resolves nothing.
        /// </summary>
        public required Func<CancellationToken, ValueTask<Uri>> ResolveTargetUriAsync { get; init; }

        /// <summary>Validates a proof against the request's method, target URI, token hash and accepted algorithms, or <see langword="null"/> when unwired.</summary>
        public Func<DpopProofValidationRequest, CancellationToken, ValueTask<DpopProofValidationResult>>? ValidateProofAsync { get; init; }

        /// <summary>Issues a fresh nonce for the target URI, or <see langword="null"/> when unwired.</summary>
        public Func<Uri, CancellationToken, ValueTask<string>>? IssueNonceAsync { get; init; }

        /// <summary>Validates a presented nonce against the target URI, or <see langword="null"/> when unwired.</summary>
        public Func<string, Uri, CancellationToken, ValueTask<DpopNonceValidationResult>>? ValidateNonceAsync { get; init; }

        /// <summary>
        /// Consults the <c>jti</c> record for a proof's <c>jti</c>, handed the target URI, the <c>jti</c> and the proof's
        /// <c>iat</c>, recording a first use for as long as the proof is accepted, or <see langword="null"/> when unwired:
        /// the library's resources record it in the context of the target URI, an application's resource through its own
        /// slots.
        /// </summary>
        public Func<Uri, string, DateTimeOffset, CancellationToken, ValueTask<JtiReplayOutcome>>? ConsultJtiAsync { get; init; }

        /// <summary>
        /// Whether a validated proof's <c>iat</c> lies within the resource's freshness window of its clock, or
        /// <see langword="null"/> where the proof validation's own <c>iat</c> tolerance is the window: an application's
        /// resource holds the <c>iat</c> to <see cref="ResourceServerIntegration.DpopFreshnessWindow"/> whatever its
        /// wired validation's tolerance, so its <c>jti</c> record covers every instant the proof is accepted at; the
        /// library's resources validate with the library's own tolerance, which their replay guard's record outlasts.
        /// </summary>
        public Func<DateTimeOffset, bool>? IsIssuedAtWithinFreshnessWindow { get; init; }

        /// <summary>
        /// The JWS <c>alg</c> values a proof is held to and the <c>algs</c> of every <c>DPoP</c> challenge, or
        /// <see langword="null"/> when the resource has no usable list, so a presented proof is answered
        /// <c>server_error</c> with <see cref="AlgorithmListFailureDescription"/>.
        /// </summary>
        public IReadOnlyList<string>? AcceptedAlgorithms { get; init; }

        /// <summary>The description a presented proof is answered with under <c>server_error</c> when <see cref="AcceptedAlgorithms"/> is <see langword="null"/>.</summary>
        public required string AlgorithmListFailureDescription { get; init; }

        /// <summary>
        /// The description a presented proof is answered with under <c>server_error</c> when <see cref="ConsultJtiAsync"/>
        /// answers <see cref="JtiReplayOutcome.StoreUnavailable"/>: what that answer means where the checks are composed,
        /// the application's own store that could not record the proof at an application's resource
        /// (<see cref="JtiStoreCouldNotRecordDescription"/>), and at the library's resources the replay guard's answer for
        /// any of its three causes, no store wired under <see cref="JtiReplayPolicy.Required"/>, a store with no atomic
        /// claim, a store that cannot resolve what it recorded (<see cref="JtiReplayDefenseCouldNotRecordDescription"/>).
        /// </summary>
        public required string JtiStoreUnavailableDescription { get; init; }

        /// <summary>The <c>WWW-Authenticate</c> value of a refusal of a token presented under the <c>Bearer</c> scheme.</summary>
        public required string BearerChallenge { get; init; }

        /// <summary>The <c>realm</c> of every <c>DPoP</c> challenge, or <see langword="null"/> for none.</summary>
        public string? Realm { get; init; }

        /// <summary>The <c>scope</c> of every <c>DPoP</c> challenge, or <see langword="null"/> for none.</summary>
        public string? Scope { get; init; }

        /// <summary>The <c>resource_metadata</c> of every <c>DPoP</c> challenge, or <see langword="null"/> for none.</summary>
        public Uri? ResourceMetadata { get; init; }
    }


    /// <summary>
    /// Runs the checks on one presentation in their one order and answers the decision; the one copy of the order, which
    /// <see cref="DecideAsync"/> and the library's own resources both run.
    /// </summary>
    /// <param name="presentation">The presentation.</param>
    /// <param name="checks">The checks and the challenge parameters.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The decision.</returns>
    internal static async ValueTask<DpopResourceDecision> DecideCoreAsync(
        DpopResourcePresentation presentation,
        DpopResourceChecks checks,
        CancellationToken cancellationToken)
    {
        //RFC 9728 Section 2 and RFC 9449 Section 7.1: a protection space requiring DPoP authentication refuses a
        //presentation under any other scheme with the DPoP challenge alone; RFC 6750 Section 3.1 names a client that
        //"attempted using an unsupported authentication method" as one answered with no error code.
        if(presentation.IsDpopBoundAccessTokenRequired && !presentation.IsDpopPresentation)
        {
            return DpopResourceDecision.Deny(WithDpopChallenge(ServerHttpResponse.Unauthorized(), BuildChallenge(null, checks)));
        }

        //RFC 9449 Section 7.1: the DPoP scheme carries a DPoP-bound access token. An unbound token presented under it
        //names no key a proof could be checked against; under the Bearer scheme it is an ordinary bearer token.
        if(!presentation.IsSenderConstrained)
        {
            return presentation.IsDpopPresentation
                ? DpopResourceDecision.Deny(RefuseUnderScheme(true, OAuthErrors.InvalidToken,
                    "The Access Token is not bound to a DPoP key and cannot be presented under the DPoP scheme.", checks))
                : DpopResourceDecision.Permit(null);
        }

        //A token sender-constrained by a confirmation method this resource does not check (a cnf without a jkt):
        //serving it as a bearer token would drop that constraint.
        if(presentation.BoundThumbprint is not string boundThumbprint)
        {
            return DpopResourceDecision.Deny(RefuseUnderScheme(presentation.IsDpopPresentation, OAuthErrors.InvalidToken,
                "The Access Token carries a confirmation method this resource cannot enforce.", checks));
        }

        //RFC 9449 Section 7.2: a DPoP-bound token received as a bearer token is rejected.
        if(!presentation.IsDpopPresentation)
        {
            return DpopResourceDecision.Deny(RefuseUnderScheme(false, OAuthErrors.InvalidToken,
                "The Access Token is sender-constrained and must be presented under the DPoP scheme.", checks));
        }

        //A bound token with a check unwired is a fault of the server's own wiring: the request fails closed rather
        //than falling back to bearer, which would drop the proof-of-possession check.
        if(checks.ValidateProofAsync is not { } validateProof
            || checks.IssueNonceAsync is not { } issueNonce
            || checks.ValidateNonceAsync is not { } validateNonce
            || checks.ConsultJtiAsync is not { } consultJti)
        {
            return DpopResourceDecision.IndeterminateDeny(
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, DpopChecksNotWiredDescription));
        }

        Uri targetUri = await checks.ResolveTargetUriAsync(cancellationToken).ConfigureAwait(false);

        //RFC 9449 Section 4.3, check 1: "There is not more than one DPoP HTTP request header field." Two field lines
        //are an invalid proof, refused before the nonce challenge a request with no proof is answered with; Section
        //7.1: the resource "MUST check that a DPoP proof was also received in the DPoP header field".
        if(presentation.DpopFieldLines.Count > 1)
        {
            return DpopResourceDecision.Deny(RefuseUnderScheme(true, OAuthErrors.InvalidDpopProof,
                DpopRequestReading.MoreThanOneDpopFieldDescription, checks));
        }

        if(presentation.DpopFieldLines.Count == 0)
        {
            return DpopResourceDecision.Deny(await ChallengeForNonceAsync(issueNonce, targetUri,
                "A DPoP proof carrying this resource's nonce is required for the sender-constrained Access Token.", checks,
                cancellationToken).ConfigureAwait(false));
        }

        //RFC 9449 Section 4.3, check 5: the alg is held to the algorithms the resource accepts. A resource with no
        //usable list leaves no policy to hold it to, so the request fails closed as a server error.
        if(checks.AcceptedAlgorithms is not IReadOnlyList<string> acceptedAlgorithms)
        {
            return DpopResourceDecision.IndeterminateDeny(
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, checks.AlgorithmListFailureDescription));
        }

        DpopProofValidationResult proofResult = await validateProof(
            new DpopProofValidationRequest
            {
                Proof = presentation.DpopFieldLines[0],
                HttpMethod = presentation.HttpMethod,
                HttpUrl = targetUri.OriginalString,
                //RFC 9449 Sections 4.2 and 7: ath binds the proof to this access token.
                AccessToken = presentation.AccessToken,
                NonceRequired = false,
                AcceptedAlgorithms = acceptedAlgorithms
            },
            cancellationToken).ConfigureAwait(false);

        if(!proofResult.IsSuccess)
        {
            return DpopResourceDecision.Deny(proofResult.FailureReason is DpopProofValidationFailureReason.NonceMissing
                or DpopProofValidationFailureReason.NonceMismatch
                ? await ChallengeForNonceAsync(issueNonce, targetUri, "DPoP nonce required.", checks, cancellationToken).ConfigureAwait(false)
                : RefuseUnderScheme(true, OAuthErrors.InvalidDpopProof,
                    $"DPoP proof validation failed: {proofResult.FailureReason}.", checks));
        }

        //A validation answering success names the base64url JWK SHA-256 Thumbprint of the proof's public key (RFC 9449
        //Section 6.1) and carries the proof's claims. A validator answering success without them is a fault of the
        //server's own validator, never the client's proof, so the request fails closed as a server error.
        if(proofResult.JwkThumbprint is not string proofThumbprint
            || !DpopJwkUtilities.IsJwkSha256ThumbprintSpelling(proofThumbprint))
        {
            return DpopResourceDecision.IndeterminateDeny(ServerHttpResponse.ServerError(
                OAuthErrors.ServerError, DpopRequestReading.ValidatedProofWithoutThumbprintDescription));
        }

        if(proofResult.Claims is not DpopProofClaims proofClaims)
        {
            return DpopResourceDecision.IndeterminateDeny(ServerHttpResponse.ServerError(
                OAuthErrors.ServerError, DpopRequestReading.ValidatedProofWithoutClaimsDescription));
        }

        //RFC 9449 Section 4.3, check 12, and Section 7.1: the proof's public key is the one the token is bound to, its
        //thumbprint compared in fixed time; a mismatch is the invalid_token of Figure 16, the token's binding being what
        //fails.
        if(!FixedTimeComparison.AreEqual(proofThumbprint, boundThumbprint))
        {
            return DpopResourceDecision.Deny(RefuseUnderScheme(true, OAuthErrors.InvalidToken,
                "The DPoP proof key does not match the Access Token's cnf.jkt binding.", checks));
        }

        //RFC 9449 Section 11.1: "servers MUST only accept DPoP proofs for a limited time after their creation", and
        //Section 7.1: "The resource server MUST NOT grant access to the resource unless all checks are successful." A
        //validation admitting an iat beyond the resource's window is cut to it, so the jti record, kept for that window,
        //covers every instant the proof is accepted at.
        if(checks.IsIssuedAtWithinFreshnessWindow is { } isIssuedAtWithinFreshnessWindow
            && !isIssuedAtWithinFreshnessWindow(proofClaims.Iat))
        {
            return DpopResourceDecision.Deny(RefuseUnderScheme(true, OAuthErrors.InvalidDpopProof,
                "DPoP proof iat lies outside the resource's freshness window.", checks));
        }

        //RFC 9449 Section 11.3: no proof without the nonce claim is accepted once a nonce has been provided, and this
        //resource provides one to every client it challenges; Section 8.1's "nonce = 1*NQCHAR" makes an empty claim no
        //nonce. Section 9: its nonce is accepted only at the endpoint that issued it, the target URI.
        if(proofClaims.Nonce is not { Length: > 0 } nonce)
        {
            return DpopResourceDecision.Deny(await ChallengeForNonceAsync(
                issueNonce, targetUri, "DPoP nonce required.", checks, cancellationToken).ConfigureAwait(false));
        }

        DpopNonceValidationResult nonceResult = await validateNonce(nonce, targetUri, cancellationToken).ConfigureAwait(false);
        if(!nonceResult.IsSuccess)
        {
            return DpopResourceDecision.Deny(await ChallengeForNonceAsync(
                issueNonce, targetUri, $"DPoP nonce invalid: {nonceResult.FailureReason}.", checks, cancellationToken).ConfigureAwait(false));
        }

        //RFC 9449 Section 11.1: the proof's jti is recorded for the time window in which the proof would be accepted,
        //which its iat bounds. An outcome other than the four named fails closed: only a first use grants access.
        JtiReplayOutcome jtiOutcome = await consultJti(targetUri, proofClaims.Jti, proofClaims.Iat, cancellationToken).ConfigureAwait(false);

        return jtiOutcome switch
        {
            JtiReplayOutcome.FirstUse => DpopResourceDecision.Permit(proofThumbprint),
            JtiReplayOutcome.Replayed => DpopResourceDecision.Deny(RefuseUnderScheme(true,
                OAuthErrors.InvalidDpopProof, "The DPoP proof jti has been presented previously.", checks)),
            JtiReplayOutcome.Unacceptable => DpopResourceDecision.Deny(RefuseUnderScheme(true,
                OAuthErrors.InvalidDpopProof, JtiReplayGuard.UnstorableDpopProofJtiDescription, checks)),
            JtiReplayOutcome.StoreUnavailable => DpopResourceDecision.IndeterminateDeny(ServerHttpResponse.ServerError(
                OAuthErrors.ServerError, checks.JtiStoreUnavailableDescription)),

            _ => DpopResourceDecision.IndeterminateDeny(ServerHttpResponse.ServerError(
                OAuthErrors.ServerError, UnrecognizedJtiOutcomeDescription))
        };
    }


    /// <summary>
    /// Attaches the <c>DPoP</c> challenge <paramref name="challenge"/> to <paramref name="response"/> as its
    /// <c>WWW-Authenticate</c> field, with the field <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>
    /// (<see cref="WellKnownDpopValues.ExposedDpopResponseFields"/>): the one place a <c>DPoP</c> challenge is attached,
    /// so every such answer exposes its fields to a browser application.
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
    /// The <c>DPoP</c> challenge of <paramref name="checks"/> with <paramref name="error"/>, written by
    /// <see cref="DpopChallenge.BuildChallenge"/>: <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449
    /// Section 7.1</see>, "The scheme name is DPoP.", the realm, the error, the scope, the <c>algs</c> and the metadata URL
    /// of the resource. The <c>algs</c> are the resource's accepted algorithms a proof can be accepted under
    /// (<see cref="DpopProofValidator.AcceptableProofAlgorithms"/>; Section 7.1: "An algs parameter SHOULD be included to
    /// signal to the client the JWS algorithms that are acceptable for the DPoP proof JWT."), and the parameter is absent
    /// when none remains.
    /// </summary>
    /// <param name="error">The error code, or <see langword="null"/> for none.</param>
    /// <param name="checks">The challenge parameters.</param>
    /// <returns>The <c>WWW-Authenticate</c> value.</returns>
    private static string BuildChallenge(string? error, DpopResourceChecks checks) =>
        DpopChallenge.BuildChallenge(
            checks.Realm,
            error,
            checks.Scope,
            checks.AcceptedAlgorithms is IReadOnlyList<string> acceptedAlgorithms ? DpopProofValidator.AcceptableProofAlgorithms(acceptedAlgorithms) : null,
            checks.ResourceMetadata);


    /// <summary>
    /// A 401 refusal carrying <paramref name="error"/> in the body and the challenge of the presentation's scheme: the
    /// <c>DPoP</c> challenge with the same error, attached through <see cref="WithDpopChallenge"/>, or the
    /// <see cref="DpopResourceChecks.BearerChallenge"/> for a <c>Bearer</c> presentation, whose refusals are all
    /// <c>invalid_token</c>. <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>:
    /// "If the mechanism used to attempt authentication could be established unambiguously, then the corresponding
    /// challenge SHOULD be used to deliver error information".
    /// </summary>
    /// <param name="isDpopPresentation">Whether the token was presented under the <c>DPoP</c> scheme.</param>
    /// <param name="error">The error code.</param>
    /// <param name="description">The <c>error_description</c> the body carries.</param>
    /// <param name="checks">The challenge parameters.</param>
    /// <returns>The 401 response.</returns>
    private static ServerHttpResponse RefuseUnderScheme(bool isDpopPresentation, string error, string description, DpopResourceChecks checks) =>
        isDpopPresentation
            ? WithDpopChallenge(ServerHttpResponse.Unauthorized(error, description), BuildChallenge(error, checks))
            : ServerHttpResponse.Unauthorized(error, description).WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, checks.BearerChallenge);


    /// <summary>
    /// Issues a fresh nonce for <paramref name="targetUri"/> and answers with the
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see> challenge: 401,
    /// <c>use_dpop_nonce</c> in the body and in the <c>DPoP</c> challenge, and the nonce in the one <c>DPoP-Nonce</c>
    /// field: "Resource servers use an HTTP 401 (Unauthorized) error code with an accompanying WWW-Authenticate: DPoP
    /// value and DPoP-Nonce value to accomplish this."
    /// </summary>
    /// <param name="issueNonce">The nonce issuance.</param>
    /// <param name="targetUri">The target URI the nonce is issued for, the one endpoint it is accepted at.</param>
    /// <param name="description">The <c>error_description</c> the body carries.</param>
    /// <param name="checks">The challenge parameters.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The 401 nonce challenge.</returns>
    private static async ValueTask<ServerHttpResponse> ChallengeForNonceAsync(
        Func<Uri, CancellationToken, ValueTask<string>> issueNonce,
        Uri targetUri,
        string description,
        DpopResourceChecks checks,
        CancellationToken cancellationToken)
    {
        string freshNonce = await issueNonce(targetUri, cancellationToken).ConfigureAwait(false);

        return WithDpopChallenge(
                ServerHttpResponse.Unauthorized(OAuthErrors.UseDpopNonce, description),
                BuildChallenge(OAuthErrors.UseDpopNonce, checks))
            .WithHeader(WellKnownHttpHeaderNames.DPoPNonce, freshNonce);
    }


    /// <summary>
    /// The <c>jti</c> step of <see cref="DecideAsync"/>: refuses a <c>jti</c> no record can hold
    /// (<see cref="JtiReplayGuard.IsStorableJti"/>) with <see cref="JtiReplayOutcome.Unacceptable"/> before the slot is
    /// called, and otherwise claims the proof's <c>jti</c> through <paramref name="consultJti"/> once, in the context of
    /// <paramref name="targetUri"/> and until <see cref="RecordExpiry"/>, answering the claim's outcome
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "In the context of
    /// the target URI, servers can store the jti value of each DPoP proof for the time window in which the respective DPoP
    /// proof JWT would be accepted to prevent multiple uses of the same DPoP proof."). The slot is handed the target URI in
    /// the one normalized form the <c>htu</c> comparison reads (<see cref="DpopProofValidator.NormalizeTargetUri"/>), the
    /// form the library's replay guard keys by, so every spelling of one target the proof's <c>htu</c> matches names one
    /// record (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>: "servers SHOULD employ
    /// syntax-based normalization (Section 6.2.2 of [RFC3986]) and scheme-based normalization (Section 6.2.3 of [RFC3986])
    /// before comparing the htu claim.").
    /// </summary>
    /// <param name="integration">The resource server's slots and clock.</param>
    /// <param name="consultJti">The atomic claim.</param>
    /// <param name="targetUri">The request's target URI, the claim's context once normalized.</param>
    /// <param name="jti">The proof's <c>jti</c>.</param>
    /// <param name="issuedAt">The proof's <c>iat</c>.</param>
    /// <param name="freshnessWindow">The window the proof's <c>iat</c> is held to, read once per decision.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The outcome.</returns>
    private static async ValueTask<JtiReplayOutcome> ClaimJtiAsync(
        ResourceServerIntegration integration,
        ConsultDpopProofJtiDelegate consultJti,
        Uri targetUri,
        string jti,
        DateTimeOffset issuedAt,
        TimeSpan freshnessWindow,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(!JtiReplayGuard.IsStorableJti(jti))
        {
            return JtiReplayOutcome.Unacceptable;
        }

        DateTimeOffset recordUntil = RecordExpiry(integration.TimeProvider.GetUtcNow(), issuedAt, freshnessWindow);
        Uri normalizedTargetUri = new(DpopProofValidator.NormalizeTargetUri(targetUri.OriginalString));

        return await consultJti(jti, normalizedTargetUri, recordUntil, context, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The instant a proof's <c>jti</c> record is kept until: the first instant after the proof's acceptance window, so a
    /// replay at the window's last instant is still refused. <see cref="DecideAsync"/> accepts a proof only while its
    /// <c>iat</c> lies within <paramref name="freshnessWindow"/> of the clock either way, the bounds included
    /// (<see cref="IsWithinFreshnessWindow"/>), whatever the wired validation's tolerance, so it is accepted until
    /// <c>iat + window</c> and is never accepted after <c>max(now, iat) + window</c>; the record lasts one tick past that
    /// instant, which a store reading its expiry as the last instant the entry counts and one reading it as the first
    /// instant the entry does not count (<see cref="Dpop.InMemoryDpopReplayCache"/>, whose record counts while its instant
    /// is after the clock) both
    /// hold through the window. An instant past the latest a <see cref="DateTimeOffset"/> holds reads as that latest instant.
    /// </summary>
    /// <param name="now">The resource server's clock.</param>
    /// <param name="issuedAt">The proof's <c>iat</c>.</param>
    /// <param name="freshnessWindow">The tolerance on a proof's <c>iat</c>, <see cref="ResourceServerIntegration.DpopFreshnessWindow"/>.</param>
    /// <returns>The record's expiry.</returns>
    private static DateTimeOffset RecordExpiry(DateTimeOffset now, DateTimeOffset issuedAt, TimeSpan freshnessWindow)
    {
        DateTimeOffset windowStart = issuedAt > now ? issuedAt : now;
        TimeSpan recordSpan = freshnessWindow + TimeSpan.FromTicks(1);

        return DateTimeOffset.MaxValue - windowStart > recordSpan
            ? windowStart + recordSpan
            : DateTimeOffset.MaxValue;
    }
}
