using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;
using Verifiable.Core.Assessment;

using Verifiable.OAuth.Server.Audit;
using Verifiable.OAuth.Server.Routing;
using Verifiable.OAuth.Server.Pipeline;
namespace Verifiable.OAuth.Server;

/// <summary>
/// Typed accessor extensions for well-known entries in a <see cref="ExchangeContext"/>
/// used by the Authorization Server dispatcher and endpoint delegates.
/// </summary>
/// <remarks>
/// <para>
/// These extension methods eliminate the need for callers to know string key names
/// or cast <see cref="object"/> values. The underlying keys are defined in
/// <see cref="AuthorizationServerHandlers"/> and remain stable across versions.
/// </para>
/// <para>
/// Library users add their own typed accessors following the same pattern using
/// C# 14 extension syntax. The methods appear alongside the library-provided ones
/// in IntelliSense.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class ExchangeContextServerExtensions
{
    extension(ExchangeContext context)
    {
        //TenantId is a cross-cutting accessor; it lives in Core's
        //ExchangeContextExtensions over the neutral context, not here.

        /// <summary>
        /// Gets the capability of the matched endpoint, placed by the dispatcher
        /// after the matcher walk completes. Read by post-match telemetry,
        /// observability, and audit code. Not a routing input — Phase 4 made
        /// capability descriptive metadata rather than a chain-walk filter.
        /// </summary>
        /// <returns>
        /// The matched capability, or <see langword="null"/> when no match has
        /// occurred yet (pre-match) or no endpoint accepted (post-match).
        /// </returns>
        public CapabilityIdentifier? Capability =>
            context.TryGetValue(AuthorizationServerHandlers.CapabilityKey, out object? v)
                && v is CapabilityIdentifier c ? c : default(CapabilityIdentifier?);

        /// <summary>
        /// Sets the capability of the matched endpoint. Called by the dispatcher
        /// after the chain walk produces a non-<see langword="null"/> match,
        /// reading <see cref="ServerEndpoint.Capability"/> from the winning
        /// endpoint. The skin and tests do not call this — the dispatcher owns
        /// it.
        /// </summary>
        /// <param name="capability">The capability of the matched endpoint.</param>
        public void SetCapability(CapabilityIdentifier capability)
        {
            context[AuthorizationServerHandlers.CapabilityKey] = capability;
        }


        /// <summary>
        /// Gets the server issuer URI placed by the ASP.NET skin.
        /// </summary>
        /// <returns>
        /// The issuer <see cref="Uri"/>, or <see langword="null"/> when not set.
        /// </returns>
        public Uri? Issuer =>
            context.TryGetValue(AuthorizationServerHandlers.IssuerKey, out object? v)
                && v is Uri u ? u : null;

        /// <summary>
        /// Sets the server issuer URI. Called by the ASP.NET skin before dispatching.
        /// </summary>
        /// <param name="issuer">The issuer URI.</param>
        public void SetIssuer(Uri issuer)
        {
            ArgumentNullException.ThrowIfNull(issuer);
            context[AuthorizationServerHandlers.IssuerKey] = issuer;
        }


        /// <summary>
        /// Gets the authenticated subject identifier placed by the application's
        /// authentication middleware.
        /// </summary>
        /// <returns>
        /// The subject identifier string, or <see langword="null"/> when the user
        /// is not authenticated or the value was not set.
        /// </returns>
        public string? SubjectId =>
            context.TryGetValue(AuthorizationServerHandlers.SubjectIdKey, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>
        /// Sets the authenticated subject identifier. Called by the application's
        /// authentication middleware before dispatching to the authorize endpoint.
        /// </summary>
        /// <param name="subjectId">The authenticated subject identifier.</param>
        public void SetSubjectId(string subjectId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
            context[AuthorizationServerHandlers.SubjectIdKey] = subjectId;
        }


        /// <summary>
        /// Gets the authentication time placed by the application's authentication
        /// middleware.
        /// </summary>
        /// <returns>
        /// The authentication time, or <see langword="null"/> when not set.
        /// </returns>
        public DateTimeOffset? AuthTime =>
            context.TryGetValue(AuthorizationServerHandlers.AuthTimeKey, out object? v)
                && v is DateTimeOffset dt ? dt : null;

        /// <summary>
        /// Sets the authentication time. Called by the application's authentication
        /// middleware before dispatching to the authorize endpoint.
        /// </summary>
        /// <param name="authTime">The UTC instant at which the subject authenticated.</param>
        public void SetAuthTime(DateTimeOffset authTime)
        {
            context[AuthorizationServerHandlers.AuthTimeKey] = authTime;
        }


        /// <summary>
        /// Gets the End-User's authentication session identifier (<c>sid</c>) placed
        /// by the application's authentication middleware. Carried from the authorize
        /// endpoint through the flow state into the ID Token's <c>sid</c> claim, so it
        /// identifies the specific login session (not merely the subject) — the value
        /// OIDC Back-Channel / Front-Channel Logout reference per session.
        /// </summary>
        /// <returns>
        /// The session identifier, or <see langword="null"/> when the application did
        /// not stamp one (no session-scoped logout for this deployment).
        /// </returns>
        public string? SessionId =>
            context.TryGetValue(AuthorizationServerHandlers.SessionIdKey, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>
        /// Sets the authentication session identifier (<c>sid</c>). Called by the
        /// application's authentication middleware before dispatching to the authorize
        /// endpoint, alongside <see cref="SetAuthTime"/> and <see cref="SetSubjectId"/>.
        /// </summary>
        /// <param name="sessionId">The session identifier.</param>
        public void SetSessionId(string sessionId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);
            context[AuthorizationServerHandlers.SessionIdKey] = sessionId;
        }


        /// <summary>
        /// Gets the Authentication Context Class Reference (<c>acr</c>) placed by the
        /// application's authentication middleware. Carried from the authorize endpoint
        /// through the flow state into the access token's <c>acr</c> claim per
        /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2.1">RFC 9068 §2.2.1</see>
        /// and <see href="https://www.rfc-editor.org/rfc/rfc9470#section-5">RFC 9470 §5</see>,
        /// so the Resource Server can read the authentication strength actually achieved.
        /// </summary>
        /// <returns>
        /// The established <c>acr</c> value, or <see langword="null"/> when the
        /// application stamped none (no step-up / authentication-context tracking).
        /// </returns>
        public string? Acr =>
            context.TryGetValue(AuthorizationServerHandlers.AcrKey, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>
        /// Sets the Authentication Context Class Reference (<c>acr</c>). Called by the
        /// application's authentication middleware before dispatching to the authorize
        /// endpoint, alongside <see cref="SetAuthTime"/> and <see cref="SetSessionId"/>.
        /// </summary>
        /// <param name="acr">The established authentication context class reference.</param>
        public void SetAcr(string acr)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(acr);
            context[AuthorizationServerHandlers.AcrKey] = acr;
        }


        /// <summary>
        /// Gets the <see cref="ClientRecord"/> resolved by the dispatcher at the
        /// start of each request. Available to all <see cref="BuildInputDelegate"/>
        /// implementations without capturing the registration from outside.
        /// </summary>
        /// <returns>
        /// The resolved registration, or <see langword="null"/> when the dispatcher has
        /// not yet resolved it.
        /// </returns>
        public ClientRecord? Registration =>
            context.TryGetValue(AuthorizationServerHandlers.RegistrationKey, out object? v)
                && v is ClientRecord r ? r : null;

        /// <summary>
        /// Sets the resolved <see cref="ClientRecord"/>. Called by the dispatcher
        /// after resolving the registration by tenant identifier.
        /// </summary>
        /// <param name="registration">The resolved client registration.</param>
        public void SetRegistration(ClientRecord registration)
        {
            ArgumentNullException.ThrowIfNull(registration);
            context[AuthorizationServerHandlers.RegistrationKey] = registration;
        }


        /// <summary>
        /// Gets the flow identifier written by a <see cref="BuildInputDelegate"/>
        /// on continuing-flow endpoints.
        /// </summary>
        /// <returns>
        /// The flow identifier string, or <see langword="null"/> when not set.
        /// </returns>
        public string? FlowId =>
            context.TryGetValue(AuthorizationServerHandlers.FlowIdKey, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>
        /// Sets the flow identifier. Called by <see cref="BuildInputDelegate"/>
        /// implementations on continuing-flow endpoints.
        /// </summary>
        /// <param name="flowId">The flow identifier.</param>
        public void SetFlowId(string flowId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(flowId);
            context[AuthorizationServerHandlers.FlowIdKey] = flowId;
        }


        /// <summary>
        /// Gets the correlation key generated by <see cref="BuildInputDelegate"/>
        /// on new-flow endpoints. The dispatcher reads this after the delegate runs
        /// to determine the storage key for
        /// <see cref="SaveServerFlowStateDelegate"/>.
        /// </summary>
        /// <returns>
        /// The correlation key string, or <see langword="null"/> when not set.
        /// </returns>
        public string? CorrelationKey =>
            context.TryGetValue(AuthorizationServerHandlers.CorrelationKeyOutputKey, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>
        /// Sets the correlation key generated for a new flow. Called by
        /// <see cref="BuildInputDelegate"/> implementations on new-flow endpoints.
        /// </summary>
        /// <param name="correlationKey">The generated correlation key.</param>
        public void SetCorrelationKey(string correlationKey)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(correlationKey);
            context[AuthorizationServerHandlers.CorrelationKeyOutputKey] = correlationKey;
        }


        /// <summary>
        /// Gets the UTC instant stamped by the dispatcher at the start of effectful
        /// work. All effectful operations within a single request use this consistent
        /// timestamp rather than reading the system clock directly.
        /// </summary>
        /// <returns>
        /// The request timestamp, or <see langword="null"/> when the dispatcher has
        /// not yet stamped it.
        /// </returns>
        public DateTimeOffset? VerifiedAt =>
            context.TryGetValue(AuthorizationServerHandlers.VerifiedAtKey, out object? v)
                && v is DateTimeOffset dt ? dt : null;

        /// <summary>
        /// Sets the request timestamp. Called by the dispatcher once per request
        /// before effectful work begins.
        /// </summary>
        /// <param name="verifiedAt">The UTC instant for this request.</param>
        public void SetVerifiedAt(DateTimeOffset verifiedAt)
        {
            context[AuthorizationServerHandlers.VerifiedAtKey] = verifiedAt;
        }


        /// <summary>
        /// Gets the validation results accumulated during request processing.
        /// Each entry corresponds to one validation point (callback, VP token, etc.)
        /// that ran during this request.
        /// </summary>
        /// <returns>
        /// The list of validation results, or <see langword="null"/> when no
        /// validation has been performed during this request.
        /// </returns>
        public IReadOnlyList<ClaimIssueResult>? ValidationResults =>
            context.TryGetValue(AuthorizationServerHandlers.ValidationResultsKey, out object? v)
                && v is List<ClaimIssueResult> list ? list : null;

        /// <summary>
        /// Appends a validation result to the request context. Called by action
        /// handlers and endpoint delegates after running a
        /// <see cref="ClaimIssuer{TInput}"/>. The application reads
        /// <see cref="ValidationResults"/> after <c>HandleAsync</c> returns for
        /// logging, OTel emission, audit archival, or structured error responses.
        /// </summary>
        /// <param name="result">The validation result to append.</param>
        public void AddValidationResult(ClaimIssueResult result)
        {
            ArgumentNullException.ThrowIfNull(result);

            if(!context.TryGetValue(AuthorizationServerHandlers.ValidationResultsKey, out object? v)
                || v is not List<ClaimIssueResult> list)
            {
                list = [];
                context[AuthorizationServerHandlers.ValidationResultsKey] = list;
            }

            list.Add(result);
        }


        /// <summary>
        /// Gets the <see cref="IssuedTokenSet"/> assembled by the token endpoint
        /// during <c>BuildInputAsync</c> for consumption by <c>BuildResponse</c>.
        /// </summary>
        /// <returns>
        /// The set of issued tokens, or <see langword="null"/> when no tokens
        /// were placed on the context (typical for non-token endpoints).
        /// </returns>
        public IssuedTokenSet? IssuedTokens =>
            context.TryGetValue(AuthorizationServerHandlers.IssuedTokensKey, out object? v)
                && v is IssuedTokenSet set ? set : null;

        /// <summary>
        /// Sets the <see cref="IssuedTokenSet"/> assembled during token endpoint
        /// processing. The transient token strings live here for the remainder of
        /// the request and are consumed by <c>BuildResponse</c> when composing
        /// the HTTP response body. The strings are never persisted.
        /// </summary>
        /// <param name="tokens">The issued token set.</param>
        public void SetIssuedTokens(IssuedTokenSet tokens)
        {
            ArgumentNullException.ThrowIfNull(tokens);
            context[AuthorizationServerHandlers.IssuedTokensKey] = tokens;
        }


        /// <summary>
        /// Gets the typed <see cref="MatchPayload"/> the dispatcher placed on
        /// the context after <see cref="EndpointChain.MatchAsync"/> selected
        /// the matched endpoint.
        /// </summary>
        /// <returns>
        /// The match payload, or <see langword="null"/> when the dispatcher
        /// has not yet matched (the typical state during pre-dispatch
        /// resolution).
        /// </returns>
        /// <remarks>
        /// <para>
        /// Endpoint handlers that consume the payload pattern-match to the
        /// subtype produced by their endpoint's
        /// <see cref="MatchRequestDelegate"/>. Endpoints whose match decision
        /// carries no classification data receive
        /// <see cref="MatchPayload.Empty"/>.
        /// </para>
        /// </remarks>
        public MatchPayload? MatchPayload =>
            context.TryGetValue(AuthorizationServerHandlers.MatchPayloadKey, out object? v)
                && v is MatchPayload payload ? payload : null;

        /// <summary>
        /// Sets the matched <see cref="MatchPayload"/> on the request context.
        /// Called by the dispatcher after
        /// <see cref="EndpointChain.MatchAsync"/> selects the matched endpoint;
        /// not normally called from application code.
        /// </summary>
        /// <param name="payload">The typed match payload.</param>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="payload"/> is <see langword="null"/>.
        /// </exception>
        public void SetMatchPayload(MatchPayload payload)
        {
            ArgumentNullException.ThrowIfNull(payload);
            context[AuthorizationServerHandlers.MatchPayloadKey] = payload;
        }


        /// <summary>
        /// Gets the active <see cref="AuthorizationServer"/> placed on the
        /// context at <see cref="AuthorizationServer.DispatchAsync"/> entry.
        /// Every per-request delegate that needs backend access (cryptography,
        /// codecs, integration delegates) reads it from here rather than
        /// receiving the server as a separate parameter.
        /// </summary>
        /// <returns>
        /// The active <see cref="AuthorizationServer"/>, or
        /// <see langword="null"/> when the dispatcher has not yet stamped it
        /// (the typical state for the brief window before dispatch begins).
        /// </returns>
        public AuthorizationServer? Server =>
            context.TryGetValue(AuthorizationServerHandlers.ServerKey, out object? v)
                && v is AuthorizationServer server ? server : null;

        /// <summary>
        /// Sets the active <see cref="AuthorizationServer"/> on the request
        /// context. Called by the dispatcher at the start of every request;
        /// not normally called from application code.
        /// </summary>
        /// <param name="server">The active authorization server.</param>
        public void SetServer(AuthorizationServer server)
        {
            ArgumentNullException.ThrowIfNull(server);
            context[AuthorizationServerHandlers.ServerKey] = server;
        }


        /// <summary>
        /// Gets the per-request <see cref="EndpointChain"/> the dispatcher
        /// built via <see cref="EndpointChain.BuildForRequestAsync"/>.
        /// Available to inspectors, discovery emission, and any delegate
        /// that needs to project the chain (e.g., to compute capability-
        /// derived discovery flags from chain membership).
        /// </summary>
        /// <returns>
        /// The per-request chain, or <see langword="null"/> when the
        /// dispatcher has not yet built it.
        /// </returns>
        public EndpointChain? EndpointChain =>
            context.TryGetValue(AuthorizationServerHandlers.EndpointChainKey, out object? v)
                && v is EndpointChain chain ? chain : null;

        /// <summary>
        /// Sets the per-request <see cref="EndpointChain"/>. Called by the
        /// dispatcher after the chain is built; not normally called from
        /// application code.
        /// </summary>
        /// <param name="chain">The per-request endpoint chain.</param>
        public void SetEndpointChain(EndpointChain chain)
        {
            ArgumentNullException.ThrowIfNull(chain);
            context[AuthorizationServerHandlers.EndpointChainKey] = chain;
        }


        /// <summary>
        /// Gets the per-request set of allowed capabilities returned by
        /// <see cref="AuthorizationServerIntegration.ResolveCapabilitiesAsync"/>
        /// during chain build. Used by request-time gating sites that run
        /// inside a handler (e.g., a token producer asking "is my required
        /// capability still active under the current request's CAEP/RISC
        /// attenuation?"). Static endpoint-builder gates read from
        /// <see cref="ClientRecord.AllowedCapabilities"/> instead — those
        /// run before the resolver and supply candidates for it to filter.
        /// </summary>
        /// <returns>
        /// The resolver's output for the current request, or
        /// <see langword="null"/> when the chain has not yet been built.
        /// </returns>
        public IReadOnlySet<CapabilityIdentifier>? ResolvedCapabilities =>
            context.TryGetValue(AuthorizationServerHandlers.ResolvedCapabilitiesKey, out object? v)
                && v is IReadOnlySet<CapabilityIdentifier> caps ? caps : null;

        /// <summary>
        /// Sets the per-request resolved capability set. Called by
        /// <see cref="EndpointChain.BuildForRequestAsync"/> after invoking the
        /// resolver; not normally called from application code.
        /// </summary>
        public void SetResolvedCapabilities(IReadOnlySet<CapabilityIdentifier> capabilities)
        {
            ArgumentNullException.ThrowIfNull(capabilities);
            context[AuthorizationServerHandlers.ResolvedCapabilitiesKey] = capabilities;
        }


        /// <summary>
        /// Gets the <see cref="ConfirmationMethod"/> binding the issuance
        /// pipeline established for the current request (typically the DPoP
        /// <c>jkt</c> thumbprint per RFC 9449 §6.1). Claim contributors
        /// emitting confirmation-related claims (e.g., <c>cnf.jkt</c> in an
        /// ID Token) read from this single per-request source rather than
        /// chasing producer-specific fields.
        /// </summary>
        /// <returns>
        /// The confirmation method, or <see langword="null"/> when no
        /// binding was established (Bearer issuance).
        /// </returns>
        public ConfirmationMethod? Confirmation =>
            context.TryGetValue(AuthorizationServerHandlers.ConfirmationKey, out object? v)
                && v is ConfirmationMethod confirmation ? confirmation : null;

        /// <summary>
        /// Sets the <see cref="ConfirmationMethod"/> binding on the request
        /// context. Called by the issuance pipeline before walking claim
        /// contributors so contributors read from the same per-request
        /// source as every other resolved value.
        /// </summary>
        /// <param name="confirmation">The confirmation method.</param>
        public void SetConfirmation(ConfirmationMethod confirmation)
        {
            ArgumentNullException.ThrowIfNull(confirmation);
            context[AuthorizationServerHandlers.ConfirmationKey] = confirmation;
        }
    }
}
