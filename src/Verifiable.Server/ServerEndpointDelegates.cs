using Verifiable.Core;
namespace Verifiable.Server;

/// <summary>
/// Validates the inbound request fields, performs effectful work, and returns
/// the <see cref="FlowInput"/> to step the PDA with.
/// </summary>
/// <remarks>
/// <para>
/// Return <c>(null, earlyExit)</c> when validation fails before an input can be
/// constructed — for example when a required field is missing. The
/// dispatch host returns the <c>earlyExit</c> response
/// immediately without stepping the PDA.
/// </para>
/// <para>
/// Return <c>(input, null)</c> when validation succeeds. The dispatcher steps the
/// PDA with the input and builds the response via <see cref="BuildResponseDelegate"/>.
/// </para>
/// </remarks>
/// <param name="fields">The parsed request fields from the HTTP form body or query string.</param>
/// <param name="context">
/// Application-defined request context parameter bag. Backend access (the
/// dispatch host instance carrying integration,
/// cryptography, and codec delegates) is reached through
/// <c>ExchangeContextServerExtensions.RequestServer</c>.
/// </param>
/// <param name="currentState">The current PDA state before the step.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<(FlowInput? Input, ServerHttpResponse? EarlyExit)> BuildInputDelegate(
    RequestFields fields,
    ExchangeContext context,
    FlowState currentState,
    CancellationToken cancellationToken);


/// <summary>
/// Builds the <see cref="ServerHttpResponse"/> from the state the PDA landed in
/// after a successful step.
/// </summary>
/// <param name="resultState">The PDA state after the step.</param>
/// <param name="flowKindName">
/// The <see cref="FlowKind.Name"/> of the flow, for logging and error messages.
/// </param>
/// <param name="context">The request context, available for response customization.</param>
public delegate ServerHttpResponse BuildResponseDelegate(
    FlowState resultState,
    string flowKindName,
    ExchangeContext context);


/// <summary>
/// The endpoint's own check: it needs only the request, the registration the
/// dispatcher already loaded and materialized, and the server, and it runs once
/// per request before any flow is created and before any stored record is
/// correlated or loaded.
/// </summary>
/// <remarks>
/// <para>
/// Runs for grants that do not exist by design. An unauthenticated caller can
/// name any handle and reach this step, so whatever it calls — the
/// application's credential validator, a proof verification, a nonce or
/// assertion replay store — is reachable by that caller and must stay bounded
/// in cost. This is the library's cryptography-before-storage ordering.
/// </para>
/// <para>
/// May consume single-use authentication material (a client assertion's
/// <c>jti</c>, a DPoP proof's <c>jti</c>, a nonce). Those stores are
/// authentication stores, never the grant store. The flow identifier, the flow
/// step count and the request's verified-at instant are not yet populated on
/// <see cref="ExchangeContext"/> when it runs. This is the design's cost, not an
/// oversight: an application wiring a <c>jti</c> or nonce store makes that store
/// reachable by any unauthenticated caller naming an arbitrary handle, and a
/// captured assertion or proof can be spent — burning its single use — by
/// whoever holds it, before the handle it was meant for is ever resolved. A
/// resolver fault or a declined resolution (an application-supplied issuer
/// delegate throwing, or answering <see langword="null"/>) is folded onto the
/// same refusal a nonexistent handle receives, for the same uniformity reason.
/// </para>
/// <para>
/// A stateless or new-flow endpoint runs this step first, before anything
/// else — there is no correlation handle to find. A continuing-flow endpoint
/// runs it after the dispatcher has found a handle present (so "Missing code."
/// and its siblings still answer a request naming none) and before that handle
/// is correlated against a tenant or its state is loaded.
/// </para>
/// <para>
/// Hosted on <see cref="ServerEndpoint"/> rather than as a registration-scoped
/// hook because a registration-scoped hook belongs to the application, while a
/// step set on the endpoint travels with the endpoint chain that
/// <see cref="Pipeline.EndpointChain.BuildForRequestAsync"/> rebuilds from
/// configuration on every request, so a live alteration cannot lose it.
/// </para>
/// </remarks>
/// <param name="endpoint">The matched endpoint, as <see cref="Routing.MatchRequestDelegate"/> receives it.</param>
/// <param name="fields">The parsed request fields from the HTTP form body or query string.</param>
/// <param name="context">
/// Application-defined request context parameter bag. Backend access is
/// reached the way <see cref="BuildInputDelegate"/>'s remarks describe, via
/// <c>ExchangeContextServerExtensions.RequestServer</c>.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The refusal to answer with, or <see langword="null"/> to proceed.</returns>
public delegate ValueTask<ServerHttpResponse?> BeforeCorrelationDelegate(
    ServerEndpoint endpoint,
    RequestFields fields,
    ExchangeContext context,
    CancellationToken cancellationToken);
