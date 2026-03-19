namespace Verifiable.OAuth.Server;

/// <summary>
/// Validates the inbound request fields, performs effectful work, and returns
/// the <see cref="OAuthFlowInput"/> to step the PDA with.
/// </summary>
/// <remarks>
/// <para>
/// Return <c>(null, earlyExit)</c> when validation fails before an input can be
/// constructed — for example when a required field is missing. The
/// <see cref="AuthorizationServerDispatcher"/> returns the <c>earlyExit</c> response
/// immediately without stepping the PDA.
/// </para>
/// <para>
/// Return <c>(input, null)</c> when validation succeeds. The dispatcher steps the
/// PDA with the input and builds the response via <see cref="BuildResponseDelegate"/>.
/// </para>
/// </remarks>
/// <param name="fields">The parsed request fields from the HTTP form body or query string.</param>
/// <param name="context">Application-defined request context parameter bag.</param>
/// <param name="currentState">The current PDA state before the step.</param>
/// <param name="options">The server options carrying all I/O delegates.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<(OAuthFlowInput? Input, ServerHttpResponse? EarlyExit)> BuildInputDelegate(
    RequestFields fields,
    RequestContext context,
    OAuthFlowState currentState,
    AuthorizationServerOptions options,
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
    OAuthFlowState resultState,
    string flowKindName,
    RequestContext context);
