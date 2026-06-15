using Verifiable.Core;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Handles a specific <see cref="OAuthAction"/> subtype, performing the effectful
/// work between two pure PDA transitions and returning the input to feed into the
/// next transition.
/// </summary>
/// <remarks>
/// <para>
/// Registered on <see cref="OAuthActionExecutor"/> via
/// <see cref="OAuthActionExecutor.Register{TAction}"/>. The executor dispatches to
/// the registered handler by looking up the concrete <see cref="OAuthAction"/>
/// type in its registry.
/// </para>
/// <para>
/// The handler reaches the <see cref="EndpointServer"/> instance for key
/// resolvers, encoder delegates, and other server configuration via
/// <see cref="ExchangeContextServerExtensions.Server"/> on
/// <paramref name="context"/>; the dispatcher places the active server on the
/// context at entry. Read from the appropriate group:
/// <c>context.Server!.Cryptography.SigningKeyResolver</c>,
/// <c>context.Server!.Codecs.Encoder</c>, and so on.
/// </para>
/// </remarks>
/// <typeparam name="TAction">The concrete action type this handler processes.</typeparam>
/// <param name="action">The action to execute.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The input to feed into the next PDA transition.</returns>
public delegate ValueTask<FlowInput> ActionHandlerDelegate<in TAction>(
    TAction action,
    ExchangeContext context,
    CancellationToken cancellationToken) where TAction: OAuthAction;
