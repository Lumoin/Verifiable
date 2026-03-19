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
/// The handler receives the <see cref="AuthorizationServer"/> instance so it can
/// read key resolvers, encoder delegates, and other server configuration at call
/// time without closure capture. Read from the appropriate group:
/// <c>server.Cryptography.SigningKeyResolver</c>, <c>server.Codecs.Encoder</c>,
/// and so on.
/// </para>
/// </remarks>
/// <typeparam name="TAction">The concrete action type this handler processes.</typeparam>
/// <param name="action">The action to execute.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="server">
/// The Authorization Server instance carrying all integration, cryptography, and
/// codec delegates.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The input to feed into the next PDA transition.</returns>
public delegate ValueTask<OAuthFlowInput> ActionHandlerDelegate<in TAction>(
    TAction action,
    RequestContext context,
    AuthorizationServer server,
    CancellationToken cancellationToken) where TAction: OAuthAction;
