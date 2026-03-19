using System.Diagnostics;
using Verifiable.Core.Automata;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Dispatches <see cref="OAuthAction"/> instances to registered handlers, driving
/// the effectful work between pure PDA transitions.
/// </summary>
/// <remarks>
/// <para>
/// Handlers are registered by action type via <see cref="Register{TAction}"/>. The
/// <see cref="ExecuteAsync"/> method looks up the concrete action type and invokes
/// the matching handler. This makes the executor extensible — library users register
/// handlers for their own <see cref="OAuthAction"/> subtypes without modifying the
/// executor class.
/// </para>
/// <para>
/// The library provides pre-wired executors for standard profiles via factory methods
/// such as <see cref="Verifiable.OAuth.Oid4Vp.HaipOid4VpVerifierExecutor.Create"/>.
/// These register the appropriate handlers at construction time. Library users extend
/// them by registering additional handlers for custom action types.
/// </para>
/// <para>
/// The effectful dispatch loop in <see cref="FlowRunner"/> calls
/// <see cref="ExecuteAsync"/> after each pure PDA transition until the new state
/// returns <see cref="NullAction.Instance"/> from its
/// <see cref="OAuthFlowState.NextAction"/> property.
/// </para>
/// </remarks>
[DebuggerDisplay("OAuthActionExecutor({handlers.Count} handlers)")]
public sealed class OAuthActionExecutor
{
    //Keyed by the concrete OAuthAction subtype. Each value is a delegate
    //that accepts the action as OAuthAction and downcasts internally.
    private readonly Dictionary<Type, Func<OAuthAction, RequestContext, AuthorizationServerOptions, CancellationToken, ValueTask<OAuthFlowInput>>> handlers = new();


    /// <summary>
    /// Registers a handler for a specific <see cref="OAuthAction"/> subtype.
    /// </summary>
    /// <typeparam name="TAction">The concrete action type this handler processes.</typeparam>
    /// <param name="handler">
    /// The handler delegate. Receives the action already downcast to
    /// <typeparamref name="TAction"/>.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when a handler is already registered for <typeparamref name="TAction"/>.
    /// </exception>
    public void Register<TAction>(ActionHandlerDelegate<TAction> handler)
        where TAction : OAuthAction
    {
        ArgumentNullException.ThrowIfNull(handler);

        //Wrap the typed delegate so the dictionary stores a uniform signature.
        //The downcast is safe because ExecuteAsync dispatches by typeof(action).
        if(!handlers.TryAdd(
            typeof(TAction),
            (action, context, options, ct) => handler((TAction)action, context, options, ct)))
        {
            throw new ArgumentException(
                $"A handler is already registered for '{typeof(TAction).Name}'.",
                nameof(handler));
        }
    }


    /// <summary>
    /// Dispatches <paramref name="action"/> to the registered handler and returns
    /// the <see cref="OAuthFlowInput"/> to feed into the next pure PDA transition.
    /// </summary>
    /// <param name="action">The action to execute.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="options">The server options carrying all I/O delegates.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no handler is registered for <paramref name="action"/>'s concrete type.
    /// </exception>
    public ValueTask<OAuthFlowInput> ExecuteAsync(
        OAuthAction action,
        RequestContext context,
        AuthorizationServerOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(options);

        Type actionType = action.GetType();

        if(!handlers.TryGetValue(actionType, out var handler))
        {
            throw new InvalidOperationException(
                $"No handler registered for action type '{actionType.Name}'. " +
                $"Call Register<{actionType.Name}>() on the executor.");
        }

        return handler(action, context, options, cancellationToken);
    }
}
