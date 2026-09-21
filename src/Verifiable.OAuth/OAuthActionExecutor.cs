using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Foundation.Automata;

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
/// <see cref="FlowState.NextAction"/> property.
/// </para>
/// </remarks>
[DebuggerDisplay("OAuthActionExecutor({Handlers.Count} handlers)")]
public sealed class OAuthActionExecutor: WiringComponent
{
    /// <summary>Handlers keyed by their concrete action type and adapted to the common action shape.</summary>
    private Dictionary<Type, Func<OAuthAction, ExchangeContext, CancellationToken, ValueTask<FlowInput>>> Handlers { get; set; } = [];


    /// <summary>Copies registered handlers into an independent alteration candidate.</summary>
    protected override WiringComponent CloneCore()
    {
        OAuthActionExecutor copy = (OAuthActionExecutor)base.CloneCore();
        copy.Handlers = new(Handlers);

        return copy;
    }


    /// <summary>
    /// Registers a handler for a specific <see cref="OAuthAction"/> subtype.
    /// </summary>
    /// <remarks>Serving registration requires an alteration candidate; a live call throws a named configuration fault.</remarks>
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
        lock(MutationLock)
        {
            EnsureMutable();
            ArgumentNullException.ThrowIfNull(handler);

            //Wrap the typed delegate so the dictionary stores a uniform signature.
            //The downcast is safe because ExecuteAsync dispatches by typeof(action).
            if(!Handlers.TryAdd(
                typeof(TAction),
                (action, context, ct) => handler((TAction)action, context, ct)))
            {
                throw new ArgumentException(
                    $"A handler is already registered for '{typeof(TAction).Name}'.",
                    nameof(handler));
            }
        }
    }


    /// <summary>Whether a handler is registered for <typeparamref name="TAction"/>.</summary>
    /// <remarks>
    /// Lets an endpoint that only sometimes needs a specific action fail closed with a graceful
    /// response before invoking <see cref="ExecuteAsync"/>, rather than letting its unhandled-action
    /// <see cref="InvalidOperationException"/> propagate out of a candidate composition that validated
    /// successfully but never wired this handler.
    /// </remarks>
    /// <typeparam name="TAction">The concrete action type to check.</typeparam>
    public bool IsRegistered<TAction>() where TAction : OAuthAction
    {

        return Handlers.ContainsKey(typeof(TAction));
    }


    /// <summary>
    /// Dispatches <paramref name="action"/> to the registered handler and returns
    /// the <see cref="FlowInput"/> to feed into the next pure PDA transition.
    /// </summary>
    /// <param name="action">The action to execute.</param>
    /// <param name="context">
    /// The per-request context bag. Handlers reach the active
    /// <see cref="EndpointServer"/> via
    /// <c>ExchangeContextServerExtensions.RequestServer</c>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no handler is registered for <paramref name="action"/>'s concrete type.
    /// </exception>
    public ValueTask<FlowInput> ExecuteAsync(
        OAuthAction action,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        ArgumentNullException.ThrowIfNull(context);

        Type actionType = action.GetType();

        if(!Handlers.TryGetValue(actionType, out var handler))
        {
            throw new InvalidOperationException(
                $"No handler registered for action type '{actionType.Name}'. " +
                $"Call Register<{actionType.Name}>() on the executor.");
        }

        return handler(action, context, cancellationToken);
    }
}
