using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// A flow kind backed by a pushdown automaton with persisted state.
/// </summary>
/// <remarks>
/// <para>
/// Derived types supply the <see cref="CreateAsync"/> and <see cref="StepAsync"/>
/// methods that wrap the flow's concrete <c>PushdownAutomaton</c> construction
/// and stepping. The <see cref="AuthorizationServer"/> dispatcher calls these at
/// request time — new flows via <see cref="CreateAsync"/>, continuing flows via
/// <see cref="StepAsync"/> after loading the persisted state.
/// </para>
/// <para>
/// Concrete <see cref="StatefulFlowKind"/> subclasses are sealed singletons with
/// a private constructor and a <c>public static Instance { get; }</c> property.
/// </para>
/// </remarks>
[DebuggerDisplay("StatefulFlowKind Name={Name}")]
public abstract class StatefulFlowKind: FlowKind
{
    /// <summary>
    /// Creates a fresh PDA for a new flow session and returns its initial state
    /// and step count.
    /// </summary>
    /// <param name="runId">
    /// A unique identifier for this PDA instance. Appears in every trace entry
    /// emitted by the PDA's observable trace stream.
    /// </param>
    /// <param name="timeProvider">Time source for expiry computation.</param>
    public abstract ValueTask<(OAuthFlowState State, int StepCount)> CreateAsync(
        string runId,
        TimeProvider timeProvider);


    /// <summary>
    /// Rehydrates a PDA from a persisted snapshot, steps it with the given
    /// input, and returns the resulting state and step count.
    /// </summary>
    public abstract ValueTask<(OAuthFlowState State, int StepCount)> StepAsync(
        OAuthFlowState state,
        int stepCount,
        OAuthFlowInput input,
        TimeProvider timeProvider,
        CancellationToken cancellationToken);


    /// <summary>
    /// Returns <see langword="true"/> when flows of this kind emit
    /// <see cref="OAuthAction"/> values during transitions, requiring the
    /// application to configure <see cref="AuthorizationServerOptions.ActionExecutor"/>.
    /// The dispatcher validates this at startup.
    /// </summary>
    public virtual bool RequiresActionExecutor => false;
}
