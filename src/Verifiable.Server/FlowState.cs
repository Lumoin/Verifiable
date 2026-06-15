using System.Diagnostics;
using Verifiable.Foundation.Automata;

namespace Verifiable.Server;

/// <summary>
/// Discriminated union base for all states in a flow PDA.
/// Each derived type carries exactly the data available at that point in the flow.
/// </summary>
/// <remarks>
/// <para>
/// This type is <c>TState</c> in
/// <c>PushdownAutomaton&lt;FlowState, FlowInput, TStackSymbol&gt;</c>.
/// The PDA's <see cref="Verifiable.Foundation.Automata.TraceEntry{TState,TInput}"/> observable
/// stream provides the complete audit trail; state records do not embed history links.
/// </para>
/// <para>
/// <strong>What belongs on this state record</strong>
/// </para>
/// <para>
/// Only data the pure PDA transition function reads or writes. The transition
/// function takes <c>(state, input, stackTop, ct)</c> and returns the next state;
/// it has no access to delegates, no clock, no randomness, no I/O. A value belongs
/// on the state if and only if a future transition's decision or output depends
/// on it.
/// </para>
/// <para>
/// <see cref="FlowId"/> — affects every storage call and identifies the flow in
/// transitions. On the state.
/// </para>
/// <para>
/// <see cref="ExpectedIssuer"/> — affects transitions directly through mix-up
/// attack defense per
/// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>:
/// inputs carrying an <c>iss</c> value are matched against the state's
/// <see cref="ExpectedIssuer"/> before the transition proceeds. On the state.
/// </para>
/// <para>
/// <see cref="ExpiresAt"/> — affects transitions (a fail transition might check
/// expiry). On the state.
/// </para>
/// <para>
/// <strong>What does not belong on this state record</strong>
/// </para>
/// <para>
/// Tenancy. The PDA transition function is tenant-blind by design — once a flow
/// is in motion, every transition operates within a single tenant's universe and
/// has no decision to make about tenancy. Tenant identity is a property of the
/// HTTP request (or other transport-level invocation), not of the flow record.
/// </para>
/// <para>
/// <c>TenantId</c> therefore lives on the request context bag (read via
/// <c>context.TenantId</c>) and is threaded through storage delegates as a
/// parameter. The dispatcher reads it from the tenant-extraction seam at the
/// start of every request and passes it to the flow-state load and save seams,
/// the registration-load seam, and the correlation-key resolution seam. Tenant
/// isolation is enforced at the storage boundary, not at the state layer.
/// </para>
/// <para>
/// Cryptographic key material is never on the state, never on inputs, never on
/// the stack — it is fetched at action time from the family's signing-key
/// resolver using a key identifier that the state may carry. The state holds the
/// identifier; the action handler resolves the material.
/// </para>
/// <para>
/// Configuration delegates. Anything on the dispatch host is consumed by action
/// handlers, not by the transition function. Storage delegates, encoders, hash
/// function selectors — all live in the surrounding effectful loop.
/// </para>
/// <para>
/// <strong>NextAction</strong>
/// </para>
/// <para>
/// <see cref="NextAction"/> declares the effectful work the dispatch loop must
/// perform after entering this state before the next input can be constructed.
/// States that wait for an external actor return <see cref="NullAction.Instance"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("{GetType().Name,nq} FlowId={FlowId}")]
public abstract record FlowState
{
    /// <summary>
    /// Stable identifier for this flow instance. Assigned at initiation and
    /// unchanged through all transitions.
    /// </summary>
    public required string FlowId { get; init; }

    /// <summary>
    /// The issuer identifier of the authorization server this flow targets.
    /// Set at initiation and immutable. Required for mix-up attack defense per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>.
    /// </summary>
    public required string ExpectedIssuer { get; init; }

    /// <summary>The UTC instant at which this state was entered.</summary>
    public required DateTimeOffset EnteredAt { get; init; }

    /// <summary>
    /// The UTC instant after which this state must be rejected.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// The flow kind that owns this state. Identifies which transition function
    /// and action executor to use when rehydrating the flow from persistent storage.
    /// </summary>
    public required FlowKind Kind { get; init; }

    /// <summary>
    /// The effectful action the dispatch loop must execute after entering this state.
    /// Returns <see cref="NullAction.Instance"/> when the next input arrives from an
    /// external source and no library-driven work is needed.
    /// </summary>
    /// <remarks>
    /// Override in derived states that require effectful work — JAR signing, JWE
    /// decryption, token issuance — before the next PDA input can be constructed.
    /// The effectful dispatch loop checks this property after each pure PDA transition
    /// and drives execution until <see cref="NullAction.Instance"/> is returned.
    /// </remarks>
    public virtual PdaAction NextAction => NullAction.Instance;
}
