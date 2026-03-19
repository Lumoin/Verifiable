using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// Discriminated union base for inputs to an OAuth/OpenID flow PDA.
/// Each derived type represents one external event that drives a state transition.
/// </summary>
/// <remarks>
/// This type is <c>TInput</c> in
/// <c>PushdownAutomaton&lt;OAuthFlowState, OAuthFlowInput, TStackSymbol&gt;</c>.
/// Inputs carry the results of effectful operations performed outside the transition
/// function — HTTP responses, cryptographic outputs, timestamps — so the transition
/// function itself remains pure and deterministic.
/// </remarks>
[DebuggerDisplay("{GetType().Name,nq}")]
public abstract record OAuthFlowInput;
