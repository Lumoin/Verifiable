using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// Discriminated union base for all states in an OAuth/OpenID flow PDA.
/// Each derived type carries exactly the data available at that point in the flow.
/// </summary>
/// <remarks>
/// <para>
/// This type is <c>TState</c> in
/// <c>PushdownAutomaton&lt;OAuthFlowState, OAuthFlowInput, TStackSymbol&gt;</c>.
/// The PDA's <see cref="TraceEntry{TState,TInput}"/> observable stream provides the
/// complete audit trail; state records do not embed history links.
/// </para>
/// <para>
/// <see cref="ExpectedIssuer"/> is present on the base and set at initiation to
/// support mix-up attack defense as required by
/// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>.
/// All inputs that carry an <c>iss</c> value must be matched against this field
/// before the transition proceeds.
/// </para>
/// </remarks>
[DebuggerDisplay("{GetType().Name,nq} FlowId={FlowId}")]
public abstract record OAuthFlowState
{
    /// <summary>
    /// Stable identifier for this flow instance. Assigned at initiation and
    /// unchanged through all transitions. Used as the primary storage key.
    /// </summary>
    public required string FlowId { get; init; }

    /// <summary>
    /// The issuer identifier of the authorization server this flow targets.
    /// Set at initiation and immutable. Required for mix-up attack defense per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>.
    /// </summary>
    public required string ExpectedIssuer { get; init; }

    /// <summary>
    /// The UTC instant at which this state was entered.
    /// </summary>
    public required DateTimeOffset EnteredAt { get; init; }

    /// <summary>
    /// The UTC instant after which this state must be rejected.
    /// Derived from the PAR <c>expires_in</c> value once PAR completes,
    /// and from a caller-configured maximum in earlier states.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; }
}
