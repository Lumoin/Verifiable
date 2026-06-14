namespace Verifiable.Vcalm;

/// <summary>
/// The W3C VCALM 1.0 §3.6.6 exchange status — the lifecycle state of an exchange instance reported
/// by the get-exchange-state endpoint and driven by the §3.6.5 vcapi participation.
/// </summary>
/// <remarks>
/// §3.6.6: "The status ('pending' | 'active' | 'complete' | 'invalid') of the exchange, set to
/// 'pending' on creation." §3.6 describes the same lifecycle in prose ("whether the exchange is
/// pending, active, or complete"). The exchange advances <c>pending → active</c> on the first vcapi
/// message, reaches the terminal <c>complete</c> when the engine has nothing more to request or
/// offer (the engine replies with an empty message or a <c>redirectUrl</c>), and reaches the terminal
/// <c>invalid</c> when a presented message is unacceptable (§3.6: "When a workflow service determines
/// that a particular message is not acceptable, it raises an error by responding with a 4xx HTTP
/// status message").
/// </remarks>
public enum VcalmExchangeState
{
    /// <summary>§3.6.6: the exchange has been created but no vcapi message has yet been exchanged.</summary>
    Pending,

    /// <summary>§3.6.6: the exchange is in progress — at least one vcapi message has been exchanged and more are expected.</summary>
    Active,

    /// <summary>§3.6.6: the exchange completed — the engine has nothing more to request from nor offer to the client.</summary>
    Complete,

    /// <summary>§3.6.6: the exchange failed — a presented message was unacceptable and the exchange cannot continue.</summary>
    Invalid
}
