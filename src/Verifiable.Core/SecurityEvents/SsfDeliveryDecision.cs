namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// How a Receiver disposes of one received SET — the delivery-method-agnostic
/// decision that a push endpoint maps to an HTTP status (202 vs 400 + error
/// body) and a poll client maps to the next poll request's <c>ack</c> versus
/// <c>setErrs</c> members.
/// </summary>
public enum SsfDeliveryOutcome
{
    /// <summary>The SET verified and validated; acknowledge it and act on its events.</summary>
    Accepted = 0,

    /// <summary>
    /// The SET's <c>jti</c> was already seen. Delivery is at-least-once and Receivers
    /// SHOULD acknowledge repeats (RFC 8936 §2.4) — acknowledge again, act on nothing.
    /// </summary>
    AcceptedDuplicate,

    /// <summary>The SET failed verification or validation; report <see cref="SsfDeliveryDecision.Error"/>.</summary>
    Rejected
}


/// <summary>
/// The outcome of receiving one SET through
/// <see cref="SecurityEventTokenReception.ReceiveAsync"/>.
/// </summary>
public sealed record SsfDeliveryDecision
{
    /// <summary>The disposition of the SET.</summary>
    public required SsfDeliveryOutcome Outcome { get; init; }

    /// <summary>
    /// The verified, typed token when <see cref="Outcome"/> is
    /// <see cref="SsfDeliveryOutcome.Accepted"/>; otherwise <see langword="null"/>.
    /// A duplicate carries no token — there is nothing new to act on.
    /// </summary>
    public SecurityEventToken? Token { get; init; }

    /// <summary>
    /// The SET error to report when <see cref="Outcome"/> is
    /// <see cref="SsfDeliveryOutcome.Rejected"/> (the push error body, or the value of a
    /// poll <c>setErrs</c> entry); otherwise <see langword="null"/>.
    /// </summary>
    public SsfSetError? Error { get; init; }
}
