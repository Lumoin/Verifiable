namespace Verifiable.DidComm.MessagePickup;

/// <summary>
/// A Message Pickup 3.0 <c>status</c> message body — the mediator's report of a recipient's pending-message
/// queue state, per
/// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Status.
/// </summary>
/// <remarks>
/// Every member is a scalar (<see cref="string"/>/<see cref="long"/>/<see cref="bool"/>), so the
/// compiler-synthesized record <c>==</c>/<see cref="Equals(MessagePickupStatus?)"/> are already correct
/// value equality — unlike a record carrying a collection or arbitrary JSON (which would need
/// <see cref="Verifiable.Foundation.StructuralEquality"/>), no hand-written equality member is needed here.
/// Build and interpret via <see cref="MessagePickupExtensions"/>.
/// </remarks>
public sealed record MessagePickupStatus
{
    /// <summary>
    /// OPTIONAL. The recipient DID the status is scoped to — echoes a <c>status-request</c>'s
    /// <c>recipient_did</c> when one was specified (§Status).
    /// </summary>
    public string? RecipientDid { get; init; }

    /// <summary>REQUIRED. The count of messages pending in the queue — the only REQUIRED status attribute (§Status).</summary>
    public required long MessageCount { get; init; }

    /// <summary>OPTIONAL. The longest delay, in seconds, of any message in the queue (§Status).</summary>
    public long? LongestWaitedSeconds { get; init; }

    /// <summary>OPTIONAL. The UTC epoch-seconds receipt time of the newest queued message (§Status).</summary>
    public long? NewestReceivedTime { get; init; }

    /// <summary>OPTIONAL. The UTC epoch-seconds receipt time of the oldest queued message (§Status).</summary>
    public long? OldestReceivedTime { get; init; }

    /// <summary>OPTIONAL. The total size, in bytes, of all queued messages (§Status).</summary>
    public long? TotalBytes { get; init; }

    /// <summary>OPTIONAL. Whether Live Mode is currently active for the connection (§Status).</summary>
    public bool? LiveDelivery { get; init; }
}
