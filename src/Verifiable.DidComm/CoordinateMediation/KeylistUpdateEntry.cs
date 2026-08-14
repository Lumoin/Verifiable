namespace Verifiable.DidComm.CoordinateMediation;

/// <summary>
/// A single entry of a <c>keylist-update</c> message's <c>body.updates</c> list — a key the recipient is
/// registering or deregistering with the mediator, per
/// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
/// §Keylist Update.
/// </summary>
/// <remarks>
/// Every member is a scalar <see cref="string"/>, so the compiler-synthesized record <c>==</c>/
/// <c>Equals</c> are already correct value equality — no hand-written equality member is needed here. Build
/// and interpret via <see cref="CoordinateMediationExtensions"/>.
/// </remarks>
public sealed record KeylistUpdateEntry
{
    /// <summary>REQUIRED. The DID subject of the update (§Keylist Update).</summary>
    public required string RecipientDid { get; init; }

    /// <summary>
    /// REQUIRED. The requested action, verbatim as it will appear on the wire.
    /// <see cref="CoordinateMediationExtensions.CreateKeylistUpdate"/> accepts only
    /// <see cref="WellKnownCoordinateMediationNames.ActionAdd"/> or
    /// <see cref="WellKnownCoordinateMediationNames.ActionRemove"/> — the wire's own vocabulary has no others
    /// (§Keylist Update).
    /// </summary>
    public required string Action { get; init; }
}
