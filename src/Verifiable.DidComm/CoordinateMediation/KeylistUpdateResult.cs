namespace Verifiable.DidComm.CoordinateMediation;

/// <summary>
/// A single entry of a <c>keylist-update-response</c> message's <c>body.updated</c> list — the mediator's
/// per-key confirmation of a requested <c>keylist-update</c>, per
/// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
/// §Keylist Response.
/// </summary>
/// <remarks>
/// Every member is a scalar <see cref="string"/>, so the compiler-synthesized record <c>==</c>/
/// <c>Equals</c> are already correct value equality — no hand-written equality member is needed here. Build
/// and interpret via <see cref="CoordinateMediationExtensions"/>.
/// </remarks>
public sealed record KeylistUpdateResult
{
    /// <summary>REQUIRED. The DID subject of the update (§Keylist Response).</summary>
    public required string RecipientDid { get; init; }

    /// <summary>
    /// REQUIRED. The echoed action, verbatim as it will appear on the wire.
    /// <see cref="CoordinateMediationExtensions.CreateKeylistUpdateResponse"/> accepts only
    /// <see cref="WellKnownCoordinateMediationNames.ActionAdd"/> or
    /// <see cref="WellKnownCoordinateMediationNames.ActionRemove"/> (§Keylist Response).
    /// </summary>
    public required string Action { get; init; }

    /// <summary>
    /// REQUIRED. The resulting state of the update, verbatim as it will appear on the wire.
    /// <see cref="CoordinateMediationExtensions.CreateKeylistUpdateResponse"/> accepts only
    /// <see cref="WellKnownCoordinateMediationNames.ResultClientError"/>,
    /// <see cref="WellKnownCoordinateMediationNames.ResultServerError"/>,
    /// <see cref="WellKnownCoordinateMediationNames.ResultNoChange"/>, or
    /// <see cref="WellKnownCoordinateMediationNames.ResultSuccess"/> (§Keylist Response).
    /// </summary>
    public required string Result { get; init; }
}
