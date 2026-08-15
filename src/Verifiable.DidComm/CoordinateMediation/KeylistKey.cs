namespace Verifiable.DidComm.CoordinateMediation;

/// <summary>
/// A single entry of a <c>keylist</c> message's <c>body.keys</c> list — one key registered for the
/// connection, per
/// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
/// §Keylist.
/// </summary>
/// <remarks>
/// The single member is a scalar <see cref="string"/>, so the compiler-synthesized record <c>==</c>/
/// <c>Equals</c> are already correct value equality — no hand-written equality member is needed here. Build
/// and interpret via <see cref="CoordinateMediationExtensions"/>.
/// </remarks>
public sealed record KeylistKey
{
    /// <summary>REQUIRED. The DID subject of the registered key (§Keylist).</summary>
    public required string RecipientDid { get; init; }
}
