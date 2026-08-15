namespace Verifiable.DidComm.CoordinateMediation;

/// <summary>
/// A <c>keylist-query</c> message's OPTIONAL <c>body.paginate</c> object — when present, MUST carry both
/// <see cref="Limit"/> and <see cref="Offset"/>, per
/// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
/// §Keylist Query.
/// </summary>
/// <remarks>
/// Every member is a scalar <see cref="long"/>, so the compiler-synthesized record <c>==</c>/<c>Equals</c>
/// are already correct value equality — no hand-written equality member is needed here. The
/// required-together relationship between <see cref="Limit"/> and <see cref="Offset"/> is enforced by this
/// record's shape itself: there is no way to construct one member without the other. Build and interpret via
/// <see cref="CoordinateMediationExtensions"/>.
/// </remarks>
public sealed record KeylistPaginate
{
    /// <summary>REQUIRED. The maximum number of keys the mediator should return (§Keylist Query).</summary>
    public required long Limit { get; init; }

    /// <summary>REQUIRED. The number of keys to skip before returning results (§Keylist Query).</summary>
    public required long Offset { get; init; }
}
