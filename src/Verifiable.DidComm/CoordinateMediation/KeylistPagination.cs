namespace Verifiable.DidComm.CoordinateMediation;

/// <summary>
/// A <c>keylist</c> message's OPTIONAL <c>body.pagination</c> object — when present, MUST carry
/// <see cref="Count"/>, <see cref="Offset"/>, and <see cref="Remaining"/>, per
/// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
/// §Keylist.
/// </summary>
/// <remarks>
/// Every member is a scalar <see cref="long"/>, so the compiler-synthesized record <c>==</c>/<c>Equals</c>
/// are already correct value equality — no hand-written equality member is needed here. The
/// required-together relationship among <see cref="Count"/>, <see cref="Offset"/>, and
/// <see cref="Remaining"/> is enforced by this record's shape itself: there is no way to construct one
/// member without the others. Build and interpret via <see cref="CoordinateMediationExtensions"/>.
/// </remarks>
public sealed record KeylistPagination
{
    /// <summary>REQUIRED. The number of keys returned in this response (§Keylist).</summary>
    public required long Count { get; init; }

    /// <summary>REQUIRED. The number of keys skipped before this response (§Keylist).</summary>
    public required long Offset { get; init; }

    /// <summary>REQUIRED. The number of keys not yet returned (§Keylist).</summary>
    public required long Remaining { get; init; }
}
