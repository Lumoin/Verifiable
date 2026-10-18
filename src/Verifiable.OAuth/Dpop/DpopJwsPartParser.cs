namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The readings of a DPoP proof's segments <see cref="DpopProofValidator"/> consumes, parallel to
/// <see cref="DpopJwsPartSerializer"/> for the inbound path. <see cref="Default"/> reads both through the library's one reading
/// of a JSON object's members (<see cref="DpopProofHeader.Read"/>, <see cref="DpopProofClaims.Read"/>), so a receiver parses
/// nothing itself; a receiver composes another reading only to change what a part read carries, such as normalising the
/// <c>htu</c> of the claims <see cref="DpopProofClaims.Read"/> answered.
/// </summary>
public sealed record DpopJwsPartParser
{
    /// <summary>The library's readings: <see cref="DpopProofHeader.Read"/> and <see cref="DpopProofClaims.Read"/>.</summary>
    public static DpopJwsPartParser Default { get; } = new()
    {
        ParseHeader = static bytes => DpopProofHeader.Read(bytes.Span),
        ParseClaims = static bytes => DpopProofClaims.Read(bytes.Span)
    };


    /// <summary>
    /// Reads the JSON bytes of a header segment into a <see cref="DpopProofHeader"/> or its typed refusal, never throwing; the
    /// validator answers a refusal as <see cref="DpopProofValidationFailureReason.Malformed"/>, and one for an absent
    /// <c>typ</c> as <see cref="DpopProofValidationFailureReason.InvalidTyp"/>.
    /// </summary>
    public required Func<ReadOnlyMemory<byte>, DpopProofPartReading<DpopProofHeader>> ParseHeader { get; init; }

    /// <summary>
    /// Reads the JSON bytes of a payload segment into a <see cref="DpopProofClaims"/> or its typed refusal, never throwing; the
    /// validator answers a refusal as <see cref="DpopProofValidationFailureReason.Malformed"/>.
    /// </summary>
    public required Func<ReadOnlyMemory<byte>, DpopProofPartReading<DpopProofClaims>> ParseClaims { get; init; }
}
