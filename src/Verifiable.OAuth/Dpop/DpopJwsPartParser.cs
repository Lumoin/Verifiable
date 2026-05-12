namespace Verifiable.OAuth.Dpop;

/// <summary>
/// Delegate-bundle wiring the JSON deserialization of DPoP proof segments.
/// Parallel to <see cref="DpopJwsPartSerializer"/> for the inbound path.
/// The application supplies these via its JSON layer; the validator does
/// not pick a JSON library.
/// </summary>
public sealed record DpopJwsPartParser
{
    /// <summary>
    /// Parses the JSON bytes of a header segment into a typed
    /// <see cref="DpopProofHeader"/>. The implementation throws on
    /// malformed JSON or missing required members; the validator catches
    /// and reports as <see cref="DpopValidationFailureReason.Malformed"/>.
    /// </summary>
    public required Func<ReadOnlyMemory<byte>, DpopProofHeader> ParseHeader { get; init; }

    /// <summary>
    /// Parses the JSON bytes of a payload segment into a typed
    /// <see cref="DpopProofClaims"/>. Same throwing semantics as
    /// <see cref="ParseHeader"/>.
    /// </summary>
    public required Func<ReadOnlyMemory<byte>, DpopProofClaims> ParseClaims { get; init; }
}
