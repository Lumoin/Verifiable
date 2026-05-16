using Verifiable.JCose;

namespace Verifiable.OAuth;

/// <summary>
/// Delegate-bundle wiring the JSON deserialization of access-token JWS
/// segments. Parallel to
/// <see cref="Verifiable.OAuth.Dpop.DpopJwsPartParser"/> on the DPoP side.
/// The application supplies these via its JSON layer; the validator does
/// not pick a JSON library.
/// </summary>
public sealed record JwsAccessTokenJsonParser
{
    /// <summary>
    /// Parses the JSON bytes of the header segment into a typed
    /// <see cref="JwtHeader"/>. Implementations throw on malformed JSON or
    /// missing structural members; the validator catches and reports as
    /// <see cref="JwsAccessTokenValidationFailureReason.InvalidHeader"/>.
    /// </summary>
    public required Func<ReadOnlyMemory<byte>, JwtHeader> ParseHeader { get; init; }

    /// <summary>
    /// Parses the JSON bytes of the payload segment into a typed
    /// <see cref="JwtPayload"/>. Same throwing semantics as
    /// <see cref="ParseHeader"/>; the validator catches and reports as
    /// <see cref="JwsAccessTokenValidationFailureReason.Malformed"/>.
    /// </summary>
    public required Func<ReadOnlyMemory<byte>, JwtPayload> ParseClaims { get; init; }
}
