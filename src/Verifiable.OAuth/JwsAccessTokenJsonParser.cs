using Verifiable.JCose;

namespace Verifiable.OAuth;

/// <summary>
/// The readings of a signed JWT's decoded segments the shared validation core consumes
/// (<see cref="JwsAccessTokenValidator.ValidateAsync"/>, <see cref="Oidc10IdTokenValidator.ValidateAsync"/>, and the OpenID
/// Connect sign-in's <see cref="AuthCode.OpenIdTokenVerification.Parser"/>). <see cref="Default"/> reads both through the
/// library's one strict judgement of a document a protocol reads as one JSON object (<see cref="JwtHeader.Read"/>,
/// <see cref="JwtPayload.Read"/>), so a receiver parses nothing itself and no JSON layer of its own is asked for; each reading
/// answers the part or the reader's typed refusal of its document (<see cref="JwtPartReading{TPart}"/>), never an exception.
/// Which members a part must carry, and of which kind, the validator judges, not the reading.
/// </summary>
public sealed record JwsAccessTokenJsonParser
{
    /// <summary>The library's readings: <see cref="JwtHeader.Read"/> and <see cref="JwtPayload.Read"/>.</summary>
    public static JwsAccessTokenJsonParser Default { get; } = new()
    {
        ParseHeader = static bytes => JwtHeader.Read(bytes.Span),
        ParseClaims = static bytes => JwtPayload.Read(bytes.Span)
    };


    /// <summary>
    /// Reads the JSON bytes of the header segment into a <see cref="JwtHeader"/> or the refusal of its document; the validator
    /// answers a refusal as <see cref="JwsAccessTokenValidationFailureReason.InvalidHeader"/>.
    /// </summary>
    public required Func<ReadOnlyMemory<byte>, JwtPartReading<JwtHeader>> ParseHeader { get; init; }

    /// <summary>
    /// Reads the JSON bytes of the payload segment into a <see cref="JwtPayload"/> or the refusal of its document; the validator
    /// answers a refusal as <see cref="JwsAccessTokenValidationFailureReason.Malformed"/>.
    /// </summary>
    public required Func<ReadOnlyMemory<byte>, JwtPartReading<JwtPayload>> ParseClaims { get; init; }
}
