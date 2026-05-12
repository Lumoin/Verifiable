using Verifiable.JCose;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// Delegate-bundle wiring the JSON serialization of DPoP proof headers and
/// payloads. The application supplies these via its JSON layer (typically
/// <c>Verifiable.OAuth.Json</c> in production, an inline JsonDocument-based
/// implementation in tests). Mirrors the pattern used by the SD-JWT and
/// JAR serialization paths.
/// </summary>
public sealed record DpopJwsPartSerializer
{
    /// <summary>
    /// Serialises a <see cref="DpopProofHeader"/> to the
    /// property-dictionary shape <see cref="Jws.SignAsync"/> consumes via
    /// its generic <c>TJwtPart</c> parameter.
    /// </summary>
    public required Func<DpopProofHeader, IReadOnlyDictionary<string, object>> SerializeHeader { get; init; }

    /// <summary>
    /// Serialises a <see cref="DpopProofClaims"/> to the property-dictionary
    /// shape <see cref="Jws.SignAsync"/> consumes.
    /// </summary>
    public required Func<DpopProofClaims, IReadOnlyDictionary<string, object>> SerializePayload { get; init; }

    /// <summary>
    /// The <see cref="JwtPartEncoder{TJwtPart}"/> bridge between a typed
    /// dictionary and the bytes <see cref="Jws.SignAsync"/> base64url-encodes
    /// into the JWS header / payload segments.
    /// </summary>
    public required JwtPartEncoder<IReadOnlyDictionary<string, object>> EncodePart { get; init; }
}
