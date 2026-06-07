namespace Verifiable.OAuth;

/// <summary>
/// Deserializes the payload portion of a compact JWS into a claim
/// dictionary keyed by JWT claim name.
/// </summary>
/// <param name="payloadBytes">
/// The decoded UTF-8 bytes of the payload JSON object.
/// </param>
/// <returns>
/// A claim dictionary whose keys are JWT claim names per
/// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4">RFC 7519 §4</see>
/// and whose values are the materialised JSON values; integer values
/// arrive as the integer family the chosen deserializer produces (see
/// <see cref="Verifiable.OAuth.Jar.JwtClaimReaders.TryToInt64"/>).
/// </returns>
/// <remarks>
/// Lives in the root <c>Verifiable.OAuth</c> namespace rather than
/// <c>Verifiable.OAuth.Jar</c> because <see cref="Verifiable.OAuth.Server.AuthorizationServerCodecs"/>
/// references this type. Symmetric with <see cref="JwtPayloadSerializer"/>.
/// </remarks>
public delegate IReadOnlyDictionary<string, object> JwtPayloadDeserializer(
    ReadOnlySpan<byte> payloadBytes);
