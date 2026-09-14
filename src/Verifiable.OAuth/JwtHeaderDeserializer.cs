namespace Verifiable.OAuth;

/// <summary>
/// Deserializes the protected header portion of a compact JWS into a
/// claim dictionary keyed by JOSE header parameter name.
/// </summary>
/// <param name="headerBytes">
/// The decoded UTF-8 bytes of the protected header JSON object.
/// </param>
/// <returns>
/// A claim dictionary whose keys are JOSE header parameter names per
/// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4">RFC 7515 §4</see>
/// and whose values are the materialised JSON values; integer values
/// arrive as the integer family the chosen deserializer produces (see
/// <see cref="Verifiable.OAuth.Jar.JwtClaimReaders.TryToInt64"/>).
/// </returns>
/// <remarks>
/// Lives in the root <c>Verifiable.OAuth</c> namespace rather than
/// <c>Verifiable.OAuth.Jar</c> because <see cref="Verifiable.OAuth.Server.AuthorizationServerCodecs"/>
/// references this type — putting it in the <c>Jar</c> namespace
/// would force <c>Server</c> to depend on <c>Jar</c>, which is the
/// wrong direction. Symmetric with <see cref="JwtHeaderSerializer"/>,
/// which lives at the same namespace level for the same reason.
/// </remarks>
public delegate IReadOnlyDictionary<string, object> JwtHeaderDeserializer(
    ReadOnlySpan<byte> headerBytes);
