using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Serialises an <see cref="SdToken{TEnvelope}"/> back to compact wire form
/// — issuer JWS, selected disclosures, and the optional KB-JWT, separated by
/// <c>~</c>. Wired by the application to
/// <c>Verifiable.Json.Sd.SdJwtSerializer.SerializeToken</c> with the
/// application's base64url encoder baked in.
/// </summary>
/// <param name="token">The structured token to project to wire form.</param>
/// <returns>The compact SD-JWT string.</returns>
public delegate string SerializeSdJwtTokenDelegate(SdToken<string> token);
