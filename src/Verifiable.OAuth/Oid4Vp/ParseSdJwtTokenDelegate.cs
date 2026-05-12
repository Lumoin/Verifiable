using Verifiable.JCose.Sd;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Parses an SD-JWT compact wire string into a structured
/// <see cref="SdToken{TEnvelope}"/>. Wired by the application to its SD-JWT
/// implementation — typically
/// <c>Verifiable.Json.Sd.SdJwtSerializer.ParseToken</c> with the application's
/// salt tag, base64url decoder, and memory pool baked in.
/// </summary>
/// <param name="sdJwt">The compact SD-JWT wire string (issuer JWS plus disclosures separated by <c>~</c>).</param>
/// <returns>The structured token, including issuer JWS, all disclosures, and the optional KB-JWT.</returns>
public delegate SdToken<string> ParseSdJwtTokenDelegate(string sdJwt);
