using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Reads an SD-JWT compact wire string into a structured
/// <see cref="SdToken{TEnvelope}"/>. Wired by the application to its SD-JWT
/// implementation — typically
/// <c>Verifiable.Json.Sd.SdJwtSerializer.ParseToken</c> with the application's
/// salt tag, base64url decoder, memory pool and disclosure-digest algorithm baked in.
/// </summary>
/// <param name="sdJwt">The compact SD-JWT wire string (issuer JWS plus disclosures separated by <c>~</c>).</param>
/// <returns>
/// The structured token, including issuer JWS, all disclosures, and the optional KB-JWT (<see cref="SdJwtRead"/>), which the
/// caller owns; or the refusal of a wire shape RFC 9901 does not define (<see cref="SdJwtRefused"/>). The reading never answers
/// a refusal with an exception: an exception out of it is a fault of a delegate it composes, cancellation among them.
/// </returns>
public delegate SdJwtReading ParseSdJwtTokenDelegate(string sdJwt);
