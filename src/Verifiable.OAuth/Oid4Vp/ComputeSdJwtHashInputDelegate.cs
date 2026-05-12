using Verifiable.JCose.Sd;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Computes the <c>sd_hash</c> input string per
/// <see href="https://www.rfc-editor.org/rfc/rfc9901#section-4.3">RFC 9901 §4.3</see>:
/// the SD-JWT plus the selected disclosures, terminated with a trailing
/// tilde, with no KB-JWT. Wired by the application to
/// <c>Verifiable.Json.Sd.SdJwtSerializer.GetSdJwtForHashing</c>.
/// </summary>
/// <param name="token">The structured SD-JWT token to project for hashing.</param>
/// <returns>The string that is hashed (via the application's hash function) to produce the <c>sd_hash</c> claim value.</returns>
public delegate string ComputeSdJwtHashInputDelegate(SdToken<string> token);
