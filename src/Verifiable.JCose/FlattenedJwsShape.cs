using System.Diagnostics;

namespace Verifiable.JCose;

/// <summary>
/// A token classified as a JWS in Flattened JSON Serialization (RFC 7515 §7.2.2): a JSON object
/// carrying a top-level <c>signature</c> member and (unless detached) a <c>payload</c> member,
/// and no <c>signatures</c> array.
/// </summary>
/// <remarks>
/// <para>
/// Carries the raw wire string only. A Flattened JSON JWS is parsed with
/// <see cref="JwsParsing.ParseFlattenedJson"/>, which returns a single-signature
/// <see cref="UnverifiedJwsMessage"/> the caller verifies under its policy.
/// </para>
/// <para>
/// <strong>Trust state.</strong> Structural shape only. No signature is verified at
/// classification time.
/// </para>
/// </remarks>
/// <param name="Value">The raw Flattened JSON JWS wire string.</param>
[DebuggerDisplay("FlattenedJwsShape")]
public sealed record FlattenedJwsShape(string Value): JoseTokenShape;
