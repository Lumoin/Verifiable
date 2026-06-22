using System.Diagnostics;

namespace Verifiable.JCose;

/// <summary>
/// A token classified as a JWS in General JSON Serialization (RFC 7515 §7.2.1): a JSON object
/// carrying a <c>signatures</c> array and (unless detached) a <c>payload</c> member.
/// </summary>
/// <remarks>
/// <para>
/// Carries the raw wire string only. A General JSON JWS is parsed with
/// <see cref="JwsParsing.ParseGeneralJson"/>, which returns an
/// <see cref="UnverifiedJwsMessage"/> whose signatures the caller verifies under its policy.
/// </para>
/// <para>
/// <strong>Trust state.</strong> Structural shape only — a JSON object with a <c>signatures</c>
/// array (RFC 7516 §9: a JWS has no <c>ciphertext</c> member). No signature is verified at
/// classification time.
/// </para>
/// </remarks>
/// <param name="Value">The raw General JSON JWS wire string.</param>
[DebuggerDisplay("GeneralJwsShape")]
public sealed record GeneralJwsShape(string Value): JoseTokenShape;
