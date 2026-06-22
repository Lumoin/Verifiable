using System.Diagnostics;

namespace Verifiable.JCose;

/// <summary>
/// A token classified as a JWE in General JSON Serialization (RFC 7516 §7.2.1): a JSON object
/// carrying a <c>recipients</c> array and a <c>ciphertext</c> member.
/// </summary>
/// <remarks>
/// <para>
/// Carries the raw wire string only. Like <see cref="JweShape"/>, the classifier does not
/// decrypt or even decode the protected header here — a General JSON JWE is decoded with the
/// caller's accepted <c>alg</c>/<c>enc</c> policy via
/// <see cref="GeneralJweParsing.ParseGeneralJson"/>, which returns an
/// <see cref="Verifiable.JCose.AeadGeneralMessage"/> ready for per-recipient decryption.
/// </para>
/// <para>
/// <strong>Trust state.</strong> Structural shape only — a JSON object with a <c>recipients</c>
/// array and a <c>ciphertext</c> member (RFC 7516 §9). Nothing in the message is authenticated
/// until AEAD decryption succeeds and binds the protected header through the AAD.
/// </para>
/// </remarks>
/// <param name="Value">The raw General JSON JWE wire string.</param>
[DebuggerDisplay("GeneralJweShape")]
public sealed record GeneralJweShape(string Value): JoseTokenShape;
