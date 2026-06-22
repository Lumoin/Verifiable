using System.Diagnostics;

namespace Verifiable.JCose;

/// <summary>
/// A token classified as a JWE in Flattened JSON Serialization (RFC 7516 §7.2.2): a JSON object
/// carrying a top-level <c>encrypted_key</c> and a <c>ciphertext</c> member, and no
/// <c>recipients</c> array.
/// </summary>
/// <remarks>
/// <para>
/// Carries the raw wire string only. A Flattened JSON JWE is decoded with the caller's accepted
/// <c>alg</c>/<c>enc</c> policy via <see cref="GeneralJweParsing.ParseFlattenedJson"/>, which
/// returns a single-recipient <see cref="Verifiable.JCose.AeadGeneralMessage"/> — flattened and
/// single-recipient general serializations decrypt identically (RFC 7516 §7.2.2).
/// </para>
/// <para>
/// <strong>Trust state.</strong> Structural shape only. Nothing is authenticated until AEAD
/// decryption succeeds.
/// </para>
/// </remarks>
/// <param name="Value">The raw Flattened JSON JWE wire string.</param>
[DebuggerDisplay("FlattenedJweShape")]
public sealed record FlattenedJweShape(string Value): JoseTokenShape;
