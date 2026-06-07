using System.Diagnostics;

namespace Verifiable.JCose;

/// <summary>
/// A token classified as opaque: a non-empty input that does not match any
/// structured JOSE shape the classifier recognizes. The application's
/// storage decides what the value means.
/// </summary>
/// <remarks>
/// <para>
/// Returned when the input is non-empty but does not match the JWS or JWE
/// compact form (wrong segment count, segments that fail Base64Url decoding,
/// header that does not parse to a JSON object). The application typically
/// resolves an opaque token by looking up <see cref="Value"/> in an
/// introspection cache or database to retrieve the associated metadata —
/// this is the canonical OAuth 2.0 Token Introspection
/// (RFC 7662) flow for tokens whose internal shape is not exposed to
/// resource servers.
/// </para>
/// <para>
/// <strong>No structural metadata.</strong>
/// Unlike <see cref="JwsShape"/> and <see cref="JweShape"/>, this subtype
/// has no header to inspect — by definition, the token is unstructured from
/// the classifier's perspective. The string itself remains
/// attacker-controlled. Consumers that pass <see cref="Value"/> to
/// downstream stores must use parameterised queries or hashed lookups, never
/// string interpolation into queries.
/// </para>
/// </remarks>
/// <param name="Value">The raw token string from the request.</param>
[DebuggerDisplay("OpaqueShape Length={Value.Length}")]
public sealed record OpaqueShape(string Value): JoseTokenShape;
