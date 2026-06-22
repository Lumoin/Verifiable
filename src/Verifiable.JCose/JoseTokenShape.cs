namespace Verifiable.JCose;

/// <summary>
/// The wire-form classification of a token string by structural inspection.
/// </summary>
/// <remarks>
/// <para>
/// A closed hierarchy of sealed-record subtypes:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see cref="JwsShape"/> — three-segment compact form per RFC 7515, header
/// parsed and known not to carry an <c>enc</c> parameter. Carries the
/// parsed-but-unverified <see cref="UnverifiedJwsMessage"/>.
/// </description></item>
/// <item><description>
/// <see cref="JweShape"/> — five-segment compact form per RFC 7516, header
/// parsed and known to carry an <c>enc</c> parameter. Carries the typed
/// <see cref="UnverifiedCompactJwe"/> wrapper.
/// </description></item>
/// <item><description>
/// <see cref="GeneralJweShape"/> / <see cref="FlattenedJweShape"/> — the JWE
/// JSON serializations of RFC 7516 §7.2.1/§7.2.2, distinguished by a
/// <c>recipients</c> array versus a top-level <c>encrypted_key</c>. Each
/// carries the raw wire string for the consumer to decode under policy.
/// </description></item>
/// <item><description>
/// <see cref="GeneralJwsShape"/> / <see cref="FlattenedJwsShape"/> — the JWS
/// JSON serializations of RFC 7515 §7.2.1/§7.2.2, distinguished by a
/// <c>signatures</c> array versus a top-level <c>signature</c>.
/// </description></item>
/// <item><description>
/// <see cref="OpaqueShape"/> — anything that does not fit a recognized JOSE
/// shape. The application's storage interprets the value.
/// </description></item>
/// <item><description>
/// <see cref="MalformedShape"/> — classification failed (structurally
/// inconsistent input, malformed Base64Url, header parses to a non-object,
/// or a JSON object carrying both JWS and JWE members). Carries a stable
/// failure reason for logging and metrics.
/// </description></item>
/// </list>
/// <para>
/// <strong>Why a discriminator over messages is a separate layer from
/// <see cref="JoseDictionary"/>.</strong>
/// <see cref="JoseDictionary"/> describes the contents of one parsed
/// segment of a JOSE token (header or payload, verified or unverified).
/// <see cref="JoseTokenShape"/> describes the wire form of a whole token
/// string before any segment is decoded. The two layers compose:
/// <see cref="JwsShape"/> exposes an <see cref="UnverifiedJwtHeader"/>
/// through <see cref="UnverifiedJwsMessage"/>;
/// <see cref="JweShape"/> exposes an <see cref="UnverifiedJwtHeader"/>
/// through <see cref="UnverifiedCompactJwe"/>. Both subtypes carry the
/// trust-marker discipline downward into their inner types.
/// </para>
/// <para>
/// <strong>Why a hierarchy and not an enum.</strong>
/// Each subtype carries a different shape of data — a JWS exposes signature
/// segments and payload bytes, a JWE exposes the encrypted blob, an opaque
/// token is just a string, a malformed token is a reason. An enum plus
/// out-parameters or a single record with nullable fields would force every
/// consumer to check for nulls or shape-specific data. A sealed-record
/// hierarchy with C# pattern matching gives type-safe discrimination.
/// </para>
/// <para>
/// <strong>Format scope.</strong>
/// The classifier produces both the compact serialization forms (3-segment
/// JWS, 5-segment JWE) and the JSON serialization forms (general and
/// flattened, for both JWS and JWE) of RFC 7515 §7.2 and RFC 7516 §7.2. The
/// JSON-form subtypes carry the raw wire string rather than a parsed inner
/// message, because the JWE JSON forms decode under a caller-supplied
/// <c>alg</c>/<c>enc</c> policy (see
/// <see cref="GeneralJweParsing.ParseGeneralJson"/> and
/// <see cref="GeneralJweParsing.ParseFlattenedJson"/>) and the JWS JSON forms
/// parse with <see cref="JwsParsing"/>; the classifier supplies the wire
/// string and the structural verdict, the consumer supplies the policy.
/// </para>
/// </remarks>
public abstract record JoseTokenShape;
