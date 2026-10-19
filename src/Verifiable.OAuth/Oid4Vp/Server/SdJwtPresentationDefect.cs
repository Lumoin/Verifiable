namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>Why an SD-JWT VP token is a malformed presentation.</summary>
public enum SdJwtPresentationDefect
{
    /// <summary>
    /// The Issuer-signed JWT's payload is not one well-formed JSON object, one of its objects repeats a claim name (RFC 8259
    /// section 4), or a name or a string of it names no Unicode text (section 8.2): it names no claim one way, so one verifier
    /// would read one value and another a different one.
    /// </summary>
    IssuerPayloadNotOneObject,

    /// <summary>
    /// The Issuer-signed JWT carries a <c>status</c> claim that does not meet Token Status List sections 6.1 and 6.2: no reference
    /// to a status mechanism, a repeated member, or a <c>status_list</c> outside its rules.
    /// </summary>
    StatusClaimMalformed,

    /// <summary>
    /// The Key Binding JWT's payload is not one JSON object naming each claim once and naming Unicode text throughout
    /// (RFC 9901 section 4.3).
    /// </summary>
    KeyBindingPayloadNotOneObject,

    /// <summary>
    /// The Key Binding JWT carries an <c>iat</c> that is no NumericDate (RFC 7519 section 2): a value that is no JSON number, a
    /// string of digits among them, or a number naming an instant no clock represents. An omitted <c>iat</c>, which RFC 9901
    /// section 4.3 has REQUIRED, is told from this and answered by the key-binding checks as absent.
    /// </summary>
    KeyBindingIssuedAtNotANumericDate,

    /// <summary>
    /// The presentation is not the compact serialization of an SD-JWT with its Key Binding JWT (RFC 9901 section 4): the parse
    /// of the wire format refused it, or the Issuer-signed JWT or the Key Binding JWT it carries is not three segments (RFC 7515
    /// section 7.1) or carries a payload segment that is no base64url text. The reading never reaches a claim of it.
    /// </summary>
    CompactSerializationMalformed,

    /// <summary>
    /// The Issuer-signed JWT's <c>cnf</c> claim carries a <c>jwk</c> (RFC 7800 section 3.2) that states no public key the
    /// library reconstructs: a member its type requires absent, a type, curve or size the library reconstructs no key of, EC
    /// coordinates naming no point of the curve, or a member that is no base64url text, so the Key Binding JWT is verified by no
    /// key.
    /// </summary>
    ConfirmationKeyNotAPublicKey
}
