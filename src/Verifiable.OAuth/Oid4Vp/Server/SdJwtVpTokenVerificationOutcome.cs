namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// The outcome of verifying an SD-JWT VP token (<see cref="SdJwtVpTokenVerification.VerifyAsync"/>): its verified contents
/// (<see cref="SdJwtVpTokenVerified"/>), or the refusal of a presentation no conformant Wallet produces
/// (<see cref="SdJwtVpTokenRefused"/>), answered as a typed value rather than raised, so a verifier routes it as the malformed
/// presentation it is.
/// </summary>
public abstract record SdJwtVpTokenVerificationOutcome;


/// <summary>
/// The presentation was read and its signatures and bindings judged: the contents and the outcome of every check, which the
/// verifier's validation rules then require (<see cref="VpTokenParsed"/>).
/// </summary>
/// <param name="Parsed">The verified contents.</param>
public sealed record SdJwtVpTokenVerified(VpTokenParsed Parsed) : SdJwtVpTokenVerificationOutcome;


/// <summary>The presentation is malformed, for the reason named.</summary>
/// <param name="Defect">Why the presentation is refused.</param>
public sealed record SdJwtVpTokenRefused(SdJwtPresentationDefect Defect) : SdJwtVpTokenVerificationOutcome;


/// <summary>Why an SD-JWT VP token is a malformed presentation.</summary>
public enum SdJwtPresentationDefect
{
    /// <summary>
    /// The Issuer-signed JWT's payload is not well-formed JSON, or one of its objects repeats a claim name (RFC 8259 section 4):
    /// it names no claim one way, so one verifier would read one value and another a different one.
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
    KeyBindingIssuedAtNotANumericDate
}
