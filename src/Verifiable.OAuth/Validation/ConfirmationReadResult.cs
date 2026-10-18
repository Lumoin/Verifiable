namespace Verifiable.OAuth.Validation;

/// <summary>
/// What reading a verified token's <c>cnf</c> (confirmation) claim (RFC 7800 section 3) found. Absence, a binding this library
/// verifies, malformed confirmation content and a confirmation method this library does not verify are distinct outcomes, so no
/// reading invents a binding a token does not carry, or the absence of one it does.
/// </summary>
internal enum ConfirmationReadResult
{
    /// <summary>The token carries no <c>cnf</c>: it is bound to no key.</summary>
    Absent,

    /// <summary>The <c>cnf</c> is an object carrying only methods this library verifies, each in its registered shape.</summary>
    Bound,

    /// <summary>
    /// The <c>cnf</c> is no JSON object, carries no member, or carries a method this library verifies in another shape than its
    /// registered one (a <c>jkt</c> that is no non-empty string, RFC 9449 section 6.1).
    /// </summary>
    Malformed,

    /// <summary>
    /// The <c>cnf</c> carries a confirmation method this library does not verify (RFC 7800 section 3 registers others, the
    /// <c>x5t#S256</c> of RFC 8705 section 3.1 among them): the token is bound to a key the library cannot check possession of,
    /// so it is neither read as unbound nor as bound by a method it is not.
    /// </summary>
    UnsupportedMethod
}
