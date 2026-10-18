using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Jar;

/// <summary>
/// A JWT Authorization Request whose JWS signature has been verified,
/// whose <c>typ</c> header has been validated, and whose JWT timing
/// claims (<c>iat</c>, <c>nbf</c>, <c>exp</c>) have been parsed and
/// checked against the supplied current instant within the supplied
/// clock-skew tolerance. Each timing claim is the NumericDate as written,
/// every digit kept.
/// </summary>
/// <param name="ProtectedHeader">The verified protected header.</param>
/// <param name="Claims">The verified claims set.</param>
/// <param name="Iat">The <c>iat</c> claim as written.</param>
/// <param name="Nbf">The <c>nbf</c> claim as written.</param>
/// <param name="Exp">The <c>exp</c> claim as written.</param>
[DebuggerDisplay("JarVerified Exp={Exp}")]
public sealed record JarVerified(
    UnverifiedJwtHeader ProtectedHeader,
    IReadOnlyDictionary<string, object> Claims,
    NumericDate Iat,
    NumericDate Nbf,
    NumericDate Exp) : JarVerificationResult;
