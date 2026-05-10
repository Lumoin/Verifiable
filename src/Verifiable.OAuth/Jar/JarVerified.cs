using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Jar;

/// <summary>
/// A JWT Authorization Request whose JWS signature has been verified,
/// whose <c>typ</c> header has been validated, and whose JWT timing
/// claims (<c>iat</c>, <c>nbf</c>, <c>exp</c>) have been parsed and
/// checked against the supplied current instant within the supplied
/// clock-skew tolerance.
/// </summary>
[DebuggerDisplay("JarVerified Exp={Exp}")]
public sealed record JarVerified(
    UnverifiedJwtHeader ProtectedHeader,
    IReadOnlyDictionary<string, object> Claims,
    DateTimeOffset Iat,
    DateTimeOffset Nbf,
    DateTimeOffset Exp): JarVerificationResult;
