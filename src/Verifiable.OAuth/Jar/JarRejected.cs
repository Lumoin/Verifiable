using System.Diagnostics;

namespace Verifiable.OAuth.Jar;

/// <summary>
/// A JWT Authorization Request that failed verification, carrying the
/// OAuth wire error code and a human-readable reason for audit.
/// </summary>
/// <param name="ErrorCode">
/// The OAuth wire error code; one of <see cref="OAuthErrors"/>.
/// </param>
/// <param name="Reason">
/// Human-readable description for audit logging. Not echoed to the
/// client unmodified — RFC 6749 §5.2 specifies that <c>error_description</c>
/// is OPTIONAL and the AS may truncate, sanitise, or omit it.
/// </param>
[DebuggerDisplay("JarRejected ErrorCode={ErrorCode} Reason={Reason}")]
public sealed record JarRejected(
    string ErrorCode,
    string Reason): JarVerificationResult;
