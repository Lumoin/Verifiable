using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// A diagnostic describing why an attestation statement verification procedure rejected an
/// attestation statement. Carries a stable <see cref="Code"/> for programmatic branching and a
/// human-readable <see cref="Message"/>. Standard conditions are exposed by
/// <see cref="Fido2AttestationErrors"/>.
/// </summary>
/// <param name="Code">A stable, machine-comparable error code.</param>
/// <param name="Message">A human-readable description of the condition. Not for display to untrusted callers verbatim.</param>
[DebuggerDisplay("Fido2AttestationError({Code,nq})")]
public sealed record Fido2AttestationError(string Code, string Message);
