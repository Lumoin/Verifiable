using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The verification result when an attestation statement fails its format's verification
/// procedure.
/// </summary>
/// <param name="Error">
/// The specific <see cref="Fido2AttestationError"/> naming what failed, drawn from the catalog
/// in <see cref="Fido2AttestationErrors"/>, so a caller can branch on the rejection reason
/// without parsing an exception message.
/// </param>
/// <remarks>
/// A rejected attestation statement is a normal verification outcome, not an exceptional one:
/// forged, malformed, or otherwise non-conforming wire input from an untrusted authenticator is
/// exactly what a verification procedure exists to detect, so it is reported as a result rather
/// than thrown.
/// </remarks>
[DebuggerDisplay("RejectedAttestationResult({Error.Code,nq})")]
public sealed record RejectedAttestationResult(Fido2AttestationError Error): AttestationResult;
