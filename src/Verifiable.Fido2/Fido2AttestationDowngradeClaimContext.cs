using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// <see cref="ClaimContext"/> subtype attached to
/// <see cref="Fido2ClaimIds.Fido2RegistrationAttestationDowngraded"/> whenever
/// <see cref="Fido2RegistrationVerifier"/> downgrades a certified attestation whose trust path did
/// not reach a supplied anchor to a none-equivalent result, per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
/// Authentication Level 3, section 7.1: Registering a New Credential</see>'s final step.
/// </summary>
/// <param name="Downgrade">The original attestation format and trust-path shortfall that was downgraded.</param>
[DebuggerDisplay("Fido2AttestationDowngradeClaimContext({Downgrade,nq})")]
public sealed record Fido2AttestationDowngradeClaimContext(Fido2AttestationDowngrade Downgrade): ClaimContext;
