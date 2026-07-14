using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// The result of <see cref="Fido2RegistrationVerifier.VerifyAsync"/>: the attestation statement's
/// verification outcome, the WebAuthn L3 §7.1 ceremony rule claims (extended with the step 26
/// credential-id-uniqueness signal), a policy-neutral summary of whether the registration is
/// acceptable, and the step 27 credential record to store when it is.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
/// Authentication Level 3, section 7.1: Registering a New Credential</see>.
/// </remarks>
/// <param name="AttestationResult">
/// The outcome of the attestation statement format's verification procedure (steps 21-23), also
/// folded into <see cref="Claims"/>'s <see cref="Fido2ClaimIds.Fido2RegistrationAttestationTrustworthy"/>
/// claim by <see cref="Fido2ValidationProfiles.RegistrationRules"/>, and repeated here so a caller
/// can recover the certificate trust path of a <see cref="CertifiedAttestationResult"/> or the
/// specific <see cref="Fido2AttestationError"/> of a <see cref="RejectedAttestationResult"/>
/// without re-deriving it from the claim outcome alone.
/// </param>
/// <param name="Claims">
/// The <see cref="ClaimIssueResult"/> produced by running the configured
/// <see cref="Fido2ValidationProfiles.RegistrationRules"/> rule list against the ceremony's surface
/// fields, extended with the step 26 credential-id-uniqueness claim
/// (<see cref="Fido2ClaimIds.Fido2RegistrationCredentialIdUnique"/>) that the rule list itself
/// cannot compute, since it depends on the relying party's own credential storage.
/// </param>
/// <param name="IsAcceptable">
/// <see langword="true"/> when no claim in <see cref="Claims"/> carries
/// <see cref="ClaimOutcome.Failure"/> and <see cref="AttestationResult"/> is not a
/// <see cref="RejectedAttestationResult"/>. <see cref="ClaimOutcome.Inconclusive"/> and
/// <see cref="ClaimOutcome.NotApplicable"/> never affect this value — they are signals for relying
/// party policy to act on, never automatic failures.
/// </param>
/// <param name="CredentialRecord">
/// The step 27 <see cref="Fido2CredentialRecord"/> to store for this credential, or
/// <see langword="null"/> when <paramref name="IsAcceptable"/> is <see langword="false"/> — an
/// unacceptable registration has nothing a relying party should persist.
/// </param>
[DebuggerDisplay("Fido2RegistrationOutcome(IsAcceptable={IsAcceptable}, CredentialRecord={CredentialRecord is not null})")]
public sealed record Fido2RegistrationOutcome(
    AttestationResult AttestationResult,
    ClaimIssueResult Claims,
    bool IsAcceptable,
    Fido2CredentialRecord? CredentialRecord);
