using System;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// The in-progress fingerprint enrollment an <c>enrollCaptureNextSample</c> command needs remembered
/// across separate CTAP2 commands, persisted as a data field on
/// <see cref="CtapAuthenticatorState.RememberedBioEnrollment"/> — the FOURTH remembered-sequence slot on
/// that record (R7), sibling to <see cref="CtapRememberedGetAssertionState"/>/
/// <see cref="CtapRememberedEnumerateRpsState"/>/<see cref="CtapRememberedEnumerateCredentialsState"/>
/// but structurally distinct from all three: it remembers a not-yet-persisted template's own capture
/// PROGRESS, never a pre-verified continuation of an already-authorized request. Every
/// <c>enrollCaptureNextSample</c> call still carries and verifies its OWN <c>pinUvAuthParam</c> (bio scout
/// §1.5) — this record carries no authenticating-protocol field for that reason, unlike the other three
/// remembered-sequence records.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7.4: Enrolling fingerprint</see>. Installed by <c>enrollBegin</c>'s own first
/// capture; advanced by <c>enrollCaptureNextSample</c> on a GOOD sample; cleared (and its
/// <see cref="TemplateId"/> ownership transferred into a new <see cref="CtapBioEnrollmentTemplateRecord"/>)
/// once <see cref="RemainingSamples"/> reaches zero; discarded — with <see cref="TemplateId"/> disposed,
/// since no store record has adopted it yet — by <c>cancelCurrentEnrollment</c>, by a fresh
/// <c>enrollBegin</c>'s own auto-cancel step, by <see cref="CtapAuthenticatorState.PowerCycle"/>, and by
/// <see cref="CtapAuthenticatorState.FactoryReset"/>.
/// </remarks>
/// <param name="TemplateId">
/// The in-progress enrollment's freshly minted template identifier, not yet visible to
/// <c>enumerateEnrollments</c>. Owned by this record until completion transfers ownership into the store.
/// </param>
/// <param name="RemainingSamples">
/// The number of further GOOD samples this enrollment still needs before it completes
/// (<see cref="CtapAuthenticatorState.MaxCaptureSamplesRequiredForEnroll"/> minus good samples captured so
/// far). A non-GOOD capture leaves this value unchanged (bio scout Finding 9).
/// </param>
public sealed record CtapRememberedBioEnrollmentState(
    BioEnrollmentTemplateId TemplateId,
    int RemainingSamples): IDisposable
{
    /// <summary>
    /// Releases the not-yet-persisted <see cref="TemplateId"/> this record owns.
    /// </summary>
    public void Dispose()
    {
        TemplateId.Dispose();
    }
}
