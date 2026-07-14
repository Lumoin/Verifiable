namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Simulates one fingerprint sensor capture attempt during <c>authenticatorBioEnrollment</c>'s
/// <c>enrollBegin</c>/<c>enrollCaptureNextSample</c> subcommands.
/// </summary>
/// <returns>
/// One of <see cref="WellKnownCtapLastEnrollSampleStatuses"/>'s registered values to report as the
/// response's own <c>lastEnrollSampleStatus</c> (<c>0x05</c>) field. Every value this delegate returns is
/// reported inside a successful <c>CTAP2_OK</c> response, never mapped to a CTAP2 protocol-level error
/// (CTAP 2.3 §6.7, bio scout Finding 9) — <see cref="WellKnownCtapLastEnrollSampleStatuses.Good"/>
/// (<c>0x00</c>) advances the enrollment's own remaining-samples counter; any other value leaves it
/// unchanged.
/// </returns>
/// <remarks>
/// A composition-time <see cref="Ctap.Authenticator.Automata.CtapAuthenticatorSimulator"/> personalization
/// knob (R8) — the outcome-injection seam mirroring <see cref="Verifiable.Cryptography.FillEntropyDelegate"/>'s
/// own production-personalization posture, never a test-only hook: the shipped default models an ideal
/// sensor (always <see cref="WellKnownCtapLastEnrollSampleStatuses.Good"/>), and a caller supplies a
/// closure returning a scripted sequence per call to exercise poor-quality or no-touch capture paths.
/// Consumed ONLY by <c>enrollBegin</c>'s and <c>enrollCaptureNextSample</c>'s own effectful executors.
/// </remarks>
public delegate int SimulateFingerprintCaptureDelegate();
