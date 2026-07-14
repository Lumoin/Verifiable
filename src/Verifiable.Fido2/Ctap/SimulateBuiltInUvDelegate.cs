namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Simulates one built-in user verification attempt (CTAP 2.3 §6.5.3.1's <c>performBuiltInUv</c>, step
/// 7: "Perform built-in user verification").
/// </summary>
/// <returns>
/// The attempt's outcome — see <see cref="CtapBuiltInUvAttemptOutcome"/>.
/// </returns>
/// <remarks>
/// A composition-time <see cref="Ctap.Authenticator.Automata.CtapAuthenticatorSimulator"/> personalization
/// knob (R8) — the outcome-injection seam mirroring <see cref="SimulateFingerprintCaptureDelegate"/>'s
/// own production-personalization posture, never a test-only hook: the shipped default always reports
/// <see cref="CtapBuiltInUvAttemptOutcome.Success"/>, and a caller supplies a closure returning a scripted
/// sequence per call to exercise retry, timeout, or lockout paths. Consumed ONLY by
/// <c>performBuiltInUv</c>'s own executors — <c>getPinUvAuthTokenUsingUvWithPermissions</c>'s (<c>0x06</c>)
/// token-issuance effect and <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>'s own
/// <c>options.uv</c> built-in-UV fallback effect.
/// </remarks>
public delegate CtapBuiltInUvAttemptOutcome SimulateBuiltInUvDelegate();
