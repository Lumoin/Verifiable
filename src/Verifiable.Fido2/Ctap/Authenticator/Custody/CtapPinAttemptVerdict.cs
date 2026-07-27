namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// The outcome of one PIN-guess attempt against a <see cref="CtapPinRetriesCustody"/> bundle's
/// authoritative persistent-tier counter (contract R-1/R-2, wavepin) — the CTAP-side analogue of a
/// <c>TPM_NT_PIN_FAIL</c> Index's own <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> read-back
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Part 1, clause 37.2.6.6; Part 2, clause 13.3</see>.
/// </summary>
/// <param name="IsMatch">
/// Whether the candidate PIN hash matched the custody's own currently provisioned value — CTAP 2.3
/// §6.5.5.2's <c>pinRetries</c> reset-to-maximum condition fires exactly when this is
/// <see langword="true"/>.
/// </param>
/// <param name="RetriesRemaining">
/// The persistent-tier retry budget immediately after this attempt was recorded — the value a
/// <see cref="Automata.CtapAuthenticatorSimulator"/> mirrors onto
/// <see cref="Automata.CtapAuthenticatorState.PinRetries"/> (contract R-4: a demoted CACHE once this
/// seam is composed) and <c>getPINRetries</c> reports on the wire.
/// </param>
/// <param name="IsBlocked">
/// Whether the persistent tier is exhausted — <see langword="true"/> exactly when
/// <paramref name="RetriesRemaining"/> is zero, mirroring <c>TPM_NT_PIN_FAIL</c>'s own
/// <c>TPM_RC_AUTH_UNAVAILABLE</c> refusal of even the correct value once <c>pinCount</c> reaches
/// <c>pinLimit</c> (TPM 2.0 Library Part 1, clause 37.2.6.6). Carried as its own field, rather than
/// re-derived from <paramref name="RetriesRemaining"/> at every call site, so contract R-5's priority
/// rule (this field beats the boot-scoped <c>PIN_AUTH_BLOCKED</c> latch) reads directly off the
/// verdict.
/// </param>
/// <param name="IsProvisioned">
/// Whether the persistent tier is genuinely provisioned — <see langword="true"/> exactly when the
/// <c>TPM_NT_PIN_FAIL</c> Index this verdict was read from or verified against actually exists
/// (TPM 2.0 Library Part 1, clause 37.2.6.6), <see langword="false"/> when the tier answered its own
/// "never defined" tolerance (<c>TPM_RC_HANDLE</c>) instead. Added by the wavepin review fix for
/// F-1/F-2: before this member existed, <see cref="Automata.CtapAuthenticatorSimulator.CreateWithCustodyAsync"/>
/// could not distinguish "a PIN is genuinely set on the durable tier" from "no PIN has ever been
/// provisioned" when the whole-snapshot's own <see cref="Automata.CtapAuthenticatorState.CurrentStoredPin"/>
/// disagreed with the durable tier — precisely the missing signal its reconciliation needs to close
/// both the authentication-bypass and no-PIN-path-recovery defects a split-brain between the two tiers
/// otherwise opens.
/// </param>
public readonly record struct CtapPinAttemptVerdict(bool IsMatch, int RetriesRemaining, bool IsBlocked, bool IsProvisioned);
