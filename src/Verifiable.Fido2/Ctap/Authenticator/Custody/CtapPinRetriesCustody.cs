using System;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// A backend-neutral seam bundling the five async delegates a <see cref="Automata.CtapAuthenticatorSimulator"/>
/// needs to custody CTAP 2.3 §6.5.5.2's persistent <c>pinRetries</c> tier against a rollback-protected
/// external PIN-throttle primitive, SIBLING to <see cref="CtapStateCustody"/> and
/// <see cref="CtapSignatureCounterCustody"/> rather than a widening of either (contract R-3, wavepin):
/// provision a fresh PIN, verify a guess against the currently provisioned one, penalize a guess whose
/// candidate hash never decrypted, read the current budget without recording an attempt, and retire the
/// tier entirely.
/// </summary>
/// <remarks>
/// <para>
/// A plain seam-bundle record of delegates, never a behavioral interface — the same house convention
/// <see cref="CtapStateCustody"/>/<see cref="CtapSignatureCounterCustody"/> establish (contract R-3): any
/// throttle-backed store (an in-memory dictionary, a database row, or package C's TPM-backed
/// <c>TpmNvPinRetriesCustody</c> over a <c>TPM_NT_PIN_FAIL</c> Index) implements this shape by supplying
/// five delegates, with no interface to implement and no base type to derive from.
/// </para>
/// <para>
/// <b>Opt-in, byte-identical when absent.</b> Composing this bundle is entirely independent of
/// <see cref="CtapStateCustody"/>/<see cref="CtapSignatureCounterCustody"/>'s own seams — with it
/// composed, <see cref="Automata.CtapAuthenticatorState.PinRetries"/> becomes a demoted CACHE (the
/// snapshot CBOR format and version are unchanged, contract R-4) and this bundle's
/// <see cref="VerifyPinAttemptAsync"/>/<see cref="PenalizeAttemptAsync"/> become the AUTHORITATIVE
/// source of every retry-budget consequence; a stale or replayed whole-snapshot can then never restore
/// a spent retry budget, and — because <see cref="ProvisionPinAsync"/> rotates the persistent tier's own
/// authorization secret — never resurrect a superseded PIN either.
/// <see cref="Automata.CtapAuthenticatorSimulator.CreateWithCustodyAsync"/>'s own
/// <c>pinRetriesCustody</c> parameter is the ONLY way a simulator gains this behavior, and it defaults
/// to <see langword="null"/> — every existing composition root is unaffected (contract R-6).
/// </para>
/// <para>
/// The PIN throttle is authenticator-global — ONE fixed persistent-tier identity, no per-call identity
/// parameter (contrast <see cref="CtapSignatureCounterCustody"/>'s own per-credential
/// <c>creationSequence</c> keying): there is exactly one <c>pinRetries</c> value per authenticator.
/// </para>
/// </remarks>
/// <param name="ProvisionPinAsync">Provisions a fresh PIN as the persistent tier's current one, resetting its retry budget to maximum.</param>
/// <param name="VerifyPinAttemptAsync">Verifies a candidate PIN hash against the currently provisioned one, atomically recording the outcome.</param>
/// <param name="PenalizeAttemptAsync">Records a failed attempt whose candidate hash never decrypted, exactly like a recorded mismatch.</param>
/// <param name="ReadRetriesAsync">Reads the current retry budget without recording an attempt.</param>
/// <param name="RetirePinAsync">Retires the persistent tier entirely.</param>
/// <exception cref="ArgumentNullException">Any of the five delegates is <see langword="null"/>.</exception>
public sealed record CtapPinRetriesCustody(
    ProvisionPinAsyncDelegate ProvisionPinAsync,
    VerifyPinAttemptAsyncDelegate VerifyPinAttemptAsync,
    PenalizeAttemptAsyncDelegate PenalizeAttemptAsync,
    ReadRetriesAsyncDelegate ReadRetriesAsync,
    RetirePinAsyncDelegate RetirePinAsync)
{
    /// <summary>Provisions a fresh PIN as the persistent tier's current one, resetting its retry budget to maximum. Never <see langword="null"/>.</summary>
    public ProvisionPinAsyncDelegate ProvisionPinAsync { get; } =
        ProvisionPinAsync ?? throw new ArgumentNullException(nameof(ProvisionPinAsync));

    /// <summary>Verifies a candidate PIN hash against the currently provisioned one, atomically recording the outcome. Never <see langword="null"/>.</summary>
    public VerifyPinAttemptAsyncDelegate VerifyPinAttemptAsync { get; } =
        VerifyPinAttemptAsync ?? throw new ArgumentNullException(nameof(VerifyPinAttemptAsync));

    /// <summary>Records a failed attempt whose candidate hash never decrypted, exactly like a recorded mismatch. Never <see langword="null"/>.</summary>
    public PenalizeAttemptAsyncDelegate PenalizeAttemptAsync { get; } =
        PenalizeAttemptAsync ?? throw new ArgumentNullException(nameof(PenalizeAttemptAsync));

    /// <summary>Reads the current retry budget without recording an attempt. Never <see langword="null"/>.</summary>
    public ReadRetriesAsyncDelegate ReadRetriesAsync { get; } =
        ReadRetriesAsync ?? throw new ArgumentNullException(nameof(ReadRetriesAsync));

    /// <summary>Retires the persistent tier entirely. Never <see langword="null"/>.</summary>
    public RetirePinAsyncDelegate RetirePinAsync { get; } =
        RetirePinAsync ?? throw new ArgumentNullException(nameof(RetirePinAsync));
}
