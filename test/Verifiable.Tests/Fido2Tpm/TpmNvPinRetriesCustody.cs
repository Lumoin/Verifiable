using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Fido2.Ctap.Authenticator.Custody;
using Automata = Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Tpm;
using Verifiable.Tpm.Extensions.Pin;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Fido2.Tpm.Ctap.Authenticator.Custody;

/// <summary>
/// Composes a <see cref="CtapPinRetriesCustody"/> bundle whose authenticator-global persistent PIN-retry
/// budget is backed by ONE <c>TPM_NT_PIN_FAIL</c> NV Index on an in-house simulated TPM (contract R-10,
/// wavepin) — a thin adapter over the <see cref="TpmDeviceExtensions"/> business-capability verbs package A
/// shipped (<c>DefinePinFailIndexAsync</c>/<c>VerifyPinAsync</c>/<c>ReadPinCountersAsync</c>/
/// <c>ResetPinCountAsync</c>/<c>UndefinePinIndexAsync</c>), never a raw <c>TPM2_NV_Read</c>/<c>NV_Write</c>
/// input, the same dogfood posture <see cref="TpmNvSignatureCounterCustody"/> established over
/// <c>Extensions/Counter</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>One fixed Index, no per-call identity.</b> Unlike <see cref="TpmNvSignatureCounterCustody"/>'s
/// per-credential Index derivation, the PIN throttle is authenticator-global (contract R-3): <see cref="Create"/>'s
/// caller supplies exactly ONE <c>pinIndexHandle</c>, resolved once at composition time, never derived from a
/// per-call identity.
/// </para>
/// <para>
/// <b>PIN rotation IS authValue rotation.</b> <see cref="CtapPinRetriesCustody.ProvisionPinAsync"/> undefines
/// the Index if present (tolerating <c>TPM_RC_HANDLE</c> — nothing was there, for example the very first
/// <c>setPIN</c>), then defines it fresh with the new PIN hash as its OWN authValue via
/// <c>DefinePinFailIndexAsync</c>, which also owner-writes a clean <c>{pinCount: 0, pinLimit: 8}</c> counter
/// window. A PIN Fail Index forbids <c>TPMA_NV_AUTHWRITE</c> (TPM 2.0 Library Part 1, Section 37.2.6.1), so
/// there is no way to change its authValue other than a fresh definition under the same handle — a stale
/// snapshot's own superseded PIN hash can therefore never again resolve authorization once this adapter has
/// provisioned a new one (contract R-2's rollback consequence).
/// </para>
/// <para>
/// <b>The TPM does the compare.</b> <see cref="CtapPinRetriesCustody.VerifyPinAttemptAsync"/> composes
/// <c>VerifyPinAsync</c>'s Index-authorized <c>TPM2_NV_Read</c>, whose compare-and-move is one atomic TPM
/// command (TPM 2.0 Library Part 1, Section 37.2.6.6): a match resets <c>pinCount</c> to zero (reported back
/// as <see cref="CtapPinAttemptVerdict.RetriesRemaining"/> equal to <c>pinLimit</c>); a mismatch answers
/// <c>TPM_RC_BAD_AUTH</c>, after which this adapter follows up with the owner-authorized, no-oracle
/// <c>ReadPinCountersAsync</c> to report the post-attempt budget (two wire calls on the mismatch path — the
/// count already moved atomically in the first — and if THAT follow-up read itself fails, the adapter
/// reports a conservative, never-fail-open mismatch verdict rather than throwing after a burn that already
/// durably happened, wavepin review fix F-3); at <c>pinLimit</c> even a correct candidate is refused with
/// <c>TPM_RC_AUTH_UNAVAILABLE</c> without moving <c>pinCount</c> further; an absent Index (never
/// provisioned, or undefined behind this authenticator's back) answers <c>TPM_RC_HANDLE</c>, tolerated
/// identically to <see cref="CtapPinRetriesCustody.ReadRetriesAsync"/>'s own tolerance rather than thrown
/// (wavepin review fix F-1/F-2) — <see cref="Automata.CtapAuthenticatorSimulator.CreateWithCustodyAsync"/>'s
/// own rehydration reconciliation is what actually resolves the split-brain this signals.
/// </para>
/// <para>
/// <b>Penalize reuses the verify path, never a raw write.</b> <see cref="CtapPinRetriesCustody.PenalizeAttemptAsync"/>
/// (CTAP's decrypt-failure arm, contract R-3) needs to record a failed attempt without ever having a real
/// candidate to present. Package A's verb surface has no owner-authorized arbitrary-count write — only
/// <c>ResetPinCountAsync</c>, which always writes <c>pinCount: 0</c> — so this adapter instead presents a
/// zero-length sentinel candidate to the SAME <c>VerifyPinAsync</c> verify path
/// <see cref="CtapPinRetriesCustody.VerifyPinAttemptAsync"/> itself uses. <see cref="System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>
/// returns <see langword="false"/> immediately whenever the two operands' lengths differ, without comparing
/// any byte content — and every provisioned PIN hash is always exactly 16 octets (<c>LEFT(SHA-256(pin), 16)</c>,
/// CTAP 2.3 lines 5592/5710) — so a zero-length candidate can NEVER accidentally match the real one, without
/// this adapter needing to know, store, or guess it. The Index's own <c>IsPinAuthUnavailable</c> pre-gate
/// (TPM 2.0 Library Part 1, Section 37.2.6.6) fires identically for this sentinel as for a genuine wrong
/// guess, so an at-limit penalize correctly reports blocked rather than advancing past <c>pinLimit</c>. This
/// is the "use the closest verb" resolution the wave contract anticipated for this exact gap — recorded here
/// and in the wave's own report rather than composing an owner <c>NV_Write</c> outside the verb group's
/// public surface.
/// </para>
/// <para>
/// <b>Read and retire.</b> <see cref="CtapPinRetriesCustody.ReadRetriesAsync"/> composes the owner-authorized,
/// no-oracle <c>ReadPinCountersAsync</c> — it never records an attempt, so
/// <see cref="Automata.CtapAuthenticatorSimulator.CreateWithCustodyAsync"/> can freely re-synchronize the
/// demoted <see cref="Automata.CtapAuthenticatorState.PinRetries"/> mirror at rehydration (contract R-4)
/// without ever spending a guess. Reading a not-yet-provisioned tier (the Index has never been defined,
/// because no <c>setPIN</c> has ever run) tolerates <c>TPM_RC_HANDLE</c> and reports the fresh, full budget
/// rather than throwing — the same composition-at-construction-time call every
/// <c>CreateWithCustodyAsync</c> invocation makes, including the very first one on a brand-new authenticator.
/// <see cref="CtapPinRetriesCustody.RetirePinAsync"/> undefines the Index, tolerating <c>TPM_RC_HANDLE</c>
/// (nothing was ever provisioned, or it was already retired) as the ordinary idempotent no-op
/// <see cref="RetirePinAsyncDelegate"/>'s own contract recommends.
/// </para>
/// <para>
/// Every other TPM-side rejection surfaces as a <see cref="TpmNvPinRetriesCustodyException"/> rather than a
/// silently unprovisioned PIN or a retry budget that was not genuinely recorded (fail closed), mirroring
/// <see cref="TpmNvSignatureCounterCustody"/>'s own posture.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1515:Consider making public types internal", Justification = "Staged composition-edge code (layering-split-ledger.md): public by design so the boundary is already the future package's API boundary, per the promotability rules.")]
public static class TpmNvPinRetriesCustody
{
    /// <summary>
    /// Builds a <see cref="CtapPinRetriesCustody"/> bundle backed by ONE <c>TPM_NT_PIN_FAIL</c> NV Index on
    /// an in-house simulated TPM.
    /// </summary>
    /// <param name="tpm">The TPM device every PIN-throttle operation is composed against.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set — used to define, read, reset, and undefine the Index.</param>
    /// <param name="pinIndexHandle">The fixed NV Index handle the authenticator-global PIN-retry budget lives at.</param>
    /// <returns>The composed seam-bundle record.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="tpm"/> is <see langword="null"/>.</exception>
    public static CtapPinRetriesCustody Create(TpmDevice tpm, ReadOnlyMemory<byte> ownerAuth, uint pinIndexHandle)
    {
        ArgumentNullException.ThrowIfNull(tpm);

        var binding = new TpmNvPinRetriesCustodyBinding(tpm, ownerAuth, pinIndexHandle);

        return new CtapPinRetriesCustody(
            binding.ProvisionPinAsync, binding.VerifyPinAttemptAsync, binding.PenalizeAttemptAsync, binding.ReadRetriesAsync, binding.RetirePinAsync);
    }
}


/// <summary>
/// The bound configuration <see cref="TpmNvPinRetriesCustody.Create"/> composes into a
/// <see cref="CtapPinRetriesCustody"/> bundle: every delegate <see cref="TpmNvPinRetriesCustody.Create"/>
/// returns is a bound instance method on one of these, so the only "context" any of them closes over is the
/// explicit receiver (<see langword="this"/>), never a captured local (house rule: no closure capture) —
/// mirroring <c>TpmNvSignatureCounterCustodyBinding</c>'s identical shape.
/// </summary>
internal sealed class TpmNvPinRetriesCustodyBinding
{
    /// <summary>
    /// The fixed attempt ceiling every Index this binding defines or resets is provisioned with, written as
    /// the <c>TPMS_NV_PIN_COUNTER_PARAMETERS.pinLimit</c> field
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 13.3). Single-sourced from the authenticator's own already-shipped
    /// <see cref="Automata.CtapAuthenticatorState.MaxPinRetries"/> rather than restating the literal, so the
    /// persistent tier's ceiling and the mirror's seed can never drift apart (CTAP 2.3, Section 6.5.2.3
    /// bounds it at 8).
    /// </summary>
    private static uint PinLimit { get; } = (uint)Automata.CtapAuthenticatorState.MaxPinRetries;

    /// <summary>The TPM device every PIN-throttle operation is composed against.</summary>
    private TpmDevice Tpm { get; }

    /// <summary>The owner hierarchy's own authorization value.</summary>
    private ReadOnlyMemory<byte> OwnerAuth { get; }

    /// <summary>The fixed NV Index handle the authenticator-global PIN-retry budget lives at.</summary>
    private uint PinIndexHandle { get; }


    /// <summary>
    /// Initializes a new binding. Use <see cref="TpmNvPinRetriesCustody.Create"/>.
    /// </summary>
    /// <param name="tpm">The TPM device every PIN-throttle operation is composed against.</param>
    /// <param name="ownerAuth">The owner hierarchy's own authorization value.</param>
    /// <param name="pinIndexHandle">The fixed NV Index handle the authenticator-global PIN-retry budget lives at.</param>
    internal TpmNvPinRetriesCustodyBinding(TpmDevice tpm, ReadOnlyMemory<byte> ownerAuth, uint pinIndexHandle)
    {
        Tpm = tpm;
        OwnerAuth = ownerAuth;
        PinIndexHandle = pinIndexHandle;
    }


    /// <summary>
    /// Undefines the Index if present, then defines it fresh with <paramref name="pinHash"/> as its own
    /// authValue and a clean <c>{pinCount: 0, pinLimit}</c> counter window — PIN rotation IS authValue
    /// rotation. Has the <see cref="ProvisionPinAsyncDelegate"/> shape.
    /// </summary>
    /// <param name="pinHash">The new stored PIN hash to install as the Index's own authValue.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <exception cref="TpmNvPinRetriesCustodyException">The undefine-if-present step (other than "nothing was there") or the fresh definition was rejected.</exception>
    internal async ValueTask ProvisionPinAsync(ReadOnlyMemory<byte> pinHash, CancellationToken cancellationToken)
    {
        TpmResult<NvUndefineSpaceResponse> undefineResult = await Tpm.UndefinePinIndexAsync(OwnerAuth, PinIndexHandle, cancellationToken).ConfigureAwait(false);
        if(!undefineResult.IsSuccess && !(undefineResult.IsTpmError && undefineResult.ResponseCode == TpmRcConstants.TPM_RC_HANDLE))
        {
            throw new TpmNvPinRetriesCustodyException(
                $"Undefining the PIN Fail NV index before provisioning a fresh PIN failed: {DescribeFailure(undefineResult)}.");
        }

        TpmResult<NvWriteResponse> defineResult = await Tpm.DefinePinFailIndexAsync(OwnerAuth, PinIndexHandle, pinHash, PinLimit, cancellationToken).ConfigureAwait(false);
        if(defineResult.IsSuccess)
        {
            return;
        }

        if(defineResult.IsTpmError && defineResult.ResponseCode == TpmRcConstants.TPM_RC_NV_DEFINED)
        {
            //Tolerated idempotency race (mirrors EnsureCounterAsync's identical NV_DEFINED tolerance): the
            //undefine above did not observably remove the Index, most plausibly because this call is itself
            //a caller-driven retry racing its own prior attempt. The counter window is still reset to
            //{0, PinLimit} via the owner-authorized write ResetPinCountAsync composes on its own, though
            //under a GENUINE concurrent ProvisionPinAsync race the authValue installed is whichever
            //attempt's own NV_DefineSpace actually created the Index — CTAP's sequential single-command
            //execution model means this narrow window is not reachable via the shipped CTAP command surface
            //(documented residual, wavepin-c-report.md §7).
            TpmResult<NvWriteResponse> resetResult = await Tpm.ResetPinCountAsync(OwnerAuth, PinIndexHandle, PinLimit, cancellationToken).ConfigureAwait(false);
            if(resetResult.IsSuccess)
            {
                return;
            }

            throw new TpmNvPinRetriesCustodyException(
                $"Provisioning the PIN Fail NV index failed while tolerating a concurrently defined index: {DescribeFailure(resetResult)}.");
        }

        throw new TpmNvPinRetriesCustodyException($"Provisioning the PIN Fail NV index with the rotated PIN failed: {DescribeFailure(defineResult)}.");
    }


    /// <summary>
    /// Verifies a real candidate PIN hash against the Index's own authValue, atomically recording the
    /// outcome. Has the <see cref="VerifyPinAttemptAsyncDelegate"/> shape.
    /// </summary>
    /// <param name="candidatePinHash">The just-decrypted candidate PIN hash.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <exception cref="TpmNvPinRetriesCustodyException">The verify, or the mismatch-path counter read-back, was rejected for a reason other than the tier being exhausted.</exception>
    internal ValueTask<CtapPinAttemptVerdict> VerifyPinAttemptAsync(ReadOnlyMemory<byte> candidatePinHash, CancellationToken cancellationToken) =>
        VerifyCandidateCoreAsync(candidatePinHash, cancellationToken);


    /// <summary>
    /// Records a failed attempt with no real candidate to present, by driving the exact same atomic
    /// Index-authorized verify path a genuine wrong guess uses, with a zero-length sentinel candidate that
    /// can never match a real (always 16-octet) provisioned PIN hash. Has the
    /// <see cref="PenalizeAttemptAsyncDelegate"/> shape.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <exception cref="TpmNvPinRetriesCustodyException">The verify, or the mismatch-path counter read-back, was rejected for a reason other than the tier being exhausted.</exception>
    internal async ValueTask<CtapPinAttemptVerdict> PenalizeAttemptAsync(CancellationToken cancellationToken)
    {
        CtapPinAttemptVerdict verdict = await VerifyCandidateCoreAsync(ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);

        //The sentinel can never legitimately match, but the record's own IsMatch is pinned false here
        //regardless, so this delegate's documented invariant holds even if a future Index-auth policy ever
        //changed what "match" means.
        return verdict with { IsMatch = false };
    }


    /// <summary>
    /// Reads the Index's current counter parameters under owner authorization, without recording an attempt.
    /// Has the <see cref="ReadRetriesAsyncDelegate"/> shape.
    /// </summary>
    /// <remarks>
    /// Tolerates <c>TPM_RC_HANDLE</c> (the Index has never been defined — no PIN has ever been provisioned,
    /// for example a freshly composed <see cref="Automata.CtapAuthenticatorSimulator.CreateWithCustodyAsync"/>
    /// call on a brand-new authenticator, whose own <c>pinRetriesCustody</c> is supplied from the start,
    /// before the first <c>setPIN</c>) by reporting the fresh, full <see cref="PinLimit"/> budget — the same
    /// value <see cref="Automata.CtapAuthenticatorState.Initial"/> already seeds its own mirror with before
    /// any PIN exists.
    /// </remarks>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <exception cref="TpmNvPinRetriesCustodyException">The owner-authorized read was rejected for a reason other than the Index never having been defined.</exception>
    internal async ValueTask<CtapPinAttemptVerdict> ReadRetriesAsync(CancellationToken cancellationToken)
    {
        TpmResult<TpmPinCounterParameters> readResult = await Tpm.ReadPinCountersAsync(OwnerAuth, PinIndexHandle, cancellationToken).ConfigureAwait(false);
        if(!readResult.IsSuccess)
        {
            if(readResult.IsTpmError && readResult.ResponseCode == TpmRcConstants.TPM_RC_HANDLE)
            {
                return new CtapPinAttemptVerdict(IsMatch: false, RetriesRemaining: (int)PinLimit, IsBlocked: false, IsProvisioned: false);
            }

            throw new TpmNvPinRetriesCustodyException($"Reading the PIN Fail NV index's current counters failed: {DescribeFailure(readResult)}.");
        }

        return ToVerdict(readResult.Value, isMatch: false);
    }


    /// <summary>
    /// Undefines the Index, tolerating an already-retired or never-provisioned tier as a no-op. Has the
    /// <see cref="RetirePinAsyncDelegate"/> shape.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <exception cref="TpmNvPinRetriesCustodyException">The undefine was rejected for a reason other than the Index never having existed.</exception>
    internal async ValueTask RetirePinAsync(CancellationToken cancellationToken)
    {
        TpmResult<NvUndefineSpaceResponse> undefineResult = await Tpm.UndefinePinIndexAsync(OwnerAuth, PinIndexHandle, cancellationToken).ConfigureAwait(false);
        if(undefineResult.IsSuccess || (undefineResult.IsTpmError && undefineResult.ResponseCode == TpmRcConstants.TPM_RC_HANDLE))
        {
            return;
        }

        throw new TpmNvPinRetriesCustodyException($"Retiring the PIN Fail NV index failed: {DescribeFailure(undefineResult)}.");
    }


    /// <summary>
    /// Composes <c>VerifyPinAsync</c>'s atomic compare-and-move, mapping its outcome onto a
    /// <see cref="CtapPinAttemptVerdict"/> per contract R-10: success reports the reset budget; a mismatch
    /// follows up with the owner-authorized, no-oracle counter read to report the post-attempt budget (a
    /// follow-up read failure there reports a conservative, never-fail-open mismatch verdict rather than
    /// throwing after the burn already durably recorded — wavepin review fix F-3); an already-exhausted
    /// tier reports blocked without a follow-up read; an absent Index (never provisioned, or undefined
    /// behind this authenticator's back — wavepin review fix F-1/F-2) reports a fail-closed non-match
    /// verdict carrying <see cref="CtapPinAttemptVerdict.IsProvisioned"/> <see langword="false"/> rather
    /// than throwing; anything else throws.
    /// </summary>
    /// <param name="candidatePinHash">The candidate hash to present to the Index's own authValue compare — real or a penalize sentinel.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The mapped verdict.</returns>
    /// <exception cref="TpmNvPinRetriesCustodyException">The verify was rejected for a reason other than the tier being exhausted or the Index being absent.</exception>
    private async ValueTask<CtapPinAttemptVerdict> VerifyCandidateCoreAsync(ReadOnlyMemory<byte> candidatePinHash, CancellationToken cancellationToken)
    {
        TpmResult<TpmPinCounterParameters> verifyResult = await Tpm.VerifyPinAsync(PinIndexHandle, candidatePinHash, cancellationToken).ConfigureAwait(false);
        if(verifyResult.IsSuccess)
        {
            return ToVerdict(verifyResult.Value, isMatch: true);
        }

        if(verifyResult.IsTpmError && verifyResult.ResponseCode == TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE)
        {
            return new CtapPinAttemptVerdict(IsMatch: false, RetriesRemaining: 0, IsBlocked: true, IsProvisioned: true);
        }

        //Wavepin review fix F-1/F-2: an absent Index — never provisioned, or undefined behind this
        //authenticator's back (a crash mid-rotation, or an owner-authorized recovery action) — answers
        //TPM_RC_HANDLE here exactly as ReadRetriesAsync's own tolerance does. Reporting a fail-closed
        //non-match with the fresh full budget (never claiming MORE retries remain than could genuinely
        //exist) lets a racing/absent tier answer a defined CTAP status instead of an uncaught exception;
        //CreateWithCustodyAsync's own reconciliation is what actually clears the stale local PIN so
        //setPIN can recover — this arm only has to avoid crashing the in-flight command.
        if(verifyResult.IsTpmError && verifyResult.ResponseCode == TpmRcConstants.TPM_RC_HANDLE)
        {
            return new CtapPinAttemptVerdict(IsMatch: false, RetriesRemaining: (int)PinLimit, IsBlocked: false, IsProvisioned: false);
        }

        if(verifyResult.IsTpmError && verifyResult.ResponseCode == TpmRcConstants.TPM_RC_BAD_AUTH)
        {
            TpmResult<TpmPinCounterParameters> readResult = await Tpm.ReadPinCountersAsync(OwnerAuth, PinIndexHandle, cancellationToken).ConfigureAwait(false);
            if(!readResult.IsSuccess)
            {
                //Wavepin review fix F-3: the mismatch was ALREADY durably recorded by the atomic verify
                //above — a throw here would report an opaque exception for a wire-visible attempt that
                //genuinely happened, and the mirror would never learn of it. Reporting a conservative
                //mismatch verdict (blocked, zero remaining) never fails open: the true remaining count is
                //somewhere between 0 and PinLimit - 1, and reporting 0 can only under-grant further
                //attempts, never over-grant them. The next ReadRetriesAsync (rehydration) self-heals the
                //mirror to the tier's own true value.
                return new CtapPinAttemptVerdict(IsMatch: false, RetriesRemaining: 0, IsBlocked: true, IsProvisioned: true);
            }

            return ToVerdict(readResult.Value, isMatch: false);
        }

        throw new TpmNvPinRetriesCustodyException($"Verifying a PIN attempt against the PIN Fail NV index failed: {DescribeFailure(verifyResult)}.");
    }


    /// <summary>Maps a TPM-reported counter window onto a <see cref="CtapPinAttemptVerdict"/>, always <see cref="CtapPinAttemptVerdict.IsProvisioned"/> <see langword="true"/> — this helper is only ever called once a real counter window has been successfully read back from a genuinely defined Index.</summary>
    /// <param name="counters">The Index's own <c>pinCount</c>/<c>pinLimit</c> as read back from the TPM.</param>
    /// <param name="isMatch">Whether this verdict corresponds to a matched candidate.</param>
    /// <returns>The mapped verdict.</returns>
    private static CtapPinAttemptVerdict ToVerdict(TpmPinCounterParameters counters, bool isMatch)
    {
        int retriesRemaining = (int)(counters.PinLimit - counters.PinCount);

        return new CtapPinAttemptVerdict(isMatch, retriesRemaining, retriesRemaining <= 0, IsProvisioned: true);
    }


    /// <summary>Describes a non-success <see cref="TpmResult{T}"/> for a fail-closed exception message.</summary>
    /// <typeparam name="T">The result's success-value type.</typeparam>
    /// <param name="result">The non-success result to describe.</param>
    /// <returns>A short, human-readable description of the TPM or transport failure.</returns>
    private static string DescribeFailure<T>(TpmResult<T> result) =>
        result.IsTpmError ? result.ResponseCode.GetDescription() : $"transport error 0x{result.TransportErrorCode:X8}";
}
