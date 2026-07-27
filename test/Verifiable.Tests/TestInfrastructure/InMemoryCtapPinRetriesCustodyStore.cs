using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Fido2.Ctap.Authenticator.Custody;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// An in-memory, single-tier test double for <see cref="CtapPinRetriesCustody"/>: models
/// <c>TPM_NT_PIN_FAIL</c>'s own <c>pinCount</c>/<c>pinLimit</c> semantics (TPM 2.0 Library Part 1, clause
/// 37.2.6.6) entirely in-process, exactly as package C's TPM-backed <c>TpmNvPinRetriesCustody</c> would
/// over a real NV Index — success resets <c>pinCount</c> to 0, mismatch increments it, and once
/// <c>pinCount</c> reaches <see cref="PinLimit"/> even a subsequently CORRECT candidate is refused without
/// ever being compared (the R-2 pre-gate a real Index's own authorization failure enforces).
/// </summary>
/// <remarks>
/// <para>
/// The library performs no I/O of its own; this double plays the rollback-protected NV Index a real
/// deployment would choose. Its five exposed methods are bound INSTANCE methods (house rule: no closure
/// capture) — the only "context" any of them closes over is the explicit receiver (<see langword="this"/>),
/// mirroring <see cref="DictionaryBackedCtapStateCustodyStore"/>'s identical discipline.
/// </para>
/// <para>
/// <see cref="OperationLog"/> and <see cref="ProvisionedPinHashes"/> exist so a test can assert ORDER
/// (verify-before-token, penalize-not-verify-on-decrypt-failure) and PIN ROTATION (each
/// <see cref="ProvisionPinAsync"/> call's exact hash bytes) without reaching into the seam's own
/// implementation — the same test-oracle discipline <see cref="RecordingSignatureCounterCustodyHarness"/>
/// establishes for the signature-counter seam.
/// </para>
/// </remarks>
internal sealed class InMemoryCtapPinRetriesCustodyStore
{
    /// <summary>The persistent tier's retry ceiling — CTAP 2.3 §6.5.5.2's <c>MaxPinRetries</c> (8).</summary>
    public const int PinLimit = 8;

    /// <summary>The order every custody operation ran in, one entry per call.</summary>
    private readonly List<string> operationLog = [];

    /// <summary>Every <see cref="ProvisionPinAsync"/> call's exact <c>pinHash</c> bytes, in call order.</summary>
    private readonly List<byte[]> provisionedPinHashes = [];

    /// <summary>The currently provisioned PIN hash, or <see langword="null"/> if none has ever been provisioned or the tier was retired.</summary>
    private byte[]? provisionedPinHash;

    /// <summary>The persistent tier's current failure count — CTAP's own <c>pinCount</c> analogue.</summary>
    private int pinCount;


    /// <summary>The order every custody operation ran in, one entry per call. Never <see langword="null"/>.</summary>
    public IReadOnlyList<string> OperationLog => operationLog;

    /// <summary>Every <see cref="ProvisionPinAsync"/> call's exact <c>pinHash</c> bytes, in call order.</summary>
    public IReadOnlyList<byte[]> ProvisionedPinHashes => provisionedPinHashes;

    /// <summary>The persistent tier's current retry budget, computed directly from <see cref="pinCount"/> — a test-only shortcut around a wire round trip.</summary>
    public int CurrentRetriesRemaining => PinLimit - pinCount;

    /// <summary>Whether the persistent tier is currently exhausted.</summary>
    public bool IsCurrentlyBlocked => pinCount >= PinLimit;


    /// <summary>
    /// Builds and returns this store's <see cref="CtapPinRetriesCustody"/> bundle — call once, immediately
    /// after construction.
    /// </summary>
    public CtapPinRetriesCustody CreateBundle() =>
        new(ProvisionPinAsync, VerifyPinAttemptAsync, PenalizeAttemptAsync, ReadRetriesAsync, RetirePinAsync);


    /// <summary>
    /// Sets the persistent tier's own failure count directly, WITHOUT going through
    /// <see cref="VerifyPinAttemptAsync"/>/<see cref="PenalizeAttemptAsync"/> — a test-only shortcut
    /// modeling a tier whose count already reflects attempts made elsewhere (a different session against
    /// the same NV Index, or a real device the whole-snapshot side never learned of).
    /// </summary>
    /// <param name="count">The failure count to set, clamped to <c>[0, PinLimit]</c>.</param>
    public void SeedPinCount(int count) => pinCount = Math.Clamp(count, 0, PinLimit);


    /// <summary>
    /// Drives <see cref="pinCount"/> to exactly <see cref="PinLimit"/> — a test-only shortcut for
    /// scenarios that need the tier already blocked before the wire-level attempt under test runs.
    /// </summary>
    public void ForceBlocked() => SeedPinCount(PinLimit);


    /// <summary>Provisions <paramref name="pinHash"/> as the persistent tier's current PIN, resetting <see cref="pinCount"/> to zero. Has the <see cref="ProvisionPinAsyncDelegate"/> shape.</summary>
    private ValueTask ProvisionPinAsync(ReadOnlyMemory<byte> pinHash, CancellationToken cancellationToken)
    {
        byte[] copy = pinHash.ToArray();
        provisionedPinHash = copy;
        provisionedPinHashes.Add(copy);
        pinCount = 0;
        operationLog.Add("Provision");

        return ValueTask.CompletedTask;
    }


    /// <summary>
    /// Verifies <paramref name="candidatePinHash"/> against the currently provisioned PIN, atomically
    /// recording the outcome. Has the <see cref="VerifyPinAttemptAsyncDelegate"/> shape.
    /// </summary>
    /// <param name="candidatePinHash">The just-decrypted candidate PIN hash.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private ValueTask<CtapPinAttemptVerdict> VerifyPinAttemptAsync(ReadOnlyMemory<byte> candidatePinHash, CancellationToken cancellationToken)
    {
        operationLog.Add("Verify");

        //Contract R-2's pre-gate: once the tier is exhausted, even the correct candidate is refused
        //without ever being compared — mirrors TPM_RC_AUTH_UNAVAILABLE's own refusal semantics.
        if(pinCount >= PinLimit)
        {
            return ValueTask.FromResult(new CtapPinAttemptVerdict(IsMatch: false, RetriesRemaining: 0, IsBlocked: true, IsProvisioned: true));
        }

        bool isMatch = provisionedPinHash is not null && candidatePinHash.Span.SequenceEqual(provisionedPinHash);
        pinCount = isMatch ? 0 : pinCount + 1;
        int retriesRemaining = PinLimit - pinCount;

        return ValueTask.FromResult(new CtapPinAttemptVerdict(isMatch, retriesRemaining, retriesRemaining == 0, IsProvisioned: provisionedPinHash is not null));
    }


    /// <summary>
    /// Records a failed attempt whose candidate hash never decrypted, exactly like a recorded mismatch.
    /// Has the <see cref="PenalizeAttemptAsyncDelegate"/> shape.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    private ValueTask<CtapPinAttemptVerdict> PenalizeAttemptAsync(CancellationToken cancellationToken)
    {
        operationLog.Add("Penalize");

        pinCount = Math.Min(pinCount + 1, PinLimit);
        int retriesRemaining = PinLimit - pinCount;

        return ValueTask.FromResult(new CtapPinAttemptVerdict(IsMatch: false, retriesRemaining, retriesRemaining == 0, IsProvisioned: provisionedPinHash is not null));
    }


    /// <summary>Reads the current retry budget without recording an attempt. Has the <see cref="ReadRetriesAsyncDelegate"/> shape.</summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    private ValueTask<CtapPinAttemptVerdict> ReadRetriesAsync(CancellationToken cancellationToken)
    {
        operationLog.Add("Read");
        int retriesRemaining = PinLimit - pinCount;

        return ValueTask.FromResult(new CtapPinAttemptVerdict(IsMatch: false, retriesRemaining, retriesRemaining == 0, IsProvisioned: provisionedPinHash is not null));
    }


    /// <summary>Retires the persistent tier entirely. Has the <see cref="RetirePinAsyncDelegate"/> shape.</summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    private ValueTask RetirePinAsync(CancellationToken cancellationToken)
    {
        operationLog.Add("Retire");
        provisionedPinHash = null;
        pinCount = 0;

        return ValueTask.CompletedTask;
    }
}
