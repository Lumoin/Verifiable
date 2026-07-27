using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Extensions.Seal;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Flow coverage for the <c>Extensions/Seal</c> business-capability verbs (<see cref="TpmDeviceExtensions.SealAsync"/>,
/// <see cref="TpmDeviceExtensions.UnsealAsync"/>, <see cref="TpmDeviceExtensions.UnsealUnderPolicyAsync"/>) against
/// the in-house behavioural <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the
/// same production wire path <see cref="TpmInHouseSimulatorSealTests"/> and <see cref="TpmInHouseSimulatorPcrSealTests"/>
/// exercise directly with <see cref="CreateInput"/>/<see cref="LoadInput"/>/<see cref="UnsealInput"/>, except every
/// seal and unseal step here goes exclusively through the verbs under test.
/// </summary>
/// <remarks>
/// <para>
/// A simulator gap this package surfaced was fixed in the same wave: <c>TpmLifecycleTransitions.OnFlushContext</c>
/// checked <c>PolicySessions</c>, <c>HmacSessions</c>, and <c>TransientObjects</c> for the flushed handle but never
/// <c>LoadedSealedObjects</c> — the dictionary a loaded sealed KEYEDHASH object actually lives in
/// (<c>OnObjectLoaded</c>) — so <c>TPM2_FlushContext</c> against a loaded sealed object's handle always rejected
/// with <c>TPM_RC_HANDLE</c> (every pre-existing seal flow test discarded the flush's result, masking it).
/// <c>OnFlushContext</c> now removes the sealed-object entry;
/// <see cref="FlushContextReleasesALoadedSealedObjectHandle"/> is the regression proof, and
/// <see cref="RepeatedSealUnsealCyclesThroughTheVerbsSucceedWithNoAccumulatingFailure"/> remains the verb-level
/// bracket proof. The verbs never propagate the flush's own outcome into the returned Unseal result (Part 3,
/// clause 28.4's "always attempted" contract, not "always succeeds").
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmSealExtensionsTests
{
    /// <summary>The session/policy/name hash algorithm the Seal verbs fix internally, and this suite mirrors for its own policy sessions.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The PCR bank the policy-gated arm selects from.</summary>
    private const TpmAlgIdConstants PcrBank = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// The PCR(s) the policy-gated arm binds to. PCR 23 is the application/debug register, reset to the
    /// all-zero image (TPM 2.0 Library Part 1, clause 17.5.3), keeping the test off the boot-measured registers.
    /// </summary>
    private static int[] PcrIndices { get; } = [23];

    /// <summary>The secret sealed and recovered by the round-trip and policy-gated tests.</summary>
    private static byte[] SecretBytes { get; } = "Persist this secret across a disk round trip through the Seal verbs."u8.ToArray();

    /// <summary>The sealAuth used by the wrong-password and round-trip tests.</summary>
    private static byte[] SealAuthBytes { get; } = "correct-horse-battery-staple"u8.ToArray();

    /// <summary>A deliberately wrong sealAuth, distinct from <see cref="SealAuthBytes"/>.</summary>
    private static byte[] WrongSealAuthBytes { get; } = "wrong-horse-battery-staple"u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Seal-unseal round trip through the verbs only: <c>SealAsync</c> produces a blob, its bytes are copied out
    /// and reparsed into an independent <see cref="TpmSealedBlob"/> (the disk round trip a caller performs
    /// between sessions), and <c>UnsealAsync</c> recovers the secret byte-exact from that reparsed instance
    /// alone — the original blob is disposed before the reparsed one is ever used, so nothing is shared beyond
    /// the copied bytes.
    /// </summary>
    [TestMethod]
    public async Task SealUnsealRoundTripsThroughTheVerbsAcrossADiskByteRoundTrip()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        try
        {
            TpmResult<TpmSealedBlob> sealResult = await tpm.SealAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, SecretBytes, SealAuthBytes,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(sealResult.IsSuccess, $"SealAsync failed: '{sealResult.ResponseCode}'.");

            byte[] persisted;
            using(TpmSealedBlob sealedBlob = sealResult.Value)
            {
                persisted = CopyToBytes(sealedBlob, pool);
            }

            //Simulate the disk round trip: the original blob is gone; only the copied bytes remain.
            var reader = new TpmReader(persisted);
            using TpmSealedBlob rehydrated = TpmSealedBlob.Parse(ref reader, pool);

            TpmResult<UnsealResponse> unsealResult = await tpm.UnsealAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, rehydrated, SealAuthBytes,
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(unsealResult.IsSuccess, $"UnsealAsync failed: '{unsealResult.ResponseCode}'.");

            using UnsealResponse unsealed = unsealResult.Value;
            Assert.IsTrue(
                unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes),
                "The unsealed data must equal the sealed secret, byte for byte, recovered through the verbs alone.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A wrong sealAuth against a dictionary-attack-PROTECTED sealed object (this suite's <c>noDa: false</c>
    /// default) must fail with the session-encoded <c>TPM_RC_AUTH_FAIL</c> the simulator's
    /// <c>RejectSessionAuthFailure</c> returns for a DA-protected mismatch (as opposed to <c>TPM_RC_BAD_AUTH</c>,
    /// which a <c>noDa: true</c> object would return instead) — and the follow-up <c>UnsealAsync</c> call with
    /// the CORRECT sealAuth against the very same <see cref="TpmSealedBlob"/> must still succeed, showing the
    /// failed attempt's Load/Unseal/FlushContext bracket left nothing behind that blocks a subsequent legitimate
    /// cycle (the practical, wire-observable form of "no transient-slot leak" available on this simulator; see
    /// the type-level remarks for why a stronger, capacity-based proof is not available here).
    /// </summary>
    [TestMethod]
    public async Task UnsealAsyncWithWrongSealAuthReturnsSessionEncodedAuthFailAndStillAdmitsAFollowUpUnseal()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        try
        {
            using TpmSealedBlob sealedBlob = (await tpm.SealAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, SecretBytes, SealAuthBytes,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false)).Value;

            TpmResult<UnsealResponse> wrongResult = await tpm.UnsealAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, sealedBlob, WrongSealAuthBytes,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(wrongResult.IsSuccess, "A wrong sealAuth must not unseal the secret.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, StripSessionModifier(wrongResult.ResponseCode),
                $"A DA-protected sealed object's wrong-sealAuth Unseal must surface as session-encoded TPM_RC_AUTH_FAIL " +
                $"(got '{wrongResult.ResponseCode}').");

            TpmResult<UnsealResponse> correctResult = await tpm.UnsealAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, sealedBlob, SealAuthBytes,
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(correctResult.IsSuccess,
                $"A follow-up Unseal with the correct sealAuth must still succeed after a failed attempt: '{correctResult.ResponseCode}'.");

            using UnsealResponse unsealed = correctResult.Value;
            Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes),
                "The follow-up Unseal must recover the same secret, byte for byte.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Policy-gated arm, satisfied case: <c>SealAsync</c> seals under a live <c>TPM2_PolicyPCR</c> digest (bound
    /// to PCR 23, computed exactly as <see cref="TpmInHouseSimulatorPcrSealTests"/> does) and
    /// <c>UnsealUnderPolicyAsync</c>, authorized by that same satisfied policy session, recovers the secret
    /// byte-exact. <c>userWithAuth</c> is left at <see cref="Tpm2bPublic.CreateSealedDataTemplate"/>'s own
    /// default (SET) — this suite does not widen <c>SealAsync</c>'s surface with a <c>userWithAuth</c> knob, per
    /// the wave contract's "closest sound alternative, do not widen the surface" instruction.
    /// </summary>
    [TestMethod]
    public async Task PolicyGatedSealUnsealsUnderASatisfiedPolicySessionViaTheVerbs()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint policyHandle = 0;

        try
        {
            (byte[] authPolicy, policyHandle) = await ComputeLivePcrPolicyDigestAsync(tpm).ConfigureAwait(false);

            using TpmSealedBlob sealedBlob = (await tpm.SealAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, SecretBytes, ReadOnlyMemory<byte>.Empty,
                authPolicy, noDa: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false)).Value;

            TpmResult<UnsealResponse> unsealResult = await tpm.UnsealUnderPolicyAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, sealedBlob, policyHandle,
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(unsealResult.IsSuccess,
                $"Policy-gated unseal under a satisfied policy session failed: '{unsealResult.ResponseCode}'.");

            using UnsealResponse unsealed = unsealResult.Value;
            Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes),
                "The unsealed data must equal the sealed secret, byte for byte.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Policy-gated arm, unsatisfied case: the object is sealed under a WRONG PCR digest (computed in a trial
    /// session, which folds the caller's digest verbatim, Part 3 clause 23.7), then <c>UnsealUnderPolicyAsync</c>
    /// is authorized by a REAL policy session bound to the live PCR state — whose digest does not match the
    /// sealed authPolicy — and must reject with <c>TPM_RC_POLICY_FAIL</c>, mirroring
    /// <see cref="TpmInHouseSimulatorPcrSealTests.PcrGatedSealRejectsUnsealWhenPolicyUnsatisfied"/>.
    /// </summary>
    [TestMethod]
    public async Task UnsealUnderPolicyAsyncRejectsAMismatchedPolicyDigestWithPolicyFail()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint trialHandle = 0;
        uint policyHandle = 0;

        try
        {
            //1. Compute a WRONG PCR policy digest in a trial session (an arbitrary, fabricated digest the live
            //PCRs will not reproduce).
            byte[] wrongPcrDigest = new byte[32];
            Array.Fill(wrongPcrDigest, (byte)0xAB);

            TpmResult<StartAuthSessionResponse> trialStartResult = await tpm.StartTrialPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(trialStartResult.IsSuccess, $"StartAuthSession (trial) failed: '{trialStartResult.ResponseCode}'.");

            using(StartAuthSessionResponse trialStart = trialStartResult.Value)
            {
                trialHandle = trialStart.SessionHandle.Value;
            }

            TpmResult<PolicyPcrResponse> trialPcrResult = await tpm.PolicyPcrAsync(
                trialHandle, PcrBank, PcrIndices, wrongPcrDigest, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(trialPcrResult.IsSuccess, $"Trial PolicyPCR failed: '{trialPcrResult.ResponseCode}'.");

            byte[] wrongAuthPolicy;
            TpmResult<PolicyGetDigestResponse> trialDigestResult = await tpm.PolicyGetDigestAsync(
                trialHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(trialDigestResult.IsSuccess, $"Trial PolicyGetDigest failed: '{trialDigestResult.ResponseCode}'.");
            using(PolicyGetDigestResponse trialDigestResponse = trialDigestResult.Value)
            {
                wrongAuthPolicy = trialDigestResponse.PolicyDigest.AsReadOnlySpan().ToArray();
            }

            _ = await tpm.FlushContextAsync(trialHandle, TestContext.CancellationToken).ConfigureAwait(false);
            trialHandle = 0;

            //2. Seal under the WRONG policy, through the verb.
            using TpmSealedBlob sealedBlob = (await tpm.SealAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, SecretBytes, ReadOnlyMemory<byte>.Empty,
                wrongAuthPolicy, noDa: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false)).Value;

            //3. Authorize the unseal with a REAL policy session bound to the LIVE PCRs — a different digest.
            (byte[] authPolicy, policyHandle) = await ComputeLivePcrPolicyDigestAsync(tpm).ConfigureAwait(false);
            Assert.IsFalse(authPolicy.AsSpan().SequenceEqual(wrongAuthPolicy),
                "The live-PCR digest and the fabricated sealed digest must differ for this negative test to be meaningful.");

            TpmResult<UnsealResponse> unsealResult = await tpm.UnsealUnderPolicyAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, sealedBlob, policyHandle,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(unsealResult.IsSuccess,
                "Unseal must be rejected when the policy session's live-PCR digest does not match the sealed authPolicy.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, StripSessionModifier(unsealResult.ResponseCode),
                $"A policy-digest mismatch must surface as TPM_RC_POLICY_FAIL (got '{unsealResult.ResponseCode}').");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await tpm.FlushContextAsync(trialHandle, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// FlushContext-bracket proof, in the form available on this simulator (see the type-level remarks): five
    /// consecutive Seal/Unseal cycles through the verbs, under the SAME storage parent, each with a distinct
    /// secret and sealAuth, all succeed with byte-exact recovery. A leaked handle, an exhausted resource, or a
    /// broken parent session left over from a prior cycle's Load/Unseal/FlushContext bracket would surface as a
    /// failure partway through this loop; none does.
    /// </summary>
    [TestMethod]
    public async Task RepeatedSealUnsealCyclesThroughTheVerbsSucceedWithNoAccumulatingFailure()
    {
        const int cycles = 5;

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        try
        {
            for(int cycle = 0; cycle < cycles; cycle++)
            {
                byte[] secret = BuildCycleSecret(cycle);
                byte[] sealAuth = BuildCycleSealAuth(cycle);

                TpmResult<TpmSealedBlob> sealResult = await tpm.SealAsync(
                    parentHandle, ReadOnlyMemory<byte>.Empty, secret, sealAuth,
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(sealResult.IsSuccess, $"Cycle {cycle}: SealAsync failed: '{sealResult.ResponseCode}'.");

                using TpmSealedBlob sealedBlob = sealResult.Value;

                TpmResult<UnsealResponse> unsealResult = await tpm.UnsealAsync(
                    parentHandle, ReadOnlyMemory<byte>.Empty, sealedBlob, sealAuth,
                    TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(unsealResult.IsSuccess, $"Cycle {cycle}: UnsealAsync failed: '{unsealResult.ResponseCode}'.");

                using UnsealResponse unsealed = unsealResult.Value;
                Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(secret),
                    $"Cycle {cycle}: recovered secret must match byte for byte.");
            }
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Regression proof for the <c>OnFlushContext</c> sealed-object arm (TPM 2.0 Library Part 3, clause 28.4):
    /// a sealed object loaded with <c>TPM2_Load</c> is flushable — the first <c>TPM2_FlushContext</c> against its
    /// handle succeeds (pre-fix it rejected with <c>TPM_RC_HANDLE</c>, because the transition never consulted the
    /// <c>LoadedSealedObjects</c> table), and a second flush of the same handle rejects with <c>TPM_RC_HANDLE</c>,
    /// proving the entry was actually removed rather than merely acknowledged.
    /// </summary>
    [TestMethod]
    public async Task FlushContextReleasesALoadedSealedObjectHandle()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        try
        {
            TpmResult<TpmSealedBlob> sealResult = await tpm.SealAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, SecretBytes, SealAuthBytes,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(sealResult.IsSuccess, $"SealAsync failed: '{sealResult.ResponseCode}'.");

            //The blob stays alive past the Load below: LoadInput borrows the blob-owned carriers for the wire
            //write and never assumes ownership (the same borrow discipline the raw seal flow tests use).
            using TpmSealedBlob sealedBlob = sealResult.Value;
            using LoadInput loadInput = new(parentHandle, sealedBlob.OutPrivate, sealedBlob.OutPublic);
            using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
                tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");

            uint itemHandle;
            using(LoadResponse loaded = loadResult.Value)
            {
                itemHandle = loaded.ObjectHandle.Value;
            }

            TpmResult<FlushContextResponse> firstFlush = await tpm.FlushContextAsync(
                itemHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                firstFlush.IsSuccess,
                $"FlushContext of a loaded sealed object must succeed, got '{firstFlush.ResponseCode}' (the pre-fix transition answered TPM_RC_HANDLE).");

            TpmResult<FlushContextResponse> secondFlush = await tpm.FlushContextAsync(
                itemHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(secondFlush.IsSuccess, "A second flush of the same handle must reject — the entry must actually be gone.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_HANDLE,
                secondFlush.ResponseCode,
                "The already-flushed handle must reject with TPM_RC_HANDLE (Part 3, clause 28.4).");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Builds a distinct secret for cycle <paramref name="cycle"/> of the repeated-cycle proof.</summary>
    /// <param name="cycle">The zero-based cycle index.</param>
    /// <returns>The secret bytes.</returns>
    private static byte[] BuildCycleSecret(int cycle)
    {
        byte[] secret = (byte[])SecretBytes.Clone();
        secret[0] = (byte)(secret[0] + cycle);

        return secret;
    }

    /// <summary>Builds a distinct sealAuth for cycle <paramref name="cycle"/> of the repeated-cycle proof.</summary>
    /// <param name="cycle">The zero-based cycle index.</param>
    /// <returns>The sealAuth bytes.</returns>
    private static byte[] BuildCycleSealAuth(int cycle)
    {
        byte[] sealAuth = (byte[])SealAuthBytes.Clone();
        sealAuth[0] = (byte)(sealAuth[0] + cycle);

        return sealAuth;
    }

    /// <summary>
    /// Strips the format-one session-index modifier bits (<c>TPM_RC_P</c>/<c>TPM_RC_S</c>/<c>TPM_RC_N_MASK</c>)
    /// from a response code, the same normalization <see cref="TpmInHouseSimulatorPcrSealTests"/> applies before
    /// comparing a session-encoded rejection to its base <see cref="TpmRcConstants"/> value (TPM 2.0 Library
    /// Part 2, Section 6.6.3).
    /// </summary>
    /// <param name="responseCode">The raw response code.</param>
    /// <returns>The base error code.</returns>
    private static TpmRcConstants StripSessionModifier(TpmRcConstants responseCode)
    {
        const uint FormatOneModifierMask = (uint)(TpmRcConstants.TPM_RC_P | TpmRcConstants.TPM_RC_S | TpmRcConstants.TPM_RC_N_MASK);

        return (TpmRcConstants)((uint)responseCode & ~FormatOneModifierMask);
    }

    /// <summary>
    /// Starts a real (non-trial) policy session, binds it to the live PCR 23 composite, and returns its
    /// policyDigest — the digest a sealed object's authPolicy must equal for this same session to later
    /// authorize an <c>UnsealUnderPolicyAsync</c> call.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <returns>
    /// The live-PCR policyDigest together with the started session's handle, so the caller can flush it later.
    /// An async method cannot declare an <see langword="out"/> parameter, hence the tuple return.
    /// </returns>
    private async Task<(byte[] Digest, uint PolicyHandle)> ComputeLivePcrPolicyDigestAsync(TpmDevice tpm)
    {
        TpmResult<StartAuthSessionResponse> policyStartResult = await tpm.StartPolicySessionAsync(
            SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");

        uint handle;
        using(StartAuthSessionResponse policyStart = policyStartResult.Value)
        {
            handle = policyStart.SessionHandle.Value;
        }

        //On a real (non-trial) session the TPM binds the policy to the LIVE PCR composite (Part 3, clause 23.7),
        //so no caller pcrDigest is supplied.
        TpmResult<PolicyPcrResponse> pcrResult = await tpm.PolicyPcrAsync(
            handle, PcrBank, PcrIndices, default, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(pcrResult.IsSuccess, $"PolicyPCR failed: '{pcrResult.ResponseCode}'.");

        TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
            handle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

        byte[] digest;
        using(PolicyGetDigestResponse digestResponse = digestResult.Value)
        {
            digest = digestResponse.PolicyDigest.AsReadOnlySpan().ToArray();
        }

        Assert.IsNotEmpty(digest, "The PCR policy digest must be non-empty.");

        return (digest, handle);
    }

    /// <summary>
    /// Copies a sealed blob's wire form into a plain, independently-owned byte array — the "write to disk" half
    /// of the persist-then-reload round trip <see cref="TpmSealedBlob.Parse"/> reverses.
    /// </summary>
    /// <param name="sealedBlob">The sealed blob to serialize.</param>
    /// <param name="pool">The memory pool for the staging buffer.</param>
    /// <returns>The serialized bytes.</returns>
    private static byte[] CopyToBytes(TpmSealedBlob sealedBlob, MemoryPool<byte> pool)
    {
        int size = sealedBlob.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        sealedBlob.WriteTo(ref writer);

        return owner.Memory.Span[..size].ToArray();
    }

    /// <summary>
    /// Creates the deterministic ECC storage parent under the owner hierarchy and returns the response (the
    /// caller owns it and flushes <see cref="CreatePrimaryResponse.ObjectHandle"/>).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response for the storage parent.</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, MemoryPool<byte> pool)
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);

        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");

        return parentResult.Value;
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase. The ECC backend is required so the simulator services
    /// <c>TPM2_CreatePrimary()</c>; the storage parent is used only as a handle to parent the sealed objects here.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-seal-verbs", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, MemoryPool<byte> pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }
}
