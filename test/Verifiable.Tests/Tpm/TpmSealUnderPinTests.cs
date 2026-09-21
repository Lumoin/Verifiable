using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Nv;
using Verifiable.Tpm.Extensions.Pin;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Extensions.Seal;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Flow coverage for the composed PIN-throttled seal verbs (<c>SealUnderPinAsync</c>, <c>UnsealUnderPinAsync</c>,
/// <c>UnsealUnderPinWithPasswordAsync</c>, <c>SealEnvelopeUnderPinAsync</c>, <c>UnsealEnvelopeUnderPinAsync</c>,
/// <c>UnsealEnvelopeUnderPinWithPasswordAsync</c>) against the in-house behavioural <see cref="TpmSimulator"/> -
/// entirely in-process, with no external assets - through the same production wire path
/// <see cref="TpmSealExtensionsTests"/> and <see cref="TpmPinExtensionsTests"/> exercise separately, now composed.
/// </summary>
/// <remarks>
/// Each verb folds a single <c>TPM2_PolicySecret</c> assertion against a PIN Fail Index as the sealed object's
/// authPolicy (TPM 2.0 Library Part 1, clause 34.2.7: "The nominal use of a PIN Index is to reference the Index
/// in an entity's policy in TPM2_PolicySecret()"), so the guess budget the Index's own <c>pinCount</c>/
/// <c>pinLimit</c> enforces (Part 1, clause 34.2.6.6) becomes the sealed secret's own guess budget, entirely
/// independent of the TPM's global dictionary-attack counter (Part 1, clause 34.2.8.2; Part 2, clause 13.4's
/// mandated <c>TPMA_NV_NO_DA</c>).
/// </remarks>
[TestClass]
internal sealed class TpmSealUnderPinTests
{
    /// <summary>The primary PIN Fail Index handle: its most-significant octet is TPM_HT_NV_INDEX (0x01).</summary>
    private const uint PinIndexHandle = 0x0100_00B1;

    /// <summary>A second PIN Fail Index handle, distinct from <see cref="PinIndexHandle"/>, for the cross-index refusal test.</summary>
    private const uint OtherPinIndexHandle = 0x0100_00B2;

    /// <summary>The stored-PIN-form authorization value used by the positive-path tests.</summary>
    private static byte[] CorrectPin { get; } = "0000"u8.ToArray();

    /// <summary>A wrong stored-PIN-form value, distinct from <see cref="CorrectPin"/>.</summary>
    private static byte[] WrongPin { get; } = "9999"u8.ToArray();

    /// <summary>The stored-PIN-form authorization value for <see cref="OtherPinIndexHandle"/>, distinct from <see cref="CorrectPin"/>.</summary>
    private static byte[] OtherPin { get; } = "1234"u8.ToArray();

    /// <summary>The secret sealed and recovered by the round-trip tests.</summary>
    private static byte[] SecretBytes { get; } = "PIN-throttled secret, sealed under the Index policy."u8.ToArray();

    /// <summary>A payload wider than the widest sealed data object, for the envelope round-trip test.</summary>
    private static byte[] WidePayload { get; } = BuildWidePayload();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A correct PIN recovers the secret and resets <c>pinCount</c> to zero
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.6: "the pinCount field is set to zero if the Index is PIN Fail"</see>).
    /// </summary>
    [TestMethod]
    public async Task SealUnderPinAsyncRoundTripsWithTheCorrectPinAndResetsPinCountToZero()
    {
        const uint PinLimit = 3;
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SealUnderPinAsyncRoundTripsWithTheCorrectPinAndResetsPinCountToZero), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        ReadOnlyMemory<byte> pinIndexName = await DefinePinIndexAsync(tpm, PinIndexHandle, CorrectPin, PinLimit).ConfigureAwait(false);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);

        try
        {
            TpmResult<TpmSealedBlob> sealResult = await tpm.SealUnderPinAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, SecretBytes, PinIndexHandle, pinIndexName,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(sealResult.IsSuccess, $"SealUnderPinAsync failed: '{sealResult.ResponseCode}'.");

            using TpmSealedBlob sealedBlob = sealResult.Value;

            TpmResult<UnsealResponse> unsealResult = await tpm.UnsealUnderPinAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, sealedBlob, PinIndexHandle, CorrectPin, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(unsealResult.IsSuccess, $"UnsealUnderPinAsync failed: '{unsealResult.ResponseCode}'.");

            using UnsealResponse unsealed = unsealResult.Value;
            Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes), "The unsealed data must equal the sealed secret, byte for byte.");

            TpmResult<TpmPinCounterParameters> countersResult = await tpm.ReadPinCountersAsync(
                ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(countersResult.IsSuccess, $"ReadPinCountersAsync failed: '{countersResult.ResponseCode}'.");
            Assert.AreEqual(0u, countersResult.Value.PinCount, "A correct PIN must reset pinCount to zero.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A wrong PIN increments the Index's own <c>pinCount</c> and leaves the TPM's global dictionary-attack
    /// counter untouched
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.8.2: "does not use (and is not affected by) the TPM's global Dictionary Attack defense mechanism"</see>).
    /// The negative control replays the identical wrong-PIN sequence against a sealed object built the OLD way -
    /// <c>SealAsync</c> with the PIN as <c>sealAuth</c> and <c>noDa: false</c> - and captures the GLOBAL counter
    /// genuinely advancing, the behaviour this verb pair replaces.
    /// </summary>
    [TestMethod]
    public async Task UnsealUnderPinAsyncWithAWrongPinIncrementsPinCountAndLeavesTheGlobalCounterUnchanged()
    {
        const uint PinLimit = 3;
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(UnsealUnderPinAsyncWithAWrongPinIncrementsPinCountAndLeavesTheGlobalCounterUnchanged), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        ReadOnlyMemory<byte> pinIndexName = await DefinePinIndexAsync(tpm, PinIndexHandle, CorrectPin, PinLimit).ConfigureAwait(false);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);

        try
        {
            TpmResult<TpmSealedBlob> sealResult = await tpm.SealUnderPinAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, SecretBytes, PinIndexHandle, pinIndexName,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(sealResult.IsSuccess, $"SealUnderPinAsync failed: '{sealResult.ResponseCode}'.");
            using TpmSealedBlob sealedBlob = sealResult.Value;

            TpmResult<TpmDictionaryAttackParameters> beforeDa = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(beforeDa.IsSuccess, $"GetDictionaryAttackParametersAsync failed: '{beforeDa.ResponseCode}'.");

            TpmResult<UnsealResponse> wrongResult = await tpm.UnsealUnderPinAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, sealedBlob, PinIndexHandle, WrongPin, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(wrongResult.IsSuccess, "A wrong PIN must be refused.");

            TpmResult<TpmPinCounterParameters> countersResult = await tpm.ReadPinCountersAsync(
                ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(countersResult.IsSuccess, $"ReadPinCountersAsync failed: '{countersResult.ResponseCode}'.");
            Assert.AreEqual(1u, countersResult.Value.PinCount, "A single wrong PIN must increment pinCount to one.");

            TpmResult<TpmDictionaryAttackParameters> afterDa = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(afterDa.IsSuccess, $"GetDictionaryAttackParametersAsync failed: '{afterDa.ResponseCode}'.");
            Assert.AreEqual(
                beforeDa.Value.LockoutCounter, afterDa.Value.LockoutCounter,
                "The GLOBAL dictionary-attack counter must be UNCHANGED by a wrong PIN against a PIN-Index-policy-gated object.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The negative control for <see cref="UnsealUnderPinAsyncWithAWrongPinIncrementsPinCountAndLeavesTheGlobalCounterUnchanged"/>:
    /// the shape the consumer's original code used - a plain <c>SealAsync</c> with the PIN as <c>sealAuth</c> and
    /// <c>noDa: false</c> (global-DA-protected) - genuinely advances the TPM's GLOBAL dictionary-attack counter
    /// on a wrong PIN, captured here as the behaviour <c>SealUnderPinAsync</c>/<c>UnsealUnderPinAsync</c> replace.
    /// Kept as its own test (not appended to the composed verbs' test) so it runs and reports independently of
    /// whatever the composed verbs' own outcome is.
    /// </summary>
    [TestMethod]
    public async Task NegativeControlPlainSealAsyncWithThePinAsSealAuthAdvancesTheGlobalCounterOnAWrongPin()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(NegativeControlPlainSealAsyncWithThePinAsSealAuthAdvancesTheGlobalCounterOnAWrongPin), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);

        try
        {
            TpmResult<TpmSealedBlob> sealResult = await tpm.SealAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, SecretBytes, CorrectPin, noDa: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(sealResult.IsSuccess, $"The negative control's SealAsync failed: '{sealResult.ResponseCode}'.");
            using TpmSealedBlob sealedBlob = sealResult.Value;

            TpmResult<TpmDictionaryAttackParameters> beforeDa = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(beforeDa.IsSuccess, $"GetDictionaryAttackParametersAsync failed: '{beforeDa.ResponseCode}'.");

            TpmResult<UnsealResponse> wrongResult = await tpm.UnsealAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, sealedBlob, WrongPin, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(wrongResult.IsSuccess, "The negative control's wrong sealAuth must be refused.");

            TpmResult<TpmDictionaryAttackParameters> afterDa = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(afterDa.IsSuccess, $"GetDictionaryAttackParametersAsync failed: '{afterDa.ResponseCode}'.");
            Assert.IsGreaterThan(
                beforeDa.Value.LockoutCounter, afterDa.Value.LockoutCounter,
                $"The negative control (plain SealAsync, noDa: false) must advance the GLOBAL counter on a wrong password: before={beforeDa.Value.LockoutCounter}, after={afterDa.Value.LockoutCounter}.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Three wrong PINs reach <c>pinLimit</c>, and even the correct PIN is then refused
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.6: "the authorization will fail if the pinCount field of the Index is not less than the pinLimit field"</see>);
    /// <c>ResetPinCountAsync</c> restores access.
    /// </summary>
    [TestMethod]
    public async Task UnsealUnderPinAsyncAtPinLimitRefusesEvenTheCorrectPinAndResetPinCountRestoresAccess()
    {
        const uint PinLimit = 3;
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(UnsealUnderPinAsyncAtPinLimitRefusesEvenTheCorrectPinAndResetPinCountRestoresAccess), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        ReadOnlyMemory<byte> pinIndexName = await DefinePinIndexAsync(tpm, PinIndexHandle, CorrectPin, PinLimit).ConfigureAwait(false);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);

        try
        {
            TpmResult<TpmSealedBlob> sealResult = await tpm.SealUnderPinAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, SecretBytes, PinIndexHandle, pinIndexName,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(sealResult.IsSuccess, $"SealUnderPinAsync failed: '{sealResult.ResponseCode}'.");
            using TpmSealedBlob sealedBlob = sealResult.Value;

            for(uint attempt = 1; attempt <= PinLimit; attempt++)
            {
                TpmResult<UnsealResponse> wrongResult = await tpm.UnsealUnderPinAsync(
                    parentHandle, ReadOnlyMemory<byte>.Empty, sealedBlob, PinIndexHandle, WrongPin, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(wrongResult.IsSuccess, $"Wrong-PIN attempt {attempt} of {PinLimit} must be refused.");
            }

            TpmResult<UnsealResponse> atLimitResult = await tpm.UnsealUnderPinAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, sealedBlob, PinIndexHandle, CorrectPin, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(atLimitResult.IsSuccess, "Once pinCount reaches pinLimit, even the CORRECT PIN must be refused.");

            TpmResult<NvWriteResponse> resetResult = await tpm.ResetPinCountAsync(
                ReadOnlyMemory<byte>.Empty, PinIndexHandle, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(resetResult.IsSuccess, $"ResetPinCountAsync failed: '{resetResult.ResponseCode}'.");

            TpmResult<UnsealResponse> recoveredResult = await tpm.UnsealUnderPinAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, sealedBlob, PinIndexHandle, CorrectPin, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(recoveredResult.IsSuccess, $"The correct PIN must succeed again once reset: '{recoveredResult.ResponseCode}'.");
            recoveredResult.Value.Dispose();
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A sealed object created under a DIFFERENT PIN Index's policy is refused under this Index's session: the
    /// policy digest binds the authorizing Index's own Name
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.4: "policySession->policyDigest is updated by PolicyUpdate(TPM_CC_PolicySecret, authEntity->Name, policyRef)"</see>),
    /// so proving the OTHER Index's own (correct, for that Index) PIN folds the wrong Name and never matches.
    /// </summary>
    [TestMethod]
    public async Task UnsealUnderPinAsyncRefusesASealedObjectBoundToADifferentPinIndex()
    {
        const uint PinLimit = 3;
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(UnsealUnderPinAsyncRefusesASealedObjectBoundToADifferentPinIndex), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        ReadOnlyMemory<byte> pinIndexName = await DefinePinIndexAsync(tpm, PinIndexHandle, CorrectPin, PinLimit).ConfigureAwait(false);
        _ = await DefinePinIndexAsync(tpm, OtherPinIndexHandle, OtherPin, PinLimit).ConfigureAwait(false);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);

        try
        {
            TpmResult<TpmSealedBlob> sealResult = await tpm.SealUnderPinAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, SecretBytes, PinIndexHandle, pinIndexName,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(sealResult.IsSuccess, $"SealUnderPinAsync failed: '{sealResult.ResponseCode}'.");
            using TpmSealedBlob sealedBlob = sealResult.Value;

            //Proving OtherPinIndexHandle's own (correct, for that Index) PIN succeeds PolicySecret, but folds
            //OtherPinIndexHandle's Name, not PinIndexHandle's - the digest mismatch surfaces as UnsealUnderPolicyAsync's own policy-mismatch refusal.
            TpmResult<UnsealResponse> crossIndexResult = await tpm.UnsealUnderPinAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, sealedBlob, OtherPinIndexHandle, OtherPin, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(crossIndexResult.IsSuccess, "A sealed object bound to one PIN Index's policy must be refused under a different Index's satisfied session.");

            TpmResult<UnsealResponse> correctIndexResult = await tpm.UnsealUnderPinAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, sealedBlob, PinIndexHandle, CorrectPin, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(correctIndexResult.IsSuccess, $"The ORIGINAL Index's own correct PIN must still succeed: '{correctIndexResult.ResponseCode}'.");
            correctIndexResult.Value.Dispose();
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The envelope pair lifts the same guess budget to a payload wider than <see cref="Tpm2bSensitiveData.MaxSize"/>:
    /// a wrong PIN refuses the open and increments <c>pinCount</c> to one, and the correct PIN then round-trips
    /// the payload byte for byte and resets <c>pinCount</c> to zero.
    /// </summary>
    [TestMethod]
    public async Task SealEnvelopeUnderPinAsyncRoundTripsAWidePayloadAndAWrongPinIncrementsPinCount()
    {
        const uint PinLimit = 3;
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SealEnvelopeUnderPinAsyncRoundTripsAWidePayloadAndAWrongPinIncrementsPinCount), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        ReadOnlyMemory<byte> pinIndexName = await DefinePinIndexAsync(tpm, PinIndexHandle, CorrectPin, PinLimit).ConfigureAwait(false);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);

        try
        {
            TpmResult<TpmSealedEnvelope> sealResult = await tpm.SealEnvelopeUnderPinAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, WidePayload, PinIndexHandle, pinIndexName,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(sealResult.IsSuccess, $"SealEnvelopeUnderPinAsync failed: '{sealResult.ResponseCode}'.");
            using TpmSealedEnvelope envelope = sealResult.Value;

            TpmResult<DecryptedContent> wrongResult = await tpm.UnsealEnvelopeUnderPinAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, envelope, PinIndexHandle, WrongPin, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(wrongResult.IsSuccess, "A wrong PIN must refuse the envelope open.");

            TpmResult<TpmPinCounterParameters> countersResult = await tpm.ReadPinCountersAsync(
                ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(countersResult.IsSuccess, $"ReadPinCountersAsync failed: '{countersResult.ResponseCode}'.");
            Assert.AreEqual(1u, countersResult.Value.PinCount, "A wrong PIN against the envelope's content key policy must increment pinCount to one.");

            TpmResult<DecryptedContent> correctResult = await tpm.UnsealEnvelopeUnderPinAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, envelope, PinIndexHandle, CorrectPin, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(correctResult.IsSuccess, $"UnsealEnvelopeUnderPinAsync failed: '{correctResult.ResponseCode}'.");
            using DecryptedContent plaintext = correctResult.Value;
            Assert.IsTrue(plaintext.AsReadOnlySpan().SequenceEqual(WidePayload), "The wide payload must round-trip byte for byte.");

            TpmResult<TpmPinCounterParameters> resetCountersResult = await tpm.ReadPinCountersAsync(
                ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(resetCountersResult.IsSuccess, $"ReadPinCountersAsync failed: '{resetCountersResult.ResponseCode}'.");
            Assert.AreEqual(0u, resetCountersResult.Value.PinCount, "The correct PIN must reset pinCount to zero.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The low <c>…WithPasswordAsync</c> variants pass the same round trip as their bound-HMAC defaults, for
    /// both the plain seal pair and the envelope pair - the explicit low-protection opt-out authorizes
    /// identically, only the channel differs.
    /// </summary>
    [TestMethod]
    public async Task WithPasswordVariantsRoundTripBothThePlainAndEnvelopePairs()
    {
        const uint PinLimit = 3;
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(WithPasswordVariantsRoundTripBothThePlainAndEnvelopePairs), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        ReadOnlyMemory<byte> pinIndexName = await DefinePinIndexAsync(tpm, PinIndexHandle, CorrectPin, PinLimit).ConfigureAwait(false);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);

        try
        {
            TpmResult<TpmSealedBlob> sealResult = await tpm.SealUnderPinAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, SecretBytes, PinIndexHandle, pinIndexName,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(sealResult.IsSuccess, $"SealUnderPinAsync failed: '{sealResult.ResponseCode}'.");
            using TpmSealedBlob sealedBlob = sealResult.Value;

            TpmResult<UnsealResponse> unsealResult = await tpm.UnsealUnderPinWithPasswordAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, sealedBlob, PinIndexHandle, CorrectPin, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(unsealResult.IsSuccess, $"UnsealUnderPinWithPasswordAsync failed: '{unsealResult.ResponseCode}'.");
            using UnsealResponse unsealed = unsealResult.Value;
            Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes), "The password-arm unseal must recover the secret byte for byte.");

            TpmResult<TpmSealedEnvelope> sealEnvelopeResult = await tpm.SealEnvelopeUnderPinAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, WidePayload, PinIndexHandle, pinIndexName,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(sealEnvelopeResult.IsSuccess, $"SealEnvelopeUnderPinAsync failed: '{sealEnvelopeResult.ResponseCode}'.");
            using TpmSealedEnvelope envelope = sealEnvelopeResult.Value;

            TpmResult<DecryptedContent> unsealEnvelopeResult = await tpm.UnsealEnvelopeUnderPinWithPasswordAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, envelope, PinIndexHandle, CorrectPin, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(unsealEnvelopeResult.IsSuccess, $"UnsealEnvelopeUnderPinWithPasswordAsync failed: '{unsealEnvelopeResult.ResponseCode}'.");
            using DecryptedContent envelopePlaintext = unsealEnvelopeResult.Value;
            Assert.IsTrue(envelopePlaintext.AsReadOnlySpan().SequenceEqual(WidePayload), "The password-arm envelope open must recover the wide payload byte for byte.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Builds a payload eight times wider than <see cref="Tpm2bSensitiveData.MaxSize"/> (a round 4 KiB), for the envelope tests.</summary>
    /// <returns>The payload bytes.</returns>
    private static byte[] BuildWidePayload()
    {
        var payload = new byte[4096];
        for(int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)(i % 251);
        }

        return payload;
    }

    /// <summary>
    /// Defines a PIN Fail Index at <paramref name="pinIndexHandle"/> with <paramref name="pinHash"/> and
    /// <paramref name="pinLimit"/>, and returns its current Name (from <c>NV_ReadPublic</c>) for a caller to seal
    /// a policy against.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="pinIndexHandle">The NV Index handle to define.</param>
    /// <param name="pinHash">The stored PIN form to install as the Index's authValue.</param>
    /// <param name="pinLimit">The attempt threshold to provision.</param>
    /// <returns>The Index's Name.</returns>
    private async Task<ReadOnlyMemory<byte>> DefinePinIndexAsync(TpmDevice tpm, uint pinIndexHandle, ReadOnlyMemory<byte> pinHash, uint pinLimit)
    {
        TpmResult<NvWriteResponse> defineResult = await tpm.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, pinIndexHandle, pinHash, pinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");

        TpmResult<NvReadPublicResponse> readPublicResult = await tpm.NvReadPublicAsync(pinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(readPublicResult.IsSuccess, $"NvReadPublicAsync failed: '{readPublicResult.ResponseCode}'.");
        using NvReadPublicResponse readPublic = readPublicResult.Value;

        return readPublic.NvName.Span.ToArray();
    }

    /// <summary>Creates the deterministic ECC storage parent under the owner hierarchy; the caller owns and flushes the handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The storage parent's object handle.</returns>
    private async Task<uint> CreateStorageParentAsync(TpmDevice tpm, BaseMemoryPool pool)
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        return parent.ObjectHandle.Value;
    }
}
