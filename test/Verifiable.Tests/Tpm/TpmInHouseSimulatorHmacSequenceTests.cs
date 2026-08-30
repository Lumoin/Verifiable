using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Acceptance tests for the HMAC sequence: <c>TPM2_HMAC_Start()</c> (TPM 2.0 Library Part 3, clause 17.2) opening
/// a sequence bound to a loaded KEYEDHASH HMAC key, fed by <c>TPM2_SequenceUpdate()</c>, and closed by the HMAC
/// arm of <c>TPM2_SequenceComplete()</c> (clause 17.8, Table 94). The positive cases reproduce RFC 4231 test case
/// 3, whose published HMAC is the oracle, and assert the NULL <c>TPMT_TK_HASHCHECK</c> the HMAC arm returns. The
/// refusal cases cover <c>TPM2_HMAC_Start()</c>'s key-shape ladder, its USER-role authorization ladder, the
/// sequence's own authorization value, the completing commands that must refuse an HMAC sequence, the object-slot
/// cap, and the single-password-session wire form.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorHmacSequenceTests
{
    /// <summary>The MSTest-provided per-test context, its cancellation token observed across every exchange.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The lowered <c>maxTries</c> the lockout case uses to reach Lockout mode quickly.</summary>
    private const uint LockoutTestMaxTries = 2;

    /// <summary>RFC 4231 test case 3 key: 20 octets of 0xaa.</summary>
    private static readonly byte[] Rfc4231Case3Key = Convert.FromHexString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    /// <summary>RFC 4231 test case 3 data: 50 octets of 0xdd.</summary>
    private static readonly byte[] Rfc4231Case3Data = Convert.FromHexString("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");

    /// <summary>RFC 4231 test case 3 published HMAC-SHA-256.</summary>
    private static readonly byte[] Rfc4231Case3Sha256 = Convert.FromHexString("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    /// <summary>A key authorization value the authorization-ladder cases install.</summary>
    private static readonly byte[] KeyPassword = "hmac-start-key-auth"u8.ToArray();

    /// <summary>A value that is not the key's authorization value.</summary>
    private static readonly byte[] WrongKeyPassword = "hmac-start-key-wrong"u8.ToArray();

    /// <summary>A sequence authorization value the sequence-auth cases install (Table 80's <c>auth</c>).</summary>
    private static readonly byte[] SequencePassword = "hmac-sequence-auth"u8.ToArray();

    /// <summary>A value that is not the sequence's authorization value.</summary>
    private static readonly byte[] WrongSequencePassword = "hmac-sequence-wrong"u8.ToArray();

    /// <summary>A short secret sealed by the sealed-data fixture in <see cref="HmacStartOverASealedDataObjectIsRefusedWithKey"/>, arbitrary and not tied to any published vector.</summary>
    private static readonly byte[] SealedSecretBytes = [1, 2, 3, 4];

    /// <summary>
    /// A single-buffer HMAC sequence (<c>TPM2_HMAC_Start()</c> then <c>TPM2_SequenceComplete()</c> with the whole
    /// message) returns the published HMAC-SHA-256 for RFC 4231 test case 3 and a NULL ticket (Table 94: "This is
    /// a NULL Ticket when the sequence is HMAC").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 17.2 and 17.8, Table 94</see>;
    /// <see href="https://www.rfc-editor.org/rfc/rfc4231#section-4.4">RFC 4231, section 4.4</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacSequenceOverCase3InOneBufferReturnsThePublishedValueAndANullTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacSequenceOverCase3InOneBufferReturnsThePublishedValueAndANullTicket), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequence = await StartHmacSequenceAsync(tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        TpmResult<SequenceCompleteResponse> completeResult = await CompleteAsync(tpm, registry, pool, sequence, Rfc4231Case3Data).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() (HMAC) failed: '{completeResult.ResponseCode}'.");
        using SequenceCompleteResponse completed = completeResult.Value;

        bool matches = completed.Result.AsReadOnlySpan().SequenceEqual(Rfc4231Case3Sha256);
        Assert.IsTrue(matches, "The HMAC sequence result must equal the published RFC 4231 test case 3 value.");
        Assert.IsTrue(completed.Validation.IsNull, "The HMAC sequence must return a NULL TPMT_TK_HASHCHECK (Table 94).");
    }

    /// <summary>
    /// An HMAC sequence fed in two <c>TPM2_SequenceUpdate()</c> blocks returns the same published HMAC as the
    /// single-buffer form, proving the accumulator concatenates its segments in order (Part 1, clause 29.4.4).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 29.4.4; Part 3, clause 17.7</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacSequenceOverCase3SplitAcrossUpdatesReturnsThePublishedValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacSequenceOverCase3SplitAcrossUpdatesReturnsThePublishedValue), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequence = await StartHmacSequenceAsync(tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        await UpdateAsync(tpm, registry, pool, sequence, Rfc4231Case3Data.AsMemory(0, 20)).ConfigureAwait(false);
        await UpdateAsync(tpm, registry, pool, sequence, Rfc4231Case3Data.AsMemory(20, 20)).ConfigureAwait(false);

        TpmResult<SequenceCompleteResponse> completeResult = await CompleteAsync(tpm, registry, pool, sequence, Rfc4231Case3Data.AsMemory(40)).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() (HMAC) failed: '{completeResult.ResponseCode}'.");
        using SequenceCompleteResponse completed = completeResult.Value;

        bool matches = completed.Result.AsReadOnlySpan().SequenceEqual(Rfc4231Case3Sha256);
        Assert.IsTrue(matches, "The split HMAC sequence result must equal the published RFC 4231 test case 3 value.");
    }

    /// <summary>
    /// <c>TPM2_HMAC_Start()</c> with <c>hashAlg = TPM_ALG_NULL</c> selects the key's own scheme hash (Table 79's
    /// "hashAlg TPM_ALG_NULL" row), so the sequence still returns the published HMAC-SHA-256 for RFC 4231 test
    /// case 3.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.2, Table 79</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacSequenceStartedWithNullHashSelectsTheKeyDefault()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacSequenceStartedWithNullHashSelectsTheKeyDefault), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequence = await StartHmacSequenceAsync(tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_NULL).ConfigureAwait(false);

        TpmResult<SequenceCompleteResponse> completeResult = await CompleteAsync(tpm, registry, pool, sequence, Rfc4231Case3Data).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() (HMAC) failed: '{completeResult.ResponseCode}'.");
        using SequenceCompleteResponse completed = completeResult.Value;

        Assert.IsTrue(completed.Result.AsReadOnlySpan().SequenceEqual(Rfc4231Case3Sha256), "A NULL-hash HMAC_Start must select the key's SHA-256 scheme.");
    }

    /// <summary>
    /// An empty final buffer is permitted: an HMAC sequence completed with no octets at all yields the same
    /// value as the one-shot <c>TPM2_HMAC()</c> over an empty buffer under the same key — the HMAC of the empty
    /// message, one digest wide ("adds the last part of data, if any").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 15.5 and 17.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacOverAnEmptyMessageIsPermittedAndConsistentAcrossForms()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAnEmptyMessageIsPermittedAndConsistentAcrossForms), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacResponse> oneShot = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, key.Handle, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(oneShot.IsSuccess, $"TPM2_HMAC() over an empty buffer failed: '{oneShot.ResponseCode}'.");
        using HmacResponse oneShotResponse = oneShot.Value;
        Assert.AreEqual(32, oneShotResponse.OutHmac.Size, "The HMAC of the empty message is one SHA-256 digest wide.");

        TpmiDhObject sequence = await StartHmacSequenceAsync(tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        TpmResult<SequenceCompleteResponse> completeResult = await CompleteAsync(tpm, registry, pool, sequence, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() over an empty message failed: '{completeResult.ResponseCode}'.");
        using SequenceCompleteResponse completed = completeResult.Value;

        Assert.IsTrue(completed.Result.AsReadOnlySpan().SequenceEqual(oneShotResponse.OutHmac.AsReadOnlySpan()), "Both forms must agree on the HMAC of the empty message.");
    }

    /// <summary>
    /// After a successful HMAC <c>TPM2_SequenceComplete()</c> the sequence handle is flushed ({F}); a second
    /// completion of the same handle is refused with <c>TPM_RC_HANDLE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.8, Table 93</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacSequenceIsFlushedAfterCompletion()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacSequenceIsFlushedAfterCompletion), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequence = await StartHmacSequenceAsync(tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        TpmResult<SequenceCompleteResponse> first = await CompleteAsync(tpm, registry, pool, sequence, Rfc4231Case3Data).ConfigureAwait(false);
        Assert.IsTrue(first.IsSuccess, $"First TPM2_SequenceComplete() failed: '{first.ResponseCode}'.");
        first.Value.Dispose();

        TpmResult<SequenceCompleteResponse> second = await CompleteAsync(tpm, registry, pool, sequence, Rfc4231Case3Data).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, second.ResponseCode, "A completed HMAC sequence handle must be flushed, so a second completion is TPM_RC_HANDLE.");
    }

    /// <summary>
    /// <c>TPM2_FlushContext()</c> releases an open HMAC sequence: the flush succeeds, a completion of the flushed
    /// handle is refused with <c>TPM_RC_HANDLE</c>, and the pool returns every carrier the sequence owned —
    /// its key copy among them.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task FlushContextReleasesAnOpenHmacSequence()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(FlushContextReleasesAnOpenHmacSequence), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmiDhObject sequence = await StartHmacSequenceAsync(tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        TpmResult<FlushContextResponse> flush = await HmacKeyHarness.FlushAsync(tpm, registry, pool, sequence.Value, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flush.IsSuccess, $"TPM2_FlushContext() of an open HMAC sequence failed: '{flush.ResponseCode}'.");

        TpmResult<SequenceCompleteResponse> completeResult = await CompleteAsync(tpm, registry, pool, sequence, Rfc4231Case3Data).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, completeResult.ResponseCode, "A flushed HMAC sequence handle must no longer resolve.");

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Opening and flushing an HMAC sequence must leave the pool balanced.");
    }

    /// <summary>
    /// <c>TPM2_ReadPublic()</c> on an open HMAC sequence is refused with <c>TPM_RC_SEQUENCE</c> ("If objectHandle
    /// references a sequence object, the TPM shall return TPM_RC_SEQUENCE").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOnAnOpenHmacSequenceIsRefusedWithSequence()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(ReadPublicOnAnOpenHmacSequenceIsRefusedWithSequence), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequence = await StartHmacSequenceAsync(tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        ReadPublicInput input = ReadPublicInput.ForHandle(sequence);
        TpmResult<ReadPublicResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SEQUENCE, result.ResponseCode, "TPM2_ReadPublic() on a sequence object must be refused with TPM_RC_SEQUENCE.");
    }

    /// <summary>
    /// An HMAC sequence copies the key's sensitive value at <c>TPM2_HMAC_Start()</c> (Part 4
    /// <c>ObjectCreateHMACSequence</c> copies the key state into the sequence object): the key is flushed — the
    /// flush succeeds and the key handle no longer resolves — and the sequence still produces the published
    /// HMAC.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 17.2.1 and 28.4.1; Part 1, clause 29.4.4</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacSequenceSurvivesTheKeyBeingFlushedAfterStart()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacSequenceSurvivesTheKeyBeingFlushedAfterStart), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequence = await StartHmacSequenceAsync(tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        TpmResult<FlushContextResponse> flush = await HmacKeyHarness.FlushAsync(tpm, registry, pool, key.Handle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flush.IsSuccess, $"TPM2_FlushContext() of the HMAC key failed: '{flush.ResponseCode}'.");

        TpmResult<HmacResponse> gone = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, key.Handle, Rfc4231Case3Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, gone.ResponseCode, "The flushed key handle must no longer resolve before the sequence completes.");

        TpmResult<SequenceCompleteResponse> completeResult = await CompleteAsync(tpm, registry, pool, sequence, Rfc4231Case3Data).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() after key flush failed: '{completeResult.ResponseCode}'.");
        using SequenceCompleteResponse completed = completeResult.Value;

        bool matches = completed.Result.AsReadOnlySpan().SequenceEqual(Rfc4231Case3Sha256);
        Assert.IsTrue(matches, "The HMAC sequence must produce the published value even after its key was flushed.");
    }

    /// <summary>
    /// "The TPM will create and initialize an HMAC sequence structure, assign a handle to the sequence, and set
    /// the authValue of the sequence object to the value in auth": a sequence opened with a non-empty
    /// <c>auth</c> accepts <c>TPM2_SequenceUpdate()</c> and <c>TPM2_SequenceComplete()</c> presenting that value
    /// and returns the published RFC 4231 test case 3 HMAC.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacSequenceWithAnAuthValueCompletesWithThatPassword()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacSequenceWithAnAuthValueCompletesWithThatPassword), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacStartResponse> started = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256, ReadOnlyMemory<byte>.Empty, SequencePassword, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(started.IsSuccess, $"TPM2_HMAC_Start() with a sequence auth failed: '{started.ResponseCode}'.");
        TpmiDhObject sequence = started.Value.SequenceHandle;

        TpmResult<SequenceUpdateResponse> update = await HmacKeyHarness.SequenceUpdateAsync(
            tpm, registry, pool, sequence, Rfc4231Case3Data.AsMemory(0, 25), SequencePassword, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(update.IsSuccess, $"TPM2_SequenceUpdate() with the sequence password failed: '{update.ResponseCode}'.");

        TpmResult<SequenceCompleteResponse> completeResult = await HmacKeyHarness.SequenceCompleteAsync(
            tpm, registry, pool, sequence, Rfc4231Case3Data.AsMemory(25), SequencePassword, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() with the sequence password failed: '{completeResult.ResponseCode}'.");
        using SequenceCompleteResponse completed = completeResult.Value;

        Assert.IsTrue(completed.Result.AsReadOnlySpan().SequenceEqual(Rfc4231Case3Sha256), "The password-authorized HMAC sequence must return the published value.");
    }

    /// <summary>
    /// A wrong sequence password at <c>TPM2_SequenceComplete()</c> is refused with the session-index-encoded
    /// <c>TPM_RC_BAD_AUTH</c>, moves no dictionary-attack counter (a sequence's authorization is DA-exempt, Part
    /// 1, clause 29.4.6), and leaves the HMAC sequence usable with the right password.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.8.1; Part 1, clause 29.4.6</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacSequenceWithAWrongSequencePasswordIsBadAuthUnchargedAndSurvives()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacSequenceWithAWrongSequencePasswordIsBadAuthUnchargedAndSurvives), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacStartResponse> started = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256, ReadOnlyMemory<byte>.Empty, SequencePassword, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(started.IsSuccess, $"TPM2_HMAC_Start() with a sequence auth failed: '{started.ResponseCode}'.");
        TpmiDhObject sequence = started.Value.SequenceHandle;

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<SequenceCompleteResponse> refused = await HmacKeyHarness.SequenceCompleteAsync(
            tpm, registry, pool, sequence, Rfc4231Case3Data, WrongSequencePassword, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), refused.ResponseCode, "A wrong sequence password must be refused with the session-encoded TPM_RC_BAD_AUTH.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A sequence authorization failure must not charge the dictionary-attack counter.");

        TpmResult<SequenceCompleteResponse> completeResult = await HmacKeyHarness.SequenceCompleteAsync(
            tpm, registry, pool, sequence, Rfc4231Case3Data, SequencePassword, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"The sequence must survive the refusal and complete with the right password: '{completeResult.ResponseCode}'.");
        using SequenceCompleteResponse completed = completeResult.Value;
        Assert.IsTrue(completed.Result.AsReadOnlySpan().SequenceEqual(Rfc4231Case3Sha256), "The surviving sequence must return the published value.");
    }

    /// <summary>
    /// <c>TPM2_HMAC_Start()</c> over a handle that names an asymmetric key is refused with <c>TPM_RC_TYPE</c>
    /// ("If the key type is not TPM_ALG_KEYEDHASH then the TPM shall return TPM_RC_TYPE").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartOverAnAsymmetricKeyHandleIsRefusedWithType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartOverAnAsymmetricKeyHandleIsRefusedWithType), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacStartResponse> result = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, TpmAlgIdConstants.TPM_ALG_SHA256, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_TYPE, result.ResponseCode, "TPM2_HMAC_Start() over an asymmetric key handle must be refused with TPM_RC_TYPE.");
    }

    /// <summary>
    /// <c>TPM2_HMAC_Start()</c> over an open sequence handle is refused with <c>TPM_RC_TYPE</c>: a sequence object
    /// is not a KEYEDHASH key.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartOverASequenceHandleIsRefusedWithType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartOverASequenceHandleIsRefusedWithType), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        TpmiDhObject sequence = await StartHmacSequenceAsync(tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        TpmResult<HmacStartResponse> result = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, sequence.Value, TpmAlgIdConstants.TPM_ALG_SHA256, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_TYPE, result.ResponseCode, "TPM2_HMAC_Start() over a sequence handle must be refused with TPM_RC_TYPE.");
    }

    /// <summary>
    /// <c>TPM2_HMAC_Start()</c> over a sealed data object (sign CLEAR) is refused with <c>TPM_RC_KEY</c> ("If the
    /// sign attribute is not SET in the key referenced by handle, then the TPM shall return TPM_RC_KEY").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartOverASealedDataObjectIsRefusedWithKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartOverASealedDataObjectIsRefusedWithKey), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint sealedHandle, _) = await PolicySweepHarness.SealAndLoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, SealedSecretBytes, ReadOnlyMemory<byte>.Empty, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacStartResponse> result = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, sealedHandle, TpmAlgIdConstants.TPM_ALG_SHA256, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, result.ResponseCode, "TPM2_HMAC_Start() over a sealed data object must be refused with TPM_RC_KEY.");
    }

    /// <summary>
    /// <c>TPM2_HMAC_Start()</c> over a restricted KEYEDHASH key is refused with <c>TPM_RC_ATTRIBUTES</c> ("If the
    /// key referenced by handle has the restricted attribute SET, the TPM shall return TPM_RC_ATTRIBUTES").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartOverARestrictedKeyIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartOverARestrictedKeyIsRefusedWithAttributes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        uint restrictedHandle = await LoadGeneratedRestrictedHmacKeyAsync(tpm, registry, pool, parent.ObjectHandle.Value, isNoDa: true, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        TpmResult<HmacStartResponse> result = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, restrictedHandle, TpmAlgIdConstants.TPM_ALG_SHA256, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "TPM2_HMAC_Start() over a restricted KEYEDHASH key must be refused with TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// The authorization checks precede the command's own key-shape checks (Part 3, clause 5.6 runs before the
    /// detailed actions of clause 17.2): in Lockout mode, <c>TPM2_HMAC_Start()</c> over a RESTRICTED DA-protected
    /// key answers <c>TPM_RC_LOCKOUT</c>, not the <c>TPM_RC_ATTRIBUTES</c> the key's shape would otherwise earn.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.6 and 17.2.1; Part 1, clause 16.8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartInLockoutOverARestrictedDaProtectedKeyAnswersLockoutBeforeAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartInLockoutOverARestrictedDaProtectedKeyAnswersLockoutBeforeAttributes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey daKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, isNoDa: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        uint restrictedHandle = await LoadGeneratedRestrictedHmacKeyAsync(tpm, registry, pool, parent.ObjectHandle.Value, isNoDa: false, KeyPassword).ConfigureAwait(false);

        await EnterLockoutAsync(tpm, registry, pool, daKey.Handle).ConfigureAwait(false);

        TpmResult<HmacStartResponse> result = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, restrictedHandle, TpmAlgIdConstants.TPM_ALG_SHA256, KeyPassword, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode, "In Lockout mode the DA gate must answer before the restricted-key gate.");
    }

    /// <summary>
    /// The authorization checks precede the command's own parameter checks: a wrong password over a DA-protected
    /// key is refused with the session-index-encoded <c>TPM_RC_AUTH_FAIL</c> and charged even when the request's
    /// <c>hashAlg</c> does not match the key — the mismatch's <c>TPM_RC_VALUE</c> (Table 79) is never reached.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.6 and 17.2, Table 79; Part 1, clause 16.8.2</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartWithAWrongPasswordAndAMismatchedHashAlgIsAuthFailAndCharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartWithAWrongPasswordAndAMismatchedHashAlgIsAuthFailAndCharged), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, isNoDa: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacStartResponse> result = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA512, WrongKeyPassword, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode, "The password compare must answer before the hashAlg selection.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter + 1, after.Value.LockoutCounter, "The failed compare must charge failedTries even though the parameters were also wrong.");
    }

    /// <summary>
    /// <c>TPM2_HMAC_Start()</c> with a <c>hashAlg</c> that is neither <c>TPM_ALG_NULL</c> nor the key's own scheme
    /// hash is refused with <c>TPM_RC_VALUE</c> (Table 79's error row).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.2, Table 79</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartWithAMismatchedHashAlgIsRefusedWithValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartWithAMismatchedHashAlgIsRefusedWithValue), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacStartResponse> result = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA512, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, result.ResponseCode, "TPM2_HMAC_Start() with a hashAlg other than the key's scheme hash must be refused with TPM_RC_VALUE.");
    }

    /// <summary>
    /// A wrong password against a DA-protected HMAC key at <c>TPM2_HMAC_Start()</c> is refused with the
    /// session-index-encoded <c>TPM_RC_AUTH_FAIL</c> and charges <c>failedTries</c> exactly once, and no sequence
    /// is opened.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.6 and 17.2.1; Part 1, clause 16.8.2</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartWithAWrongPasswordOnADaProtectedKeyIsAuthFailAndCharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartWithAWrongPasswordOnADaProtectedKeyIsAuthFailAndCharged), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, isNoDa: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacStartResponse> result = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256, WrongKeyPassword, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode, "A wrong password on a DA-protected key must be refused with the session-encoded TPM_RC_AUTH_FAIL.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter + 1, after.Value.LockoutCounter, "A wrong password against a DA-protected key must charge failedTries exactly once.");
    }

    /// <summary>
    /// A wrong password against a <c>noDA</c> HMAC key at <c>TPM2_HMAC_Start()</c> is refused with the
    /// session-index-encoded <c>TPM_RC_BAD_AUTH</c> and moves no dictionary-attack counter.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.3; Part 3, clause 5.6, check 10</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartWithAWrongPasswordOnANoDaKeyIsBadAuthAndUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartWithAWrongPasswordOnANoDaKeyIsBadAuthAndUncharged), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, isNoDa: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacStartResponse> result = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256, WrongKeyPassword, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode, "A wrong password on a noDA key must be refused with the session-encoded TPM_RC_BAD_AUTH.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A wrong password against a noDA key must not move failedTries.");
    }

    /// <summary>
    /// A key whose <c>userWithAuth</c> attribute is CLEAR is refused a password session at
    /// <c>TPM2_HMAC_Start()</c> with <c>TPM_RC_POLICY_FAIL</c> (Part 3, clause 5.6, check 7.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6, check 7.1; Part 2, clause 8.3.3.6</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartOverAUserWithAuthClearKeyIsRefusedWithPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartOverAUserWithAuthClearKeyIsRefusedWithPolicyFail), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, isUserWithAuth: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacStartResponse> result = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode, "A password session against a userWithAuth-CLEAR key must be refused with TPM_RC_POLICY_FAIL.");
    }

    /// <summary>
    /// The <c>userWithAuth</c> check precedes the command's own key-shape checks (Part 3, clause 5.6, check 7.1,
    /// runs before the detailed actions of clause 17.2): a password session over a RESTRICTED key whose
    /// <c>userWithAuth</c> is CLEAR answers <c>TPM_RC_POLICY_FAIL</c>, not the <c>TPM_RC_ATTRIBUTES</c> the key's
    /// shape would otherwise earn.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.6 (check 7.1) and 17.2.1; Part 2, clause 8.3.3.6</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartOverAUserWithAuthClearRestrictedKeyAnswersPolicyFailBeforeAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartOverAUserWithAuthClearRestrictedKeyAnswersPolicyFailBeforeAttributes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        uint restrictedHandle = await LoadGeneratedRestrictedHmacKeyAsync(tpm, registry, pool, parent.ObjectHandle.Value, isNoDa: true, ReadOnlyMemory<byte>.Empty, isUserWithAuth: false).ConfigureAwait(false);

        TpmResult<HmacStartResponse> result = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, restrictedHandle, TpmAlgIdConstants.TPM_ALG_SHA256, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode, "The userWithAuth gate must answer before the restricted-key gate.");
    }

    /// <summary>
    /// In Lockout mode <c>TPM2_HMAC_Start()</c> with the CORRECT password over a DA-protected key is refused
    /// with the bare <c>TPM_RC_LOCKOUT</c> ("any use of a DA-protected authValue will return TPM_RC_LOCKOUT"),
    /// while a <c>noDA</c> key still opens a sequence.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.3; Part 3, clause 5.6, check 3</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartInLockoutIsRefusedForADaProtectedKeyAndAdmittedForANoDaKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartInLockoutIsRefusedForADaProtectedKeyAndAdmittedForANoDaKey), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey daKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, isNoDa: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey noDaKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, isNoDa: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        await EnterLockoutAsync(tpm, registry, pool, daKey.Handle).ConfigureAwait(false);

        TpmResult<HmacStartResponse> refused = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, daKey.Handle, TpmAlgIdConstants.TPM_ALG_SHA256, KeyPassword, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, refused.ResponseCode, "A locked-out TPM must refuse even a correct-password TPM2_HMAC_Start() over a DA-protected key with the bare TPM_RC_LOCKOUT.");

        TpmResult<HmacStartResponse> admitted = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, noDaKey.Handle, TpmAlgIdConstants.TPM_ALG_SHA256, KeyPassword, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(admitted.IsSuccess, $"A noDA key must still open a sequence in Lockout mode, but TPM2_HMAC_Start() failed: '{admitted.ResponseCode}'.");
    }

    /// <summary>
    /// "If sequenceHandle references a hash or HMAC sequence, the TPM shall return TPM_RC_MODE":
    /// <c>TPM2_EventSequenceComplete()</c> over an open HMAC sequence is refused with <c>TPM_RC_MODE</c>, and the
    /// sequence survives to complete with the published value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task EventSequenceCompleteOnAnHmacSequenceIsRefusedWithModeAndTheSequenceSurvives()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(EventSequenceCompleteOnAnHmacSequenceIsRefusedWithModeAndTheSequenceSurvives), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        TpmiDhObject sequence = await StartHmacSequenceAsync(tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        using EventSequenceCompleteInput input = EventSequenceCompleteInput.Create(TpmiDhPcr.FromValue((uint)TpmRh.TPM_RH_NULL), sequence, Rfc4231Case3Data, pool);
        using TpmPasswordSession pcrAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession sequenceAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<EventSequenceCompleteResponse> refused = await TpmCommandExecutor.ExecuteAsync<EventSequenceCompleteResponse>(
            tpm, input, [pcrAuth, sequenceAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_MODE, refused.ResponseCode, "TPM2_EventSequenceComplete() on an HMAC sequence must be refused with TPM_RC_MODE.");

        TpmResult<SequenceCompleteResponse> completeResult = await CompleteAsync(tpm, registry, pool, sequence, Rfc4231Case3Data).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"The HMAC sequence must survive the refusal: '{completeResult.ResponseCode}'.");
        using SequenceCompleteResponse completed = completeResult.Value;
        Assert.IsTrue(completed.Result.AsReadOnlySpan().SequenceEqual(Rfc4231Case3Sha256), "The surviving sequence must return the published value.");
    }

    /// <summary>
    /// <c>TPM2_SignSequenceComplete()</c> completes only a signing sequence: over an open HMAC sequence, with a
    /// loaded ECC signing key, it is refused with <c>TPM_RC_MODE</c> and the HMAC sequence survives.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 20.6; Part 1, clause 29.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOnAnHmacSequenceIsRefusedWithModeAndTheSequenceSurvives()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignSequenceCompleteOnAnHmacSequenceIsRefusedWithModeAndTheSequenceSurvives), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        TpmiDhObject sequence = await StartHmacSequenceAsync(tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        using CreatePrimaryInput signingKeyInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> signingKeyResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, signingKeyInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signingKeyResult.IsSuccess, $"CreatePrimary (ECC signing key) failed: '{signingKeyResult.ResponseCode}'.");
        using CreatePrimaryResponse signingKey = signingKeyResult.Value;

        using SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(sequence, signingKey.ObjectHandle, Rfc4231Case3Data, pool);
        using TpmPasswordSession sequenceAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<SignSequenceCompleteResponse> refused = await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
            tpm, input, [sequenceAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_MODE, refused.ResponseCode, "TPM2_SignSequenceComplete() on an HMAC sequence must be refused with TPM_RC_MODE.");

        TpmResult<SequenceCompleteResponse> completeResult = await CompleteAsync(tpm, registry, pool, sequence, Rfc4231Case3Data).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"The HMAC sequence must survive the refusal: '{completeResult.ResponseCode}'.");
        using SequenceCompleteResponse completed = completeResult.Value;
        Assert.IsTrue(completed.Result.AsReadOnlySpan().SequenceEqual(Rfc4231Case3Sha256), "The surviving sequence must return the published value.");
    }

    /// <summary>
    /// An open HMAC sequence occupies one object slot: <c>TPM2_HMAC_Start()</c> opens sequences until every
    /// slot the parent and the key leave free is taken, and the one past the count is refused with
    /// <c>TPM_RC_OBJECT_MEMORY</c> — consuming no handle: once a slot is freed, the next Start receives the very
    /// handle the refused one would have taken.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 27.4, 29.4.6 and 36.3.2; Part 3, clause 6.2, Table 3</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartPastTheObjectSlotCountReturnsObjectMemory()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartPastTheObjectSlotCountReturnsObjectMemory), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        const int OccupiedByParentAndKey = 2;
        var opened = new List<TpmiDhObject>();
        for(int i = 0; i < TpmSimulatorState.MaxLoadedObjects - OccupiedByParentAndKey; i++)
        {
            opened.Add(await StartHmacSequenceAsync(tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false));
        }

        Assert.HasCount(TpmSimulatorState.MaxLoadedObjects - OccupiedByParentAndKey, opened, "Every free object slot must accept an HMAC sequence.");

        TpmResult<HmacStartResponse> overflow = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_OBJECT_MEMORY, overflow.ResponseCode, "The Start that would need one slot more than the TPM has must be refused with TPM_RC_OBJECT_MEMORY.");

        TpmResult<FlushContextResponse> flush = await HmacKeyHarness.FlushAsync(tpm, registry, pool, opened[0].Value, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flush.IsSuccess, $"Flushing an open HMAC sequence failed: '{flush.ResponseCode}'.");

        TpmiDhObject reopened = await StartHmacSequenceAsync(tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.AreEqual(opened[^1].Value + 1, reopened.Value, "The refused Start must consume no handle: the freed slot hands out the next handle in sequence.");
    }

    /// <summary>
    /// Table 80's <c>@handle</c> requires an authorization session: a <c>TPM_ST_NO_SESSIONS</c> frame is refused
    /// with <c>TPM_RC_AUTH_MISSING</c> (Part 3, clause 5.5).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, Table 80</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartFramedWithoutSessionsIsRefusedWithAuthMissing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartFramedWithoutSessionsIsRefusedWithAuthMissing), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmRcConstants code = await SubmitHmacStartFramedAsync(simulator, pool, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, key.Handle, [], (ushort)TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_MISSING, code, "A TPM2_HMAC_Start() frame without an authorization area must be refused with TPM_RC_AUTH_MISSING.");
    }

    /// <summary>
    /// A session-shaped handle at the key's slot that names no loaded session is refused with
    /// <c>TPM_RC_REFERENCE_S0</c> ("the handle in the indicated position refers to an entity that is not
    /// present", Part 2, Table 18) — the slot is resolved as any session would be (Part 3, clause 5.5, step 4),
    /// so a well-typed-but-absent handle is a missing reference, not a type error. A real HMAC or policy session
    /// authorizes <c>TPM2_HMAC_Start()</c> through the session forms.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.6.3, Table 18; Part 3, clause 5.5, step 4</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartFramedWithASessionHandleNamingNoLoadedSessionIsRefusedWithReferenceS0()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartFramedWithASessionHandleNamingNoLoadedSessionIsRefusedWithReferenceS0), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        const uint HmacSessionShapedHandle = 0x02000000u;
        TpmRcConstants code = await SubmitHmacStartFramedAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_SESSIONS, key.Handle, [HmacSessionShapedHandle], (ushort)TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_S0, code, "A session-shaped handle naming no loaded session must be refused with TPM_RC_REFERENCE_S0.");
    }

    /// <summary>
    /// Table 80 carries exactly one <c>@</c> handle, so an authorization area holding a second session is refused
    /// with <c>TPM_RC_AUTHSIZE</c> (Part 2, Table 18).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.6.3, Table 18; Part 3, clause 5.5, Table 80</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartFramedWithTwoSessionsIsRefusedWithAuthSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartFramedWithTwoSessionsIsRefusedWithAuthSize), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmRcConstants code = await SubmitHmacStartFramedAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_SESSIONS, key.Handle, [(uint)TpmRh.TPM_RH_PW, (uint)TpmRh.TPM_RH_PW], (ushort)TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTHSIZE, code, "Two sessions for a single @ handle must be refused with TPM_RC_AUTHSIZE.");
    }

    /// <summary>
    /// <c>hashAlg</c> is a <c>TPMI_ALG_HASH+</c>: a value that is neither an implemented hash nor
    /// <c>TPM_ALG_NULL</c> is refused by the unmarshal with <c>TPM_RC_HASH</c> (Part 2, Table 77's
    /// <c>#TPM_RC_HASH</c>; Part 3, clause 5.8). This simulator parses the parameter area ahead of the
    /// authorization ladder, a recorded divergence from clause 5.6's placement that the empty-auth key here
    /// leaves unobservable.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.31, Table 77; Part 3, clause 5.8, Table 80</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacStartFramedWithANonHashAlgorithmIsRefusedWithHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartFramedWithANonHashAlgorithmIsRefusedWithHash), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        const ushort NotAHashAlgorithm = 0x0000;
        TpmRcConstants code = await SubmitHmacStartFramedAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_SESSIONS, key.Handle, [(uint)TpmRh.TPM_RH_PW], NotAHashAlgorithm).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HASH, code, "A hashAlg that is not a hash identifier must fail the unmarshal with TPM_RC_HASH.");
    }

    /// <summary>Opens an HMAC sequence over an empty-auth key with an empty sequence auth, asserting success, and returns its handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The loaded HMAC key handle.</param>
    /// <param name="hashAlg">The requested hash algorithm.</param>
    /// <returns>The opened sequence handle.</returns>
    private async Task<TpmiDhObject> StartHmacSequenceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint keyHandle, TpmAlgIdConstants hashAlg)
    {
        TpmResult<HmacStartResponse> result = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, keyHandle, hashAlg, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HMAC_Start() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>
    /// Creates and loads a restricted HMAC key whose sensitive value the TPM generates (sensitiveDataOrigin SET),
    /// the shape that is creatable but unusable by <c>TPM2_HMAC_Start()</c>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <param name="isNoDa">Whether the key is exempt from dictionary-attack protection.</param>
    /// <param name="userAuth">The key's authorization value.</param>
    /// <param name="isUserWithAuth">Whether the template sets <c>userWithAuth</c>, admitting a password session for the USER role.</param>
    /// <returns>The loaded restricted HMAC key handle.</returns>
    private async Task<uint> LoadGeneratedRestrictedHmacKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, bool isNoDa, ReadOnlyMemory<byte> userAuth, bool isUserWithAuth = true)
    {
        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateHmacKeyAsync(
            tpm, registry, pool, parentHandle, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256,
            isRestricted: true, isSensitiveDataOrigin: true, userAuth: userAuth, isNoDa: isNoDa, isUserWithAuth: isUserWithAuth, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (restricted HMAC key) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        TpmResult<LoadResponse> loadResult = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, parentHandle, created.OutPrivate, created.OutPublic, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (restricted HMAC key) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        return loaded.ObjectHandle.Value;
    }

    /// <summary>
    /// Drives the TPM into Lockout mode: lowers <c>maxTries</c> and fails the key's password that many times
    /// through <c>TPM2_HMAC_Start()</c>, then asserts the lockout state.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="daKeyHandle">A loaded DA-protected HMAC key to fail against.</param>
    /// <returns>A task that completes once Lockout mode has been asserted.</returns>
    private async Task EnterLockoutAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint daKeyHandle)
    {
        TpmResult<DictionaryAttackParametersResponse> lowered = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LockoutTestMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowered.IsSuccess, $"Lowering maxTries failed: '{lowered.ResponseCode}'.");

        for(uint attempt = 1; attempt <= LockoutTestMaxTries; attempt++)
        {
            TpmResult<HmacStartResponse> wrong = await HmacKeyHarness.HmacStartAsync(
                tpm, registry, pool, daKeyHandle, TpmAlgIdConstants.TPM_ALG_SHA256, WrongKeyPassword, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(wrong.IsSuccess, $"Attempt {attempt} of {LockoutTestMaxTries} with a wrong password must fail.");
        }

        TpmResult<TpmDictionaryAttackParameters> state = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(state.Value.IsLockedOut, "The TPM must be in Lockout mode before the locked-out cases run.");
    }

    /// <summary>Feeds one block into an HMAC sequence over its empty authorization, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The open sequence handle.</param>
    /// <param name="buffer">The block to append.</param>
    /// <returns>A task that completes once the update has been asserted.</returns>
    private async Task UpdateAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, ReadOnlyMemory<byte> buffer)
    {
        TpmResult<SequenceUpdateResponse> result = await HmacKeyHarness.SequenceUpdateAsync(
            tpm, registry, pool, sequenceHandle, buffer, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SequenceUpdate() failed: '{result.ResponseCode}'.");
    }

    /// <summary>Completes an HMAC sequence over its empty authorization and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence to complete.</param>
    /// <param name="buffer">The trailing block.</param>
    /// <returns>The executor result; the caller owns a successful value.</returns>
    private Task<TpmResult<SequenceCompleteResponse>> CompleteAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, ReadOnlyMemory<byte> buffer) =>
        HmacKeyHarness.SequenceCompleteAsync(tpm, registry, pool, sequenceHandle, buffer, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken);

    /// <summary>
    /// Hand-frames a <c>TPM2_HMAC_Start()</c> whose authorization area or parameters the typed input cannot
    /// express — the header, the key handle, one session block per entry of <paramref name="sessionHandles"/>
    /// (each with an empty nonce, <c>continueSession</c>, and an empty hmac), then the parameters (an empty
    /// <c>auth</c> then the raw <paramref name="hashAlg"/> value) — submits it, and returns the response code.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag.</param>
    /// <param name="keyHandle">The <c>@handle</c> value.</param>
    /// <param name="sessionHandles">The session handles to frame; empty for no authorization area.</param>
    /// <param name="hashAlg">The raw hash algorithm identifier to frame.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitHmacStartFramedAsync(TpmSimulator simulator, BaseMemoryPool pool, ushort tag, uint keyHandle, uint[] sessionHandles, ushort hashAlg)
    {
        const int SessionBlockSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        int authorizationSize = sessionHandles.Length * SessionBlockSize;
        int parametersSize = sizeof(ushort) + sizeof(ushort);
        int length = TpmHeader.HeaderSize + sizeof(uint) + (sessionHandles.Length > 0 ? sizeof(uint) + authorizationSize : 0) + parametersSize;
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader(tag, (uint)length, (uint)TpmCcConstants.TPM_CC_HMAC_Start);
        header.WriteTo(ref writer);
        writer.WriteUInt32(keyHandle);
        if(sessionHandles.Length > 0)
        {
            writer.WriteUInt32((uint)authorizationSize);
            foreach(uint sessionHandle in sessionHandles)
            {
                writer.WriteUInt32(sessionHandle);
                writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
                writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
                writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            }
        }

        writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
        writer.WriteUInt16(hashAlg);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed TPM2_HMAC_Start() must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }
}
