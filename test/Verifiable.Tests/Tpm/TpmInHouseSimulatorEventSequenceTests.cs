using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
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
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Event Sequences on the in-house simulator through the production executor and codecs:
/// <c>TPM2_HashSequenceStart()</c> with <c>hashAlg</c> = <c>TPM_ALG_NULL</c> (TPM 2.0 Library Part 3, clause
/// 17.4), <c>TPM2_SequenceUpdate()</c> (clause 17.7), and <c>TPM2_EventSequenceComplete()</c> (clause 17.9) — the
/// digests of the whole event under every implemented hash algorithm, the named register extended, the two
/// authorizations, the kind and locality gates, and the flush. Digest oracles are the framework's own SHA-1/SHA-2
/// implementations, independent of the simulator's digest seam.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorEventSequenceTests
{
    private const int Sha256DigestSize = 32;

    private const uint Locality4Pcr = 17;

    private const uint ArbitraryUnknownHandle = 0x8000_0999;

    private static TpmiAlgHash Sha256 => TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256);

    private static TpmiAlgHash NullHash => TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_NULL);

    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Clause 17.9.1: "This command adds the last part of data, if any, to an Event Sequence and returns the
    /// result in a digest list. If pcrHandle references a PCR and not TPM_RH_NULL, then the returned digest list
    /// is processed in the same manner as the digest list input parameter to TPM2_PCR_Extend()" — across three
    /// updates and a trailing buffer, the four implemented digests cover the whole event and PCR 7 reads back as
    /// SHA-256(0³² ‖ SHA-256(event)).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.9.1; Part 1, clauses 14.2 and 14.4</see>.
    /// </summary>
    [TestMethod]
    public async Task EventSequenceCompleteAcrossUpdatesReturnsTheDigestsOfTheWholeEventAndExtendsTheRegister()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] sequenceAuth = [0x0E, 0x0F];
        byte[] block1 = RandomNumberGenerator.GetBytes(1024);
        byte[] block2 = RandomNumberGenerator.GetBytes(333);
        byte[] block3 = RandomNumberGenerator.GetBytes(1);
        byte[] trailing = RandomNumberGenerator.GetBytes(77);
        byte[] whole = [.. block1, .. block2, .. block3, .. trailing];
        uint counterBefore = await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartEventSequenceAsync(tpm, registry, pool, sequenceAuth).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, sequenceAuth, block1).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, sequenceAuth, block2).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, sequenceAuth, block3).ConfigureAwait(false);

        TpmResult<EventSequenceCompleteResponse> result = await SubmitCompleteAsync(tpm, registry, pool, 7, [], sequenceHandle, sequenceAuth, trailing).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_EventSequenceComplete() failed: '{result.ResponseCode}'.");

        using EventSequenceCompleteResponse response = result.Value;
        AssertImplementedDigests(response.Results, whole);

        Assert.AreSequenceEqual(SHA256.HashData([.. new byte[Sha256DigestSize], .. SHA256.HashData(whole)]), await ReadPcrAsync(tpm, registry, pool, 7).ConfigureAwait(false), "PCR 7 must be extended with the SHA-256 digest of the whole event.");
        Assert.AreEqual(counterBefore + 1u, await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false), "One counted register changed once.");
    }

    /// <summary>
    /// Clause 17.9.1's note: "a digest is always returned for each implemented hash algorithm. There is no option
    /// to only return digests for which pcrHandle is allocated" — with <c>TPM_RH_NULL</c> the four digests come
    /// back, nothing is extended, and the sequence is still flushed (<c>{F}</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.9.2, Table 95</see>.
    /// </summary>
    [TestMethod]
    public async Task EventSequenceCompleteWithTheNullPcrReturnsTheDigestsFlushesAndExtendsNothing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] block = RandomNumberGenerator.GetBytes(50);
        uint counterBefore = await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartEventSequenceAsync(tpm, registry, pool, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], block).ConfigureAwait(false);

        TpmResult<EventSequenceCompleteResponse> result = await SubmitCompleteAsync(tpm, registry, pool, (uint)TpmRh.TPM_RH_NULL, [], sequenceHandle, [], []).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_EventSequenceComplete() with TPM_RH_NULL failed: '{result.ResponseCode}'.");

        using EventSequenceCompleteResponse response = result.Value;
        AssertImplementedDigests(response.Results, block);
        Assert.AreEqual(counterBefore, await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false), "No register changed, so the counter must not move.");

        TpmResult<FlushContextResponse> flush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(sequenceHandle.Value), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), flush.ResponseCode, "The completed sequence must have been flushed.");
    }

    /// <summary>
    /// Part 1, clause 29.4.3: an Event Sequence is a Start "followed by TPM2_SequenceUpdate() (zero or more)" —
    /// with no update, the completing command's own buffer is the whole event.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 29.4.3; Part 3, clause 17.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task EventSequenceCompleteWithNoPriorUpdateDigestsItsOwnBufferAlone()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] trailing = RandomNumberGenerator.GetBytes(40);

        TpmiDhObject sequenceHandle = await StartEventSequenceAsync(tpm, registry, pool, []).ConfigureAwait(false);
        TpmResult<EventSequenceCompleteResponse> result = await SubmitCompleteAsync(tpm, registry, pool, 1, [], sequenceHandle, [], trailing).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_EventSequenceComplete() failed: '{result.ResponseCode}'.");

        using EventSequenceCompleteResponse response = result.Value;
        AssertImplementedDigests(response.Results, trailing);
        Assert.AreSequenceEqual(SHA256.HashData([.. new byte[Sha256DigestSize], .. SHA256.HashData(trailing)]), await ReadPcrAsync(tpm, registry, pool, 1).ConfigureAwait(false), "PCR 1 must be extended with the digest of the completing buffer alone.");
    }

    /// <summary>
    /// Clause 17.9.1: "If sequenceHandle references a hash or HMAC sequence, the TPM shall return TPM_RC_MODE" —
    /// a SHA-256 hash sequence is refused and survives; the same kind mismatch refuses a signing sequence (Part
    /// 1, clause 29.4.1 assigns it to <c>TPM2_SignSequenceComplete()</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.9.1; Part 1, clause 29.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task EventSequenceCompleteOnAHashSequenceAndOnASigningSequenceReturnsModeAndTheSequencesSurvive()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using HashSequenceStartInput hashStart = HashSequenceStartInput.Create([], Sha256, pool);
        TpmResult<HashSequenceStartResponse> hashStarted = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            tpm, hashStart, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(hashStarted.IsSuccess, $"TPM2_HashSequenceStart() failed: '{hashStarted.ResponseCode}'.");
        TpmiDhObject hashSequence = hashStarted.Value.SequenceHandle;

        TpmResult<EventSequenceCompleteResponse> onHash = await SubmitCompleteAsync(tpm, registry, pool, 0, [], hashSequence, [], RandomNumberGenerator.GetBytes(4)).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_MODE, 1), onHash.ResponseCode, "TPM2_EventSequenceComplete() on a hash sequence must be refused with TPM_RC_MODE.");
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, hashSequence, [], RandomNumberGenerator.GetBytes(4)).ConfigureAwait(false);

        using CreatePrimaryInput keyInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> keyResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, keyInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(keyResult.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{keyResult.ResponseCode}'.");
        using CreatePrimaryResponse signingKey = keyResult.Value;

        using SignSequenceStartInput signStart = SignSequenceStartInput.Create(signingKey.ObjectHandle, [], pool);
        TpmResult<SignSequenceStartResponse> signStarted = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            tpm, signStart, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signStarted.IsSuccess, $"TPM2_SignSequenceStart() failed: '{signStarted.ResponseCode}'.");

        TpmResult<EventSequenceCompleteResponse> onSigning = await SubmitCompleteAsync(tpm, registry, pool, 0, [], signStarted.Value.SequenceHandle, [], []).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_MODE, 1), onSigning.ResponseCode, "TPM2_EventSequenceComplete() on a signing sequence must be refused with TPM_RC_MODE.");

        TpmResult<FlushContextResponse> flush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(signStarted.Value.SequenceHandle.Value), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flush.IsSuccess, "The signing sequence must survive the refused completion and remain flushable.");
    }

    /// <summary>
    /// After the sequence-kind check, a non-NULL <c>pcrHandle</c> that locality 0 may not extend (PCR 17, PTP
    /// 1.07 Table 14) is <c>TPM_RC_LOCALITY</c>, and the sequence is left as it was — a later update still
    /// succeeds.
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/">PC Client PTP 1.07, Table 14</see>.
    /// </summary>
    [TestMethod]
    public async Task EventSequenceCompleteOnTheLocality4PcrReturnsLocalityAndTheSequenceSurvives()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartEventSequenceAsync(tpm, registry, pool, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], RandomNumberGenerator.GetBytes(9)).ConfigureAwait(false);

        TpmResult<EventSequenceCompleteResponse> refused = await SubmitCompleteAsync(tpm, registry, pool, Locality4Pcr, [], sequenceHandle, [], []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCALITY, refused.ResponseCode, "PCR 17 cannot be extended at locality 0.");

        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], RandomNumberGenerator.GetBytes(9)).ConfigureAwait(false);
    }

    /// <summary>
    /// Table 95 authorizes <c>@sequenceHandle</c> at Auth Index 2: a wrong sequence password is
    /// <c>TPM_RC_BAD_AUTH</c> encoded for session 2, uncharged (Part 1, clause 29.4.6), and the sequence survives;
    /// <c>@pcrHandle</c> at Auth Index 1 takes only the EmptyAuth (PTP 1.07, clause 4.7, item 5), so a non-empty
    /// PCR password is refused on session 1, uncharged (Part 1, clause 14.7).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.9, Table 95; Part 1, clauses 14.7 and 29.4.6</see>.
    /// </summary>
    [TestMethod]
    public async Task EventSequenceCompleteWithAWrongSequenceOrPcrPasswordReturnsBadAuthOnThatSessionUnchargedAndTheSequenceSurvives()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] sequenceAuth = [0x71, 0x72];
        byte[] block = RandomNumberGenerator.GetBytes(30);
        TpmiDhObject sequenceHandle = await StartEventSequenceAsync(tpm, registry, pool, sequenceAuth).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, sequenceAuth, block).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<EventSequenceCompleteResponse> wrongSequence = await SubmitCompleteAsync(tpm, registry, pool, 4, [], sequenceHandle, [0x71, 0x99], []).ConfigureAwait(false);
        Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), wrongSequence.ResponseCode, "A wrong sequence password must be refused with TPM_RC_BAD_AUTH on session 2.");

        TpmResult<EventSequenceCompleteResponse> wrongPcr = await SubmitCompleteAsync(tpm, registry, pool, 4, [0x01], sequenceHandle, sequenceAuth, []).ConfigureAwait(false);
        Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), wrongPcr.ResponseCode, "A non-empty PCR password must be refused with TPM_RC_BAD_AUTH on session 1.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "Neither refusal may charge the dictionary-attack counter.");

        TpmResult<EventSequenceCompleteResponse> completed = await SubmitCompleteAsync(tpm, registry, pool, 4, [], sequenceHandle, sequenceAuth, []).ConfigureAwait(false);
        Assert.IsTrue(completed.IsSuccess, $"The sequence must survive both refusals and complete with the right passwords: '{completed.ResponseCode}'.");
        using EventSequenceCompleteResponse response = completed.Value;
        AssertImplementedDigests(response.Results, block);
    }

    /// <summary>
    /// <c>sequenceHandle</c> is <c>TPM2_EventSequenceComplete()</c>'s 2nd handle (index 1, Table 95: pcrHandle then
    /// sequenceHandle). An unresolved TRANSIENT-range value answers <c>TPM_RC_REFERENCE_H1</c> (TPM 2.0 Library
    /// Part 3, clause 5.4, step 2.1) — an unknown handle, and a completed sequence's own handle once flushed,
    /// alike, since "If this command completes successfully, the sequenceHandle object will be flushed" leaves it
    /// exactly as unresolved as a handle that was never allocated. A handle that DOES resolve, but to an ordinary
    /// object rather than a sequence, answers <c>TPM_RC_MODE</c> handle-encoded to index 1 (TPM 2.0 Library Part
    /// 2, Table 16's one-based N field) — Part 3, clause 17.9.1's "If sequenceHandle references a hash or HMAC sequence,
    /// the TPM shall return TPM_RC_MODE" generalized to every non-sequence kind this slot can resolve to, since a
    /// loaded key is exactly as much "not an Event Sequence" as a hash/HMAC sequence is.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.6.2, Tables 15-16; Part 3, clause 5.4, step 2.1, and clause 17.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task EventSequenceCompleteOnAnUnresolvedHandleAnswersReferenceH1AndOnALoadedKeyAnswersMode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<EventSequenceCompleteResponse> onUnknown = await SubmitCompleteAsync(tpm, registry, pool, 0, [], TpmiDhObject.FromValue(ArbitraryUnknownHandle), [], []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H1, onUnknown.ResponseCode, "An unresolved transient-range sequenceHandle (index 1) must be refused with TPM_RC_REFERENCE_H1 (TPM 2.0 Library Part 3, clause 5.4, step 2.1).");

        using CreatePrimaryInput keyInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> keyResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, keyInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(keyResult.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{keyResult.ResponseCode}'.");
        using CreatePrimaryResponse key = keyResult.Value;

        TpmResult<EventSequenceCompleteResponse> onKey = await SubmitCompleteAsync(tpm, registry, pool, 0, [], key.ObjectHandle, [], []).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_MODE, handleIndex: 1), onKey.ResponseCode,
            "A loaded key handle resolves but is not a sequence, and must be refused with TPM_RC_MODE handle-encoded to index 1 (TPM 2.0 Library Part 3, clause 17.9.1, generalized to every non-sequence kind; Part 2, clause 6.6.2, Table 16).");

        TpmiDhObject sequenceHandle = await StartEventSequenceAsync(tpm, registry, pool, []).ConfigureAwait(false);
        TpmResult<EventSequenceCompleteResponse> first = await SubmitCompleteAsync(tpm, registry, pool, (uint)TpmRh.TPM_RH_NULL, [], sequenceHandle, [], RandomNumberGenerator.GetBytes(3)).ConfigureAwait(false);
        Assert.IsTrue(first.IsSuccess, $"TPM2_EventSequenceComplete() failed: '{first.ResponseCode}'.");
        first.Value.Dispose();

        TpmResult<EventSequenceCompleteResponse> second = await SubmitCompleteAsync(tpm, registry, pool, (uint)TpmRh.TPM_RH_NULL, [], sequenceHandle, [], []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H1, second.ResponseCode, "The completed sequence must have been flushed, so its transient-range handle no longer resolves and answers TPM_RC_REFERENCE_H1, exactly as an unallocated one would.");
    }

    /// <summary>
    /// Table 95: the tag is <c>TPM_ST_SESSIONS</c> and both handles carry <c>@</c> — a no-sessions frame and a
    /// one-slot authorization area are both <c>TPM_RC_AUTH_MISSING</c> (Part 3, clause 5.5: "An authorization
    /// session is present for each of the handles with the '@' decoration"); an octet after <c>buffer</c> is
    /// <c>TPM_RC_SIZE</c> (clause 5.2).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.2 and 5.5; Table 95</see>.
    /// </summary>
    [TestMethod]
    public async Task EventSequenceCompleteHandFramedWithoutSessionsOrWithOneSlotReturnsAuthMissingAndATrailingOctetReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartEventSequenceAsync(tpm, registry, pool, []).ConfigureAwait(false);
        byte[] buffer = [0x00, 0x02, 0xAA, 0xBB];

        TpmRcConstants noSessions = await SubmitPasswordCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_EventSequenceComplete, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, [0u, sequenceHandle.Value], [], buffer).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_MISSING, noSessions, "A TPM_ST_NO_SESSIONS frame must be refused with TPM_RC_AUTH_MISSING.");

        TpmRcConstants oneSlot = await SubmitPasswordCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_EventSequenceComplete, (ushort)TpmStConstants.TPM_ST_SESSIONS, [0u, sequenceHandle.Value], [[]], buffer).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_MISSING, oneSlot, "One session for two @ handles must be refused with TPM_RC_AUTH_MISSING.");

        TpmRcConstants trailing = await SubmitPasswordCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_EventSequenceComplete, (ushort)TpmStConstants.TPM_ST_SESSIONS, [0u, sequenceHandle.Value], [[], []], [.. buffer, 0x00]).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, trailing, "An octet after the final parameter must be refused with TPM_RC_SIZE.");

        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], RandomNumberGenerator.GetBytes(2)).ConfigureAwait(false);
    }

    /// <summary>
    /// Asserts a returned digest list is exactly the four implemented hashes of <paramref name="message"/> in the
    /// reference's algorithm order — SHA-1, SHA-256, SHA-384, SHA-512 — each against the framework's own
    /// implementation.
    /// </summary>
    /// <param name="digests">The returned list.</param>
    /// <param name="message">The whole event.</param>
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms",
        Justification = "SHA-1 is one of the TCG hash algorithms the simulator implements and returns a digest under; the framework's SHA1 is the independent oracle for that entry, not a security use.")]
    private static void AssertImplementedDigests(TpmlDigestValues digests, byte[] message)
    {
        Assert.AreEqual(4, digests.Count, "One digest per implemented hash algorithm must be returned.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA1, digests[0].HashAlg.Value);
        Assert.AreSequenceEqual(SHA1.HashData(message), digests[0].Digest.ToArray());
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, digests[1].HashAlg.Value);
        Assert.AreSequenceEqual(SHA256.HashData(message), digests[1].Digest.ToArray());
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA384, digests[2].HashAlg.Value);
        Assert.AreSequenceEqual(SHA384.HashData(message), digests[2].Digest.ToArray());
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA512, digests[3].HashAlg.Value);
        Assert.AreSequenceEqual(SHA512.HashData(message), digests[3].Digest.ToArray());
    }

    /// <summary>Starts an Event Sequence (<c>hashAlg</c> = <c>TPM_ALG_NULL</c>), asserting success, and returns its handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceAuth">The sequence's own authValue.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartEventSequenceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, byte[] sequenceAuth)
    {
        using HashSequenceStartInput input = HashSequenceStartInput.Create(sequenceAuth, NullHash, pool);
        TpmResult<HashSequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HashSequenceStart(TPM_ALG_NULL) failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>Submits <c>TPM2_SequenceUpdate()</c> with the sequence password and asserts success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The open sequence's handle.</param>
    /// <param name="sequenceAuth">The sequence's own authValue.</param>
    /// <param name="buffer">The block to append.</param>
    /// <returns>A task that completes when the update has been asserted.</returns>
    private async Task UpdateSequenceSuccessfullyAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, byte[] sequenceAuth, byte[] buffer)
    {
        using TpmPasswordSession sequenceSession = sequenceAuth.Length == 0 ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(sequenceAuth, pool);
        using SequenceUpdateInput input = SequenceUpdateInput.Create(sequenceHandle, buffer, pool);

        TpmResult<SequenceUpdateResponse> result = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
            tpm, input, [sequenceSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SequenceUpdate() failed: '{result.ResponseCode}'.");
    }

    /// <summary>Submits <c>TPM2_EventSequenceComplete()</c> through the production executor with two password sessions.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="pcrHandle">The raw <c>pcrHandle</c> value.</param>
    /// <param name="pcrPassword">The password presented for the PCR slot (session 1).</param>
    /// <param name="sequenceHandle">The sequence to complete.</param>
    /// <param name="sequenceAuth">The password presented for the sequence slot (session 2).</param>
    /// <param name="buffer">The trailing block.</param>
    /// <returns>The executor result; the caller owns a successful value.</returns>
    private async Task<TpmResult<EventSequenceCompleteResponse>> SubmitCompleteAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint pcrHandle, byte[] pcrPassword, TpmiDhObject sequenceHandle, byte[] sequenceAuth, byte[] buffer)
    {
        using TpmPasswordSession pcrSession = pcrPassword.Length == 0 ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(pcrPassword, pool);
        using TpmPasswordSession sequenceSession = sequenceAuth.Length == 0 ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(sequenceAuth, pool);
        using EventSequenceCompleteInput input = EventSequenceCompleteInput.Create(TpmiDhPcr.FromValue(pcrHandle), sequenceHandle, buffer, pool);

        return await TpmCommandExecutor.ExecuteAsync<EventSequenceCompleteResponse>(
            tpm, input, [pcrSession, sequenceSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads one SHA-256 register through <c>TPM2_PCR_Read()</c>.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="pcr">The register index.</param>
    /// <returns>The register's value.</returns>
    private async Task<byte[]> ReadPcrAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint pcr)
    {
        using PcrReadInput input = PcrReadInput.ForPcrs(TpmAlgIdConstants.TPM_ALG_SHA256, [(int)pcr], pool);
        TpmResult<PcrReadResponse> result = await TpmCommandExecutor.ExecuteAsync<PcrReadResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_PCR_Read() failed: '{result.ResponseCode}'.");

        using PcrReadResponse response = result.Value;

        return response.PcrValues[0].AsReadOnlySpan().ToArray();
    }

    /// <summary>Reads <c>pcrUpdateCounter</c> through a <c>TPM2_PCR_Read()</c> of PCR 0.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The counter.</returns>
    private async Task<uint> ReadPcrUpdateCounterAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using PcrReadInput input = PcrReadInput.ForPcrs(TpmAlgIdConstants.TPM_ALG_SHA256, [0], pool);
        TpmResult<PcrReadResponse> result = await TpmCommandExecutor.ExecuteAsync<PcrReadResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_PCR_Read() failed: '{result.ResponseCode}'.");

        using PcrReadResponse response = result.Value;

        return response.PcrUpdateCounter;
    }

    /// <summary>
    /// Hand-frames an authorized command — header, the given handles, an authorization area of one
    /// <c>TPM_RS_PW</c> slot per password (none for a <c>TPM_ST_NO_SESSIONS</c> frame), then the raw parameter
    /// octets — and returns the response code.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="commandCode">The command code.</param>
    /// <param name="tag">The command tag.</param>
    /// <param name="handles">The handle area's raw values.</param>
    /// <param name="passwords">One password per <c>TPM_RS_PW</c> slot; empty for no authorization area.</param>
    /// <param name="parameters">The raw parameter area.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitPasswordCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmCcConstants commandCode, ushort tag, uint[] handles, byte[][] passwords, byte[] parameters)
    {
        int authorizationSize = 0;
        foreach(byte[] password in passwords)
        {
            authorizationSize += sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort) + password.Length;
        }

        int length = TpmHeader.HeaderSize + (handles.Length * sizeof(uint)) + (passwords.Length > 0 ? sizeof(uint) + authorizationSize : 0) + parameters.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader(tag, (uint)length, (uint)commandCode);
        header.WriteTo(ref writer);
        foreach(uint handle in handles)
        {
            writer.WriteUInt32(handle);
        }

        if(passwords.Length > 0)
        {
            writer.WriteUInt32((uint)authorizationSize);
            foreach(byte[] password in passwords)
            {
                writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
                writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
                writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
                writer.WriteTpm2b(password);
            }
        }

        writer.WriteBytes(parameters);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)).
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceUpdate, TpmResponseCodec.SequenceUpdate);
        _ = registry.Register(TpmCcConstants.TPM_CC_EventSequenceComplete, TpmResponseCodec.EventSequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_PCR_Read, TpmResponseCodec.PcrRead);

        return registry;
    }

    /// <summary>Creates a powered-on simulator brought to the Operational phase with <c>TPM2_Startup(CLEAR)</c>.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The simulator (the caller owns it).</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-event-sequence",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

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
        Assert.AreEqual((uint)TpmRcConstants.TPM_RC_SUCCESS, responseHeader.Code, "TPM2_Startup(CLEAR) must answer TPM_RC_SUCCESS.");

        return simulator;
    }
}
