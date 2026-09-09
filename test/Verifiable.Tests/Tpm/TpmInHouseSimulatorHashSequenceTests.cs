using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
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
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Hash sequences on the in-house simulator through the production executor and codecs:
/// <c>TPM2_HashSequenceStart()</c> (TPM 2.0 Library Part 3, clause 17.4), <c>TPM2_SequenceUpdate()</c> on a
/// hash sequence (clause 17.7), and <c>TPM2_SequenceComplete()</c> (clause 17.8) with its
/// <c>TPMT_TK_HASHCHECK</c> ticket proved end to end against <c>TPM2_SignDigest()</c> on a restricted key
/// (clause 20.7). Digest oracles are the framework's own SHA-2 implementations, independent of the
/// simulator's digest seam.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorHashSequenceTests
{
    private const int P256ComponentSize = 32;

    private const int Sha256DigestSize = 32;

    private const int Sha384DigestSize = 48;

    private const uint ArbitraryUnknownHandle = 0x8000_0999;

    private const uint OutOfTableHierarchy = 0x4000_0099;

    private static byte[] TpmGeneratedValueBytes { get; } = [0xFF, 0x54, 0x43, 0x47];

    private static TpmiAlgHash Sha256 => TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256);

    private static TpmiAlgHash Sha384 => TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA384);

    private static TpmiAlgHash NullHash => TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_NULL);

    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Clause 17.4.1: "the TPM will create and initialize a Hash Sequence context ... it will assign a handle to
    /// the context". Two starts yield two distinct transient handles.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HashSequenceStartReturnsATransientHandleAndASecondStartReturnsADistinctHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject first = await StartHashSequenceAsync(tpm, registry, pool, Sha256, []).ConfigureAwait(false);
        TpmiDhObject second = await StartHashSequenceAsync(tpm, registry, pool, Sha256, []).ConfigureAwait(false);

        Assert.IsTrue(first.IsTransient, "A hash sequence's handle most-significant octet must be TPM_HT_TRANSIENT (Part 1, clause 27.2.3).");
        Assert.IsTrue(second.IsTransient, "The second sequence's handle must also be TPM_HT_TRANSIENT.");
        Assert.AreNotEqual(first, second, "Two concurrently open hash sequences must receive distinct handles.");
    }

    /// <summary>
    /// Part 1, clause 27.4: a sequence context is removed by <c>TPM2_FlushContext()</c>; a second flush of the
    /// same handle finds nothing (<c>TPM_RC_HANDLE</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.4; Part 3, clause 28.4</see>.
    /// </summary>
    [TestMethod]
    public async Task FlushContextOnAHashSequenceSucceedsAndASecondFlushReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, Sha256, []).ConfigureAwait(false);

        FlushContextInput flushInput = FlushContextInput.ForHandle(sequenceHandle.Value);
        TpmResult<FlushContextResponse> firstFlush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(firstFlush.IsSuccess, $"TPM2_FlushContext() on an open hash sequence must succeed: '{firstFlush.ResponseCode}'.");

        TpmResult<FlushContextResponse> secondFlush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), secondFlush.ResponseCode, "A second flush of the already-flushed hash sequence must be refused with TPM_RC_HANDLE.");
    }

    /// <summary>
    /// Clause 17.4.1: "If hashAlg is neither an implemented algorithm nor TPM_ALG_NULL, then the TPM shall
    /// return TPM_RC_HASH." <c>TPM_ALG_SHA3_256</c> is a TCG hash identifier the simulator does not implement.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HashSequenceStartWithAnUnimplementedHashReturnsHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<HashSequenceStartResponse> result = await SubmitStartAsync(
            tpm, registry, pool, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA3_256), []).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 1), result.ResponseCode, "An unimplemented hash algorithm must be refused with TPM_RC_HASH.");
    }

    /// <summary>
    /// Part 2, Table 77: a value that is not a hash identifier fails the <c>TPMI_ALG_HASH</c> unmarshal with
    /// <c>#TPM_RC_HASH</c>. The simulator does not distinguish this from clause 17.4.1's refusal — both are
    /// <c>TPM_RC_HASH</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.31, Table 77</see>.
    /// </summary>
    [TestMethod]
    public async Task HashSequenceStartWithANonHashIdentifierHandFramedReturnsHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        TpmRcConstants code = await SubmitHashSequenceStartCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, [], (ushort)TpmAlgIdConstants.TPM_ALG_ECDSA, trailing: []).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 1), code, "hashAlg is TPM2_HashSequenceStart()'s second parameter (Table 85, index 1); TPM_ALG_ECDSA is not a hash identifier and must be refused with parameter-encoded TPM_RC_HASH.");
    }

    /// <summary>
    /// Table 85: the tag is <c>TPM_ST_SESSIONS</c> only when an audit or decrypt session is present. This frame
    /// carries no authorization area at all behind that tag, so the TPM reads its own
    /// <c>auth</c>/<c>hashAlg</c> octets as <c>authorizationSize</c> and answers the area's own
    /// structural refusal, <c>TPM_RC_AUTHSIZE</c> (clause 5.5, step 4.3), rather than misreading them as command
    /// parameters. A trailing octet after <c>hashAlg</c> on the <c>TPM_ST_NO_SESSIONS</c> form is
    /// <c>TPM_RC_SIZE</c> (clause 5.8.2, Table 2).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.4.2, Table 85, clause 5.5</see>.
    /// </summary>
    [TestMethod]
    public async Task HashSequenceStartFramedWithSessionsReturnsAuthsizeAndATrailingOctetReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        TpmRcConstants sessionTagged = await SubmitHashSequenceStartCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_SESSIONS, [], (ushort)TpmAlgIdConstants.TPM_ALG_SHA256, trailing: []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTHSIZE, sessionTagged, "A TPM_ST_SESSIONS frame with no well-formed authorization area behind it must be refused with the area's own TPM_RC_AUTHSIZE.");

        TpmRcConstants trailing = await SubmitHashSequenceStartCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, [], (ushort)TpmAlgIdConstants.TPM_ALG_SHA256, trailing: [0x00]).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, trailing, "An octet after the final parameter must be refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// Part 1, clause 29.4.6: "the public portion of a sequence is not readable with TPM2_ReadPublic()";
    /// Part 3, clause 12.4.1: a sequence object answers <c>TPM_RC_SEQUENCE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 29.4.6; Part 3, clause 12.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOnAHashSequenceHandleReturnsSequence()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, Sha256, []).ConfigureAwait(false);

        TpmResult<ReadPublicResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            tpm, ReadPublicInput.ForHandle(sequenceHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SEQUENCE, result.ResponseCode, "TPM2_ReadPublic() on a hash sequence must be refused with TPM_RC_SEQUENCE.");
    }

    /// <summary>
    /// Part 1, clause 29.4.6: a sequence context "may occupy an object slot on the TPM"; clause 36.3.2: out of
    /// slots is <c>TPM_RC_OBJECT_MEMORY</c>. <c>TPM2_HashSequenceStart()</c> needs no key, so every slot can
    /// hold a hash sequence and the one past <see cref="TpmSimulatorState.MaxLoadedObjects"/> is refused.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 29.4.6 and 36.3.2</see>.
    /// </summary>
    [TestMethod]
    public async Task HashSequenceStartPastTheObjectSlotCountReturnsObjectMemory()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        var handles = new List<TpmiDhObject>();
        for(int i = 0; i < TpmSimulatorState.MaxLoadedObjects; i++)
        {
            handles.Add(await StartHashSequenceAsync(tpm, registry, pool, Sha256, []).ConfigureAwait(false));
        }

        Assert.HasCount(TpmSimulatorState.MaxLoadedObjects, handles, "Every object slot must accept a hash sequence.");

        TpmResult<HashSequenceStartResponse> overflow = await SubmitStartAsync(tpm, registry, pool, Sha256, []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_OBJECT_MEMORY, overflow.ResponseCode, "The Start that would need one slot more than the TPM has must be refused with TPM_RC_OBJECT_MEMORY.");
    }

    /// <summary>
    /// Clause 17.8.1: "This command adds the last part of data, if any, to a hash/HMAC sequence and returns the
    /// result" — across three updates and a trailing buffer, <c>result</c> is SHA-256 of the whole message;
    /// the ticket names the requested hierarchy and, per clause 20.7, lets a RESTRICTED key sign the digest
    /// (the signature verified off-TPM).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 17.8.1 and 20.7; Part 1, clause 29.4.2</see>.
    /// </summary>
    [TestMethod]
    public async Task SequenceCompleteAcrossUpdatesReturnsTheWholeMessageDigestAndATicketARestrictedKeyAccepts()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] sequenceAuth = [0x0A, 0x0B, 0x0C];
        byte[] block1 = RandomNumberGenerator.GetBytes(300);
        byte[] block2 = RandomNumberGenerator.GetBytes(1024);
        byte[] block3 = RandomNumberGenerator.GetBytes(7);
        byte[] trailing = RandomNumberGenerator.GetBytes(41);
        byte[] expectedDigest = SHA256.HashData([.. block1, .. block2, .. block3, .. trailing]);

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, Sha256, sequenceAuth).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, sequenceAuth, block1).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, sequenceAuth, block2).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, sequenceAuth, block3).ConfigureAwait(false);

        TpmResult<SequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, sequenceAuth, trailing, TpmiRhHierarchy.Owner).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() failed: '{completeResult.ResponseCode}'.");

        using SequenceCompleteResponse complete = completeResult.Value;
        Assert.AreSequenceEqual(expectedDigest, complete.Result.AsReadOnlySpan().ToArray(), "result must be the SHA-256 of every octet the sequence received, in order.");
        Assert.IsFalse(complete.Validation.IsNull, "A safe-to-sign digest under a real hierarchy must carry a non-NULL ticket.");
        Assert.AreEqual(TpmiRhHierarchy.Owner, complete.Validation.Hierarchy, "The ticket's hierarchy must be the one the command named.");
        Assert.HasCount(Sha256DigestSize, complete.Validation.Digest.ToArray(), "The ticket HMAC is computed under the simulator's SHA-256 context algorithm.");

        using CreatePrimaryResponse restrictedKey = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using SignDigestInput signInput = SignDigestInput.CreateForRestrictedKey(restrictedKey.ObjectHandle, expectedDigest, complete.Validation, pool);
        using TpmPasswordSession keySession = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keySession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_SignDigest() on a restricted key must accept the ticket TPM2_SequenceComplete() minted: '{signResult.ResponseCode}'.");

        using SignDigestResponse signature = signResult.Value;
        Assert.IsTrue(
            VerifyEcdsaSignatureOffTpm(restrictedKey.OutPublic.PublicArea.Unique.Ecc!, expectedDigest, signature.Signature),
            "The restricted key's signature over the sequence digest must verify off-TPM.");
    }

    /// <summary>
    /// Clause 17.4.1: the hash sequence's algorithm is the one named at Start — a SHA-384 sequence returns a
    /// 48-octet <c>result</c> equal to the independent SHA-384 of the message.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 17.4.1 and 17.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task SequenceCompleteOnASha384SequenceReturnsTheSha384Digest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] block = RandomNumberGenerator.GetBytes(500);
        byte[] trailing = RandomNumberGenerator.GetBytes(12);
        byte[] expectedDigest = SHA384.HashData([.. block, .. trailing]);

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, Sha384, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], block).ConfigureAwait(false);

        TpmResult<SequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, [], trailing, TpmiRhHierarchy.Owner).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() failed: '{completeResult.ResponseCode}'.");

        using SequenceCompleteResponse complete = completeResult.Value;
        Assert.AreEqual(Sha384DigestSize, complete.Result.Size, "A SHA-384 sequence returns a 48-octet digest.");
        Assert.AreSequenceEqual(expectedDigest, complete.Result.AsReadOnlySpan().ToArray(), "result must be the SHA-384 of the whole message.");
        Assert.IsFalse(complete.Validation.IsNull, "The ticket is minted regardless of the sequence's own hash algorithm.");
    }

    /// <summary>
    /// Part 1, clause 29.4.2: a hash sequence is a Start "followed by TPM2_SequenceUpdate() (zero or more)"
    /// — with no update, the completing command's own buffer is the whole message.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 29.4.2</see>.
    /// </summary>
    [TestMethod]
    public async Task SequenceCompleteWithNoPriorUpdateDigestsItsOwnBufferAlone()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] trailing = RandomNumberGenerator.GetBytes(64);
        byte[] expectedDigest = SHA256.HashData(trailing);

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, Sha256, []).ConfigureAwait(false);
        TpmResult<SequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, [], trailing, TpmiRhHierarchy.Endorsement).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() failed: '{completeResult.ResponseCode}'.");

        using SequenceCompleteResponse complete = completeResult.Value;
        Assert.AreSequenceEqual(expectedDigest, complete.Result.AsReadOnlySpan().ToArray(), "result must be the SHA-256 of the completing buffer alone.");
        Assert.AreEqual(TpmiRhHierarchy.Endorsement, complete.Validation.Hierarchy, "The ticket carries the named hierarchy.");
    }

    /// <summary>
    /// Clause 17.8.1: "If hierarchy is TPM_RH_NULL, then digest in the ticket will be the Empty Buffer."
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task SequenceCompleteWithTheNullHierarchyReturnsTheNullTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] data = RandomNumberGenerator.GetBytes(32);

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, Sha256, []).ConfigureAwait(false);
        TpmResult<SequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, [], data, TpmiRhHierarchy.Null).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() failed: '{completeResult.ResponseCode}'.");

        using SequenceCompleteResponse complete = completeResult.Value;
        Assert.AreSequenceEqual(SHA256.HashData(data), complete.Result.AsReadOnlySpan().ToArray(), "The digest is returned regardless of the ticket.");
        Assert.IsTrue(complete.Validation.IsNull, "TPM_RH_NULL asks for no ticket: hierarchy TPM_RH_NULL and an empty digest.");
    }

    /// <summary>
    /// Clause 17.8.1: "If the digest is not safe to sign, then validation will be a TPMT_TK_HASHCHECK with the
    /// hierarchy set to TPM_RH_NULL and digest set to the Empty Buffer" — a first block beginning with
    /// <c>TPM_GENERATED_VALUE</c>; and clause 20.7: a restricted key then refuses the digest (<c>TPM_RC_TICKET</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 17.7.1, 17.8.1 and 20.7</see>.
    /// </summary>
    [TestMethod]
    public async Task SequenceCompleteWhoseFirstBlockBeginsWithTpmGeneratedReturnsTheNullTicketAndARestrictedKeyRefuses()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] firstBlock = [.. TpmGeneratedValueBytes, .. RandomNumberGenerator.GetBytes(20)];
        byte[] secondBlock = RandomNumberGenerator.GetBytes(20);
        byte[] expectedDigest = SHA256.HashData([.. firstBlock, .. secondBlock]);

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, Sha256, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], firstBlock).ConfigureAwait(false);

        TpmResult<SequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, [], secondBlock, TpmiRhHierarchy.Owner).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() must still succeed: '{completeResult.ResponseCode}'.");

        using SequenceCompleteResponse complete = completeResult.Value;
        Assert.AreSequenceEqual(expectedDigest, complete.Result.AsReadOnlySpan().ToArray(), "The digest itself is unaffected by the ticket verdict.");
        Assert.IsTrue(complete.Validation.IsNull, "A message whose first block begins with TPM_GENERATED_VALUE is not safe to sign, so the ticket is NULL even though a hierarchy was named.");

        using CreatePrimaryResponse restrictedKey = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using SignDigestInput signInput = SignDigestInput.CreateForRestrictedKey(restrictedKey.ObjectHandle, expectedDigest, complete.Validation, pool);
        using TpmPasswordSession keySession = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keySession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 2), signResult.ResponseCode, "A restricted key must refuse a digest that carries only the NULL ticket.");
    }

    /// <summary>
    /// Clause 17.8.1's note: "if the first buffer sent to the TPM had fewer than sizeof(TPM_GENERATED) octets,
    /// then the TPM will operate as if digest is not safe to sign" — Part 4's <c>TicketIsSafe()</c> returns
    /// FALSE for a buffer shorter than four octets.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task SequenceCompleteWhoseFirstBlockIsShorterThanFourOctetsReturnsTheNullTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] shortFirstBlock = [0x01, 0x02, 0x03];
        byte[] rest = RandomNumberGenerator.GetBytes(50);

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, Sha256, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], shortFirstBlock).ConfigureAwait(false);

        TpmResult<SequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, [], rest, TpmiRhHierarchy.Owner).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() must still succeed: '{completeResult.ResponseCode}'.");

        using SequenceCompleteResponse complete = completeResult.Value;
        Assert.AreSequenceEqual(SHA256.HashData([.. shortFirstBlock, .. rest]), complete.Result.AsReadOnlySpan().ToArray(), "The digest covers every octet.");
        Assert.IsTrue(complete.Validation.IsNull, "A first block shorter than sizeof(TPM_GENERATED) is treated as not safe to sign.");
    }

    /// <summary>
    /// Clause 17.8.1: "Proper authorization for the sequence object associated with sequenceHandle is
    /// required"; Part 1, clause 29.4.6: a sequence's authorization failure never charges the
    /// dictionary-attack counter. The refused command leaves the sequence usable (clause 17.7.1's rule).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.8.1; Part 1, clause 29.4.6</see>.
    /// </summary>
    [TestMethod]
    public async Task SequenceCompleteWithWrongAuthReturnsBadAuthUnchargedAndTheSequenceSurvives()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] sequenceAuth = [0x51, 0x52];
        byte[] data = RandomNumberGenerator.GetBytes(16);
        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, Sha256, sequenceAuth).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<SequenceCompleteResponse> refused = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, [0x51, 0x99], data, TpmiRhHierarchy.Owner).ConfigureAwait(false);
        Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), refused.ResponseCode, "A wrong sequence password must be refused with TPM_RC_BAD_AUTH on session 1.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A sequence authorization failure must not charge the dictionary-attack counter.");

        TpmResult<SequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, sequenceAuth, data, TpmiRhHierarchy.Owner).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"The sequence must survive the refused completion and complete with the right password: '{completeResult.ResponseCode}'.");
        completeResult.Value.Dispose();
    }

    /// <summary>
    /// Clause 17.8.1: "If sequenceHandle references an Event Sequence, then the TPM shall return TPM_RC_MODE."
    /// An Event Sequence is what <c>TPM2_HashSequenceStart()</c> opens for <c>hashAlg</c> = <c>TPM_ALG_NULL</c>
    /// (clause 17.4.1); it accepts updates and survives the refusal.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 17.4.1 and 17.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task SequenceCompleteOnAnEventSequenceReturnsModeAndTheSequenceSurvives()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject eventSequence = await StartHashSequenceAsync(tpm, registry, pool, NullHash, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, eventSequence, [], RandomNumberGenerator.GetBytes(10)).ConfigureAwait(false);

        TpmResult<SequenceCompleteResponse> refused = await SubmitCompleteAsync(
            tpm, registry, pool, eventSequence, [], [], TpmiRhHierarchy.Owner).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_MODE, 0), refused.ResponseCode, "TPM2_SequenceComplete() on an Event Sequence must be refused with TPM_RC_MODE at sequenceHandle, handle 1 of Table 93.");

        FlushContextInput flushInput = FlushContextInput.ForHandle(eventSequence.Value);
        TpmResult<FlushContextResponse> flush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flush.IsSuccess, "The Event Sequence must survive the refused completion and remain flushable.");
    }

    /// <summary>
    /// Part 1, clause 29.4.1 assigns a signing sequence to <c>TPM2_SignSequenceComplete()</c>; completing it
    /// with <c>TPM2_SequenceComplete()</c> is the same kind mismatch Part 3, clause 17.8.1 answers with
    /// <c>TPM_RC_MODE</c>, and the sequence survives.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 29.4.1; Part 3, clause 17.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task SequenceCompleteOnASigningSequenceReturnsModeAndTheSequenceSurvives()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signingKey = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using SignSequenceStartInput startInput = SignSequenceStartInput.Create(signingKey.ObjectHandle, [], pool);
        TpmResult<SignSequenceStartResponse> started = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(started.IsSuccess, $"TPM2_SignSequenceStart() failed: '{started.ResponseCode}'.");

        TpmResult<SequenceCompleteResponse> refused = await SubmitCompleteAsync(
            tpm, registry, pool, started.Value.SequenceHandle, [], RandomNumberGenerator.GetBytes(8), TpmiRhHierarchy.Owner).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_MODE, 0), refused.ResponseCode, "TPM2_SequenceComplete() on a signing sequence must be refused with TPM_RC_MODE at sequenceHandle, handle 1 of Table 93.");

        FlushContextInput flushInput = FlushContextInput.ForHandle(started.Value.SequenceHandle.Value);
        TpmResult<FlushContextResponse> flush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flush.IsSuccess, "The signing sequence must survive the refused completion and remain flushable.");
    }

    /// <summary>
    /// Clause 17.8.1: "If this command completes successfully, the sequenceHandle object will be flushed"
    /// (<c>{F}</c>, Table 93) — a second completion names a TRANSIENT-range <c>sequenceHandle</c> resolving to no
    /// loaded sequence, refused <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0 Library Part 3, clause 5.4, step 2.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.8.2, Table 93; Part 1, clause 29.4.6</see>.
    /// </summary>
    [TestMethod]
    public async Task SequenceCompleteFlushesTheSequenceOnSuccess()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, Sha256, []).ConfigureAwait(false);
        TpmResult<SequenceCompleteResponse> first = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, [], RandomNumberGenerator.GetBytes(5), TpmiRhHierarchy.Null).ConfigureAwait(false);
        Assert.IsTrue(first.IsSuccess, $"TPM2_SequenceComplete() failed: '{first.ResponseCode}'.");
        first.Value.Dispose();

        TpmResult<SequenceCompleteResponse> second = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, [], [], TpmiRhHierarchy.Null).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, second.ResponseCode, "sequenceHandle is TPM2_SequenceComplete()'s sole handle (index 0); the completed sequence has been flushed, so its TRANSIENT-range handle resolves to nothing loaded, TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1).");
    }

    /// <summary>
    /// <c>sequenceHandle</c> resolving to a loaded signing key rather than a sequence names something that is not
    /// a sequence at all; clause 17.8 names no RC of its own for this exact case (only for "references an Event
    /// Sequence", clause 17.8.1), but the reference's own <c>ObjectIsSequence</c> check generalizes
    /// <c>TPM_RC_MODE</c> to every non-sequence kind, handle-encoded to index 0 (TPM 2.0 Library Part
    /// 2, clause 6.6.2, Table 16's one-based N field). A well-typed but unloaded TRANSIENT-range
    /// value at the same slot resolves nowhere and is refused <c>TPM_RC_REFERENCE_H0</c> instead (TPM 2.0 Library
    /// Part 3, clause 5.4, step 2.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.6.2, Table 16; Part 3, clause 17.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task SequenceCompleteOnAKeyHandleAnswersModeAndOnAnUnknownHandleAnswersReferenceH0()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<SequenceCompleteResponse> onKey = await SubmitCompleteAsync(
            tpm, registry, pool, key.ObjectHandle, [], [], TpmiRhHierarchy.Null).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_MODE, handleIndex: 0), onKey.ResponseCode,
            "A key handle is not a sequence and must be refused with TPM_RC_MODE handle-encoded to index 0 (TPM 2.0 Library Part 2, clause 6.6.2, Table 16).");

        TpmResult<SequenceCompleteResponse> onUnknown = await SubmitCompleteAsync(
            tpm, registry, pool, TpmiDhObject.FromValue(ArbitraryUnknownHandle), [], [], TpmiRhHierarchy.Null).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, onUnknown.ResponseCode, "sequenceHandle is TPM2_SequenceComplete()'s sole handle (index 0); an unloaded TRANSIENT-range value is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1).");
    }

    /// <summary>
    /// Part 2, Table 59: a <c>hierarchy</c> outside the <c>TPMI_RH_HIERARCHY</c> selectors fails the unmarshal
    /// with <c>#TPM_RC_VALUE</c>; Table 96: a <c>buffer</c> over <c>MAX_2B_BUFFER_SIZE</c> (1024) is
    /// <c>TPM_RC_SIZE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.13, Table 59; clause 10.3.8, Table 96</see>.
    /// </summary>
    [TestMethod]
    public async Task SequenceCompleteHandFramedWithAnOutOfTableHierarchyReturnsValueAndAnOversizedBufferReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, Sha256, []).ConfigureAwait(false);

        TpmRcConstants badHierarchy = await SubmitSequenceCompleteCommandAsync(
            simulator, pool, sequenceHandle.Value, new byte[4], OutOfTableHierarchy).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 1), badHierarchy, "hierarchy is TPM2_SequenceComplete()'s second parameter (Table 93, index 1); one outside Table 59 must be refused with parameter-encoded TPM_RC_VALUE.");

        TpmRcConstants oversized = await SubmitSequenceCompleteCommandAsync(
            simulator, pool, sequenceHandle.Value, new byte[Tpm2bMaxBuffer.MaxSize + 1], (uint)TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), oversized, "buffer is TPM2_SequenceComplete()'s first parameter (Table 93, index 0); one over MAX_2B_BUFFER_SIZE must be refused with parameter-encoded TPM_RC_SIZE.");

        FlushContextInput flushInput = FlushContextInput.ForHandle(sequenceHandle.Value);
        TpmResult<FlushContextResponse> flush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flush.IsSuccess, "Both refusals must leave the sequence unmodified and flushable.");
    }

    /// <summary>Submits <c>TPM2_HashSequenceStart()</c> through the production executor and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hashAlg">The sequence's hash algorithm, or <c>TPM_ALG_NULL</c> for an Event Sequence.</param>
    /// <param name="sequenceAuth">The sequence's own authValue.</param>
    /// <returns>The executor result.</returns>
    private async Task<TpmResult<HashSequenceStartResponse>> SubmitStartAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiAlgHash hashAlg, byte[] sequenceAuth)
    {
        using HashSequenceStartInput input = HashSequenceStartInput.Create(sequenceAuth, hashAlg, pool);

        return await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Starts a hash (or Event) sequence via <see cref="SubmitStartAsync"/>, asserting success, and returns its handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hashAlg">The sequence's hash algorithm, or <c>TPM_ALG_NULL</c> for an Event Sequence.</param>
    /// <param name="sequenceAuth">The sequence's own authValue.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartHashSequenceAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiAlgHash hashAlg, byte[] sequenceAuth)
    {
        TpmResult<HashSequenceStartResponse> result = await SubmitStartAsync(tpm, registry, pool, hashAlg, sequenceAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HashSequenceStart() failed: '{result.ResponseCode}'.");

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

    /// <summary>Submits <c>TPM2_SequenceComplete()</c> through the production executor and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence to complete.</param>
    /// <param name="sequenceAuth">The password presented for the sequence.</param>
    /// <param name="buffer">The trailing block.</param>
    /// <param name="hierarchy">The ticket hierarchy.</param>
    /// <returns>The executor result; the caller owns a successful value.</returns>
    private async Task<TpmResult<SequenceCompleteResponse>> SubmitCompleteAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, byte[] sequenceAuth, byte[] buffer, TpmiRhHierarchy hierarchy)
    {
        using TpmPasswordSession sequenceSession = sequenceAuth.Length == 0 ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(sequenceAuth, pool);
        using SequenceCompleteInput input = SequenceCompleteInput.Create(sequenceHandle, buffer, hierarchy, pool);

        return await TpmCommandExecutor.ExecuteAsync<SequenceCompleteResponse>(
            tpm, input, [sequenceSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_HashSequenceStart()</c> command (Table 85: <c>auth</c> then <c>hashAlg</c>) with a
    /// caller-chosen tag, raw algorithm value, and trailing octets, and returns the response code.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag.</param>
    /// <param name="auth">The sequence authValue.</param>
    /// <param name="rawHashAlg">The raw <c>hashAlg</c> value.</param>
    /// <param name="trailing">Octets appended after the final parameter.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitHashSequenceStartCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, ushort tag, byte[] auth, ushort rawHashAlg, byte[] trailing)
    {
        int length = TpmHeader.HeaderSize + sizeof(ushort) + auth.Length + sizeof(ushort) + trailing.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader(tag, (uint)length, (uint)TpmCcConstants.TPM_CC_HashSequenceStart);
        header.WriteTo(ref writer);
        writer.WriteTpm2b(auth);
        writer.WriteUInt16(rawHashAlg);
        writer.WriteBytes(trailing);

        return await SubmitRawAsync(simulator, pool, owner.Memory[..length]).ConfigureAwait(false);
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_SequenceComplete()</c> command (Table 93: <c>@sequenceHandle</c>, one empty
    /// <c>TPM_RS_PW</c> slot, <c>buffer</c>, <c>hierarchy</c>) with a raw hierarchy value and returns the
    /// response code.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence handle.</param>
    /// <param name="buffer">The trailing block.</param>
    /// <param name="rawHierarchy">The raw <c>hierarchy</c> value.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSequenceCompleteCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint sequenceHandle, byte[] buffer, uint rawHierarchy)
    {
        const int PasswordSlotSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);

        int length =
            TpmHeader.HeaderSize
            + sizeof(uint)                     //Handle area: @sequenceHandle.
            + sizeof(uint) + PasswordSlotSize  //authorizationSize + one empty TPM_RS_PW slot.
            + sizeof(ushort) + buffer.Length   //buffer: TPM2B_MAX_BUFFER.
            + sizeof(uint);                    //hierarchy: TPMI_RH_HIERARCHY.

        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_SequenceComplete);
        header.WriteTo(ref writer);
        writer.WriteUInt32(sequenceHandle);
        writer.WriteUInt32((uint)PasswordSlotSize);
        writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
        writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
        writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
        writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
        writer.WriteTpm2b(buffer);
        writer.WriteUInt32(rawHierarchy);

        return await SubmitRawAsync(simulator, pool, owner.Memory[..length]).ConfigureAwait(false);
    }

    /// <summary>Submits a hand-framed command and returns its response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="command">The framed command.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitRawAsync(TpmSimulator simulator, BaseMemoryPool pool, ReadOnlyMemory<byte> command)
    {
        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>Creates an unrestricted ECC P-256 signing primary under the owner hierarchy, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a RESTRICTED ECC P-256 signing primary under the owner hierarchy, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateRestrictedEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreateRestrictedEccSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (restricted ECC P-256) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Composes a restricted ECC signing key template — <c>TPMA_OBJECT.restricted</c> SET alongside <c>sign</c>,
    /// with no password — the key whose <c>TPM2_SignDigest()</c> demands a valid <c>TPMT_TK_HASHCHECK</c>.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the returned CreatePrimaryInput, whose Dispose releases them.")]
    private static CreatePrimaryInput CreateRestrictedEccSigningKeyInput(BaseMemoryPool pool)
    {
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);

        var attributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH |
            TpmaObject.SIGN_ENCRYPT |
            TpmaObject.RESTRICTED |
            TpmaObject.NO_DA;

        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            attributes,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));

        return new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
    }

    /// <summary>
    /// Verifies a P-256 ECDSA signature off-TPM against a public key reconstructed solely from the simulator's
    /// exported public point — sharing no code path with the signer.
    /// </summary>
    /// <param name="point">The exported public point.</param>
    /// <param name="digest">The digest that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns><see langword="true"/> when the signature verifies.</returns>
    private static bool VerifyEcdsaSignatureOffTpm(TpmsEccPoint point, byte[] digest, TpmuSignature signature)
    {
        var ecParameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = ToFixed(point.X.AsReadOnlySpan(), P256ComponentSize),
                Y = ToFixed(point.Y.AsReadOnlySpan(), P256ComponentSize)
            }
        };

        byte[] p1363Signature = new byte[2 * P256ComponentSize];
        ToFixed(signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        using ECDsa ecdsa = ECDsa.Create(ecParameters);

        return ecdsa.VerifyHash(digest, p1363Signature);
    }

    /// <summary>Left-pads (or left-trims) a big-endian integer to exactly <paramref name="length"/> octets.</summary>
    /// <param name="value">The integer octets.</param>
    /// <param name="length">The fixed width.</param>
    /// <returns>The fixed-width octets.</returns>
    private static byte[] ToFixed(ReadOnlySpan<byte> value, int length)
    {
        byte[] result = new byte[length];
        if(value.Length <= length)
        {
            value.CopyTo(result.AsSpan(length - value.Length));
        }
        else
        {
            value[^length..].CopyTo(result);
        }

        return result;
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
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceComplete, TpmResponseCodec.SequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignDigest, TpmResponseCodec.SignDigest);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_ReadPublic, TpmResponseCodec.ReadPublic);

        return registry;
    }

    /// <summary>Creates a powered-on simulator brought to the Operational phase with <c>TPM2_Startup(CLEAR)</c>.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The simulator (the caller owns it).</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-hash-sequence",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Submits <c>TPM2_Startup(CLEAR)</c> to a powered-on simulator, asserting success.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>A task that completes when the TPM is Operational.</returns>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
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
        Assert.AreEqual((uint)TpmRcConstants.TPM_RC_SUCCESS, responseHeader.Code, "TPM2_Startup(CLEAR) must answer TPM_RC_SUCCESS.");
    }
}
