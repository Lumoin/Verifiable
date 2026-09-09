using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Foundation.Automata;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// The pool-accounting and identity proofs for a command's captured parameter area — cpHash's
/// <c>parameters</c> term (TPM 2.0 Library Part 1, clause 15.7, equation 15), held in the pooled
/// <see cref="TpmParameterArea"/> carrier the parse rents and the request owns — and for the handle-Name terms
/// that same equation concatenates ahead of it. Every proof drives the real wire through the production command
/// path and reads real pool telemetry (<see cref="MeteredHousePool"/>), never an internal hook.
/// </summary>
/// <remarks>
/// Three properties are separable and each is proved on its own here: the carrier is rented as the parse's LAST
/// act, so a parse refused on a wire check rents nothing at all; every path out of the command — refused at
/// entry, refused at the continuation, refused on an HMAC mismatch, or accepted — releases it exactly once; and
/// a parameter-encrypted command transforms THAT SAME carrier in place, so the octets cpHash covered as
/// ciphertext are the octets the command body decodes as plaintext (Part 3, clause 5.6 precedes clause 5.7).
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorParameterAreaCarrierTests
{
    /// <summary>The session and Name hash algorithm every command here uses.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The SHA-256 digest width in octets.</summary>
    private const int DigestSize = 32;

    /// <summary>The Index the owner-authorized proofs read and write.</summary>
    private const uint OwnerIndexHandle = 0x0100_0071;

    /// <summary>The Index the Index-authorized proofs read.</summary>
    private const uint SelfAuthIndexHandle = 0x0100_0072;

    /// <summary>The Index handle no proof ever defines, so naming it is refused at the entry transition.</summary>
    private const uint UndefinedIndexHandle = 0x0100_0079;

    /// <summary>The declared data area width of every Index these proofs define.</summary>
    private const ushort IndexDataSize = 8;

    /// <summary>An owner-authorized, dictionary-attack-exempt Index: only the owner hierarchy may read or write it.</summary>
    private const TpmaNv OwnerAuthorizedAttributes = TpmaNv.TPMA_NV_OWNERREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>A caller-authorized, dictionary-attack-exempt Index: its own authValue reads and writes it.</summary>
    private const TpmaNv SelfAuthorizedAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>The octets every proof writes into an Index's data area.</summary>
    private static byte[] IndexData { get; } = [0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58];

    /// <summary>The data a sealed object carries, so the Unseal proof reads a non-empty value back.</summary>
    private static byte[] SealedSecret { get; } = [0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68];

    /// <summary>The authorization value the in-place decryption proof assigns to the Index it defines.</summary>
    private static byte[] EncryptedIndexAuth { get; } = [0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78];

    /// <summary>The owner authorization value the bind-omission proof installs, so a bound session has something to omit.</summary>
    private static byte[] BoundOwnerAuth { get; } = [0x81, 0x82, 0x83, 0x84];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A <c>TPM2_NV_Read()</c> whose parameter area carries a trailing octet no parameter accounts for is
    /// refused with <c>TPM_RC_SIZE</c> at the wire read (TPM 2.0 Library Part 3, clause 5.8.2, Table 2) — and refused
    /// there rents NOTHING: the parameter-area carrier is created as the parse's last act, after every wire
    /// check has passed, so a refused parse never leaves one outstanding.
    /// </summary>
    [TestMethod]
    public async Task NvReadOverSessionRefusedAtTheParseRentsNoParameterAreaCarrier()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-parameterarea-parse").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineIndexAsync(tpm, registry, pool, SelfAuthIndexHandle, SelfAuthorizedAttributes, IndexData).ConfigureAwait(false);
        (uint sessionHandle, _) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        //Handle area, then a minimal authorization area, then size ‖ offset with one octet too many behind them.
        var body = new List<byte>();
        AppendUInt32(body, SelfAuthIndexHandle);
        AppendUInt32(body, SelfAuthIndexHandle);
        AppendAuthorizationArea(body, sessionHandle);
        AppendUInt16(body, IndexDataSize);
        AppendUInt16(body, 0);
        body.Add(0xFF);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_NV_Read, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, code,
            "An octet no parameter accounts for is TPM_RC_SIZE at the wire read (Part 3, clause 5.8.2, Table 2).");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The parameter-area carrier is rented as the parse's last act, so a parse refused on a wire check must rent nothing.");

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_NV_Read()</c> over an HMAC session returns its parameter-area carrier on all three of its exit
    /// paths: refused at the entry transition (an Index that is not defined, <c>TPM_RC_HANDLE</c>), refused on a
    /// command-HMAC mismatch (<c>TPM_RC_AUTH_FAIL</c>), and accepted.
    /// </summary>
    [TestMethod]
    public async Task NvReadOverSessionReturnsItsParameterAreaCarrierOnEveryPath()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-parameterarea-nvread").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] indexName = await DefineIndexAsync(tpm, registry, pool, SelfAuthIndexHandle, SelfAuthorizedAttributes, IndexData).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            long baseline = trackingPool.OutstandingCount;

            {
                var input = new NvReadInput(AuthHandle: UndefinedIndexHandle, NvIndex: UndefinedIndexHandle, Size: IndexDataSize, Offset: 0);
                TpmResult<NvReadResponse> refused = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                    tpm, input, [session], [indexName, indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(refused.IsSuccess, "Reading an Index that was never defined must be refused.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A command refused at its entry transition must release the parameter area its parse rented.");

            {
                //The wrong Name in cpHash makes the caller's command HMAC disagree with the simulator's, which
                //is the mismatch arm of Part 3, clause 5.6, check 9.
                byte[] wrongName = new byte[indexName.Length];
                indexName.CopyTo(wrongName, 0);
                wrongName[^1] ^= 0xFF;

                var input = new NvReadInput(AuthHandle: SelfAuthIndexHandle, NvIndex: SelfAuthIndexHandle, Size: IndexDataSize, Offset: 0);
                TpmResult<NvReadResponse> refused = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                    tpm, input, [session], [wrongName, wrongName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(refused.IsSuccess, "A command HMAC computed over the wrong Name must not authorize.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A command-HMAC mismatch must release the parameter area the request still owns.");

            {
                var input = new NvReadInput(AuthHandle: SelfAuthIndexHandle, NvIndex: SelfAuthIndexHandle, Size: IndexDataSize, Offset: 0);
                TpmResult<NvReadResponse> result = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                    tpm, input, [session], [indexName, indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Read over an HMAC session failed: '{result.ResponseCode}'.");

                using NvReadResponse read = result.Value;
                Assert.AreSequenceEqual(IndexData, read.Data.ToArray(), "The read must return the written octets.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The accepting continuation is the parameter area's terminal owner and must release it too.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_NV_Write()</c> over an HMAC session returns its parameter-area carrier across a refusal (a write
    /// past the Index's declared data area, <c>TPM_RC_NV_RANGE</c>, refused at the continuation AFTER the HMAC
    /// verified) and a success.
    /// </summary>
    [TestMethod]
    public async Task NvWriteOverSessionReturnsItsParameterAreaCarrierAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-parameterarea-nvwrite").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] indexName = await DefineIndexAsync(tpm, registry, pool, OwnerIndexHandle, OwnerAuthorizedAttributes, data: null).ConfigureAwait(false);
        byte[] ownerName = HandleFormName((uint)TpmRh.TPM_RH_OWNER);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            long baseline = trackingPool.OutstandingCount;

            {
                //The offset places the write past the declared data area, which the continuation refuses only
                //after the command HMAC has verified (Part 3, clause 31.7.1).
                using Tpm2bMaxNvBuffer inputBuffer = Tpm2bMaxNvBuffer.Create(IndexData, pool);
                var input = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, OwnerIndexHandle, inputBuffer, Offset: IndexDataSize);
                TpmResult<NvWriteResponse> refused = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
                    tpm, input, [session], [ownerName, indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_NV_RANGE, refused.ResponseCode,
                    "A write past the declared data area is TPM_RC_NV_RANGE (Part 3, clause 31.7.1).");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A command refused at its continuation must release the parameter area its parse rented.");

            {
                using Tpm2bMaxNvBuffer inputBuffer = Tpm2bMaxNvBuffer.Create(IndexData, pool);
                var input = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, OwnerIndexHandle, inputBuffer, Offset: 0);
                TpmResult<NvWriteResponse> result = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
                    tpm, input, [session], [ownerName, indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Write over an HMAC session failed: '{result.ResponseCode}'.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The accepting continuation is the parameter area's terminal owner and must release it too.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_NV_DefineSpace()</c> over an HMAC session returns its parameter-area carrier across a refusal (a
    /// second definition of an Index that already exists, <c>TPM_RC_NV_DEFINED</c>) and a success. It is the one
    /// NV command whose cpHash carries a single Name — the owner hierarchy's own 4-octet handle — because no
    /// Index exists yet to contribute a second (Part 3, clause 31.3.2, Table 245).
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOverSessionReturnsItsParameterAreaCarrierAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-parameterarea-nvdefine").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        _ = await DefineIndexAsync(tpm, registry, pool, OwnerIndexHandle, OwnerAuthorizedAttributes, data: null).ConfigureAwait(false);
        byte[] ownerName = HandleFormName((uint)TpmRh.TPM_RH_OWNER);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            long baseline = trackingPool.OutstandingCount;

            {
                TpmResult<NvDefineSpaceResponse> refused = await DefineOverSessionAsync(
                    tpm, registry, pool, session, ownerName, OwnerIndexHandle).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_NV_DEFINED, refused.ResponseCode,
                    "Redefining an existing Index is TPM_RC_NV_DEFINED (Part 3, clause 31.3.1).");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A refused definition must release the parameter area its parse rented alongside the auth and policy carriers.");

            {
                TpmResult<NvDefineSpaceResponse> result = await DefineOverSessionAsync(
                    tpm, registry, pool, session, ownerName, SelfAuthIndexHandle).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace over an HMAC session failed: '{result.ResponseCode}'.");
            }

            //The defined Index keeps the auth and data-area carriers the parse rented (they transferred into
            //durable state), so only the parameter area returns here.
            Assert.AreEqual(
                baseline + 2, trackingPool.OutstandingCount,
                "A successful definition transfers the Index authValue and the data area reserved at its declared dataSize into durable state (its empty policy digest is the shared sentinel) and releases the parameter area.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// The two parameter-free-response hierarchy commands return their parameter-area carriers on both kinds of
    /// path: <c>TPM2_ClearControl()</c> over an HMAC session on its accepted path (Part 3, clause 24.7), and
    /// <c>TPM2_Clear()</c> over an HMAC session on a refusal taken at its continuation, after the command HMAC
    /// has already verified (<c>disableClear</c> SET, <c>TPM_RC_DISABLED</c>, Part 3, clause 24.6.1).
    /// </summary>
    [TestMethod]
    public async Task ClearAndClearControlOverSessionsReturnTheirParameterAreaCarriers()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-parameterarea-clear").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] lockoutName = HandleFormName((uint)TpmRh.TPM_RH_LOCKOUT);
        byte[] platformName = HandleFormName((uint)TpmRh.TPM_RH_PLATFORM);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            long baseline = trackingPool.OutstandingCount;

            //platformAuth may set disableClear in either direction; lockoutAuth may only SET it (Part 3,
            //clause 24.7.1), so the platform hierarchy authorizes both legs here.
            {
                var input = new ClearControlInput(TpmRh.TPM_RH_PLATFORM, TpmiYesNo.Yes);
                TpmResult<ClearControlResponse> result = await TpmCommandExecutor.ExecuteAsync<ClearControlResponse>(
                    tpm, input, [session], [platformName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_ClearControl(YES) over an HMAC session failed: '{result.ResponseCode}'.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The accepted ClearControl must release the parameter area its parse rented before its response is framed.");

            {
                var input = new ClearInput(TpmRh.TPM_RH_LOCKOUT);
                TpmResult<ClearResponse> refused = await TpmCommandExecutor.ExecuteAsync<ClearResponse>(
                    tpm, input, [session], [lockoutName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_DISABLED, refused.ResponseCode,
                    "TPM2_Clear() with disableClear SET is TPM_RC_DISABLED (Part 3, clause 24.6.1).");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A clear refused at its continuation must release the parameter area its parse rented.");

            {
                var input = new ClearControlInput(TpmRh.TPM_RH_PLATFORM, TpmiYesNo.No);
                TpmResult<ClearControlResponse> result = await TpmCommandExecutor.ExecuteAsync<ClearControlResponse>(
                    tpm, input, [session], [platformName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_ClearControl(NO) over an HMAC session failed: '{result.ResponseCode}'.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The second accepted ClearControl must release its own parameter area too.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_GetRandom()</c> over an HMAC session returns its parameter-area carrier — the 2-octet
    /// <c>bytesRequested</c> field, the one parse that captures a FIXED-width area rather than everything
    /// remaining (Part 3, clause 16.1) — on both a refused and an accepted round trip.
    /// </summary>
    [TestMethod]
    public async Task GetRandomOverSessionReturnsItsParameterAreaCarrierAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-parameterarea-getrandom").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        //The session-tagged form of TPM2_GetRandom() always encrypts its response parameter (Part 3, clause
        //16.1; Part 1, clause 18), so both sessions negotiate a symmetric definition and claim encrypt.
        TpmtSymDef symmetric = TpmtSymDef.Xor(SessionAlg);
        (uint flushedHandle, TpmSession flushedSession) = await StartUnboundSessionAsync(tpm, registry, pool, symmetric).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, symmetric).ConfigureAwait(false);
        flushedSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
        using(flushedSession)
        using(session)
        {
            //The first session leaves the table before the baseline is taken, so naming it is a session
            //reference miss the entry transition refuses (Part 3, clause 5.5, step 4.2).
            await FlushAsync(tpm, registry, pool, flushedHandle).ConfigureAwait(false);

            long baseline = trackingPool.OutstandingCount;

            {
                var input = new GetRandomInput(DigestSize);
                TpmResult<GetRandomResponse> refused = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    tpm, input, [flushedSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(refused.IsSuccess, "A session that has been flushed must not authorize a command.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A command refused at its entry transition must release the fixed-width parameter area the parse rented.");

            {
                var input = new GetRandomInput(DigestSize);
                TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    tpm, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_GetRandom over an HMAC session failed: '{result.ResponseCode}'.");
                result.Value.Dispose();
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The accepting continuation must release the parameter area before the response is framed.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_Create()</c> over sessions returns its parameter-area carrier — the buffer whose
    /// <c>inSensitive</c> the decrypt step decodes in place — on both a refused and an accepted round trip, and
    /// <c>TPM2_Unseal()</c>, which carries no command parameters at all, rides the dispose-immune empty area and
    /// rents nothing for it.
    /// </summary>
    [TestMethod]
    public async Task CreateAndUnsealOverSessionsAccountForTheirParameterAreasExactly()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-parameterarea-create").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStoragePrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] parentName = parent.Name.Span.ToArray();
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            long baseline = trackingPool.OutstandingCount;

            {
                byte[] wrongName = new byte[parentName.Length];
                parentName.CopyTo(wrongName, 0);
                wrongName[^1] ^= 0xFF;

                using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, pool);
                using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
                using CreateInput input = new(parent.ObjectHandle.Value, inSensitive, template, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                TpmResult<CreateResponse> refused = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                    tpm, input, [session], [wrongName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(refused.IsSuccess, "A command HMAC computed over the wrong parent Name must not authorize.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A refused TPM2_Create() over sessions must release the parameter area its parse rented.");

            uint sealedHandle;
            byte[] sealedName;
            {
                using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, pool);
                using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
                using CreateInput input = new(parent.ObjectHandle.Value, inSensitive, template, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                    tpm, input, [session], [parentName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_Create() over sessions failed: '{result.ResponseCode}'.");

                using CreateResponse created = result.Value;
                (sealedHandle, sealedName) = await LoadAsync(tpm, registry, pool, parent.ObjectHandle.Value, created).ConfigureAwait(false);
            }

            long afterLoad = trackingPool.OutstandingCount;

            {
                UnsealInput input = UnsealInput.ForItem(TpmiDhObject.FromValue(sealedHandle));

                TpmResult<UnsealResponse> result = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                    tpm, input, [session], [sealedName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_Unseal over a session failed: '{result.ResponseCode}'.");

                using UnsealResponse unsealed = result.Value;
                Assert.AreSequenceEqual(SealedSecret, unsealed.OutData.AsReadOnlySpan().ToArray(), "The unseal must return the sealed octets.");
            }

            Assert.AreEqual(
                afterLoad, trackingPool.OutstandingCount,
                "TPM2_Unseal() has no command parameters, so its area is the dispose-immune shared empty carrier and the round trip is flat.");

            await FlushAsync(tpm, registry, pool, sealedHandle).ConfigureAwait(false);
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        await FlushAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// The two sensitive values a session-authorized <c>TPM2_Create()</c> decodes OUT OF its parameter area —
    /// <c>inSensitive.userAuth</c> and <c>inSensitive.data</c> (<c>TPMS_SENSITIVE_CREATE</c>, TPM 2.0 Library
    /// Part 2, clause 11.1.15, Table 171) — ride pooled carriers of their own, rented as the decode's last act
    /// and released by the sealing effect, which is their terminal owner: <c>TPM2_Create()</c> installs no
    /// durable object, so the wrapped private blob it packs them into is their only use (Part 1, clause 16.6.4).
    /// Both values are deliberately NON-empty, since an empty one is the shared dispose-immune sentinel and
    /// would make the balance vacuous.
    /// </summary>
    [TestMethod]
    public async Task CreateOverSessionsReleasesTheSensitiveCarriersItDecodes()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-parameterarea-createsensitive").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStoragePrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] parentName = parent.Name.Span.ToArray();
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            long baseline = trackingPool.OutstandingCount;

            {
                using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, EncryptedIndexAuth, pool);
                using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
                using CreateInput input = new(parent.ObjectHandle.Value, inSensitive, template, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                    tpm, input, [session], [parentName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_Create() over sessions failed: '{result.ResponseCode}'.");

                result.Value.Dispose();
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The sealing effect is the terminal owner of the decoded secret and userAuth carriers and must release both.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        await FlushAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// A <c>TPM2_NV_DefineSpace()</c> whose <c>auth</c> parameter travels encrypted under the authorizing
    /// session's own <c>decrypt</c> attribute transforms ONE carrier: the parameter area the parse captured is
    /// digested as ciphertext for cpHash (TPM 2.0 Library Part 3, clause 5.6) and then decrypted IN PLACE
    /// (clause 5.7), so the buffer the verification covered and the buffer the body decodes are the same
    /// instance with different contents.
    /// </summary>
    /// <remarks>
    /// The proof reads the automaton's own trace: the verification action's <c>ParameterArea</c> and the
    /// decrypted feedback's <c>Request.RawParameterArea</c> are compared by reference, and the octets are copied
    /// at each observation so the before/after contents can be compared after the command completes. A design
    /// that copied instead of aliasing would leave the two instances distinct; one that decrypted before
    /// digesting would leave the contents equal.
    /// </remarks>
    [TestMethod]
    public async Task AnEncryptedDefineSpaceDigestsAndDecryptsTheSameParameterAreaCarrier()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-parameterarea-inplace").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        var observer = new ParameterAreaObserver();
        using IDisposable subscription = simulator.Subscribe(observer);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(
            (uint)TpmRh.TPM_RH_OWNER, SessionAlg, TestEntropy.NewCounterStream(), pool, TpmtSymDef.Xor(SessionAlg));
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound, XOR) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;
        using TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(sessionHandle), ReadOnlyMemory<byte>.Empty, startInput.NonceCaller, started.NonceTPM,
            SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric: TpmtSymDef.Xor(SessionAlg), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
        session.SetAuthValue(ReadOnlySpan<byte>.Empty, pool);

        byte[] ownerName = HandleFormName((uint)TpmRh.TPM_RH_OWNER);
        {
            using Tpm2bAuth auth = Tpm2bAuth.Create(EncryptedIndexAuth, pool);
            using Tpm2bDigest policyDigest = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool);
            using TpmsNvPublic publicInfo = new(SelfAuthIndexHandle, SessionAlg, SelfAuthorizedAttributes, policyDigest, IndexDataSize);
            using NvDefineSpaceInput input = new(TpmRh.TPM_RH_OWNER, auth, publicInfo);

            TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
                tpm, input, [session], [ownerName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"An encrypted TPM2_NV_DefineSpace failed: '{result.ResponseCode}'.");
        }

        Assert.IsNotNull(observer.VerifiedArea, "The command-HMAC verification must have been declared over a parameter area.");
        Assert.IsNotNull(observer.DecryptedArea, "The decryption must have been declared over a parameter area.");
        Assert.IsTrue(
            ReferenceEquals(observer.VerifiedArea, observer.DecryptedArea),
            "cpHash covers the octets exactly as received and the decryption transforms them in place, so both steps must hold the SAME carrier instance.");

        //The auth parameter's 2-octet size field is never itself encrypted (Part 1, clause 18.1), so the value
        //sits directly behind it — as ciphertext in the octets the digest covered, and as the caller's own
        //plaintext once the same buffer has been transformed.
        byte[] digestedAuth = observer.DigestedOctets[sizeof(ushort)..(sizeof(ushort) + EncryptedIndexAuth.Length)];
        Assert.IsFalse(
            AreEqual(EncryptedIndexAuth, digestedAuth),
            "cpHash must have covered the parameter as CIPHERTEXT, before any decryption ran (Part 3, clause 5.6 precedes clause 5.7).");
        Assert.AreSequenceEqual(
            EncryptedIndexAuth, observer.RecoveredAuth,
            "Decrypting that same buffer in place must recover exactly the auth value the caller sent.");

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// Releasing a parameter area ZEROES its octets before the storage goes back to the pool. That matters
    /// because an in-place parameter decryption (TPM 2.0 Library Part 3, clause 5.7) leaves the recovered
    /// PLAINTEXT in the area — a <c>TPMS_SENSITIVE_CREATE</c>'s <c>userAuth</c> and sealed <c>data</c>, or a
    /// replacement authorization value — and it stays there until the owning request releases the carrier. The
    /// proof adopts storage the test itself holds, so what the carrier leaves behind is directly readable.
    /// <c>area</c> is disposed explicitly, not via a <see langword="using"/> declaration, because the
    /// zeroing assertion right after it must see the release already happened.
    /// </summary>
    [TestMethod]
    public void ReleasingAParameterAreaZeroesItsOctets()
    {
        byte[] backing = new byte[16];
        using var owner = new TestOwnedMemory(backing);
        TpmParameterArea area = TpmParameterArea.Adopt(owner, EncryptedIndexAuth.Length);
        EncryptedIndexAuth.CopyTo(area.Memory.Span);

        Assert.AreSequenceEqual(
            EncryptedIndexAuth, area.Span.ToArray(),
            "The area must hold the octets written through its mutable view before it is released.");

        area.Dispose();

        Assert.IsTrue(
            Array.TrueForAll(backing, octet => octet == 0),
            "Disposing the area must zero its storage, since an in-place decryption can have left recovered plaintext there.");
    }

    /// <summary>
    /// A two-handle command's cpHash is <c>H(commandCode ‖ Name1 ‖ Name2 ‖ parameters)</c> (TPM 2.0 Library
    /// Part 1, clause 15.7, equation 15), with the terms in the command's own handle order and a permanent
    /// entity's Name written as its 4-octet BIG-ENDIAN handle value (clause 13, Table 9). This drives an owner-authorized
    /// <c>TPM2_NV_Read()</c>, whose Name1 is that handle form and whose Name2 is the Index's computed Name,
    /// recomputes the digest and the command HMAC independently through the project's own digest and HMAC seams,
    /// and compares them against the octets on the wire — which the simulator accepted.
    /// </summary>
    [TestMethod]
    public async Task CpHashOverTwoNamesMatchesAnIndependentDigestOfTheCommandCodeNamesAndParameters()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-parameterarea-cphash").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using var recorder = new TpmRecorder();
        using IDisposable subscription = tpm.Subscribe(recorder);
        TpmResponseRegistry registry = CreateRegistry();

        byte[] indexName = await DefineIndexAsync(tpm, registry, pool, OwnerIndexHandle, OwnerAuthorizedAttributes, IndexData).ConfigureAwait(false);
        byte[] ownerName = HandleFormName((uint)TpmRh.TPM_RH_OWNER);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            //The session's nonceTPM as the command will carry it; the caller nonce is read back off the wire,
            //since the executor rolls a fresh one for every command.
            byte[] nonceTpm = session.NonceTpm.ToArray();

            var input = new NvReadInput(AuthHandle: (uint)TpmRh.TPM_RH_OWNER, NvIndex: OwnerIndexHandle, Size: IndexDataSize, Offset: 0);
            TpmResult<NvReadResponse> result = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                tpm, input, [session], [ownerName, indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"An owner-authorized TPM2_NV_Read over a session failed: '{result.ResponseCode}'.");
            result.Value.Dispose();

            ReadOnlyMemory<byte> commandWire = recorder.GetExchanges()[^1].Command;
            (byte[] wireNonceCaller, byte[] wireHmac, byte[] wireParameters, byte wireAttributes) = ReadCommandSession(commandWire.Span, handleCount: 2);

            //cpHash = H(commandCode ‖ Name1 ‖ Name2 ‖ parameters), assembled here from the command code, the
            //owner hierarchy's handle-form Name, the Index's computed Name, and the parameter octets as sent.
            var cpHashInput = new List<byte>();
            AppendUInt32(cpHashInput, (uint)TpmCcConstants.TPM_CC_NV_Read);
            cpHashInput.AddRange(ownerName);
            cpHashInput.AddRange(indexName);
            cpHashInput.AddRange(wireParameters);

            using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
                cpHashInput.ToArray(), DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            //authHMAC = HMAC_sessionAlg(sessionKey ‖ authValue, cpHash ‖ nonceCaller ‖ nonceTPM ‖
            //sessionAttributes) — equation 17. An unbound, unsalted session against the empty owner authValue
            //keys on the empty string, so the message alone decides the value.
            var hmacInput = new List<byte>();
            hmacInput.AddRange(cpHash.AsReadOnlySpan().ToArray());
            hmacInput.AddRange(wireNonceCaller);
            hmacInput.AddRange(nonceTpm);
            hmacInput.Add(wireAttributes);

            using HmacValue expected = await CryptographicKeyEvents.ComputeHmacAsync(
                hmacInput.ToArray(), ReadOnlyMemory<byte>.Empty, DigestSize, CryptoTags.HmacSha256Value, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreSequenceEqual(
                expected.AsReadOnlySpan().ToArray(), wireHmac,
                "The accepted command's HMAC must equal one computed from an independently assembled H(commandCode ‖ Name1 ‖ Name2 ‖ parameters).");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// A session bound to a permanent entity records that entity's Name in its bound-entity value, and a
    /// permanent entity's Name IS its 4-octet BIG-ENDIAN handle value (TPM 2.0 Library Part 1, clause 13, Table 9; Part
    /// 4, <c>SessionComputeBoundEntity()</c>). Binding to the owner hierarchy while its authValue is non-empty
    /// and then authorizing that same hierarchy exercises equation 22's omission: the caller leaves the
    /// authValue out of the HMAC key and the command is accepted only because the simulator recomputed the
    /// identical bound-entity value from the identical handle octets.
    /// </summary>
    [TestMethod]
    public async Task ASessionBoundToTheOwnerHierarchyOmitsItsAuthValueFromTheCommandHmacKey()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-parameterarea-bind").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        {
            using Tpm2bAuth newAuth = Tpm2bAuth.Create(BoundOwnerAuth, pool);
            using var input = new HierarchyChangeAuthInput(TpmRh.TPM_RH_OWNER, newAuth);
            using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<HierarchyChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyChangeAuthResponse>(
                tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyChangeAuth failed: '{result.ResponseCode}'.");
        }

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession((uint)TpmRh.TPM_RH_OWNER, SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to the owner hierarchy) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;
        using TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(sessionHandle), BoundOwnerAuth, startInput.NonceCaller, started.NonceTPM,
            SessionAlg, TestEntropy.NewCounterStream(), pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        //The caller deliberately does NOT call SetAuthValue: the bind already folded the owner authValue into
        //the session key, so equation 22 omits it from the HMAC key on both sides.
        byte[] ownerName = HandleFormName((uint)TpmRh.TPM_RH_OWNER);
        {
            TpmResult<NvDefineSpaceResponse> result = await DefineOverSessionAsync(
                tpm, registry, pool, session, ownerName, OwnerIndexHandle).ConfigureAwait(false);
            Assert.IsTrue(
                result.IsSuccess,
                $"A session bound to the owner hierarchy must authorize it with the authValue omitted: '{result.ResponseCode}'.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// Storage over an array the test keeps a reference to, so what a released carrier leaves in its storage is
    /// readable after the release. Its <see cref="Dispose"/> returns nothing anywhere.
    /// </summary>
    /// <param name="backing">The array the memory views.</param>
    private sealed class TestOwnedMemory(byte[] backing): IMemoryOwner<byte>
    {
        /// <summary>Gets the array this owner hands out and the test reads back.</summary>
        private byte[] Backing { get; } = backing;

        /// <summary>Gets the whole backing array as memory.</summary>
        public Memory<byte> Memory => Backing;

        /// <summary>Releases nothing; the array outlives the owner so the test can read it.</summary>
        public void Dispose()
        {
        }
    }

    /// <summary>
    /// Collects the parameter-area carrier the command-HMAC verification was declared over and the one the
    /// decryption step fed back, copying each observation's octets while they are still readable.
    /// </summary>
    private sealed class ParameterAreaObserver: IObserver<TraceEntry<TpmSimulatorState, TpmSimulatorInput>>
    {
        /// <summary>Gets the carrier the command-HMAC verification action carried, or <see langword="null"/> if none was seen.</summary>
        public TpmParameterArea? VerifiedArea { get; private set; }

        /// <summary>Gets the carrier the decryption action was declared over, or <see langword="null"/> if none was seen.</summary>
        public TpmParameterArea? DecryptedArea { get; private set; }

        /// <summary>Gets the octets the verification action's carrier held while cpHash covered them.</summary>
        public byte[] DigestedOctets { get; private set; } = [];

        /// <summary>Gets the authorization value the decryption recovered out of that same carrier.</summary>
        public byte[] RecoveredAuth { get; private set; } = [];

        /// <summary>Records the three observations of interest as the automaton steps through the command.</summary>
        /// <param name="value">The trace entry.</param>
        public void OnNext(TraceEntry<TpmSimulatorState, TpmSimulatorInput> value)
        {
            if(VerifiedArea is null && value.StateAfter.NextAction is TpmVerifyCommandHmacAction verify)
            {
                VerifiedArea = verify.ParameterArea;
                DigestedOctets = verify.ParameterArea.Span.ToArray();
            }

            if(DecryptedArea is null && value.StateAfter.NextAction is TpmDecryptNvDefineAuthAction decrypt)
            {
                DecryptedArea = decrypt.RawParameterArea;
            }

            //The recovered value is read off the decryption's own feedback rather than off the carrier, which
            //the installing transition releases inside the very step this entry reports.
            if(RecoveredAuth.Length == 0 && value.Input is TpmNvDefineAuthDecrypted decrypted)
            {
                RecoveredAuth = decrypted.DecryptedAuth.AsReadOnlySpan().ToArray();
            }
        }

        /// <summary>Ignored; the automaton's trace stream never faults in these proofs.</summary>
        /// <param name="error">The error.</param>
        public void OnError(Exception error)
        {
        }

        /// <summary>Ignored; completion carries no observation.</summary>
        public void OnCompleted()
        {
        }
    }

    /// <summary>Compares two octet sequences for equality.</summary>
    /// <param name="first">The first sequence.</param>
    /// <param name="second">The second sequence.</param>
    /// <returns><see langword="true"/> when both hold the same octets in the same order.</returns>
    private static bool AreEqual(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second) => first.SequenceEqual(second);

    /// <summary>Renders a permanent entity's Name: its 4-octet big-endian handle value (Part 1, clause 13, Table 9).</summary>
    /// <param name="handle">The entity's handle.</param>
    /// <returns>The handle-form Name.</returns>
    private static byte[] HandleFormName(uint handle)
    {
        byte[] name = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(name, handle);

        return name;
    }

    /// <summary>Appends a big-endian <c>UINT32</c> to a command body under construction.</summary>
    /// <param name="body">The body being built.</param>
    /// <param name="value">The value to append.</param>
    private static void AppendUInt32(List<byte> body, uint value)
    {
        Span<byte> octets = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(octets, value);
        body.AddRange(octets);
    }

    /// <summary>Appends a big-endian <c>UINT16</c> to a command body under construction.</summary>
    /// <param name="body">The body being built.</param>
    /// <param name="value">The value to append.</param>
    private static void AppendUInt16(List<byte> body, ushort value)
    {
        Span<byte> octets = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(octets, value);
        body.AddRange(octets);
    }

    /// <summary>
    /// Appends a one-session authorization area carrying a zero-length nonceCaller and a zero-length hmac — the
    /// smallest well-formed <c>TPMS_AUTH_COMMAND</c> (TPM 2.0 Library Part 2, clause 10.12.2, Table 156) — which
    /// is enough for a parse-time proof, since the parse never evaluates the credential.
    /// </summary>
    /// <param name="body">The body being built.</param>
    /// <param name="sessionHandle">The session handle to name.</param>
    private static void AppendAuthorizationArea(List<byte> body, uint sessionHandle)
    {
        var area = new List<byte>();
        AppendUInt32(area, sessionHandle);
        AppendUInt16(area, 0);
        area.Add((byte)TpmaSession.CONTINUE_SESSION);
        AppendUInt16(area, 0);

        AppendUInt32(body, (uint)area.Count);
        body.AddRange(area);
    }

    /// <summary>
    /// Reads a single-session command's authorization area and its parameter octets straight off the wire, so a
    /// proof can recompute what the caller signed without going through the production session code.
    /// </summary>
    /// <param name="command">The command frame as sent.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <returns>The session's caller nonce and supplied hmac, the parameter octets, and the session-attributes octet.</returns>
    private static (byte[] NonceCaller, byte[] Hmac, byte[] Parameters, byte Attributes) ReadCommandSession(ReadOnlySpan<byte> command, int handleCount)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < handleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint authorizationSize = reader.ReadUInt32();
        int authorizationEnd = reader.Position + (int)authorizationSize;

        _ = reader.ReadUInt32();
        ushort nonceSize = reader.ReadUInt16();
        byte[] nonceCaller = reader.ReadBytes(nonceSize).ToArray();
        byte attributes = reader.ReadByte();
        ushort hmacSize = reader.ReadUInt16();
        byte[] hmac = reader.ReadBytes(hmacSize).ToArray();

        Assert.AreEqual(authorizationEnd, reader.Position, "The single session must consume the whole declared authorization area.");

        byte[] parameters = reader.ReadBytes(reader.Remaining).ToArray();

        return (nonceCaller, hmac, parameters, attributes);
    }

    /// <summary>Submits a hand-framed command body and returns the response code alone.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag.</param>
    /// <param name="commandCode">The command code.</param>
    /// <param name="body">Everything after the header.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitFramedAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmStConstants tag, TpmCcConstants commandCode, byte[] body)
    {
        int length = TpmHeader.HeaderSize + body.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)tag, (uint)length, (uint)commandCode);
        header.WriteTo(ref writer);
        writer.WriteBytes(body);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a malformed command rather than fault.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>
    /// Defines an Index with the given attributes under empty owner authorization and returns its Name
    /// (<c>nameAlg ‖ H(TPMS_NV_PUBLIC)</c>, TPM 2.0 Library Part 1, clause 13, Table 9), computed independently of the
    /// simulator so a caller can build cpHash from it.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index attributes.</param>
    /// <param name="data">Octets to write into the Index, or <see langword="null"/> to leave it unwritten.</param>
    /// <returns>The defined Index's Name.</returns>
    private async Task<byte[]> DefineIndexAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, TpmaNv attributes, byte[]? data)
    {
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool);
        using TpmsNvPublic publicInfo = new(nvIndex, SessionAlg, attributes, policyDigest, IndexDataSize);

        {
            using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, Tpm2bAuth.Empty, publicInfo);
            using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
                tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace failed: '{result.ResponseCode}'.");
        }

        if(data is not null)
        {
            bool isOwnerWrite = (attributes & TpmaNv.TPMA_NV_OWNERWRITE) != 0;
            using Tpm2bMaxNvBuffer inputBuffer = Tpm2bMaxNvBuffer.Create(data, pool);
            var input = new NvWriteInput(isOwnerWrite ? (uint)TpmRh.TPM_RH_OWNER : nvIndex, nvIndex, inputBuffer, Offset: 0);
            using TpmPasswordSession writeAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<NvWriteResponse> result = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
                tpm, input, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Write failed: '{result.ResponseCode}'.");
        }

        //The Name is read back from the TPM rather than recomputed, because TPMA_NV_WRITTEN is part of the
        //public area the Name digests and a first write SETs it (TPM 2.0 Library Part 1, clause 34.2.6.3), so a
        //Name taken before the write would no longer name the Index.
        var readPublicInput = new NvReadPublicInput(nvIndex);
        TpmResult<NvReadPublicResponse> readPublic = await TpmCommandExecutor.ExecuteAsync<NvReadPublicResponse>(
            tpm, readPublicInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(readPublic.IsSuccess, $"TPM2_NV_ReadPublic failed: '{readPublic.ResponseCode}'.");

        using NvReadPublicResponse publicArea = readPublic.Value;

        return publicArea.NvName.Span.ToArray();
    }

    /// <summary>Issues an owner-authorized <c>TPM2_NV_DefineSpace()</c> over a session and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The authorizing session.</param>
    /// <param name="ownerName">The owner hierarchy's handle-form Name, cpHash's only Name term here.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <returns>The define result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineOverSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSession session, byte[] ownerName, uint nvIndex)
    {
        using Tpm2bAuth auth = Tpm2bAuth.Create(EncryptedIndexAuth, pool);
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool);
        using TpmsNvPublic publicInfo = new(nvIndex, SessionAlg, SelfAuthorizedAttributes, policyDigest, IndexDataSize);
        using NvDefineSpaceInput input = new(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, input, [session], [ownerName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Loads a sealed object beneath its parent and returns its transient handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent.</param>
    /// <param name="created">The Create response carrying the wrapped object.</param>
    /// <returns>The loaded object's handle and its Name, which cpHash's only term for a later Unseal is.</returns>
    private async Task<(uint Handle, byte[] Name)> LoadAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, CreateResponse created)
    {
        using Tpm2bPublic clonedPublic = ClonePublic(created.OutPublic, pool);
        using var input = new LoadInput(parentHandle, created.OutPrivate, clonedPublic);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<LoadResponse> result = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, input, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_Load failed: '{result.ResponseCode}'.");

        using LoadResponse loaded = result.Value;

        return (loaded.ObjectHandle.Value, loaded.Name.Span.ToArray());
    }

    /// <summary>Re-parses a public area into a fresh carrier so the load owns an instance of its own.</summary>
    /// <param name="source">The public area to clone.</param>
    /// <param name="pool">The memory pool backing the clone.</param>
    /// <returns>The cloned public area.</returns>
    private static Tpm2bPublic ClonePublic(Tpm2bPublic source, BaseMemoryPool pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);

        var reader = new TpmReader(owner.Memory.Span[..size]);

        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>Creates an empty-auth ECC P-256 storage parent in the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateStoragePrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (storage parent) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Starts an unbound, unsalted HMAC session and returns its handle and client-side wrapper.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="symmetric">The symmetric definition to negotiate for parameter encryption, or <see langword="null"/> for none.</param>
    /// <returns>The session handle and the caller-side session.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartUnboundSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtSymDef? symmetric = null)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric)
        {
            SessionAttributes = TpmaSession.CONTINUE_SESSION
        };

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Flushes a transient object or session handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        var input = FlushContextInput.ForHandle(handle);
        TpmResult<FlushContextResponse> result = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_FlushContext failed: '{result.ResponseCode}'.");
    }

    /// <summary>Builds the response codec registry these proofs drive the executor with.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_ReadPublic, TpmResponseCodec.NvReadPublic);
        _ = registry.Register(TpmCcConstants.TPM_CC_Clear, TpmResponseCodec.Clear);
        _ = registry.Register(TpmCcConstants.TPM_CC_ClearControl, TpmResponseCodec.ClearControl);
        _ = registry.Register(TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmResponseCodec.HierarchyChangeAuth);

        return registry;
    }

    /// <summary>Creates a simulator with an ECC signing backend, powers it on, and brings it operational.</summary>
    /// <param name="pool">The memory pool every command runs against.</param>
    /// <param name="tpmId">The simulated TPM's run identifier, unique per test so no meter is shared.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, string tpmId)
    {
        var simulator = new TpmSimulator(tpmId, signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
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
        result.Value.Dispose();
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);

        return simulator;
    }
}
