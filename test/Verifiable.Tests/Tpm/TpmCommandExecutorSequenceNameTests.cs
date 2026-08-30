using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Host-side coverage of the sequence-Name rule <see cref="TpmCommandExecutor"/> applies when it builds the
/// cpHash handle area, and of the command inputs' own declarations that drive it. A sequence object carries no
/// Name a <c>TPM2B_NAME</c> could hold, so its cpHash term is the Empty Buffer — a present, zero-length term the
/// executor derives from <see cref="ITpmCommandInput.HandleIsSequence"/> rather than from the handle value,
/// which cannot distinguish a loaded key from an open sequence.
/// </summary>
/// <remarks>
/// The wire-level cases drive a scripted <see cref="TpmDevice.Create"/> handler that captures the emitted
/// command and answers a header-only error, so the executor stops right after the send. The captured
/// authorization area is then reduced with an independent SHA-256/HMAC oracle
/// (<see cref="SHA256"/>/<see cref="HMACSHA256"/>, used to check the executor's composition, never as the system
/// under test) over <c>cpHash = H(commandCode ‖ Name1 ‖ … ‖ parameters)</c>. Each case also recomputes the HMAC
/// a naive executor that folded the sequence handle's four octets would have produced, so the assertion fails
/// on the wrong term rather than merely agreeing with itself.
/// </remarks>
[TestClass]
internal sealed class TpmCommandExecutorSequenceNameTests
{
    /// <summary>The TPM command and response header: tag (UINT16), size (UINT32), commandCode/responseCode (UINT32).</summary>
    private const int HeaderSize = 10;

    /// <summary><c>TPM_ST_NO_SESSIONS</c>, the tag of the header-only error frame the scripted device answers.</summary>
    private const ushort TpmStNoSessions = 0x8001;

    /// <summary>The handle the canned HMAC session presents; only its <c>TPM_HT_HMAC_SESSION</c> type matters here.</summary>
    private const uint HmacSessionHandle = 0x02000000u;

    /// <summary>The transient handle standing for the open sequence in the wire-level cases.</summary>
    private const uint SequenceHandleValue = 0x80000010u;

    /// <summary>The transient handle standing for the signing or verification key in the two-handle cases.</summary>
    private const uint KeyHandleValue = 0x80000021u;

    /// <summary>The register <c>TPM2_EventSequenceComplete()</c> extends; a PCR handle's Name is its four handle octets.</summary>
    private const uint PcrHandleValue = 7u;

    /// <summary>The hash every session in this class negotiates.</summary>
    private static TpmAlgIdConstants SessionAlg => TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The canned <c>nonceTPM</c> the host session starts from, so the expected HMAC is reproducible.</summary>
    private static byte[] NonceTpmValue
    {
        get
        {
            byte[] nonce = new byte[32];
            for(int i = 0; i < nonce.Length; i++)
            {
                nonce[i] = (byte)(0xC0 ^ i);
            }

            return nonce;
        }
    }

    /// <summary>The sequence's authorization value, the HMAC key of an unbound session with an empty sessionKey.</summary>
    private static byte[] SequenceAuthValue => System.Text.Encoding.UTF8.GetBytes("sequence-secret");

    /// <summary>
    /// A distinct, multi-octet key Name in <c>nameAlg ‖ digest</c> shape (TPM 2.0 Library Part 1, clause 16).
    /// It is an arbitrary test Name; the scripted device does not validate it, and its distinctness makes a
    /// mis-offset concatenation produce a different cpHash.
    /// </summary>
    private static byte[] KeyName
    {
        get
        {
            byte[] name = new byte[2 + 32];
            name[1] = 0x0B; //TPM_ALG_SHA256 = 0x000B.
            for(int i = 0; i < 32; i++)
            {
                name[2 + i] = (byte)(0x40 + i);
            }

            return name;
        }
    }

    /// <summary>The MSTest-supplied per-test context, the source of the cancellation token every await observes.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// <see cref="TpmCommandExecutor"/> folds the Empty Buffer, and nothing else, for
    /// <c>TPM2_SequenceUpdate()</c>'s single <c>@sequenceHandle</c>: "If an authorization or audit of this
    /// command requires computation of a cpHash and an rpHash, the Name associated with sequenceHandle will be
    /// the Empty Buffer"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.7; Part 1: Architecture, clauses 15.7 (equation 15) and
    /// 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task ExecutorDerivesTheEmptyBufferNameForSequenceUpdatesSequenceHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] authValue = SequenceAuthValue;
        byte[] buffer = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] expectedParameters = [0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];

        using SequenceUpdateInput input = SequenceUpdateInput.Create(TpmiDhObject.FromValue(SequenceHandleValue), buffer, pool);
        using TpmSession session = CreateUnboundHmacSession(authValue, pool);

        var captured = await CaptureAuthorizationAsync<SequenceUpdateResponse>(
            input,
            TpmCcConstants.TPM_CC_SequenceUpdate,
            TpmResponseCodec.SequenceUpdate,
            handleCount: 1,
            sessions: [session],
            handleNames: null,
            authorizingSlotIndex: 0,
            pool).ConfigureAwait(false);

        Assert.IsTrue(captured.Parameters.AsSpan().SequenceEqual(expectedParameters),
            "TPM2_SequenceUpdate()'s parameter area is the TPM2B_MAX_BUFFER alone (Table 91).");

        AssertSequenceNameIsTheEmptyBuffer(
            captured,
            authValue,
            derivedNames: [],
            naiveNames: [HandleOctets(SequenceHandleValue)],
            "TPM2_SequenceUpdate()");
    }

    /// <summary>
    /// <see cref="TpmCommandExecutor"/> folds the Empty Buffer for <c>TPM2_SequenceComplete()</c>'s
    /// <c>@sequenceHandle</c>, the same rule every sequence object carries: "If an authorization or audit for a
    /// sequence object requires computation of a cpHash and an rpHash, the Name associated with the sequence
    /// object will be the Empty Buffer"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 29.4.6; Part 3: Commands, clause 17.8, Table 93).
    /// </summary>
    [TestMethod]
    public async Task ExecutorDerivesTheEmptyBufferNameForSequenceCompletesSequenceHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] authValue = SequenceAuthValue;
        byte[] buffer = [0x01, 0x02];

        //buffer (TPM2B_MAX_BUFFER) then hierarchy (TPMI_RH_HIERARCHY = TPM_RH_OWNER, 0x40000001).
        byte[] expectedParameters = [0x00, 0x02, 0x01, 0x02, 0x40, 0x00, 0x00, 0x01];

        using SequenceCompleteInput input = SequenceCompleteInput.Create(
            TpmiDhObject.FromValue(SequenceHandleValue), buffer, TpmiRhHierarchy.Owner, pool);
        using TpmSession session = CreateUnboundHmacSession(authValue, pool);

        var captured = await CaptureAuthorizationAsync<SequenceCompleteResponse>(
            input,
            TpmCcConstants.TPM_CC_SequenceComplete,
            TpmResponseCodec.SequenceComplete,
            handleCount: 1,
            sessions: [session],
            handleNames: null,
            authorizingSlotIndex: 0,
            pool).ConfigureAwait(false);

        Assert.IsTrue(captured.Parameters.AsSpan().SequenceEqual(expectedParameters),
            "TPM2_SequenceComplete()'s parameter area is buffer then hierarchy (Table 93).");

        AssertSequenceNameIsTheEmptyBuffer(
            captured,
            authValue,
            derivedNames: [],
            naiveNames: [HandleOctets(SequenceHandleValue)],
            "TPM2_SequenceComplete()");
    }

    /// <summary>
    /// <see cref="TpmCommandExecutor"/> folds <c>@pcrHandle</c>'s four handle octets and then the Empty Buffer
    /// for <c>@sequenceHandle</c>, in handle order: a PCR handle's Name is its handle value while the sequence
    /// beside it contributes no octets
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.9, Table 95; Part 1: Architecture, clauses 15.7
    /// (equation 15) and 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task ExecutorDerivesTheEmptyBufferNameForEventSequenceCompletesSequenceHandleAfterThePcrHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] authValue = SequenceAuthValue;
        byte[] buffer = [0xAA, 0xBB, 0xCC];
        byte[] expectedParameters = [0x00, 0x03, 0xAA, 0xBB, 0xCC];

        using EventSequenceCompleteInput input = EventSequenceCompleteInput.Create(
            TpmiDhPcr.FromValue(PcrHandleValue), TpmiDhObject.FromValue(SequenceHandleValue), buffer, pool);

        //Table 95 authorizes @pcrHandle first (the PC Client PCR's EmptyAuth, a TPM_RS_PW slot) and
        //@sequenceHandle second, so the HMAC session sits at slot 1.
        using TpmPasswordSession pcrAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmSession session = CreateUnboundHmacSession(authValue, pool);

        var captured = await CaptureAuthorizationAsync<EventSequenceCompleteResponse>(
            input,
            TpmCcConstants.TPM_CC_EventSequenceComplete,
            TpmResponseCodec.EventSequenceComplete,
            handleCount: 2,
            sessions: [pcrAuth, session],
            handleNames: null,
            authorizingSlotIndex: 1,
            pool).ConfigureAwait(false);

        Assert.IsTrue(captured.Parameters.AsSpan().SequenceEqual(expectedParameters),
            "TPM2_EventSequenceComplete()'s parameter area is the TPM2B_MAX_BUFFER alone (Table 95).");

        AssertSequenceNameIsTheEmptyBuffer(
            captured,
            authValue,
            derivedNames: [HandleOctets(PcrHandleValue)],
            naiveNames: [HandleOctets(PcrHandleValue), HandleOctets(SequenceHandleValue)],
            "TPM2_EventSequenceComplete()");
    }

    /// <summary>
    /// <see cref="TpmCommandExecutor"/> folds the Empty Buffer for <c>@sequenceHandle</c> and then the caller's
    /// key Name for <c>@keyHandle</c>, in handle order, so the sequence's zero-length term precedes a term that
    /// only the caller can supply
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6, Table 124; Part 1: Architecture, clauses 15.7
    /// (equation 15) and 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task ExecutorDerivesTheEmptyBufferNameForSignSequenceCompletesSequenceHandleBesideTheKeyName()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] authValue = SequenceAuthValue;
        byte[] keyName = KeyName;
        byte[] buffer = [0x10, 0x20, 0x30, 0x40, 0x50];
        byte[] expectedParameters = [0x00, 0x05, 0x10, 0x20, 0x30, 0x40, 0x50];

        using SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(
            TpmiDhObject.FromValue(SequenceHandleValue), TpmiDhObject.FromValue(KeyHandleValue), buffer, pool);

        //Table 124 authorizes @sequenceHandle first and @keyHandle second, so the HMAC session sits at slot 0
        //and the key's own authorization travels in the TPM_RS_PW slot beside it.
        using TpmSession session = CreateUnboundHmacSession(authValue, pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        ReadOnlyMemory<byte>[] handleNames = [ReadOnlyMemory<byte>.Empty, keyName];

        var captured = await CaptureAuthorizationAsync<SignSequenceCompleteResponse>(
            input,
            TpmCcConstants.TPM_CC_SignSequenceComplete,
            TpmResponseCodec.SignSequenceComplete,
            handleCount: 2,
            sessions: [session, keyAuth],
            handleNames: handleNames,
            authorizingSlotIndex: 0,
            pool).ConfigureAwait(false);

        Assert.IsTrue(captured.Parameters.AsSpan().SequenceEqual(expectedParameters),
            "TPM2_SignSequenceComplete()'s parameter area is the TPM2B_MAX_BUFFER alone (Table 124).");

        AssertSequenceNameIsTheEmptyBuffer(
            captured,
            authValue,
            derivedNames: [keyName],
            naiveNames: [HandleOctets(SequenceHandleValue), keyName],
            "TPM2_SignSequenceComplete()");
    }

    /// <summary>
    /// <see cref="TpmCommandExecutor"/> folds the Empty Buffer for <c>@sequenceHandle</c> and then the key Name
    /// for the unauthorized <c>keyHandle</c>: equation 15 covers every handle of the handle area, authorized or
    /// not, so a handle carrying Auth Index None is still a cpHash term
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3, Table 118; Part 1: Architecture, clauses 15.7
    /// (equation 15) and 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task ExecutorDerivesTheEmptyBufferNameForVerifySequenceCompletesSequenceHandleBesideTheKeyName()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] authValue = SequenceAuthValue;
        byte[] keyName = KeyName;

        byte[] hmacDigest = new byte[32];
        for(int i = 0; i < hmacDigest.Length; i++)
        {
            hmacDigest[i] = (byte)(0x70 + i);
        }

        //signature (TPMT_SIGNATURE): sigAlg = TPM_ALG_HMAC (0x0005), then the TPMT_HA's hashAlg = TPM_ALG_SHA256
        //(0x000B) and its unsized digest (Part 2, clause 10.2.2, Table 89).
        byte[] expectedParameters = Concat([0x00, 0x05], [0x00, 0x0B], hmacDigest);

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.Create(
            TpmiDhObject.FromValue(SequenceHandleValue),
            TpmiDhObject.FromValue(KeyHandleValue),
            hmacDigest,
            TpmAlgIdConstants.TPM_ALG_HMAC,
            TpmAlgIdConstants.TPM_ALG_SHA256,
            pool);

        using TpmSession session = CreateUnboundHmacSession(authValue, pool);
        ReadOnlyMemory<byte>[] handleNames = [ReadOnlyMemory<byte>.Empty, keyName];

        var captured = await CaptureAuthorizationAsync<VerifySequenceCompleteResponse>(
            input,
            TpmCcConstants.TPM_CC_VerifySequenceComplete,
            TpmResponseCodec.VerifySequenceComplete,
            handleCount: 2,
            sessions: [session],
            handleNames: handleNames,
            authorizingSlotIndex: 0,
            pool).ConfigureAwait(false);

        Assert.IsTrue(captured.Parameters.AsSpan().SequenceEqual(expectedParameters),
            "TPM2_VerifySequenceComplete()'s parameter area is the TPMT_SIGNATURE alone (Table 118).");

        AssertSequenceNameIsTheEmptyBuffer(
            captured,
            authValue,
            derivedNames: [keyName],
            naiveNames: [HandleOctets(SequenceHandleValue), keyName],
            "TPM2_VerifySequenceComplete()");
    }

    /// <summary>
    /// A Name supplied for a handle the input declares as a sequence is refused with an
    /// <see cref="ArgumentException"/> naming <c>handleNames</c>, never silently ignored: the sequence's cpHash
    /// term is the Empty Buffer by definition, so folding caller-supplied octets there would build a cpHash the
    /// TPM never computes
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 29.4.6; Part 3: Commands, clause 17.7).
    /// </summary>
    [TestMethod]
    public async Task ExecutorRefusesACallerSuppliedNameForADeclaredSequenceHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            BaseMemoryPool handlerPool,
            CancellationToken cancellationToken)
        {
            Assert.Fail("The device must not be invoked when a Name is supplied for a declared sequence handle.");

            return ValueTask.FromResult(TpmResult<TpmResponse>.TransportError(0u));
        }

        using var device = TpmDevice.Create(Handler);
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceUpdate, TpmResponseCodec.SequenceUpdate);

        using SequenceUpdateInput input = SequenceUpdateInput.Create(
            TpmiDhObject.FromValue(SequenceHandleValue), [0x01], pool);
        using TpmSession session = CreateUnboundHmacSession(SequenceAuthValue, pool);

        //A plausible-looking sequence "Name" the caller might compute from the handle value.
        ReadOnlyMemory<byte>[] handleNames = [HandleOctets(SequenceHandleValue)];

        ArgumentException thrown = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
                device, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual("handleNames", thrown.ParamName,
            "The refusal must name the handleNames argument that carried the offending Name.");
    }

    /// <summary>
    /// A transient handle the input does NOT declare a sequence still demands its Name: an object's Name is
    /// <c>nameAlg ‖ H(publicArea)</c>, a value only the caller holds, so the Empty-Buffer derivation is scoped
    /// to declared sequence positions alone and the key beside one is refused without its Name
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 13, Table 9 and its footnote (1), and clause 15.7,
    /// equation 15; Part 3: Commands, clause 20.6, Table 124).
    /// </summary>
    [TestMethod]
    public async Task ExecutorStillRequiresANameForATransientHandleThatIsNotADeclaredSequence()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            BaseMemoryPool handlerPool,
            CancellationToken cancellationToken)
        {
            Assert.Fail("The device must not be invoked when a required object Name is missing.");

            return ValueTask.FromResult(TpmResult<TpmResponse>.TransportError(0u));
        }

        using var device = TpmDevice.Create(Handler);
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceComplete, TpmResponseCodec.SignSequenceComplete);

        using SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(
            TpmiDhObject.FromValue(SequenceHandleValue), TpmiDhObject.FromValue(KeyHandleValue), [0x01], pool);
        using TpmSession session = CreateUnboundHmacSession(SequenceAuthValue, pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);

        //Position 0 is a declared sequence, so its empty entry is derived; position 1 is a key, so its empty
        //entry is a missing Name.
        ReadOnlyMemory<byte>[] handleNames = [ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty];

        ArgumentException thrown = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
                device, input, [session, keyAuth], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual("handleNames", thrown.ParamName,
            "The refusal must name the handleNames argument the key's Name was missing from.");
    }

    /// <summary>
    /// <see cref="SequenceUpdateInput"/> declares its only handle, <c>@sequenceHandle</c> at position 0, a
    /// sequence, and no other position
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.7, Table 91).
    /// </summary>
    [TestMethod]
    public void SequenceUpdateInputDeclaresOnlyItsFirstHandleASequence()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using SequenceUpdateInput input = SequenceUpdateInput.Create(TpmiDhObject.FromValue(SequenceHandleValue), [0x01], pool);

        Assert.IsTrue(input.HandleIsSequence(0), "Table 91's only handle is @sequenceHandle.");
        Assert.IsFalse(input.HandleIsSequence(1), "Table 91 has no second handle, so no later position is a sequence.");
    }

    /// <summary>
    /// <see cref="SequenceCompleteInput"/> declares its only handle, <c>@sequenceHandle</c> at position 0, a
    /// sequence, and no other position
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.8, Table 93).
    /// </summary>
    [TestMethod]
    public void SequenceCompleteInputDeclaresOnlyItsFirstHandleASequence()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using SequenceCompleteInput input = SequenceCompleteInput.Create(
            TpmiDhObject.FromValue(SequenceHandleValue), [0x01], TpmiRhHierarchy.Owner, pool);

        Assert.IsTrue(input.HandleIsSequence(0), "Table 93's only handle is @sequenceHandle.");
        Assert.IsFalse(input.HandleIsSequence(1), "Table 93 has no second handle, so no later position is a sequence.");
    }

    /// <summary>
    /// <see cref="EventSequenceCompleteInput"/> declares position 1 a sequence and position 0 not: Table 95's
    /// handle area is <c>@pcrHandle</c> first, <c>@sequenceHandle</c> second, and a PCR handle's Name is its own
    /// handle octets
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.9, Table 95).
    /// </summary>
    [TestMethod]
    public void EventSequenceCompleteInputDeclaresOnlyItsSecondHandleASequence()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using EventSequenceCompleteInput input = EventSequenceCompleteInput.Create(
            TpmiDhPcr.FromValue(PcrHandleValue), TpmiDhObject.FromValue(SequenceHandleValue), [0x01], pool);

        Assert.IsFalse(input.HandleIsSequence(0), "Table 95's first handle is @pcrHandle, whose Name is its handle value.");
        Assert.IsTrue(input.HandleIsSequence(1), "Table 95's second handle is @sequenceHandle.");
    }

    /// <summary>
    /// <see cref="SignSequenceCompleteInput"/> declares position 0 a sequence and position 1 not: Table 124's
    /// handle area is <c>@sequenceHandle</c> first, <c>@keyHandle</c> second, and the key's Name is the caller's
    /// to supply
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6, Table 124).
    /// </summary>
    [TestMethod]
    public void SignSequenceCompleteInputDeclaresOnlyItsFirstHandleASequence()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(
            TpmiDhObject.FromValue(SequenceHandleValue), TpmiDhObject.FromValue(KeyHandleValue), [0x01], pool);

        Assert.IsTrue(input.HandleIsSequence(0), "Table 124's first handle is @sequenceHandle.");
        Assert.IsFalse(input.HandleIsSequence(1), "Table 124's second handle is @keyHandle, an object with a real Name.");
    }

    /// <summary>
    /// <see cref="VerifySequenceCompleteInput"/> declares position 0 a sequence and position 1 not: Table 118's
    /// handle area is <c>@sequenceHandle</c> first, <c>keyHandle</c> second, and the unauthorized key still
    /// contributes its real Name to cpHash
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3, Table 118).
    /// </summary>
    [TestMethod]
    public void VerifySequenceCompleteInputDeclaresOnlyItsFirstHandleASequence()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            TpmiDhObject.FromValue(SequenceHandleValue), TpmiDhObject.FromValue(KeyHandleValue), new byte[64], TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        Assert.IsTrue(input.HandleIsSequence(0), "Table 118's first handle is @sequenceHandle.");
        Assert.IsFalse(input.HandleIsSequence(1), "Table 118's second handle is keyHandle, an object with a real Name.");
    }

    /// <summary>
    /// A command whose handles are all real entities leaves <see cref="ITpmCommandInput.HandleIsSequence"/> at
    /// its interface default of <see langword="false"/>, so <c>TPM2_Sign()</c>'s <c>@keyHandle</c> keeps
    /// demanding the key's Name rather than silently hashing nothing
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.5, Table 122; Part 1: Architecture, clause 15.7,
    /// equation 15).
    /// </summary>
    [TestMethod]
    public void SignInputDeclaresNoHandleASequence()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using SignInput input = SignInput.ForEcdsa(TpmiDhObject.FromValue(KeyHandleValue), new byte[32], TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        ITpmCommandInput declaration = input;
        Assert.IsFalse(declaration.HandleIsSequence(0), "TPM2_Sign()'s @keyHandle is a key, never a sequence.");
        Assert.IsFalse(declaration.HandleIsSequence(1), "TPM2_Sign() has no second handle.");
    }

    /// <summary>
    /// <c>TPM2_VerifySequenceComplete()</c>'s first parameter <c>signature</c> is a <c>TPMT_SIGNATURE</c>, a
    /// tagged union with no leading size field, so it is not eligible for session-based parameter encryption —
    /// only a first parameter that "has a size field" is
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clauses 18.1 and 15.4; Part 3: Commands, clause 20.3,
    /// Table 118).
    /// </summary>
    [TestMethod]
    public void VerifySequenceCompleteInputDeclaresItsSignatureParameterNotEncryptable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            TpmiDhObject.FromValue(SequenceHandleValue), TpmiDhObject.FromValue(KeyHandleValue), new byte[64], TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        Assert.IsFalse(input.FirstCommandParameterIsEncryptable,
            "Table 118's first parameter signature is a TPMT_SIGNATURE, which carries no size field.");
    }

    /// <summary>
    /// The Empty Buffer the host derives is the term a TPM actually computes: a <c>TPM2_SequenceUpdate()</c>
    /// authorized by a real HMAC session over an open HMAC sequence succeeds end to end against the in-house
    /// simulator, whose own cpHash uses the sequence object's Empty-Buffer Name; the session then verifies the
    /// response authorization, so both directions agree on the term
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.7; Part 1: Architecture, clause 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task SimulatorAcceptsTheEmptyBufferNameTheExecutorDerivesForASequenceUpdateOverAnHmacSession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] sequenceAuth = SequenceAuthValue;

        using var simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SimulatorAcceptsTheEmptyBufferNameTheExecutorDerivesForASequenceUpdateOverAnHmacSession), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(
            tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, new byte[32], TpmAlgIdConstants.TPM_ALG_SHA256,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacStartResponse> startResult = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256, ReadOnlyMemory<byte>.Empty, sequenceAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"TPM2_HMAC_Start() must open the sequence: '{startResult.ResponseCode}'.");
        HmacStartResponse sequence = startResult.Value;

        StartAuthSessionInput sessionInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg);
        TpmResult<StartAuthSessionResponse> sessionResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, sessionInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(sessionResult.IsSuccess, $"StartAuthSession (unbound HMAC) must succeed: '{sessionResult.ResponseCode}'.");
        StartAuthSessionResponse started = sessionResult.Value;

        using var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, pool);
        session.SetAuthValue(sequenceAuth, pool);

        try
        {
            using SequenceUpdateInput updateInput = SequenceUpdateInput.Create(sequence.SequenceHandle, [0x61, 0x62, 0x63], pool);
            TpmResult<SequenceUpdateResponse> updateResult = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
                tpm, updateInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(updateResult.IsSuccess,
                $"TPM2_SequenceUpdate() over an HMAC session must succeed with the sequence's Empty-Buffer Name in cpHash: '{updateResult.ResponseCode}'.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequence.SequenceHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, started.SessionHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, key.Handle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Asserts that the captured command authorization HMAC equals the one an independent oracle computes over
    /// a cpHash whose sequence-handle term contributes no octets, and that it differs from the one a naive
    /// executor folding the sequence handle's four octets would have produced.
    /// </summary>
    /// <param name="captured">The captured command terms.</param>
    /// <param name="authValue">The authorization value keying the unbound session's HMAC.</param>
    /// <param name="derivedNames">The handle-area Name terms with the sequence contributing nothing, in handle order.</param>
    /// <param name="naiveNames">The same terms with the sequence handle's octets folded in its place.</param>
    /// <param name="commandLabel">The command's name, for the assertion messages.</param>
    private static void AssertSequenceNameIsTheEmptyBuffer(
        (byte[] CommandCode, byte[] NonceCaller, byte Attributes, byte[] Hmac, byte[] Parameters) captured,
        byte[] authValue,
        byte[][] derivedNames,
        byte[][] naiveNames,
        string commandLabel)
    {
        byte[] expected = ExpectedAuthHmac(
            authValue,
            Concat([captured.CommandCode, .. derivedNames, captured.Parameters]),
            captured.NonceCaller,
            NonceTpmValue,
            captured.Attributes);

        Assert.IsTrue(captured.Hmac.AsSpan().SequenceEqual(expected),
            $"{commandLabel}'s command HMAC must be computed over cpHash = H(commandCode || names || parameters) with the sequence handle's Name contributing no octets.");

        byte[] naive = ExpectedAuthHmac(
            authValue,
            Concat([captured.CommandCode, .. naiveNames, captured.Parameters]),
            captured.NonceCaller,
            NonceTpmValue,
            captured.Attributes);

        Assert.IsFalse(captured.Hmac.AsSpan().SequenceEqual(naive),
            $"{commandLabel}'s command HMAC must NOT be the one produced by folding the sequence handle's four octets as its Name.");
    }

    /// <summary>
    /// Drives one command through a scripted device that captures the emitted frame and answers a header-only
    /// error, so execution stops right after the send, then splits the captured command into the terms the
    /// command authorization HMAC was computed over.
    /// </summary>
    /// <typeparam name="TResponse">The command's response type, never parsed because the scripted answer is an error.</typeparam>
    /// <param name="input">The command input under test.</param>
    /// <param name="commandCode">The command code the codec registers under.</param>
    /// <param name="codec">The response codec, present only so the executor's fail-fast lookup succeeds.</param>
    /// <param name="handleCount">The command's handle count, which fixes the authorization area's offset.</param>
    /// <param name="sessions">The authorization sessions, in slot order.</param>
    /// <param name="handleNames">The caller-supplied per-handle Names, or <see langword="null"/>.</param>
    /// <param name="authorizingSlotIndex">The slot whose terms are returned.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command code, the caller nonce, the session attributes, the auth HMAC, and the parameter area, all as sent.</returns>
    private async Task<(byte[] CommandCode, byte[] NonceCaller, byte Attributes, byte[] Hmac, byte[] Parameters)> CaptureAuthorizationAsync<TResponse>(
        ITpmCommandInput input,
        TpmCcConstants commandCode,
        TpmResponseCodec codec,
        int handleCount,
        IReadOnlyList<TpmSessionBase> sessions,
        IReadOnlyList<ReadOnlyMemory<byte>>? handleNames,
        int authorizingSlotIndex,
        BaseMemoryPool pool)
        where TResponse : ITpmWireType
    {
        byte[]? observed = null;

        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            BaseMemoryPool handlerPool,
            CancellationToken cancellationToken)
        {
            observed = command.ToArray();

            return ValueTask.FromResult(SuccessFrame(BuildHeaderOnlyErrorFrame((uint)TpmRcConstants.TPM_RC_VALUE), handlerPool));
        }

        using var device = TpmDevice.Create(Handler);
        var registry = new TpmResponseRegistry();
        _ = registry.Register(commandCode, codec);

        TpmResult<TResponse> result = await TpmCommandExecutor.ExecuteAsync<TResponse>(
            device, input, sessions, handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTpmError, "The scripted error must surface so execution stops after the command is captured.");
        Assert.IsNotNull(observed);

        //Command layout: header(tag, size, commandCode) + handles + authorizationSize + slots + parameters.
        var reader = new TpmReader(observed);
        _ = reader.ReadUInt16();
        _ = reader.ReadUInt32();
        uint sentCommandCode = reader.ReadUInt32();
        for(int i = 0; i < handleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint authorizationSize = reader.ReadUInt32();

        byte[] nonceCaller = [];
        byte attributes = 0;
        byte[] hmac = [];
        for(int slot = 0; slot <= authorizingSlotIndex; slot++)
        {
            _ = reader.ReadUInt32();
            nonceCaller = reader.ReadTpm2b().ToArray();
            attributes = reader.ReadByte();
            hmac = reader.ReadTpm2b().ToArray();
        }

        int parameterOffset = HeaderSize + (handleCount * sizeof(uint)) + sizeof(uint) + (int)authorizationSize;
        byte[] parameters = observed[parameterOffset..];
        byte[] commandCodeOctets =
        [
            (byte)(sentCommandCode >> 24),
            (byte)(sentCommandCode >> 16),
            (byte)(sentCommandCode >> 8),
            (byte)sentCommandCode
        ];

        return (commandCodeOctets, nonceCaller, attributes, hmac, parameters);
    }

    /// <summary>
    /// Builds the host-side unbound, unsalted HMAC session the wire-level cases authorize with: its sessionKey
    /// is empty ("If both tpmKey and bind are TPM_RH_NULL, then sessionKey is set to an Empty Buffer", TPM 2.0
    /// Library Part 1, clause 16.6.8), so equation 17's key <c>sessionKey ‖ authValue</c> reduces to the entity's
    /// authorization value alone (clause 16.6.5).
    /// </summary>
    /// <param name="authValue">The authorized entity's authorization value.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The canned nonceTPM ownership transfers to the TpmSession the caller disposes.")]
    private static TpmSession CreateUnboundHmacSession(ReadOnlySpan<byte> authValue, BaseMemoryPool pool)
    {
        Tpm2bNonce nonceTpm = Tpm2bNonce.Create(NonceTpmValue, pool);
        var session = new TpmSession(new TpmHandle(HmacSessionHandle), nonceTpm, SessionAlg, pool);
        session.SetAuthValue(authValue, pool);

        return session;
    }

    /// <summary>
    /// Recomputes the expected command authorization HMAC with an independent oracle
    /// (<see cref="SHA256"/>/<see cref="HMACSHA256"/>, used only to verify the executor's composition, not as
    /// the system under test). cpHash is SHA-256 over <paramref name="cpHashInput"/>; for an unbound session
    /// with an empty sessionKey the HMAC key is the authorization value alone, and the HMAC'd data is
    /// <c>cpHash ‖ nonceCaller ‖ nonceTPM ‖ sessionAttributes</c>.
    /// </summary>
    /// <param name="authValue">The authorized entity's authorization value.</param>
    /// <param name="cpHashInput">The octets cpHash is taken over.</param>
    /// <param name="nonceCaller">The caller nonce the executor generated and sent.</param>
    /// <param name="nonceTpm">The session's current TPM nonce.</param>
    /// <param name="attributes">The session attributes octet as sent.</param>
    /// <returns>The expected authorization HMAC.</returns>
    private static byte[] ExpectedAuthHmac(byte[] authValue, byte[] cpHashInput, byte[] nonceCaller, byte[] nonceTpm, byte attributes)
    {
        byte[] cpHash = SHA256.HashData(cpHashInput);
        byte[] data = Concat([cpHash, nonceCaller, nonceTpm, [attributes]]);

        return HMACSHA256.HashData(authValue, data);
    }

    /// <summary>The four big-endian octets of a handle value, the Name a naive executor would fold for a sequence.</summary>
    /// <param name="handle">The handle value.</param>
    /// <returns>The handle's four octets.</returns>
    private static byte[] HandleOctets(uint handle)
    {
        return [(byte)(handle >> 24), (byte)(handle >> 16), (byte)(handle >> 8), (byte)handle];
    }

    /// <summary>Concatenates the given octet runs in order.</summary>
    /// <param name="parts">The runs to concatenate.</param>
    /// <returns>The concatenation.</returns>
    private static byte[] Concat(params byte[][] parts)
    {
        int length = 0;
        foreach(byte[] part in parts)
        {
            length += part.Length;
        }

        byte[] result = new byte[length];
        int offset = 0;
        foreach(byte[] part in parts)
        {
            part.CopyTo(result, offset);
            offset += part.Length;
        }

        return result;
    }

    /// <summary>Frames a header-only <c>TPM_ST_NO_SESSIONS</c> response carrying the given response code.</summary>
    /// <param name="responseCode">The response code the scripted device answers.</param>
    /// <returns>The framed response.</returns>
    private static byte[] BuildHeaderOnlyErrorFrame(uint responseCode)
    {
        byte[] frame = new byte[HeaderSize];
        frame[0] = (byte)(TpmStNoSessions >> 8);
        frame[1] = (byte)(TpmStNoSessions & 0xFF);
        frame[2] = (byte)(HeaderSize >> 24);
        frame[3] = (byte)(HeaderSize >> 16);
        frame[4] = (byte)(HeaderSize >> 8);
        frame[5] = (byte)(HeaderSize & 0xFF);
        frame[6] = (byte)(responseCode >> 24);
        frame[7] = (byte)(responseCode >> 16);
        frame[8] = (byte)(responseCode >> 8);
        frame[9] = (byte)(responseCode & 0xFF);

        return frame;
    }

    /// <summary>Wraps the given octets as a successful transport read the executor then parses.</summary>
    /// <param name="bytes">The framed response octets.</param>
    /// <param name="pool">The memory pool the response is rented from.</param>
    /// <returns>The transport result.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The TpmResponse is owned by the returned TpmResult and disposed by the executor under test.")]
    private static TpmResult<TpmResponse> SuccessFrame(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return TpmResult<TpmResponse>.Success(new TpmResponse(owner, bytes.Length));
    }
}
