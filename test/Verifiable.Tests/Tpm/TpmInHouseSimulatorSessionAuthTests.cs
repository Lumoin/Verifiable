using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives command-side session-HMAC verification against the in-house behavioural <see cref="TpmSimulator"/> —
/// entirely in-process, with no external assets — through the same production command path the production code
/// uses (<see cref="TpmCommandExecutor"/> with the real <see cref="GetRandomInput"/>, <see cref="CreateInput"/>,
/// <see cref="UnsealInput"/>, <see cref="TpmSession"/>, and the real response codecs): <c>TPM2_GetRandom()</c> and
/// <c>TPM2_Unseal()</c> over a bound HMAC session now have their command HMAC genuinely verified (TPM 2.0 Library
/// Part 1, clauses 18.7 and 19.6; Part 3, clause 5.6), where before this wave the field parsed and was discarded.
/// </summary>
/// <remarks>
/// <para>
/// Every negative test is proven non-vacuous: a deliberately WRONG HMAC, a stale replayed nonce, or a wrong
/// authorization value is rejected, and the SAME bytes with the correct value are accepted — the bar the
/// parameter-encryption tests already set (<see cref="TpmInHouseSimulatorParameterEncryptionTests"/>).
/// </para>
/// <para>
/// One test recomputes the expected command HMAC independently — <c>KDFa</c> (Part 1, clause 11.4.10.2) and the
/// HMAC itself (clause 19.6.5, equation 17) composed by hand, field by field, through the project's own
/// <c>Kdfa</c> and registered digest/HMAC seam — from the raw wire bytes a genuine <see cref="TpmSession"/> sent,
/// proving the simulator's accept path against an independently-assembled transcription. Independence is at the
/// composition level (this test builds the message itself and compares to what the simulator accepted), not the
/// primitive level: the underlying KDFa/HMAC primitives are proven separately by their own known-answer tests.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorSessionAuthTests
{
    /// <summary>The session/name hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The digest width, in octets, of <see cref="SessionAlg"/>.</summary>
    private const int DigestSize = 32;

    /// <summary>The fixed secret sealed and recovered by the Unseal-over-HMAC-session tests.</summary>
    private static byte[] SecretBytes { get; } = "Session-authorized secret."u8.ToArray();

    /// <summary>The correct authValue assigned to a sealed object under test.</summary>
    private static byte[] CorrectUserAuth { get; } = [0x11, 0x22, 0x33, 0x44];

    /// <summary>A wrong authValue, distinct from <see cref="CorrectUserAuth"/>.</summary>
    private static byte[] WrongUserAuth { get; } = [0x99, 0x99, 0x99, 0x99];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task TamperedGetRandomHmacIsRejectedWithSessionEncodedBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateGetRandomRegistry();

        using CreatePrimaryResponse bindObject = await CreateSigningBindObjectAsync(tpm, registry, pool).ConfigureAwait(false);
        uint objectHandle = bindObject.ObjectHandle.Value;

        try
        {
            (uint sessionHandle, TpmSession session, _, _) = await StartBoundHmacSessionAsync(tpm, registry, pool, objectHandle, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
            using(session)
            {
                //GetRandom authorizes no entity (no @-handle), so its lone session MUST set at least one of
                //decrypt/encrypt/audit (Part 3, clause 5.5) or the session area itself is rejected before any HMAC
                //is evaluated; set encrypt (GetRandom's own randomBytes response parameter is a sized TPM2B,
                //eligible for response encryption) so this test still reaches — and proves — the HMAC-tamper check.
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                try
                {
                    //A one-byte-flipping submit wrapper applied ONLY to this final GetRandom command: the LAST
                    //byte (the final octet of the session's hmac field, since bytesRequested is the fixed 2-byte
                    //tail) is corrupted before it reaches the simulator, proving the mechanism actually gates
                    //something rather than accepting anything.
                    byte[]? lastCommand = null;
                    async ValueTask<TpmResult<TpmResponse>> TamperLastHmacByteAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, System.Threading.CancellationToken ct)
                    {
                        byte[] mutable = command.ToArray();
                        lastCommand = mutable;

                        int hmacByteIndex = mutable.Length - 1 - sizeof(ushort);
                        mutable[hmacByteIndex] ^= 0xFF;

                        return await simulator.SubmitAsync(mutable, commandPool, ct).ConfigureAwait(false);
                    }

                    using TpmDevice tamperingDevice = TpmDevice.Create(TamperLastHmacByteAsync);
                    var getRandomInput = new GetRandomInput(16);

                    TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                        tamperingDevice, getRandomInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsFalse(result.IsSuccess, "A tampered command HMAC must be rejected.");
                    Assert.AreEqual(
                        SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
                        "GetRandom authorizes no entity, so a tampered HMAC must reject with the session-index-encoded TPM_RC_BAD_AUTH (no DA counter involved).");
                    Assert.IsNotNull(lastCommand, "The tampering wrapper must have observed the outgoing command.");
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, objectHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task ZeroLengthHmacOnABoundSessionIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateGetRandomRegistry();

        using CreatePrimaryResponse bindObject = await CreateSigningBindObjectAsync(tpm, registry, pool).ConfigureAwait(false);
        uint objectHandle = bindObject.ObjectHandle.Value;

        try
        {
            (uint sessionHandle, TpmSession session, _, _) = await StartBoundHmacSessionAsync(tpm, registry, pool, objectHandle, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
            using(session)
            {
                //GetRandom authorizes no entity, so its lone session MUST set at least one of decrypt/encrypt/audit
                //(Part 3, clause 5.5) or the session area itself is rejected before this test's own zero-length-hmac
                //mechanism is ever reached; set encrypt so the rejection asserted below is the one this test names.
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                try
                {
                    //A submit wrapper applied ONLY to this final GetRandom command, zeroing its hmac TPM2B's size
                    //field (navigated to from the front, since its offset depends on nonceCaller's actual size).
                    async ValueTask<TpmResult<TpmResponse>> ZeroTheHmacAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, System.Threading.CancellationToken ct)
                    {
                        byte[] mutable = command.ToArray();

                        var reader = new TpmReader(mutable);
                        _ = TpmHeader.Parse(ref reader);
                        uint oldAuthorizationSize = reader.ReadUInt32(); //authorizationSize.
                        _ = reader.ReadUInt32(); //sessionHandle.
                        ushort nonceSize = reader.ReadUInt16();
                        reader.Skip(nonceSize);
                        _ = reader.ReadByte(); //sessionAttributes.

                        int hmacSizeFieldIndex = reader.Consumed;
                        ushort oldHmacLength = BinaryPrimitives.ReadUInt16BigEndian(mutable.AsSpan(hmacSizeFieldIndex));

                        //Overwrite the hmac TPM2B's size field with zero, truncating the command so the (now
                        //zero-length) hmac field carries no octets — the exact wire shape of a caller sending an
                        //empty hmac. Whatever follows (bytesRequested) is shifted down to close the gap.
                        byte[] rewritten = new byte[mutable.Length - oldHmacLength];
                        Array.Copy(mutable, 0, rewritten, 0, hmacSizeFieldIndex);
                        BinaryPrimitives.WriteUInt16BigEndian(rewritten.AsSpan(hmacSizeFieldIndex), 0);

                        int tailStart = hmacSizeFieldIndex + sizeof(ushort) + oldHmacLength;
                        int tailLength = mutable.Length - tailStart;
                        Array.Copy(mutable, tailStart, rewritten, hmacSizeFieldIndex + sizeof(ushort), tailLength);

                        //Fix up commandSize (the UINT32 immediately after the 2-octet tag) to match the new,
                        //shorter length.
                        BinaryPrimitives.WriteUInt32BigEndian(rewritten.AsSpan(sizeof(ushort)), (uint)rewritten.Length);

                        //Fix up authorizationSize too (GetRandom has no handles, so this field sits immediately
                        //after the 10-octet header, TpmHeader.HeaderSize): the hmac field shrank by oldHmacLength
                        //octets, and authorizationSize does not include itself, so the new value is simply the old
                        //value minus that same shrinkage. Left stale, TryBeginAuthArea's own
                        //authorizationSize/commandSize framing cross-check rejects with TPM_RC_AUTHSIZE BEFORE the
                        //simulator ever reaches the clause 19.6.15 empty-hmac gate this test names — masking the
                        //very check under test (F4: the prior version of this helper left authorizationSize stale).
                        BinaryPrimitives.WriteUInt32BigEndian(rewritten.AsSpan(TpmHeader.HeaderSize), oldAuthorizationSize - oldHmacLength);

                        return await simulator.SubmitAsync(rewritten, commandPool, ct).ConfigureAwait(false);
                    }

                    using TpmDevice zeroingDevice = TpmDevice.Create(ZeroTheHmacAsync);
                    var getRandomInput = new GetRandomInput(16);

                    TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                        zeroingDevice, getRandomInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.AreEqual(
                        SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
                        "A bound session's non-empty sessionKey means a zero-length hmac must be rejected by the " +
                        "clause 19.6.15 empty-hmac gate specifically (session-index-encoded TPM_RC_BAD_AUTH), not merely " +
                        "some other rejection reason (e.g. a stale authorizationSize producing TPM_RC_AUTHSIZE at framing).");
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, objectHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task GetRandomOverALoneAttributelessSessionIsRejectedWithSessionEncodedAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateGetRandomRegistry();

        using CreatePrimaryResponse bindObject = await CreateSigningBindObjectAsync(tpm, registry, pool).ConfigureAwait(false);
        uint objectHandle = bindObject.ObjectHandle.Value;

        try
        {
            //StartBoundHmacSessionAsync leaves SessionAttributes at its own default (CONTINUE_SESSION alone, no
            //decrypt/encrypt/audit) — exactly the shape Part 3, clause 5.5 forbids for a session that authorizes no
            //entity: GetRandom carries no @-handle, so this lone session MUST set at least one of decrypt, encrypt,
            //or audit. Proves the uniform session-area gate (TpmLifecycleTransitions.ValidateSessionArea) is
            //non-vacuous — the same check TPM2_Unseal() and TPM2_Create() already apply — by rejecting the one
            //shape every OTHER test in this file deliberately avoids.
            (uint sessionHandle, TpmSession session, _, _) = await StartBoundHmacSessionAsync(tpm, registry, pool, objectHandle, TpmtSymDef.Null).ConfigureAwait(false);
            using(session)
            {
                try
                {
                    var getRandomInput = new GetRandomInput(16);

                    TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                        tpm, getRandomInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsFalse(result.IsSuccess, "A lone session with none of decrypt/encrypt/audit set must be rejected before any HMAC is evaluated.");
                    Assert.AreEqual(
                        SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), result.ResponseCode,
                        "GetRandom authorizes no entity, so a lone attribute-less session must reject with the session-index-encoded TPM_RC_ATTRIBUTES (Part 3, clause 5.5).");
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, objectHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task IndependentlyTranscribedCommandHmacMatchesWhatTheSimulatorAccepted()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[]? capturedCommand = null;
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, System.Threading.CancellationToken ct)
        {
            capturedCommand = command.ToArray();
            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice capturingDevice = TpmDevice.Create(CaptureAsync);
        TpmResponseRegistry registry = CreateGetRandomRegistry();

        using CreatePrimaryResponse bindObject = await CreateSigningBindObjectAsync(capturingDevice, registry, pool).ConfigureAwait(false);
        uint objectHandle = bindObject.ObjectHandle.Value;

        try
        {
            (uint sessionHandle, TpmSession session, byte[] initialNonceCaller, byte[] initialNonceTpm) =
                await StartBoundHmacSessionAsync(capturingDevice, registry, pool, objectHandle, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);

            using(session)
            {
                //GetRandom authorizes no entity, so its lone session MUST set at least one of decrypt/encrypt/audit
                //(Part 3, clause 5.5); encrypt matches the pre-existing parameter-encryption flow tests and lets
                //this test's dynamically-parsed sessionAttributes octet (below) carry the real, non-zero value.
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                try
                {
                    const ushort BytesRequested = 24;
                    var getRandomInput = new GetRandomInput(BytesRequested);

                    TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                        capturingDevice, getRandomInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(result.IsSuccess, $"Encrypted GetRandom over a bound session failed: '{result.ResponseCode}'.");
                    result.Value.Dispose();

                    Assert.IsNotNull(capturedCommand, "The capturing wrapper must have observed the outgoing command.");

                    //Parse the captured wire bytes back apart: sessionHandle, nonceCaller, sessionAttributes, hmac,
                    //bytesRequested — firewalled to the wire, no back-channel into the session object's own fields
                    //except NonceCaller (needed as the session-key KDFa's own context, unavailable from the wire
                    //alone since the wire only ever carries the SessionKey's downstream HMAC, never the key itself).
                    ParseGetRandomOverSessionCommand(
                        capturedCommand!, out ReadOnlyMemory<byte> nonceCaller, out byte sessionAttributes,
                        out ReadOnlyMemory<byte> suppliedHmac, out ReadOnlyMemory<byte> rawBytesRequested);

                    BaseMemoryPool oraclePool = BaseMemoryPool.Shared;

                    //Independent oracle: KDFa (Part 1, clause 11.4.10.2) via the project's own Kdfa, keyed on the
                    //bind object's authValue (empty for this test's signing key) — the session-key derivation the
                    //sim itself performs at TPM2_StartAuthSession() (equation 20). Context order is nonceTPM
                    //(contextU) then nonceCaller (contextV), the initial StartAuthSession nonces.
                    using IMemoryOwner<byte> derivedSessionKey = await Kdfa.DeriveAsync(
                        HashAlgorithmName.SHA256, ReadOnlyMemory<byte>.Empty, "ATH", initialNonceTpm, initialNonceCaller, DigestSize * 8, oraclePool, TestContext.CancellationToken).ConfigureAwait(false);
                    ReadOnlyMemory<byte> sessionKey = derivedSessionKey.Memory[..DigestSize];

                    //cpHash = H_SHA256(commandCode || parameters) — GetRandom-over-session carries no command
                    //handles, so the handle-Name term is empty (Part 1, clause 18.7, equation 15).
                    int cpHashInputLength = sizeof(uint) + rawBytesRequested.Length;
                    using IMemoryOwner<byte> cpHashInputOwner = oraclePool.Rent(cpHashInputLength);
                    {
                        var writer = new TpmWriter(cpHashInputOwner.Memory.Span[..cpHashInputLength]);
                        writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_GetRandom);
                        writer.WriteBytes(rawBytesRequested.Span);
                    }

                    using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
                        cpHashInputOwner.Memory[..cpHashInputLength], outputByteLength: DigestSize, tag: DigestTag(), pool: oraclePool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

                    //authHMAC = HMAC_SHA256(sessionKey, cpHash || nonceCaller || nonceTPM || sessionAttributes)
                    //(Part 1, clause 19.6.5, equation 17) — GetRandom authorizes no entity, so the key is the
                    //session key alone (no authValue term) and there is no nonceTPMdecrypt/encrypt fold (a single
                    //session in the auth area never folds, clause 19.6.3.4).
                    int hmacInputLength = cpHash.AsReadOnlySpan().Length + nonceCaller.Length + initialNonceTpm.Length + 1;
                    using IMemoryOwner<byte> hmacInputOwner = oraclePool.Rent(hmacInputLength);
                    {
                        var writer = new TpmWriter(hmacInputOwner.Memory.Span[..hmacInputLength]);
                        writer.WriteBytes(cpHash.AsReadOnlySpan());
                        writer.WriteBytes(nonceCaller.Span);
                        writer.WriteBytes(initialNonceTpm);
                        writer.WriteByte(sessionAttributes);
                    }

                    using HmacValue expectedHmac = await CryptographicKeyEvents.ComputeHmacAsync(
                        hmacInputOwner.Memory[..hmacInputLength], sessionKey, outputByteLength: DigestSize, tag: HmacTag(), pool: oraclePool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsTrue(
                        expectedHmac.AsReadOnlySpan().SequenceEqual(suppliedHmac.Span),
                        "The independently transcribed command HMAC must equal the hmac field TpmSession actually sent and the simulator accepted.");
                }
                finally
                {
                    await FlushIfPresentAsync(capturingDevice, registry, sessionHandle).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(capturingDevice, registry, objectHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task UnsealOverHmacSessionWithCorrectUserAuthReturnsPlaintext()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateSealRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;

        try
        {
            using LoadResponse loaded = await SealAndLoadAsync(tpm, registry, pool, parentHandle, CorrectUserAuth, noDa: false).ConfigureAwait(false);
            itemHandle = loaded.ObjectHandle.Value;

            (sessionHandle, TpmSession session, _, _) = await StartBoundHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Null).ConfigureAwait(false);
            using(session)
            {
                session.SetAuthValue(CorrectUserAuth, pool);

                UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
                TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                    tpm, unsealInput, [session], [loaded.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                //Success here means the session's response HMAC verified host-side too (ExecuteAsync fails the
                //result otherwise), proving both directions of the HMAC session-authorized Unseal.
                Assert.IsTrue(unsealResult.IsSuccess, $"Unseal over a correctly-authorized HMAC session failed: '{unsealResult.ResponseCode}'.");

                using UnsealResponse unsealed = unsealResult.Value;
                Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes), "The recovered secret must equal the sealed one.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task UnsealOverHmacSessionWithAnAuditOnlySecondSessionReturnsPlaintextUnencrypted()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateSealRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;
        uint auditSessionHandle = 0;

        try
        {
            using LoadResponse loaded = await SealAndLoadAsync(tpm, registry, pool, parentHandle, CorrectUserAuth, noDa: false).ConfigureAwait(false);
            itemHandle = loaded.ObjectHandle.Value;

            (sessionHandle, TpmSession session, _, _) = await StartBoundHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Null).ConfigureAwait(false);
            (auditSessionHandle, TpmSession auditSession, _, _) = await StartBoundHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
            using(session)
            using(auditSession)
            {
                session.SetAuthValue(CorrectUserAuth, pool);

                //The second session carries ONLY the audit attribute — no decrypt, no encrypt — a shape
                //ValidateSessionArea admits (Part 3, clause 5.5: a session that authorizes no entity needs at
                //least one of decrypt/encrypt/audit, and audit alone suffices) but which must NEVER trigger
                //response encryption on session 0's behalf: a real symmetric algorithm is negotiated so that, were
                //the sim to wrongly apply encryption anyway, the returned bytes would come back garbled against
                //this test's own plaintext assertion below rather than by coincidence matching it.
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
                TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                    tpm, unsealInput, [session, auditSession], [loaded.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(unsealResult.IsSuccess, $"Unseal with an audit-only second session failed: '{unsealResult.ResponseCode}'.");

                using UnsealResponse unsealed = unsealResult.Value;
                Assert.IsTrue(
                    unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes),
                    "An audit-only second session must never cause the sim to apply response encryption on its behalf; the recovered secret must equal the sealed plaintext exactly.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, auditSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task UnsealOverHmacSessionWithWrongUserAuthCountsAuthFailOnDaProtectedObject()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateSealRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;

        try
        {
            //DA-protected: noDa is CLEAR (the default template), so a wrong authorization counts (Part 1, clause 19.8).
            using LoadResponse loaded = await SealAndLoadAsync(tpm, registry, pool, parentHandle, CorrectUserAuth, noDa: false).ConfigureAwait(false);
            itemHandle = loaded.ObjectHandle.Value;

            TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(before.IsSuccess);

            (sessionHandle, TpmSession session, _, _) = await StartBoundHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Null).ConfigureAwait(false);
            using(session)
            {
                session.SetAuthValue(WrongUserAuth, pool);

                UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
                TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                    tpm, unsealInput, [session], [loaded.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(unsealResult.IsSuccess, "A wrong userAuth must be rejected.");
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), unsealResult.ResponseCode,
                    "A DA-protected object's wrong authValue over an HMAC session must reject with the session-index-encoded TPM_RC_AUTH_FAIL.");
            }

            TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(after.IsSuccess);
            Assert.AreEqual(before.Value.LockoutCounter + 1, after.Value.LockoutCounter, "FailedTries must move by exactly 1.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task UnsealOverHmacSessionWithWrongUserAuthOnNoDaObjectIsBadAuthWithoutCountingFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateSealRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;

        try
        {
            using LoadResponse loaded = await SealAndLoadAsync(tpm, registry, pool, parentHandle, CorrectUserAuth, noDa: true).ConfigureAwait(false);
            itemHandle = loaded.ObjectHandle.Value;

            TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(before.IsSuccess);

            (sessionHandle, TpmSession session, _, _) = await StartBoundHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Null).ConfigureAwait(false);
            using(session)
            {
                session.SetAuthValue(WrongUserAuth, pool);

                UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
                TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                    tpm, unsealInput, [session], [loaded.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(unsealResult.IsSuccess, "A wrong userAuth must be rejected.");
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), unsealResult.ResponseCode,
                    "A noDA-exempt object's wrong authValue must reject with the session-index-encoded TPM_RC_BAD_AUTH, never AUTH_FAIL.");
            }

            TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(after.IsSuccess);
            Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A noDA object's auth failure must never move FailedTries.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task UnsealOverHmacSessionAlreadyLockedOutRejectsWithoutTouchingFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateSealRegistry();

        //Lower maxTries so a single wrong password Unseal (over the plain form, cheap to drive) engages Lockout mode.
        const uint LoweredMaxTries = 1;
        TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;

        try
        {
            using LoadResponse loaded = await SealAndLoadAsync(tpm, registry, pool, parentHandle, CorrectUserAuth, noDa: false).ConfigureAwait(false);
            itemHandle = loaded.ObjectHandle.Value;

            //Engage Lockout mode with one wrong-password attempt over the plain (password-session) Unseal form.
            using TpmPasswordSession wrongPasswordSession = TpmPasswordSession.Create(WrongUserAuth, pool);
            UnsealInput wrongInput = UnsealInput.ForItem(loaded.ObjectHandle);
            TpmResult<UnsealResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, wrongInput, [wrongPasswordSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), wrongResult.ResponseCode,
                "The lone priming failure must count (session-index-encoded) and engage Lockout mode at LoweredMaxTries=1.");

            TpmResult<TpmDictionaryAttackParameters> locked = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(locked.IsSuccess);
            Assert.IsTrue(locked.Value.IsLockedOut, "The TPM must be in Lockout mode after the priming failure.");
            uint failedTriesAtLockout = locked.Value.LockoutCounter;

            (sessionHandle, TpmSession session, _, _) = await StartBoundHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Null).ConfigureAwait(false);
            using(session)
            {
                //Even the CORRECT userAuth must be rejected while locked out (Part 1, clause 17.8.3).
                session.SetAuthValue(CorrectUserAuth, pool);

                UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
                TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                    tpm, unsealInput, [session], [loaded.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, unsealResult.ResponseCode, "A locked-out TPM must reject a DA-protected object's HMAC-session Unseal with TPM_RC_LOCKOUT, before any HMAC is evaluated.");
            }

            TpmResult<TpmDictionaryAttackParameters> afterLockedAttempt = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(afterLockedAttempt.IsSuccess);
            Assert.AreEqual(failedTriesAtLockout, afterLockedAttempt.Value.LockoutCounter, "A LOCKOUT rejection must never move FailedTries further.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task PasswordUnsealWithWrongPasswordCountsAuthFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateSealRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;

        try
        {
            using LoadResponse loaded = await SealAndLoadAsync(tpm, registry, pool, parentHandle, CorrectUserAuth, noDa: false).ConfigureAwait(false);
            itemHandle = loaded.ObjectHandle.Value;

            TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

            using TpmPasswordSession wrongSession = TpmPasswordSession.Create(WrongUserAuth, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
            TpmResult<UnsealResponse> result = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [wrongSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
                "A wrong password against a DA-protected sealed object must now be compared, counted, and session-index-encoded (previously vacuous).");

            TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(before.Value.LockoutCounter + 1, after.Value.LockoutCounter, "FailedTries must move by exactly 1.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task PasswordUnsealAcceptsAPasswordDifferingOnlyInTrailingZeros()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateSealRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;

        try
        {
            using LoadResponse loaded = await SealAndLoadAsync(tpm, registry, pool, parentHandle, CorrectUserAuth, noDa: false).ConfigureAwait(false);
            itemHandle = loaded.ObjectHandle.Value;

            //Both directions of the strip rule (Part 1, clause 19.4): a password padded with trailing zero octets
            //relative to the stored authValue must still be accepted.
            byte[] paddedPassword = [.. CorrectUserAuth, 0x00, 0x00];

            using TpmPasswordSession paddedSession = TpmPasswordSession.Create(paddedPassword, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
            TpmResult<UnsealResponse> result = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [paddedSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsSuccess, $"A password padded with trailing zeros relative to the stored authValue must be accepted (got '{result.ResponseCode}').");
            using UnsealResponse unsealed = result.Value;
            Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes));
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task ReplayedCommandBytesAfterTheSessionAdvancedAreRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateSealRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;

        try
        {
            using LoadResponse loaded = await SealAndLoadAsync(tpm, registry, pool, parentHandle, CorrectUserAuth, noDa: false).ConfigureAwait(false);
            itemHandle = loaded.ObjectHandle.Value;

            byte[]? firstCommand = null;
            async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, System.Threading.CancellationToken ct)
            {
                firstCommand ??= command.ToArray();
                return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
            }

            using TpmDevice capturingDevice = TpmDevice.Create(CaptureAsync);

            //StartAuthSession itself goes through the PLAIN device: capturingDevice must observe ONLY the Unseal
            //command that follows, or "??=" would freeze firstCommand on the StartAuthSession bytes instead.
            (sessionHandle, TpmSession session, _, _) = await StartBoundHmacSessionAsync(tpm, registry, pool, parentHandle, TpmtSymDef.Null).ConfigureAwait(false);
            using(session)
            {
                session.SetAuthValue(CorrectUserAuth, pool);

                UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
                ReadOnlyMemory<byte>[] handleNames = [loaded.Name.Span.ToArray()];

                TpmResult<UnsealResponse> firstResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                    capturingDevice, unsealInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(firstResult.IsSuccess, $"The first (genuine) Unseal must succeed: '{firstResult.ResponseCode}'.");
                firstResult.Value.Dispose();

                Assert.IsNotNull(firstCommand, "The capturing wrapper must have observed the first command.");

                //Resend the EXACT same wire bytes directly against the simulator: the session's stored nonceTPM has
                //since rolled (the first command's response verification adopted a new one host-side, and the
                //simulator's own stored copy — the value the replay's HMAC was computed against — also rolled), so
                //the replayed command's cpHash/HMAC composition no longer matches what the simulator now expects.
                TpmResult<TpmResponse> replayResult = await simulator.SubmitAsync(firstCommand!, pool, TestContext.CancellationToken).ConfigureAwait(false);
                using(TpmResponse replayResponse = replayResult.Value)
                {
                    var reader = new TpmReader(replayResponse.AsReadOnlySpan());
                    TpmHeader replayHeader = TpmHeader.Parse(ref reader);
                    var replayRc = (TpmRcConstants)replayHeader.Code;

                    Assert.AreEqual(
                        SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), replayRc,
                        $"Replaying the exact first-command bytes after the session advanced must reject as a DA-protected auth failure (got '{replayRc}').");
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task ResetClearsHmacSessions()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateGetRandomRegistry();

        using CreatePrimaryResponse bindObject = await CreateSigningBindObjectAsync(tpm, registry, pool).ConfigureAwait(false);
        uint objectHandle = bindObject.ObjectHandle.Value;

        try
        {
            (uint sessionHandle, TpmSession session, _, _) = await StartBoundHmacSessionAsync(tpm, registry, pool, objectHandle, TpmtSymDef.Null).ConfigureAwait(false);
            using(session)
            {
                //TPM Reset (_TPM_Init then Startup(CLEAR) with no preceding orderly Shutdown) must invalidate every
                //HMAC session. A repeated Startup() without an intervening _TPM_Init is itself rejected (a real
                //TPM answers TPM_RC_INITIALIZE), so power-cycle first, mirroring a genuine Reset sequence.
                await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
                await IssueStartupClearAsync(simulator, pool).ConfigureAwait(false);

                var getRandomInput = new GetRandomInput(8);
                TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    tpm, getRandomInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_REFERENCE_S0, result.ResponseCode,
                    "A TPM Reset must clear HmacSessions: using a pre-Reset session must fail as if the handle were never loaded.");
            }
        }
        finally
        {
            //The object survives the transient-object table across this Reset call in this test (Reset does not
            //clear TransientObjects in this slice), so flushing is still meaningful; ignore the result either way.
            await FlushIfPresentAsync(tpm, registry, objectHandle).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)) — the test-side mirror of TpmLifecycleTransitions.SessionEncodedRc, transcribed
    /// independently here since production helpers are private.
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>
    /// Builds the digest <see cref="Tag"/> exactly as <c>TpmCommandExecutor.BuildDigestTag</c> does: SHA-256
    /// digest, raw encoding, direct material.
    /// </summary>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    /// <summary>
    /// Builds the HMAC <see cref="Tag"/> exactly as <c>TpmSession.ComputeSessionHmacAsync</c> does: SHA-256
    /// HMAC, raw encoding, direct material.
    /// </summary>
    private static Tag HmacTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Hmac).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    /// <summary>
    /// Parses a captured <c>TPM2_GetRandom()</c>-over-session wire command back into its per-session fields and
    /// the raw <c>bytesRequested</c> parameter bytes, firewalled to the wire (no back-channel into simulator or
    /// session internals).
    /// </summary>
    private static void ParseGetRandomOverSessionCommand(
        byte[] command, out ReadOnlyMemory<byte> nonceCaller, out byte sessionAttributes, out ReadOnlyMemory<byte> hmac, out ReadOnlyMemory<byte> rawBytesRequested)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        _ = reader.ReadUInt32(); //authorizationSize.
        _ = reader.ReadUInt32(); //sessionHandle.

        ushort nonceSize = reader.ReadUInt16();
        nonceCaller = reader.ReadBytes(nonceSize).ToArray();

        sessionAttributes = reader.ReadByte();

        ushort hmacSize = reader.ReadUInt16();
        hmac = reader.ReadBytes(hmacSize).ToArray();

        rawBytesRequested = reader.ReadBytes(sizeof(ushort)).ToArray();
    }

    /// <summary>
    /// Creates a transient ECC signing key (empty auth) used purely as a session bind target — mirroring
    /// <see cref="TpmInHouseSimulatorParameterEncryptionTests"/>'s bind object — and its Name (needed to bind a
    /// session to a real entity's actual authValue-bearing identity is not required here since the bind target's
    /// own authValue is empty; the object exists only to give <c>StartAuthSession</c>'s <c>bind</c> handle
    /// something real to resolve).
    /// </summary>
    private async Task<CreatePrimaryResponse> CreateSigningBindObjectAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (bind object) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates the deterministic ECC storage parent under the owner hierarchy.
    /// </summary>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary storage parent failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Seals <see cref="SecretBytes"/> under <paramref name="userAuth"/>, persists-and-reloads it through wire
    /// bytes only, and returns the loaded object's response.
    /// </summary>
    private async Task<LoadResponse> SealAndLoadAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, byte[] userAuth, bool noDa)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, userAuth, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: noDa);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (seal) failed: '{createResult.ResponseCode}'.");

        using CreateResponse sealedObject = createResult.Value;
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");

        return loadResult.Value;
    }

    /// <summary>
    /// Starts a bound, unsalted HMAC session against <paramref name="bindHandle"/> through the production
    /// <c>TPM2_StartAuthSession()</c> path and wraps it as a <see cref="TpmSession"/>. Also returns copies of the
    /// two start nonces (captured before nonceTPM's ownership transfers into the session) — the session-key
    /// KDFa's own context, needed by the independent-oracle test.
    /// </summary>
    private async Task<(uint SessionHandle, TpmSession Session, byte[] InitialNonceCaller, byte[] InitialNonceTpm)> StartBoundHmacSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint bindHandle, TpmtSymDef symmetric)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(bindHandle, SessionAlg, symmetric);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        byte[] initialNonceCaller = startInput.NonceCaller.ToArray();
        byte[] initialNonceTpm = startResponse.NonceTPM.AsReadOnlySpan().ToArray();
        using Tpm2bAuth bindAuth = Tpm2bAuth.CreateEmpty(pool);

        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(startResponse.SessionHandle.Value), bindAuth.AsReadOnlyMemory(), startInput.NonceCaller,
            startResponse.NonceTPM, SessionAlg, pool, symmetric: symmetric, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (startResponse.SessionHandle.Value, session, initialNonceCaller, initialNonceTpm);
    }

    /// <summary>Flushes a transient object or session handle when one is present (non-zero), ignoring the result.</summary>
    private async Task FlushIfPresentAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        if(!registry.TryGet(TpmCcConstants.TPM_CC_FlushContext, out _))
        {
            _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        }

        var flush = FlushContextInput.ForHandle(handle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, BaseMemoryPool.Shared, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reserializes a public area into a fresh <see cref="Tpm2bPublic"/> (a disk-persisted round trip).</summary>
    private static Tpm2bPublic ClonePublic(Tpm2bPublic source, BaseMemoryPool pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);

        var reader = new TpmReader(owner.Memory.Span[..size]);
        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>Creates a response codec registry covering the GetRandom-over-session flow tests.</summary>
    private static TpmResponseRegistry CreateGetRandomRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>Creates a response codec registry covering the seal/load/unseal flow tests.</summary>
    private static TpmResponseRegistry CreateSealRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_DictionaryAttackParameters, TpmResponseCodec.DictionaryAttackParameters);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);

        return registry;
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-session-auth", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupClearAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire.
    /// </summary>
    private async Task IssueStartupClearAsync(TpmSimulator simulator, BaseMemoryPool pool)
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
    }
}
