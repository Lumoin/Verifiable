using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the SESSION-authorized form of <c>TPM2_VerifySequenceComplete()</c> against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, through the production command path
/// (<see cref="TpmCommandExecutor"/> with the real <see cref="VerifySequenceCompleteInput"/> and the real
/// response codecs) — where the sequence's authorization rides a genuine HMAC session rather than a
/// <c>TPM_RS_PW</c> password.
/// </summary>
/// <remarks>
/// <para>
/// Table 118 types <c>@sequenceHandle</c> Auth Index 1, Auth Role USER and <c>keyHandle</c> Auth Index None, so
/// the command carries exactly ONE authorizing slot and the verification key is never authorized. The key's Name
/// is nevertheless a term of <c>cpHash</c>: equation 15 concatenates the Name of every handle in the handle
/// area, authorized or not (TPM 2.0 Library Part 1, clause 15.7), while the sequence's own Name is the Empty
/// Buffer — a present, zero-length term (Part 1, clause 29.4.6; Part 3, clause 17.7.1) the executor derives from
/// the input's own <see cref="VerifySequenceCompleteInput.HandleIsSequence"/> declaration. Every real session
/// here therefore passes <c>handleNames</c> as <c>[Empty, keyName]</c>, and verifies the RESPONSE authorization
/// end to end inside the executor before its <c>nonceTPM</c> is allowed to roll.
/// </para>
/// <para>
/// <c>signature</c> is a <c>TPMT_SIGNATURE</c> and the response's <c>validation</c> a <c>TPMT_TK_VERIFIED</c>;
/// neither carries a size field, so neither a <c>decrypt</c> nor an <c>encrypt</c> claim has anything to name on
/// this command and both are refused with <c>TPM_RC_ATTRIBUTES</c> at the claiming slot (Part 1, clause 18.1).
/// Those claims and every companion slot are planted on the WIRE — the host executor refuses them client-side
/// before they could reach the TPM, and the rules under test are the area's structural ones, which Part 3,
/// clause 5.5 settles strictly before clause 5.6's authorization.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorVerifySequenceCompleteSessionTests
{
    /// <summary>The hash algorithm every real HMAC session in this class negotiates.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The number of bytes in a NIST P-256 coordinate or an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The number of bytes in a SHA-256 digest or a SHA-256 HMAC — distinct from <see cref="P256ComponentSize"/> even though both are 32, so a move to a wider curve or hash does not silently ask for the wrong width.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The RSA modulus size in bits used by the RSA arm.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The command header's fixed width: tag (UINT16), commandSize (UINT32), commandCode (UINT32).</summary>
    private const int CommandHeaderSize = 10;

    /// <summary>The number of handles <c>TPM2_VerifySequenceComplete()</c> carries (Table 118: <c>@sequenceHandle</c> then <c>keyHandle</c>), which fixes where its authorization area starts on the wire.</summary>
    private const int VerifySequenceCompleteHandleCount = 2;

    /// <summary>A fixed seed standing in for the hierarchy's persistent random proof secret, injected so a minted ticket is reproducible off-TPM.</summary>
    private static byte[] TicketSeed { get; } = Convert.FromHexString("A1B2C3D4E5F60718293A4B5C6D7E8F9001122334455667788990AABBCCDDEEFF");

    /// <summary>
    /// The authorization value every verification sequence in this class is started with. Its width stays within
    /// the SHA-256 digest an authValue may not exceed (TPM 2.0 Library Part 1, clause 16.6.4.2).
    /// </summary>
    private static byte[] SequenceAuth { get; } = "verify-seq-complete-seq-auth"u8.ToArray();

    /// <summary>An authorization value that never matches <see cref="SequenceAuth"/>.</summary>
    private static byte[] WrongSequenceAuth { get; } = "verify-seq-complete-wrong-auth"u8.ToArray();

    /// <summary>The signing key's own authorization value, folded into the bind of the bound-session case.</summary>
    private static byte[] KeyPassword { get; } = "verify-seq-complete-key-auth"u8.ToArray();

    /// <summary>
    /// The <c>nonceCaller</c> every planted companion presents. Its 44-octet width is unlike any other width the
    /// surrounding machinery rents, so a rent of exactly this size identifies the carrier the parser created for
    /// the companion slot.
    /// </summary>
    private static byte[] CompanionNonce { get; } = "Companion slot nonceCaller proof octets, 44."u8.ToArray();

    /// <summary>
    /// The <c>hmac</c> every planted companion presents. A companion owes a real command HMAC (Part 3, clause 5.6
    /// applies to every session in the area), but no test here reaches that check, so these octets stand in for
    /// one at the right width without any test depending on their value.
    /// </summary>
    private static byte[] CompanionHmac { get; } = "Companion slot hmac field proof octets, 40 lo"u8.ToArray()[..Sha256DigestSize];

    /// <summary>The RFC 4231 test case 3 key: twenty octets of <c>0xaa</c>.</summary>
    private static byte[] Rfc4231Case3Key { get; } = Convert.FromHexString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    /// <summary>The RFC 4231 test case 3 data: fifty octets of <c>0xdd</c>.</summary>
    private static byte[] Rfc4231Case3Data { get; } = Convert.FromHexString("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");

    /// <summary>The published RFC 4231 test case 3 HMAC-SHA-256 value.</summary>
    private static byte[] Rfc4231Case3Sha256 { get; } = Convert.FromHexString("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The ECDSA happy path over a real, unbound HMAC session at <c>@sequenceHandle</c> (Auth Index 1, USER
    /// role): the sequence's own authorization value authorizes the completion, the unauthorized
    /// <c>keyHandle</c>'s Name and the sequence's Empty-Buffer Name are both <c>cpHash</c> terms, and the minted
    /// <c>TPM_ST_MESSAGE_VERIFIED</c> ticket is reproduced off-TPM from the injected proof seed as
    /// <c>HMAC(H(seed ‖ hierarchy), TPM_ST_MESSAGE_VERIFIED ‖ message ‖ keyName)</c> — Equation (5) over the RAW
    /// accumulated message, with no digest and no metadata
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3, Table 118; Part 1: Architecture, clauses 15.7, 29.4.6;
    /// Part 2: Structures, clause 10.6.5).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteOverTheSequencesHmacSessionOnAnEccKeyMintsTheRecomputedMessageVerifiedTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, TicketSeed).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, password: null).ConfigureAwait(false);
        byte[] message = "an ECDSA verification sequence completed over the sequence's own HMAC session."u8.ToArray();
        byte[] signature = await SignDigestEcdsaAsync(tpm, registry, pool, key.ObjectHandle, SHA256.HashData(message), keyPassword: null).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, SequenceAuth, message).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, TpmtSymDef.Null, SequenceAuth).ConfigureAwait(false);
        try
        {
            byte[] nonceBefore = session.NonceTpm.ToArray();

            using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
                sequenceHandle, key.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> result = await ExecuteOverSessionAsync(
                tpm, registry, pool, input, session, key.Name.Span.ToArray()).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"An ECDSA verification sequence authorized by a real HMAC session over the sequence's own authValue must complete: '{result.ResponseCode}'.");

            using VerifySequenceCompleteResponse verified = result.Value;
            Assert.AreEqual(TpmStConstants.TPM_ST_MESSAGE_VERIFIED, verified.Validation.Tag, "A successful completion must mint a ticket tagged TPM_ST_MESSAGE_VERIFIED.");
            Assert.AreEqual(TpmiRhHierarchy.Owner, verified.Validation.Hierarchy, "The ticket hierarchy must be the verifying key's own hierarchy.");
            Assert.IsFalse(verified.Validation.Metadata.HasValue, "A TPM_ST_MESSAGE_VERIFIED ticket carries no metadata (Table 111's messageVerified arm is TPMS_EMPTY).");
            Assert.HasCount(Sha256DigestSize, verified.Validation.Hmac, "The verified ticket HMAC is a SHA-256 HMAC.");

            byte[] expectedTicket = HMACSHA256.HashData(DeriveTicketProof((uint)TpmRh.TPM_RH_OWNER), BuildMessageVerifiedTicketMessage(message, key.Name.Span));
            Assert.IsTrue(
                expectedTicket.AsSpan().SequenceEqual(verified.Validation.Hmac),
                "The ticket minted over sessions must be HMAC(H(seed ‖ hierarchy), TPM_ST_MESSAGE_VERIFIED ‖ message ‖ keyName) over the RAW message, exactly as the password form mints it.");

            Assert.IsFalse(
                session.NonceTpm.Span.SequenceEqual(nonceBefore),
                "A successful exchange rolls the session's nonceTPM, and the session adopts the new value only once the response entry's own HMAC has verified (Part 1, clause 16.6.3.1).");
        }
        finally
        {
            session.Dispose();
            await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The RSASSA counterpart of
    /// <see cref="VerifySequenceCompleteOverTheSequencesHmacSessionOnAnEccKeyMintsTheRecomputedMessageVerifiedTicket"/>:
    /// an RSA key created with an EXPLICIT RSASSA/SHA-256 template scheme verifies the whole accumulated message
    /// over the sequence's own HMAC session, and the ticket is again reproduced from the injected seed
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3, Table 118; Part 2: Structures, clause 10.6.5).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteOverTheSequencesHmacSessionOnAnRsaKeyMintsTheRecomputedMessageVerifiedTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, TicketSeed).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] message = "an RSASSA verification sequence completed over the sequence's own HMAC session."u8.ToArray();
        byte[] signature = await SignDigestRsaAsync(tpm, registry, pool, key.ObjectHandle, SHA256.HashData(message)).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, SequenceAuth, message).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, TpmtSymDef.Null, SequenceAuth).ConfigureAwait(false);
        try
        {
            using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForRsaSsa(
                sequenceHandle, key.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> result = await ExecuteOverSessionAsync(
                tpm, registry, pool, input, session, key.Name.Span.ToArray()).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"An RSASSA verification sequence authorized by a real HMAC session must complete: '{result.ResponseCode}'.");

            using VerifySequenceCompleteResponse verified = result.Value;
            Assert.AreEqual(TpmStConstants.TPM_ST_MESSAGE_VERIFIED, verified.Validation.Tag, "A successful completion must mint a ticket tagged TPM_ST_MESSAGE_VERIFIED.");

            byte[] expectedTicket = HMACSHA256.HashData(DeriveTicketProof((uint)TpmRh.TPM_RH_OWNER), BuildMessageVerifiedTicketMessage(message, key.Name.Span));
            Assert.IsTrue(
                expectedTicket.AsSpan().SequenceEqual(verified.Validation.Hmac),
                "The RSA arm's ticket over sessions must reproduce from the injected seed exactly as the ECC arm's does.");
        }
        finally
        {
            session.Dispose();
            await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The KEYEDHASH counterpart: an HMAC signing key verifies the published RFC 4231 test case 3 vector
    /// accumulated through <c>TPM2_SequenceUpdate()</c>, authorized by a real HMAC session at
    /// <c>@sequenceHandle</c>, and the minted ticket reproduces from the injected seed
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3, Table 118; the HMAC vector is
    /// <see href="https://www.rfc-editor.org/rfc/rfc4231">RFC 4231</see>, section 4.4).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteOverTheSequencesHmacSessionOnAnHmacKeyVerifiesTheRfcVector()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, TicketSeed).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, TpmiDhObject.FromValue(key.Handle), SequenceAuth).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, SequenceAuth, Rfc4231Case3Data).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, TpmtSymDef.Null, SequenceAuth).ConfigureAwait(false);
        try
        {
            using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.Create(
                sequenceHandle, TpmiDhObject.FromValue(key.Handle), Rfc4231Case3Sha256, TpmAlgIdConstants.TPM_ALG_HMAC, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> result = await ExecuteOverSessionAsync(
                tpm, registry, pool, input, session, key.Name.AsReadOnlyMemory()).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"The published RFC 4231 case 3 HMAC must verify through a session-authorized TPM2_VerifySequenceComplete(): '{result.ResponseCode}'.");

            using VerifySequenceCompleteResponse verified = result.Value;
            Assert.AreEqual(TpmStConstants.TPM_ST_MESSAGE_VERIFIED, verified.Validation.Tag, "A successful completion must mint a ticket tagged TPM_ST_MESSAGE_VERIFIED.");

            byte[] expectedTicket = HMACSHA256.HashData(DeriveTicketProof((uint)TpmRh.TPM_RH_OWNER), BuildMessageVerifiedTicketMessage(Rfc4231Case3Data, key.Name.Span));
            Assert.IsTrue(
                expectedTicket.AsSpan().SequenceEqual(verified.Validation.Hmac),
                "The KEYEDHASH arm's ticket over sessions must reproduce from the injected seed exactly as the asymmetric arms' do.");
        }
        finally
        {
            session.Dispose();
            await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "cpHash ≔ H(commandCode ‖ Name1 ‖ … ‖ parameters)" covers EVERY handle in the handle area, authorized or
    /// not: the unauthorized <c>keyHandle</c>'s Name is a <c>cpHash</c> term of
    /// <c>TPM2_VerifySequenceComplete()</c>, so a caller folding a DIFFERENT key's Name computes a different
    /// <c>cpHash</c> and its command HMAC no longer matches — refused as the mismatch it is, session-encoded to
    /// the one authorizing slot; the correct Name over the SAME session then completes
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 15.7, equation 15; clause 16.6.5, equation 17).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteOverAnHmacSessionWithAWrongKeyNameInCpHashIsRefusedAtTheSequenceSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, password: null).ConfigureAwait(false);
        using CreatePrimaryResponse otherKey = await CreateEccSigningPrimaryAsync(tpm, registry, pool, password: null).ConfigureAwait(false);

        byte[] message = "a message whose completion folds the verifying key's Name into cpHash."u8.ToArray();
        byte[] signature = await SignDigestEcdsaAsync(tpm, registry, pool, key.ObjectHandle, SHA256.HashData(message), keyPassword: null).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, SequenceAuth, message).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, TpmtSymDef.Null, SequenceAuth).ConfigureAwait(false);
        try
        {
            using VerifySequenceCompleteInput wrongNameInput = VerifySequenceCompleteInput.ForEcdsa(
                sequenceHandle, key.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> wrongNameResult = await ExecuteOverSessionAsync(
                tpm, registry, pool, wrongNameInput, session, otherKey.Name.Span.ToArray()).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, wrongNameResult.BaseError,
                "A cpHash computed over the wrong keyHandle Name makes the command HMAC mismatch, and a sequence is dictionary-attack exempt, so the mismatch is the uncharged TPM_RC_BAD_AUTH.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), wrongNameResult.ResponseCode,
                "The mismatch names the one authorizing slot, so the wire code carries its session-index modifier (Part 2, clause 6.6.2).");

            using VerifySequenceCompleteInput rightNameInput = VerifySequenceCompleteInput.ForEcdsa(
                sequenceHandle, key.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> rightNameResult = await ExecuteOverSessionAsync(
                tpm, registry, pool, rightNameInput, session, key.Name.Span.ToArray()).ConfigureAwait(false);
            Assert.IsTrue(
                rightNameResult.IsSuccess,
                $"The very same session and signature must complete once the CORRECT keyHandle Name is folded, proving the Name term — not some other difference — caused the mismatch: '{rightNameResult.ResponseCode}'.");
            rightNameResult.Value.Dispose();
        }
        finally
        {
            session.Dispose();
            await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If the signature check succeeds, then the TPM will produce a TPMT_TK_VERIFIED. Otherwise, the TPM shall
    /// return TPM_RC_SIGNATURE" — a command-rule refusal, decided after the session has proved the sequence's
    /// authValue, and answered BARE. The error response is header-only with no session area, so the session's
    /// <c>nonceTPM</c> does NOT roll and the sequence is retained: a corrected retry over the SAME session
    /// completes, flushes the sequence, and a further completion names <c>sequenceHandle</c> — the sole handle,
    /// index 0 — as a TRANSIENT-range value resolving to nothing loaded, <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0
    /// Library Part 3, clause 5.4, step 2.1)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 6.2, 20.3.1; Part 1: Architecture, clauses 15.8, 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteOverAnHmacSessionWithAWrongSignatureAnswersSignatureBareAndRollsNoNonce()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, password: null).ConfigureAwait(false);
        byte[] message = "a message whose signature is corrupted once, then presented intact."u8.ToArray();
        byte[] signature = await SignDigestEcdsaAsync(tpm, registry, pool, key.ObjectHandle, SHA256.HashData(message), keyPassword: null).ConfigureAwait(false);
        byte[] corrupted = (byte[])signature.Clone();
        corrupted[^1] ^= 0xFF;

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, SequenceAuth, message).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, TpmtSymDef.Null, SequenceAuth).ConfigureAwait(false);
        try
        {
            byte[] nonceBeforeRefusal = session.NonceTpm.ToArray();

            using VerifySequenceCompleteInput badInput = VerifySequenceCompleteInput.ForEcdsa(
                sequenceHandle, key.ObjectHandle, corrupted, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> badResult = await ExecuteOverSessionAsync(
                tpm, registry, pool, badInput, session, key.Name.Span.ToArray()).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIGNATURE, 0), badResult.ResponseCode,
                "A failed signature check answers signature, parameter 1 of Table 118 — never session-encoded — because the session slot itself is not to blame.");
            Assert.IsTrue(
                session.NonceTpm.Span.SequenceEqual(nonceBeforeRefusal),
                "An error response is header-only with no session area, so nothing rolls the session's nonceTPM (Part 3, clause 6.2).");

            using VerifySequenceCompleteInput goodInput = VerifySequenceCompleteInput.ForEcdsa(
                sequenceHandle, key.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> goodResult = await ExecuteOverSessionAsync(
                tpm, registry, pool, goodInput, session, key.Name.Span.ToArray()).ConfigureAwait(false);
            Assert.IsTrue(goodResult.IsSuccess, $"The retained sequence must complete over the SAME, still-usable session once the intact signature arrives: '{goodResult.ResponseCode}'.");
            goodResult.Value.Dispose();

            using VerifySequenceCompleteInput replayInput = VerifySequenceCompleteInput.ForEcdsa(
                sequenceHandle, key.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> replayResult = await ExecuteOverSessionAsync(
                tpm, registry, pool, replayInput, session, key.Name.Span.ToArray()).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_REFERENCE_H0, replayResult.ResponseCode,
                "sequenceHandle is TPM2_VerifySequenceComplete()'s sole handle (index 0); a successful completion flushes the sequence context, so a further completion is a TRANSIENT-range value resolving to nothing loaded, TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1; Part 1, clause 29.4.6's {F}).");
        }
        finally
        {
            session.Dispose();
            await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "only the first parameter in the parameter area of a request or response can be encrypted. That parameter
    /// must have an explicit size field." <c>TPM2_VerifySequenceComplete()</c>'s only command parameter is a
    /// <c>TPMT_SIGNATURE</c>, which has none, so the AUTHORIZING slot claiming <c>decrypt</c> is refused with
    /// <c>TPM_RC_ATTRIBUTES</c> encoded to its own index — the session-area check of Part 3, clause 5.5, decided
    /// before any authorization
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 18.1; Part 2: Structures, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithADecryptClaimAtTheSequenceSlotIsRefusedWithAttributesAtThatSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (TpmRcConstants responseCode, TpmRcConstants baseError) = await VerifyCompleteWithPlantedSlotAttributeAsync(pool, TpmaSession.DECRYPT).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, baseError,
            "A decrypt claim on a command whose first parameter has no size field is refused for its attributes (Part 1, clause 18.1).");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), responseCode,
            "The refusal names the claiming slot — the sole authorizing session at index 0 — session-index-encoded.");
    }

    /// <summary>
    /// The response side of the same rule: <c>TPM2_VerifySequenceComplete()</c>'s only response parameter is a
    /// <c>TPMT_TK_VERIFIED</c>, which carries no size field either, so the authorizing slot claiming
    /// <c>encrypt</c> is refused with <c>TPM_RC_ATTRIBUTES</c> at its own index
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 18.1; Part 3: Commands, clause 20.3, Table 119).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithAnEncryptClaimAtTheSequenceSlotIsRefusedWithAttributesAtThatSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (TpmRcConstants responseCode, TpmRcConstants baseError) = await VerifyCompleteWithPlantedSlotAttributeAsync(pool, TpmaSession.ENCRYPT).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, baseError,
            "An encrypt claim on a command whose first response parameter has no size field is refused for its attributes (Part 1, clause 18.1).");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), responseCode,
            "The refusal names the claiming slot — the sole authorizing session at index 0 — session-index-encoded.");
    }

    /// <summary>
    /// A companion slot — Table 12's position after the authorization sessions, which authorizes nothing — that
    /// claims <c>decrypt</c> is refused with <c>TPM_RC_ATTRIBUTES</c> at its own index: there is nothing on this
    /// command a decrypt session could protect, wherever in the area it rides
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clauses 15.6.1, 18.1).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithACompanionClaimingDecryptIsRefusedWithAttributesAtTheCompanionSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (TpmRcConstants responseCode, TpmRcConstants baseError) = await VerifyCompleteWithPlantedCompanionAsync(
            pool, TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, baseError, "A companion has no first parameter to decrypt on this command, so its claim is an attribute error.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), responseCode,
            "The refusal names the companion slot at index 1, session-index-encoded (Part 2, clause 6.6.2).");
    }

    /// <summary>
    /// The companion counterpart for <c>encrypt</c>: the response's <c>TPMT_TK_VERIFIED</c> has no size field, so
    /// a companion claiming it is refused with <c>TPM_RC_ATTRIBUTES</c> at its own index
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clauses 15.6.1, 18.1).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithACompanionClaimingEncryptIsRefusedWithAttributesAtTheCompanionSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (TpmRcConstants responseCode, TpmRcConstants baseError) = await VerifyCompleteWithPlantedCompanionAsync(
            pool, TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, baseError, "A companion has no first response parameter to encrypt on this command, so its claim is an attribute error.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), responseCode,
            "The refusal names the companion slot at index 1, session-index-encoded (Part 2, clause 6.6.2).");
    }

    /// <summary>
    /// A companion claiming <c>audit</c> is admitted for the attribute — unlike <c>decrypt</c>/<c>encrypt</c>,
    /// <c>audit</c> names no parameter for Table 38 to require (TPM 2.0 Library Part 1, clause 17.1) — and then
    /// owes a command HMAC of its own, so a companion planted on the wire with an arbitrary <c>hmac</c> is
    /// refused for THAT, session-encoded <c>TPM_RC_BAD_AUTH</c> at its own index, never for the attribute.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1; Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithACompanionClaimingAuditOwesItsOwnCommandHmac()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (TpmRcConstants responseCode, TpmRcConstants baseError) = await VerifyCompleteWithPlantedCompanionAsync(
            pool, TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, baseError, "A companion carrying audit is admitted for the attribute and refused for the HMAC it could not supply.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), responseCode,
            "The refusal names the companion slot at index 1, session-index-encoded (Part 2, clause 6.6.2).");
        Assert.AreNotEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), responseCode,
            "TPM_RC_ATTRIBUTES would mean the audit attribute itself was refused rather than admitted.");
    }

    /// <summary>
    /// "If a session is not being used for authorization, at least one of decrypt, encrypt, or audit must be
    /// SET": a companion claiming NONE of them is refused with <c>TPM_RC_ATTRIBUTES</c> at its own index. Since
    /// none of the three is claimable on this command, no companion slot is admissible at all
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 15.6.4; Part 2: Structures, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithACompanionClaimingNoAttributeIsRefusedWithAttributesAtTheCompanionSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (TpmRcConstants responseCode, TpmRcConstants baseError) = await VerifyCompleteWithPlantedCompanionAsync(
            pool, TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, baseError, "A session authorizing no entity must claim at least one of decrypt, encrypt, or audit (Part 1, clause 15.6.4).");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), responseCode,
            "The refusal names the companion slot at index 1, session-index-encoded (Part 2, clause 6.6.2).");
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_AUTHSIZE, responseCode,
            "TPM_RC_AUTHSIZE would mean the parser never read the companion slot, leaving its attributes unvalidated.");
    }

    /// <summary>
    /// "If keyHandle refers to a key that is not the same as the key that was used to start the signature
    /// context, the TPM shall return TPM_RC_SIGN_CONTEXT_KEY" — one of the command's own rules, so it is answered
    /// BARE on the session form exactly as on the password form, decided only AFTER the session has proved the
    /// sequence's authValue; the sequence survives and completes under its own starting key over the same session
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 5.6, 5.8, 20.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteOverAnHmacSessionWithADifferentKeyAnswersSignContextKeyHandleEncoded()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse startingKey = await CreateEccSigningPrimaryAsync(tpm, registry, pool, password: null).ConfigureAwait(false);
        using CreatePrimaryResponse otherKey = await CreateEccSigningPrimaryAsync(tpm, registry, pool, password: null).ConfigureAwait(false);

        byte[] message = "verified only by the key that started this sequence."u8.ToArray();
        byte[] signature = await SignDigestEcdsaAsync(tpm, registry, pool, startingKey.ObjectHandle, SHA256.HashData(message), keyPassword: null).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, startingKey.ObjectHandle, SequenceAuth).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, SequenceAuth, message).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, TpmtSymDef.Null, SequenceAuth).ConfigureAwait(false);
        try
        {
            using VerifySequenceCompleteInput wrongKeyInput = VerifySequenceCompleteInput.ForEcdsa(
                sequenceHandle, otherKey.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> wrongKeyResult = await ExecuteOverSessionAsync(
                tpm, registry, pool, wrongKeyInput, session, otherKey.Name.Span.ToArray()).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_SIGN_CONTEXT_KEY, 1), wrongKeyResult.ResponseCode,
                "A key other than the one that started the sequence designates keyHandle, handle 2 of Table 118, never session-encoded.");

            using VerifySequenceCompleteInput retryInput = VerifySequenceCompleteInput.ForEcdsa(
                sequenceHandle, startingKey.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> retryResult = await ExecuteOverSessionAsync(
                tpm, registry, pool, retryInput, session, startingKey.Name.Span.ToArray()).ConfigureAwait(false);
            Assert.IsTrue(retryResult.IsSuccess, $"The sequence and the session must both survive a TPM_RC_SIGN_CONTEXT_KEY refusal: '{retryResult.ResponseCode}'.");
            retryResult.Value.Dispose();
        }
        finally
        {
            session.Dispose();
            await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A Complete command presented a sequence of the wrong KIND is refused with <c>TPM_RC_MODE</c> — the
    /// refusal clauses 17.8.1 and 17.9.1 give for a sequence a Complete does not consume, here a SIGNING sequence
    /// presented to <c>TPM2_VerifySequenceComplete()</c>. It is one of the command's own rules, answered BARE on
    /// the session form and only after the session has proved the sequence's authValue
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 5.6, 5.8, 17.8.1, 20.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteOverAnHmacSessionAgainstASigningSequenceAnswersModeHandleEncoded()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, password: null).ConfigureAwait(false);
        byte[] message = "a signing sequence presented to the verification Complete."u8.ToArray();
        byte[] signature = await SignDigestEcdsaAsync(tpm, registry, pool, key.ObjectHandle, SHA256.HashData(message), keyPassword: null).ConfigureAwait(false);

        using SignSequenceStartInput startInput = SignSequenceStartInput.Create(key.ObjectHandle, SequenceAuth, pool);
        TpmResult<SignSequenceStartResponse> startResult = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"TPM2_SignSequenceStart() failed: '{startResult.ResponseCode}'.");
        TpmiDhObject signingSequence = startResult.Value.SequenceHandle;
        await UpdateSequenceAsync(tpm, registry, pool, signingSequence, SequenceAuth, message).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, TpmtSymDef.Null, SequenceAuth).ConfigureAwait(false);
        try
        {
            using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
                signingSequence, key.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> result = await ExecuteOverSessionAsync(
                tpm, registry, pool, input, session, key.Name.Span.ToArray()).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_MODE, 0), result.ResponseCode,
                "A SIGNING sequence presented to TPM2_VerifySequenceComplete() designates sequenceHandle, handle 1 of Table 118.");
        }
        finally
        {
            session.Dispose();
            await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "A sequence is exempt from dictionary attack protection and authorization failures will not cause the TPM
    /// to enter lockout": a WRONG sequence authorization value folded into an unbound HMAC session fails the
    /// command HMAC with the UNCHARGED <c>TPM_RC_BAD_AUTH</c> — never the DA-counted <c>TPM_RC_AUTH_FAIL</c> —
    /// session-encoded to the sequence's slot, and <c>failedTries</c> does not move
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clauses 16.8.1, 29.4.6; Part 2: Structures, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteOverAnHmacSessionWithAWrongSequenceAuthIsRefusedWithBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, password: null).ConfigureAwait(false);
        byte[] message = "a sequence whose own authValue is guessed wrongly."u8.ToArray();
        byte[] signature = await SignDigestEcdsaAsync(tpm, registry, pool, key.ObjectHandle, SHA256.HashData(message), keyPassword: null).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, SequenceAuth, message).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess, $"GetDictionaryAttackParameters failed: '{before.ResponseCode}'.");

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool, TpmtSymDef.Null, WrongSequenceAuth).ConfigureAwait(false);
        try
        {
            using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
                sequenceHandle, key.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> result = await ExecuteOverSessionAsync(
                tpm, registry, pool, input, session, key.Name.Span.ToArray()).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError,
                "A sequence entity is dictionary-attack exempt, so a wrong sequence authorization is the uncharged TPM_RC_BAD_AUTH, never TPM_RC_AUTH_FAIL.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
                "The mismatch names the sequence's slot at index 0, session-index-encoded (Part 2, clause 6.6.2).");
        }
        finally
        {
            session.Dispose();
            await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "A sequence's authorization failure must never move failedTries (Part 1, clause 29.4.6).");
    }

    /// <summary>
    /// A LOADED policy session presented at <c>@sequenceHandle</c> is a kind of authorization this arm does not
    /// model, and is answered with the BARE <c>TPM_RC_AUTH_TYPE</c> — resolved at slot resolution, before any
    /// command HMAC is queued and before the command's own rules run
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.6; Part 3: Commands, clause 20.3, Table 118).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithALoadedPolicySessionAtTheSequenceSlotIsRefusedWithBareAuthType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, password: null).ConfigureAwait(false);
        byte[] message = "a completion whose slot names a policy session."u8.ToArray();
        byte[] signature = await SignDigestEcdsaAsync(tpm, registry, pool, key.ObjectHandle, SHA256.HashData(message), keyPassword: null).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, SequenceAuth, message).ConfigureAwait(false);

        TpmResult<StartAuthSessionResponse> policyStartResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStartResult.IsSuccess, $"StartPolicySession failed: '{policyStartResult.ResponseCode}'.");

        StartAuthSessionResponse policyStarted = policyStartResult.Value;
        uint policySessionHandle = policyStarted.SessionHandle.Value;
        try
        {
            using TpmSession policySlotSession = new(new TpmHandle(policySessionHandle), policyStarted.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            policySlotSession.SetAuthValue(SequenceAuth, pool);

            using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
                sequenceHandle, key.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> result = await ExecuteOverSessionAsync(
                tpm, registry, pool, input, policySlotSession, key.Name.Span.ToArray()).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode,
                "A loaded policy session at the sequence's slot is the wrong KIND of authorization for this arm, answered bare.");
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, policySessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Equation 22's bind omission applies only when the session's <c>bind</c> entity IS the entity the session
    /// authorizes. A session bound to the VERIFYING KEY authorizes the SEQUENCE, a different entity, so the
    /// sequence's own authorization value must still be folded into the command HMAC: omitting it is refused with
    /// the uncharged <c>TPM_RC_BAD_AUTH</c> at the sequence's slot, and supplying it over the very same session
    /// completes
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clauses 16.6.10, 16.6.5; Part 3: Commands, clause 20.3, Table 118).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteOverASessionBoundToTheVerifyingKeyStillFoldsTheSequencesOwnAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, KeyPassword).ConfigureAwait(false);
        byte[] message = "a completion whose session is bound to the verifying key, not to the sequence."u8.ToArray();
        byte[] signature = await SignDigestEcdsaAsync(tpm, registry, pool, key.ObjectHandle, SHA256.HashData(message), KeyPassword).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, SequenceAuth, message).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, key.ObjectHandle.Value, KeyPassword, TpmtSymDef.Null, isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using VerifySequenceCompleteInput omittedInput = VerifySequenceCompleteInput.ForEcdsa(
                sequenceHandle, key.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> omittedResult = await ExecuteOverSessionAsync(
                tpm, registry, pool, omittedInput, session, key.Name.Span.ToArray()).ConfigureAwait(false);
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), omittedResult.ResponseCode,
                "A session bound to the KEY does not authorize the SEQUENCE for free: omitting the sequence's authValue must fail the command HMAC at the sequence's slot.");

            session.SetAuthValue(SequenceAuth, pool);

            using VerifySequenceCompleteInput foldedInput = VerifySequenceCompleteInput.ForEcdsa(
                sequenceHandle, key.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> foldedResult = await ExecuteOverSessionAsync(
                tpm, registry, pool, foldedInput, session, key.Name.Span.ToArray()).ConfigureAwait(false);
            Assert.IsTrue(
                foldedResult.IsSuccess,
                $"The same key-bound session must complete once the SEQUENCE's own authValue is folded in (equation 17): '{foldedResult.ResponseCode}'.");
            foldedResult.Value.Dispose();
        }
        finally
        {
            session.Dispose();
            await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Every carrier a session-authorized <c>TPM2_VerifySequenceComplete()</c> makes the pool hand out — the
    /// session's key, authValue and nonces, the parsed authorization area, and the sequence's own accumulated
    /// segments — returns to the pool, whether the round trip is REFUSED (a wrong sequence authorization, which
    /// retains the sequence) or SUCCESSFUL (which flushes it). Real pool telemetry over a genuine
    /// <see cref="BaseMemoryPool"/>, with no test hook in production code
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3; Part 1: Architecture, clause 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteOverAnHmacSessionReturnsEveryRentedCarrierToPoolAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(tpm, registry, pool, password: null).ConfigureAwait(false);
        byte[] message = "a metered completion, refused once and then accepted."u8.ToArray();
        byte[] signature = await SignDigestEcdsaAsync(tpm, registry, pool, key.ObjectHandle, SHA256.HashData(message), keyPassword: null).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmiDhObject refusedSequence = await StartVerifySequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, refusedSequence, SequenceAuth, message).ConfigureAwait(false);

        (uint refusedSessionHandle, TpmSession refusedSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool, TpmtSymDef.Null, WrongSequenceAuth).ConfigureAwait(false);
        try
        {
            Assert.IsGreaterThan(
                baseline, trackingPool.OutstandingCount,
                "An open sequence and a session carrying an authValue must leave live rentals, or the balance assertions below are vacuous.");

            using VerifySequenceCompleteInput refusedInput = VerifySequenceCompleteInput.ForEcdsa(
                refusedSequence, key.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> refusedResult = await ExecuteOverSessionAsync(
                tpm, registry, pool, refusedInput, refusedSession, key.Name.Span.ToArray()).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, refusedResult.BaseError,
                "The refused round trip must be a genuine command-HMAC failure, or its carrier accounting proves nothing about a refusal.");
        }
        finally
        {
            refusedSession.Dispose();
            await FlushAsync(tpm, registry, pool, refusedSessionHandle).ConfigureAwait(false);
            await FlushAsync(tpm, registry, pool, refusedSequence.Value).ConfigureAwait(false);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A refused completion, its session and its retained sequence must together return every rented carrier to the pool.");

        TpmiDhObject acceptedSequence = await StartVerifySequenceAsync(tpm, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, acceptedSequence, SequenceAuth, message).ConfigureAwait(false);

        (uint acceptedSessionHandle, TpmSession acceptedSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool, TpmtSymDef.Null, SequenceAuth).ConfigureAwait(false);
        try
        {
            using VerifySequenceCompleteInput acceptedInput = VerifySequenceCompleteInput.ForEcdsa(
                acceptedSequence, key.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySequenceCompleteResponse> acceptedResult = await ExecuteOverSessionAsync(
                tpm, registry, pool, acceptedInput, acceptedSession, key.Name.Span.ToArray()).ConfigureAwait(false);
            Assert.IsTrue(acceptedResult.IsSuccess, $"The accepted round trip must complete: '{acceptedResult.ResponseCode}'.");
            acceptedResult.Value.Dispose();
        }
        finally
        {
            acceptedSession.Dispose();
            await FlushAsync(tpm, registry, pool, acceptedSessionHandle).ConfigureAwait(false);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A successful completion — which flushes the sequence as part of installing the response — must likewise return every rented carrier to the pool.");
    }


    /// <summary>
    /// Runs a <c>TPM2_VerifySequenceComplete()</c> whose sole authorizing slot is a real HMAC session, with
    /// <paramref name="plantedAttributes"/> additionally SET in that slot's attributes octet on the wire — the
    /// only way to reach the TPM's own session-area rules, since the host executor refuses a decrypt or encrypt
    /// claim on a command that admits neither before ever framing it.
    /// </summary>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="plantedAttributes">The attribute bits planted into the authorizing slot's octet.</param>
    /// <returns>The response code the simulator answered and its base (session-modifier-free) form.</returns>
    private async Task<(TpmRcConstants ResponseCode, TpmRcConstants BaseError)> VerifyCompleteWithPlantedSlotAttributeAsync(
        BaseMemoryPool pool, TpmaSession plantedAttributes)
    {
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(plainDevice, registry, pool, password: null).ConfigureAwait(false);
        byte[] message = "a completion whose authorizing slot claims an attribute this command cannot honour."u8.ToArray();
        byte[] signature = await SignDigestEcdsaAsync(plainDevice, registry, pool, key.ObjectHandle, SHA256.HashData(message), keyPassword: null).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(plainDevice, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);
        await UpdateSequenceAsync(plainDevice, registry, pool, sequenceHandle, SequenceAuth, message).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(plainDevice, registry, pool, TpmtSymDef.Xor(HmacSessionAlg), SequenceAuth).ConfigureAwait(false);
        try
        {
            byte[] Rewrite(byte[] command)
            {
                SetSessionAttributeBit(command, VerifySequenceCompleteHandleCount, sessionIndex: 0, plantedAttributes);

                return command;
            }

            using TpmDevice rewritingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_VerifySequenceComplete, Rewrite);
            using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
                sequenceHandle, key.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

            TpmResult<VerifySequenceCompleteResponse> result = await ExecuteOverSessionAsync(
                rewritingDevice, registry, pool, input, session, key.Name.Span.ToArray()).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            return (result.ResponseCode, result.BaseError);
        }
        finally
        {
            session.Dispose();
            await FlushAsync(plainDevice, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Runs a <c>TPM2_VerifySequenceComplete()</c> over a <c>TPM_RS_PW</c> slot for the sequence with a companion
    /// slot planted behind it on the wire, and returns what the simulator answered. A LONE password slot would
    /// parse to the plain password form, so the planted companion is also what routes the command to the
    /// session-authorized arm.
    /// </summary>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="companionSymmetric">The symmetric definition the companion's session negotiates at <c>TPM2_StartAuthSession()</c>.</param>
    /// <param name="companionAttributes">The attributes octet the planted companion presents.</param>
    /// <returns>The response code the simulator answered and its base (session-modifier-free) form.</returns>
    private async Task<(TpmRcConstants ResponseCode, TpmRcConstants BaseError)> VerifyCompleteWithPlantedCompanionAsync(
        BaseMemoryPool pool, TpmtSymDef companionSymmetric, TpmaSession companionAttributes)
    {
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningPrimaryAsync(plainDevice, registry, pool, password: null).ConfigureAwait(false);
        byte[] message = "a completion carrying a companion slot that can claim nothing."u8.ToArray();
        byte[] signature = await SignDigestEcdsaAsync(plainDevice, registry, pool, key.ObjectHandle, SHA256.HashData(message), keyPassword: null).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(plainDevice, registry, pool, key.ObjectHandle, SequenceAuth).ConfigureAwait(false);
        await UpdateSequenceAsync(plainDevice, registry, pool, sequenceHandle, SequenceAuth, message).ConfigureAwait(false);

        StartAuthSessionInput companionStartInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool, companionSymmetric);
        TpmResult<StartAuthSessionResponse> companionStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            plainDevice, companionStartInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(companionStartResult.IsSuccess, $"StartAuthSession (companion) failed: '{companionStartResult.ResponseCode}'.");

        using StartAuthSessionResponse companion = companionStartResult.Value;
        uint companionHandle = companion.SessionHandle.Value;
        try
        {
            byte[] Rewrite(byte[] command) => WithAppendedSession(command, VerifySequenceCompleteHandleCount, companionHandle, companionAttributes);

            using TpmDevice rewritingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_VerifySequenceComplete, Rewrite);
            using TpmPasswordSession sequenceAuth = TpmPasswordSession.Create(SequenceAuth, pool);
            using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
                sequenceHandle, key.ObjectHandle, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

            TpmResult<VerifySequenceCompleteResponse> result = await TpmCommandExecutor.ExecuteAsync<VerifySequenceCompleteResponse>(
                rewritingDevice, input, [sequenceAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            return (result.ResponseCode, result.BaseError);
        }
        finally
        {
            await FlushAsync(plainDevice, registry, pool, companionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Executes an already-built <see cref="VerifySequenceCompleteInput"/> over one real session at the
    /// sequence's slot, passing the handle-Name area Table 118 fixes: the Empty Buffer for <c>@sequenceHandle</c>
    /// (which the executor derives from the input's own declaration) and the verifying key's Name for the
    /// unauthorized <c>keyHandle</c>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The already-built command input; not disposed by this method.</param>
    /// <param name="session">The session authorizing the sequence.</param>
    /// <param name="keyName">The verifying key's Name.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<VerifySequenceCompleteResponse>> ExecuteOverSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, VerifySequenceCompleteInput input, TpmSessionBase session, ReadOnlyMemory<byte> keyName)
    {
        ReadOnlyMemory<byte>[] handleNames = [ReadOnlyMemory<byte>.Empty, keyName];

        return await TpmCommandExecutor.ExecuteAsync<VerifySequenceCompleteResponse>(
            tpm, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Starts a real, unbound and unsalted HMAC session negotiating <paramref name="symmetric"/> and hands it
    /// <paramref name="authValue"/> as the entity authorization value its command HMAC folds in.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="symmetric">The symmetric definition the session negotiates.</param>
    /// <param name="authValue">The authorization value to fold into the command HMAC key.</param>
    /// <returns>The session handle and the host session; the caller disposes the session and flushes the handle.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartUnboundHmacSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtSymDef symmetric, ReadOnlyMemory<byte> authValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound HMAC) failed: '{startResult.ResponseCode}'.");

        //The response owns nothing but nonceTPM, which the session takes over, so it is deliberately not disposed.
        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;
        if(!authValue.IsEmpty)
        {
            session.SetAuthValue(authValue.Span, pool);
        }

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Starts a verification sequence over the key's own Auth-Index-None handle, asserting success, and returns its handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The verification key handle.</param>
    /// <param name="sequenceAuth">The sequence's own authorization value.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartVerifySequenceAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        using VerifySequenceStartInput input = VerifySequenceStartInput.Create(keyHandle, sequenceAuth, pool);
        TpmResult<VerifySequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<VerifySequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_VerifySequenceStart() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>Appends a buffer to an open sequence over the sequence's own <c>TPM_RS_PW</c> session, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence handle.</param>
    /// <param name="sequenceAuth">The sequence's own authorization value.</param>
    /// <param name="buffer">The update buffer.</param>
    private async Task UpdateSequenceAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, byte[] sequenceAuth, byte[] buffer)
    {
        using TpmPasswordSession sequenceSession = HmacKeyHarness.PasswordSession(sequenceAuth, pool);
        using SequenceUpdateInput input = SequenceUpdateInput.Create(sequenceHandle, buffer, pool);
        TpmResult<SequenceUpdateResponse> result = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
            tpm, input, [sequenceSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SequenceUpdate() failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Signs a digest with an ECDSA key through <c>TPM2_SignDigest()</c> over a password session, returning the
    /// IEEE P1363 <c>r ‖ s</c> form — the ON-TPM signer every verification case here feeds to the sequence,
    /// since the simulator holds no private key material a framework signer could reach.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The ECDSA signing key handle.</param>
    /// <param name="digest">The digest to sign.</param>
    /// <param name="keyPassword">The key's own password, or <see langword="null"/> for an empty-password session.</param>
    /// <returns>The IEEE P1363 signature octets.</returns>
    private async Task<byte[]> SignDigestEcdsaAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] digest, byte[]? keyPassword)
    {
        using TpmPasswordSession keyAuth = keyPassword is { Length: > 0 } ? TpmPasswordSession.Create(keyPassword, pool) : TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput input = SignDigestInput.Create(keyHandle, digest, pool);
        TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, input, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SignDigest() (ECDSA) failed: '{result.ResponseCode}'.");

        using SignDigestResponse signature = result.Value;

        return ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan());
    }

    /// <summary>Signs a digest with the RSASSA key through <c>TPM2_SignDigest()</c> and returns the raw RSA signature octets.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The RSA signing key handle.</param>
    /// <param name="digest">The digest to sign.</param>
    /// <returns>The raw RSA signature octets.</returns>
    private async Task<byte[]> SignDigestRsaAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] digest)
    {
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput input = SignDigestInput.Create(keyHandle, digest, pool);
        TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, input, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SignDigest() (RSA) failed: '{result.ResponseCode}'.");

        using SignDigestResponse signature = result.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSASSA, signature.SignatureAlgorithm, "The RSA key's retained template scheme must produce an RSASSA signature.");

        return signature.Signature.RsaSignature.Buffer.ToArray();
    }

    /// <summary>Concatenates the ECDSA r and s components into the IEEE P1363 form, left-padding each to the P-256 field width.</summary>
    /// <param name="r">The signature's r component.</param>
    /// <param name="s">The signature's s component.</param>
    /// <returns>The concatenated, fixed-width P1363 signature.</returns>
    private static byte[] ConcatenateP1363(ReadOnlySpan<byte> r, ReadOnlySpan<byte> s)
    {
        byte[] result = new byte[2 * P256ComponentSize];
        ToFixed(r, P256ComponentSize).CopyTo(result.AsSpan(0));
        ToFixed(s, P256ComponentSize).CopyTo(result.AsSpan(P256ComponentSize));

        return result;
    }

    /// <summary>Left-pads a big-endian integer to a fixed width, as the IEEE P1363 encoding requires.</summary>
    /// <param name="value">The big-endian value.</param>
    /// <param name="length">The fixed width to pad to.</param>
    /// <returns>A new array of exactly <paramref name="length"/> bytes.</returns>
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

    /// <summary>Creates an unrestricted ECC P-256 signing/verification primary under the owner hierarchy, exempt from dictionary-attack protection.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="password">The key's authorization value, or <see langword="null"/> for an empty one.</param>
    /// <returns>The CreatePrimary response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, byte[]? password)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password is null ? null : System.Text.Encoding.UTF8.GetString(password),
            TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256 signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an unrestricted, empty-password RSA 2048 signing/verification primary with an explicit RSASSA/SHA-256 template scheme.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA 2048 RSASSA signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Flushes a session, sequence, or object handle, ignoring the outcome — cleanup, not an assertion.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    private static async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(handle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
    }

    /// <summary>
    /// Wraps the simulator in a device that rewrites the wire bytes of exactly one command code on their way in,
    /// leaving every other command untouched.
    /// </summary>
    /// <param name="simulator">The simulator the rewritten command is submitted to.</param>
    /// <param name="commandCode">The command whose bytes are rewritten.</param>
    /// <param name="rewrite">The rewrite to apply.</param>
    /// <returns>The rewriting device; the caller owns it.</returns>
    private static TpmDevice CreateRewritingDevice(TpmSimulator simulator, TpmCcConstants commandCode, Func<byte[], byte[]> rewrite)
    {
        return TpmDevice.Create(async (command, commandPool, cancellationToken) =>
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == commandCode)
            {
                bytes = rewrite(bytes);
            }

            return await simulator.SubmitAsync(bytes, commandPool, cancellationToken).ConfigureAwait(false);
        }, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
    }

    /// <summary>Reads a framed command's commandCode field (TPM 2.0 Library Part 1, clause 15.2.3's commandCode header field).</summary>
    /// <param name="command">The framed command.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(ReadOnlySpan<byte> command) =>
        (TpmCcConstants)BinaryPrimitives.ReadUInt32BigEndian(command[6..CommandHeaderSize]);

    /// <summary>
    /// Appends one <c>TPMS_AUTH_COMMAND</c> block to a framed command's authorization area, growing both the
    /// area's declared <c>authorizationSize</c> and the header's <c>commandSize</c> to match.
    /// </summary>
    /// <param name="command">The framed command to extend.</param>
    /// <param name="handleCount">The command's handle count, which fixes where its authorization area starts.</param>
    /// <param name="sessionHandle">The appended slot's session handle.</param>
    /// <param name="sessionAttributes">The appended slot's attributes octet.</param>
    /// <returns>A new framed command carrying the extra slot.</returns>
    private static byte[] WithAppendedSession(ReadOnlySpan<byte> command, int handleCount, uint sessionHandle, TpmaSession sessionAttributes)
    {
        int authorizationSizeOffset = CommandHeaderSize + (handleCount * sizeof(uint));
        uint authorizationSize = BinaryPrimitives.ReadUInt32BigEndian(command.Slice(authorizationSizeOffset, sizeof(uint)));
        int insertAt = authorizationSizeOffset + sizeof(uint) + (int)authorizationSize;

        int blockLength = sizeof(uint) + sizeof(ushort) + CompanionNonce.Length + sizeof(byte) + sizeof(ushort) + CompanionHmac.Length;
        byte[] extended = new byte[command.Length + blockLength];
        command[..insertAt].CopyTo(extended);
        command[insertAt..].CopyTo(extended.AsSpan(insertAt + blockLength));

        Span<byte> block = extended.AsSpan(insertAt, blockLength);
        BinaryPrimitives.WriteUInt32BigEndian(block, sessionHandle);
        BinaryPrimitives.WriteUInt16BigEndian(block[sizeof(uint)..], (ushort)CompanionNonce.Length);
        CompanionNonce.CopyTo(block[(sizeof(uint) + sizeof(ushort))..]);
        int afterNonce = sizeof(uint) + sizeof(ushort) + CompanionNonce.Length;
        block[afterNonce] = (byte)sessionAttributes;
        BinaryPrimitives.WriteUInt16BigEndian(block[(afterNonce + sizeof(byte))..], (ushort)CompanionHmac.Length);
        CompanionHmac.CopyTo(block[(afterNonce + sizeof(byte) + sizeof(ushort))..]);

        BinaryPrimitives.WriteUInt32BigEndian(extended.AsSpan(authorizationSizeOffset), authorizationSize + (uint)blockLength);
        BinaryPrimitives.WriteUInt32BigEndian(extended.AsSpan(sizeof(ushort)), (uint)extended.Length);

        return extended;
    }

    /// <summary>Sets one or more attribute bits in an existing authorization slot's attributes octet, in place.</summary>
    /// <param name="command">The framed command to rewrite.</param>
    /// <param name="handleCount">The command's handle count, which fixes where its authorization area starts.</param>
    /// <param name="sessionIndex">The zero-based slot whose attributes octet is rewritten.</param>
    /// <param name="sessionAttributes">The attribute bits to set.</param>
    private static void SetSessionAttributeBit(byte[] command, int handleCount, int sessionIndex, TpmaSession sessionAttributes)
    {
        int offset = CommandHeaderSize + (handleCount * sizeof(uint)) + sizeof(uint);
        for(int slot = 0; slot < sessionIndex; slot++)
        {
            offset += sizeof(uint);
            offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(command.AsSpan(offset, sizeof(ushort)));
            offset += sizeof(byte);
            offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(command.AsSpan(offset, sizeof(ushort)));
        }

        offset += sizeof(uint);
        offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(command.AsSpan(offset, sizeof(ushort)));
        command[offset] |= (byte)sessionAttributes;
    }

    /// <summary>
    /// The format-one session-index encoding: <c>rc = baseRc + TPM_RC_S + 0x100 · (index + 1)</c> (TPM 2.0
    /// Library Part 2, clause 6.6.2).
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index the code names.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>Derives a hierarchy's ticket proof as the seeded simulator does: <c>H(seed ‖ hierarchy)</c>.</summary>
    /// <param name="hierarchy">The hierarchy handle.</param>
    /// <returns>The proof octets.</returns>
    private static byte[] DeriveTicketProof(uint hierarchy)
    {
        byte[] input = new byte[TicketSeed.Length + sizeof(uint)];
        var writer = new TpmWriter(input);
        writer.WriteBytes(TicketSeed);
        writer.WriteUInt32(hierarchy);

        return SHA256.HashData(input);
    }

    /// <summary>
    /// Builds the <c>TPM_ST_MESSAGE_VERIFIED</c> ticket HMAC message — Equation (5): the tag (UINT16), the RAW
    /// accumulated message, and the verifying key's Name, with no digest and no metadata (TPM 2.0 Library Part 2,
    /// clause 10.6.5).
    /// </summary>
    /// <param name="message">The whole accumulated sequence message.</param>
    /// <param name="keyName">The verifying key's Name.</param>
    /// <returns>The ticket message octets.</returns>
    private static byte[] BuildMessageVerifiedTicketMessage(ReadOnlySpan<byte> message, ReadOnlySpan<byte> keyName)
    {
        byte[] result = new byte[sizeof(ushort) + message.Length + keyName.Length];
        var writer = new TpmWriter(result);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_MESSAGE_VERIFIED);
        writer.WriteBytes(message);
        writer.WriteBytes(keyName);

        return result;
    }

    /// <summary>Builds the response codec registry covering every executor-driven command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignDigest, TpmResponseCodec.SignDigest);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySequenceStart, TpmResponseCodec.VerifySequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceUpdate, TpmResponseCodec.SequenceUpdate);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySequenceComplete, TpmResponseCodec.VerifySequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers it
    /// on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="seed">The hierarchy-proof seed the simulator's tickets derive from; empty for the identifier-derived default.</param>
    /// <returns>The operational simulator; the caller owns it.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, ReadOnlyMemory<byte> seed = default)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-verify-sequence-complete-sessions",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(),
            seed: seed, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
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
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Startup(CLEAR) must succeed.");
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase, "The simulator must be operational before any command under test runs.");
    }
}
