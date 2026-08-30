using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Acceptance tests for the session-authorized form of <c>TPM2_SequenceUpdate()</c> against the in-house
/// behavioural <see cref="TpmSimulator"/>: the one command that feeds every kind of open sequence — signing,
/// verification, hash, and HMAC — and whose single handle carries Auth Index 1 with Auth Role USER
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3: Commands, clause 17.7, Table 91). Everything travels the production wire path
/// (<see cref="TpmCommandExecutor"/>, the real <see cref="SequenceUpdateInput"/> and response codecs), and every
/// real HMAC session verifies the simulator's response authorization end to end
/// (<see cref="TpmSession.VerifyAndUpdateAsync"/>), so a wrong response HMAC surfaces as a failed exchange.
/// </summary>
/// <remarks>
/// <para>
/// The rule this command exists to prove is the Empty-Buffer Name: "If an authorization or audit of this command
/// requires computation of a cpHash and an rpHash, the Name associated with sequenceHandle will be the Empty
/// Buffer" (Part 3, clause 17.7.1; the same sentence for every sequence object at Part 1: Architecture, clause
/// 29.4.6). A sequence handle's Name is therefore a PRESENT term of zero octets, which the host executor derives
/// from the input's own declaration (<see cref="ITpmCommandInput.HandleIsSequence"/>) rather than from the handle
/// value. A caller that folds the handle's four octets, or any other Name, into its cpHash computes a different
/// command HMAC and is refused for the mismatch.
/// </para>
/// <para>
/// The other rule this command is the clearest witness for is the dictionary-attack exemption: "A sequence is
/// exempt from dictionary attack protection and authorization failures will not cause the TPM to enter lockout"
/// (Part 1, clause 29.4.6). A wrong sequence authorization over an unbound session is therefore uncharged, while
/// the same mismatch over a session BOUND to a dictionary-attack-protected entity is charged for the bind's sake
/// (Part 1, clause 16.8.7's OR), and a correct sequence authorization works even in Lockout mode.
/// </para>
/// <para>
/// The area negatives the host executor refuses client-side — an <c>encrypt</c> claim on a command whose response
/// carries no parameter — are planted on the WIRE through a rewriting device: Part 3, clause 5.5's session-area
/// checks run strictly before clause 5.6's authorization, so a planted bit is refused for the area rule under
/// test rather than for the command HMAC it also breaks.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorSequenceUpdateSessionTests
{
    /// <summary>The hash algorithm every session and sequence in these tests negotiates.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The command header's fixed width: tag (UINT16), commandSize (UINT32), commandCode (UINT32).</summary>
    private const int CommandHeaderSize = 10;

    /// <summary>The lowered <c>maxTries</c> the Lockout-mode case uses to reach Lockout quickly.</summary>
    private const uint LockoutTestMaxTries = 2;

    /// <summary>A transient handle value no object or sequence these tests create ever occupies.</summary>
    private const uint UnknownTransientHandle = 0x8000_0999;

    /// <summary>The P-256 field width each ECDSA signature component is left-padded to.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>RFC 4231 test case 3 key: 20 octets of 0xaa.</summary>
    private static byte[] Rfc4231Case3Key { get; } = Convert.FromHexString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    /// <summary>RFC 4231 test case 3 data: 50 octets of 0xdd, fed to the sequence through this command.</summary>
    private static byte[] Rfc4231Case3Data { get; } = Convert.FromHexString("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");

    /// <summary>RFC 4231 test case 3 published HMAC-SHA-256.</summary>
    private static byte[] Rfc4231Case3Sha256 { get; } = Convert.FromHexString("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    /// <summary>The authorization value every sequence these tests open carries.</summary>
    private static byte[] SequenceAuth { get; } = "sequence-update-auth"u8.ToArray();

    /// <summary>A value that is not any sequence's authorization value.</summary>
    private static byte[] WrongSequenceAuth { get; } = "sequence-update-wrong"u8.ToArray();

    /// <summary>The authorization value the dictionary-attack-protected bind key carries.</summary>
    private static byte[] KeyPassword { get; } = "sequence-bind-key-auth"u8.ToArray();

    /// <summary>A value that is not the bind key's authorization value, used to drive the TPM into Lockout mode.</summary>
    private static byte[] WrongKeyPassword { get; } = "sequence-bind-key-wrong"u8.ToArray();

    /// <summary>The message these tests accumulate through <c>TPM2_SequenceUpdate()</c> when no published vector is the oracle.</summary>
    private static byte[] Message { get; } = "TPM2_SequenceUpdate over a session feeds the whole message."u8.ToArray();

    /// <summary>The first half of <see cref="Message"/>, fed by the first of two updates over one session.</summary>
    private static byte[] MessageFirstHalf { get; } = Message.AsSpan(0, Message.Length / 2).ToArray();

    /// <summary>The second half of <see cref="Message"/>, fed by the second of two updates over one session.</summary>
    private static byte[] MessageSecondHalf { get; } = Message.AsSpan(Message.Length / 2).ToArray();

    /// <summary>
    /// A Name that is neither the Empty Buffer nor the sequence handle's octets: a <c>TPM_ALG_SHA256</c>
    /// algorithm identifier followed by a 32-octet digest, the shape a loaded object's Name has (TPM 2.0 Library
    /// Part 1, clause 13, Table 9).
    /// </summary>
    private static byte[] ForeignName { get; } = Convert.FromHexString("000B" + new string('5', 64));

    /// <summary>Gets or sets the per-test context, whose cancellation token is observed across every exchange.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// <c>TPM2_SequenceUpdate()</c> over an unbound HMAC session whose key folds the SEQUENCE's authorization
    /// value feeds a SIGNING sequence, and the sequence's own <c>TPM2_SignSequenceComplete()</c> then signs the
    /// accumulated message to the published RFC 4231 case 3 value — the oracle being the vector rather than the
    /// simulator, so a mis-accumulated block or a mis-keyed command HMAC could not produce it
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.7, Table 91; Part 1: Architecture, clause 16.6.5,
    /// equation 17; <see href="https://www.rfc-editor.org/rfc/rfc4231#section-4.4">RFC 4231, section 4.4</see>).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateOverAnUnboundSessionOnASigningSequenceCompletesToThePublishedHmac()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateOverAnUnboundSessionOnASigningSequenceCompletesToThePublishedHmac), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, SessionAlg, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, TpmiDhObject.FromValue(key.Handle), SequenceAuth).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SequenceAuth, pool);

            TpmResult<SequenceUpdateResponse> update = await UpdateOverSessionAsync(tpm, registry, pool, session, sequenceHandle, Rfc4231Case3Data).ConfigureAwait(false);
            Assert.IsTrue(update.IsSuccess, $"TPM2_SequenceUpdate() over an unbound HMAC session must feed a signing sequence: '{update.ResponseCode}'.");

            TpmResult<SignSequenceCompleteResponse> completed = await SignSequenceCompleteAsync(
                tpm, registry, pool, sequenceHandle, TpmiDhObject.FromValue(key.Handle), [], SequenceAuth, []).ConfigureAwait(false);
            Assert.IsTrue(completed.IsSuccess, $"TPM2_SignSequenceComplete() over the fed sequence must succeed: '{completed.ResponseCode}'.");

            using SignSequenceCompleteResponse signature = completed.Value;
            Assert.IsTrue(
                signature.Signature.HmacSignature!.AsReadOnlyMemory().Span.SequenceEqual(Rfc4231Case3Sha256),
                "The message fed through the session-authorized update must sign to the published RFC 4231 case 3 value.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_SequenceUpdate()</c> over an unbound HMAC session feeds a VERIFICATION sequence, and
    /// <c>TPM2_VerifySequenceComplete()</c> then checks a signature made off the sequence against the accumulated
    /// message, minting the <c>TPM_ST_MESSAGE_VERIFIED</c> ticket — which it can only do if the octets this
    /// command installed are the very message that was signed
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 17.6, 17.7, 20.3; Part 2: Structures, clause 10.6.5).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateOverAnUnboundSessionOnAVerificationSequenceMintsTheVerifiedTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateOverAnUnboundSessionOnAVerificationSequenceMintsTheVerifiedTicket), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] digest = SHA256.HashData(Message);
        byte[] p1363Signature = await SignDigestEcdsaAsync(tpm, registry, pool, signer.ObjectHandle, digest).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, signer.ObjectHandle, SequenceAuth).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SequenceAuth, pool);

            TpmResult<SequenceUpdateResponse> update = await UpdateOverSessionAsync(tpm, registry, pool, session, sequenceHandle, Message).ConfigureAwait(false);
            Assert.IsTrue(update.IsSuccess, $"TPM2_SequenceUpdate() over an unbound HMAC session must feed a verification sequence: '{update.ResponseCode}'.");

            using VerifySequenceCompleteInput completeInput = VerifySequenceCompleteInput.ForEcdsa(
                sequenceHandle, signer.ObjectHandle, p1363Signature, SessionAlg, pool);
            using TpmPasswordSession sequenceSession = TpmPasswordSession.Create(SequenceAuth, pool);
            TpmResult<VerifySequenceCompleteResponse> completed = await TpmCommandExecutor.ExecuteAsync<VerifySequenceCompleteResponse>(
                tpm, completeInput, [sequenceSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(completed.IsSuccess, $"TPM2_VerifySequenceComplete() over the fed sequence must succeed: '{completed.ResponseCode}'.");

            using VerifySequenceCompleteResponse verified = completed.Value;
            Assert.AreEqual(
                TpmStConstants.TPM_ST_MESSAGE_VERIFIED, verified.Validation.Tag,
                "A signature over the message this command fed must mint a real TPM_ST_MESSAGE_VERIFIED ticket.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_SequenceUpdate()</c> over an unbound HMAC session feeds a HASH sequence, and
    /// <c>TPM2_SequenceComplete()</c> returns exactly the framework's digest of the accumulated octets — the
    /// oracle being an independent SHA-256 implementation rather than the simulator
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 17.4, 17.7, 17.8).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateOverAnUnboundSessionOnAHashSequenceCompletesToTheFrameworkDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateOverAnUnboundSessionOnAHashSequenceCompletesToTheFrameworkDigest), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, SequenceAuth).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SequenceAuth, pool);

            TpmResult<SequenceUpdateResponse> update = await UpdateOverSessionAsync(tpm, registry, pool, session, sequenceHandle, Message).ConfigureAwait(false);
            Assert.IsTrue(update.IsSuccess, $"TPM2_SequenceUpdate() over an unbound HMAC session must feed a hash sequence: '{update.ResponseCode}'.");

            byte[] digest = await CompleteHashSequenceAsync(tpm, registry, pool, sequenceHandle, [], SequenceAuth).ConfigureAwait(false);
            Assert.IsTrue(digest.AsSpan().SequenceEqual(SHA256.HashData(Message)), "The completed hash sequence must equal the framework digest of the octets the session-authorized update fed.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_SequenceUpdate()</c> over an unbound HMAC session feeds an HMAC-kind sequence opened by
    /// <c>TPM2_HMAC_Start()</c>, and <c>TPM2_SequenceComplete()</c> returns the published RFC 4231 case 3 value
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 17.2, 17.7, 17.8;
    /// <see href="https://www.rfc-editor.org/rfc/rfc4231#section-4.4">RFC 4231, section 4.4</see>).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateOverAnUnboundSessionOnAnHmacSequenceCompletesToThePublishedValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateOverAnUnboundSessionOnAnHmacSequenceCompletesToThePublishedValue), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, SessionAlg, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartHmacSequenceAsync(tpm, registry, pool, TpmiDhObject.FromValue(key.Handle), SequenceAuth).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SequenceAuth, pool);

            TpmResult<SequenceUpdateResponse> update = await UpdateOverSessionAsync(tpm, registry, pool, session, sequenceHandle, Rfc4231Case3Data).ConfigureAwait(false);
            Assert.IsTrue(update.IsSuccess, $"TPM2_SequenceUpdate() over an unbound HMAC session must feed an HMAC sequence: '{update.ResponseCode}'.");

            byte[] result = await CompleteHashSequenceAsync(tpm, registry, pool, sequenceHandle, [], SequenceAuth).ConfigureAwait(false);
            Assert.IsTrue(result.AsSpan().SequenceEqual(Rfc4231Case3Sha256), "The completed HMAC sequence must equal the published RFC 4231 case 3 value.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The Empty Buffer is a PRESENT, zero-length cpHash term, so a caller that hands the executor an explicitly
    /// EMPTY Name for the sequence handle computes the identical command HMAC as one that hands it no
    /// <c>handleNames</c> at all: both succeed, because the executor derives the term from the input's own
    /// declaration either way
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.7.1; Part 1: Architecture, clause 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateOverASessionWithAnExplicitEmptyHandleNameSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateOverASessionWithAnExplicitEmptyHandleNameSucceeds), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, SequenceAuth).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SequenceAuth, pool);

            using SequenceUpdateInput input = SequenceUpdateInput.Create(sequenceHandle, Message, pool);
            ReadOnlyMemory<byte>[] emptyName = [ReadOnlyMemory<byte>.Empty];
            TpmResult<SequenceUpdateResponse> update = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
                tpm, input, [session], emptyName, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(update.IsSuccess, $"An explicitly empty handle Name must fold the same zero octets the executor derives: '{update.ResponseCode}'.");

            byte[] digest = await CompleteHashSequenceAsync(tpm, registry, pool, sequenceHandle, [], SequenceAuth).ConfigureAwait(false);
            Assert.IsTrue(digest.AsSpan().SequenceEqual(SHA256.HashData(Message)), "The block fed under the explicitly empty Name must be the block the sequence accumulated.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A caller that folds the sequence handle's FOUR OCTETS into its cpHash — the Name a permanent, PCR, or
    /// session handle would carry (TPM 2.0 Library Part 1, clause 13, Table 9) — computes a command HMAC over
    /// different octets than the TPM does, and is refused <c>TPM_RC_BAD_AUTH</c> at slot 0 without charging
    /// <c>failedTries</c>: the sequence's Name is the Empty Buffer, not its handle
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.7.1; Part 1: Architecture, clauses 15.7 equation 15 and
    /// 29.4.6; Part 2: Structures, clause 6.6.2 for the session-index encoding).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateFoldingTheSequenceHandleValueAsItsNameIsRefusedWithBadAuth()
    {
        TpmRcConstants responseCode = await UpdateWithCallerSuppliedNameAsync(
            nameof(SequenceUpdateFoldingTheSequenceHandleValueAsItsNameIsRefusedWithBadAuth), useHandleOctetsAsName: true).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), responseCode,
            "Folding the sequence handle's octets as its Name must be refused as a command-HMAC mismatch at slot 0, uncharged.");
    }

    /// <summary>
    /// The same refusal for ANY non-empty Name: a caller that folds an object-shaped
    /// <c>nameAlg ‖ H(publicArea)</c> term for the sequence handle is refused <c>TPM_RC_BAD_AUTH</c> at slot 0,
    /// so the Empty Buffer is pinned as the one admissible term rather than merely "not the handle value"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.7.1; Part 1: Architecture, clause 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateFoldingAForeignNameForTheSequenceIsRefusedWithBadAuth()
    {
        TpmRcConstants responseCode = await UpdateWithCallerSuppliedNameAsync(
            nameof(SequenceUpdateFoldingAForeignNameForTheSequenceIsRefusedWithBadAuth), useHandleOctetsAsName: false).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), responseCode,
            "Folding any non-empty Name for the sequence handle must be refused as a command-HMAC mismatch at slot 0.");
    }

    /// <summary>
    /// <c>buffer</c> is the sized first command parameter (TPM 2.0 Library Part 3, clause 17.7, Table 91), so a
    /// session claiming <c>decrypt</c> with XOR obfuscation carries it across the wire protected and the TPM
    /// recovers it under a cipher key that folds the SEQUENCE'S OWN authorization value — "If a session is also
    /// being used for authorization, sessionValue is sessionKey ‖ authValue" (Part 1, clause 18.1). The completed
    /// digest equalling the framework's is what proves the plaintext landed
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clauses 18.1 and 18.2).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateWithAnXorDecryptProtectedBufferCompletesToTheFrameworkDigest() =>
        await RunDecryptProtectedUpdateAsync(
            nameof(SequenceUpdateWithAnXorDecryptProtectedBufferCompletesToTheFrameworkDigest), TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);

    /// <summary>
    /// The same recovery under AES-128-CFB, the platform-specific mode keyed and IV'd from the session's KDFa
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 18.3; Part 3: Commands, clause 17.7, Table 91).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateWithAnAesCfbDecryptProtectedBufferCompletesToTheFrameworkDigest() =>
        await RunDecryptProtectedUpdateAsync(
            nameof(SequenceUpdateWithAnAesCfbDecryptProtectedBufferCompletesToTheFrameworkDigest),
            TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)).ConfigureAwait(false);

    /// <summary>
    /// "buffer may be any size up to the limits of the TPM" places no lower bound on it, so a zero-length
    /// <c>buffer</c> over a session is accepted and appends nothing: the sequence completes to the digest of the
    /// octets its other calls supplied
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.7).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateWithAnEmptyBufferOverASessionSucceedsAndAppendsNothing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateWithAnEmptyBufferOverASessionSucceedsAndAppendsNothing), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, SequenceAuth).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SequenceAuth, pool);

            TpmResult<SequenceUpdateResponse> update = await UpdateOverSessionAsync(tpm, registry, pool, session, sequenceHandle, []).ConfigureAwait(false);
            Assert.IsTrue(update.IsSuccess, $"An empty buffer over a session must be accepted: '{update.ResponseCode}'.");

            byte[] digest = await CompleteHashSequenceAsync(tpm, registry, pool, sequenceHandle, Message, SequenceAuth).ConfigureAwait(false);
            Assert.IsTrue(digest.AsSpan().SequenceEqual(SHA256.HashData(Message)), "An empty update must append nothing, so the digest is of the completing block alone.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A wrong sequence authorization over an unbound HMAC session is refused <c>TPM_RC_BAD_AUTH</c> at slot 0
    /// and does NOT move <c>failedTries</c> — "A sequence is exempt from dictionary attack protection and
    /// authorization failures will not cause the TPM to enter lockout" — and "If the command does not return
    /// TPM_RC_SUCCESS, the state of the sequence is unmodified", which the next completion over the intended
    /// message proves by digesting that message alone
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 29.4.6; Part 3: Commands, clause 17.7).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateWithAWrongSequenceAuthIsBadAuthUnchargedAndAppendsNothing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateWithAWrongSequenceAuthIsBadAuthUnchargedAndAppendsNothing), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, SequenceAuth).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(WrongSequenceAuth, pool);
            uint before = await ReadLockoutCounterAsync(tpm, pool).ConfigureAwait(false);

            byte[] rejectedBlock = "octets that must never reach the sequence"u8.ToArray();
            TpmResult<SequenceUpdateResponse> refused = await UpdateOverSessionAsync(tpm, registry, pool, session, sequenceHandle, rejectedBlock).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), refused.ResponseCode,
                "A wrong sequence authorization over an unbound session must be TPM_RC_BAD_AUTH at slot 0.");
            Assert.AreEqual(before, await ReadLockoutCounterAsync(tpm, pool).ConfigureAwait(false), "A sequence authorization failure is dictionary-attack exempt and must not move failedTries.");

            byte[] digest = await CompleteHashSequenceAsync(tpm, registry, pool, sequenceHandle, Message, SequenceAuth).ConfigureAwait(false);
            Assert.IsTrue(
                digest.AsSpan().SequenceEqual(SHA256.HashData(Message)),
                "The refused update must have installed no segment, so the sequence digests the completing block alone.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The very same mismatch over a session BOUND to a dictionary-attack-protected key answers
    /// <c>TPM_RC_AUTH_FAIL</c> at slot 0 and charges <c>failedTries</c> once: the sequence contributes no
    /// standing of its own, but "the authorization session is bound to an entity that is DA protected" keeps the
    /// bind's, so the two standings are OR'd
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clauses 16.8.7 and 29.4.6; Part 3: Commands, clause 5.6).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateWithAWrongSequenceAuthOverASessionBoundToADaProtectedKeyIsAuthFailAndCharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateWithAWrongSequenceAuthOverASessionBoundToADaProtectedKeyIsAuthFailAndCharged), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey daKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, SessionAlg, userAuth: KeyPassword, isNoDa: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, SequenceAuth).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, daKey.Handle, KeyPassword, TpmtSymDef.Null, isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(WrongSequenceAuth, pool);
            uint before = await ReadLockoutCounterAsync(tpm, pool).ConfigureAwait(false);

            TpmResult<SequenceUpdateResponse> refused = await UpdateOverSessionAsync(tpm, registry, pool, session, sequenceHandle, Message).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), refused.ResponseCode,
                "A wrong sequence authorization over a session bound to a DA-protected key must be TPM_RC_AUTH_FAIL at slot 0.");
            Assert.AreEqual(before + 1, await ReadLockoutCounterAsync(tpm, pool).ConfigureAwait(false), "The bind's dictionary-attack standing must charge failedTries exactly once.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Lockout mode gates only dictionary-attack-protected entities, and a sequence is not one: a correct
    /// sequence authorization over an unbound HMAC session is ADMITTED while the TPM is locked out, and the block
    /// it feeds is the block the sequence accumulates
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 29.4.6; Part 3: Commands, clause 5.6, check 3).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateOverASessionIsAdmittedInLockoutMode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateOverASessionIsAdmittedInLockoutMode), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey daKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, SessionAlg, userAuth: KeyPassword, isNoDa: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, SequenceAuth).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SequenceAuth, pool);
            await EnterLockoutAsync(tpm, registry, pool, daKey.Handle).ConfigureAwait(false);

            TpmResult<SequenceUpdateResponse> update = await UpdateOverSessionAsync(tpm, registry, pool, session, sequenceHandle, Message).ConfigureAwait(false);
            Assert.IsTrue(update.IsSuccess, $"A sequence is dictionary-attack exempt, so its session-authorized update must be admitted in Lockout mode: '{update.ResponseCode}'.");

            TpmResult<DictionaryAttackLockResetResponse> reset = await tpm.DictionaryAttackLockResetAsync(
                ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(reset.IsSuccess, $"TPM2_DictionaryAttackLockReset() must leave Lockout mode so the accumulation can be read back: '{reset.ResponseCode}'.");

            byte[] digest = await CompleteHashSequenceAsync(tpm, registry, pool, sequenceHandle, [], SequenceAuth).ConfigureAwait(false);
            Assert.IsTrue(digest.AsSpan().SequenceEqual(SHA256.HashData(Message)), "The block fed while locked out must be the block the sequence accumulated.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>@sequenceHandle</c> is a <c>TPMI_DH_OBJECT</c> that must name an OPEN SEQUENCE: a loaded key's handle
    /// at that slot is refused with the BARE <c>TPM_RC_HANDLE</c>, decided before any authorization is evaluated,
    /// so the refusal carries no session-index modifier
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.7, Table 91; Part 2: Structures, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateNamingALoadedKeyAtTheSequenceSlotIsRefusedWithHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateNamingALoadedKeyAtTheSequenceSlotIsRefusedWithHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, SessionAlg, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SequenceAuth, pool);

            TpmResult<SequenceUpdateResponse> refused = await UpdateOverSessionAsync(
                tpm, registry, pool, session, TpmiDhObject.FromValue(key.Handle), Message).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_HANDLE, refused.ResponseCode,
                "A loaded key at @sequenceHandle must be refused with the bare TPM_RC_HANDLE before any authorization is read.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The <c>TPM2B_MAX_BUFFER</c> bound belongs to the PLAINTEXT: on the session form the parse only steps over
    /// the first parameter's framing, and a recovered <c>buffer</c> wider than the 1,024-octet bound is refused
    /// <c>TPM_RC_SIZE</c> session-encoded to the slot that claimed <c>decrypt</c>, which is the slot that
    /// supplied the octets
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 5.7 and 17.7; Part 2: Structures, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateWithAnOverBoundPlaintextBufferIsRefusedWithSizeAtTheDecryptSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateWithAnOverBoundPlaintextBufferIsRefusedWithSizeAtTheDecryptSlot), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, SequenceAuth).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SequenceAuth, pool);
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            byte[] overBound = new byte[Tpm2bMaxBuffer.MaxSize + 1];
            Array.Fill(overBound, (byte)0x5A);
            var input = new UnboundedSequenceUpdateInput(sequenceHandle.Value, overBound);

            TpmResult<SequenceUpdateResponse> refused = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
                tpm, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_SIZE, sessionIndex: 0), refused.ResponseCode,
                "A recovered buffer wider than TPM2B_MAX_BUFFER must be TPM_RC_SIZE encoded to the decrypting slot.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_SequenceUpdate()</c> returns no parameter at all (TPM 2.0 Library Part 3, clause 17.7, Table 92),
    /// so a session claiming <c>encrypt</c> is refused <c>TPM_RC_ATTRIBUTES</c> session-encoded to the claiming
    /// slot — "only the first parameter in the parameter area of a request or response can be encrypted. That
    /// parameter must have an explicit size field" (Part 1, clause 18.1). The host executor refuses the claim
    /// client-side for the same reason, so the bit is planted on the wire, where the area check of clause 5.5
    /// answers it ahead of the command HMAC the plant also breaks
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.5; Part 2: Structures, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateWithAPlantedEncryptAttributeIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateWithAPlantedEncryptAttributeIsRefusedWithAttributes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, SequenceAuth).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SequenceAuth, pool);

            using TpmDevice plantingDevice = CreateRewritingDevice(
                simulator, TpmCcConstants.TPM_CC_SequenceUpdate, command => WithSlotZeroAttribute(command, TpmaSession.ENCRYPT));

            TpmResult<SequenceUpdateResponse> refused = await UpdateOverSessionAsync(plantingDevice, registry, pool, session, sequenceHandle, Message).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), refused.ResponseCode,
                "An encrypt claim on a command with no response parameter must be TPM_RC_ATTRIBUTES at the claiming slot.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An authorization area may mix a <c>TPM_RS_PW</c> password at the authorizing position with a companion
    /// session behind it that authorizes nothing and rides only to protect the parameter (TPM 2.0 Library Part 1,
    /// clause 15.6.1 and Table 12). Such a companion's cipher key is its session key ALONE — "If the session is
    /// not being used for authorization, sessionValue is sessionKey" (clause 18.1) — and the completed digest is
    /// what proves the plaintext landed
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.7, Table 91).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateWithADecryptCompanionBesideAPasswordSequenceSlotRecoversTheBuffer()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateWithADecryptCompanionBesideAPasswordSequenceSlotRecoversTheBuffer), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, SequenceAuth).ConfigureAwait(false);
        (uint companionHandle, TpmSession companion) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);

        try
        {
            companion.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            using TpmPasswordSession sequenceSession = TpmPasswordSession.Create(SequenceAuth, pool);
            using SequenceUpdateInput input = SequenceUpdateInput.Create(sequenceHandle, Message, pool);

            TpmResult<SequenceUpdateResponse> update = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
                tpm, input, [sequenceSession, companion], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(update.IsSuccess, $"A decrypt companion beside a password sequence slot must be admitted: '{update.ResponseCode}'.");

            byte[] digest = await CompleteHashSequenceAsync(tpm, registry, pool, sequenceHandle, [], SequenceAuth).ConfigureAwait(false);
            Assert.IsTrue(
                digest.AsSpan().SequenceEqual(SHA256.HashData(Message)),
                "The companion's keystream folds no authValue, so only a cipher key of the session key alone recovers the caller's plaintext.");
        }
        finally
        {
            companion.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, companionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A LOADED policy session at the authorizing slot is a kind of authorization this command's session arm does
    /// not model, answered with the BARE <c>TPM_RC_AUTH_TYPE</c> — resolved before any command-HMAC verification
    /// is queued, so the refusal carries no session-index modifier
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.6; Part 2: Structures, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateWithALoadedPolicySessionAtTheSequenceSlotIsRefusedWithAuthType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateWithALoadedPolicySessionAtTheSequenceSlotIsRefusedWithAuthType), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, SequenceAuth).ConfigureAwait(false);

        TpmResult<StartAuthSessionResponse> policyStart = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStart.IsSuccess, $"StartPolicySession failed: '{policyStart.ResponseCode}'.");

        StartAuthSessionResponse started = policyStart.Value;
        uint policySessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession policySlotSession = new(new TpmHandle(policySessionHandle), started.NonceTPM, SessionAlg, pool);

            TpmResult<SequenceUpdateResponse> refused = await UpdateOverSessionAsync(tpm, registry, pool, policySlotSession, sequenceHandle, Message).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_TYPE, refused.ResponseCode,
                "A loaded policy session at @sequenceHandle's slot must be refused with the bare TPM_RC_AUTH_TYPE.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(policySessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Two consecutive <c>TPM2_SequenceUpdate()</c> calls over ONE continued session each succeed and each
    /// install their block: the second exchange's command and response HMACs key on the nonceTPM the first
    /// response rolled, so a nonceTPM that failed to roll would fail the second exchange outright, and the
    /// completed digest over both halves proves both blocks landed in order
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clauses 16.6.3 and 16.6.5; Part 3: Commands, clause 17.7).
    /// </summary>
    [TestMethod]
    public async Task TwoSequenceUpdatesOverOneSessionRollTheNonceAndAccumulateBothBlocks()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(TwoSequenceUpdatesOverOneSessionRollTheNonceAndAccumulateBothBlocks), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, SequenceAuth).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SequenceAuth, pool);

            TpmResult<SequenceUpdateResponse> first = await UpdateOverSessionAsync(tpm, registry, pool, session, sequenceHandle, MessageFirstHalf).ConfigureAwait(false);
            Assert.IsTrue(first.IsSuccess, $"The first update over the continued session must succeed: '{first.ResponseCode}'.");

            TpmResult<SequenceUpdateResponse> second = await UpdateOverSessionAsync(tpm, registry, pool, session, sequenceHandle, MessageSecondHalf).ConfigureAwait(false);
            Assert.IsTrue(second.IsSuccess, $"The second update must key on the rolled nonceTPM and succeed: '{second.ResponseCode}'.");

            byte[] digest = await CompleteHashSequenceAsync(tpm, registry, pool, sequenceHandle, [], SequenceAuth).ConfigureAwait(false);
            Assert.IsTrue(digest.AsSpan().SequenceEqual(SHA256.HashData(Message)), "Both blocks must have been accumulated in the order they were fed.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A refused and a decrypt-protected successful <c>TPM2_SequenceUpdate()</c>, followed by the completion that
    /// flushes the sequence, together return every carrier the pool handed out: the parse-rented authorization
    /// area and raw parameter area of both exchanges, the carrier the decryption step rents for the recovered
    /// <c>buffer</c>, and the segment the sequence retained until it completed
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 17.7 and 17.8; Part 1: Architecture, clause 29.4.6 for the
    /// flush on a successful completion).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateRoundTripsReturnEveryRentedCarrierToThePool()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateRoundTripsReturnEveryRentedCarrierToThePool), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SequenceAuth, pool);
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            long baseline = trackingPool.OutstandingCount;

            TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, SequenceAuth).ConfigureAwait(false);

            TpmResult<SequenceUpdateResponse> refused = await UpdateOverSessionAsync(
                tpm, registry, pool, session, TpmiDhObject.FromValue(UnknownTransientHandle), Message).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_HANDLE, refused.ResponseCode,
                "The balance below proves nothing unless the refused exchange really was refused after its carriers were rented.");

            TpmResult<SequenceUpdateResponse> accepted = await UpdateOverSessionAsync(tpm, registry, pool, session, sequenceHandle, Message).ConfigureAwait(false);
            Assert.IsTrue(accepted.IsSuccess, $"The successful exchange must feed the sequence: '{accepted.ResponseCode}'.");

            byte[] digest = await CompleteHashSequenceAsync(tpm, registry, pool, sequenceHandle, [], SequenceAuth).ConfigureAwait(false);
            Assert.IsTrue(digest.AsSpan().SequenceEqual(SHA256.HashData(Message)), "The balance below proves nothing unless the successful exchange really fed the sequence.");

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A refused update, a decrypt-protected successful update, and the completion that flushes the sequence must return every rented carrier.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Runs one decrypt-protected <c>TPM2_SequenceUpdate()</c> over an unbound HMAC session negotiating
    /// <paramref name="symmetric"/> against a hash sequence, and asserts the completed digest equals the
    /// framework's digest of the caller's plaintext — the one observable that pins the keystream.
    /// </summary>
    /// <param name="testName">The calling test's name, naming the simulator instance.</param>
    /// <param name="symmetric">The symmetric definition the session negotiates.</param>
    private async Task RunDecryptProtectedUpdateAsync(string testName, TpmtSymDef symmetric)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(testName, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, SequenceAuth).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, symmetric).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SequenceAuth, pool);
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            TpmResult<SequenceUpdateResponse> update = await UpdateOverSessionAsync(tpm, registry, pool, session, sequenceHandle, Message).ConfigureAwait(false);
            Assert.IsTrue(update.IsSuccess, $"A decrypt-protected update over a '{symmetric.Algorithm}' session must succeed: '{update.ResponseCode}'.");

            byte[] digest = await CompleteHashSequenceAsync(tpm, registry, pool, sequenceHandle, [], SequenceAuth).ConfigureAwait(false);
            Assert.IsTrue(
                digest.AsSpan().SequenceEqual(SHA256.HashData(Message)),
                "Only a cipher key that folds the sequence's own authorization value recovers the caller's plaintext.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Runs one <c>TPM2_SequenceUpdate()</c> over an unbound HMAC session whose cpHash folds a CALLER-SUPPLIED
    /// Name for the sequence handle rather than the Empty Buffer, and returns what the simulator answered. The
    /// input declares the handle as an ordinary object so the executor asks for a Name instead of deriving one.
    /// </summary>
    /// <param name="testName">The calling test's name, naming the simulator instance.</param>
    /// <param name="useHandleOctetsAsName">Whether the folded Name is the handle's own four octets rather than an object-shaped Name.</param>
    /// <returns>The response code the simulator answered.</returns>
    private async Task<TpmRcConstants> UpdateWithCallerSuppliedNameAsync(string testName, bool useHandleOctetsAsName)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(testName, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, SequenceAuth).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);

        try
        {
            session.SetAuthValue(SequenceAuth, pool);

            byte[] handleOctets = new byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(handleOctets, sequenceHandle.Value);
            ReadOnlyMemory<byte>[] names = [useHandleOctetsAsName ? handleOctets : ForeignName];

            var input = new CallerNamedSequenceUpdateInput(sequenceHandle.Value, Message);
            TpmResult<SequenceUpdateResponse> refused = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
                tpm, input, [session], names, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(refused.IsSuccess, "A cpHash folding a Name for the sequence handle must not authorize the command.");

            return refused.ResponseCode;
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Submits one <c>TPM2_SequenceUpdate()</c> over <paramref name="session"/> and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The authorizing session; the caller owns it.</param>
    /// <param name="sequenceHandle">The sequence (or candidate) handle.</param>
    /// <param name="buffer">The block to append.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<SequenceUpdateResponse>> UpdateOverSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSessionBase session, TpmiDhObject sequenceHandle, byte[] buffer)
    {
        using SequenceUpdateInput input = SequenceUpdateInput.Create(sequenceHandle, buffer, pool);

        return await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
            tpm, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Opens a HASH sequence carrying <paramref name="sequenceAuth"/> and returns its handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceAuth">The authorization value the sequence carries.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartHashSequenceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, byte[] sequenceAuth)
    {
        using HashSequenceStartInput input = HashSequenceStartInput.Create(sequenceAuth, TpmiAlgHash.FromValue(SessionAlg), pool);
        TpmResult<HashSequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HashSequenceStart() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>Opens a SIGNING sequence over <paramref name="keyHandle"/> and returns its handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The signing key the sequence binds to.</param>
    /// <param name="sequenceAuth">The authorization value the sequence carries.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartSignSequenceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        using SignSequenceStartInput input = SignSequenceStartInput.Create(keyHandle, sequenceAuth, pool);
        TpmResult<SignSequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SignSequenceStart() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>Opens a VERIFICATION sequence over <paramref name="keyHandle"/> and returns its handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The verification key the sequence binds to.</param>
    /// <param name="sequenceAuth">The authorization value the sequence carries.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartVerifySequenceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        using VerifySequenceStartInput input = VerifySequenceStartInput.Create(keyHandle, sequenceAuth, pool);
        TpmResult<VerifySequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<VerifySequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_VerifySequenceStart() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>Opens an HMAC-kind sequence over <paramref name="keyHandle"/> and returns its handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The HMAC key the sequence uses.</param>
    /// <param name="sequenceAuth">The authorization value the sequence carries.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartHmacSequenceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        TpmResult<HmacStartResponse> result = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, keyHandle.Value, SessionAlg, ReadOnlyMemory<byte>.Empty, sequenceAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HMAC_Start() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>
    /// Completes a hash or HMAC sequence over a single <c>TPM_RS_PW</c> slot and returns the result octets,
    /// asserting the completion succeeded.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence to complete.</param>
    /// <param name="buffer">The trailing block.</param>
    /// <param name="sequenceAuth">The sequence's authorization value.</param>
    /// <returns>The completion's result octets.</returns>
    private async Task<byte[]> CompleteHashSequenceAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, byte[] buffer, byte[] sequenceAuth)
    {
        using TpmPasswordSession sequenceSession = TpmPasswordSession.Create(sequenceAuth, pool);
        using SequenceCompleteInput input = SequenceCompleteInput.Create(sequenceHandle, buffer, TpmiRhHierarchy.Owner, pool);

        TpmResult<SequenceCompleteResponse> result = await TpmCommandExecutor.ExecuteAsync<SequenceCompleteResponse>(
            tpm, input, [sequenceSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SequenceComplete() failed: '{result.ResponseCode}'.");

        using SequenceCompleteResponse completed = result.Value;

        return completed.Result.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Submits <c>TPM2_SignSequenceComplete()</c> over two <c>TPM_RS_PW</c> slots — <c>@sequenceHandle</c> then
    /// <c>@keyHandle</c> — and returns the raw result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence to complete.</param>
    /// <param name="keyHandle">The signing key.</param>
    /// <param name="buffer">The trailing block.</param>
    /// <param name="sequenceAuth">The sequence's authorization value.</param>
    /// <param name="keyAuth">The key's authorization value.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<SignSequenceCompleteResponse>> SignSequenceCompleteAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, TpmiDhObject keyHandle,
        byte[] buffer, byte[] sequenceAuth, byte[] keyAuth)
    {
        using TpmPasswordSession sequenceSession = HmacKeyHarness.PasswordSession(sequenceAuth, pool);
        using TpmPasswordSession keySession = HmacKeyHarness.PasswordSession(keyAuth, pool);
        using SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(sequenceHandle, keyHandle, buffer, pool);

        return await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
            tpm, input, [sequenceSession, keySession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates an unrestricted, empty-password, dictionary-attack-exempt ECC P-256 signing primary under the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(SessionAlg), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256 signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Signs <paramref name="digest"/> with an ECDSA key through <c>TPM2_SignDigest()</c> over an empty-password
    /// slot and returns the IEEE P1363 <c>r ‖ s</c> signature the verification sequence is checked against.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The ECDSA signing key handle.</param>
    /// <param name="digest">The digest to sign.</param>
    /// <returns>The IEEE P1363 signature octets.</returns>
    private async Task<byte[]> SignDigestEcdsaAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] digest)
    {
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput input = SignDigestInput.Create(keyHandle, digest, pool);

        TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, input, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SignDigest() (ECDSA) failed: '{result.ResponseCode}'.");

        using SignDigestResponse signature = result.Value;
        byte[] p1363 = new byte[2 * P256ComponentSize];
        ToFixed(signature.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363.AsSpan(0));
        ToFixed(signature.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363.AsSpan(P256ComponentSize));

        return p1363;
    }

    /// <summary>Left-pads or trims <paramref name="value"/> to exactly <paramref name="length"/> octets.</summary>
    /// <param name="value">The value to normalize.</param>
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
    /// Drives the TPM into Lockout mode: lowers <c>maxTries</c> and then fails a dictionary-attack-protected
    /// key's password that many times at <c>TPM2_Sign()</c>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="daKeyHandle">A loaded dictionary-attack-protected key to fail against.</param>
    private async Task EnterLockoutAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint daKeyHandle)
    {
        TpmResult<DictionaryAttackParametersResponse> lowered = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LockoutTestMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowered.IsSuccess, $"Lowering maxTries failed: '{lowered.ResponseCode}'.");

        byte[] digest = SHA256.HashData(Message);
        for(uint attempt = 1; attempt <= LockoutTestMaxTries; attempt++)
        {
            using TpmPasswordSession wrongAuth = TpmPasswordSession.Create(WrongKeyPassword, pool);
            using SignInput input = SignInput.Create(
                TpmiDhObject.FromValue(daKeyHandle), digest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, pool);

            TpmResult<SignResponse> wrong = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, input, [wrongAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(wrong.IsSuccess, $"Attempt {attempt} of {LockoutTestMaxTries} with a wrong password must fail.");
        }

        TpmResult<TpmDictionaryAttackParameters> state = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(state.IsSuccess, $"GetDictionaryAttackParameters failed: '{state.ResponseCode}'.");
        Assert.IsTrue(state.Value.IsLockedOut, "The TPM must be in Lockout mode before the admission case runs.");
    }

    /// <summary>Reads the live <c>failedTries</c> value back from the TPM.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The reported lockout counter.</returns>
    private async Task<uint> ReadLockoutCounterAsync(TpmDevice tpm, BaseMemoryPool pool)
    {
        TpmResult<TpmDictionaryAttackParameters> result = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"GetDictionaryAttackParameters failed: '{result.ResponseCode}'.");

        return result.Value.LockoutCounter;
    }

    /// <summary>Starts an unbound, unsalted HMAC session through the production path and wraps it as a <see cref="TpmSession"/>.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="symmetric">The symmetric definition the session negotiates.</param>
    /// <returns>The session handle and the host session; the caller owns and flushes both.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartUnboundSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtSymDef symmetric)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, symmetric);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound HMAC) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, pool, symmetric)
        {
            SessionAttributes = TpmaSession.CONTINUE_SESSION
        };

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Builds the response codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_HMAC_Start, TpmResponseCodec.HmacStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySequenceStart, TpmResponseCodec.VerifySequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceUpdate, TpmResponseCodec.SequenceUpdate);
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceComplete, TpmResponseCodec.SequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceComplete, TpmResponseCodec.SignSequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySequenceComplete, TpmResponseCodec.VerifySequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignDigest, TpmResponseCodec.SignDigest);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);

        return registry;
    }

    /// <summary>Reads a framed command's <c>commandCode</c> field (TPM 2.0 Library Part 1, clause 15.2.3's commandCode header field).</summary>
    /// <param name="command">The framed command.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(ReadOnlySpan<byte> command) =>
        (TpmCcConstants)BinaryPrimitives.ReadUInt32BigEndian(command[(sizeof(ushort) + sizeof(uint))..]);

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
        });
    }

    /// <summary>
    /// Sets attribute bits in the <c>sessionAttributes</c> octet of the single <c>TPMS_AUTH_COMMAND</c> block of
    /// a one-handle command, leaving every other octet of the frame alone.
    /// </summary>
    /// <param name="command">The framed command.</param>
    /// <param name="attribute">The attribute bits to set.</param>
    /// <returns>The rewritten command.</returns>
    private static byte[] WithSlotZeroAttribute(byte[] command, TpmaSession attribute)
    {
        byte[] rewritten = (byte[])command.Clone();

        //Header, the one handle, authorizationSize, the slot's session handle, then the slot's nonceCaller.
        int cursor = CommandHeaderSize + sizeof(uint) + sizeof(uint) + sizeof(uint);
        ushort nonceSize = BinaryPrimitives.ReadUInt16BigEndian(rewritten.AsSpan(cursor));
        cursor += sizeof(ushort) + nonceSize;
        rewritten[cursor] |= (byte)attribute;

        return rewritten;
    }

    /// <summary>
    /// A <c>TPM2_SequenceUpdate()</c> input that does NOT declare its handle a sequence, so
    /// <see cref="TpmCommandExecutor"/> demands a caller-supplied cpHash Name for it instead of deriving the
    /// Empty Buffer — the only way a host can present a command HMAC computed over a Name term the TPM never
    /// folds. It owns nothing: the buffer memory is the caller's.
    /// </summary>
    /// <param name="sequenceHandle">The <c>@sequenceHandle</c> handle value.</param>
    /// <param name="buffer">The <c>buffer</c> parameter's octets — borrowed; the caller owns them.</param>
    private sealed class CallerNamedSequenceUpdateInput(uint sequenceHandle, ReadOnlyMemory<byte> buffer): ITpmCommandInput
    {
        /// <summary>The <c>TPM2_SequenceUpdate()</c> command code.</summary>
        public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_SequenceUpdate;

        /// <summary><c>buffer</c> is a sized first parameter, so a decrypt session may protect it.</summary>
        public bool FirstCommandParameterIsEncryptable => true;

        /// <summary>The handle area (<c>@sequenceHandle</c>) plus <c>buffer</c> as a TPM2B.</summary>
        /// <returns>The serialized size.</returns>
        public int GetSerializedSize() => sizeof(uint) + sizeof(ushort) + buffer.Length;

        /// <summary>Writes <c>@sequenceHandle</c>.</summary>
        /// <param name="writer">The writer.</param>
        public void WriteHandles(ref TpmWriter writer) => writer.WriteUInt32(sequenceHandle);

        /// <summary>Writes <c>buffer</c> verbatim as a TPM2B.</summary>
        /// <param name="writer">The writer.</param>
        public void WriteParameters(ref TpmWriter writer) => writer.WriteTpm2b(buffer.Span);
    }

    /// <summary>
    /// A <c>TPM2_SequenceUpdate()</c> input that declares its sequence handle exactly as
    /// <see cref="SequenceUpdateInput"/> does but frames a <c>buffer</c> wider than
    /// <see cref="Tpm2bMaxBuffer.MaxSize"/>, bypassing that type's own caller-side bound so the TPM's bound is
    /// the one under test. It owns nothing: the buffer memory is the caller's.
    /// </summary>
    /// <param name="sequenceHandle">The <c>@sequenceHandle</c> handle value.</param>
    /// <param name="buffer">The over-bound <c>buffer</c> octets — borrowed; the caller owns them.</param>
    private sealed class UnboundedSequenceUpdateInput(uint sequenceHandle, ReadOnlyMemory<byte> buffer): ITpmCommandInput
    {
        /// <summary>The <c>TPM2_SequenceUpdate()</c> command code.</summary>
        public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_SequenceUpdate;

        /// <summary><c>buffer</c> is a sized first parameter, so a decrypt session may protect it.</summary>
        public bool FirstCommandParameterIsEncryptable => true;

        /// <summary>The sequence handle sits at position 0, so its cpHash Name term is the Empty Buffer the executor derives.</summary>
        /// <param name="handleIndex">The zero-based position in the command's handle area.</param>
        /// <returns><see langword="true"/> for the sequence handle's position.</returns>
        public bool HandleIsSequence(int handleIndex) => handleIndex == 0;

        /// <summary>The handle area (<c>@sequenceHandle</c>) plus <c>buffer</c> as a TPM2B.</summary>
        /// <returns>The serialized size.</returns>
        public int GetSerializedSize() => sizeof(uint) + sizeof(ushort) + buffer.Length;

        /// <summary>Writes <c>@sequenceHandle</c>.</summary>
        /// <param name="writer">The writer.</param>
        public void WriteHandles(ref TpmWriter writer) => writer.WriteUInt32(sequenceHandle);

        /// <summary>Writes the over-bound <c>buffer</c> verbatim as a TPM2B.</summary>
        /// <param name="writer">The writer.</param>
        public void WriteParameters(ref TpmWriter writer) => writer.WriteTpm2b(buffer.Span);
    }

    /// <summary>
    /// The No-HMAC-Authorization rule, both directions: over an unbound, unsalted session the session key is the
    /// Empty Buffer, and on a sequence whose own authValue is empty the HMAC key is entirely empty, so the caller
    /// "has the option of either providing the results of the authHMAC computation, or not" — an empty
    /// <c>hmac</c> authorizes the update, and "the TPM will use the same formulation in the response as was in the
    /// command… If hmac was an Empty Buffer in the command, it will be an Empty Buffer in the response", with the
    /// nonceTPM still rolled
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 16.6.16 and clause 16.6.9). The command is framed by hand
    /// because the host session always computes a full authHMAC; the block's arrival is proved by the sequence's
    /// completed digest.
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateWithAnEmptyHmacOverAnUnboundSessionOnAnEmptyAuthSequenceIsAnsweredWithAnEmptyHmac()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateWithAnEmptyHmacOverAnUnboundSessionOnAnEmptyAuthSequenceIsAnsweredWithAnEmptyHmac), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sequenceHandle = await StartHashSequenceAsync(tpm, registry, pool, []).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            (TpmRcConstants code, int nonceTpmSize, int responseHmacSize) = await SubmitSequenceUpdateWithAnEmptyHmacAsync(
                simulator, pool, sessionHandle, sequenceHandle.Value, MessageFirstHalf).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "An empty hmac over an entirely empty HMAC key must authorize the update.");
            Assert.AreEqual(SHA256.HashSizeInBytes, nonceTpmSize, "The response entry must carry a rolled nonceTPM of the session hash's width.");
            Assert.AreEqual(0, responseHmacSize, "An empty command hmac is answered with an empty response hmac — the same formulation in both directions.");

            byte[] digest = await CompleteHashSequenceAsync(tpm, registry, pool, sequenceHandle, MessageSecondHalf, []).ConfigureAwait(false);
            Assert.IsTrue(digest.AsSpan().SequenceEqual(SHA256.HashData(Message)), "The block authorized by the empty hmac must have been appended to the sequence.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Frames <c>TPM2_SequenceUpdate()</c> by hand with ONE real-session block whose <c>nonceCaller</c> and
    /// <c>hmac</c> are both the Empty Buffer (Table 91's handle and parameter, Part 1's Table 15 block), submits
    /// it, and reads the response's code and — on success — its single session entry's nonceTPM and hmac widths
    /// (Part 1, clause 15.6.1; Part 2, clause 10.12.3, Table 157).
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sessionHandle">The authorizing HMAC session.</param>
    /// <param name="sequenceHandle">The sequence to update.</param>
    /// <param name="block">The block to append.</param>
    /// <returns>The response code and, on success, the entry's nonceTPM and hmac sizes (zero otherwise).</returns>
    private async Task<(TpmRcConstants Code, int NonceTpmSize, int ResponseHmacSize)> SubmitSequenceUpdateWithAnEmptyHmacAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint sessionHandle, uint sequenceHandle, byte[] block)
    {
        const int MinimalBlockSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        int commandSize = CommandHeaderSize + sizeof(uint) + sizeof(uint) + MinimalBlockSize + sizeof(ushort) + block.Length;
        byte[] command = new byte[commandSize];
        var writer = new TpmWriter(command);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
        writer.WriteUInt32((uint)commandSize);
        writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_SequenceUpdate);
        writer.WriteUInt32(sequenceHandle);
        writer.WriteUInt32(MinimalBlockSize);
        writer.WriteUInt32(sessionHandle);
        writer.WriteUInt16(0);
        writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
        writer.WriteUInt16(0);
        writer.WriteTpm2b(block);

        TpmResult<TpmResponse> submitted = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitted.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitted.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader header = TpmHeader.Parse(ref reader);
        var code = (TpmRcConstants)header.Code;
        if(code != TpmRcConstants.TPM_RC_SUCCESS)
        {
            return (code, 0, 0);
        }

        _ = reader.ReadUInt32();
        ushort nonceTpmSize = reader.ReadUInt16();
        _ = reader.ReadBytes(nonceTpmSize);
        _ = reader.ReadByte();
        ushort responseHmacSize = reader.ReadUInt16();

        return (code, nonceTpmSize, responseHmacSize);
    }
}
