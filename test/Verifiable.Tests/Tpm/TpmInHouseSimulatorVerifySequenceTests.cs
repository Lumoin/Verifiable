using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Algorithms;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_CreatePrimary()</c>, <c>TPM2_VerifySequenceStart()</c>, <c>TPM2_SequenceUpdate()</c>, and
/// <c>TPM2_VerifySequenceComplete()</c> against the in-house behavioural <see cref="TpmSimulator"/> — entirely
/// in-process, with no external assets — through the same production command path the production code uses
/// (<see cref="TpmCommandExecutor"/> with the real <see cref="VerifySequenceStartInput"/>,
/// <see cref="SequenceUpdateInput"/>, <see cref="VerifySequenceCompleteInput"/>, and response codecs).
/// </summary>
/// <remarks>
/// <para>
/// A verification sequence accumulates a message across zero or more <c>TPM2_SequenceUpdate()</c> calls and is
/// consumed by <c>TPM2_VerifySequenceComplete()</c>, which checks a caller-supplied <c>TPMT_SIGNATURE</c> against
/// the whole accumulated message and, on success, mints a <c>TPMT_TK_VERIFIED</c> tagged
/// <c>TPM_ST_MESSAGE_VERIFIED</c> before flushing the sequence
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3: Commands, clauses 17.6, 20.3; Part 1: Architecture, clause 29.4.6). Unlike
/// <c>TPM2_SignSequenceComplete()</c>, this command carries no trailing <c>buffer</c> parameter (Table 118): the
/// whole message must arrive through <c>TPM2_SequenceUpdate()</c>, and a sequence that never receives one is
/// still a well-formed, empty message.
/// </para>
/// <para>
/// Signatures fed to <c>TPM2_VerifySequenceComplete()</c> in the tests below are minted ON-TPM — by
/// <c>TPM2_SignDigest()</c> over an independent SHA-256 digest of the message computed with framework
/// <c>SHA256.HashData(...)</c>, or (in one test) by <c>TPM2_SignSequenceComplete()</c> itself — never by a
/// framework signer, since the simulator holds no private key material a framework signer could reach. The
/// Equation (5) ticket reproduction likewise runs entirely off the registered digest and HMAC seams the
/// simulator itself hashes with: framework <c>SHA256.HashData(...)</c> derives the proof from the injected seed
/// and framework <c>HMACSHA256.HashData(...)</c> authenticates a hand-built message of
/// <c>tag ‖ raw message ‖ keyName</c> (no digest, no metadata) — reproducing both the proof derivation and the
/// ticket HMAC with a primitive the simulator never touches.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorVerifySequenceTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The number of bytes in a SHA-256 digest or a SHA-256 HMAC — distinct from <see cref="P256ComponentSize"/> even though both are 32, so a move to a wider curve or hash does not silently ask for the wrong width.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The RSA modulus size in bits used by the RSA signing tests.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>A placeholder ECDSA signature (r ‖ s, both zero) for gates that reject before the verify delegate ever runs.</summary>
    private static byte[] PlaceholderEcdsaSignature { get; } = new byte[2 * P256ComponentSize];

    /// <summary>A fixed seed standing in for the hierarchy's persistent random proof secret, injected to make the verified ticket reproducible.</summary>
    private static byte[] TicketSeed { get; } = Convert.FromHexString("B1C2D3E4F5061728394A5B6C7D8E9F00112233445566778899AABBCCDDEEFF");

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// <c>TPM2_VerifySequenceStart()</c> against an unrestricted ECC signing/verification key returns a handle
    /// whose most-significant octet is <c>TPM_HT_TRANSIENT</c>, distinct from the key's own handle — the same
    /// shared transient allocator every other sequence and object handle is drawn from
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.6, Table 90; Part 1: Architecture, clause 27.2.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartOnAnUnrestrictedEccKeyReturnsATransientHandleDistinctFromTheKeys()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        Assert.IsTrue(sequenceHandle.IsTransient, "A verification sequence's handle most-significant octet must be TPM_HT_TRANSIENT.");
        Assert.AreNotEqual(primary.ObjectHandle, sequenceHandle, "A verification sequence's handle must never alias the key's own handle.");
    }

    /// <summary>
    /// <c>TPM2_FlushContext()</c> "causes all context associated with a loaded object, sequence object, or
    /// session to be removed"; an open verification sequence is flushed by it, and a second flush on the same,
    /// already-flushed handle answers <c>TPM_RC_HANDLE</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 28.4).
    /// </summary>
    [TestMethod]
    public async Task FlushContextOnAVerificationSequenceHandleSucceedsAndASecondFlushReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        FlushContextInput flushInput = FlushContextInput.ForHandle(sequenceHandle.Value);
        TpmResult<FlushContextResponse> firstFlush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(firstFlush.IsSuccess, $"TPM2_FlushContext() on an open verification sequence must succeed: '{firstFlush.ResponseCode}'.");

        TpmResult<FlushContextResponse> secondFlush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, secondFlush.ResponseCode, "A second TPM2_FlushContext() on the same, already-flushed sequence handle must be refused with TPM_RC_HANDLE.");
    }

    /// <summary>
    /// "If keyHandle does not refer to a signing key, the TPM shall return TPM_RC_KEY" — clause 17.6 restates the
    /// same sentence for the verifying handle: a storage parent's <c>sign</c> (SIGN_ENCRYPT) attribute is CLEAR
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.6).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartOnAStorageParentReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<VerifySequenceStartResponse> startResult = await SubmitVerifyStartAsync(tpm, registry, pool, parent.ObjectHandle, []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, startResult.ResponseCode, "A storage parent's sign attribute is CLEAR; TPM2_VerifySequenceStart() must refuse it with TPM_RC_KEY.");
    }

    /// <summary>
    /// "If keyHandle refers to a key whose scheme is TPM_ALG_NULL, the TPM shall return TPM_RC_SCHEME"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.6).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartOnANullSchemeRsaTemplateReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmtRsaScheme.Null).ConfigureAwait(false);

        TpmResult<VerifySequenceStartResponse> startResult = await SubmitVerifyStartAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, startResult.ResponseCode, "A key created with a NULL template scheme retains none; TPM2_VerifySequenceStart() must refuse it with TPM_RC_SCHEME.");
    }

    /// <summary>
    /// A loaded sealed (KEYEDHASH data) object is not a signing/verification key
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.6).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartOnALoadedSealedObjectHandleReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sealedHandle = await CreateLoadedSealedObjectHandleAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<VerifySequenceStartResponse> startResult = await SubmitVerifyStartAsync(tpm, registry, pool, sealedHandle, []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, startResult.ResponseCode, "A sealed (KEYEDHASH data) object is not a verification key; TPM2_VerifySequenceStart() must refuse it with TPM_RC_KEY.");
    }

    /// <summary>
    /// <c>keyHandle</c> resolving nowhere is refused with <c>TPM_RC_HANDLE</c> ("the handle is not correct for
    /// the use", Table 17)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.6).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartOnAnUnknownHandleReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<VerifySequenceStartResponse> startResult = await SubmitVerifyStartAsync(
            tpm, registry, pool, TpmiDhObject.FromValue(0x8000_7FFFu), []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, startResult.ResponseCode, "A keyHandle resolving nowhere must be refused with TPM_RC_HANDLE.");
    }

    /// <summary>
    /// "hint must be supplied for TPM_ALG_EDDSA, and must be zero-length in all other cases": a non-empty hint
    /// under ECDSA is refused with <c>TPM_RC_SIZE</c>, the same basis Table 220's <c>empty[0]</c> arm gives the
    /// neighbouring <c>context</c> parameter. <see cref="VerifySequenceStartInput"/> always frames an empty hint,
    /// so this hand-frames the command
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.6).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartWithANonEmptyHintHandFramedReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        byte[] nonEmptyHint = [0x01];
        TpmRcConstants code = await SubmitVerifySequenceStartCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, primary.ObjectHandle.Value, [], nonEmptyHint, []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "A non-empty hint under ECDSA must be refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// A non-empty <c>context</c> is refused with <c>TPM_RC_SIZE</c> under every scheme this simulator executes
    /// (Table 220's <c>empty[0]</c> arm), mirroring
    /// <see cref="VerifySequenceStartWithANonEmptyHintHandFramedReturnsSize"/> for the neighbouring parameter
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.7/11.3.8, Tables 220/221).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartWithANonEmptyContextHandFramedReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        byte[] nonEmptyContext = [0x01];
        TpmRcConstants code = await SubmitVerifySequenceStartCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, primary.ObjectHandle.Value, [], [], nonEmptyContext).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "A non-empty context under any scheme this simulator executes must be refused with TPM_RC_SIZE (Table 220's empty[0] arm).");
    }

    /// <summary>
    /// <c>TPM2_VerifySequenceStart()</c> is framed <c>TPM_ST_NO_SESSIONS</c> — no authorization of <c>keyHandle</c>
    /// is required — so a command framed <c>TPM_ST_SESSIONS</c> is refused with <c>TPM_RC_BAD_TAG</c>, matching
    /// <c>TPM2_SignSequenceStart()</c>'s own posture for the identical Auth Index None handle
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.6, Table 89).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartFramedWithSessionsReturnsBadTag()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        TpmRcConstants code = await SubmitVerifySequenceStartCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_SESSIONS, primary.ObjectHandle.Value, [], [], []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_TAG, code, "TPM2_VerifySequenceStart() framed with TPM_ST_SESSIONS must be refused with TPM_RC_BAD_TAG.");
    }

    /// <summary>
    /// Clause 17.5's "Authorization of the key referenced by keyHandle is not required at this time" governs
    /// <c>TPM2_VerifySequenceStart()</c> exactly as it governs <c>TPM2_SignSequenceStart()</c>: Table 89 types
    /// <c>keyHandle</c> Auth Index None, so a bare command with no sessions at all succeeds against a
    /// DA-protected password-guarded key, and never moves <c>failedTries</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.5's quote applied via clause 17.6, Table 89's Auth Index None).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartOnADaProtectedPasswordGuardedKeySucceedsWithNoSessionsAndLeavesLockoutCounterUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateDaProtectedEccSigningPrimaryAsync(tpm, registry, pool, "verify-start-no-auth-password").ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<VerifySequenceStartResponse> startResult = await SubmitVerifyStartAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"TPM2_VerifySequenceStart() with no sessions at all, against a DA-protected password-guarded key, must succeed: '{startResult.ResponseCode}'.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "TPM2_VerifySequenceStart() must never move failedTries: it checks no authorization of keyHandle at all.");
    }

    /// <summary>
    /// An <c>x509sign</c> signing key is ADMITTED at both <c>TPM2_VerifySequenceStart()</c> and
    /// <c>TPM2_VerifySequenceComplete()</c>, unlike at <c>TPM2_SignSequenceStart()</c>/<c>TPM2_SignSequenceComplete()</c>:
    /// "This attribute does not limit the use of the key in any command other than TPM2_Sign(),
    /// TPM2_SignSequenceComplete(), and TPM2_SignDigest()"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 8.3.3.15, Table 37, Bit[19]).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteOnAnX509SignKeySucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateX509SignEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] message = "an x509sign key verifying through the sequence commands."u8.ToArray();
        byte[] digest = SHA256.HashData(message);
        byte[] p1363Signature = await SignDigestEcdsaAsync(tpm, registry, pool, primary.ObjectHandle, digest).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], message).ConfigureAwait(false);

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> result = await SubmitVerifyCompleteAsync(tpm, registry, pool, input, []).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"An x509sign key must be admitted at both TPM2_VerifySequenceStart() and TPM2_VerifySequenceComplete(): '{result.ResponseCode}'.");
        result.Value.Dispose();
    }

    /// <summary>
    /// A correct sequence auth authorizes <c>TPM2_SequenceUpdate()</c> against a verification sequence exactly as
    /// it does against a signing sequence, and a wrong auth is refused with the plain, session-index-0-encoded
    /// <c>TPM_RC_BAD_AUTH</c> — never charging the key's own dictionary-attack counter, since the sequence's
    /// authValue is exempt
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 29.4.6; Part 3: Commands, clause 17.7).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateOnAVerificationSequenceWithCorrectAuthSucceedsAndWrongAuthReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateDaProtectedEccSigningPrimaryAsync(tpm, registry, pool, "verify-update-key-auth").ConfigureAwait(false);
        byte[] sequenceAuth = System.Text.Encoding.UTF8.GetBytes("verify-update-sequence-auth");
        byte[] wrongSequenceAuth = System.Text.Encoding.UTF8.GetBytes("wrong-verify-update-sequence-auth");
        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, sequenceAuth).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<SequenceUpdateResponse> correctResult = await SubmitUpdateAsync(tpm, registry, pool, sequenceHandle, sequenceAuth, "some data"u8.ToArray()).ConfigureAwait(false);
        Assert.IsTrue(correctResult.IsSuccess, $"TPM2_SequenceUpdate() with the correct sequence auth must succeed: '{correctResult.ResponseCode}'.");

        TpmResult<SequenceUpdateResponse> wrongResult = await SubmitUpdateAsync(tpm, registry, pool, sequenceHandle, wrongSequenceAuth, "more data"u8.ToArray()).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), wrongResult.ResponseCode,
            "A wrong sequence auth over the sequence handle's own TPM_RS_PW session must be refused with session-index-0-encoded TPM_RC_BAD_AUTH.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A sequence's authValue is exempt from dictionary-attack protection; a wrong sequence auth must never move failedTries.");
    }

    /// <summary>
    /// <c>TPM2_VerifySequenceComplete()</c>'s own sequence-authorization gate (Table 118's
    /// <c>@sequenceHandle</c>, Auth Index 1, USER role): a wrong sequence auth is refused with the plain,
    /// session-index-0-encoded <c>TPM_RC_BAD_AUTH</c> and never charges the key's dictionary-attack counter —
    /// the sequence's authValue is exempt — and the correct auth then completes with a real
    /// <c>TPM_ST_MESSAGE_VERIFIED</c> ticket
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 29.4.6; Part 3: Commands, clause 20.3, Table 118).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithWrongSequenceAuthReturnsBadAuthUnchargedAndCorrectAuthSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateDaProtectedEccSigningPrimaryAsync(tpm, registry, pool, "verify-complete-key-auth").ConfigureAwait(false);
        byte[] sequenceAuth = System.Text.Encoding.UTF8.GetBytes("verify-complete-sequence-auth");
        byte[] wrongSequenceAuth = System.Text.Encoding.UTF8.GetBytes("wrong-verify-complete-sequence-auth");
        byte[] message = "a message accumulated under an authorization-guarded verification sequence."u8.ToArray();

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, sequenceAuth).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, sequenceAuth, message).ConfigureAwait(false);

        byte[] digest = SHA256.HashData(message);
        byte[] p1363Signature = await SignDigestEcdsaAsync(tpm, registry, pool, primary.ObjectHandle, digest, System.Text.Encoding.UTF8.GetBytes("verify-complete-key-auth")).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using VerifySequenceCompleteInput wrongAuthInput = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> wrongAuthResult = await SubmitVerifyCompleteAsync(tpm, registry, pool, wrongAuthInput, wrongSequenceAuth).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), wrongAuthResult.ResponseCode,
            "A wrong sequence auth at TPM2_VerifySequenceComplete() must be refused with session-index-0-encoded TPM_RC_BAD_AUTH, uncharged.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A wrong sequence auth at TPM2_VerifySequenceComplete() must never move failedTries; the sequence's authValue is exempt from dictionary-attack protection.");

        using VerifySequenceCompleteInput correctAuthInput = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> correctAuthResult = await SubmitVerifyCompleteAsync(tpm, registry, pool, correctAuthInput, sequenceAuth).ConfigureAwait(false);
        Assert.IsTrue(correctAuthResult.IsSuccess, $"TPM2_VerifySequenceComplete() with the correct sequence auth must succeed: '{correctAuthResult.ResponseCode}'.");

        using VerifySequenceCompleteResponse verified = correctAuthResult.Value;
        Assert.AreEqual(TpmStConstants.TPM_ST_MESSAGE_VERIFIED, verified.Validation.Tag, "The correctly-authorized completion must return a real MESSAGE_VERIFIED ticket.");
    }

    /// <summary>
    /// The ECDSA happy path with the two-sided proof: a message split across three <c>TPM2_SequenceUpdate()</c>
    /// calls verifies against a signature <c>TPM2_SignDigest()</c> produced over the SHA-256 digest of the whole
    /// message, the returned ticket is tagged <c>TPM_ST_MESSAGE_VERIFIED</c> with NO metadata, and its HMAC is
    /// independently reproduced from the injected proof seed — Equation (5),
    /// <c>HMAC_contextAlg(proof, tag ‖ message ‖ keyName)</c>, with no digest and no metadata
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.5; Part 3: Commands, clause 20.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteEcdsaAcrossMultipleUpdatesReproducesEquationFiveFromTheInjectedSeed()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateSeededOperationalAsync(TicketSeed, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        byte[] chunk1 = "Verifiable "u8.ToArray();
        byte[] chunk2 = "in-house TPM "u8.ToArray();
        byte[] chunk3 = "verification sequence acceptance test."u8.ToArray();
        byte[] fullMessage = [.. chunk1, .. chunk2, .. chunk3];

        byte[] digest = SHA256.HashData(fullMessage);
        byte[] p1363Signature = await SignDigestEcdsaAsync(tpm, registry, pool, primary.ObjectHandle, digest).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk1).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk2).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk3).ConfigureAwait(false);

        using VerifySequenceCompleteInput completeInput = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> completeResult = await SubmitVerifyCompleteAsync(tpm, registry, pool, completeInput, []).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_VerifySequenceComplete() (ECDSA) failed: '{completeResult.ResponseCode}'.");

        using VerifySequenceCompleteResponse verified = completeResult.Value;
        Assert.AreEqual(TpmStConstants.TPM_ST_MESSAGE_VERIFIED, verified.Validation.Tag, "The ticket tag must be TPM_ST_MESSAGE_VERIFIED.");
        Assert.AreEqual(TpmiRhHierarchy.Owner, verified.Validation.Hierarchy, "The ticket hierarchy must be the verifying key's own hierarchy.");
        Assert.IsFalse(verified.Validation.IsNull, "A successful verification must return a real ticket, not a NULL ticket.");
        Assert.HasCount(Sha256DigestSize, verified.Validation.Hmac, "The verified ticket HMAC is a SHA-256 HMAC.");
        Assert.IsFalse(verified.Validation.Metadata.HasValue, "A TPM_ST_MESSAGE_VERIFIED ticket must carry NO metadata (Table 111's messageVerified arm is TPMS_EMPTY).");

        //Recompute the ticket exactly as TPM2_VerifySequenceComplete would: proof = H(seed || hierarchy), and the
        //ticket HMAC is HMAC(proof, TPM_ST_MESSAGE_VERIFIED || message || keyName) — Equation (5), NO digest and
        //NO metadata: a TPM_ST_MESSAGE_VERIFIED ticket's digestOrMessage is the raw accumulated message
        //(Part 2, clause 10.6.5), never its digest.
        byte[] proof = SHA256.HashData(BuildProofInput(TicketSeed, (uint)TpmRh.TPM_RH_OWNER));
        byte[] ticketMessage = BuildMessageVerifiedTicketMessage(fullMessage, primary.Name.Span);
        byte[] expectedTicket = HMACSHA256.HashData(proof, ticketMessage);

        Assert.IsTrue(
            expectedTicket.AsSpan().SequenceEqual(verified.Validation.Hmac),
            "The verified ticket must be HMAC(H(seed || hierarchy), TPM_ST_MESSAGE_VERIFIED || message || keyName), verifiable against the injected seed with no digest and no metadata.");
    }

    /// <summary>
    /// The RSASSA counterpart of <see cref="VerifySequenceCompleteEcdsaAcrossMultipleUpdatesReproducesEquationFiveFromTheInjectedSeed"/>:
    /// an RSA key created with an EXPLICIT RSASSA/SHA-256 template scheme verifies a signature over the whole
    /// accumulated message under that retained scheme
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3; Part 3: Commands, clause 20.1, Table 115).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteRsaSsaAcrossMultipleUpdatesSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRsaSigningPrimaryAsync(
            tpm, registry, pool, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256)).ConfigureAwait(false);

        byte[] chunk1 = "RSASSA "u8.ToArray();
        byte[] chunk2 = "verification sequence "u8.ToArray();
        byte[] chunk3 = "acceptance test."u8.ToArray();
        byte[] fullMessage = [.. chunk1, .. chunk2, .. chunk3];

        byte[] digest = SHA256.HashData(fullMessage);
        byte[] rsaSignature = await SignDigestRsaAsync(tpm, registry, pool, primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_RSASSA).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk1).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk2).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk3).ConfigureAwait(false);

        using VerifySequenceCompleteInput completeInput = VerifySequenceCompleteInput.ForRsaSsa(
            sequenceHandle, primary.ObjectHandle, rsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> completeResult = await SubmitVerifyCompleteAsync(tpm, registry, pool, completeInput, []).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_VerifySequenceComplete() (RSASSA) failed: '{completeResult.ResponseCode}'.");

        using VerifySequenceCompleteResponse verified = completeResult.Value;
        Assert.AreEqual(TpmStConstants.TPM_ST_MESSAGE_VERIFIED, verified.Validation.Tag);
        Assert.IsFalse(verified.Validation.Metadata.HasValue, "A TPM_ST_MESSAGE_VERIFIED ticket must carry NO metadata.");
    }

    /// <summary>
    /// The RSAPSS counterpart of <see cref="VerifySequenceCompleteRsaSsaAcrossMultipleUpdatesSucceeds"/>, proving
    /// the RETAINED PSS scheme, not a fixed model default, drives the verification primitive
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3; Part 3: Commands, clause 20.1, Table 115).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteRsaPssAcrossMultipleUpdatesSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRsaSigningPrimaryAsync(
            tpm, registry, pool, TpmtRsaScheme.RsaPss(TpmAlgIdConstants.TPM_ALG_SHA256)).ConfigureAwait(false);

        byte[] chunk1 = "RSAPSS "u8.ToArray();
        byte[] chunk2 = "verification sequence "u8.ToArray();
        byte[] chunk3 = "acceptance test."u8.ToArray();
        byte[] fullMessage = [.. chunk1, .. chunk2, .. chunk3];

        byte[] digest = SHA256.HashData(fullMessage);
        byte[] rsaSignature = await SignDigestRsaAsync(tpm, registry, pool, primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_RSAPSS).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk1).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk2).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk3).ConfigureAwait(false);

        using VerifySequenceCompleteInput completeInput = VerifySequenceCompleteInput.ForRsaPss(
            sequenceHandle, primary.ObjectHandle, rsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> completeResult = await SubmitVerifyCompleteAsync(tpm, registry, pool, completeInput, []).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_VerifySequenceComplete() (RSAPSS) failed: '{completeResult.ResponseCode}'.");

        using VerifySequenceCompleteResponse verified = completeResult.Value;
        Assert.AreEqual(TpmStConstants.TPM_ST_MESSAGE_VERIFIED, verified.Validation.Tag);
    }

    /// <summary>
    /// A signature minted by <c>TPM2_SignSequenceComplete()</c> over a message verifies through
    /// <c>TPM2_VerifySequenceComplete()</c> over the SAME message under a fresh verification sequence — the two
    /// sequence-command families agree on how the key's scheme hashes the accumulated message
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 17.5, 17.6, 20.1's Table 115, 20.3, 20.6).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteAcceptsASignatureMintedBySignSequenceCompleteOverTheSameMessage()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] message = "the same message signed by one sequence family and verified by the other."u8.ToArray();

        TpmiDhObject signingSequence = await StartSignSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, signingSequence, [], message).ConfigureAwait(false);

        using SignSequenceCompleteInput signCompleteInput = SignSequenceCompleteInput.Create(
            signingSequence, primary.ObjectHandle, ReadOnlySpan<byte>.Empty, pool);
        using TpmPasswordSession signSequenceSession = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signKeySession = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<SignSequenceCompleteResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
            tpm, signCompleteInput, [signSequenceSession, signKeySession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_SignSequenceComplete() failed: '{signResult.ResponseCode}'.");

        using SignSequenceCompleteResponse signature = signResult.Value;
        byte[] p1363Signature = ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan());

        TpmiDhObject verifySequence = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, verifySequence, [], message).ConfigureAwait(false);

        using VerifySequenceCompleteInput verifyInput = VerifySequenceCompleteInput.ForEcdsa(
            verifySequence, primary.ObjectHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> verifyResult = await SubmitVerifyCompleteAsync(tpm, registry, pool, verifyInput, []).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"A signature minted by TPM2_SignSequenceComplete() must verify through TPM2_VerifySequenceComplete() over the same message: '{verifyResult.ResponseCode}'.");
        verifyResult.Value.Dispose();
    }

    /// <summary>
    /// The failure counterpart of the happy path: a corrupted signature is refused with <c>TPM_RC_SIGNATURE</c>
    /// and the sequence is RETAINED (not flushed) — "the state of the sequence is unmodified" carries over to a
    /// failing Complete just as it does to a failing Update — so the good signature then verifies against the
    /// SAME, still-open sequence
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithACorruptedSignatureReturnsSignatureAndTheSequenceSurvives()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] message = "a message whose signature will be corrupted, then retried intact."u8.ToArray();
        byte[] digest = SHA256.HashData(message);
        byte[] p1363Signature = await SignDigestEcdsaAsync(tpm, registry, pool, primary.ObjectHandle, digest).ConfigureAwait(false);

        byte[] corrupted = (byte[])p1363Signature.Clone();
        corrupted[^1] ^= 0xFF;

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], message).ConfigureAwait(false);

        using VerifySequenceCompleteInput badInput = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, corrupted, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> badResult = await SubmitVerifyCompleteAsync(tpm, registry, pool, badInput, []).ConfigureAwait(false);
        Assert.IsFalse(badResult.IsSuccess, "A corrupted signature must not verify.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIGNATURE, badResult.ResponseCode);

        using VerifySequenceCompleteInput goodInput = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> goodResult = await SubmitVerifyCompleteAsync(tpm, registry, pool, goodInput, []).ConfigureAwait(false);
        Assert.IsTrue(goodResult.IsSuccess, $"The good signature must verify against the still-open, unmodified sequence: '{goodResult.ResponseCode}'.");
        goodResult.Value.Dispose();
    }

    /// <summary>
    /// "If keyHandle refers to a key that is not the same as the key that was used to start the signature
    /// context, the TPM shall return TPM_RC_SIGN_CONTEXT_KEY": a different key is refused and the sequence
    /// SURVIVES, so a retry with the starting key still verifies
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithADifferentKeyReturnsSignContextKeyAndTheSequenceSurvives()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse startingKey = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse otherKey = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        byte[] message = "verified only by the key that started this sequence."u8.ToArray();
        byte[] digest = SHA256.HashData(message);
        byte[] p1363Signature = await SignDigestEcdsaAsync(tpm, registry, pool, startingKey.ObjectHandle, digest).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, startingKey.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], message).ConfigureAwait(false);

        using VerifySequenceCompleteInput wrongKeyInput = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, otherKey.ObjectHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> wrongKeyResult = await SubmitVerifyCompleteAsync(tpm, registry, pool, wrongKeyInput, []).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIGN_CONTEXT_KEY, wrongKeyResult.ResponseCode,
            "Completing with a key different from the one that started the sequence must be refused with TPM_RC_SIGN_CONTEXT_KEY.");

        using VerifySequenceCompleteInput retryInput = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, startingKey.ObjectHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> retryResult = await SubmitVerifyCompleteAsync(tpm, registry, pool, retryInput, []).ConfigureAwait(false);
        Assert.IsTrue(retryResult.IsSuccess, $"The sequence must survive the TPM_RC_SIGN_CONTEXT_KEY refusal and complete under its own starting key: '{retryResult.ResponseCode}'.");
        retryResult.Value.Dispose();
    }

    /// <summary>
    /// A <c>keyHandle</c> resolving to a loaded sealed (KEYEDHASH data) object is not a verification key
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithKeyHandleResolvingToASealedObjectReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        TpmiDhObject sealedHandle = await CreateLoadedSealedObjectHandleAsync(tpm, registry, pool).ConfigureAwait(false);

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, sealedHandle, PlaceholderEcdsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> result = await SubmitVerifyCompleteAsync(tpm, registry, pool, input, []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, result.ResponseCode, "A keyHandle resolving to a sealed object is not a verification key; TPM2_VerifySequenceComplete() must refuse it with TPM_RC_KEY.");
    }

    /// <summary>
    /// A <c>keyHandle</c> resolving to a sequence object (the sequence's own handle presented as the verification
    /// key) is not a verification key
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithKeyHandleResolvingToTheSequenceItselfReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, sequenceHandle, PlaceholderEcdsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> result = await SubmitVerifyCompleteAsync(tpm, registry, pool, input, []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, result.ResponseCode, "A keyHandle resolving to the sequence's own handle is not a verification key; TPM2_VerifySequenceComplete() must refuse it with TPM_RC_KEY.");
    }

    /// <summary>
    /// A <c>keyHandle</c> resolving nowhere is refused with <c>TPM_RC_HANDLE</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithAnUnknownKeyHandleReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, TpmiDhObject.FromValue(0x8000_7FFEu), PlaceholderEcdsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> result = await SubmitVerifyCompleteAsync(tpm, registry, pool, input, []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, result.ResponseCode, "A keyHandle resolving nowhere must be refused with TPM_RC_HANDLE.");
    }

    /// <summary>
    /// A genuine RSASSA signature presented under the claimed RSAPSS scheme is refused with <c>TPM_RC_SCHEME</c>:
    /// clause 20.4.1's own sentence — "The TPM will verify that the signing scheme (including the hash or XOF
    /// algorithm) in signature matches the signing scheme of keyHandle" — applies here exactly as it does at
    /// <c>TPM2_VerifyDigestSignature()</c>, whose clause 20.4 is itself "like" <c>TPM2_VerifySequenceComplete()</c>'s
    /// own clause 20.3; the signature's declared scheme must be the EXACT scheme retained by the key, not merely
    /// a compatible family
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.4.1, applied to clause 20.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithAnRsassaSignaturePresentedAsRsapssReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRsaSigningPrimaryAsync(
            tpm, registry, pool, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256)).ConfigureAwait(false);
        byte[] message = "an RSASSA signature masquerading as RSAPSS."u8.ToArray();
        byte[] digest = SHA256.HashData(message);
        byte[] rsaSignature = await SignDigestRsaAsync(tpm, registry, pool, primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_RSASSA).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], message).ConfigureAwait(false);

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForRsaPss(
            sequenceHandle, primary.ObjectHandle, rsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> result = await SubmitVerifyCompleteAsync(tpm, registry, pool, input, []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, result.ResponseCode, "A genuine RSASSA signature presented under the claimed RSAPSS scheme must be refused with TPM_RC_SCHEME.");
    }

    /// <summary>
    /// An ECDSA key whose retained template scheme hash is SHA-256 refuses a signature claiming SHA-384 with
    /// <c>TPM_RC_SCHEME</c>, ahead of any hashing or verification — the scheme gate precedes the empty sequence's
    /// content ever mattering — under clause 20.4.1's own exact-match sentence (the hash or XOF algorithm is part
    /// of the scheme it compares), applied to <c>TPM2_VerifySequenceComplete()</c> as clause 20.4's stated
    /// sibling
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.4.1, applied to clause 20.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithMismatchedHashAlgorithmReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, PlaceholderEcdsaSignature, TpmAlgIdConstants.TPM_ALG_SHA384, pool);
        TpmResult<VerifySequenceCompleteResponse> result = await SubmitVerifyCompleteAsync(tpm, registry, pool, input, []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, result.ResponseCode, "A signature declaring SHA-384 against a SHA-256-schemed key must be refused with TPM_RC_SCHEME.");
    }

    /// <summary>
    /// A signing sequence cannot be completed by <c>TPM2_VerifySequenceComplete()</c>: clause 17.8's "If
    /// sequenceHandle references an Event Sequence, then the TPM shall return TPM_RC_MODE" and clause 17.9's "If
    /// sequenceHandle references a hash or HMAC sequence, the TPM shall return TPM_RC_MODE" both answer
    /// <c>TPM_RC_MODE</c> for a sequence handle of the wrong kind presented to a Complete command; the same rule
    /// applies to the Signing/Verification pair this model adds — a sequence completes only under the command
    /// family that started it
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 17.8, 17.9).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteOnASigningSequenceReturnsMode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        TpmiDhObject signingSequence = await StartSignSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            signingSequence, primary.ObjectHandle, PlaceholderEcdsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> result = await SubmitVerifyCompleteAsync(tpm, registry, pool, input, []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_MODE, result.ResponseCode, "TPM2_VerifySequenceComplete() against a SIGNING sequence must be refused with TPM_RC_MODE.");
    }

    /// <summary>
    /// The mirror of <see cref="VerifySequenceCompleteOnASigningSequenceReturnsMode"/>: a verification sequence
    /// cannot be completed by <c>TPM2_SignSequenceComplete()</c>, the same "wrong sequence kind for this Complete
    /// command" refusal clauses 17.8 and 17.9 answer with <c>TPM_RC_MODE</c> for an Event or hash/HMAC sequence
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 17.8, 17.9).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOnAVerificationSequenceReturnsMode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        TpmiDhObject verifySequence = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        using SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(verifySequence, primary.ObjectHandle, ReadOnlySpan<byte>.Empty, pool);
        using TpmPasswordSession sequenceSession = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keySession = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<SignSequenceCompleteResponse> result = await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
            tpm, input, [sequenceSession, keySession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_MODE, result.ResponseCode, "TPM2_SignSequenceComplete() against a VERIFICATION sequence must be refused with TPM_RC_MODE.");
    }

    /// <summary>
    /// "If the key is in the NULL hierarchy, then hmac in the ticket will be the Empty Buffer": a NULL-hierarchy
    /// key's successful verification still returns a real <c>TPM_ST_MESSAGE_VERIFIED</c> tag, but the NULL tuple
    /// — <c>TPM_RH_NULL</c>, empty hmac, no metadata
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteAgainstANullHierarchyKeyReturnsTheNullTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_NULL).ConfigureAwait(false);
        byte[] message = "verified under a NULL-hierarchy key."u8.ToArray();
        byte[] digest = SHA256.HashData(message);
        byte[] p1363Signature = await SignDigestEcdsaAsync(tpm, registry, pool, primary.ObjectHandle, digest).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], message).ConfigureAwait(false);

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> result = await SubmitVerifyCompleteAsync(tpm, registry, pool, input, []).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_VerifySequenceComplete() (NULL hierarchy key) failed: '{result.ResponseCode}'.");

        using VerifySequenceCompleteResponse verified = result.Value;
        Assert.AreEqual(TpmStConstants.TPM_ST_MESSAGE_VERIFIED, verified.Validation.Tag, "The ticket tag must still be TPM_ST_MESSAGE_VERIFIED.");
        Assert.IsTrue(verified.Validation.IsNull, "A NULL-hierarchy key's ticket must be the NULL tuple.");
        Assert.IsTrue(verified.Validation.Hierarchy.IsNull, "The ticket hierarchy must be TPM_RH_NULL.");
        Assert.IsTrue(verified.Validation.Hmac.IsEmpty, "The NULL ticket's hmac must be the Empty Buffer.");
        Assert.IsFalse(verified.Validation.Metadata.HasValue, "The NULL ticket must still carry NO metadata (Table 111's messageVerified arm admits no metadata at all).");
    }

    /// <summary>
    /// A verification sequence that never receives a single <c>TPM2_SequenceUpdate()</c> accumulates the EMPTY
    /// message, and a signature over SHA-256("") verifies against it — an empty sequence is well-formed, not a
    /// refusal. Part 1 clause 29.4.5.2's own note — "TPM2_VerifySequenceComplete() does not allow passing
    /// additional data into the sequence, so TPM2_SequenceUpdate() needs to be used at least once" — describes
    /// usage rather than naming a response code, so it does not forbid this admission; the resulting
    /// <c>TPM_ST_MESSAGE_VERIFIED</c> ticket's HMAC is reproduced from the injected seed over the zero-segment
    /// chain <c>tag ‖ keyName</c> alone (no message octets, no digest, no metadata) to pin that the empty
    /// accumulator folds correctly rather than only that the command happens to succeed
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 29.4.5.2; Part 3: Commands, clause 20.3; Part 2:
    /// Structures, clause 10.6.5).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteOverAnEmptySequenceVerifiesASignatureOverTheEmptyMessage()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateSeededOperationalAsync(TicketSeed, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] digest = SHA256.HashData(ReadOnlySpan<byte>.Empty);
        byte[] p1363Signature = await SignDigestEcdsaAsync(tpm, registry, pool, primary.ObjectHandle, digest).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> result = await SubmitVerifyCompleteAsync(tpm, registry, pool, input, []).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"An empty verification sequence must be admitted and verify a signature over SHA-256(\"\"): '{result.ResponseCode}'.");

        using VerifySequenceCompleteResponse verified = result.Value;
        byte[] proof = SHA256.HashData(BuildProofInput(TicketSeed, (uint)TpmRh.TPM_RH_OWNER));
        byte[] ticketMessage = BuildMessageVerifiedTicketMessage(ReadOnlySpan<byte>.Empty, primary.Name.Span);
        byte[] expectedTicket = HMACSHA256.HashData(proof, ticketMessage);

        Assert.IsTrue(
            expectedTicket.AsSpan().SequenceEqual(verified.Validation.Hmac),
            "The empty-sequence ticket must be HMAC(H(seed || hierarchy), TPM_ST_MESSAGE_VERIFIED || keyName) — the zero-segment chain folded with no message octets, no digest, and no metadata.");
    }

    /// <summary>
    /// "When ... TPM2_VerifySequenceComplete() completes successfully, the sequence context is flushed from the
    /// TPM": a second Complete, and a FlushContext, on the same handle both answer <c>TPM_RC_HANDLE</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteFlushesTheSequenceOnSuccess()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] message = "flushed once verified."u8.ToArray();
        byte[] digest = SHA256.HashData(message);
        byte[] p1363Signature = await SignDigestEcdsaAsync(tpm, registry, pool, primary.ObjectHandle, digest).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], message).ConfigureAwait(false);

        using VerifySequenceCompleteInput firstInput = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> firstComplete = await SubmitVerifyCompleteAsync(tpm, registry, pool, firstInput, []).ConfigureAwait(false);
        Assert.IsTrue(firstComplete.IsSuccess, $"The first TPM2_VerifySequenceComplete() must succeed: '{firstComplete.ResponseCode}'.");
        firstComplete.Value.Dispose();

        using VerifySequenceCompleteInput secondInput = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> secondComplete = await SubmitVerifyCompleteAsync(tpm, registry, pool, secondInput, []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, secondComplete.ResponseCode, "A second TPM2_VerifySequenceComplete() on an already-flushed sequence must be refused with TPM_RC_HANDLE.");

        FlushContextInput flushInput = FlushContextInput.ForHandle(sequenceHandle.Value);
        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, flushResult.ResponseCode, "TPM2_FlushContext() on an already-flushed sequence must also be refused with TPM_RC_HANDLE.");
    }

    /// <summary>
    /// The real-wire <c>TPM2_PolicyAuthorize()</c> end-to-end flow over a <c>TPM_ST_MESSAGE_VERIFIED</c> ticket: a
    /// verification sequence over <c>approvedPolicy ‖ policyRef</c> produces a genuine ticket, and
    /// <c>TPM2_PolicyAuthorize()</c> consumes it — recomputing Equation (5) over the RAW <c>toBeSigned</c> octets,
    /// with no digest and no metadata — to replace the session's revisable sub-policy with the fixed,
    /// authority-controlled <c>authPolicy</c> a sealed object was created under, exactly as the VERIFIED-ticket
    /// flow does for <c>TPM2_VerifySignature()</c>'s own ticket family
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 23.16; Part 2: Structures, clause 10.6.5).
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeEccFlowConsumesAMessageVerifiedTicketAndUnsealsUnderThePredictedAuthPolicy()
    {
        const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;
        byte[] secretBytes = "Bind this secret to a MESSAGE_VERIFIED-ticket PolicyAuthorize()."u8.ToArray();

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        using CreatePrimaryResponse authorityKey = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] keySign = authorityKey.Name.Span.ToArray();
        byte[] policyRef = "verify-sequence-policyauthorize-ref"u8.ToArray();

        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] approvedPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForCommandCode(zero, TpmCcConstants.TPM_CC_Unseal, SessionAlg, approvedPolicy);

        byte[] authPolicy = new byte[size];
        _ = TpmPolicyDigest.ExtendForAuthorize(keySign, policyRef, SessionAlg, authPolicy);

        //toBeSigned = approvedPolicy || policyRef (Part 3, clause 23.16, equation 33) is the RAW message the
        //verification sequence accumulates: a MESSAGE_VERIFIED ticket's digestOrMessage is the raw toBeSigned
        //octets, not their digest (Part 2, clause 10.6.5).
        byte[] toBeSigned = [.. approvedPolicy, .. policyRef];
        byte[] digest = SHA256.HashData(toBeSigned);
        byte[] p1363Signature = await SignDigestEcdsaAsync(tpm, registry, pool, authorityKey.ObjectHandle, digest).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, authorityKey.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], approvedPolicy).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], policyRef).ConfigureAwait(false);

        using VerifySequenceCompleteInput verifyInput = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, authorityKey.ObjectHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> verifyResult = await SubmitVerifyCompleteAsync(tpm, registry, pool, verifyInput, []).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifySequenceComplete() (PolicyAuthorize ticket) failed: '{verifyResult.ResponseCode}'.");

        using VerifySequenceCompleteResponse verified = verifyResult.Value;
        Assert.IsFalse(verified.Validation.IsNull, "A real-hierarchy authority key must produce a usable (non-NULL) ticket.");

        uint policyHandle = 0;
        uint itemHandle = 0;
        try
        {
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(secretBytes, pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy, noDa: true);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(createResult.IsSuccess, $"Create (seal under the PolicyAuthorize-predicted authPolicy) failed: '{createResult.ResponseCode}'.");

            using CreateResponse sealedObject = createResult.Value;

            using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
            using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
            using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
            using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
                tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");

            using LoadResponse loaded = loadResult.Value;
            itemHandle = loaded.ObjectHandle.Value;
            ReadOnlyMemory<byte>[] handleNames = [loaded.Name.Span.ToArray()];

            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            policyHandle = session.SessionHandle.Value;

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(
                policyHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            TpmResult<PolicyAuthorizeResponse> authorizeResult = await tpm.PolicyAuthorizeAsync(
                policyHandle, approvedPolicy, policyRef, keySign, verified.Validation, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authorizeResult.IsSuccess, $"PolicyAuthorize (MESSAGE_VERIFIED ticket) failed: '{authorizeResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse policyDigest = digestResult.Value;
            Assert.IsTrue(
                policyDigest.PolicyDigest.AsReadOnlySpan().SequenceEqual(authPolicy),
                "The simulator's policyDigest after PolicyAuthorize must match the independently predicted ExtendForAuthorize value.");

            using TpmPolicySession policySession = TpmPolicySession.ForSession(policyHandle, SessionAlg, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);

            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(unsealResult.IsSuccess, $"Unseal gated on the PolicyAuthorize digest failed: '{unsealResult.ResponseCode}'.");

            using UnsealResponse unsealed = unsealResult.Value;
            Assert.IsTrue(
                unsealed.OutData.AsReadOnlySpan().SequenceEqual(secretBytes),
                "The unsealed data must equal the secret sealed under the PolicyAuthorize-predicted authPolicy.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, policyHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, authorityKey.ObjectHandle.Value).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, parentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A cross-tag replay refusal: a genuine <c>TPM_ST_MESSAGE_VERIFIED</c> ticket's own HMAC bytes, re-tagged
    /// <c>TPM_ST_VERIFIED</c> or <c>TPM_ST_DIGEST_VERIFIED</c> and resubmitted to <c>TPM2_PolicyAuthorize()</c>
    /// over the SAME <c>approvedPolicy</c>/<c>policyRef</c>/<c>keySign</c>, is a ticket the recompute cannot
    /// validate — "If the ticket is not valid, the TPM shall return TPM_RC_POLICY" (clause 23.16.1) — because
    /// each tag recomputes Equation (5) over a DIFFERENT <c>digestOrMessage</c> (raw <c>toBeSigned</c> for
    /// MESSAGE_VERIFIED, <c>H_nameAlg(toBeSigned)</c> for VERIFIED, <c>H_metadata(toBeSigned)</c> for
    /// DIGEST_VERIFIED), so the same HMAC bytes cannot satisfy more than one tag's recomputation
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 23.16.1; Part 2: Structures, clause 10.6.5, Table 111).
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithAMessageVerifiedTicketRetaggedVerifiedOrDigestVerifiedReturnsPolicy()
    {
        const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] keySign = authorityKey.Name.Span.ToArray();
        byte[] policyRef = "cross-tag-replay-ref"u8.ToArray();

        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] approvedPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForCommandCode(zero, TpmCcConstants.TPM_CC_Unseal, SessionAlg, approvedPolicy);

        byte[] toBeSigned = [.. approvedPolicy, .. policyRef];
        byte[] digest = SHA256.HashData(toBeSigned);
        byte[] p1363Signature = await SignDigestEcdsaAsync(tpm, registry, pool, authorityKey.ObjectHandle, digest).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, authorityKey.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], toBeSigned).ConfigureAwait(false);

        using VerifySequenceCompleteInput verifyInput = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, authorityKey.ObjectHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> verifyResult = await SubmitVerifyCompleteAsync(tpm, registry, pool, verifyInput, []).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifySequenceComplete() failed: '{verifyResult.ResponseCode}'.");

        using VerifySequenceCompleteResponse verified = verifyResult.Value;
        byte[] genuineHmac = verified.Validation.Hmac.ToArray();

        using TpmtTkVerified retaggedVerified = MintRetaggedTicket(
            TpmStConstants.TPM_ST_VERIFIED, verified.Validation.Hierarchy, metadata: null, genuineHmac, pool);
        await AssertPolicyAuthorizeRefusesWithPolicyAsync(tpm, SessionAlg, approvedPolicy, policyRef, keySign, retaggedVerified, "TPM_ST_VERIFIED").ConfigureAwait(false);

        using TpmtTkVerified retaggedDigestVerified = MintRetaggedTicket(
            TpmStConstants.TPM_ST_DIGEST_VERIFIED, verified.Validation.Hierarchy, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), genuineHmac, pool);
        await AssertPolicyAuthorizeRefusesWithPolicyAsync(tpm, SessionAlg, approvedPolicy, policyRef, keySign, retaggedDigestVerified, "TPM_ST_DIGEST_VERIFIED").ConfigureAwait(false);
    }

    /// <summary>
    /// Security hardening: a genuine <c>TPM_ST_MESSAGE_VERIFIED</c> ticket minted over
    /// <c>approvedPolicy ‖ policyRefA</c> does not authorize <c>TPM2_PolicyAuthorize()</c> when the caller
    /// substitutes a DIFFERENT <c>policyRefB</c> — the recomputed <c>toBeSigned</c> no longer matches what the
    /// ticket actually attests to, so Equation (5)'s recomputation fails the ticket check: "If the ticket is not
    /// valid, the TPM shall return TPM_RC_POLICY"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 23.16.1).
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithAMessageVerifiedTicketOverADifferentPolicyRefReturnsPolicy()
    {
        const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] keySign = authorityKey.Name.Span.ToArray();
        byte[] policyRefA = "the-signed-ref"u8.ToArray();
        byte[] policyRefB = "a-different-unsigned-ref"u8.ToArray();

        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] approvedPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForCommandCode(zero, TpmCcConstants.TPM_CC_Unseal, SessionAlg, approvedPolicy);

        byte[] toBeSigned = [.. approvedPolicy, .. policyRefA];
        byte[] digest = SHA256.HashData(toBeSigned);
        byte[] p1363Signature = await SignDigestEcdsaAsync(tpm, registry, pool, authorityKey.ObjectHandle, digest).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, authorityKey.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], toBeSigned).ConfigureAwait(false);

        using VerifySequenceCompleteInput verifyInput = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, authorityKey.ObjectHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> verifyResult = await SubmitVerifyCompleteAsync(tpm, registry, pool, verifyInput, []).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifySequenceComplete() failed: '{verifyResult.ResponseCode}'.");

        using VerifySequenceCompleteResponse verified = verifyResult.Value;

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            TpmResult<PolicyAuthorizeResponse> authorizeResult = await tpm.PolicyAuthorizeAsync(
                sessionHandle, approvedPolicy, policyRefB, keySign, verified.Validation, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(authorizeResult.IsSuccess, "A MESSAGE_VERIFIED ticket over policyRefA must not authorize a PolicyAuthorize() claiming policyRefB.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY, authorizeResult.ResponseCode, "The ticket no longer reproduces Equation (5) for policyRefB, so clause 23.16.1's ticket-invalid sentence applies: TPM_RC_POLICY.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A refused <c>TPM2_VerifySequenceStart()</c> returns the parsed <c>auth</c> carrier to the pool: Start
    /// against a storage parent's <c>sign</c>-attribute-CLEAR key is refused with <c>TPM_RC_KEY</c> after a
    /// non-empty auth has already been rented at parse
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.6).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartRefusedOnANonSigningKeyReturnsTheParsedCarriersToPool()
    {
        using var housePool = new MeteredHousePool();
        BaseMemoryPool pool = housePool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        long baseline = housePool.OutstandingCount;

        byte[] sequenceAuth = "attempted-verify-sequence-auth"u8.ToArray();
        TpmResult<VerifySequenceStartResponse> startResult = await SubmitVerifyStartAsync(tpm, registry, pool, parent.ObjectHandle, sequenceAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, startResult.ResponseCode, "A storage parent's sign attribute is CLEAR; TPM2_VerifySequenceStart() must refuse it with TPM_RC_KEY.");

        Assert.AreEqual(baseline, housePool.OutstandingCount, "A refused TPM2_VerifySequenceStart() must return its parsed, non-empty auth carrier to the pool.");
    }

    /// <summary>
    /// A <c>TPM2_VerifySequenceComplete()</c> refused with <c>TPM_RC_SIGNATURE</c> returns its parsed signature
    /// and password carriers to the pool, even though the sequence itself survives the refusal
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteRefusedOnABadSignatureReturnsTheParsedCarriersToPool()
    {
        using var housePool = new MeteredHousePool();
        BaseMemoryPool pool = housePool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] message = "pool-balance probe message."u8.ToArray();

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], message).ConfigureAwait(false);

        long baseline = housePool.OutstandingCount;

        VerifySequenceCompleteInput badInput = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, PlaceholderEcdsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> badResult;
        try
        {
            badResult = await SubmitVerifyCompleteAsync(tpm, registry, pool, badInput, []).ConfigureAwait(false);
        }
        finally
        {
            //The host input owns the signature octets it framed; it is released before the balance is read so the
            //assertion observes the simulator's own rentals alone, even if an assertion below throws.
            badInput.Dispose();
        }

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIGNATURE, badResult.ResponseCode, "A placeholder (non-matching) signature must be refused with TPM_RC_SIGNATURE.");
        Assert.AreEqual(baseline, housePool.OutstandingCount, "A TPM_RC_SIGNATURE refusal must return the parsed signature carrier and the sequence-password session carrier to the pool.");
    }

    /// <summary>
    /// A COMPLETED verification sequence returns every accumulated segment rental — plus the deep-copied starting
    /// key Name, the sequence's own auth carrier, and the response's own ticket HMAC carrier — to the pool once
    /// the response is disposed: the balance after Start, two updates, and a successful Complete returns to
    /// exactly its post-<c>TPM2_CreatePrimary()</c> baseline
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task CompletedVerifySequenceReturnsEverySegmentAndTicketRentalToPool()
    {
        using var housePool = new MeteredHousePool();
        BaseMemoryPool pool = housePool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] chunk1 = "pool balance "u8.ToArray();
        byte[] chunk2 = "success probe"u8.ToArray();
        byte[] fullMessage = [.. chunk1, .. chunk2];
        byte[] digest = SHA256.HashData(fullMessage);
        byte[] p1363Signature = await SignDigestEcdsaAsync(tpm, registry, pool, primary.ObjectHandle, digest).ConfigureAwait(false);

        long baseline = housePool.OutstandingCount;

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        Assert.IsGreaterThan(baseline, housePool.OutstandingCount, "The started sequence must hold live carrier rentals, or the balance assertion below is vacuous.");

        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk1).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk2).ConfigureAwait(false);

        VerifySequenceCompleteInput completeInput = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySequenceCompleteResponse> completeResult;
        try
        {
            completeResult = await SubmitVerifyCompleteAsync(tpm, registry, pool, completeInput, []).ConfigureAwait(false);
        }
        finally
        {
            //The host input owns the signature octets it framed; it is released before the balance is read so the
            //assertion observes the simulator's own rentals alone, even if an assertion below throws.
            completeInput.Dispose();
        }

        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_VerifySequenceComplete() over the accumulated segments must succeed: '{completeResult.ResponseCode}'.");
        completeResult.Value.Dispose();

        Assert.AreEqual(baseline, housePool.OutstandingCount, "A completed verification sequence must return every accumulated segment rental, the deep-copied starting key Name, the sequence auth, and the ticket's own HMAC carrier to the pool once flushed and the response disposed.");
    }

    /// <summary>
    /// An <c>auth</c> declared over <see cref="Tpm2bAuth.MaxSize"/> (64 octets) on the wire is refused with
    /// <c>TPM_RC_SIZE</c> before any rental — the structure's own Parse bound (TPM 2.0 Library Part 2, clause
    /// 10.3.5), reached through <c>TPM2_VerifySequenceStart()</c>'s own parameter parse
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.6, Table 89).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartWithAnAuthOver64OctetsOnTheWireReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        byte[] oversizedAuth = new byte[Tpm2bAuth.MaxSize + 1];
        TpmRcConstants code = await SubmitVerifySequenceStartCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, primary.ObjectHandle.Value, oversizedAuth, [], []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "An auth declared one octet over Tpm2bAuth.MaxSize must be refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// A <c>hint</c> declared over <see cref="Tpm2bSignatureHint.MaxSize"/> (57 octets) ON THE WIRE is refused
    /// with <c>TPM_RC_SIZE</c> before any rental — the command parser's own bound, distinct from
    /// <see cref="Tpm2bSignatureHint.Parse"/>'s own type-level triad
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.6, Table 89; Part 2: Structures, clause 11.3.9, Table 222).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartWithAHintOver57OctetsOnTheWireReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        byte[] oversizedHint = new byte[Tpm2bSignatureHint.MaxSize + 1];
        TpmRcConstants code = await SubmitVerifySequenceStartCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, primary.ObjectHandle.Value, [], oversizedHint, []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "A hint declared one octet over Tpm2bSignatureHint.MaxSize must be refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// One trailing octet after <c>context</c> — <c>TPM2_VerifySequenceStart()</c>'s final parameter — is refused
    /// with <c>TPM_RC_SIZE</c>: no octet may follow the last parameter
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.2).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartWithATrailingOctetReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        TpmRcConstants code = await SubmitVerifySequenceStartCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, primary.ObjectHandle.Value, [], [], [], includeTrailingOctet: true).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "A trailing octet after context must be refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// <c>TPM2_VerifySequenceComplete()</c>'s command tag is unconditionally <c>TPM_ST_SESSIONS</c> (Table 118):
    /// a command framed <c>TPM_ST_NO_SESSIONS</c> is refused with <c>TPM_RC_AUTH_MISSING</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3, Table 118).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteFramedWithNoSessionsReturnsAuthMissing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, PlaceholderEcdsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmRcConstants code = await SubmitVerifySequenceCompleteCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, input, []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_MISSING, code, "TPM2_VerifySequenceComplete() framed with TPM_ST_NO_SESSIONS must be refused with TPM_RC_AUTH_MISSING.");
    }

    /// <summary>
    /// <c>TPM2_VerifySequenceComplete()</c> authorizes exactly one slot (<c>@sequenceHandle</c>, Auth Index 1); a
    /// second block in the area is a companion, which "must have at least one of decrypt, encrypt, or audit SET"
    /// — a <c>TPM_RS_PW</c> block can carry none of them, so it is refused with <c>TPM_RC_ATTRIBUTES</c> encoded
    /// to its own index
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 15.6.4; Part 2: Structures, clause 6.6.2). Part 4's
    /// <c>ParseSessionBuffer</c> answers <c>TPM_RC_HANDLE</c> at the same index for the same shape — its
    /// consistency walk tests an unassigned <c>TPM_RS_PW</c> slot before the attribute rule — so the two agree on
    /// the slot and differ on the code; Part 1's own sentence names the attribute rule, which this model follows.
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithAPasswordCompanionSlotReturnsAttributesIndexedToSlotOne()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, PlaceholderEcdsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        (uint SessionHandle, byte[] Hmac)[] twoSlots = [((uint)TpmRh.TPM_RH_PW, []), ((uint)TpmRh.TPM_RH_PW, [])];
        TpmRcConstants code = await SubmitVerifySequenceCompleteCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_SESSIONS, input, twoSlots).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), code,
            "A TPM_RS_PW companion claims no decrypt, encrypt, or audit attribute, so it must be refused with TPM_RC_ATTRIBUTES encoded to session index 1.");
    }

    /// <summary>
    /// An HMAC-session handle naming no loaded session at <c>TPM2_VerifySequenceComplete()</c>'s single
    /// authorization slot is refused with <c>TPM_RC_REFERENCE_S0</c> — the slot resolves as a real session
    /// before any rule is applied, and the reference warning already carries the offending slot's index
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.5, step 4; Part 2: Structures, clause 6.6.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithAnUnloadedSessionHandleReturnsReferenceS0()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, PlaceholderEcdsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        (uint SessionHandle, byte[] Hmac)[] nonPasswordSlot = [(0x0200_0000u, [])];
        TpmRcConstants code = await SubmitVerifySequenceCompleteCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_SESSIONS, input, nonPasswordSlot).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_S0, code, "An HMAC-session handle naming no loaded session at the sequence slot must be refused with TPM_RC_REFERENCE_S0.");
    }

    /// <summary>
    /// A <c>sigAlg</c> outside <c>{TPM_ALG_ECDSA, TPM_ALG_RSASSA, TPM_ALG_RSAPSS, TPM_ALG_HMAC}</c> — the set
    /// this simulator executes for this command — is refused with <c>TPM_RC_SCHEME</c> at the TPMT_SIGNATURE
    /// parse, before the union member is ever read; <c>TPM_ALG_ECDAA</c> is a TCG signing scheme whose member
    /// this simulator does not model (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clause 20.3, Table 118; Part 2: Structures, clause 11.3.6, Table 219).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithAnUnsupportedSigAlgReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.Create(
            sequenceHandle, primary.ObjectHandle, PlaceholderEcdsaSignature, TpmAlgIdConstants.TPM_ALG_ECDAA, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        (uint SessionHandle, byte[] Hmac)[] passwordSlot = [((uint)TpmRh.TPM_RH_PW, [])];
        TpmRcConstants code = await SubmitVerifySequenceCompleteCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_SESSIONS, input, passwordSlot).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, code, "A sigAlg outside {ECDSA, RSASSA, RSAPSS, HMAC} must be refused with TPM_RC_SCHEME at the TPMT_SIGNATURE parse.");
    }

    /// <summary>
    /// One trailing octet after <c>signature</c> — <c>TPM2_VerifySequenceComplete()</c>'s final parameter — is
    /// refused with <c>TPM_RC_SIZE</c>: no octet may follow the last parameter
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.2).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithATrailingOctetReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            sequenceHandle, primary.ObjectHandle, PlaceholderEcdsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        (uint SessionHandle, byte[] Hmac)[] passwordSlot = [((uint)TpmRh.TPM_RH_PW, [])];
        TpmRcConstants code = await SubmitVerifySequenceCompleteCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_SESSIONS, input, passwordSlot, includeTrailingOctet: true).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "A trailing octet after signature must be refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// Asserts a re-tagged ticket is refused with <c>TPM_RC_POLICY</c> — "If the ticket is not valid, the TPM
    /// shall return TPM_RC_POLICY" (clause 23.16.1) — on a fresh policy session reaching <c>approvedPolicy</c>
    /// via <c>PolicyCommandCode(TPM_CC_Unseal)</c>, and flushes the session afterward.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="sessionAlg">The policy session hash algorithm.</param>
    /// <param name="approvedPolicy">The approved policy digest.</param>
    /// <param name="policyRef">The policy qualifier.</param>
    /// <param name="keySign">The authority key's Name.</param>
    /// <param name="ticket">The re-tagged ticket under test.</param>
    /// <param name="ticketDescription">A short label for the assertion message.</param>
    private async Task AssertPolicyAuthorizeRefusesWithPolicyAsync(
        TpmDevice tpm, TpmAlgIdConstants sessionAlg, byte[] approvedPolicy, byte[] policyRef, byte[] keySign, TpmtTkVerified ticket, string ticketDescription)
    {
        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                sessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            TpmResult<PolicyAuthorizeResponse> authorizeResult = await tpm.PolicyAuthorizeAsync(
                sessionHandle, approvedPolicy, policyRef, keySign, ticket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(authorizeResult.IsSuccess, $"A genuine MESSAGE_VERIFIED ticket re-tagged {ticketDescription} must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY, authorizeResult.ResponseCode, "The ticket re-verification fails Equation (5) for the claimed tag, so clause 23.16.1's ticket-invalid sentence applies: TPM_RC_POLICY.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Composes a TPMT_TK_VERIFIED value claiming <paramref name="tag"/> and <paramref name="hierarchy"/> over
    /// <paramref name="hmac"/> exactly as an attacker would submit one on the wire (TPM 2.0 Library Part 2,
    /// clause 10.6.5), parsed back through the production wire shape so the result is a genuine ticket value
    /// with a caller-chosen tag.
    /// </summary>
    /// <param name="tag">The ticket structure tag to claim.</param>
    /// <param name="hierarchy">The hierarchy the ticket claims.</param>
    /// <param name="metadata">The metadata hash algorithm, required exactly when <paramref name="tag"/> is <c>TPM_ST_DIGEST_VERIFIED</c>.</param>
    /// <param name="hmac">The ticket HMAC octets.</param>
    /// <param name="pool">The memory pool backing the parsed ticket.</param>
    /// <returns>The composed ticket; the caller disposes it.</returns>
    private static TpmtTkVerified MintRetaggedTicket(TpmStConstants tag, TpmiRhHierarchy hierarchy, TpmiAlgHash? metadata, ReadOnlySpan<byte> hmac, BaseMemoryPool pool)
    {
        int size = sizeof(ushort) + sizeof(uint) + (metadata.HasValue ? sizeof(ushort) : 0) + sizeof(ushort) + hmac.Length;
        using IMemoryOwner<byte> owner = pool.Rent(size);
        Span<byte> wire = owner.Memory.Span[..size];
        var writer = new TpmWriter(wire);
        writer.WriteUInt16((ushort)tag);
        hierarchy.WriteTo(ref writer);
        if(metadata is { } metadataHash)
        {
            metadataHash.WriteTo(ref writer);
        }

        writer.WriteUInt16((ushort)hmac.Length);
        writer.WriteBytes(hmac);
        var reader = new TpmReader(wire);

        return TpmtTkVerified.Parse(ref reader, pool);
    }

    /// <summary>
    /// Reserializes a public area into a fresh <see cref="Tpm2bPublic"/>, the round-trip a disk-persisted public
    /// blob makes; keeps the seal and unseal steps firewalled to wire bytes.
    /// </summary>
    /// <param name="source">The public area to clone.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>An independent copy of the public area.</returns>
    private static Tpm2bPublic ClonePublic(Tpm2bPublic source, BaseMemoryPool pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);

        var reader = new TpmReader(owner.Memory.Span[..size]);

        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>
    /// Flushes a transient object or session handle when one is present (non-zero), ignoring the result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="handle">The handle to flush, or 0 when none was acquired.</param>
    private async Task FlushIfPresentAsync(TpmDevice tpm, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        _ = await tpm.FlushContextAsync(handle, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Submits <see cref="VerifySequenceStartInput.Create"/> with no session (Auth Index None; no authorization
    /// of <c>keyHandle</c> is required) and returns the raw result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The candidate verification key handle.</param>
    /// <param name="sequenceAuth">The sequence's own authValue.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<VerifySequenceStartResponse>> SubmitVerifyStartAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        using VerifySequenceStartInput input = VerifySequenceStartInput.Create(keyHandle, sequenceAuth, pool);

        return await TpmCommandExecutor.ExecuteAsync<VerifySequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Starts a verification sequence via <see cref="SubmitVerifyStartAsync"/>, asserting success, and returns its handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The verification key handle.</param>
    /// <param name="sequenceAuth">The sequence's own authValue.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartVerifySequenceAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        TpmResult<VerifySequenceStartResponse> result = await SubmitVerifyStartAsync(tpm, registry, pool, keyHandle, sequenceAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_VerifySequenceStart() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>
    /// Starts a SIGNING sequence via <see cref="SignSequenceStartInput.Create"/>, asserting success, and returns
    /// its handle — used by the cross-family and <c>TPM_RC_MODE</c> tests, which must open a signing sequence
    /// alongside a verification one.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The signing key handle.</param>
    /// <param name="sequenceAuth">The sequence's own authValue.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartSignSequenceAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        using SignSequenceStartInput input = SignSequenceStartInput.Create(keyHandle, sequenceAuth, pool);
        TpmResult<SignSequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SignSequenceStart() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>
    /// Submits <see cref="SequenceUpdateInput.Create"/> over a single <c>TPM_RS_PW</c> session authorizing
    /// <c>@sequenceHandle</c> (Auth Index 1) and returns the raw result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence (or candidate) handle.</param>
    /// <param name="sequenceAuth">The caller-supplied sequence auth (empty for an empty-authValue sequence).</param>
    /// <param name="buffer">The update buffer.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<SequenceUpdateResponse>> SubmitUpdateAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, byte[] sequenceAuth, byte[] buffer)
    {
        using TpmPasswordSession sequenceSession = sequenceAuth.Length == 0 ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(sequenceAuth, pool);
        using SequenceUpdateInput input = SequenceUpdateInput.Create(sequenceHandle, buffer, pool);

        return await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
            tpm, input, [sequenceSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Updates a sequence via <see cref="SubmitUpdateAsync"/>, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence handle.</param>
    /// <param name="sequenceAuth">The sequence's own authValue.</param>
    /// <param name="buffer">The update buffer.</param>
    private async Task UpdateSequenceSuccessfullyAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, byte[] sequenceAuth, byte[] buffer)
    {
        TpmResult<SequenceUpdateResponse> result = await SubmitUpdateAsync(tpm, registry, pool, sequenceHandle, sequenceAuth, buffer).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SequenceUpdate() failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Submits an already-constructed <see cref="VerifySequenceCompleteInput"/> over a single <c>TPM_RS_PW</c>
    /// session authorizing <c>@sequenceHandle</c> (Auth Index 1; <c>keyHandle</c> takes Auth Index None and no
    /// session) and returns the raw result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The already-built command input; not disposed by this method.</param>
    /// <param name="sequenceAuth">The caller-supplied sequence auth (empty for an empty-authValue sequence).</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<VerifySequenceCompleteResponse>> SubmitVerifyCompleteAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, VerifySequenceCompleteInput input, byte[] sequenceAuth)
    {
        using TpmPasswordSession sequenceSession = sequenceAuth.Length == 0 ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(sequenceAuth, pool);

        return await TpmCommandExecutor.ExecuteAsync<VerifySequenceCompleteResponse>(
            tpm, input, [sequenceSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Signs <paramref name="digest"/> with an ECDSA key via <c>TPM2_SignDigest()</c> over an empty-password
    /// session, and returns the IEEE P1363 <c>r ‖ s</c> signature — the ON-TPM signer every verification test in
    /// this file feeds to <c>TPM2_VerifySequenceComplete()</c>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The ECDSA signing key handle.</param>
    /// <param name="digest">The digest to sign.</param>
    /// <param name="keyPassword">The signing key's own password, or <see langword="null"/> or empty for an empty-password session.</param>
    /// <returns>The IEEE P1363 signature octets.</returns>
    private async Task<byte[]> SignDigestEcdsaAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] digest, byte[]? keyPassword = null)
    {
        using TpmPasswordSession keyAuth = keyPassword is { Length: > 0 } ? TpmPasswordSession.Create(keyPassword, pool) : TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.Create(keyHandle, digest, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_SignDigest() (ECDSA) failed: '{signResult.ResponseCode}'.");

        using SignDigestResponse signature = signResult.Value;

        return ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan());
    }

    /// <summary>
    /// Signs <paramref name="digest"/> with an RSA key via <c>TPM2_SignDigest()</c> over an empty-password
    /// session, and returns the raw RSA signature octets — used by both the RSASSA and RSAPSS happy paths, since
    /// the key's own retained template scheme (not this parameter) selects which one <c>TPM2_SignDigest()</c>
    /// actually produces.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The RSA signing key handle.</param>
    /// <param name="digest">The digest to sign.</param>
    /// <param name="expectedAlgorithm">The signature algorithm the key's own retained scheme is expected to produce, asserted against the response.</param>
    /// <returns>The raw RSA signature octets.</returns>
    private async Task<byte[]> SignDigestRsaAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] digest, TpmAlgIdConstants expectedAlgorithm)
    {
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.Create(keyHandle, digest, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_SignDigest() (RSA) failed: '{signResult.ResponseCode}'.");

        using SignDigestResponse signature = signResult.Value;
        Assert.AreEqual(expectedAlgorithm, signature.SignatureAlgorithm, "TPM2_SignDigest() must produce the key's own retained scheme algorithm.");

        return signature.Signature.RsaSignature.Buffer.ToArray();
    }

    /// <summary>
    /// Concatenates the ECDSA r and s components into the IEEE P1363 <c>r ‖ s</c> form
    /// <see cref="VerifySequenceCompleteInput.ForEcdsa"/> takes, left-padding each to the P-256 field width.
    /// </summary>
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

    /// <summary>
    /// Left-pads a big-endian integer to a fixed width, as the IEEE P1363 encoding requires. The simulator
    /// returns TPM2B integers that may omit leading zero bytes.
    /// </summary>
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

    /// <summary>Creates an unrestricted, empty-password ECC P-256 signing/verification primary under the given hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a DA-protected, password-guarded ECC P-256 signing/verification primary under the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="password">The key's own password.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateDaProtectedEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, string password)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: false);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (DA-protected ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an unrestricted, empty-password RSA 2048 signing/verification primary with the given template scheme.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="scheme">The RSA template scheme (NULL, RSASSA, or RSAPSS).</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateRsaSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtRsaScheme scheme)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: Rsa2048KeyBits, scheme, pool, noDa: true);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA 2048) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Composes an X509SIGN ECC signing key template — <c>TPMA_OBJECT.x509sign</c> SET alongside <c>sign</c>,
    /// with no password (empty authValue) — mirroring
    /// <c>TpmInHouseSimulatorSignSequenceTests.CreateX509SignEccSigningKeyInput</c>'s direct-composition style,
    /// since no production factory builds an X509SIGN signing key.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the returned CreatePrimaryInput, whose Dispose releases them.")]
    private static CreatePrimaryInput CreateX509SignEccSigningKeyInput(BaseMemoryPool pool)
    {
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);

        var attributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH |
            TpmaObject.SIGN_ENCRYPT |
            TpmaObject.X509SIGN |
            TpmaObject.NO_DA;

        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            attributes,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));

        return new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
    }

    /// <summary>Creates an X509SIGN ECC signing primary under the owner hierarchy and returns the response (the caller owns it).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateX509SignEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreateX509SignEccSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (X509SIGN ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an unrestricted, empty-password ECC storage parent under the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary storage parent failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a storage parent, seals data under it, and loads the sealed (KEYEDHASH data) object, returning its
    /// handle.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The loaded sealed object's handle.</returns>
    private async Task<TpmiDhObject> CreateLoadedSealedObjectHandleAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData("not a verification key"u8.ToArray(), pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);
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

        using LoadResponse loaded = loadResult.Value;

        return loaded.ObjectHandle;
    }

    /// <summary>Creates a response codec registry covering the executor-driven commands these tests issue directly.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignDigest, TpmResponseCodec.SignDigest);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceComplete, TpmResponseCodec.SignSequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySequenceStart, TpmResponseCodec.VerifySequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceUpdate, TpmResponseCodec.SequenceUpdate);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySequenceComplete, TpmResponseCodec.VerifySequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
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

    /// <summary>Builds the ticket proof-derivation input: the seed followed by the hierarchy handle.</summary>
    /// <param name="seed">The TPM seed.</param>
    /// <param name="hierarchy">The hierarchy handle.</param>
    /// <returns>The proof-derivation input bytes.</returns>
    private static byte[] BuildProofInput(byte[] seed, uint hierarchy)
    {
        byte[] input = new byte[seed.Length + sizeof(uint)];
        var writer = new TpmWriter(input);
        writer.WriteBytes(seed);
        writer.WriteUInt32(hierarchy);

        return input;
    }

    /// <summary>
    /// Builds the <c>TPM_ST_MESSAGE_VERIFIED</c> ticket HMAC message: tag (UINT16) followed by the RAW
    /// accumulated message and the verifying key's Name — Equation (5), TPM 2.0 Library Part 2, clause 10.6.5,
    /// with NO metadata (unlike <see cref="VerifyDigestSignatureInput"/>'s digest-tagged message).
    /// </summary>
    /// <param name="message">The whole accumulated sequence message.</param>
    /// <param name="keyName">The verifying key's Name.</param>
    /// <returns>The ticket message bytes.</returns>
    private static byte[] BuildMessageVerifiedTicketMessage(ReadOnlySpan<byte> message, ReadOnlySpan<byte> keyName)
    {
        byte[] result = new byte[sizeof(ushort) + message.Length + keyName.Length];
        var writer = new TpmWriter(result);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_MESSAGE_VERIFIED);
        writer.WriteBytes(message);
        writer.WriteBytes(keyName);

        return result;
    }

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers
    /// it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-verify-sequence",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Creates a simulator wired with a caller-injected hierarchy proof seed (making its tickets independently
    /// reproducible) and BOTH signing backends, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c>
    /// into the operational phase.
    /// </summary>
    /// <param name="seed">The proof seed to inject.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateSeededOperationalAsync(byte[] seed, BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-verify-sequence-seed",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(),
            seed: seed);
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
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_VerifySequenceStart()</c> command with a caller-chosen tag, <c>hint</c>, and
    /// <c>context</c> body, bypassing <see cref="VerifySequenceStartInput"/> (which always frames
    /// <c>TPM_ST_NO_SESSIONS</c> and empty hint/context) — letting a caller submit a malformed tag, an oversized
    /// or non-empty hint/context, or a trailing octet directly against the simulator.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag to frame verbatim.</param>
    /// <param name="keyHandle">The <c>keyHandle</c> handle value.</param>
    /// <param name="sequenceAuth">The <c>auth</c> parameter's octets.</param>
    /// <param name="hint">The <c>hint</c> parameter's octets, written verbatim as a TPM2B.</param>
    /// <param name="context">The <c>context</c> parameter's octets, written verbatim as a TPM2B.</param>
    /// <param name="includeTrailingOctet">Whether to append one octet beyond <c>context</c>, which the wire layout does not admit.</param>
    /// <param name="length">The framed command's total length.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameVerifySequenceStartCommand(
        BaseMemoryPool pool, ushort tag, uint keyHandle, ReadOnlySpan<byte> sequenceAuth, ReadOnlySpan<byte> hint, ReadOnlySpan<byte> context,
        bool includeTrailingOctet, out int length)
    {
        length =
            TpmHeader.HeaderSize
            + sizeof(uint)                          //Handle area: keyHandle (Auth Index None).
            + (sizeof(ushort) + sequenceAuth.Length) //auth: TPM2B_AUTH.
            + (sizeof(ushort) + hint.Length)         //hint: TPM2B_SIGNATURE_HINT.
            + (sizeof(ushort) + context.Length)      //context: TPM2B_SIGNATURE_CTX.
            + (includeTrailingOctet ? 1 : 0);        //One trailing octet the wire layout does not admit.

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader(tag, (uint)length, (uint)TpmCcConstants.TPM_CC_VerifySequenceStart);
            header.WriteTo(ref writer);
            writer.WriteUInt32(keyHandle);
            writer.WriteTpm2b(sequenceAuth);
            writer.WriteTpm2b(hint);
            writer.WriteTpm2b(context);
            if(includeTrailingOctet)
            {
                writer.WriteByte(0xAA);
            }

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_VerifySequenceStart()</c> built by
    /// <see cref="FrameVerifySequenceStartCommand"/> straight to the simulator (bypassing
    /// <see cref="TpmCommandExecutor"/>) and yields the response code.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag to frame verbatim.</param>
    /// <param name="keyHandle">The <c>keyHandle</c> handle value.</param>
    /// <param name="sequenceAuth">The <c>auth</c> parameter's octets.</param>
    /// <param name="hint">The <c>hint</c> parameter's octets.</param>
    /// <param name="context">The <c>context</c> parameter's octets.</param>
    /// <param name="includeTrailingOctet">Whether to append one octet beyond <c>context</c>, which the wire layout does not admit.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitVerifySequenceStartCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, ushort tag, uint keyHandle, byte[] sequenceAuth, byte[] hint, byte[] context, bool includeTrailingOctet = false)
    {
        using IMemoryOwner<byte> commandOwner = FrameVerifySequenceStartCommand(pool, tag, keyHandle, sequenceAuth, hint, context, includeTrailingOctet, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_VerifySequenceComplete()</c> command over an explicit list of session slots, reusing
    /// an already-built <see cref="VerifySequenceCompleteInput"/> for the handle area and the TPMT_SIGNATURE
    /// parameter body, bypassing <see cref="TpmCommandExecutor"/> so a caller can submit a malformed tag or
    /// authorization area, or a trailing octet, directly against the simulator.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag to frame verbatim.</param>
    /// <param name="input">The command whose handles and TPMT_SIGNATURE body are framed verbatim.</param>
    /// <param name="sessions">The session slots to frame, in wire order, each as a full <c>TPMS_AUTH_COMMAND</c> entry with an empty nonceCaller and the CONTINUE_SESSION attribute.</param>
    /// <param name="authorizationSizeOverride">The declared <c>authorizationSize</c> field value, in place of the actual octet count <paramref name="sessions"/> occupy, or <see langword="null"/> for the actual size.</param>
    /// <param name="includeTrailingOctet">Whether to append one octet beyond <c>signature</c>, which the wire layout does not admit.</param>
    /// <param name="length">The framed command's total length.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameVerifySequenceCompleteCommand(
        BaseMemoryPool pool, ushort tag, VerifySequenceCompleteInput input, (uint SessionHandle, byte[] Hmac)[] sessions,
        uint? authorizationSizeOverride, bool includeTrailingOctet, out int length)
    {
        int actualAuthorizationSize = 0;
        foreach((uint _, byte[] hmac) in sessions)
        {
            actualAuthorizationSize += sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort) + hmac.Length;
        }

        uint authorizationSize = authorizationSizeOverride ?? (uint)actualAuthorizationSize;

        //GetSerializedSize() covers the handle area AND the parameter body together (ITpmCommandInput's own
        //convention); the handle area is subtracted back out here because the authorization area is framed
        //between WriteHandles and WriteParameters on the wire, so this helper writes the two areas separately.
        int parameterSize = input.GetSerializedSize() - (2 * sizeof(uint));

        length =
            TpmHeader.HeaderSize
            + (2 * sizeof(uint))            //Handle area: @sequenceHandle then keyHandle (Auth Index None).
            + sizeof(uint)                  //authorizationSize.
            + actualAuthorizationSize       //The framed session slots.
            + parameterSize                 //signature (TPMT_SIGNATURE).
            + (includeTrailingOctet ? 1 : 0); //One trailing octet the wire layout does not admit.

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader(tag, (uint)length, (uint)TpmCcConstants.TPM_CC_VerifySequenceComplete);
            header.WriteTo(ref writer);
            input.WriteHandles(ref writer);
            writer.WriteUInt32(authorizationSize);
            foreach((uint sessionHandle, byte[] hmac) in sessions)
            {
                writer.WriteUInt32(sessionHandle);
                writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
                writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
                writer.WriteTpm2b(hmac);
            }

            input.WriteParameters(ref writer);
            if(includeTrailingOctet)
            {
                writer.WriteByte(0xAA);
            }

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_VerifySequenceComplete()</c> built by
    /// <see cref="FrameVerifySequenceCompleteCommand"/> straight to the simulator (bypassing
    /// <see cref="TpmCommandExecutor"/>) and yields the response code.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag to frame verbatim.</param>
    /// <param name="input">The command whose handles and TPMT_SIGNATURE body are framed verbatim.</param>
    /// <param name="sessions">The session slots to frame, in wire order.</param>
    /// <param name="authorizationSizeOverride">The declared <c>authorizationSize</c> override, or <see langword="null"/> for the actual size.</param>
    /// <param name="includeTrailingOctet">Whether to append one octet beyond <c>signature</c>, which the wire layout does not admit.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitVerifySequenceCompleteCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, ushort tag, VerifySequenceCompleteInput input, (uint SessionHandle, byte[] Hmac)[] sessions,
        uint? authorizationSizeOverride = null, bool includeTrailingOctet = false)
    {
        using IMemoryOwner<byte> commandOwner = FrameVerifySequenceCompleteCommand(pool, tag, input, sessions, authorizationSizeOverride, includeTrailingOctet, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }
}
