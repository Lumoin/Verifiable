using System;
using System.Buffers;
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
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_CreatePrimary()</c>, <c>TPM2_SignSequenceStart()</c>, <c>TPM2_SequenceUpdate()</c>, and
/// <c>TPM2_SignSequenceComplete()</c> against the in-house behavioural <see cref="TpmSimulator"/> — entirely
/// in-process, with no external assets — through the same production command path the production code uses
/// (<see cref="TpmCommandExecutor"/> with the real <see cref="SignSequenceStartInput"/>,
/// <see cref="SequenceUpdateInput"/>, <see cref="SignSequenceCompleteInput"/>, and response codecs).
/// </summary>
/// <remarks>
/// <para>
/// A sequence object accumulates a message across one or more <c>TPM2_SequenceUpdate()</c> calls and is
/// consumed by <c>TPM2_SignSequenceComplete()</c>, which appends a trailing <c>buffer</c>, hashes the whole
/// accumulated message as the key's scheme requires, signs the digest, and flushes the sequence
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3: Commands, clauses 17.5, 17.7, 20.6; Part 1: Architecture, clause 29.4.6). No
/// authorization of <c>keyHandle</c> is required at Start — it is checked only at Complete — so
/// <c>TPM2_SignSequenceStart()</c> is framed <c>TPM_ST_NO_SESSIONS</c> and submitted with no session.
/// </para>
/// <para>
/// <c>TPM2_SignSequenceComplete()</c> carries no <c>validation TPMT_TK_HASHCHECK</c> parameter — unlike
/// <c>TPM2_SignDigest()</c> — so a restricted signing key's safety is judged solely from whether the message's
/// first presented block begins with <c>TPM_GENERATED_VALUE</c>, not from a caller-supplied ticket.
/// </para>
/// <para>
/// Completing on a verification sequence (<c>TPM2_VerifySequenceComplete()</c> called against a sequence
/// started for signing, or the reverse) is out of scope here: the verification-sequence commands land in a
/// later stage, so the <c>TPM_RC_MODE</c> cross-check has no verification sequence to exercise against yet.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorSignSequenceTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus size in bits used by the RSA signing tests.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The lowered <c>maxTries</c> used by the tests that drive the TPM into Lockout mode quickly.</summary>
    private const uint LoweredMaxTries = 2;

    /// <summary>
    /// A transient handle value naming no loaded object in a freshly-brought-operational simulator — stands in
    /// for a sequence or key handle in a test whose refusal fires at handle resolution.
    /// </summary>
    private const uint ArbitraryUnknownHandle = 0x8000_0999;

    /// <summary>
    /// <c>TPM_GENERATED_VALUE</c> (Table 7), big-endian: the four octets a restricted signing key's first
    /// presented sequence block must never begin with.
    /// </summary>
    private static byte[] TpmGeneratedValueBytes { get; } = [0xFF, 0x54, 0x43, 0x47];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// <c>TPM2_SignSequenceStart()</c> against an unrestricted ECC signing key returns a handle whose
    /// most-significant octet is <c>TPM_HT_TRANSIENT</c>, and a second, concurrently open sequence started
    /// under the same key receives a distinct handle drawn from the same transient allocator
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.5, Table 88; Part 1: Architecture, clause 27.2.3).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartOnAnUnrestrictedEccKeyReturnsATransientHandleAndASecondStartReturnsADistinctHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmiDhObject firstHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        Assert.IsTrue(firstHandle.IsTransient, "A sequence object's handle most-significant octet must be TPM_HT_TRANSIENT.");
        Assert.AreNotEqual(primary.ObjectHandle, firstHandle, "A sequence handle must be drawn from the SAME shared transient allocator as the signing key, so it must never alias the key's own handle (Part 1, clause 27.4: a handle may not be assigned to any other TPM resource, object, or session).");

        TpmiDhObject secondHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        Assert.IsTrue(secondHandle.IsTransient, "The second, concurrently open sequence's handle must also be TPM_HT_TRANSIENT.");
        Assert.AreNotEqual(primary.ObjectHandle, secondHandle, "The second sequence handle must also never alias the signing key's own handle.");
        Assert.AreNotEqual(firstHandle, secondHandle, "Two concurrently open sequences must receive distinct handles.");
    }

    /// <summary>
    /// <c>TPM2_FlushContext()</c> "causes all context associated with a loaded object, sequence object, or
    /// session to be removed"; a handle it no longer names is refused with <c>TPM_RC_HANDLE</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 28.4).
    /// </summary>
    [TestMethod]
    public async Task FlushContextOnASequenceHandleSucceedsAndASecondFlushReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        FlushContextInput flushInput = FlushContextInput.ForHandle(sequenceHandle.Value);
        TpmResult<FlushContextResponse> firstFlush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(firstFlush.IsSuccess, $"TPM2_FlushContext() on an open sequence must succeed: '{firstFlush.ResponseCode}'.");

        TpmResult<FlushContextResponse> secondFlush = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), secondFlush.ResponseCode, "A second TPM2_FlushContext() on the same, already-flushed sequence handle must be refused with TPM_RC_HANDLE.");
    }

    /// <summary>
    /// "If keyHandle does not refer to a signing key, the TPM shall return TPM_RC_KEY": a storage parent's
    /// <c>sign</c> (SIGN_ENCRYPT) attribute is CLEAR
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.5).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartOnAStorageParentReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<SignSequenceStartResponse> startResult = await SubmitStartAsync(tpm, registry, pool, parent.ObjectHandle, []).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), startResult.ResponseCode, "A storage parent's sign attribute is CLEAR; TPM2_SignSequenceStart() must refuse it with TPM_RC_KEY.");
    }

    /// <summary>
    /// "If keyHandle refers to a key whose scheme is TPM_ALG_NULL, the TPM shall return TPM_RC_SCHEME"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.5).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartOnANullSchemeRsaSigningTemplateReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmtRsaScheme.Null).ConfigureAwait(false);

        TpmResult<SignSequenceStartResponse> startResult = await SubmitStartAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_SCHEME, 0), startResult.ResponseCode, "A key created with a NULL template scheme retains none; TPM2_SignSequenceStart() must refuse it with TPM_RC_SCHEME.");
    }

    /// <summary>
    /// A loaded sealed (KEYEDHASH data) object is not a signing key
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.5).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartOnALoadedSealedObjectHandleReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmiDhObject sealedHandle = await CreateLoadedSealedObjectHandleAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<SignSequenceStartResponse> startResult = await SubmitStartAsync(tpm, registry, pool, sealedHandle, []).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), startResult.ResponseCode, "A sealed (KEYEDHASH data) object is not a signing key; TPM2_SignSequenceStart() must refuse it with TPM_RC_KEY.");
    }

    /// <summary>
    /// A non-empty <c>context</c> is refused with <c>TPM_RC_SIZE</c>: Table 220's <c>empty[0]</c> arm is the
    /// only conformant value for every scheme this simulator executes
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.7/11.3.8, Tables 220/221).
    /// <see cref="SignSequenceStartInput"/> always frames an empty context, so this hand-frames the command.
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartWithANonEmptyContextHandFramedReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        byte[] nonEmptyContext = [0x01];
        TpmRcConstants code = await SubmitSignSequenceStartCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, primary.ObjectHandle.Value, [], nonEmptyContext).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), code, "A non-empty context under any scheme this simulator executes must be refused with TPM_RC_SIZE (Table 220's empty[0] arm).");
    }

    /// <summary>
    /// Table 87 conditions the tag on an audit or decrypt session: a <c>TPM_ST_SESSIONS</c> frame with no
    /// well-formed authorization area behind it reads its own (empty) <c>auth</c>/<c>context</c> octets as a
    /// bogus <c>authorizationSize</c> and is refused with the area's own structural code, <c>TPM_RC_AUTHSIZE</c>
    /// (clause 5.5, step 4.3), rather than misread as command parameters
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.5, Table 87, clause 5.5).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartFramedWithSessionsReturnsAuthsize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmRcConstants code = await SubmitSignSequenceStartCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_SESSIONS, primary.ObjectHandle.Value, [], []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTHSIZE, code, "A TPM_ST_SESSIONS frame with no well-formed authorization area behind it must be refused with the area's own TPM_RC_AUTHSIZE.");
    }

    /// <summary>
    /// A key whose <c>x509sign</c> attribute (Part 2, Table 37, bit 19) is SET is refused at Start — the errata
    /// clause 2.2 fail-fast check, ahead of the same refusal <c>TPM2_SignSequenceComplete()</c> also carries
    /// normatively
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.5; Part 2: Structures, clause 8.3.2, Table 37).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartOnAnX509SignKeyReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateX509SignEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<SignSequenceStartResponse> startResult = await SubmitStartAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), startResult.ResponseCode, "A key whose x509sign attribute is SET must be refused with TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// A correct sequence auth authorizes <c>TPM2_SequenceUpdate()</c>, and "buffer" "may be any size up to the
    /// limits of the TPM," including an empty buffer
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.7, Table 91).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateWithCorrectAuthSucceedsAndAcceptsAnEmptyBuffer()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] sequenceAuth = System.Text.Encoding.UTF8.GetBytes("sequence-update-auth");
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, sequenceAuth).ConfigureAwait(false);

        TpmResult<SequenceUpdateResponse> updateResult = await SubmitUpdateAsync(tpm, registry, pool, sequenceHandle, sequenceAuth, "some data"u8.ToArray()).ConfigureAwait(false);
        Assert.IsTrue(updateResult.IsSuccess, $"TPM2_SequenceUpdate() with the correct sequence auth must succeed: '{updateResult.ResponseCode}'.");

        TpmResult<SequenceUpdateResponse> emptyResult = await SubmitUpdateAsync(tpm, registry, pool, sequenceHandle, sequenceAuth, []).ConfigureAwait(false);
        Assert.IsTrue(emptyResult.IsSuccess, $"An empty TPM2_SequenceUpdate() buffer must be accepted: '{emptyResult.ResponseCode}'.");
    }

    /// <summary>
    /// "A sequence is exempt from dictionary attack protection and authorization failures will not cause the TPM
    /// to enter lockout": a wrong sequence auth is refused with the plain, session-index-0-encoded
    /// <c>TPM_RC_BAD_AUTH</c>, and never moves <c>failedTries</c> — even though the sequence's own signing key is
    /// itself dictionary-attack protected. "If the command does not return TPM_RC_SUCCESS, the state of the
    /// sequence is unmodified": completing the sequence afterward with the correct auths and an empty trailing
    /// buffer signs the EMPTY message, proving the refused update's <c>"data"</c> buffer was never appended
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clauses 16.8.3, 29.4.6; Part 2: Structures, clause 6.6.2; Part
    /// 3: Commands, clause 17.7).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateWithWrongAuthReturnsBadAuthAndNeverChargesDictionaryAttack()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] keyAuth = System.Text.Encoding.UTF8.GetBytes("sequence-key-auth");
        using CreatePrimaryResponse primary = await CreateDaProtectedEccSigningPrimaryAsync(tpm, registry, pool, "sequence-key-auth").ConfigureAwait(false);
        byte[] sequenceAuth = System.Text.Encoding.UTF8.GetBytes("sequence-update-auth");
        byte[] wrongSequenceAuth = System.Text.Encoding.UTF8.GetBytes("wrong-sequence-auth");
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, sequenceAuth).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<SequenceUpdateResponse> wrongResult = await SubmitUpdateAsync(tpm, registry, pool, sequenceHandle, wrongSequenceAuth, "data"u8.ToArray()).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), wrongResult.ResponseCode,
            "A wrong sequence auth over the sequence handle's own TPM_RS_PW session must be refused with session-index-0-encoded TPM_RC_BAD_AUTH.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "A sequence's authValue is exempt from dictionary-attack protection; a wrong sequence auth must never move failedTries, even while signing under a DA-protected key.");

        TpmResult<SignSequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, sequenceAuth, keyAuth, []).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SignSequenceComplete() after the refused update must still succeed: '{completeResult.ResponseCode}'.");

        using SignSequenceCompleteResponse signature = completeResult.Value;
        byte[] digest = SHA256.HashData(ReadOnlySpan<byte>.Empty);
        Assert.IsTrue(
            VerifyEcdsaSignatureOffTpm(primary.OutPublic.PublicArea.Unique.Ecc!, digest, signature.Signature),
            "Clause 17.7's unmodified-state posture: the refused update's buffer must never have been appended, so the completed message is empty.");
    }

    /// <summary>
    /// "While in Lockout mode, any use of a DA-protected authValue will return TPM_RC_LOCKOUT" (clause 16.8.3):
    /// once a DA-protected signing key's repeated wrong authorizations drive the TPM into general Lockout mode,
    /// even the key's CORRECT password is refused with the bare <c>TPM_RC_LOCKOUT</c> — proving the TPM really
    /// is locked out, not merely reporting a counter. "A sequence is exempt from dictionary attack protection
    /// and authorization failures will not cause the TPM to enter lockout": against that same premise, the
    /// sequence's own auth remains fully functional throughout — a correct sequence auth still authorizes
    /// <c>TPM2_SequenceUpdate()</c>, and a wrong one still answers plain <c>TPM_RC_BAD_AUTH</c>, never
    /// <c>TPM_RC_LOCKOUT</c> or <c>TPM_RC_AUTH_FAIL</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clauses 16.8.3, 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateRemainsExemptFromDictionaryAttackEvenAfterTheTpmEntersLockout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = await CreateDaProtectedEccSigningPrimaryAsync(tpm, registry, pool, "lockout-key-auth").ConfigureAwait(false);
        byte[] correctKeyAuth = System.Text.Encoding.UTF8.GetBytes("lockout-key-auth");
        byte[] wrongKeyAuth = System.Text.Encoding.UTF8.GetBytes("wrong-lockout-key-auth");
        byte[] sequenceAuth = System.Text.Encoding.UTF8.GetBytes("lockout-sequence-auth");
        byte[] wrongSequenceAuth = System.Text.Encoding.UTF8.GetBytes("wrong-lockout-sequence-auth");

        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, sequenceAuth).ConfigureAwait(false);

        for(uint attempt = 1; attempt <= LoweredMaxTries; attempt++)
        {
            TpmResult<SignSequenceCompleteResponse> wrongKeyResult = await SubmitCompleteAsync(
                tpm, registry, pool, sequenceHandle, primary.ObjectHandle, sequenceAuth, wrongKeyAuth, []).ConfigureAwait(false);
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), wrongKeyResult.ResponseCode,
                $"Attempt {attempt} of {LoweredMaxTries} must count as an auth-failure, not yet Lockout mode. A failing SignSequenceComplete() leaves the sequence unmodified, so the same sequence is reused.");
        }

        TpmResult<TpmDictionaryAttackParameters> locked = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(locked.Value.IsLockedOut, "The DA-protected signing key must now be in Lockout mode.");

        TpmResult<SignSequenceCompleteResponse> correctKeyResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, sequenceAuth, correctKeyAuth, []).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, correctKeyResult.ResponseCode,
            "Once the TPM is in general Lockout mode, TPM2_SignSequenceComplete() must refuse the DA-protected key's authValue with the bare TPM_RC_LOCKOUT even when the supplied password is correct, proving the TPM is genuinely locked out rather than merely reporting a counter.");

        TpmResult<SequenceUpdateResponse> correctUpdateResult = await SubmitUpdateAsync(tpm, registry, pool, sequenceHandle, sequenceAuth, "still fine"u8.ToArray()).ConfigureAwait(false);
        Assert.IsTrue(correctUpdateResult.IsSuccess, $"A sequence's own authValue must still authorize TPM2_SequenceUpdate() while the TPM is in general Lockout mode: '{correctUpdateResult.ResponseCode}'.");

        TpmResult<SequenceUpdateResponse> wrongUpdateResult = await SubmitUpdateAsync(tpm, registry, pool, sequenceHandle, wrongSequenceAuth, "still fine"u8.ToArray()).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), wrongUpdateResult.ResponseCode,
            "A wrong sequence auth while the TPM is in Lockout mode must still answer plain TPM_RC_BAD_AUTH, never TPM_RC_LOCKOUT or TPM_RC_AUTH_FAIL.");
    }

    /// <summary>
    /// <c>@sequenceHandle</c> resolving to a loaded key rather than a sequence names something that is not a
    /// sequence at all; <c>TPM2_SequenceUpdate()</c>'s own clause 17.7 names no response code of its own for
    /// this exact case, but <c>TPM2_SequenceComplete()</c>'s clause 17.8.1 states <c>TPM_RC_MODE</c> for a
    /// sequence handle of the wrong KIND, and the reference's own <c>ObjectIsSequence</c> check generalizes it
    /// to this non-sequence object case too, handle-encoded to index 0 (TPM 2.0 Library Part 2, clause 6.6.2,
    /// Table 16's one-based N field).
    /// <c>sequenceHandle</c> is <c>TPM2_SequenceUpdate()</c>'s sole handle (index 0); a TRANSIENT-range value
    /// resolving to no loaded object at all is instead <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0 Library Part 3, clause
    /// 5.4, step 2.1)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 6.6.2, Table 16; Part 3: Commands, clause 17.7, 17.8.1).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateOnAKeyHandleAnswersModeAndOnAnUnknownHandleAnswersReferenceH0()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<SequenceUpdateResponse> onKeyResult = await SubmitUpdateAsync(tpm, registry, pool, primary.ObjectHandle, [], "data"u8.ToArray()).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_MODE, handleIndex: 0), onKeyResult.ResponseCode,
            "TPM2_SequenceUpdate() against a signing key's own handle (not a sequence) must be refused with TPM_RC_MODE handle-encoded to index 0 (TPM 2.0 Library Part 2, clause 6.6.2, Table 16).");

        TpmiDhObject unknownHandle = TpmiDhObject.FromValue(ArbitraryUnknownHandle);
        TpmResult<SequenceUpdateResponse> unknownResult = await SubmitUpdateAsync(tpm, registry, pool, unknownHandle, [], "data"u8.ToArray()).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, unknownResult.ResponseCode, "sequenceHandle is TPM2_SequenceUpdate()'s sole handle (index 0); a TRANSIENT-range value naming no loaded object is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1).");
    }

    /// <summary>
    /// "In all TPMs, a buffer size of 1,024 octets is allowed": a wire-declared buffer one octet over
    /// <see cref="Tpm2bMaxBuffer.MaxSize"/>, bypassing <see cref="SequenceUpdateInput"/>'s own host-side bound,
    /// is refused with <c>TPM_RC_SIZE</c>. "If the command does not return TPM_RC_SUCCESS, the state of the
    /// sequence is unmodified": completing the sequence afterward signs the EMPTY message, proving the refused
    /// oversized buffer was never appended
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.7, Table 91).
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateWithABufferOverMaxSizeHandFramedReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        byte[] tooLarge = new byte[Tpm2bMaxBuffer.MaxSize + 1];
        TpmRcConstants code = await SubmitSequenceUpdateCommandAsync(simulator, pool, sequenceHandle.Value, tooLarge).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), code, "buffer is TPM2_SequenceUpdate()'s sole parameter (Table 91, index 0); one over Tpm2bMaxBuffer.MaxSize must be refused with parameter-encoded TPM_RC_SIZE (Table 91's floor).");

        TpmResult<SignSequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, [], [], []).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SignSequenceComplete() after the refused oversized update must still succeed: '{completeResult.ResponseCode}'.");

        using SignSequenceCompleteResponse signature = completeResult.Value;
        byte[] digest = SHA256.HashData(ReadOnlySpan<byte>.Empty);
        Assert.IsTrue(
            VerifyEcdsaSignatureOffTpm(primary.OutPublic.PublicArea.Unique.Ecc!, digest, signature.Signature),
            "Clause 17.7's unmodified-state posture: the refused oversized buffer must never have been appended, so the completed message is empty.");
    }

    /// <summary>
    /// The ECDSA happy path: a message split across three <c>TPM2_SequenceUpdate()</c> chunks plus a trailing
    /// <c>TPM2_SignSequenceComplete()</c> buffer signs the SHA-256 digest of the WHOLE concatenated message —
    /// "computes the digest of the message, signs the digest" — verified OFF-TPM against the framework's own
    /// independent SHA-256, sharing no code path with the sequence's own hashing
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6; Part 3: Commands, clause 20.1, Table 115).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteEcdsaAcrossMultipleUpdatesVerifiesOffTpmAgainstTheWholeMessage()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        byte[] chunk1 = "Verifiable "u8.ToArray();
        byte[] chunk2 = "in-house TPM "u8.ToArray();
        byte[] chunk3 = "sequence signing "u8.ToArray();
        byte[] trailing = "acceptance test."u8.ToArray();
        byte[] fullMessage = [.. chunk1, .. chunk2, .. chunk3, .. trailing];

        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk1).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk2).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk3).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, [], [], trailing).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SignSequenceComplete() (ECDSA) failed: '{completeResult.ResponseCode}'.");

        using SignSequenceCompleteResponse signature = completeResult.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, signature.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.HashAlgorithm);

        //Independent-oracle carve-out: framework SHA256.HashData computes the digest and framework ECDsa verifies
        //the signature over it, sharing no code path with the sequence's own hashing or signing.
        byte[] digest = SHA256.HashData(fullMessage);
        Assert.IsTrue(
            VerifyEcdsaSignatureOffTpm(primary.OutPublic.PublicArea.Unique.Ecc!, digest, signature.Signature),
            "A TPM2_SignSequenceComplete() ECDSA signature must verify against the SHA-256 digest of the whole accumulated message.");
    }

    /// <summary>
    /// The RSASSA counterpart of <see cref="SignSequenceCompleteEcdsaAcrossMultipleUpdatesVerifiesOffTpmAgainstTheWholeMessage"/>:
    /// an RSA signing key created with an EXPLICIT RSASSA/SHA-256 template scheme signs the digest of the whole
    /// accumulated message under that retained scheme
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6; Part 3: Commands, clause 20.1, Table 115).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteRsaSsaAcrossMultipleUpdatesVerifiesOffTpmAgainstTheWholeMessage()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRsaSigningPrimaryAsync(
            tpm, registry, pool, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256)).ConfigureAwait(false);

        byte[] chunk1 = "RSASSA "u8.ToArray();
        byte[] chunk2 = "sequence "u8.ToArray();
        byte[] chunk3 = "signing "u8.ToArray();
        byte[] trailing = "acceptance test."u8.ToArray();
        byte[] fullMessage = [.. chunk1, .. chunk2, .. chunk3, .. trailing];

        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk1).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk2).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk3).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, [], [], trailing).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SignSequenceComplete() (RSASSA) failed: '{completeResult.ResponseCode}'.");

        using SignSequenceCompleteResponse signature = completeResult.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSASSA, signature.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.HashAlgorithm);

        byte[] digest = SHA256.HashData(fullMessage);

        Assert.IsTrue(
            VerifyRsaSignatureOffTpm(primary.OutPublic, digest, signature.Signature, RSASignaturePadding.Pkcs1),
            "A TPM2_SignSequenceComplete() RSASSA signature must verify against the SHA-256 digest of the whole accumulated message.");
    }

    /// <summary>
    /// The RSAPSS counterpart of <see cref="SignSequenceCompleteRsaSsaAcrossMultipleUpdatesVerifiesOffTpmAgainstTheWholeMessage"/>,
    /// proving the RETAINED PSS scheme, not a fixed model default, drives the signing primitive
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6; Part 3: Commands, clause 20.1, Table 115).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteRsaPssAcrossMultipleUpdatesVerifiesOffTpmAgainstTheWholeMessage()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRsaSigningPrimaryAsync(
            tpm, registry, pool, TpmtRsaScheme.RsaPss(TpmAlgIdConstants.TPM_ALG_SHA256)).ConfigureAwait(false);

        byte[] chunk1 = "RSAPSS "u8.ToArray();
        byte[] chunk2 = "sequence "u8.ToArray();
        byte[] chunk3 = "signing "u8.ToArray();
        byte[] trailing = "acceptance test."u8.ToArray();
        byte[] fullMessage = [.. chunk1, .. chunk2, .. chunk3, .. trailing];

        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk1).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk2).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], chunk3).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, [], [], trailing).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SignSequenceComplete() (RSAPSS) failed: '{completeResult.ResponseCode}'.");

        using SignSequenceCompleteResponse signature = completeResult.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSAPSS, signature.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.HashAlgorithm);

        byte[] digest = SHA256.HashData(fullMessage);

        Assert.IsTrue(
            VerifyRsaSignatureOffTpm(primary.OutPublic, digest, signature.Signature, RSASignaturePadding.Pss),
            "A TPM2_SignSequenceComplete() RSAPSS signature must verify against the SHA-256 digest of the whole accumulated message as PSS.");
    }

    /// <summary>
    /// "buffer: data to be added to the signature" is appended BEFORE signing, so a one-buffer message needs no
    /// <c>TPM2_SequenceUpdate()</c> at all
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6, Table 124).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteWithASingleBufferAndNoUpdateSigns()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] message = "a one-shot message needing no TPM2_SequenceUpdate() at all."u8.ToArray();

        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        TpmResult<SignSequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, [], [], message).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SignSequenceComplete() over a freshly-started, never-updated sequence must still succeed: '{completeResult.ResponseCode}'.");

        using SignSequenceCompleteResponse signature = completeResult.Value;
        byte[] digest = SHA256.HashData(message);

        Assert.IsTrue(
            VerifyEcdsaSignatureOffTpm(primary.OutPublic.PublicArea.Unique.Ecc!, digest, signature.Signature),
            "The one-shot signature must verify against the SHA-256 digest of the Complete buffer alone.");
    }

    /// <summary>
    /// "When ... TPM2_SignSequenceComplete() ... completes successfully, the sequence context is flushed from
    /// the TPM": a second Complete names <c>sequenceHandle</c> — its sole handle, index 0 — as a TRANSIENT-range
    /// value resolving to nothing loaded, <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0 Library Part 3, clause 5.4, step
    /// 2.1); <c>TPM2_FlushContext()</c> on the same handle keeps its own clause's <c>TPM_RC_HANDLE</c>, parameter-encoded to the same index
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 29.4.6; Part 3: Commands, clause 28.4.1).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteFlushesTheSequenceOnSuccess()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> firstComplete = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, [], [], "message"u8.ToArray()).ConfigureAwait(false);
        Assert.IsTrue(firstComplete.IsSuccess, $"The first TPM2_SignSequenceComplete() must succeed: '{firstComplete.ResponseCode}'.");
        firstComplete.Value.Dispose();

        TpmResult<SignSequenceCompleteResponse> secondComplete = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, [], [], "message"u8.ToArray()).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, secondComplete.ResponseCode, "sequenceHandle is TPM2_SignSequenceComplete()'s sole handle (index 0); an already-flushed sequence is a TRANSIENT-range value resolving to nothing loaded, TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1).");

        FlushContextInput flushInput = FlushContextInput.ForHandle(sequenceHandle.Value);
        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), flushResult.ResponseCode, "TPM2_FlushContext() on an already-flushed sequence is refused at flushHandle, parameter 1 of Table 228 (TPM 2.0 Library Part 3, clause 28.4.1).");
    }

    /// <summary>
    /// "If keyHandle refers to a key that is not the same as the key that was used to start the signature
    /// context, the TPM shall return TPM_RC_SIGN_CONTEXT_KEY": a failing Complete leaves the sequence's state
    /// unmodified, so retrying with the STARTING key signs the ORIGINAL, unmodified accumulated message — the
    /// failing attempt's own trailing <c>"tail"</c> buffer is discriminating proof, not merely an empty one: had
    /// it been installed before the refusal, the retry's signature would cover it too
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6; Part 3: Commands, clause 17.7's unmodified-state posture).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteWithADifferentSigningKeyReturnsSignContextKeyAndTheSequenceSurvives()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse startingKey = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreatePrimaryResponse otherKey = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        byte[] originalMessage = "the original, unmodified sequence message."u8.ToArray();
        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, startingKey.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], originalMessage).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> wrongKeyResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, otherKey.ObjectHandle, [], [], "tail"u8.ToArray()).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_SIGN_CONTEXT_KEY, 1), wrongKeyResult.ResponseCode,
            "Completing with a key different from the one that started the sequence must be refused with TPM_RC_SIGN_CONTEXT_KEY.");

        TpmResult<SignSequenceCompleteResponse> retryResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, startingKey.ObjectHandle, [], [], []).ConfigureAwait(false);
        Assert.IsTrue(retryResult.IsSuccess, $"The sequence must survive the TPM_RC_SIGN_CONTEXT_KEY refusal and complete under its own starting key: '{retryResult.ResponseCode}'.");

        using SignSequenceCompleteResponse signature = retryResult.Value;
        byte[] digest = SHA256.HashData(originalMessage);

        Assert.IsTrue(
            VerifyEcdsaSignatureOffTpm(startingKey.OutPublic.PublicArea.Unique.Ecc!, digest, signature.Signature),
            "The retried completion must sign exactly the ORIGINAL accumulated message, unmodified by the failed attempt's own trailing buffer.");
    }

    /// <summary>
    /// A wrong sequence auth at Complete is refused, uncharged, with the plain session-index-0-encoded
    /// <c>TPM_RC_BAD_AUTH</c>; a wrong KEY auth (Auth Index 2, the second supplied session) is refused with the
    /// session-index-1-encoded <c>TPM_RC_AUTH_FAIL</c> and charges the DA-protected key's <c>failedTries</c>
    /// exactly once
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 6.6.2; Part 1: Architecture, clauses 16.8.3, 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteWithWrongSequenceAuthReturnsBadAuthUnchargedAndWrongKeyAuthReturnsAuthFailCharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateDaProtectedEccSigningPrimaryAsync(tpm, registry, pool, "complete-key-auth").ConfigureAwait(false);
        byte[] correctKeyAuth = System.Text.Encoding.UTF8.GetBytes("complete-key-auth");
        byte[] wrongKeyAuth = System.Text.Encoding.UTF8.GetBytes("wrong-complete-key-auth");
        byte[] sequenceAuth = System.Text.Encoding.UTF8.GetBytes("complete-sequence-auth");
        byte[] wrongSequenceAuth = System.Text.Encoding.UTF8.GetBytes("wrong-complete-sequence-auth");

        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, sequenceAuth).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> wrongSequenceResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, wrongSequenceAuth, correctKeyAuth, []).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), wrongSequenceResult.ResponseCode,
            "A wrong sequence auth at Complete must be refused with session-index-0-encoded TPM_RC_BAD_AUTH, uncharged.");

        TpmResult<TpmDictionaryAttackParameters> afterWrongSequence = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, afterWrongSequence.Value.LockoutCounter, "A wrong sequence auth must never move failedTries.");

        TpmResult<SignSequenceCompleteResponse> wrongKeyResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, sequenceAuth, wrongKeyAuth, []).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), wrongKeyResult.ResponseCode,
            "A wrong KEY auth at Complete over its own TPM_RS_PW session (the second supplied session) must be refused with session-index-1-encoded TPM_RC_AUTH_FAIL.");

        TpmResult<TpmDictionaryAttackParameters> afterWrongKey = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            afterWrongSequence.Value.LockoutCounter + 1, afterWrongKey.Value.LockoutCounter,
            "A wrong KEY auth against a DA-protected signing key must charge failedTries exactly once.");
    }

    /// <summary>
    /// Proves TPM 2.0 Library Part 3, clause 5.6, check 7.1 at <c>TPM2_SignSequenceComplete()</c>'s key slot
    /// (Auth Index 2, Auth Role USER): a plain <c>TPM_RS_PW</c> session over a key whose
    /// <c>TPMA_OBJECT.userWithAuth</c> is CLEAR is refused with a <c>TPM_RC_POLICY_FAIL</c>, session-encoded to the same index — even though
    /// the sequence's own auth (Auth Index 1) is correct and the key password supplied is itself correct —
    /// because it is the session's SHAPE, not its credential, that is inadmissible for a userWithAuth-CLEAR
    /// object's USER role
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.6, check 7.1).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOnAUserWithAuthClearKeyReturnsPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        const string KeyPassword = "user-with-auth-clear-key-auth";
        using CreatePrimaryResponse primary = await CreateUserWithAuthClearEccSigningPrimaryAsync(tpm, registry, pool, KeyPassword).ConfigureAwait(false);
        byte[] sequenceAuth = System.Text.Encoding.UTF8.GetBytes("user-with-auth-clear-sequence-auth");
        byte[] keyAuth = System.Text.Encoding.UTF8.GetBytes(KeyPassword);

        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, sequenceAuth).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, sequenceAuth, keyAuth, []).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 1), completeResult.ResponseCode,
            "A userWithAuth-CLEAR signing key must refuse TPM2_SignSequenceComplete()'s password session at keyHandle, session 2 of Table 124, even though the sequence auth and the key password are both correct.");
    }

    /// <summary>
    /// "If the restricted attribute of keyHandle is SET, then message must not begin with TPM_GENERATED_VALUE" —
    /// clause 20.6 names no response code for this rule; TPM_RC_ATTRIBUTES is used here, matching the
    /// neighbouring x509sign rule in the same clause for "this key's attributes forbid this use"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6; Part 3: Commands, clause 17.7's first-block rule).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOnARestrictedKeyWithATpmGeneratedPrefixedMessageReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] message = [.. TpmGeneratedValueBytes, .. "trailing content"u8.ToArray()];

        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], message).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, [], [], []).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), completeResult.ResponseCode,
            "A restricted signing key completing a sequence whose first presented block begins with TPM_GENERATED_VALUE must be refused with TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// A restricted signing key completing an ordinary message — one whose first presented block does not begin
    /// with <c>TPM_GENERATED_VALUE</c> — succeeds
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6; Part 3: Commands, clause 17.7's first-block rule).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOnARestrictedKeyWithAnOrdinaryMessageSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] message = "an ordinary message not beginning with TPM_GENERATED_VALUE."u8.ToArray();

        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], message).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, [], [], []).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"A restricted key completing an ordinary message must succeed: '{completeResult.ResponseCode}'.");

        using SignSequenceCompleteResponse signature = completeResult.Value;
        byte[] digest = SHA256.HashData(message);

        Assert.IsTrue(
            VerifyEcdsaSignatureOffTpm(primary.OutPublic.PublicArea.Unique.Ecc!, digest, signature.Signature),
            "The restricted key's signature must verify against the SHA-256 digest of the ordinary message.");
    }

    /// <summary>
    /// The first-block safety verdict is taken once, on the FIRST buffer presented to the sequence, and never
    /// revisited: a first block shorter than <c>sizeof(TPM_GENERATED)</c> (four octets) is judged unsafe, and a
    /// restricted key is refused <c>TPM_RC_ATTRIBUTES</c> at Complete even when every later chunk is innocent
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.8's "fewer than sizeof(TPM_GENERATED) octets" note).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOnARestrictedKeyWithAShortFirstBlockReturnsAttributesEvenWithInnocentLaterChunks()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] shortFirstBlock = [0x01, 0x02, 0x03]; //Fewer than sizeof(TPM_GENERATED) octets.
        byte[] laterChunk = "perfectly innocent content"u8.ToArray();

        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], shortFirstBlock).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], laterChunk).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, [], [], []).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), completeResult.ResponseCode,
            "The first-block safety verdict is taken once and never revisited: a first block shorter than sizeof(TPM_GENERATED) is unsafe regardless of what follows.");
    }

    /// <summary>
    /// Only a RESTRICTED signing key consults the first-block safety verdict: the SAME <c>TPM_GENERATED_VALUE</c>
    /// -prefixed message, under an unrestricted key, succeeds
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6's restricted-only rule).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOnAnUnrestrictedKeyWithATpmGeneratedPrefixedMessageSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] message = [.. TpmGeneratedValueBytes, .. "trailing content"u8.ToArray()];

        TpmiDhObject sequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceSuccessfullyAsync(tpm, registry, pool, sequenceHandle, [], message).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> completeResult = await SubmitCompleteAsync(
            tpm, registry, pool, sequenceHandle, primary.ObjectHandle, [], [], []).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"An unrestricted key must ignore the first-block safety verdict and succeed: '{completeResult.ResponseCode}'.");

        using SignSequenceCompleteResponse signature = completeResult.Value;
        byte[] digest = SHA256.HashData(message);

        Assert.IsTrue(
            VerifyEcdsaSignatureOffTpm(primary.OutPublic.PublicArea.Unique.Ecc!, digest, signature.Signature),
            "The unrestricted key's signature must verify against the SHA-256 digest of the TPM_GENERATED_VALUE-prefixed message.");
    }

    /// <summary>
    /// "An object context is only removed from TPM memory with TPM2_FlushContext(), deletion of the associated
    /// hierarchy seed, or TPM2_Startup()": issuing another <c>TPM2_Startup()</c> against an already-operational
    /// simulator flushes EVERY open sequence, not merely one — <c>sequenceHandle</c> is
    /// <c>TPM2_SequenceUpdate()</c>'s sole handle (index 0), and each of two concurrently open sequences is a
    /// TRANSIENT-range value resolving to nothing loaded after the reset, refused <c>TPM_RC_REFERENCE_H0</c>
    /// (TPM 2.0 Library Part 3, clause 5.4, step 2.1) on the next <c>TPM2_SequenceUpdate()</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 27.4).
    /// </summary>
    [TestMethod]
    public async Task StartupFlushesEveryOpenSequence()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject firstSequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        TpmiDhObject secondSequenceHandle = await StartSequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        //A TPM Reset: an orderly TPM2_Shutdown(CLEAR), the _TPM_Init signal, then TPM2_Startup(CLEAR) (TPM 2.0
        //Library Part 1, clause 9.3) — the only way a second TPM2_Startup() is admitted on a running TPM.
        await IssueShutdownClearAsync(simulator, pool).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        TpmResult<SequenceUpdateResponse> firstUpdateResult = await SubmitUpdateAsync(tpm, registry, pool, firstSequenceHandle, [], "data"u8.ToArray()).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, firstUpdateResult.ResponseCode, "sequenceHandle is TPM2_SequenceUpdate()'s sole handle (index 0); TPM2_Startup() must flush every open sequence, so the first of two concurrently open sequences is a TRANSIENT-range value naming nothing loaded, TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1).");

        TpmResult<SequenceUpdateResponse> secondUpdateResult = await SubmitUpdateAsync(tpm, registry, pool, secondSequenceHandle, [], "data"u8.ToArray()).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, secondUpdateResult.ResponseCode, "sequenceHandle is TPM2_SequenceUpdate()'s sole handle (index 0); TPM2_Startup() must flush every open sequence, so the second, concurrently open sequence must likewise answer TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1).");
    }

    /// <summary>
    /// Issues <c>TPM2_Shutdown(TPM_SU_CLEAR)</c> directly against the simulator, framed the same unauthorized way
    /// <see cref="BringOperationalAsync"/> frames <c>TPM2_Startup()</c>, so a following <c>_TPM_Init</c> and
    /// <c>TPM2_Startup(CLEAR)</c> form a TPM Reset (TPM 2.0 Library Part 3, clause 9.4).
    /// </summary>
    /// <param name="simulator">The simulator to shut down.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task IssueShutdownClearAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new ShutdownInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Shutdown(CLEAR) must succeed at the transport level.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Shutdown(CLEAR) must succeed.");
    }

    /// <summary>
    /// Submits <see cref="SignSequenceStartInput.Create"/> with no session (Auth Index None; no authorization of
    /// <c>keyHandle</c> is required at Start) and returns the raw result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The candidate signing key handle.</param>
    /// <param name="sequenceAuth">The sequence's own authValue.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<SignSequenceStartResponse>> SubmitStartAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        using SignSequenceStartInput input = SignSequenceStartInput.Create(keyHandle, sequenceAuth, pool);

        return await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Starts a sequence via <see cref="SubmitStartAsync"/>, asserting success, and returns its handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The signing key handle.</param>
    /// <param name="sequenceAuth">The sequence's own authValue.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartSequenceAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        TpmResult<SignSequenceStartResponse> result = await SubmitStartAsync(tpm, registry, pool, keyHandle, sequenceAuth).ConfigureAwait(false);
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
    /// Submits <see cref="SignSequenceCompleteInput.Create"/> over two <c>TPM_RS_PW</c> sessions authorizing
    /// <c>@sequenceHandle</c> (Auth Index 1, session 0) then <c>@keyHandle</c> (Auth Index 2, session 1), and
    /// returns the raw result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence handle.</param>
    /// <param name="keyHandle">The candidate signing key handle.</param>
    /// <param name="sequenceAuth">The caller-supplied sequence auth (empty for an empty-authValue sequence).</param>
    /// <param name="keyAuth">The caller-supplied key auth (empty for an empty-authValue key).</param>
    /// <param name="buffer">The trailing Complete buffer.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<SignSequenceCompleteResponse>> SubmitCompleteAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, TpmiDhObject keyHandle,
        byte[] sequenceAuth, byte[] keyAuth, byte[] buffer)
    {
        using TpmPasswordSession sequenceSession = sequenceAuth.Length == 0 ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(sequenceAuth, pool);
        using TpmPasswordSession keySession = keyAuth.Length == 0 ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(keyAuth, pool);
        using SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(sequenceHandle, keyHandle, buffer, pool);

        return await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
            tpm, input, [sequenceSession, keySession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Composes an X509SIGN ECC signing key template — <c>TPMA_OBJECT.x509sign</c> SET alongside <c>sign</c>,
    /// with no password (empty authValue) — mirroring the restricted-key template's direct-composition style,
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
    /// <remarks>
    /// This assumes <c>TPM2_CreatePrimary()</c> admits the <c>x509sign</c> attribute at creation and refuses it
    /// only downstream, at <c>TPM2_SignSequenceStart()</c> — the same posture the simulator already takes for
    /// every other attribute-gated refusal (e.g. a NULL-scheme template, or a CLEAR <c>sign</c> attribute, both
    /// create successfully and are refused only when used to sign).
    /// </remarks>
    private async Task<CreatePrimaryResponse> CreateX509SignEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreateX509SignEccSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (X509SIGN ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Composes a restricted ECC signing key template — <c>TPMA_OBJECT.restricted</c> SET alongside <c>sign</c>,
    /// with no password (empty authValue) — mirroring
    /// <c>TpmInHouseSimulatorSignDigestTests.CreateRestrictedEccSigningKeyInput</c>'s direct-template style,
    /// since no production factory builds a restricted signing key.
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

    /// <summary>Creates a restricted ECC signing primary under the owner hierarchy and returns the response (the caller owns it).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateRestrictedEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreateRestrictedEccSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (restricted ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an unrestricted, empty-password ECC P-256 signing primary under the owner hierarchy and returns the response (the caller owns it).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response.</returns>
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

    /// <summary>Creates a DA-protected, password-guarded ECC P-256 signing primary under the owner hierarchy.</summary>
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

    /// <summary>
    /// Composes a CreatePrimary input for a DA-protected ECC signing key whose <c>TPMA_OBJECT.userWithAuth</c>
    /// bit is CLEAR — no production factory omits it, so the public template is built directly, mirroring
    /// <c>TpmInHouseSimulatorSignTests.CreateUserWithAuthClearEccSigningKeyInput</c>.
    /// </summary>
    /// <param name="password">The real password bound to the key's retained authValue.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the returned CreatePrimaryInput, whose Dispose releases them.")]
    private static CreatePrimaryInput CreateUserWithAuthClearEccSigningKeyInput(string password, BaseMemoryPool pool)
    {
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.WithPassword(password, pool);

        var attributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.SIGN_ENCRYPT;

        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            attributes,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));

        return new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
    }

    /// <summary>Creates a userWithAuth-CLEAR ECC signing primary under the owner hierarchy and returns the response (the caller owns it).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="password">The key's own password.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateUserWithAuthClearEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, string password)
    {
        using CreatePrimaryInput input = CreateUserWithAuthClearEccSigningKeyInput(password, pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (userWithAuth-CLEAR ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an unrestricted, empty-password RSA 2048 signing primary with the given template scheme.</summary>
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
    /// handle — mirroring <c>TpmInHouseSimulatorSignDigestTests.SignDigestAgainstAKeyedhashKeyReturnsScheme</c>'s
    /// setup.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The loaded sealed object's handle.</returns>
    private async Task<TpmiDhObject> CreateLoadedSealedObjectHandleAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData("not a signing key"u8.ToArray(), pool);
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

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceUpdate, TpmResponseCodec.SequenceUpdate);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceComplete, TpmResponseCodec.SignSequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);

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

    /// <summary>
    /// Verifies an RSA signature off-TPM against a public key reconstructed solely from the simulator's exported
    /// modulus — sharing no code path with the signer.
    /// </summary>
    /// <param name="outPublic">The exported public area.</param>
    /// <param name="digest">The digest that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="padding">The RSA signature padding (PKCS#1 v1.5 for RSASSA, PSS for RSAPSS).</param>
    /// <returns><see langword="true"/> when the signature verifies.</returns>
    private static bool VerifyRsaSignatureOffTpm(Tpm2bPublic outPublic, byte[] digest, TpmuSignature signature, RSASignaturePadding padding)
    {
        var rsaParameters = new RSAParameters
        {
            Modulus = outPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
            Exponent = [0x01, 0x00, 0x01]
        };

        using RSA rsa = RSA.Create(rsaParameters);

        return rsa.VerifyHash(digest, signature.RsaSignature.Buffer.ToArray(), HashAlgorithmName.SHA256, padding);
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
            "tpm-in-house-sign-sequence",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>. Reusable a
    /// second time against an already-operational simulator to prove <c>TPM2_Startup()</c> flushes volatile state.
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
    /// Persist-then-reload a public area through wire bytes only — the disk round-trip a real deployment
    /// performs — yielding an independently-owned copy rather than aliasing <paramref name="source"/>'s own
    /// storage.
    /// </summary>
    /// <param name="source">The public area to clone.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The cloned public area; the caller owns and disposes it.</returns>
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
    /// Left-pads a big-endian integer to a fixed width, as the IEEE P1363 / ECPoint encodings require. The
    /// simulator returns TPM2B integers that may omit leading zero bytes.
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

    /// <summary>
    /// Hand-frames a <c>TPM2_SignSequenceStart()</c> command with a caller-chosen tag and <c>context</c> body,
    /// bypassing <see cref="SignSequenceStartInput"/> (which always frames <c>TPM_ST_NO_SESSIONS</c> and an
    /// empty context) — letting a caller submit a malformed tag or a non-empty context directly against the
    /// simulator.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag to frame verbatim.</param>
    /// <param name="keyHandle">The <c>keyHandle</c> handle value.</param>
    /// <param name="sequenceAuth">The <c>auth</c> parameter's octets.</param>
    /// <param name="context">The <c>context</c> parameter's octets, written verbatim as a TPM2B.</param>
    /// <param name="length">The framed command's total length.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameSignSequenceStartCommand(
        BaseMemoryPool pool, ushort tag, uint keyHandle, ReadOnlySpan<byte> sequenceAuth, ReadOnlySpan<byte> context, out int length)
    {
        length =
            TpmHeader.HeaderSize
            + sizeof(uint)                          //Handle area: @keyHandle.
            + (sizeof(ushort) + sequenceAuth.Length) //auth: TPM2B_AUTH.
            + (sizeof(ushort) + context.Length);     //context: TPM2B_SIGNATURE_CTX.

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader(tag, (uint)length, (uint)TpmCcConstants.TPM_CC_SignSequenceStart);
            header.WriteTo(ref writer);
            writer.WriteUInt32(keyHandle);
            writer.WriteTpm2b(sequenceAuth);
            writer.WriteTpm2b(context);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_SignSequenceStart()</c> built by <see cref="FrameSignSequenceStartCommand"/>
    /// straight to the simulator (bypassing <see cref="TpmCommandExecutor"/>) and yields the response code.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag to frame verbatim.</param>
    /// <param name="keyHandle">The <c>keyHandle</c> handle value.</param>
    /// <param name="sequenceAuth">The <c>auth</c> parameter's octets.</param>
    /// <param name="context">The <c>context</c> parameter's octets.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSignSequenceStartCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, ushort tag, uint keyHandle, byte[] sequenceAuth, byte[] context)
    {
        using IMemoryOwner<byte> commandOwner = FrameSignSequenceStartCommand(pool, tag, keyHandle, sequenceAuth, context, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_SequenceUpdate()</c> command carrying an oversized <c>buffer</c>, bypassing
    /// <see cref="SequenceUpdateInput.Create"/>'s own host-side bound, over a single empty-password
    /// <c>TPM_RS_PW</c> slot.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The <c>@sequenceHandle</c> handle value.</param>
    /// <param name="buffer">The <c>buffer</c> parameter's octets, written verbatim as a TPM2B.</param>
    /// <param name="length">The framed command's total length.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameSequenceUpdateCommand(
        BaseMemoryPool pool, uint sequenceHandle, ReadOnlySpan<byte> buffer, out int length)
    {
        const int PasswordSlotSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);

        length =
            TpmHeader.HeaderSize
            + sizeof(uint)                     //Handle area: @sequenceHandle.
            + sizeof(uint) + PasswordSlotSize  //authorizationSize + one empty TPM_RS_PW slot.
            + sizeof(ushort) + buffer.Length;  //buffer: TPM2B_MAX_BUFFER.

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_SequenceUpdate);
            header.WriteTo(ref writer);
            writer.WriteUInt32(sequenceHandle);
            writer.WriteUInt32((uint)PasswordSlotSize);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteTpm2b(buffer);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_SequenceUpdate()</c> built by <see cref="FrameSequenceUpdateCommand"/>
    /// straight to the simulator (bypassing <see cref="TpmCommandExecutor"/>) and yields the response code.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The <c>@sequenceHandle</c> handle value.</param>
    /// <param name="buffer">The <c>buffer</c> parameter's octets.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSequenceUpdateCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint sequenceHandle, byte[] buffer)
    {
        using IMemoryOwner<byte> commandOwner = FrameSequenceUpdateCommand(pool, sequenceHandle, buffer, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }
}
