using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
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
/// Proves TPM 2.0 Library Part 3, clause 5.4 (Handle Area Validation) against the in-house behavioural
/// <see cref="TpmSimulator"/>: an unloaded TRANSIENT-range handle in a command's handle area answers
/// <c>TPM_RC_REFERENCE_H0 + N</c> (step 2.1, <c>N</c> the handle's 0-based position in the command's own Part 3
/// table); its PERSISTENT-range twin at the same position answers <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (step 2.2); and a
/// SESSION named in the handle area (every <c>TPM2_Policy*()</c> command's <c>policySession</c>) that is not
/// loaded answers the same <c>TPM_RC_REFERENCE_H0 + N</c> family (step 2.4) — while a value outside
/// <c>TPMI_SH_POLICY</c>'s own range (TPM 2.0 Library Part 2, Table 56) never reaches step 2.4 at all, refused
/// <c>TPM_RC_VALUE</c>, handle-encoded to the same index at unmarshal instead. Every two-handle row holds a genuinely loaded object at the
/// slot it is not probing, so the code is proven from the probed handle's own position, not from "the first
/// handle failed."
/// </summary>
/// <remarks>
/// <para>
/// <b>Commands covered by this class's own rows:</b> the thirteen single-handle <c>TPM2_Policy*()</c> commands
/// (<c>PolicyCommandCode</c>, <c>PolicyAuthValue</c>, <c>PolicyGetDigest</c>, <c>PolicyPCR</c>, <c>PolicyOR</c>,
/// <c>PolicyCounterTimer</c>, <c>PolicyPassword</c>, <c>PolicyCpHash</c>, <c>PolicyNameHash</c>,
/// <c>PolicyParameters</c>, <c>PolicyTemplate</c>, <c>PolicyLocality</c>, <c>PolicyNvWritten</c>) for both the
/// unloaded-session and the out-of-range rows, <c>TPM2_PolicyDuplicationSelect()</c>'s out-of-range row riding
/// the identical shared framer; <c>TPM2_PolicySecret()</c>'s <c>authHandle</c> (index 0) and
/// <c>policySession</c> (index 1) across every outcome clause 5.4 and the standing modelling boundary produce;
/// <c>TPM2_EventSequenceComplete()</c>'s persistent-range <c>sequenceHandle</c> miss; the PERSISTENT-range
/// twin of <c>TPM2_Certify()</c> (both handles), <c>TPM2_CertifyCreation()</c> (both handles), <c>TPM2_Quote()</c>,
/// <c>TPM2_GetTime()</c>, <c>TPM2_Sign()</c>, <c>TPM2_Load()</c>, <c>TPM2_NV_Certify()</c> and
/// <c>TPM2_ActivateCredential()</c> (both handles); <c>TPM2_EvictControl()</c>'s <c>objectHandle</c> (index 1)
/// across both ranges; <c>TPM2_SignDigest()</c>'s <c>keyHandle</c> (index 0) across both ranges;
/// <c>TPM2_Duplicate()</c>'s <c>objectHandle</c> (index 0) and <c>newParentHandle</c> (index 1) across both
/// ranges; <c>TPM2_Import()</c>'s <c>parentHandle</c> (index 0) across both ranges; <c>TPM2_Create()</c>'s
/// KEYEDHASH-arm <c>parentHandle</c> (index 0) across both ranges, on BOTH wire forms, plus a sessions-form row
/// over a genuinely loaded, non-zero-digest AUDIT companion proving its <c>nonceTPM</c> and audit digest
/// byte-identical across the refusal; <c>TPM2_PolicyNV()</c> and <c>TPM2_PolicyAuthorizeNV()</c>'s
/// <c>policySession</c> (index 2, unloaded and out-of-range); <c>TPM2_PolicyTicket()</c> and
/// <c>TPM2_PolicyAuthorize()</c>'s <c>policySession</c> (index 0, unloaded and out-of-range); and
/// <c>TPM2_PolicySigned()</c>'s <c>policySession</c> out-of-range row (its unloaded row is proven in its own
/// class, cited rather than duplicated).
/// </para>
/// <para>
/// <b>PERSISTENT-range twins and wrong-kind branches rowed here across both outcomes and every wire
/// form</b>: <c>TPM2_Unseal()</c>'s <c>itemHandle</c> (index 0, PLAIN and SESSIONS forms);
/// <c>TPM2_RSA_Decrypt()</c>'s <c>keyHandle</c> (index 0, PLAIN and over-session forms);
/// <c>TPM2_Decapsulate()</c>'s <c>keyHandle</c> (index 0, both outcomes, neither proven anywhere else in the
/// tree); <c>TPM2_ObjectChangeAuth()</c>'s <c>objectHandle</c> (index 0) and <c>parentHandle</c> (index 1)
/// PERSISTENT-range twins (the TRANSIENT twin is proven in its own class); the sequence family's
/// <c>sequenceHandle</c> PERSISTENT-range twin — <c>TPM2_SequenceUpdate()</c> (index 0, PLAIN and over-session),
/// <c>TPM2_SequenceComplete()</c> (index 0), <c>TPM2_SignSequenceComplete()</c> and
/// <c>TPM2_VerifySequenceComplete()</c> (index 0, PLAIN and over-session; the TRANSIENT twin for all four is
/// proven in each command's own class) — plus <c>TPM2_SignSequenceComplete()</c>'s and
/// <c>TPM2_VerifySequenceComplete()</c>'s own resolved-but-not-a-sequence branch, a loaded signing key at
/// <c>sequenceHandle</c> answering handle-encoded <c>TPM_RC_MODE</c> at index 0 (Part 2, clause 6.6.2, Table 16;
/// Part 3, clauses 20.6 and 20.3 name no override of their own, but the family's wrong-KIND rule — Part 3, clause 17.8.1 /
/// 17.9.1's <c>TPM_RC_MODE</c>, generalized to every non-sequence kind — applies here too), proven nowhere else
/// in the tree.
/// </para>
/// <para>
/// <b>Eight SESSIONS-form combinations rowed here</b>: the SESSIONS wire forms
/// of <c>TPM2_Certify()</c> (<c>objectHandle</c> and <c>signHandle</c>), <c>TPM2_CertifyCreation()</c>
/// (<c>signHandle</c> and <c>objectHandle</c>), <c>TPM2_GetTime()</c> (<c>signHandle</c>) and
/// <c>TPM2_NV_Certify()</c> (<c>signHandle</c>) — each proving BOTH outcomes over an empty-password companion
/// slot, since clause 5.4 precedes clause 5.5's session judgment so a password area suffices;
/// <c>TPM2_Quote()</c>'s SESSIONS-form persistent-range twin (its PLAIN-form ternary already proves both
/// outcomes, so only the persistent twin is rowed here); and
/// <c>TPM2_GetSessionAuditDigest()</c>'s <c>signHandle</c> (index 1, both ranges, both wire forms — a genuinely
/// started audit session at <c>sessionHandle</c>, index 2).
/// </para>
/// <para>
/// <b>Sites proven elsewhere, not duplicated here</b> (each already carries its own transient-range and, where
/// applicable, out-of-range or session-slot row): <c>TPM2_Certify()</c> both handles, <c>TPM2_CertifyCreation()</c>
/// <c>signHandle</c>, <c>TPM2_Quote()</c> <c>signHandle</c> (PLAIN form), <c>TPM2_GetTime()</c> <c>signHandle</c>
/// (PLAIN form), <c>TPM2_NV_Certify()</c> <c>signHandle</c> (PLAIN form), <c>TPM2_Sign()</c> <c>keyHandle</c>,
/// <c>TPM2_Load()</c> <c>parentHandle</c>, <c>TPM2_ActivateCredential()</c> <c>activateHandle</c>,
/// <c>TPM2_ContextSave()</c> <c>saveHandle</c> (both the transient- and session-range miss),
/// <c>TPM2_GetSessionAuditDigest()</c> <c>sessionHandle</c>, <c>TPM2_PolicyRestart()</c> <c>sessionHandle</c>
/// (both the unloaded and the out-of-range case), <c>TPM2_PolicyDuplicationSelect()</c> <c>policySession</c>'s
/// unloaded row (its out-of-range row is rowed here instead), <c>TPM2_PolicySigned()</c> <c>policySession</c>
/// (checked before <c>authObject</c>), <c>TPM2_Unseal()</c> <c>itemHandle</c>'s PLAIN-form TRANSIENT-range row,
/// <c>TPM2_RSA_Decrypt()</c> <c>keyHandle</c>'s PLAIN-form TRANSIENT-range row, <c>TPM2_ObjectChangeAuth()</c>'s
/// TRANSIENT-range row for both handles, and the sequence family's TRANSIENT-range row for
/// <c>TPM2_SequenceUpdate()</c>, <c>TPM2_SequenceComplete()</c>, <c>TPM2_SignSequenceComplete()</c> and
/// <c>TPM2_VerifySequenceComplete()</c> on every wire form — all in their own per-command test classes.
/// </para>
/// <para>
/// <b>The clause-stated overrides</b> (TPM 2.0 Library Part 3): <c>TPM2_FlushContext()</c>'s own text (clause
/// 28.4.1) names <c>TPM_RC_HANDLE</c> for an unresolved <c>flushHandle</c>, but Table 228 designates
/// <c>flushHandle</c> a PARAMETER rather than a handle, so this tree answers it parameter-encoded; and
/// <c>TPM2_StartAuthSession()</c>'s <c>tpmKey</c>/<c>bind</c> (clause 11.1.1) is likewise handle-encoded rather
/// than bare. Both are pinned in their own classes and are not rowed here.
/// </para>
/// <para>
/// <b>Sites deliberately not rowed</b> (the shared reader clause 5.4 step 2.4 funnels every <c>TPM2_Policy*()</c>
/// <c>policySession</c> through is proven uniformly by the thirteen single-handle commands plus
/// <c>PolicyNV</c>/<c>PolicyAuthorizeNV</c>/<c>PolicyTicket</c>/<c>PolicyAuthorize</c>, so the remaining sites
/// ride the identical mechanism): <c>TPM2_PolicyRestart()</c> (already proven in its own class, both outcomes).
/// </para>
/// <para>
/// <b>The one site still left unrowed</b>: <c>TPM2_Quote()</c>'s SESSIONS-form TRANSIENT-range outcome — its
/// PLAIN-form ternary and its SESSIONS-form persistent twin (above) already prove the mechanism at this
/// index, so it is left for whichever future row happens to need the fixture.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorHandleAreaValidationTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A well-typed but unloaded TRANSIENT-range handle, from a range this class never allocates into.</summary>
    private const uint UnloadedTransientHandle = TpmHandleRanges.TRANSIENT_FIRST + 0xFF;

    /// <summary>A well-typed but unallocated PERSISTENT-range handle, the twin of <see cref="UnloadedTransientHandle"/> for clause 5.4 step 2.2.</summary>
    private const uint UnallocatedPersistentHandle = TpmHandleRanges.PERSISTENT_FIRST + 0xFF;

    /// <summary>A well-typed but unloaded POLICY-session-range handle, from a range this class never starts a session into.</summary>
    private const uint UnloadedPolicySessionHandle = TpmHandleRanges.POLICY_SESSION_FIRST + 0xFF;

    /// <summary>An HMAC-session-range value, outside <c>TPMI_SH_POLICY</c>'s own range (TPM 2.0 Library Part 2, Table 56).</summary>
    private const uint HmacRangeOutOfPolicyRange = TpmHandleRanges.HMAC_SESSION_FIRST + 0xFF;

    /// <summary>A TRANSIENT-object-range value, outside <c>TPMI_SH_POLICY</c>'s own range (TPM 2.0 Library Part 2, Table 56).</summary>
    private const uint ObjectRangeOutOfPolicyRange = TpmHandleRanges.TRANSIENT_FIRST + 0xFF;

    /// <summary>A fixed 32-octet buffer used wherever a row needs SOME well-formed digest-shaped bytes; clause 5.4's handle check runs before any parameter content is judged, so its value is immaterial.</summary>
    private static byte[] FixedDigest { get; } = new byte[32];

    /// <summary>A fixed, non-empty caller nonce used wherever a row's command frames a <c>TPM2B</c> qualifying-data or nonce parameter.</summary>
    private static byte[] QualifyingData { get; } = [0x10, 0x20, 0x30, 0x40];

    /// <summary>
    /// A single non-empty placeholder byte used as a probed handle's cpHash Name where an HMAC or policy session
    /// is present: clause 5.4's handle-area resolution failure precedes any cpHash judgment, so the actual
    /// content is immaterial — only its non-emptiness matters, since the executor refuses a missing Name for a
    /// transient/persistent-range handle before submitting.
    /// </summary>
    private static byte[] PlaceholderProbeName { get; } = [0xAA];

    /// <summary>A valid, in-range persistentHandle target for <c>TPM2_EvictControl()</c> rows that probe <c>objectHandle</c> instead — distinct from <see cref="UnallocatedPersistentHandle"/> so the two never collide.</summary>
    private const uint EvictControlTargetPersistentHandle = TpmHandleRanges.PERSISTENT_FIRST + 0x0500;

    /// <summary>A defined, owner-readable NV Index used by the <c>TPM2_PolicyNV()</c>/<c>TPM2_PolicyAuthorizeNV()</c> rows, so <c>nvIndex</c> resolves and the probe reaches <c>policySession</c> at index 2.</summary>
    private const uint SampleNvIndex = TpmHandleRanges.NV_INDEX_FIRST + 0x0500;

    /// <summary>Builds the response codec registry for this class's rows that submit through <see cref="TpmCommandExecutor"/> directly (the Policy-family extension verbs compose their own internal registry).</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_Certify, TpmResponseCodec.Certify);
        _ = registry.Register(TpmCcConstants.TPM_CC_CertifyCreation, TpmResponseCodec.CertifyCreation);
        _ = registry.Register(TpmCcConstants.TPM_CC_Quote, TpmResponseCodec.Quote);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetTime, TpmResponseCodec.GetTime);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);
        _ = registry.Register(TpmCcConstants.TPM_CC_ActivateCredential, TpmResponseCodec.ActivateCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignDigest, TpmResponseCodec.SignDigest);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Certify, TpmResponseCodec.NvCertify);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_RSA_Decrypt, TpmResponseCodec.RsaDecrypt);
        _ = registry.Register(TpmCcConstants.TPM_CC_Decapsulate, TpmResponseCodec.Decapsulate);
        _ = registry.Register(TpmCcConstants.TPM_CC_ObjectChangeAuth, TpmResponseCodec.ObjectChangeAuth);
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceUpdate, TpmResponseCodec.SequenceUpdate);
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceComplete, TpmResponseCodec.SequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceComplete, TpmResponseCodec.SignSequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySequenceComplete, TpmResponseCodec.VerifySequenceComplete);

        return registry;
    }

    /// <summary>
    /// Creates an operational simulator carrying an RSA signing backend in addition to the ECC one — required
    /// for <c>TPM2_RSA_Decrypt()</c>'s two rows, since <see cref="HmacKeyHarness.CreateOperationalAsync"/>'s
    /// plain simulator answers <c>TPM_RC_COMMAND_CODE</c> for any RSA-backed command.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The operational simulator; the caller disposes it.</returns>
    private static async Task<TpmSimulator> CreateOperationalWithRsaBackendAsync(BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        var simulator = new TpmSimulator(
            "tpm-handle-area-rsa", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(cancellationToken).ConfigureAwait(false);

        var startupInput = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + startupInput.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)startupInput.CommandCode);
        header.WriteTo(ref writer);
        startupInput.WriteHandles(ref writer);
        startupInput.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");
        using(TpmResponse response = result.Value)
        {
            var responseReader = new TpmReader(response.AsReadOnlySpan());
            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)TpmHeader.Parse(ref responseReader).Code, "TPM2_Startup(CLEAR) must succeed.");
        }

        return simulator;
    }

    /// <summary>Creates a loaded ECC signing primary under the owner hierarchy, asserting success — the genuinely loaded companion object every two-handle row's non-probed slot holds.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The CreatePrimary response; the caller disposes it.</returns>
    private static async Task<CreatePrimaryResponse> CreateEccSigningKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Submits the named <c>TPM2_Policy*()</c> command with <paramref name="policySessionProbe"/> at its
    /// <c>policySession</c> slot, every other parameter a minimal well-formed value — clause 5.4's handle-area
    /// check runs before any of them is judged, so their content never matters to the outcome under test.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="command">The Policy command to submit.</param>
    /// <param name="policySessionProbe">The value placed at the command's <c>policySession</c> handle-area slot.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The command's response code.</returns>
    private static async Task<TpmRcConstants> SubmitPolicySessionSlotProbeAsync(TpmDevice tpm, TpmCcConstants command, uint policySessionProbe, CancellationToken cancellationToken)
    {
        return command switch
        {
            TpmCcConstants.TPM_CC_PolicyCommandCode =>
                (await tpm.PolicyCommandCodeAsync(policySessionProbe, TpmCcConstants.TPM_CC_NV_Read, cancellationToken).ConfigureAwait(false)).ResponseCode,
            TpmCcConstants.TPM_CC_PolicyAuthValue =>
                (await tpm.PolicyAuthValueAsync(policySessionProbe, cancellationToken).ConfigureAwait(false)).ResponseCode,
            TpmCcConstants.TPM_CC_PolicyGetDigest =>
                (await tpm.PolicyGetDigestAsync(policySessionProbe, cancellationToken).ConfigureAwait(false)).ResponseCode,
            TpmCcConstants.TPM_CC_PolicyPCR =>
                (await tpm.PolicyPcrAsync(policySessionProbe, TpmAlgIdConstants.TPM_ALG_SHA256, [0], default, cancellationToken).ConfigureAwait(false)).ResponseCode,
            TpmCcConstants.TPM_CC_PolicyOR =>
                (await tpm.PolicyOrAsync(policySessionProbe, [FixedDigest, FixedDigest], cancellationToken).ConfigureAwait(false)).ResponseCode,
            TpmCcConstants.TPM_CC_PolicyCounterTimer =>
                (await tpm.PolicyCounterTimerAsync(policySessionProbe, FixedDigest.AsMemory(0, 1), 0, TpmEoConstants.TPM_EO_EQ, cancellationToken).ConfigureAwait(false)).ResponseCode,
            TpmCcConstants.TPM_CC_PolicyPassword =>
                (await tpm.PolicyPasswordAsync(policySessionProbe, cancellationToken).ConfigureAwait(false)).ResponseCode,
            TpmCcConstants.TPM_CC_PolicyCpHash =>
                (await tpm.PolicyCpHashAsync(policySessionProbe, FixedDigest, cancellationToken).ConfigureAwait(false)).ResponseCode,
            TpmCcConstants.TPM_CC_PolicyNameHash =>
                (await tpm.PolicyNameHashAsync(policySessionProbe, FixedDigest, cancellationToken).ConfigureAwait(false)).ResponseCode,
            TpmCcConstants.TPM_CC_PolicyParameters =>
                (await tpm.PolicyParametersAsync(policySessionProbe, FixedDigest, cancellationToken).ConfigureAwait(false)).ResponseCode,
            TpmCcConstants.TPM_CC_PolicyTemplate =>
                (await tpm.PolicyTemplateAsync(policySessionProbe, FixedDigest, cancellationToken).ConfigureAwait(false)).ResponseCode,
            TpmCcConstants.TPM_CC_PolicyLocality =>
                (await tpm.PolicyLocalityAsync(policySessionProbe, TpmaLocality.TPM_LOC_ZERO, cancellationToken).ConfigureAwait(false)).ResponseCode,
            TpmCcConstants.TPM_CC_PolicyNvWritten =>
                (await tpm.PolicyNvWrittenAsync(policySessionProbe, isWrittenSet: true, cancellationToken).ConfigureAwait(false)).ResponseCode,
            TpmCcConstants.TPM_CC_PolicyDuplicationSelect =>
                (await tpm.PolicyDuplicationSelectAsync(policySessionProbe, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, isObjectIncluded: false, cancellationToken).ConfigureAwait(false)).ResponseCode,
            _ => throw new ArgumentOutOfRangeException(nameof(command), command, "Unhandled TPM2_Policy*() command in the handle-area probe framer."),
        };
    }

    /// <summary>
    /// Every <c>TPM2_Policy*()</c> command's <c>policySession</c> is its sole handle (index 0); a well-typed
    /// value naming no live policy session is a session in the handle area that is not present,
    /// <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0 Library Part 3, clause 5.4, step 2.4).
    /// </summary>
    /// <param name="command">The Policy command under test.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_PolicyCommandCode, DisplayName = "TPM2_PolicyCommandCode() policySession, index 0")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyAuthValue, DisplayName = "TPM2_PolicyAuthValue() policySession, index 0")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyGetDigest, DisplayName = "TPM2_PolicyGetDigest() policySession, index 0")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyPCR, DisplayName = "TPM2_PolicyPCR() policySession, index 0")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyOR, DisplayName = "TPM2_PolicyOR() policySession, index 0")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyCounterTimer, DisplayName = "TPM2_PolicyCounterTimer() policySession, index 0")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyPassword, DisplayName = "TPM2_PolicyPassword() policySession, index 0")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyCpHash, DisplayName = "TPM2_PolicyCpHash() policySession, index 0")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyNameHash, DisplayName = "TPM2_PolicyNameHash() policySession, index 0")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyParameters, DisplayName = "TPM2_PolicyParameters() policySession, index 0")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyTemplate, DisplayName = "TPM2_PolicyTemplate() policySession, index 0")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyLocality, DisplayName = "TPM2_PolicyLocality() policySession, index 0")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyNvWritten, DisplayName = "TPM2_PolicyNvWritten() policySession, index 0")]
    public async Task PolicySessionSlotUnloadedAnswersReferenceH0(TpmCcConstants command)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(PolicySessionSlotUnloadedAnswersReferenceH0)}-{command}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmRcConstants code = await SubmitPolicySessionSlotProbeAsync(tpm, command, UnloadedPolicySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_REFERENCE_H0, code,
            $"'{command}': policySession is the sole handle in the handle area (index 0); a well-typed value naming no loaded policy session is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.4).");
    }

    /// <summary>
    /// Every <c>TPM2_Policy*()</c> command's <c>policySession</c> is <c>TPMI_SH_POLICY</c> (TPM 2.0 Library
    /// Part 2, Table 56: <c>#TPM_RC_VALUE</c>, "error returned if the handle is out of range"); a value outside
    /// the policy-session range — an HMAC-range value or a transient-object-range value — is refused
    /// <c>TPM_RC_VALUE</c> at unmarshal, never reaching Part 3, clause 5.4's handle-area resolution at all.
    /// </summary>
    /// <param name="command">The Policy command under test.</param>
    /// <param name="probeHandle">The out-of-range value placed at the command's <c>policySession</c> slot.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_PolicyCommandCode, HmacRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyCommandCode() policySession, HMAC-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyCommandCode, ObjectRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyCommandCode() policySession, object-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyAuthValue, HmacRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyAuthValue() policySession, HMAC-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyAuthValue, ObjectRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyAuthValue() policySession, object-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyGetDigest, HmacRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyGetDigest() policySession, HMAC-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyGetDigest, ObjectRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyGetDigest() policySession, object-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyPCR, HmacRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyPCR() policySession, HMAC-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyPCR, ObjectRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyPCR() policySession, object-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyOR, HmacRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyOR() policySession, HMAC-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyOR, ObjectRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyOR() policySession, object-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyCounterTimer, HmacRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyCounterTimer() policySession, HMAC-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyCounterTimer, ObjectRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyCounterTimer() policySession, object-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyPassword, HmacRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyPassword() policySession, HMAC-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyPassword, ObjectRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyPassword() policySession, object-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyCpHash, HmacRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyCpHash() policySession, HMAC-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyCpHash, ObjectRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyCpHash() policySession, object-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyNameHash, HmacRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyNameHash() policySession, HMAC-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyNameHash, ObjectRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyNameHash() policySession, object-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyParameters, HmacRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyParameters() policySession, HMAC-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyParameters, ObjectRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyParameters() policySession, object-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyTemplate, HmacRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyTemplate() policySession, HMAC-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyTemplate, ObjectRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyTemplate() policySession, object-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyLocality, HmacRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyLocality() policySession, HMAC-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyLocality, ObjectRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyLocality() policySession, object-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyNvWritten, HmacRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyNvWritten() policySession, HMAC-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyNvWritten, ObjectRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyNvWritten() policySession, object-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyDuplicationSelect, HmacRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyDuplicationSelect() policySession, HMAC-range")]
    [DataRow(TpmCcConstants.TPM_CC_PolicyDuplicationSelect, ObjectRangeOutOfPolicyRange, DisplayName = "TPM2_PolicyDuplicationSelect() policySession, object-range")]
    public async Task PolicySessionSlotOutOfPolicyRangeAnswersValue(TpmCcConstants command, uint probeHandle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(PolicySessionSlotOutOfPolicyRangeAnswersValue)}-{command}-{probeHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmRcConstants code = await SubmitPolicySessionSlotProbeAsync(tpm, command, probeHandle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), code,
            $"'{command}': policySession is this command's sole handle, index 0; 0x{probeHandle:X8} is outside TPMI_SH_POLICY's own range, refused handle-encoded TPM_RC_VALUE at unmarshal (TPM 2.0 Library Part 2, Table 56) rather than reaching Part 3, clause 5.4's handle-area resolution.");
    }

    /// <summary>
    /// <c>TPM2_PolicySecret()</c>'s <c>authHandle</c> is its 1st handle (index 0); a transient-range value that
    /// resolves to no loaded object is <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0 Library Part 3, clause 5.4, step
    /// 2.1), and a well-typed but unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (step 2.2) —
    /// <c>policySession</c> is a genuinely started policy session throughout, so the index is proven from
    /// <c>authHandle</c>'s own position.
    /// </summary>
    /// <param name="probeAuthHandle">The value placed at <c>authHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, DisplayName = "TPM2_PolicySecret() authHandle, index 0, unresolved transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_PolicySecret() authHandle, index 0, persistent-range miss")]
    public async Task PolicySecretAuthHandleAtHandleAreaIndexZeroAnswersReferenceCodeOrHandle(uint probeAuthHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H1-encoded value from it — the reference warning stays
        //unencoded (Table 15's own N=0 case for a code that already carries no designation).
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(PolicySecretAuthHandleAtHandleAreaIndexZeroAnswersReferenceCodeOrHandle)}-{probeAuthHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");
        uint policySessionHandle;
        using(StartAuthSessionResponse started = startResult.Value)
        {
            policySessionHandle = started.SessionHandle.Value;
        }

        try
        {
            TpmResult<PolicySecretResponse> result = await tpm.PolicySecretWithPasswordAsync(probeAuthHandle, policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                expected, result.ResponseCode,
                "authHandle is TPM2_PolicySecret()'s 1st handle (index 0); an unresolved transient-range value is TPM_RC_REFERENCE_H0 and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, steps 2.1 and 2.2).");
        }
        finally
        {
            await tpm.FlushContextAsync(policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_PolicySecret()</c>'s <c>policySession</c> is its 2nd handle (index 1); a well-typed but unloaded
    /// value is <c>TPM_RC_REFERENCE_H1</c> (TPM 2.0 Library Part 3, clause 5.4, step 2.4), and a value outside
    /// <c>TPMI_SH_POLICY</c>'s own range is <c>TPM_RC_VALUE</c>, handle-encoded to the same index at unmarshal (TPM 2.0 Library Part 2, Table
    /// 56) — <c>authHandle</c> is <c>TPM_RH_ENDORSEMENT</c> throughout, a permanent handle needing no loading, so
    /// the index is proven from <c>policySession</c>'s own position.
    /// </summary>
    /// <param name="probePolicySession">The value placed at <c>policySession</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedPolicySessionHandle, TpmRcConstants.TPM_RC_REFERENCE_H1, DisplayName = "TPM2_PolicySecret() policySession, index 1, unloaded")]
    [DataRow(HmacRangeOutOfPolicyRange, TpmRcConstants.TPM_RC_VALUE, DisplayName = "TPM2_PolicySecret() policySession, index 1, out of range")]
    public async Task PolicySecretPolicySessionAtHandleAreaIndexOneAnswersReferenceH1OrValue(uint probePolicySession, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the out-of-range row carries the bare code and
        //this computes the actually-expected H1-encoded value from it — policySession is TPM2_PolicySecret()'s
        //second handle, index 1.
        if(expected == TpmRcConstants.TPM_RC_VALUE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 1);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(PolicySecretPolicySessionAtHandleAreaIndexOneAnswersReferenceH1OrValue)}-{probePolicySession:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<PolicySecretResponse> result = await tpm.PolicySecretWithPasswordAsync(
            (uint)TpmRh.TPM_RH_ENDORSEMENT, probePolicySession, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "policySession is TPM2_PolicySecret()'s 2nd handle (index 1); an unloaded but well-typed value is TPM_RC_REFERENCE_H1 (clause 5.4, step 2.4) and an out-of-range value is handle-encoded TPM_RC_VALUE at unmarshal (Part 2, Table 56).");
    }

    /// <summary>
    /// <c>TPM2_PolicySecret()</c>'s <c>authHandle</c>, RESOLVED to a genuinely loaded object that is not one of
    /// the four hierarchies, stays <c>TPM_RC_HANDLE</c>, handle-encoded to the same index — the standing modelling boundary this simulator
    /// implements: <c>authHandle</c>'s real wire type, <c>TPMI_DH_ENTITY+</c>, admits hierarchies, NV Indices,
    /// and ordinary transient/persistent objects, but this simulator resolves only the hierarchies, so a loaded
    /// non-hierarchy object at <c>authHandle</c> is refused exactly as an unsupported entity kind rather than
    /// promoted to the clause 5.4 step 2.1 warning a resolved, in-scope object never reaches.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretAuthHandleResolvedToALoadedObjectAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicySecretAuthHandleResolvedToALoadedObjectAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");
        uint policySessionHandle;
        using(StartAuthSessionResponse started = startResult.Value)
        {
            policySessionHandle = started.SessionHandle.Value;
        }

        try
        {
            TpmResult<PolicySecretResponse> result = await tpm.PolicySecretWithPasswordAsync(
                key.ObjectHandle.Value, policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
                "A loaded, non-hierarchy authHandle designates authHandle, handle 1 of TPM2_PolicySecret()'s own command table: this simulator resolves authHandle only for the permanent hierarchies, so a genuinely loaded object never reaches clause 5.4 step 2.1's warning.");
        }
        finally
        {
            await tpm.FlushContextAsync(policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_EventSequenceComplete()</c>'s <c>sequenceHandle</c> is its 2nd handle (index 1, Table 95:
    /// <c>pcrHandle</c> then <c>sequenceHandle</c>); a well-typed but unallocated PERSISTENT-range value is
    /// <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2) — structurally unreachable through a
    /// real event sequence (a hash/HMAC sequence is never persistent), but the persistent-range twin clause 5.4
    /// states uniformly for every transient-capable slot.
    /// </summary>
    [TestMethod]
    public async Task EventSequenceCompleteSequenceHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(EventSequenceCompleteSequenceHandlePersistentRangeMissAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using EventSequenceCompleteInput input = EventSequenceCompleteInput.Create(
            TpmiDhPcr.FromValue((uint)TpmRh.TPM_RH_NULL), TpmiDhObject.FromValue(UnallocatedPersistentHandle), ReadOnlySpan<byte>.Empty, pool);
        using TpmPasswordSession pcrAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession sequenceAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<EventSequenceCompleteResponse> result = await TpmCommandExecutor.ExecuteAsync<EventSequenceCompleteResponse>(
            tpm, input, [pcrAuth, sequenceAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), result.ResponseCode,
            "sequenceHandle is TPM2_EventSequenceComplete()'s 2nd handle (index 1); a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_Unseal()</c>'s <c>itemHandle</c> is its sole handle (index 0, Table 30) on the PLAIN wire form;
    /// an unloaded TRANSIENT-range value is <c>TPM_RC_REFERENCE_H0</c> (clause 5.4, step 2.1) and a well-typed
    /// but unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (step 2.2), the persistent-range
    /// twin no other test in the tree pins, rowed here on both outcomes.
    /// </summary>
    /// <param name="probeItemHandle">The value placed at <c>itemHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, DisplayName = "TPM2_Unseal() itemHandle, plain, index 0, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_Unseal() itemHandle, plain, index 0, persistent-range miss")]
    public async Task UnsealItemHandlePlainFormAnswersReferenceH0OrHandle(uint probeItemHandle, TpmRcConstants expected)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(UnsealItemHandlePlainFormAnswersReferenceH0OrHandle)}-{probeItemHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession itemAuth = TpmPasswordSession.CreateEmpty(pool);
        UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(probeItemHandle));

        TpmResult<UnsealResponse> result = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
            tpm, unsealInput, [itemAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        //DataRow arguments must be compile-time constants, so the persistent-range-miss row's bare constant is
        //transformed here to the value the table actually assigns: itemHandle is Unseal's sole handle (H1).
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(expected, 0);
        }

        Assert.AreEqual(
            expected, result.ResponseCode,
            "itemHandle is TPM2_Unseal()'s sole handle (index 0) on the PLAIN wire form; an unloaded TRANSIENT-range value is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated PERSISTENT-range value is handle-encoded TPM_RC_HANDLE (step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_Unseal()</c>'s <c>itemHandle</c> on the SESSIONS wire form (an empty-password companion beside
    /// the sole authorizing session): an unloaded TRANSIENT-range value is <c>TPM_RC_REFERENCE_H0</c> and an
    /// unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4,
    /// steps 2.1 and 2.2), the wire form no other test in the tree exercises for either outcome.
    /// </summary>
    /// <param name="probeItemHandle">The value placed at <c>itemHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, DisplayName = "TPM2_Unseal() itemHandle, sessions, index 0, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_Unseal() itemHandle, sessions, index 0, persistent-range miss")]
    public async Task UnsealItemHandleSessionsFormAnswersReferenceH0OrHandle(uint probeItemHandle, TpmRcConstants expected)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(UnsealItemHandleSessionsFormAnswersReferenceH0OrHandle)}-{probeItemHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession itemAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession companion = TpmPasswordSession.CreateEmpty(pool);
        UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(probeItemHandle));

        TpmResult<UnsealResponse> result = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
            tpm, unsealInput, [itemAuth, companion], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        //DataRow arguments must be compile-time constants; the persistent-range-miss row's bare constant is
        //transformed here to the value the table assigns: itemHandle is Unseal's sole handle (H1).
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(expected, 0);
        }

        Assert.AreEqual(
            expected, result.ResponseCode,
            "itemHandle is TPM2_Unseal()'s sole handle (index 0) on the SESSIONS wire form; an unloaded TRANSIENT-range value is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated PERSISTENT-range value is handle-encoded TPM_RC_HANDLE (step 2.2), the companion slot never reached.");
    }

    /// <summary>
    /// <c>TPM2_RSA_Decrypt()</c>'s <c>keyHandle</c> is its sole handle (index 0, Table 46) on the PLAIN wire
    /// form; a well-typed but unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0 Library
    /// Part 3, clause 5.4, step 2.2), the persistent-range twin no other test in the tree pins.
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptKeyHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalWithRsaBackendAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bPublicKeyRsa cipherText = Tpm2bPublicKeyRsa.Create(ReadOnlySpan<byte>.Empty, pool);
        var input = new RsaDecryptInput(TpmiDhObject.FromValue(UnallocatedPersistentHandle), cipherText, TpmtRsaDecrypt.Null, Tpm2bData.Empty);

        TpmResult<RsaDecryptResponse> result = await TpmCommandExecutor.ExecuteAsync<RsaDecryptResponse>(
            tpm, input, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "keyHandle is TPM2_RSA_Decrypt()'s sole handle (index 0) on the PLAIN wire form; a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_RSA_Decrypt()</c>'s <c>keyHandle</c> on the over-session (SESSIONS) wire form; an unloaded
    /// TRANSIENT-range value is <c>TPM_RC_REFERENCE_H0</c> and a PERSISTENT-range miss keeps
    /// <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, steps 2.1 and 2.2), the wire form no other
    /// test in the tree exercises for either outcome.
    /// </summary>
    /// <param name="probeKeyHandle">The value placed at <c>keyHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, DisplayName = "TPM2_RSA_Decrypt() keyHandle, sessions, index 0, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_RSA_Decrypt() keyHandle, sessions, index 0, persistent-range miss")]
    public async Task RsaDecryptKeyHandleOverSessionAnswersReferenceH0OrHandle(uint probeKeyHandle, TpmRcConstants expected)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalWithRsaBackendAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession companion = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bPublicKeyRsa cipherText = Tpm2bPublicKeyRsa.Create(ReadOnlySpan<byte>.Empty, pool);
        var input = new RsaDecryptInput(TpmiDhObject.FromValue(probeKeyHandle), cipherText, TpmtRsaDecrypt.Null, Tpm2bData.Empty);

        TpmResult<RsaDecryptResponse> result = await TpmCommandExecutor.ExecuteAsync<RsaDecryptResponse>(
            tpm, input, [keyAuth, companion], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        //DataRow arguments must be compile-time constants; the persistent-range-miss row's bare constant is
        //transformed here to the value the table assigns: keyHandle is RSA_Decrypt's sole handle (H1).
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(expected, 0);
        }

        Assert.AreEqual(
            expected, result.ResponseCode,
            "keyHandle is TPM2_RSA_Decrypt()'s sole handle (index 0) on the over-session wire form; an unloaded TRANSIENT-range value is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated PERSISTENT-range value is handle-encoded TPM_RC_HANDLE (step 2.2), the companion slot never reached.");
    }

    /// <summary>
    /// <c>TPM2_Decapsulate()</c>'s <c>keyHandle</c> is its sole handle (index 0, Table 62); an unloaded
    /// TRANSIENT-range value is <c>TPM_RC_REFERENCE_H0</c> and a PERSISTENT-range miss keeps
    /// <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, steps 2.1 and 2.2), neither outcome pinned
    /// by any other test in the tree.
    /// </summary>
    /// <param name="probeKeyHandle">The value placed at <c>keyHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, DisplayName = "TPM2_Decapsulate() keyHandle, index 0, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_Decapsulate() keyHandle, index 0, persistent-range miss")]
    public async Task DecapsulateKeyHandleAnswersReferenceH0OrHandle(uint probeKeyHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(DecapsulateKeyHandleAnswersReferenceH0OrHandle)}-{probeKeyHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using DecapsulateInput input = DecapsulateInput.Create(TpmiDhObject.FromValue(probeKeyHandle), ReadOnlySpan<byte>.Empty, pool);

        TpmResult<DecapsulateResponse> result = await TpmCommandExecutor.ExecuteAsync<DecapsulateResponse>(
            tpm, input, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "keyHandle is TPM2_Decapsulate()'s sole handle (index 0); an unloaded TRANSIENT-range value is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_ObjectChangeAuth()</c>'s <c>objectHandle</c> is the 1st handle (index 0, Table 32); an unloaded
    /// TRANSIENT-range value is <c>TPM_RC_REFERENCE_H0</c> (already proven, in its own class) and a
    /// PERSISTENT-range miss keeps <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2), the
    /// persistent-range twin no other test in the tree pins. <c>parentHandle</c> holds a genuinely loaded
    /// storage parent throughout, so the index is proven from <c>objectHandle</c>'s own position.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthObjectHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(ObjectChangeAuthObjectHandlePersistentRangeMissAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth newAuth = Tpm2bAuth.CreateEmpty(pool);
        var input = new ObjectChangeAuthInput(TpmiDhObject.FromValue(UnallocatedPersistentHandle), parent.ObjectHandle, newAuth);

        TpmResult<ObjectChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<ObjectChangeAuthResponse>(
            tpm, input, [objectAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "objectHandle is TPM2_ObjectChangeAuth()'s 1st handle (index 0); a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_ObjectChangeAuth()</c>'s <c>parentHandle</c> is the 2nd handle (index 1, Table 32); an unloaded
    /// TRANSIENT-range value is <c>TPM_RC_REFERENCE_H1</c> (already proven, in its own class) and a
    /// PERSISTENT-range miss keeps <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2), the
    /// persistent-range twin no other test in the tree pins. <c>objectHandle</c> holds a genuinely loaded
    /// object throughout.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthParentHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(ObjectChangeAuthParentHandlePersistentRangeMissAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmPasswordSession parentParentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256,
            isSensitiveDataOrigin: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (HMAC key) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;
        TpmResult<LoadResponse> loadResult = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, created.OutPrivate, created.OutPublic, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (HMAC key) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth newAuth = Tpm2bAuth.CreateEmpty(pool);
        var input = new ObjectChangeAuthInput(loaded.ObjectHandle, TpmiDhObject.FromValue(UnallocatedPersistentHandle), newAuth);

        TpmResult<ObjectChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<ObjectChangeAuthResponse>(
            tpm, input, [objectAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), result.ResponseCode,
            "parentHandle is TPM2_ObjectChangeAuth()'s 2nd handle (index 1); a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_SequenceUpdate()</c>'s <c>sequenceHandle</c> is its sole handle (index 0, Table 91) on the PLAIN
    /// wire form; a well-typed but unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0
    /// Library Part 3, clause 5.4, step 2.2), structurally unreachable through a real sequence (never
    /// persistent) but the persistent twin clause 5.4 states uniformly for every transient-capable slot.
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateSequenceHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateSequenceHandlePersistentRangeMissAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession sequenceAuth = TpmPasswordSession.CreateEmpty(pool);
        using SequenceUpdateInput input = SequenceUpdateInput.Create(TpmiDhObject.FromValue(UnallocatedPersistentHandle), ReadOnlySpan<byte>.Empty, pool);

        TpmResult<SequenceUpdateResponse> result = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
            tpm, input, [sequenceAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "sequenceHandle is TPM2_SequenceUpdate()'s sole handle (index 0); a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_SequenceUpdate()</c>'s <c>sequenceHandle</c> on the over-session (SESSIONS) wire form; the
    /// persistent-range twin of the PLAIN-form proof above.
    /// </summary>
    [TestMethod]
    public async Task SequenceUpdateSequenceHandlePersistentRangeMissAnswersHandleOverSession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceUpdateSequenceHandlePersistentRangeMissAnswersHandleOverSession), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession sequenceAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession companion = TpmPasswordSession.CreateEmpty(pool);
        using SequenceUpdateInput input = SequenceUpdateInput.Create(TpmiDhObject.FromValue(UnallocatedPersistentHandle), ReadOnlySpan<byte>.Empty, pool);

        TpmResult<SequenceUpdateResponse> result = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
            tpm, input, [sequenceAuth, companion], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "sequenceHandle is TPM2_SequenceUpdate()'s sole handle (index 0) on the over-session wire form; a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2), the companion slot never reached.");
    }

    /// <summary>
    /// <c>TPM2_SequenceComplete()</c>'s <c>sequenceHandle</c> is its sole handle (index 0, Table 93); a
    /// well-typed but unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0 Library Part 3,
    /// clause 5.4, step 2.2).
    /// </summary>
    [TestMethod]
    public async Task SequenceCompleteSequenceHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SequenceCompleteSequenceHandlePersistentRangeMissAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession sequenceAuth = TpmPasswordSession.CreateEmpty(pool);
        using SequenceCompleteInput input = SequenceCompleteInput.Create(TpmiDhObject.FromValue(UnallocatedPersistentHandle), ReadOnlySpan<byte>.Empty, TpmiRhHierarchy.Null, pool);

        TpmResult<SequenceCompleteResponse> result = await TpmCommandExecutor.ExecuteAsync<SequenceCompleteResponse>(
            tpm, input, [sequenceAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "sequenceHandle is TPM2_SequenceComplete()'s sole handle (index 0); a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_SignSequenceComplete()</c>'s <c>sequenceHandle</c> is its 1st handle (index 0, Table 124) on the
    /// PLAIN wire form; a well-typed but unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM
    /// 2.0 Library Part 3, clause 5.4, step 2.2). <c>keyHandle</c> holds a genuinely loaded signing key
    /// throughout.
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteSequenceHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SignSequenceCompleteSequenceHandlePersistentRangeMissAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmPasswordSession sequenceAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(
            TpmiDhObject.FromValue(UnallocatedPersistentHandle), signer.ObjectHandle, ReadOnlySpan<byte>.Empty, pool);

        TpmResult<SignSequenceCompleteResponse> result = await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
            tpm, input, [sequenceAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "sequenceHandle is TPM2_SignSequenceComplete()'s 1st handle (index 0); a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_SignSequenceComplete()</c>'s <c>sequenceHandle</c> on the over-session (SESSIONS) wire form; the
    /// persistent-range twin of the PLAIN-form proof above.
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteSequenceHandlePersistentRangeMissAnswersHandleOverSession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SignSequenceCompleteSequenceHandlePersistentRangeMissAnswersHandleOverSession), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmPasswordSession sequenceAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession companion = TpmPasswordSession.CreateEmpty(pool);
        using SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(
            TpmiDhObject.FromValue(UnallocatedPersistentHandle), signer.ObjectHandle, ReadOnlySpan<byte>.Empty, pool);

        TpmResult<SignSequenceCompleteResponse> result = await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
            tpm, input, [sequenceAuth, keyAuth, companion], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "sequenceHandle is TPM2_SignSequenceComplete()'s 1st handle (index 0) on the over-session wire form; a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2), the companion slot never reached.");
    }

    /// <summary>
    /// <c>TPM2_SignSequenceComplete()</c>'s <c>sequenceHandle</c>, RESOLVED to a genuinely loaded signing key
    /// rather than a sequence, is refused with handle-encoded <c>TPM_RC_MODE</c> at index 0 (TPM 2.0 Library
    /// Part 2, clause 6.6.2, Table 16's one-based N field): Part 3, clause 20.6 itself names no override of its own for
    /// this exact case, but the family's wrong-KIND rule — Part 3, clause 17.8.1 / 17.9.1's <c>TPM_RC_MODE</c>,
    /// generalized to every non-sequence kind, and the reference code's <c>ObjectIsSequence</c> check — applies
    /// here too. No test elsewhere in the tree pins this wrong-kind branch for this command.
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOnALoadedKeyHandleAnswersMode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SignSequenceCompleteOnALoadedKeyHandleAnswersMode), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmPasswordSession sequenceAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(
            signer.ObjectHandle, signer.ObjectHandle, ReadOnlySpan<byte>.Empty, pool);

        TpmResult<SignSequenceCompleteResponse> result = await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
            tpm, input, [sequenceAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_MODE, handleIndex: 0), result.ResponseCode,
            "sequenceHandle resolved to a loaded signing key rather than a sequence is refused with TPM_RC_MODE handle-encoded to index 0 (TPM 2.0 Library Part 2, clause 6.6.2, Table 16): Part 3, clause 20.6 names no override of its own for this exact case.");
    }

    /// <summary>
    /// <c>TPM2_VerifySequenceComplete()</c>'s <c>sequenceHandle</c> is its 1st handle (index 0, Table 118) on
    /// the PLAIN wire form; a well-typed but unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index
    /// (TPM 2.0 Library Part 3, clause 5.4, step 2.2).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteSequenceHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(VerifySequenceCompleteSequenceHandlePersistentRangeMissAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmPasswordSession sequenceAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            TpmiDhObject.FromValue(UnallocatedPersistentHandle), signer.ObjectHandle, FixedDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<VerifySequenceCompleteResponse> result = await TpmCommandExecutor.ExecuteAsync<VerifySequenceCompleteResponse>(
            tpm, input, [sequenceAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "sequenceHandle is TPM2_VerifySequenceComplete()'s 1st handle (index 0); a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_VerifySequenceComplete()</c>'s <c>sequenceHandle</c> on the over-session (SESSIONS) wire form;
    /// the persistent-range twin of the PLAIN-form proof above.
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteSequenceHandlePersistentRangeMissAnswersHandleOverSession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(VerifySequenceCompleteSequenceHandlePersistentRangeMissAnswersHandleOverSession), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmPasswordSession sequenceAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession companion = TpmPasswordSession.CreateEmpty(pool);
        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            TpmiDhObject.FromValue(UnallocatedPersistentHandle), signer.ObjectHandle, FixedDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<VerifySequenceCompleteResponse> result = await TpmCommandExecutor.ExecuteAsync<VerifySequenceCompleteResponse>(
            tpm, input, [sequenceAuth, keyAuth, companion], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "sequenceHandle is TPM2_VerifySequenceComplete()'s 1st handle (index 0) on the over-session wire form; a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2), the companion slot never reached.");
    }

    /// <summary>
    /// <c>TPM2_VerifySequenceComplete()</c>'s <c>sequenceHandle</c>, RESOLVED to a genuinely loaded signing key
    /// rather than a sequence, is refused with handle-encoded <c>TPM_RC_MODE</c> at index 0 (TPM 2.0 Library
    /// Part 2, clause 6.6.2, Table 16's one-based N field): Part 3, clause 20.3 itself names no override of its own for
    /// this exact case, but the family's wrong-KIND rule — Part 3, clause 17.8.1 / 17.9.1's <c>TPM_RC_MODE</c>,
    /// generalized to every non-sequence kind, and the reference code's <c>ObjectIsSequence</c> check — applies
    /// here too. No test elsewhere in the tree pins this wrong-kind branch for this command.
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteOnALoadedKeyHandleAnswersMode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(VerifySequenceCompleteOnALoadedKeyHandleAnswersMode), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmPasswordSession sequenceAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.ForEcdsa(
            signer.ObjectHandle, signer.ObjectHandle, FixedDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<VerifySequenceCompleteResponse> result = await TpmCommandExecutor.ExecuteAsync<VerifySequenceCompleteResponse>(
            tpm, input, [sequenceAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_MODE, handleIndex: 0), result.ResponseCode,
            "sequenceHandle resolved to a loaded signing key rather than a sequence is refused with TPM_RC_MODE handle-encoded to index 0 (TPM 2.0 Library Part 2, clause 6.6.2, Table 16): Part 3, clause 20.3 names no override of its own for this exact case.");
    }

    /// <summary>
    /// <c>TPM2_Certify()</c>'s <c>objectHandle</c> is the 1st handle in the handle area (index 0); a well-typed
    /// but unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index, the twin of the transient miss's
    /// <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0 Library Part 3, clause 5.4, step 2.2) — <c>signHandle</c> holds a
    /// genuinely loaded key throughout, so the index is proven from <c>objectHandle</c>'s own position.
    /// </summary>
    [TestMethod]
    public async Task CertifyObjectHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(CertifyObjectHandlePersistentRangeMissAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput certifyInput = CertifyInput.ForEcdsa(
            TpmiDhObject.FromValue(UnallocatedPersistentHandle), signer.ObjectHandle, QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "objectHandle is TPM2_Certify()'s 1st handle (index 0); a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_Certify()</c>'s <c>signHandle</c> is the 2nd handle in the handle area (index 1); a well-typed but
    /// unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step
    /// 2.2) — <c>objectHandle</c> holds a genuinely loaded object throughout, so the index is proven from
    /// <c>signHandle</c>'s own position.
    /// </summary>
    [TestMethod]
    public async Task CertifySignHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(CertifySignHandlePersistentRangeMissAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput certifyInput = CertifyInput.ForEcdsa(
            subject.ObjectHandle, TpmiDhObject.FromValue(UnallocatedPersistentHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), result.ResponseCode,
            "signHandle is TPM2_Certify()'s 2nd handle (index 1); a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_CertifyCreation()</c>'s <c>signHandle</c> is the 1st handle in the handle area (index 0); a
    /// well-typed but unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0 Library Part 3,
    /// clause 5.4, step 2.2) — <c>objectHandle</c>, <c>creationHash</c> and <c>creationTicket</c> all come from a
    /// genuinely loaded object's own CreatePrimary response, so the index is proven from <c>signHandle</c>'s own
    /// position.
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationSignHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(CertifyCreationSignHandlePersistentRangeMissAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
            TpmiDhObject.FromValue(UnallocatedPersistentHandle), subject.ObjectHandle, QualifyingData,
            subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, certifyCreationInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "signHandle is TPM2_CertifyCreation()'s 1st handle (index 0); a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_Quote()</c>'s <c>signHandle</c> is its sole handle (index 0); a well-typed but unallocated
    /// PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).
    /// </summary>
    [TestMethod]
    public async Task QuoteSignHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(QuoteSignHandlePersistentRangeMissAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(TpmAlgIdConstants.TPM_ALG_SHA256, [0], pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using QuoteInput quoteInput = QuoteInput.ForEcdsa(
            TpmiDhObject.FromValue(UnallocatedPersistentHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

        TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "signHandle is TPM2_Quote()'s sole handle (index 0); a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_GetTime()</c>'s <c>signHandle</c> is the 2nd handle in the handle area (index 1, after the
    /// out-of-scope hierarchy <c>privacyAdminHandle</c>); a well-typed but unallocated PERSISTENT-range value is
    /// <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).
    /// </summary>
    [TestMethod]
    public async Task GetTimeSignHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(GetTimeSignHandlePersistentRangeMissAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(
            TpmiDhObject.FromValue(UnallocatedPersistentHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
            tpm, getTimeInput, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), result.ResponseCode,
            "signHandle is TPM2_GetTime()'s 2nd handle (index 1); a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_Sign()</c>'s <c>keyHandle</c> is its sole handle (index 0); a well-typed but unallocated
    /// PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).
    /// </summary>
    [TestMethod]
    public async Task SignKeyHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SignKeyHandlePersistentRangeMissAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(TpmiDhObject.FromValue(UnallocatedPersistentHandle), FixedDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<SignResponse> result = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "keyHandle is TPM2_Sign()'s sole handle (index 0); a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_Load()</c>'s <c>parentHandle</c> is its sole handle (index 0); a well-typed but unallocated
    /// PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2) —
    /// <c>inPrivate</c>/<c>inPublic</c> are a genuine wrapped object from a real create, so the refusal is
    /// proven against real parse-rented carriers, not a degenerate empty pair.
    /// </summary>
    [TestMethod]
    public async Task LoadParentHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(LoadParentHandlePersistentRangeMissAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256,
            isSensitiveDataOrigin: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (HMAC key) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        TpmResult<LoadResponse> result = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, UnallocatedPersistentHandle, created.OutPrivate, created.OutPublic, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "parentHandle is TPM2_Load()'s sole handle (index 0); a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_ActivateCredential()</c>'s <c>activateHandle</c> is the 1st handle in the handle area (index 0); a
    /// well-typed but unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0 Library Part 3,
    /// clause 5.4, step 2.2) — <c>keyHandle</c> holds a genuinely loaded key throughout, so the index is proven
    /// from <c>activateHandle</c>'s own position.
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialActivateHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(ActivateCredentialActivateHandlePersistentRangeMissAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
            TpmiDhObject.FromValue(UnallocatedPersistentHandle), key.ObjectHandle, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, pool);

        TpmResult<ActivateCredentialResponse> result = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
            tpm, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "activateHandle is TPM2_ActivateCredential()'s 1st handle (index 0); a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_ActivateCredential()</c>'s <c>keyHandle</c> is the 2nd handle in the handle area (index 1); an
    /// unloaded TRANSIENT-range value is <c>TPM_RC_REFERENCE_H1</c> (TPM 2.0 Library Part 3, clause 5.4, step
    /// 2.1) and a well-typed but unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (step 2.2) —
    /// <c>activateHandle</c> holds a genuinely loaded object throughout, so the index is proven from
    /// <c>keyHandle</c>'s own position.
    /// </summary>
    /// <param name="probeKeyHandle">The value placed at <c>keyHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H1, DisplayName = "TPM2_ActivateCredential() keyHandle, index 1, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_ActivateCredential() keyHandle, index 1, persistent-range miss")]
    public async Task ActivateCredentialKeyHandleAtHandleAreaIndexOneAnswersReferenceH1OrHandle(uint probeKeyHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(ActivateCredentialKeyHandleAtHandleAreaIndexOneAnswersReferenceH1OrHandle)}-{probeKeyHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse activateObject = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
            activateObject.ObjectHandle, TpmiDhObject.FromValue(probeKeyHandle), ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, pool);

        TpmResult<ActivateCredentialResponse> result = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
            tpm, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "keyHandle is TPM2_ActivateCredential()'s 2nd handle (index 1); an unloaded transient-range value is TPM_RC_REFERENCE_H1 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_CertifyCreation()</c>'s <c>objectHandle</c> is the 2nd handle in the handle area (index 1); an
    /// unloaded TRANSIENT-range value is <c>TPM_RC_REFERENCE_H1</c> (TPM 2.0 Library Part 3, clause 5.4, step
    /// 2.1) and a well-typed but unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (step 2.2) —
    /// <c>signHandle</c> holds a genuinely loaded signing key throughout, so the index is proven from
    /// <c>objectHandle</c>'s own position.
    /// </summary>
    /// <param name="probeObjectHandle">The value placed at <c>objectHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H1, DisplayName = "TPM2_CertifyCreation() objectHandle, index 1, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_CertifyCreation() objectHandle, index 1, persistent-range miss")]
    public async Task CertifyCreationObjectHandleAtHandleAreaIndexOneAnswersReferenceH1OrHandle(uint probeObjectHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(CertifyCreationObjectHandleAtHandleAreaIndexOneAnswersReferenceH1OrHandle)}-{probeObjectHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
            subject.ObjectHandle, TpmiDhObject.FromValue(probeObjectHandle), QualifyingData,
            subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, certifyCreationInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "objectHandle is TPM2_CertifyCreation()'s 2nd handle (index 1); an unloaded transient-range value is TPM_RC_REFERENCE_H1 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_NV_Certify()</c>'s <c>signHandle</c> is the 1st handle in the handle area (index 0); a well-typed
    /// but unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4,
    /// step 2.2). <c>authHandle</c> (the owner hierarchy) and <c>nvIndex</c> name a genuinely DEFINED,
    /// owner-readable Index, so the handle-encoded <c>TPM_RC_HANDLE</c> this row asserts is attributable to
    /// <c>signHandle</c>'s own persistent-range miss and not to an undefined-Index arm answering the identical
    /// code (clause 5.4, step 2.3.1) — a placeholder <c>nvIndex</c> could not tell the two apart.
    /// </summary>
    [TestMethod]
    public async Task NvCertifySignHandlePersistentRangeMissAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(NvCertifySignHandlePersistentRangeMissAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await PolicySweepHarness.DefineOwnerReadableIndexAsync(tpm, registry, pool, SampleNvIndex, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.CreateEmpty(pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            TpmiDhObject.FromValue(UnallocatedPersistentHandle), authHandle: (uint)TpmRh.TPM_RH_OWNER, nvIndex: SampleNvIndex, QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, size: 0, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "signHandle is TPM2_NV_Certify()'s 1st handle (index 0); a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2), reachable only because authHandle and nvIndex both resolve to a genuinely defined Index.");
    }

    /// <summary>
    /// <c>TPM2_Certify()</c>'s <c>objectHandle</c> is the 1st handle (index 0) on the SESSIONS wire form (a
    /// three-block authorization area — Part 1, clause 15.6.1 admits up to three — with an empty-password companion at
    /// index 2 rather than the object/sign sessions alone): the refusal precedes Part 3, clause 5.5's session judgment,
    /// so an empty-password companion suffices to prove the identical ternary the PLAIN form already proves.
    /// </summary>
    /// <param name="probeObjectHandle">The value placed at <c>objectHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, DisplayName = "TPM2_Certify() objectHandle, sessions, index 0, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_Certify() objectHandle, sessions, index 0, persistent-range miss")]
    public async Task CertifyObjectHandleSessionsFormAnswersReferenceH0OrHandle(uint probeObjectHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(CertifyObjectHandleSessionsFormAnswersReferenceH0OrHandle)}-{probeObjectHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession companion = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput certifyInput = CertifyInput.ForEcdsa(
            TpmiDhObject.FromValue(probeObjectHandle), signer.ObjectHandle, QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth, companion], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "objectHandle is TPM2_Certify()'s 1st handle (index 0) on the SESSIONS wire form; an unloaded transient-range value is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2), a three-block authorization area's companion slot never reached.");
    }

    /// <summary>
    /// <c>TPM2_Certify()</c>'s <c>signHandle</c> is the 2nd handle (index 1) on the SESSIONS wire form, the
    /// same three-block area <see cref="CertifyObjectHandleSessionsFormAnswersReferenceH0OrHandle"/> uses.
    /// </summary>
    /// <param name="probeSignHandle">The value placed at <c>signHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H1, DisplayName = "TPM2_Certify() signHandle, sessions, index 1, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_Certify() signHandle, sessions, index 1, persistent-range miss")]
    public async Task CertifySignHandleSessionsFormAnswersReferenceH1OrHandle(uint probeSignHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(CertifySignHandleSessionsFormAnswersReferenceH1OrHandle)}-{probeSignHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession companion = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput certifyInput = CertifyInput.ForEcdsa(
            subject.ObjectHandle, TpmiDhObject.FromValue(probeSignHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth, companion], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "signHandle is TPM2_Certify()'s 2nd handle (index 1) on the SESSIONS wire form; an unloaded transient-range value is TPM_RC_REFERENCE_H1 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2), a three-block authorization area's companion slot never reached.");
    }

    /// <summary>
    /// <c>TPM2_CertifyCreation()</c>'s <c>signHandle</c> is the 1st handle (index 0) on the SESSIONS wire form
    /// (a companion at index 1 beside the sole authorizing session): the refusal precedes clause 5.5, so an
    /// empty-password companion suffices.
    /// </summary>
    /// <param name="probeSignHandle">The value placed at <c>signHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, DisplayName = "TPM2_CertifyCreation() signHandle, sessions, index 0, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_CertifyCreation() signHandle, sessions, index 0, persistent-range miss")]
    public async Task CertifyCreationSignHandleSessionsFormAnswersReferenceH0OrHandle(uint probeSignHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(CertifyCreationSignHandleSessionsFormAnswersReferenceH0OrHandle)}-{probeSignHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession companion = TpmPasswordSession.CreateEmpty(pool);
        using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
            TpmiDhObject.FromValue(probeSignHandle), subject.ObjectHandle, QualifyingData,
            subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, certifyCreationInput, [signAuth, companion], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "signHandle is TPM2_CertifyCreation()'s 1st handle (index 0) on the SESSIONS wire form; an unloaded transient-range value is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2), the companion slot never reached.");
    }

    /// <summary>
    /// <c>TPM2_CertifyCreation()</c>'s <c>objectHandle</c> is the 2nd handle (index 1) on the SESSIONS wire
    /// form, the same companion-carrying area <see cref="CertifyCreationSignHandleSessionsFormAnswersReferenceH0OrHandle"/> uses.
    /// </summary>
    /// <param name="probeObjectHandle">The value placed at <c>objectHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H1, DisplayName = "TPM2_CertifyCreation() objectHandle, sessions, index 1, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_CertifyCreation() objectHandle, sessions, index 1, persistent-range miss")]
    public async Task CertifyCreationObjectHandleSessionsFormAnswersReferenceH1OrHandle(uint probeObjectHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(CertifyCreationObjectHandleSessionsFormAnswersReferenceH1OrHandle)}-{probeObjectHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession companion = TpmPasswordSession.CreateEmpty(pool);
        using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
            subject.ObjectHandle, TpmiDhObject.FromValue(probeObjectHandle), QualifyingData,
            subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, certifyCreationInput, [signAuth, companion], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "objectHandle is TPM2_CertifyCreation()'s 2nd handle (index 1) on the SESSIONS wire form; an unloaded transient-range value is TPM_RC_REFERENCE_H1 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2), the companion slot never reached.");
    }

    /// <summary>
    /// <c>TPM2_GetTime()</c>'s <c>signHandle</c> is the 2nd handle (index 1) on the SESSIONS wire form (a
    /// third, empty-password companion beside the privacyAdminHandle and signHandle sessions): the refusal
    /// precedes clause 5.5, so an empty-password companion suffices.
    /// </summary>
    /// <param name="probeSignHandle">The value placed at <c>signHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H1, DisplayName = "TPM2_GetTime() signHandle, sessions, index 1, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_GetTime() signHandle, sessions, index 1, persistent-range miss")]
    public async Task GetTimeSignHandleSessionsFormAnswersReferenceH1OrHandle(uint probeSignHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(GetTimeSignHandleSessionsFormAnswersReferenceH1OrHandle)}-{probeSignHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession companion = TpmPasswordSession.CreateEmpty(pool);
        using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(
            TpmiDhObject.FromValue(probeSignHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
            tpm, getTimeInput, [privacyAdminAuth, signAuth, companion], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "signHandle is TPM2_GetTime()'s 2nd handle (index 1) on the SESSIONS wire form; an unloaded transient-range value is TPM_RC_REFERENCE_H1 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2), the companion slot never reached.");
    }

    /// <summary>
    /// <c>TPM2_NV_Certify()</c>'s <c>signHandle</c> is the 1st handle (index 0) on the SESSIONS wire form (a
    /// third, empty-password companion beside signHandle and authHandle's own sessions): the refusal precedes
    /// clause 5.5, so an empty-password companion suffices. <c>authHandle</c> (the owner hierarchy) and
    /// <c>nvIndex</c> name a genuinely DEFINED, owner-readable Index, so the code is attributable to
    /// <c>signHandle</c>'s own miss.
    /// </summary>
    /// <param name="probeSignHandle">The value placed at <c>signHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, DisplayName = "TPM2_NV_Certify() signHandle, sessions, index 0, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_NV_Certify() signHandle, sessions, index 0, persistent-range miss")]
    public async Task NvCertifySignHandleSessionsFormAnswersReferenceH0OrHandle(uint probeSignHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H1-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(NvCertifySignHandleSessionsFormAnswersReferenceH0OrHandle)}-{probeSignHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await PolicySweepHarness.DefineOwnerReadableIndexAsync(tpm, registry, pool, SampleNvIndex, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession companion = TpmPasswordSession.CreateEmpty(pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            TpmiDhObject.FromValue(probeSignHandle), authHandle: (uint)TpmRh.TPM_RH_OWNER, nvIndex: SampleNvIndex, QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, size: 0, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth, companion], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "signHandle is TPM2_NV_Certify()'s 1st handle (index 0) on the SESSIONS wire form; an unloaded transient-range value is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2), reachable only because authHandle and nvIndex both resolve to a genuinely defined Index, the companion slot never reached.");
    }

    /// <summary>
    /// <c>TPM2_Quote()</c>'s <c>signHandle</c> is its sole handle (index 0) on the SESSIONS wire form (an
    /// empty-password companion at index 1 beside the sole authorizing session): the persistent-range twin
    /// of <see cref="QuoteSignHandlePersistentRangeMissAnswersHandle"/>, proving the PLAIN-form ternary holds
    /// unchanged when a companion slot is present, since the refusal precedes clause 5.5.
    /// </summary>
    [TestMethod]
    public async Task QuoteSignHandlePersistentRangeMissAnswersHandleOverTheSessionsForm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(QuoteSignHandlePersistentRangeMissAnswersHandleOverTheSessionsForm), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(TpmAlgIdConstants.TPM_ALG_SHA256, [0], pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession companion = TpmPasswordSession.CreateEmpty(pool);
        using QuoteInput quoteInput = QuoteInput.ForEcdsa(
            TpmiDhObject.FromValue(UnallocatedPersistentHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

        TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [keyAuth, companion], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "signHandle is TPM2_Quote()'s sole handle (index 0) on the SESSIONS wire form; a well-typed but unallocated PERSISTENT-range value is TPM_RC_HANDLE, handle-encoded to the same index (TPM 2.0 Library Part 3, clause 5.4, step 2.2), the companion slot never reached.");
    }

    /// <summary>
    /// Starts a genuine, unbound HMAC session claiming <c>audit</c> — the shape
    /// <c>TPM2_GetSessionAuditDigest()</c>'s own <c>sessionHandle</c> (index 2) names — through the production
    /// path, leaving it open for the caller to name at that slot. <c>sessionHandle</c> carries no
    /// authorization of its own (Auth Index None), so the session need not be exercised, only started.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The started session's raw handle value.</returns>
    private static async Task<uint> StartAuditSessionHandleAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants.TPM_ALG_SHA256, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (audit sessionHandle slot) failed: '{startResult.ResponseCode}'.");

        return startResult.Value.SessionHandle.Value;
    }

    /// <summary>
    /// <c>TPM2_GetSessionAuditDigest()</c>'s <c>signHandle</c> is the 2nd handle (index 1, Table 103:
    /// privacyAdminHandle 0, signHandle 1, sessionHandle 2); <c>privacyAdminHandle</c> is
    /// <c>TPM_RH_ENDORSEMENT</c>, a permanent handle needing no loading, and <c>sessionHandle</c> names a
    /// genuinely started (but unauthorized, Auth Index None) audit session, so the index is proven from
    /// <c>signHandle</c>'s own position.
    /// </summary>
    /// <param name="probeSignHandle">The value placed at <c>signHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H1, DisplayName = "TPM2_GetSessionAuditDigest() signHandle, index 1, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_GetSessionAuditDigest() signHandle, index 1, persistent-range miss")]
    public async Task GetSessionAuditDigestSignHandleAtHandleAreaIndexOneAnswersReferenceH1OrHandle(uint probeSignHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(GetSessionAuditDigestSignHandleAtHandleAreaIndexOneAnswersReferenceH1OrHandle)}-{probeSignHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartAuditSessionHandleAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        try
        {
            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
                TpmiDhObject.FromValue(probeSignHandle), TpmiShHmac.FromValue(sessionHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

            TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                expected, result.ResponseCode,
                "signHandle is TPM2_GetSessionAuditDigest()'s 2nd handle (index 1); an unloaded transient-range value is TPM_RC_REFERENCE_H1 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2).");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_GetSessionAuditDigest()</c>'s <c>signHandle</c> is the 2nd handle (index 1) on the SESSIONS
    /// wire form (a fourth, empty-password companion beside privacyAdminHandle's and signHandle's own
    /// sessions): the refusal precedes clause 5.5, so an empty-password companion suffices.
    /// </summary>
    /// <param name="probeSignHandle">The value placed at <c>signHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H1, DisplayName = "TPM2_GetSessionAuditDigest() signHandle, sessions, index 1, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_GetSessionAuditDigest() signHandle, sessions, index 1, persistent-range miss")]
    public async Task GetSessionAuditDigestSignHandleSessionsFormAnswersReferenceH1OrHandle(uint probeSignHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(GetSessionAuditDigestSignHandleSessionsFormAnswersReferenceH1OrHandle)}-{probeSignHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartAuditSessionHandleAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        try
        {
            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession companion = TpmPasswordSession.CreateEmpty(pool);
            using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
                TpmiDhObject.FromValue(probeSignHandle), TpmiShHmac.FromValue(sessionHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

            TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                tpm, input, [privacyAdminAuth, signAuth, companion], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                expected, result.ResponseCode,
                "signHandle is TPM2_GetSessionAuditDigest()'s 2nd handle (index 1) on the SESSIONS wire form; an unloaded transient-range value is TPM_RC_REFERENCE_H1 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2), the companion slot never reached.");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_EvictControl()</c>'s <c>objectHandle</c> is the 2nd handle in the handle area (index 1, after the
    /// out-of-scope hierarchy <c>@auth</c>); an unloaded TRANSIENT-range value is <c>TPM_RC_REFERENCE_H1</c>
    /// (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and a well-typed but unallocated PERSISTENT-range value is
    /// <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (step 2.2) — <paramref name="probeObjectHandle"/> is checked against a
    /// well-formed, in-range <c>persistentHandle</c> parameter target, so the refusal is proven at the
    /// generic clause 5.4 mechanism rather than at <c>persistentHandle</c>'s own type-level range check.
    /// </summary>
    /// <param name="probeObjectHandle">The value placed at <c>objectHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H1, DisplayName = "TPM2_EvictControl() objectHandle, index 1, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_EvictControl() objectHandle, index 1, persistent-range miss")]
    public async Task EvictControlObjectHandleAtHandleAreaIndexOneAnswersReferenceH1OrHandle(uint probeObjectHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(EvictControlObjectHandleAtHandleAreaIndexOneAnswersReferenceH1OrHandle)}-{probeObjectHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<EvictControlResponse> result = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, probeObjectHandle, EvictControlTargetPersistentHandle, authHandle: TpmRh.TPM_RH_OWNER, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "objectHandle is TPM2_EvictControl()'s 2nd handle (index 1); an unloaded transient-range value is TPM_RC_REFERENCE_H1 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_SignDigest()</c>'s <c>keyHandle</c> is its sole handle (index 0); an unloaded TRANSIENT-range
    /// value is <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and a well-typed but
    /// unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (step 2.2).
    /// </summary>
    /// <param name="probeKeyHandle">The value placed at <c>keyHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, DisplayName = "TPM2_SignDigest() keyHandle, index 0, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_SignDigest() keyHandle, index 0, persistent-range miss")]
    public async Task SignDigestKeyHandleAtHandleAreaIndexZeroAnswersReferenceH0OrHandle(uint probeKeyHandle, TpmRcConstants expected)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(SignDigestKeyHandleAtHandleAreaIndexZeroAnswersReferenceH0OrHandle)}-{probeKeyHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.Create(TpmiDhObject.FromValue(probeKeyHandle), FixedDigest, pool);

        TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        //DataRow arguments must be compile-time constants; the persistent-range-miss row's bare constant is
        //transformed here to the value the table assigns: keyHandle is SignDigest's sole handle (H1).
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(expected, 0);
        }

        Assert.AreEqual(
            expected, result.ResponseCode,
            "keyHandle is TPM2_SignDigest()'s sole handle (index 0); an unloaded transient-range value is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is handle-encoded TPM_RC_HANDLE (step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_Duplicate()</c>'s <c>objectHandle</c> is its 1st handle (index 0); an unloaded TRANSIENT-range
    /// value is <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and a well-typed but
    /// unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (step 2.2) — <c>newParentHandle</c> holds
    /// a genuinely loaded storage parent throughout, so the index is proven from <c>objectHandle</c>'s own
    /// position; the DUP-role ladder is never reached, so a plain password session at the object slot suffices.
    /// </summary>
    /// <param name="probeObjectHandle">The value placed at <c>objectHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, DisplayName = "TPM2_Duplicate() objectHandle, index 0, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_Duplicate() objectHandle, index 0, persistent-range miss")]
    public async Task DuplicateObjectHandleAtHandleAreaIndexZeroAnswersReferenceH0OrHandle(uint probeObjectHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(DuplicateObjectHandleAtHandleAreaIndexZeroAnswersReferenceH0OrHandle)}-{probeObjectHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse newParent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        DuplicateInput input = new(probeObjectHandle, newParent.ObjectHandle.Value);

        TpmResult<DuplicateResponse> result = await TpmCommandExecutor.ExecuteAsync<DuplicateResponse>(
            tpm, input, [objectAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "objectHandle is TPM2_Duplicate()'s 1st handle (index 0); an unloaded transient-range value is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_Duplicate()</c>'s <c>newParentHandle</c> is its 2nd handle (index 1); an unloaded TRANSIENT-range
    /// value is <c>TPM_RC_REFERENCE_H1</c> (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and a well-typed but
    /// unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (step 2.2) — <c>objectHandle</c> holds a
    /// genuinely loaded, duplicable KEYEDHASH object authorized through its own DUP-role policy session
    /// throughout, so the index is proven from <c>newParentHandle</c>'s own position, reached only once the
    /// entire DUP-role ladder ahead of it (resolution, policy digest match, latch, duplicable attribute)
    /// succeeds.
    /// </summary>
    /// <param name="probeNewParentHandle">The value placed at <c>newParentHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H1, DisplayName = "TPM2_Duplicate() newParentHandle, index 1, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_Duplicate() newParentHandle, index 1, persistent-range miss")]
    public async Task DuplicateNewParentHandleAtHandleAreaIndexOneAnswersReferenceH1OrHandle(uint probeNewParentHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(DuplicateNewParentHandleAtHandleAreaIndexOneAnswersReferenceH1OrHandle)}-{probeNewParentHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using Tpm2bDigest dupPolicy = HmacKeyHarness.DuplicationPolicyDigest(pool);
        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256,
            isSensitiveDataOrigin: true, isDuplicable: true, authPolicy: dupPolicy.AsReadOnlySpan().ToArray(), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (duplicable HMAC key) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        TpmResult<LoadResponse> loadResult = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, created.OutPrivate, created.OutPublic, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (duplicable HMAC key) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        TpmResult<DuplicateResponse> result = await HmacKeyHarness.DuplicateRawAsync(
            tpm, registry, pool, loaded.ObjectHandle.Value, loaded.Name.Span.ToArray(), probeNewParentHandle, PlaceholderProbeName, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "newParentHandle is TPM2_Duplicate()'s 2nd handle (index 1); an unloaded transient-range value is TPM_RC_REFERENCE_H1 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_Import()</c>'s <c>parentHandle</c> is its sole handle (index 0); an unloaded TRANSIENT-range
    /// value is <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and a well-typed but
    /// unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (step 2.2) — the refusal precedes the
    /// imported blob's own use, so a well-formed <c>TPM2_Create()</c> output stands in for a genuine duplication
    /// blob.
    /// </summary>
    /// <param name="probeParentHandle">The value placed at <c>parentHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, DisplayName = "TPM2_Import() parentHandle, index 0, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_Import() parentHandle, index 0, persistent-range miss")]
    public async Task ImportParentHandleAtHandleAreaIndexZeroAnswersReferenceH0OrHandle(uint probeParentHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(ImportParentHandleAtHandleAreaIndexZeroAnswersReferenceH0OrHandle)}-{probeParentHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256,
            isSensitiveDataOrigin: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (well-formed blob source) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        TpmResult<ImportResponse> result = await HmacKeyHarness.ImportAsync(
            tpm, registry, pool, probeParentHandle, created.OutPublic, created.OutPrivate, Tpm2bEncryptedSecret.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "parentHandle is TPM2_Import()'s sole handle (index 0); an unloaded transient-range value is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_Create()</c>'s KEYEDHASH-arm <c>parentHandle</c> is its sole handle (index 0) on the PLAIN
    /// (password-authorized) wire form: an unloaded TRANSIENT-range value is <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0
    /// Library Part 3, clause 5.4, step 2.1) and a well-typed but unallocated PERSISTENT-range value is
    /// <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (step 2.2).
    /// </summary>
    /// <param name="probeParentHandle">The value placed at <c>parentHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, DisplayName = "TPM2_Create() KEYEDHASH parentHandle, plain, index 0, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_Create() KEYEDHASH parentHandle, plain, index 0, persistent-range miss")]
    public async Task CreateKeyedHashParentHandlePlainFormAnswersReferenceH0OrHandle(uint probeParentHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(CreateKeyedHashParentHandlePlainFormAnswersReferenceH0OrHandle)}-{probeParentHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(FixedDigest, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);
        using CreateInput createInput = new(probeParentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "parentHandle is TPM2_Create()'s sole handle (index 0) on the PLAIN wire form; an unloaded transient-range value is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2).");
    }

    /// <summary>
    /// <c>TPM2_Create()</c>'s KEYEDHASH-arm <c>parentHandle</c> is its sole handle (index 0) on the SESSIONS wire
    /// form (an HMAC session in the authorization area at the parent slot): an
    /// unloaded TRANSIENT-range value is <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0 Library Part 3, clause 5.4, step
    /// 2.1) and a well-typed but unallocated PERSISTENT-range value is <c>TPM_RC_HANDLE</c>, handle-encoded to the same index (step 2.2) —
    /// the resolution failure precedes the HMAC verification, so the session need not be bound to any real
    /// entity.
    /// </summary>
    /// <param name="probeParentHandle">The value placed at <c>parentHandle</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedTransientHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, DisplayName = "TPM2_Create() KEYEDHASH parentHandle, sessions, index 0, unloaded transient")]
    [DataRow(UnallocatedPersistentHandle, TpmRcConstants.TPM_RC_HANDLE, DisplayName = "TPM2_Create() KEYEDHASH parentHandle, sessions, index 0, persistent-range miss")]
    public async Task CreateKeyedHashParentHandleSessionsFormAnswersReferenceH0OrHandle(uint probeParentHandle, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the persistent-range-miss row carries the bare
        //code and this computes the actually-expected H-encoded value from it.
        if(expected == TpmRcConstants.TPM_RC_HANDLE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(CreateKeyedHashParentHandleSessionsFormAnswersReferenceH0OrHandle)}-{probeParentHandle:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants.TPM_ALG_SHA256, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (parent slot) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession parentAuthSession = new(new TpmHandle(sessionHandle), started.NonceTPM, TpmAlgIdConstants.TPM_ALG_SHA256, TestEntropy.NewCounterStream(), pool);
            parentAuthSession.SetAuthValue(ReadOnlySpan<byte>.Empty, pool);

            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(FixedDigest, pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);
            using CreateInput createInput = new(probeParentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);

            TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [parentAuthSession], [PlaceholderProbeName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                expected, result.ResponseCode,
                "parentHandle is TPM2_Create()'s sole handle (index 0) on the SESSIONS wire form; an unloaded transient-range value is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) and an unallocated persistent-range value is TPM_RC_HANDLE, handle-encoded to the same index (step 2.2).");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Clause 5.4 precedes clause 5.5: on the SESSIONS wire form, an authorizing session that is a genuine,
    /// loaded AUDIT companion — one that has already folded a real successful command into a non-zero audit
    /// digest — has that digest, and its own <c>nonceTPM</c>, left byte-identical across the handle-area
    /// refusal, read back through two real <c>TPM2_GetSessionAuditDigest()</c> calls that bracket it. The
    /// established digest is genuinely non-zero (a real successful <c>TPM2_Create()</c> folds it first), so
    /// this is not a degenerate always-zero comparison a broken fold would also pass.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part
    /// 3, clause 5.4, step 2.1; clause 5.5</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateKeyedHashParentHandleSessionsFormOverAGenuineAuditCompanionLeavesItsNonceAndDigestUntouched()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(CreateKeyedHashParentHandleSessionsFormOverAGenuineAuditCompanionLeavesItsNonceAndDigestUntouched), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse signer = await CreateEccSigningKeyAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] parentName = parent.Name.Span.ToArray();

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants.TPM_ALG_SHA256, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (audit companion) failed: '{startResult.ResponseCode}'.");
        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession auditSession = new(new TpmHandle(sessionHandle), started.NonceTPM, TpmAlgIdConstants.TPM_ALG_SHA256, TestEntropy.NewCounterStream(), pool);
            auditSession.SetAuthValue(ReadOnlySpan<byte>.Empty, pool);
            auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

            //Establishes a genuine, non-zero audit digest: a real, successful TPM2_Create() over the parent
            //folds the simulator's own server-side audit digest, so the "unchanged" proof below cannot pass
            //on a perpetually-zero digest a broken fold would also leave looking untouched.
            using Tpm2bSensitiveCreate establishingSensitive = Tpm2bSensitiveCreate.ForSealedData(FixedDigest, pool);
            using Tpm2bPublic establishingTemplate = Tpm2bPublic.CreateSealedDataTemplate(TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);
            using CreateInput establishingInput = new(parent.ObjectHandle.Value, establishingSensitive, establishingTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            TpmResult<CreateResponse> establishingResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, establishingInput, [auditSession], [parentName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(establishingResult.IsSuccess, $"The establishing TPM2_Create() over the audit companion must succeed: '{establishingResult.ResponseCode}'.");
            establishingResult.Value.Dispose();

            using GetSessionAuditDigestInput beforeInput = GetSessionAuditDigestInput.ForEcdsa(
                signer.ObjectHandle, TpmiShHmac.FromValue(sessionHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            using TpmPasswordSession privacyAdminAuthBefore = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession signAuthBefore = TpmPasswordSession.CreateEmpty(pool);
            TpmResult<GetSessionAuditDigestResponse> beforeResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                tpm, beforeInput, [privacyAdminAuthBefore, signAuthBefore], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(beforeResult.IsSuccess, $"TPM2_GetSessionAuditDigest() (before the refusal) failed: '{beforeResult.ResponseCode}'.");
            byte[] digestBefore;
            using(GetSessionAuditDigestResponse before = beforeResult.Value)
            {
                digestBefore = before.SessionAudit.SessionDigest.AsReadOnlySpan().ToArray();
            }

            byte[] nonceBefore = auditSession.NonceTpm.ToArray();
            Assert.IsFalse(digestBefore.AsSpan().SequenceEqual(new byte[digestBefore.Length]), "The establishing TPM2_Create() must have folded a genuinely non-zero digest for this proof to discriminate a broken fold from a correct one.");

            using Tpm2bSensitiveCreate probeSensitive = Tpm2bSensitiveCreate.ForSealedData(FixedDigest, pool);
            using Tpm2bPublic probeTemplate = Tpm2bPublic.CreateSealedDataTemplate(TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);
            using CreateInput probeInput = new(UnloadedTransientHandle, probeSensitive, probeTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            TpmResult<CreateResponse> probeResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, probeInput, [auditSession], [PlaceholderProbeName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_REFERENCE_H0, probeResult.ResponseCode,
                "parentHandle is TPM2_Create()'s sole handle (index 0) on the SESSIONS wire form; an unloaded TRANSIENT-range value is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1) — the refusal never reaches the session's own audit-companion role (clause 5.5).");
            Assert.IsTrue(
                auditSession.NonceTpm.Span.SequenceEqual(nonceBefore),
                "A refused command's response is header-only with no session area, so the audit companion's own nonceTPM does not roll (TPM 2.0 Library Part 3, clause 5.9).");

            using GetSessionAuditDigestInput afterInput = GetSessionAuditDigestInput.ForEcdsa(
                signer.ObjectHandle, TpmiShHmac.FromValue(sessionHandle), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            using TpmPasswordSession privacyAdminAuthAfter = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession signAuthAfter = TpmPasswordSession.CreateEmpty(pool);
            TpmResult<GetSessionAuditDigestResponse> afterResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                tpm, afterInput, [privacyAdminAuthAfter, signAuthAfter], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(afterResult.IsSuccess, $"TPM2_GetSessionAuditDigest() (after the refusal) failed: '{afterResult.ResponseCode}'.");
            using(GetSessionAuditDigestResponse after = afterResult.Value)
            {
                byte[] digestAfter = after.SessionAudit.SessionDigest.AsReadOnlySpan().ToArray();

                Assert.IsTrue(
                    digestAfter.AsSpan().SequenceEqual(digestBefore),
                    "The refused command folds nothing into the audit digest (clause 5.4 precedes clause 5.5), so the already-non-zero digest a genuine audit companion carries is byte-identical before and after the refusal.");
            }
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_PolicyNV()</c>'s <c>policySession</c> is its 3rd handle (index 2, after <c>authHandle</c> and
    /// <c>nvIndex</c>, both out of this sweep's scope): an unloaded but well-typed value is
    /// <c>TPM_RC_REFERENCE_H2</c> (TPM 2.0 Library Part 3, clause 5.4, step 2.4) and a value outside
    /// <c>TPMI_SH_POLICY</c>'s own range is refused <c>TPM_RC_VALUE</c>, handle-encoded to the same index at unmarshal (TPM 2.0 Library Part
    /// 2, Table 56) — <c>nvIndex</c> is a genuinely defined NV Index so the probe reaches <c>policySession</c>'s
    /// own check rather than failing earlier on an undefined Index (Part 3, clause 5.4 step 2.3.1).
    /// </summary>
    /// <param name="probePolicySession">The value placed at <c>policySession</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedPolicySessionHandle, TpmRcConstants.TPM_RC_REFERENCE_H2, DisplayName = "TPM2_PolicyNV() policySession, index 2, unloaded")]
    [DataRow(HmacRangeOutOfPolicyRange, TpmRcConstants.TPM_RC_VALUE, DisplayName = "TPM2_PolicyNV() policySession, index 2, out of range")]
    public async Task PolicyNvPolicySessionAtHandleAreaIndexTwoAnswersReferenceH2OrValue(uint probePolicySession, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the out-of-range row carries the bare code and
        //this computes the actually-expected H2-encoded value from it — policySession is TPM2_PolicyNV()'s
        //third handle, index 2.
        if(expected == TpmRcConstants.TPM_RC_VALUE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 2);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(PolicyNvPolicySessionAtHandleAreaIndexTwoAnswersReferenceH2OrValue)}-{probePolicySession:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await PolicySweepHarness.DefineOwnerReadableIndexAsync(tpm, registry, pool, SampleNvIndex, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<PolicyNvResponse> result = await tpm.PolicyNvAsync(
            (uint)TpmRh.TPM_RH_OWNER, SampleNvIndex, probePolicySession, FixedDigest, offset: 0, TpmEoConstants.TPM_EO_EQ, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "policySession is TPM2_PolicyNV()'s 3rd handle (index 2); an unloaded but well-typed value is TPM_RC_REFERENCE_H2 (TPM 2.0 Library Part 3, clause 5.4, step 2.4) and an out-of-range value is handle-encoded TPM_RC_VALUE at unmarshal (TPM 2.0 Library Part 2, Table 56).");
    }

    /// <summary>
    /// <c>TPM2_PolicyAuthorizeNV()</c>'s <c>policySession</c> is its 3rd handle (index 2, after
    /// <c>authHandle</c> and <c>nvIndex</c>, both out of this sweep's scope): an unloaded but well-typed value is
    /// <c>TPM_RC_REFERENCE_H2</c> (TPM 2.0 Library Part 3, clause 5.4, step 2.4) and a value outside
    /// <c>TPMI_SH_POLICY</c>'s own range is refused <c>TPM_RC_VALUE</c>, handle-encoded to the same index at unmarshal (TPM 2.0 Library Part
    /// 2, Table 56).
    /// </summary>
    /// <param name="probePolicySession">The value placed at <c>policySession</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedPolicySessionHandle, TpmRcConstants.TPM_RC_REFERENCE_H2, DisplayName = "TPM2_PolicyAuthorizeNV() policySession, index 2, unloaded")]
    [DataRow(HmacRangeOutOfPolicyRange, TpmRcConstants.TPM_RC_VALUE, DisplayName = "TPM2_PolicyAuthorizeNV() policySession, index 2, out of range")]
    public async Task PolicyAuthorizeNvPolicySessionAtHandleAreaIndexTwoAnswersReferenceH2OrValue(uint probePolicySession, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the out-of-range row carries the bare code and
        //this computes the actually-expected H2-encoded value from it — policySession is
        //TPM2_PolicyAuthorizeNV()'s third handle, index 2.
        if(expected == TpmRcConstants.TPM_RC_VALUE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 2);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(PolicyAuthorizeNvPolicySessionAtHandleAreaIndexTwoAnswersReferenceH2OrValue)}-{probePolicySession:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await PolicySweepHarness.DefineOwnerReadableIndexAsync(tpm, registry, pool, SampleNvIndex, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<PolicyAuthorizeNvResponse> result = await tpm.PolicyAuthorizeNvAsync(
            (uint)TpmRh.TPM_RH_OWNER, SampleNvIndex, probePolicySession, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "policySession is TPM2_PolicyAuthorizeNV()'s 3rd handle (index 2); an unloaded but well-typed value is TPM_RC_REFERENCE_H2 (TPM 2.0 Library Part 3, clause 5.4, step 2.4) and an out-of-range value is handle-encoded TPM_RC_VALUE at unmarshal (TPM 2.0 Library Part 2, Table 56).");
    }

    /// <summary>
    /// <c>TPM2_PolicyTicket()</c>'s <c>policySession</c> is its sole handle (index 0): an unloaded but well-typed
    /// value is <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0 Library Part 3, clause 5.4, step 2.4) and a value outside
    /// <c>TPMI_SH_POLICY</c>'s own range is refused <c>TPM_RC_VALUE</c>, handle-encoded to the same index at unmarshal (TPM 2.0 Library Part
    /// 2, Table 56) — the refusal precedes the ticket's own HMAC check, so a syntactically well-formed but
    /// unverified ticket suffices.
    /// </summary>
    /// <param name="probePolicySession">The value placed at <c>policySession</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedPolicySessionHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, DisplayName = "TPM2_PolicyTicket() policySession, index 0, unloaded")]
    [DataRow(HmacRangeOutOfPolicyRange, TpmRcConstants.TPM_RC_VALUE, DisplayName = "TPM2_PolicyTicket() policySession, index 0, out of range")]
    public async Task PolicyTicketPolicySessionAtHandleAreaIndexZeroAnswersReferenceH0OrValue(uint probePolicySession, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the out-of-range row carries the bare code and
        //this computes the actually-expected H0-encoded value from it — policySession is TPM2_PolicyTicket()'s
        //sole handle, index 0.
        if(expected == TpmRcConstants.TPM_RC_VALUE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(PolicyTicketPolicySessionAtHandleAreaIndexZeroAnswersReferenceH0OrValue)}-{probePolicySession:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        byte[] timeout = new byte[8];
        using TpmtTkAuth ticket = TpmtTkAuth.Create(TpmStConstants.TPM_ST_AUTH_SECRET, TpmiRhHierarchy.Null, new byte[32], pool);

        TpmResult<PolicyTicketResponse> result = await tpm.PolicyTicketAsync(
            probePolicySession, timeout, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ticket, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "policySession is TPM2_PolicyTicket()'s sole handle (index 0); an unloaded but well-typed value is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.4) and an out-of-range value is handle-encoded TPM_RC_VALUE at unmarshal (TPM 2.0 Library Part 2, Table 56).");
    }

    /// <summary>
    /// <c>TPM2_PolicyAuthorize()</c>'s <c>policySession</c> is its sole handle (index 0): an unloaded but
    /// well-typed value is <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0 Library Part 3, clause 5.4, step 2.4) and a value
    /// outside <c>TPMI_SH_POLICY</c>'s own range is refused <c>TPM_RC_VALUE</c>, handle-encoded to the same index at unmarshal (TPM 2.0
    /// Library Part 2, Table 56) — the refusal precedes the approved-policy digest compare, so an empty ticket
    /// and digest suffice.
    /// </summary>
    /// <param name="probePolicySession">The value placed at <c>policySession</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(UnloadedPolicySessionHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, DisplayName = "TPM2_PolicyAuthorize() policySession, index 0, unloaded")]
    [DataRow(HmacRangeOutOfPolicyRange, TpmRcConstants.TPM_RC_VALUE, DisplayName = "TPM2_PolicyAuthorize() policySession, index 0, out of range")]
    public async Task PolicyAuthorizePolicySessionAtHandleAreaIndexZeroAnswersReferenceH0OrValue(uint probePolicySession, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the out-of-range row carries the bare code and
        //this computes the actually-expected H0-encoded value from it — policySession is
        //TPM2_PolicyAuthorize()'s sole handle, index 0.
        if(expected == TpmRcConstants.TPM_RC_VALUE)
        {
            expected = HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(PolicyAuthorizePolicySessionAtHandleAreaIndexZeroAnswersReferenceH0OrValue)}-{probePolicySession:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<PolicyAuthorizeResponse> result = await tpm.PolicyAuthorizeAsync(
            probePolicySession, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TpmtTkVerified.Null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            expected, result.ResponseCode,
            "policySession is TPM2_PolicyAuthorize()'s sole handle (index 0); an unloaded but well-typed value is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.4) and an out-of-range value is handle-encoded TPM_RC_VALUE at unmarshal (TPM 2.0 Library Part 2, Table 56).");
    }

    /// <summary>
    /// <c>TPM2_PolicySigned()</c>'s <c>policySession</c> is its 2nd handle (index 1); a value outside
    /// <c>TPMI_SH_POLICY</c>'s own range is refused <c>TPM_RC_VALUE</c>, handle-encoded to the same index at unmarshal (TPM 2.0 Library Part
    /// 2, Table 56), read as part of the same handle-area block as <c>authObject</c> before either handle is
    /// resolved or the signature is examined. The unloaded-but-in-range case
    /// (<c>TPM_RC_REFERENCE_H1</c>) is proven in <c>TpmInHouseSimulatorPolicySignedTests</c>, not duplicated
    /// here.
    /// </summary>
    /// <param name="probePolicySession">The out-of-range value placed at <c>policySession</c>.</param>
    [TestMethod]
    [DataRow(HmacRangeOutOfPolicyRange, DisplayName = "TPM2_PolicySigned() policySession, index 1, HMAC-range")]
    [DataRow(ObjectRangeOutOfPolicyRange, DisplayName = "TPM2_PolicySigned() policySession, index 1, object-range")]
    public async Task PolicySignedPolicySessionOutOfPolicyRangeAnswersValue(uint probePolicySession)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(PolicySignedPolicySessionOutOfPolicyRangeAnswersValue)}-{probePolicySession:X8}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        byte[] placeholderSignature = new byte[64];

        TpmResult<PolicySignedResponse> result = await tpm.PolicySignedAsync(
            (uint)TpmRh.TPM_RH_OWNER, probePolicySession, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, 0, placeholderSignature,
            TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 1), result.ResponseCode,
            "policySession is TPM2_PolicySigned()'s 2nd handle (index 1); a value outside TPMI_SH_POLICY's own range is refused handle-encoded TPM_RC_VALUE at unmarshal (TPM 2.0 Library Part 2, Table 56).");
    }
}
