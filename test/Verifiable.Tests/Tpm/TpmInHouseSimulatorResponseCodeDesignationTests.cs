using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Hierarchy;
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
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proves TPM 2.0 Library Part 2, clause 6.6.2, Table 15's own designation rule against the in-house
/// behavioural <see cref="TpmSimulator"/>: "When an error is associated with a parameter, TPM_RC_P (0x040) is
/// added and N is set to the parameter number. […] For an error associated with a handle, a parameter number
/// (1 to 7) is added to the N field. For an error associated with a session, a value of 8 plus the session
/// number (1 to 7) is added to the N field. […] If an implementation is not able to designate the handle,
/// session, or parameter in error, then P and N will be zero." The first three rows prove the mechanism
/// itself — Table 16's raw-code layout (the P bit at 0x040, the four-bit N field at bits 8-11) — by masking
/// the wire response code directly, one representative command per designation kind. The rows after that
/// prove, for each <see cref="TpmLifecycleTransitions"/> site whose designation no other class in the tree
/// exercises, the handle, parameter, or session number the command's own Part 3 table gives it. A further
/// group of rows each prove one site Table 15's closing sentence leaves at <c>N = 0</c> stays there — the
/// reference-bare and class-H header sites the reference itself cannot attribute to one handle, session, or
/// parameter — so a later change cannot "fix" a condition it never could.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorResponseCodeDesignationTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>Table 16's P bit: set when the answer is associated with a parameter.</summary>
    private const uint ParameterBit = 0x040;

    /// <summary>Table 16's six-bit E (error number) field.</summary>
    private const uint ErrorNumberMask = 0x03F;

    /// <summary>Table 16's four-bit N field, at bit offset 8.</summary>
    private const int NumberFieldShift = 8;

    /// <summary>Table 16's four-bit N field mask, once shifted down by <see cref="NumberFieldShift"/>.</summary>
    private const uint NumberFieldMask = 0x00F;

    /// <summary>
    /// Table 15: "For an error associated with a handle, a parameter number (1 to 7) is added to the N
    /// field" — proven over <c>TPM2_ReadPublic()</c>'s sole handle, <c>objectHandle</c> (Table 24, handle 1):
    /// an unallocated PERSISTENT-range value answers <c>TPM_RC_HANDLE</c> (clause 5.4, step 2.2) with the E
    /// field unchanged, the P bit CLEAR, and N = 1 (the one-based position of the command's only handle).
    /// </summary>
    [TestMethod]
    public async Task HandleAssociatedAnswerCarriesTheHandleNumberWithPClear()
    {
        const uint UnallocatedPersistentHandle = 0x8100_9999;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(HandleAssociatedAnswerCarriesTheHandleNumberWithPClear), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        ReadPublicInput input = ReadPublicInput.ForHandle(TpmiDhObject.FromValue(UnallocatedPersistentHandle));
        TpmResult<ReadPublicResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "An unallocated persistent handle must not resolve.");
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "Table 24: objectHandle is TPM2_ReadPublic()'s sole handle (handle 1), so a persistent-range miss (clause 5.4, step 2.2) is handle-encoded TPM_RC_HANDLE at index 0.");

        uint raw = (uint)result.ResponseCode;
        Assert.AreEqual((uint)TpmRcConstants.TPM_RC_HANDLE & ErrorNumberMask, raw & ErrorNumberMask, "Table 16: the E field is the unmodified error number, untouched by the designation.");
        Assert.AreEqual(0u, raw & ParameterBit, "Table 16: a handle-associated answer carries the P bit CLEAR.");
        Assert.AreEqual(1u, (raw >> NumberFieldShift) & NumberFieldMask, "Table 15: a handle-associated N is the handle's one-based position — 1 for the command's only handle.");
    }

    /// <summary>
    /// Table 15: "When an error is associated with a parameter, TPM_RC_P (0x040) is added and N is set to the
    /// parameter number" — proven over <c>TPM2_FlushContext()</c>'s <c>flushHandle</c>, which Table 228 frames
    /// as a PARAMETER despite its <c>TPMI_DH_CONTEXT</c> typing (the command's sole field is a use of a handle
    /// AS a parameter, not a handle-area entry): an unresolved TRANSIENT-range value answers
    /// <c>TPM_RC_HANDLE</c> with the E field unchanged, the P bit SET, and N = 1 (the one-based position of the
    /// command's only parameter).
    /// </summary>
    [TestMethod]
    public async Task ParameterAssociatedAnswerCarriesPSetAndTheParameterNumber()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(ParameterAssociatedAnswerCarriesPSetAndTheParameterNumber), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        FlushContextInput input = FlushContextInput.ForHandle(TpmHandleRanges.TRANSIENT_FIRST);
        TpmResult<FlushContextResponse> result = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A transient handle nothing is loaded at must not resolve.");
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "Table 228: flushHandle is TPM2_FlushContext()'s sole PARAMETER (index 0); an unresolved transient value is parameter-encoded TPM_RC_HANDLE.");

        uint raw = (uint)result.ResponseCode;
        Assert.AreEqual((uint)TpmRcConstants.TPM_RC_HANDLE & ErrorNumberMask, raw & ErrorNumberMask, "Table 16: the E field is the unmodified error number, untouched by the designation.");
        Assert.AreEqual(ParameterBit, raw & ParameterBit, "Table 15: a parameter-associated answer adds TPM_RC_P (0x040) — the P bit is SET.");
        Assert.AreEqual(1u, (raw >> NumberFieldShift) & NumberFieldMask, "Table 15: a parameter-associated N is the parameter's one-based position — 1 for the command's only parameter.");
    }

    /// <summary>
    /// Table 15: "For an error associated with a session, a value of 8 plus the session number (1 to 7) is
    /// added to the N field" — proven over <c>TPM2_HMAC()</c>'s sole authorizing session (Table 71, session
    /// 1): a password session presented against a key whose <c>userWithAuth</c> is CLEAR is refused
    /// <c>TPM_RC_POLICY_FAIL</c> (clause 5.6, check 7.1) with the E field unchanged, the P bit CLEAR, and
    /// N = 9 (8 + the session's one-based number, 1).
    /// </summary>
    [TestMethod]
    public async Task SessionAssociatedAnswerCarriesEightPlusTheSessionNumber()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SessionAssociatedAnswerCarriesEightPlusTheSessionNumber), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256,
            isUserWithAuth: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] data = [0x01, 0x02, 0x03];
        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, key.Handle, data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A password session must not authorize a userWithAuth-CLEAR key.");
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), result.ResponseCode,
            "Table 71: the key's authorizing session is session 1; a password session over a userWithAuth-CLEAR key is session-encoded TPM_RC_POLICY_FAIL.");

        uint raw = (uint)result.ResponseCode;
        Assert.AreEqual((uint)TpmRcConstants.TPM_RC_POLICY_FAIL & ErrorNumberMask, raw & ErrorNumberMask, "Table 16: the E field is the unmodified error number, untouched by the designation.");
        Assert.AreEqual(0u, raw & ParameterBit, "Table 15: a session-associated answer carries the P bit CLEAR — sessions are distinguished by the N range alone.");
        Assert.AreEqual(9u, (raw >> NumberFieldShift) & NumberFieldMask, "Table 15: a session-associated N is 8 plus the session's one-based number — 8 + 1 = 9 for the command's only session.");
    }

    /// <summary>
    /// <c>TPM2_DictionaryAttackLockReset()</c>'s <c>lockHandle</c> is its sole handle (<c>TPMI_RH_LOCKOUT</c>,
    /// Table 210); a value other than <c>TPM_RH_LOCKOUT</c> is refused handle-encoded <c>TPM_RC_HANDLE</c> at
    /// index 0 (the reference's handle-area unmarshal attributes any failure to the handle's position). No
    /// other class in this tree drives this command with a non-lockout handle.
    /// </summary>
    [TestMethod]
    public async Task DictionaryAttackLockResetWithALockHandleOtherThanLockoutAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(DictionaryAttackLockResetWithALockHandleOtherThanLockoutAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_DictionaryAttackLockReset, TpmResponseCodec.DictionaryAttackLockReset);

        var input = new DictionaryAttackLockResetInput((TpmRh)TpmHandleRanges.PERSISTENT_FIRST);
        using TpmPasswordSession lockoutSession = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<DictionaryAttackLockResetResponse> result = await TpmCommandExecutor.ExecuteAsync<DictionaryAttackLockResetResponse>(
            tpm, input, [lockoutSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A lockHandle other than TPM_RH_LOCKOUT must not be admitted.");
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "Table 210: lockHandle is TPM2_DictionaryAttackLockReset()'s sole handle (handle 1); a value other than TPM_RH_LOCKOUT is handle-encoded TPM_RC_HANDLE.");
    }

    /// <summary>
    /// The <c>TPM2_DictionaryAttackParameters()</c> counterpart of
    /// <see cref="DictionaryAttackLockResetWithALockHandleOtherThanLockoutAnswersHandle"/>: <c>lockHandle</c>
    /// (Table 212's sole handle, <c>TPMI_RH_LOCKOUT</c>) other than <c>TPM_RH_LOCKOUT</c> is handle-encoded
    /// <c>TPM_RC_HANDLE</c> at index 0. No other class in this tree drives this command with a non-lockout
    /// handle.
    /// </summary>
    [TestMethod]
    public async Task DictionaryAttackParametersWithALockHandleOtherThanLockoutAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(DictionaryAttackParametersWithALockHandleOtherThanLockoutAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_DictionaryAttackParameters, TpmResponseCodec.DictionaryAttackParameters);

        var input = new DictionaryAttackParametersInput((TpmRh)TpmHandleRanges.PERSISTENT_FIRST, 3, 10, 10);
        using TpmPasswordSession lockoutSession = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<DictionaryAttackParametersResponse> result = await TpmCommandExecutor.ExecuteAsync<DictionaryAttackParametersResponse>(
            tpm, input, [lockoutSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A lockHandle other than TPM_RH_LOCKOUT must not be admitted.");
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "Table 212: lockHandle is TPM2_DictionaryAttackParameters()'s sole handle (handle 1); a value other than TPM_RH_LOCKOUT is handle-encoded TPM_RC_HANDLE.");
    }

    /// <summary>
    /// <c>TPM2_PolicyNameHash()</c>'s <c>nameHash</c> is its sole parameter (Table 166, parameter 1); a digest
    /// whose width does not match the session's own hash algorithm is refused parameter-encoded
    /// <c>TPM_RC_SIZE</c> at index 0 (the reference's own <c>RC_PolicyNameHash_nameHash</c> modifier). No other
    /// class in this tree supplies a wrong-width digest to this command.
    /// </summary>
    [TestMethod]
    public async Task PolicyNameHashWithAWrongWidthDigestAnswersSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyNameHashWithAWrongWidthDigestAnswersSize), pool, TestContext.CancellationToken).ConfigureAwait(false);
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
            //SHA-256's digest is 32 octets; 16 is a well-formed but wrong-width TPM2B_DIGEST for this session.
            byte[] wrongWidthNameHash = new byte[16];

            TpmResult<PolicyNameHashResponse> result = await tpm.PolicyNameHashAsync(policySessionHandle, wrongWidthNameHash, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A nameHash whose width does not match the session's hash algorithm must not be admitted.");
            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), result.ResponseCode,
                "Table 166: nameHash is TPM2_PolicyNameHash()'s sole parameter (index 0); a wrong-width digest is parameter-encoded TPM_RC_SIZE.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, HmacKeyHarness.CreateRegistry(), pool, policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_HierarchyControl()</c>'s <c>authHandle</c> is its sole handle (Table 193, handle 1,
    /// <c>TPMI_RH_BASE_HIERARCHY</c>): a value outside that type's set — owner, endorsement, or platform — is
    /// refused handle-encoded <c>TPM_RC_VALUE</c> at index 0, proven here on the password-authorized wire
    /// form. No other class in this tree drives this command with an out-of-range authorizing handle.
    /// </summary>
    [TestMethod]
    public async Task HierarchyControlWithAnAuthHandleOutsideTheBaseHierarchySetAnswersHandleOnThePasswordForm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(HierarchyControlWithAnAuthHandleOutsideTheBaseHierarchySetAnswersHandleOnThePasswordForm), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<HierarchyControlResponse> result = await tpm.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_LOCKOUT, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "TPM_RH_LOCKOUT is not a member of TPMI_RH_BASE_HIERARCHY and must not authorize TPM2_HierarchyControl().");
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode,
            "Table 193: authHandle is TPM2_HierarchyControl()'s sole handle (handle 1); a value outside TPMI_RH_BASE_HIERARCHY is handle-encoded TPM_RC_VALUE.");
    }

    /// <summary>
    /// <c>TPM2_HierarchyControl()</c>'s <c>enable</c> is parameter 1 of Table 193's two parameters
    /// (<c>TPMI_RH_ENABLES</c>; <c>state</c> is parameter 2): a value outside that type's set is refused
    /// parameter-encoded <c>TPM_RC_VALUE</c> at index 0, proven here on the password-authorized wire form. No
    /// other class in this tree drives this command with an out-of-range enable value.
    /// </summary>
    [TestMethod]
    public async Task HierarchyControlWithAnEnableOutsideTheEnablesSetAnswersValueOnThePasswordForm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(HierarchyControlWithAnEnableOutsideTheEnablesSetAnswersValueOnThePasswordForm), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<HierarchyControlResponse> result = await tpm.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_LOCKOUT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "TPM_RH_LOCKOUT is not a member of TPMI_RH_ENABLES and must not be written by TPM2_HierarchyControl().");
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode,
            "Table 193: enable is TPM2_HierarchyControl()'s parameter 1 of two; a value outside TPMI_RH_ENABLES is parameter-encoded TPM_RC_VALUE.");
    }

    /// <summary>
    /// The session-authorized wire form of
    /// <see cref="HierarchyControlWithAnAuthHandleOutsideTheBaseHierarchySetAnswersHandleOnThePasswordForm"/>:
    /// Table 193's <c>authHandle</c> check applies identically whether the command is authorized by password
    /// or by an HMAC session bound to it, since the check reads the parsed handle field itself, ahead of any
    /// session verification.
    /// </summary>
    [TestMethod]
    public async Task HierarchyControlOverSessionWithAnAuthHandleOutsideTheBaseHierarchySetAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(HierarchyControlOverSessionWithAnAuthHandleOutsideTheBaseHierarchySetAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<HierarchyControlResponse> result = await tpm.DisableHierarchyAsync(
            TpmRh.TPM_RH_LOCKOUT, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "TPM_RH_LOCKOUT is not a member of TPMI_RH_BASE_HIERARCHY and must not authorize TPM2_HierarchyControl().");
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode,
            "Table 193: authHandle is TPM2_HierarchyControl()'s sole handle (handle 1); a value outside TPMI_RH_BASE_HIERARCHY is handle-encoded TPM_RC_VALUE, unconditional on the session form.");
    }

    /// <summary>
    /// The session-authorized wire form of
    /// <see cref="HierarchyControlWithAnEnableOutsideTheEnablesSetAnswersValueOnThePasswordForm"/>: Table 193's
    /// <c>enable</c> check applies identically whether the command is authorized by password or by an HMAC
    /// session bound to <c>authHandle</c>, since the check reads the parsed parameter field itself, ahead of
    /// any session verification.
    /// </summary>
    [TestMethod]
    public async Task HierarchyControlOverSessionWithAnEnableOutsideTheEnablesSetAnswersValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(HierarchyControlOverSessionWithAnEnableOutsideTheEnablesSetAnswersValue), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<HierarchyControlResponse> result = await tpm.DisableHierarchyAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_LOCKOUT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "TPM_RH_LOCKOUT is not a member of TPMI_RH_ENABLES and must not be written by TPM2_HierarchyControl().");
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode,
            "Table 193: enable is TPM2_HierarchyControl()'s parameter 1 of two; a value outside TPMI_RH_ENABLES is parameter-encoded TPM_RC_VALUE, unconditional on the session form.");
    }

    /// <summary>
    /// <c>TPM2_PolicyCounterTimer()</c>'s <c>offset + operandB.size &gt; 25</c> check spans TWO parameters —
    /// <c>operandB</c> (Table 158, parameter 1) and <c>offset</c> (parameter 2) — jointly, so the reference
    /// itself answers bare (a literal <c>TPM_RC_RANGE</c>, no modifier), exactly Table 15's closing sentence:
    /// "If an implementation is not able to designate the handle, session, or parameter in error, then P and N
    /// will be zero." This proves that stays true so a later change does not force the joint condition into a
    /// single-field designation it cannot support.
    /// </summary>
    [TestMethod]
    public async Task PolicyCounterTimerJointRangeConditionStaysBare()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyCounterTimerJointRangeConditionStaysBare), pool, TestContext.CancellationToken).ConfigureAwait(false);
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
            //offset (20) + operandB.size (10) = 30 > 25, TpmsTimeInfo's own marshaled width — the joint bound
            //the reference judges with no single field to blame.
            byte[] operandB = new byte[10];

            TpmResult<PolicyCounterTimerResponse> result = await tpm.PolicyCounterTimerAsync(
                policySessionHandle, operandB, offset: 20, TpmEoConstants.TPM_EO_EQ, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "offset + operandB.size beyond TpmsTimeInfo's own width must be refused.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_RANGE, result.ResponseCode,
                "The joint offset/operandB.size bound is not attributable to either field alone, so it stays bare TPM_RC_RANGE (Table 15's closing sentence).");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, HmacKeyHarness.CreateRegistry(), pool, policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_ReadPublic()</c>'s handle area (Table 24, handle 1) precedes its authorization area (TPM 2.0
    /// Library Part 2, clause 6.6.1); a session-authorized frame too short to carry even the handle is refused
    /// handle-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, the same designation the command's own no-sessions
    /// handle read carries.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOverACompanionSessionWithNoHandleOctetsAtAllAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(ReadPublicOverACompanionSessionWithNoHandleOctetsAtAllAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] frame = TpmCommandFrameHarness.BuildFrame((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)TpmCcConstants.TPM_CC_ReadPublic, ReadOnlySpan<byte>.Empty);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 24: objectHandle is TPM2_ReadPublic()'s sole handle (handle 1); a frame with no octets left to carry it is handle-encoded TPM_RC_INSUFFICIENT.");
    }

    /// <summary>
    /// <c>TPM2_ReadPublic()</c>'s <c>objectHandle</c> is <c>TPMI_DH_OBJECT</c> (Table 24, handle 1): transient or
    /// persistent only (TPM 2.0 Library Part 2, clause 9.3, Table 49). A value outside both ranges is refused
    /// handle-encoded <c>TPM_RC_VALUE</c> at index 0 on the plain (no-sessions) wire form.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicWithAnObjectHandleOutsideTheTransientOrPersistentRangeOnTheNoSessionsFormAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(ReadPublicWithAnObjectHandleOutsideTheTransientOrPersistentRangeOnTheNoSessionsFormAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(
            TpmCcConstants.TPM_CC_ReadPublic, [(uint)TpmRh.TPM_RH_OWNER], ReadOnlySpan<byte>.Empty);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), code,
            "Table 24: objectHandle is TPM2_ReadPublic()'s sole handle (handle 1); a permanent-range value is outside TPMI_DH_OBJECT and is handle-encoded TPM_RC_VALUE.");
    }

    /// <summary>
    /// <c>TPM2_NV_ReadPublic()</c>'s <c>nvIndex</c> is <c>TPMI_RH_NV_INDEX</c> (Table 251, handle 1): its own
    /// interface-type check admits only the NV Index handle type (TPM 2.0 Library Part 2, Table 71). A value
    /// outside that range is refused handle-encoded <c>TPM_RC_VALUE</c> at index 0 on the plain (no-sessions)
    /// wire form.
    /// </summary>
    [TestMethod]
    public async Task NvReadPublicWithAnIndexOutsideTheNvIndexRangeOnTheNoSessionsFormAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(NvReadPublicWithAnIndexOutsideTheNvIndexRangeOnTheNoSessionsFormAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(
            TpmCcConstants.TPM_CC_NV_ReadPublic, [(uint)TpmRh.TPM_RH_OWNER], ReadOnlySpan<byte>.Empty);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), code,
            "Table 251: nvIndex is TPM2_NV_ReadPublic()'s sole handle (handle 1); a permanent-range value is outside TPMI_RH_NV_INDEX and is handle-encoded TPM_RC_VALUE.");
    }

    /// <summary>
    /// <c>TPM2_NV_ChangeAuth()</c> admits a second, <c>decrypt</c>-companion session whenever the declared
    /// authorization-area size exceeds what the first slot alone consumes (TPM 2.0 Library Part 3, clause
    /// 31.15). A declared size that leaves fewer than four octets for that second slot's own
    /// <c>sessionHandle</c> field is refused session-encoded <c>TPM_RC_INSUFFICIENT</c> at index 1 — the same
    /// designation the first slot's identical read carries, shifted to the second session's own number.
    /// </summary>
    [TestMethod]
    public async Task NvChangeAuthsSecondCompanionSlotWithNoOctetsLeftForItsSessionHandleAnswersSession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(NvChangeAuthsSecondCompanionSlotWithNoOctetsLeftForItsSessionHandleAnswersSession), pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] firstSlot = TpmCommandFrameHarness.BuildSessionSlotOctets(
            0x0300_0001, ReadOnlySpan<byte>.Empty, 0, default, ReadOnlySpan<byte>.Empty, 0);
        byte[] shortfall = [0x00];
        byte[] authorizationAreaOctets = [.. firstSlot, .. shortfall];

        byte[] frame = TpmCommandFrameHarness.FrameCommandWithRawAuthorizationArea(
            TpmCcConstants.TPM_CC_NV_ChangeAuth, [TpmHandleRanges.NV_INDEX_FIRST + 1], authorizationAreaOctets, authorizationAreaOctets.Length, ReadOnlySpan<byte>.Empty);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 1), code,
            "The declared authorization size admits a second (index 1) session that leaves fewer than four octets for its own sessionHandle field, session-encoded TPM_RC_INSUFFICIENT.");
    }

    /// <summary>
    /// The same second companion slot's <c>sessionAttributes</c> octet (TPM 2.0 Library Part 2, clause 10.12.2,
    /// Table 156), read after its <c>sessionHandle</c> and empty <c>nonceCaller</c>, is refused session-encoded
    /// <c>TPM_RC_INSUFFICIENT</c> at index 1 when no octet remains for it.
    /// </summary>
    [TestMethod]
    public async Task NvChangeAuthsSecondCompanionSlotWithNoOctetLeftForItsAttributesAnswersSession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(NvChangeAuthsSecondCompanionSlotWithNoOctetLeftForItsAttributesAnswersSession), pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] firstSlot = TpmCommandFrameHarness.BuildSessionSlotOctets(
            0x0300_0001, ReadOnlySpan<byte>.Empty, 0, default, ReadOnlySpan<byte>.Empty, 0);
        byte[] secondSlotFull = TpmCommandFrameHarness.BuildSessionSlotOctets(
            0x0300_0002, ReadOnlySpan<byte>.Empty, 0, default, ReadOnlySpan<byte>.Empty, 0);
        byte[] secondSlotPartial = secondSlotFull[..6];
        byte[] authorizationAreaOctets = [.. firstSlot, .. secondSlotPartial];

        byte[] frame = TpmCommandFrameHarness.FrameCommandWithRawAuthorizationArea(
            TpmCcConstants.TPM_CC_NV_ChangeAuth, [TpmHandleRanges.NV_INDEX_FIRST + 1], authorizationAreaOctets, authorizationAreaOctets.Length, ReadOnlySpan<byte>.Empty);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 1), code,
            "The second (index 1) session's sessionHandle and empty nonceCaller read cleanly, leaving no octet for its own sessionAttributes, session-encoded TPM_RC_INSUFFICIENT.");
    }

    /// <summary>
    /// <c>TPM2_EventSequenceComplete()</c> (Table 95) reads a second password slot for its <c>@sequenceHandle</c>
    /// whenever the declared authorization size leaves room for one; a declared size that leaves fewer than
    /// four octets for that second slot's own <c>sessionHandle</c> field is refused session-encoded
    /// <c>TPM_RC_INSUFFICIENT</c> at index 1.
    /// </summary>
    [TestMethod]
    public async Task EventSequenceCompletesSecondPasswordSlotWithNoOctetsLeftForItsSessionHandleAnswersSession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(EventSequenceCompletesSecondPasswordSlotWithNoOctetsLeftForItsSessionHandleAnswersSession), pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] firstSlot = TpmCommandFrameHarness.BuildPasswordSlotOctets();
        byte[] shortfall = [0x00];
        byte[] authorizationAreaOctets = [.. firstSlot, .. shortfall];

        byte[] frame = TpmCommandFrameHarness.FrameCommandWithRawAuthorizationArea(
            TpmCcConstants.TPM_CC_EventSequenceComplete, [(uint)TpmRh.TPM_RH_NULL, 0x0300_0005], authorizationAreaOctets, authorizationAreaOctets.Length, ReadOnlySpan<byte>.Empty);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 1), code,
            "The declared authorization size admits a second (index 1) password slot that leaves fewer than four octets for its own sessionHandle field, session-encoded TPM_RC_INSUFFICIENT.");
    }

    /// <summary>
    /// The same second password slot's <c>sessionAttributes</c> octet is refused session-encoded
    /// <c>TPM_RC_INSUFFICIENT</c> at index 1 when its <c>sessionHandle</c> (<c>TPM_RS_PW</c>) and empty
    /// <c>nonceCaller</c> read cleanly but no octet remains for it.
    /// </summary>
    [TestMethod]
    public async Task EventSequenceCompletesSecondPasswordSlotWithNoOctetLeftForItsAttributesAnswersSession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(EventSequenceCompletesSecondPasswordSlotWithNoOctetLeftForItsAttributesAnswersSession), pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] firstSlot = TpmCommandFrameHarness.BuildPasswordSlotOctets();
        byte[] secondSlotFull = TpmCommandFrameHarness.BuildPasswordSlotOctets();
        byte[] secondSlotPartial = secondSlotFull[..6];
        byte[] authorizationAreaOctets = [.. firstSlot, .. secondSlotPartial];

        byte[] frame = TpmCommandFrameHarness.FrameCommandWithRawAuthorizationArea(
            TpmCcConstants.TPM_CC_EventSequenceComplete, [(uint)TpmRh.TPM_RH_NULL, 0x0300_0005], authorizationAreaOctets, authorizationAreaOctets.Length, ReadOnlySpan<byte>.Empty);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 1), code,
            "The second (index 1) password slot's TPM_RS_PW sessionHandle and empty nonceCaller read cleanly, leaving no octet for its own sessionAttributes, session-encoded TPM_RC_INSUFFICIENT.");
    }

    /// <summary>
    /// <c>TPM2_HierarchyControl()</c>'s authorizing slot reads its <c>hmac</c> field as a <c>TPM2B_AUTH</c> (TPM
    /// 2.0 Library Part 2, clause 10.12.2, Table 156): a declared size within the structural bound but wider
    /// than the octets that actually follow is refused session-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0 —
    /// the width check having already admitted the declared size, so the field's own body-length read is what
    /// fails.
    /// </summary>
    [TestMethod]
    public async Task HierarchyControlOverASessionWithAnHmacDeclaredWiderThanItsBodyAnswersSession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(HierarchyControlOverASessionWithAnHmacDeclaredWiderThanItsBodyAnswersSession), pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] frame = TpmCommandFrameHarness.FrameRealSessionCommand(
            TpmCcConstants.TPM_CC_HierarchyControl, [(uint)TpmRh.TPM_RH_OWNER], sessionHandle: 0x0300_0001,
            nonceOctets: ReadOnlySpan<byte>.Empty, declaredNonceSize: 0, sessionAttributes: default,
            hmacOctets: new byte[5], declaredHmacSize: 32, parameters: ReadOnlySpan<byte>.Empty);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "The hmac field's declared size (32) lies within sizeof(TPMU_HA) so the width check admits it, but only 5 octets follow, session-encoded TPM_RC_INSUFFICIENT at the authorizing slot's own index.");
    }

    /// <summary>
    /// <c>TPM2_NV_DefineSpace()</c>'s <c>auth</c> (Table 245, parameter 1) reads as an unbounded <c>TPM2B</c>
    /// before a separate manual check bounds it at <c>sizeof(TPMU_HA)</c>: a declared size wider than the
    /// octets that follow it is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceWithAnAuthDeclaredWiderThanItsBodyAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(NvDefineSpaceWithAnAuthDeclaredWiderThanItsBodyAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_NV_DefineSpace, [(uint)TpmRh.TPM_RH_OWNER], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 245: auth is TPM2_NV_DefineSpace()'s first parameter (index 0); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_NV_DefineSpace()</c>'s <c>authPolicy</c> is a field of <c>publicInfo</c> (Table 245, parameter 2,
    /// nested <c>TPMS_NV_PUBLIC</c>): every failure reading it — a declared size wider than the octets that
    /// follow, or a declared size past <c>sizeof(TPMU_HA)</c> — is attributed to <c>publicInfo</c> as a whole,
    /// parameter-encoded at index 1, TPM 2.0 Library Part 2, clause 10.3.2, Table 90's implied rule for both
    /// shapes.
    /// </summary>
    /// <param name="declaredAuthPolicySize">The size to declare for authPolicy's own <c>TPM2B</c>.</param>
    /// <param name="actualAuthPolicyLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "authPolicy declared wider than its body")]
    [DataRow(Tpm2bDigest.MaxSize + 1, Tpm2bDigest.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "authPolicy declared past sizeof(TPMU_HA)")]
    public async Task NvDefineSpaceWithAnAuthPolicyMalformedInsidePublicInfoAnswersTheDeclaredCode(
        int declaredAuthPolicySize, int actualAuthPolicyLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(NvDefineSpaceWithAnAuthPolicyMalformedInsidePublicInfoAnswersTheDeclaredCode)}{declaredAuthPolicySize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> publicInfo = [];
        //TPMS_NV_PUBLIC's leading fixed fields (nvIndex UINT32, nameAlg UINT16, attributes TPMA_NV/UINT32):
        //their content is irrelevant, since the parse fails at authPolicy before any of them is judged.
        publicInfo.AddRange(new byte[sizeof(uint) + sizeof(ushort) + sizeof(uint)]);
        TpmCommandFrameHarness.AppendTpm2b(publicInfo, new byte[actualAuthPolicyLength], declaredAuthPolicySize);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //auth: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, [.. publicInfo]); //publicInfo's own outer TPM2B_NV_PUBLIC size, declared to match exactly.

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_NV_DefineSpace, [(uint)TpmRh.TPM_RH_OWNER], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 1), code,
            "Table 245: authPolicy is a field of publicInfo, TPM2_NV_DefineSpace()'s second parameter (index 1); a malformed authPolicy is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_NV_Write()</c>'s <c>data</c> (Table 253, parameter 1) is a <c>TPM2B_MAX_NV_BUFFER</c>: a declared
    /// size wider than the octets that follow it is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, and
    /// a declared size past <c>MAX_NV_BUFFER_SIZE</c> (TPM 2.0 Library Part 2, clause 10.3.9, Table 97) is
    /// parameter-encoded <c>TPM_RC_SIZE</c> there.
    /// </summary>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "data declared wider than its body")]
    [DataRow(Tpm2bMaxNvBuffer.MaxSize + 1, Tpm2bMaxNvBuffer.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "data declared past MAX_NV_BUFFER_SIZE")]
    public async Task NvWriteWithADataParameterMalformedAnswersTheDeclaredCode(int declaredDataSize, int actualDataLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(NvWriteWithADataParameterMalformedAnswersTheDeclaredCode)}{declaredDataSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualDataLength], declaredDataSize);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_NV_Write, [(uint)TpmRh.TPM_RH_OWNER, TpmHandleRanges.NV_INDEX_FIRST + 1], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 0), code,
            "Table 253: data is TPM2_NV_Write()'s first parameter (index 0); a malformed data field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_NV_Extend()</c>'s <c>data</c> (Table 257, sole parameter) carries the identical
    /// <c>TPM2B_MAX_NV_BUFFER</c> rule <c>TPM2_NV_Write()</c>'s own <c>data</c> does, at the same index 0.
    /// </summary>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "data declared wider than its body")]
    [DataRow(Tpm2bMaxNvBuffer.MaxSize + 1, Tpm2bMaxNvBuffer.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "data declared past MAX_NV_BUFFER_SIZE")]
    public async Task NvExtendWithADataParameterMalformedAnswersTheDeclaredCode(int declaredDataSize, int actualDataLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(NvExtendWithADataParameterMalformedAnswersTheDeclaredCode)}{declaredDataSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualDataLength], declaredDataSize);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_NV_Extend, [(uint)TpmRh.TPM_RH_OWNER, TpmHandleRanges.NV_INDEX_FIRST + 1], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 0), code,
            "Table 257: data is TPM2_NV_Extend()'s sole parameter (index 0); a malformed data field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_NV_ChangeAuth()</c>'s <c>newAuth</c> (Table 269, sole parameter) reads as an unbounded
    /// <c>TPM2B_AUTH</c> before a separate manual check bounds it at <c>sizeof(TPMU_HA)</c>: a declared size
    /// wider than the octets that follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, and a
    /// declared size past that bound is parameter-encoded <c>TPM_RC_SIZE</c> there — the structural wire rule,
    /// distinct from the command's own narrower per-entity rule against the Index's nameAlg digest width.
    /// </summary>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "newAuth declared wider than its body")]
    [DataRow(Tpm2bAuth.MaxSize + 1, Tpm2bAuth.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "newAuth declared past sizeof(TPMU_HA)")]
    public async Task NvChangeAuthWithANewAuthParameterMalformedAnswersTheDeclaredCode(int declaredNewAuthSize, int actualNewAuthLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(NvChangeAuthWithANewAuthParameterMalformedAnswersTheDeclaredCode)}{declaredNewAuthSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualNewAuthLength], declaredNewAuthSize);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_NV_ChangeAuth, [TpmHandleRanges.NV_INDEX_FIRST + 1], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 0), code,
            "Table 269: newAuth is TPM2_NV_ChangeAuth()'s sole parameter (index 0); the structural wire rule is parameter-encoded at that index, whichever shape it breaks.");
    }

    /// <summary>
    /// <c>TPM2_HierarchyChangeAuth()</c>'s <c>newAuth</c> (Table 205, sole parameter) reads as an unbounded
    /// <c>TPM2B_AUTH</c> before a separate manual check bounds it at <c>sizeof(TPMU_HA)</c>: a declared size
    /// wider than the octets that follow it is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0 — the
    /// sibling of the structural SIZE shape the union bound already proves for this same field.
    /// </summary>
    [TestMethod]
    public async Task HierarchyChangeAuthWithANewAuthDeclaredWiderThanItsBodyAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(HierarchyChangeAuthWithANewAuthDeclaredWiderThanItsBodyAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_HierarchyChangeAuth, [(uint)TpmRh.TPM_RH_ENDORSEMENT], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 205: newAuth is TPM2_HierarchyChangeAuth()'s sole parameter (index 0); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_HMAC()</c>'s <c>buffer</c> (Table 71, parameter 1) reads bound-first against
    /// <c>TPM2B_MAX_BUFFER</c>'s own <c>MaxSize</c> (TPM 2.0 Library Part 2, clause 10.3.8): a declared size past
    /// that bound is parameter-encoded <c>TPM_RC_SIZE</c> at index 0, and a declared size within the bound but
    /// wider than the octets that follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> there.
    /// </summary>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "buffer declared wider than its body")]
    [DataRow(Tpm2bMaxBuffer.MaxSize + 1, Tpm2bMaxBuffer.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "buffer declared past its MaxSize")]
    public async Task HmacWithABufferParameterMalformedAnswersTheDeclaredCode(int declaredBufferSize, int actualBufferLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(HmacWithABufferParameterMalformedAnswersTheDeclaredCode)}{declaredBufferSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualBufferLength], declaredBufferSize);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_HMAC, [0x8000_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 0), code,
            "Table 71: buffer is TPM2_HMAC()'s first parameter (index 0); a malformed buffer field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_HMAC_Start()</c>'s <c>auth</c> (Table 80, parameter 1, the new sequence's own authorization value)
    /// carries the identical bound-first <c>TPM2B_AUTH</c> rule at the same index 0.
    /// </summary>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "auth declared wider than its body")]
    [DataRow(Tpm2bAuth.MaxSize + 1, Tpm2bAuth.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "auth declared past sizeof(TPMU_HA)")]
    public async Task HmacStartWithASequenceAuthParameterMalformedAnswersTheDeclaredCode(int declaredAuthSize, int actualAuthLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(HmacStartWithASequenceAuthParameterMalformedAnswersTheDeclaredCode)}{declaredAuthSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualAuthLength], declaredAuthSize);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_HMAC_Start, [0x8000_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 0), code,
            "Table 80: auth is TPM2_HMAC_Start()'s first parameter (index 0); a malformed auth field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_Import()</c>'s <c>duplicate</c> (Table 40, parameter 3) is a <c>TPM2B_PRIVATE</c>, bounded at
    /// <c>sizeof(_PRIVATE)</c> by TPM 2.0 Library Part 2, clause 12.3.7, Table 243 — this implementation's own
    /// PRIVATE storage bounds it there too — so a declared size wider than the octets that follow is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 2. The reference's <c>TPM2B_PRIVATE_Unmarshal</c>
    /// also answers <c>TPM_RC_SIZE</c> for a declared size past that bound; this simulator does not model that
    /// check.
    /// </summary>
    [TestMethod]
    public async Task ImportWithADuplicateDeclaredWiderThanItsBodyAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(ImportWithADuplicateDeclaredWiderThanItsBodyAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //encryptionKey: the modeled NULL form, well-formed empty.
        parameters.AddRange(BuildWellFormedHmacKeyPublicAreaOctets(pool)); //objectPublic: a well-formed marshaled TPM2B_PUBLIC.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10); //duplicate: malformed.

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_Import, [0x8000_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 2), code,
            "Table 40: duplicate is TPM2_Import()'s third parameter (index 2); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_Import()</c>'s <c>inSymSeed</c> (Table 40, parameter 4) reads bound-first against
    /// <c>TPM2B_ENCRYPTED_SECRET</c>'s own union bound (TPM 2.0 Library Part 2, clause 11.4.3, Table 224): a
    /// declared size past that bound is parameter-encoded <c>TPM_RC_SIZE</c> at index 3, and a declared size
    /// within the bound but wider than the octets that follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c>
    /// there.
    /// </summary>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "inSymSeed declared wider than its body")]
    [DataRow(Tpm2bEncryptedSecret.MaxSize + 1, Tpm2bEncryptedSecret.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "inSymSeed declared past its union bound")]
    public async Task ImportWithAnInSymSeedParameterMalformedAnswersTheDeclaredCode(int declaredInSymSeedSize, int actualInSymSeedLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(ImportWithAnInSymSeedParameterMalformedAnswersTheDeclaredCode)}{declaredInSymSeedSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //encryptionKey: the modeled NULL form, well-formed empty.
        parameters.AddRange(BuildWellFormedHmacKeyPublicAreaOctets(pool)); //objectPublic: a well-formed marshaled TPM2B_PUBLIC.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //duplicate: well-formed empty, so the parse reaches inSymSeed.
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualInSymSeedLength], declaredInSymSeedSize);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_Import, [0x8000_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 3), code,
            "Table 40: inSymSeed is TPM2_Import()'s fourth parameter (index 3); a malformed inSymSeed field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_HMAC()</c>'s and <c>TPM2_HMAC_Start()</c>'s shared front reads their common <c>@handle</c> (Table
    /// 71 and Table 80, handle 1 for both) before any authorization area; a frame with no octets left to carry
    /// it is refused handle-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0 for either command.
    /// </summary>
    /// <param name="commandCode">The command sharing the keyed-hash front.</param>
    [TestMethod]
    [DataRow(TpmCcConstants.TPM_CC_HMAC, DisplayName = "TPM2_HMAC()")]
    [DataRow(TpmCcConstants.TPM_CC_HMAC_Start, DisplayName = "TPM2_HMAC_Start()")]
    public async Task KeyedHashCommandFrontsKeyHandleWithNoHandleOctetsAtAllAnswersHandle(TpmCcConstants commandCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(KeyedHashCommandFrontsKeyHandleWithNoHandleOctetsAtAllAnswersHandle)}{commandCode}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] frame = TpmCommandFrameHarness.BuildFrame((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)commandCode, ReadOnlySpan<byte>.Empty);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "The shared keyed-hash front reads @handle as its sole handle (index 0) before any authorization area; a frame with no octets left to carry it is handle-encoded TPM_RC_INSUFFICIENT.");
    }

    /// <summary>
    /// <c>TPM2_NV_SetBits()</c> (Table 259) and the <c>TPM2_NV_ReadLock()</c>/<c>TPM2_NV_WriteLock()</c> family
    /// share one prologue reading <c>@authHandle</c> then <c>nvIndex</c> together: a frame too short to carry
    /// either is attributed to the first (index 0) handle, handle-encoded <c>TPM_RC_INSUFFICIENT</c>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsWithNoHandleOctetsAtAllAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(NvSetBitsWithNoHandleOctetsAtAllAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] frame = TpmCommandFrameHarness.BuildFrame((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)TpmCcConstants.TPM_CC_NV_SetBits, ReadOnlySpan<byte>.Empty);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 259: authHandle is TPM2_NV_SetBits()'s first handle (index 0); a frame too short to carry the combined authHandle/nvIndex read is handle-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_EventSequenceComplete()</c> (Table 95) reads <c>pcrHandle</c> as its first handle, shared with
    /// <c>TPM2_PCR_Extend()</c>, <c>TPM2_PCR_Event()</c> and <c>TPM2_PCR_Reset()</c>: a frame with no octets left
    /// to carry it is handle-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0.
    /// </summary>
    [TestMethod]
    public async Task EventSequenceCompleteWithNoHandleOctetsAtAllAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(EventSequenceCompleteWithNoHandleOctetsAtAllAnswersHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] frame = TpmCommandFrameHarness.BuildFrame((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)TpmCcConstants.TPM_CC_EventSequenceComplete, ReadOnlySpan<byte>.Empty);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 95: pcrHandle is TPM2_EventSequenceComplete()'s first handle (index 0); a frame with no octets left to carry it is handle-encoded TPM_RC_INSUFFICIENT.");
    }

    /// <summary>
    /// <c>TPM2_Sign()</c>'s <c>digest</c> (Table 122, parameter 1) reads on the password-authorized wire form
    /// against <c>TPM2B_DIGEST</c>'s own <c>sizeof(TPMU_HA)</c> bound: a declared size wider than the octets
    /// that follow it is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, and a declared size past the
    /// bound is parameter-encoded <c>TPM_RC_SIZE</c> there.
    /// </summary>
    /// <param name="declaredDigestSize">The size to declare for digest's own <c>TPM2B</c>.</param>
    /// <param name="actualDigestLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "digest declared wider than its body")]
    [DataRow(Tpm2bDigest.MaxSize + 1, Tpm2bDigest.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "digest declared past sizeof(TPMU_HA)")]
    public async Task SignWithADigestParameterMalformedOnThePasswordFormAnswersTheDeclaredCode(int declaredDigestSize, int actualDigestLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(SignWithADigestParameterMalformedOnThePasswordFormAnswersTheDeclaredCode)}{declaredDigestSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualDigestLength], declaredDigestSize);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_Sign, [0x8000_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 0), code,
            "Table 122: digest is TPM2_Sign()'s first parameter (index 0); a malformed digest field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_Sign()</c>'s <c>validation</c> (Table 122, parameter 3, <c>TPMT_TK_HASHCHECK</c>) carries its own
    /// <c>TPM2B_DIGEST</c> field, bounded against <c>sizeof(TPMU_HA)</c> BEFORE any truncation check: a declared
    /// size past that bound is parameter-encoded <c>TPM_RC_SIZE</c> at index 2, and a declared size within the
    /// bound but wider than the octets that follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> there.
    /// </summary>
    /// <param name="declaredTicketDigestSize">The size to declare for validation's own digest field.</param>
    /// <param name="actualTicketDigestLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "validation's digest declared wider than its body")]
    [DataRow(Tpm2bDigest.MaxSize + 1, Tpm2bDigest.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "validation's digest declared past sizeof(TPMU_HA)")]
    public async Task SignWithAValidationTicketDigestMalformedAnswersTheDeclaredCode(int declaredTicketDigestSize, int actualTicketDigestLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(SignWithAValidationTicketDigestMalformedAnswersTheDeclaredCode)}{declaredTicketDigestSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //digest: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendUInt16(parameters, (ushort)TpmAlgIdConstants.TPM_ALG_NULL); //inScheme: the bare NULL selector, parameter 1.
        TpmCommandFrameHarness.AppendUInt16(parameters, (ushort)TpmStConstants.TPM_ST_HASHCHECK); //validation.tag.
        TpmCommandFrameHarness.AppendUInt32(parameters, (uint)TpmRh.TPM_RH_NULL); //validation.hierarchy.
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualTicketDigestLength], declaredTicketDigestSize); //validation.digest: malformed.

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_Sign, [0x8000_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 2), code,
            "Table 122: validation is TPM2_Sign()'s third parameter (index 2); its own digest field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// The non-all-password (session) wire form of
    /// <see cref="SignWithADigestParameterMalformedOnThePasswordFormAnswersTheDeclaredCode"/>: a real
    /// authorizing session leaves <c>digest</c> undecoded for the decryption step, so only the field's own
    /// framing is checked at parse time — a declared size wider than the octets that follow it is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, the sole wire shape this form can reach.
    /// </summary>
    [TestMethod]
    public async Task SignWithADigestParameterMalformedOnASessionFormAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SignWithADigestParameterMalformedOnASessionFormAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> commandParameters = [];
        TpmCommandFrameHarness.AppendTpm2b(commandParameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FrameRealSessionCommand(
            TpmCcConstants.TPM_CC_Sign, [0x8000_0001], sessionHandle: 0x0300_0001,
            nonceOctets: ReadOnlySpan<byte>.Empty, declaredNonceSize: 0, sessionAttributes: default,
            hmacOctets: ReadOnlySpan<byte>.Empty, declaredHmacSize: 0, parameters: [.. commandParameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 122: digest is TPM2_Sign()'s first parameter (index 0); on a real-session wire form its framing alone is checked, and a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_SignDigest()</c>'s <c>context</c> (Table 126, parameter 1, <c>TPM2B_SIGNATURE_CTX</c>) reads
    /// bound-first against its own <c>MaxSize</c> (255) on the password-authorized wire form: a declared size
    /// past that bound is parameter-encoded <c>TPM_RC_SIZE</c> at index 0, and a declared size within the bound
    /// but wider than the octets that follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> there.
    /// </summary>
    /// <param name="declaredContextSize">The size to declare for context's own <c>TPM2B</c>.</param>
    /// <param name="actualContextLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "context declared wider than its body")]
    [DataRow(Tpm2bSignatureCtx.MaxSize + 1, Tpm2bSignatureCtx.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "context declared past its MaxSize")]
    public async Task SignDigestWithAContextParameterMalformedOnThePasswordFormAnswersTheDeclaredCode(int declaredContextSize, int actualContextLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(SignDigestWithAContextParameterMalformedOnThePasswordFormAnswersTheDeclaredCode)}{declaredContextSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualContextLength], declaredContextSize);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_SignDigest, [0x8000_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 0), code,
            "Table 126: context is TPM2_SignDigest()'s first parameter (index 0); a malformed context field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_SignDigest()</c>'s <c>digest</c> (Table 126, parameter 2) is bound-first against
    /// <c>sizeof(TPMU_HA)</c> and decoded identically on both wire forms, since it sits behind the first
    /// (encryptable) parameter: a declared size past the bound is parameter-encoded <c>TPM_RC_SIZE</c> at index
    /// 1, and a declared size within the bound but wider than the octets that follow is parameter-encoded
    /// <c>TPM_RC_INSUFFICIENT</c> there.
    /// </summary>
    /// <param name="declaredDigestSize">The size to declare for digest's own <c>TPM2B</c>.</param>
    /// <param name="actualDigestLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "digest declared wider than its body")]
    [DataRow(Tpm2bDigest.MaxSize + 1, Tpm2bDigest.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "digest declared past sizeof(TPMU_HA)")]
    public async Task SignDigestWithADigestParameterMalformedAnswersTheDeclaredCode(int declaredDigestSize, int actualDigestLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(SignDigestWithADigestParameterMalformedAnswersTheDeclaredCode)}{declaredDigestSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //context: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualDigestLength], declaredDigestSize);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_SignDigest, [0x8000_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 1), code,
            "Table 126: digest is TPM2_SignDigest()'s second parameter (index 1); a malformed digest field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_SignDigest()</c>'s <c>validation</c> (Table 126, parameter 3, <c>TPMT_TK_HASHCHECK</c>) carries
    /// its own <c>TPM2B_DIGEST</c> field, bounded against <c>sizeof(TPMU_HA)</c> BEFORE any truncation check,
    /// genuinely parsed rather than skipped on either wire form: a declared size past the bound is
    /// parameter-encoded <c>TPM_RC_SIZE</c> at index 2, and a declared size within the bound but wider than the
    /// octets that follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> there.
    /// </summary>
    /// <param name="declaredTicketDigestSize">The size to declare for validation's own digest field.</param>
    /// <param name="actualTicketDigestLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "validation's digest declared wider than its body")]
    [DataRow(Tpm2bDigest.MaxSize + 1, Tpm2bDigest.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "validation's digest declared past sizeof(TPMU_HA)")]
    public async Task SignDigestWithAValidationTicketDigestMalformedAnswersTheDeclaredCode(int declaredTicketDigestSize, int actualTicketDigestLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(SignDigestWithAValidationTicketDigestMalformedAnswersTheDeclaredCode)}{declaredTicketDigestSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //context: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //digest: well-formed empty, parameter 1.
        TpmCommandFrameHarness.AppendUInt16(parameters, (ushort)TpmStConstants.TPM_ST_HASHCHECK); //validation.tag.
        TpmCommandFrameHarness.AppendUInt32(parameters, (uint)TpmRh.TPM_RH_NULL); //validation.hierarchy.
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualTicketDigestLength], declaredTicketDigestSize); //validation.digest: malformed.

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_SignDigest, [0x8000_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 2), code,
            "Table 126: validation is TPM2_SignDigest()'s third parameter (index 2); its own digest field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// The non-all-password (session) wire form of
    /// <see cref="SignDigestWithAContextParameterMalformedOnThePasswordFormAnswersTheDeclaredCode"/>: a real
    /// authorizing session leaves <c>context</c> undecoded for the decryption step, so only the field's own
    /// framing is checked at parse time — a declared size wider than the octets that follow it is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, the sole wire shape this form can reach.
    /// </summary>
    [TestMethod]
    public async Task SignDigestWithAContextParameterMalformedOnASessionFormAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SignDigestWithAContextParameterMalformedOnASessionFormAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> commandParameters = [];
        TpmCommandFrameHarness.AppendTpm2b(commandParameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FrameRealSessionCommand(
            TpmCcConstants.TPM_CC_SignDigest, [0x8000_0001], sessionHandle: 0x0300_0001,
            nonceOctets: ReadOnlySpan<byte>.Empty, declaredNonceSize: 0, sessionAttributes: default,
            hmacOctets: ReadOnlySpan<byte>.Empty, declaredHmacSize: 0, parameters: [.. commandParameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 126: context is TPM2_SignDigest()'s first parameter (index 0); on a real-session wire form its framing alone is checked, and a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_RSA_Decrypt()</c>'s <c>cipherText</c> (Table 46, parameter 1, <c>TPM2B_PUBLIC_KEY_RSA</c>) reads
    /// on the password-authorized wire form and is bounded against <c>MAX_RSA_KEY_BYTES</c> (TPM 2.0 Library
    /// Part 2, clause 11.2.4.6, Table 194): a declared size wider than the octets that follow it is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, and a declared size past that bound is
    /// parameter-encoded <c>TPM_RC_SIZE</c> there.
    /// </summary>
    /// <param name="declaredCipherTextSize">The size to declare for cipherText's own <c>TPM2B</c>.</param>
    /// <param name="actualCipherTextLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "cipherText declared wider than its body")]
    [DataRow(Tpm2bPublicKeyRsa.MaxRsaKeyBytes + 1, Tpm2bPublicKeyRsa.MaxRsaKeyBytes + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "cipherText declared past MAX_RSA_KEY_BYTES")]
    public async Task RsaDecryptWithACipherTextParameterMalformedOnThePasswordFormAnswersTheDeclaredCode(int declaredCipherTextSize, int actualCipherTextLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(RsaDecryptWithACipherTextParameterMalformedOnThePasswordFormAnswersTheDeclaredCode)}{declaredCipherTextSize}", pool, TestContext.CancellationToken, includeRsaBackend: true).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualCipherTextLength], declaredCipherTextSize);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_RSA_Decrypt, [0x8000_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 0), code,
            "Table 46: cipherText is TPM2_RSA_Decrypt()'s first parameter (index 0); a malformed cipherText field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// The non-all-password (session) wire form of
    /// <see cref="RsaDecryptWithACipherTextParameterMalformedOnThePasswordFormAnswersTheDeclaredCode"/>: a real
    /// authorizing session leaves <c>cipherText</c> undecoded for the decryption step, so only the field's own
    /// framing is checked at parse time — a declared size wider than the octets that follow it is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, the sole wire shape this form can reach.
    /// </summary>
    [TestMethod]
    public async Task RsaDecryptWithACipherTextParameterMalformedOnASessionFormAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(RsaDecryptWithACipherTextParameterMalformedOnASessionFormAnswersInsufficient), pool, TestContext.CancellationToken, includeRsaBackend: true).ConfigureAwait(false);

        List<byte> commandParameters = [];
        TpmCommandFrameHarness.AppendTpm2b(commandParameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FrameRealSessionCommand(
            TpmCcConstants.TPM_CC_RSA_Decrypt, [0x8000_0001], sessionHandle: 0x0300_0001,
            nonceOctets: ReadOnlySpan<byte>.Empty, declaredNonceSize: 0, sessionAttributes: default,
            hmacOctets: ReadOnlySpan<byte>.Empty, declaredHmacSize: 0, parameters: [.. commandParameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 46: cipherText is TPM2_RSA_Decrypt()'s first parameter (index 0); on a real-session wire form its framing alone is checked, and a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_StartAuthSession()</c>'s <c>nonceCaller</c> (Table 14, parameter 1, <c>TPM2B_NONCE</c>) carries no
    /// authorization area of its own (<c>tpmKey</c> and <c>bind</c> are both Auth Index None): a declared size
    /// wider than the octets that follow it is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, and a
    /// declared size past its own <c>MaxSize</c> is parameter-encoded <c>TPM_RC_SIZE</c> there.
    /// </summary>
    /// <param name="declaredNonceCallerSize">The size to declare for nonceCaller's own <c>TPM2B</c>.</param>
    /// <param name="actualNonceCallerLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "nonceCaller declared wider than its body")]
    [DataRow(Tpm2bNonce.MaxSize + 1, Tpm2bNonce.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "nonceCaller declared past its MaxSize")]
    public async Task StartAuthSessionWithANonceCallerParameterMalformedAnswersTheDeclaredCode(int declaredNonceCallerSize, int actualNonceCallerLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(StartAuthSessionWithANonceCallerParameterMalformedAnswersTheDeclaredCode)}{declaredNonceCallerSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualNonceCallerLength], declaredNonceCallerSize);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(
            TpmCcConstants.TPM_CC_StartAuthSession, [(uint)TpmRh.TPM_RH_NULL, (uint)TpmRh.TPM_RH_NULL], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 0), code,
            "Table 14: nonceCaller is TPM2_StartAuthSession()'s first parameter (index 0); a malformed nonceCaller field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_StartAuthSession()</c>'s <c>encryptedSalt</c> (Table 14, parameter 2, <c>TPM2B_ENCRYPTED_SECRET</c>)
    /// reads after a well-formed <c>nonceCaller</c>: a declared size wider than the octets that follow it is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 1, and a declared size past its own <c>MaxSize</c>
    /// is parameter-encoded <c>TPM_RC_SIZE</c> there.
    /// </summary>
    /// <param name="declaredEncryptedSaltSize">The size to declare for encryptedSalt's own <c>TPM2B</c>.</param>
    /// <param name="actualEncryptedSaltLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "encryptedSalt declared wider than its body")]
    [DataRow(Tpm2bEncryptedSecret.MaxSize + 1, Tpm2bEncryptedSecret.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "encryptedSalt declared past its MaxSize")]
    public async Task StartAuthSessionWithAnEncryptedSaltParameterMalformedAnswersTheDeclaredCode(int declaredEncryptedSaltSize, int actualEncryptedSaltLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(StartAuthSessionWithAnEncryptedSaltParameterMalformedAnswersTheDeclaredCode)}{declaredEncryptedSaltSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //nonceCaller: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualEncryptedSaltLength], declaredEncryptedSaltSize);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(
            TpmCcConstants.TPM_CC_StartAuthSession, [(uint)TpmRh.TPM_RH_NULL, (uint)TpmRh.TPM_RH_NULL], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 1), code,
            "Table 14: encryptedSalt is TPM2_StartAuthSession()'s second parameter (index 1); a malformed encryptedSalt field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_VerifyDigestSignature()</c>'s <c>digest</c> (Table 120, parameter 2) reads on the
    /// <c>TPM_ST_NO_SESSIONS</c> ("direct") wire form, bound-first against <c>sizeof(TPMU_HA)</c>: a declared
    /// size past that bound is parameter-encoded <c>TPM_RC_SIZE</c> at index 1, and a declared size within the
    /// bound but wider than the octets that follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> there.
    /// </summary>
    /// <param name="declaredDigestSize">The size to declare for digest's own <c>TPM2B</c>.</param>
    /// <param name="actualDigestLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "digest declared wider than its body")]
    [DataRow(Tpm2bDigest.MaxSize + 1, Tpm2bDigest.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "digest declared past sizeof(TPMU_HA)")]
    public async Task VerifyDigestSignatureWithADigestParameterMalformedOnTheDirectFormAnswersTheDeclaredCode(int declaredDigestSize, int actualDigestLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(VerifyDigestSignatureWithADigestParameterMalformedOnTheDirectFormAnswersTheDeclaredCode)}{declaredDigestSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //context: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualDigestLength], declaredDigestSize);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(
            TpmCcConstants.TPM_CC_VerifyDigestSignature, [TpmHandleRanges.TRANSIENT_FIRST], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 1), code,
            "Table 120: digest is TPM2_VerifyDigestSignature()'s second parameter (index 1); a malformed digest field is parameter-encoded at that index, whichever wire rule it breaks, on the no-sessions wire form.");
    }

    /// <summary>
    /// <c>TPM2_Certify()</c>'s <c>qualifyingData</c> (Table 97, parameter 1) reads on the all-password wire form
    /// (both authorizing slots <c>TPM_RS_PW</c>, no companion) unbounded, then is checked against
    /// <c>sizeof(TPMT_HA)</c> after the read: a declared size wider than the octets that follow is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, and a declared size within the octets that
    /// follow but past that bound is parameter-encoded <c>TPM_RC_SIZE</c> there.
    /// </summary>
    /// <param name="declaredQualifyingDataSize">The size to declare for qualifyingData's own <c>TPM2B</c>.</param>
    /// <param name="actualQualifyingDataLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "qualifyingData declared wider than its body")]
    [DataRow(Tpm2bData.MaxSize + 1, Tpm2bData.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "qualifyingData declared past sizeof(TPMT_HA)")]
    public async Task CertifyWithAQualifyingDataParameterMalformedOnThePasswordFormAnswersTheDeclaredCode(int declaredQualifyingDataSize, int actualQualifyingDataLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(CertifyWithAQualifyingDataParameterMalformedOnThePasswordFormAnswersTheDeclaredCode)}{declaredQualifyingDataSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualQualifyingDataLength], declaredQualifyingDataSize);

        byte[] passwordSlot = TpmCommandFrameHarness.BuildPasswordSlotOctets();
        byte[] authorizationArea = [.. passwordSlot, .. passwordSlot];
        byte[] frame = TpmCommandFrameHarness.FrameCommandWithRawAuthorizationArea(
            TpmCcConstants.TPM_CC_Certify, [0x8000_0001, 0x8000_0002], authorizationArea, authorizationArea.Length, [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 0), code,
            "Table 97: qualifyingData is TPM2_Certify()'s first parameter (index 0); on the all-password wire form a malformed qualifyingData field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_Certify()</c>'s <c>qualifyingData</c> (Table 97, parameter 1) is only skipped over, not decoded,
    /// on a wire form where at least one authorizing slot is a real session: a declared size wider than the
    /// octets that follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, the sole wire shape this
    /// form can reach (the field's own bound is enforced only against a RECOVERED value the password form
    /// alone produces at parse time).
    /// </summary>
    [TestMethod]
    public async Task CertifyWithAQualifyingDataParameterMalformedOnASessionFormAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(CertifyWithAQualifyingDataParameterMalformedOnASessionFormAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] realSlot = TpmCommandFrameHarness.BuildSessionSlotOctets(
            0x0300_0001, ReadOnlySpan<byte>.Empty, 0, default, ReadOnlySpan<byte>.Empty, 0);
        byte[] passwordSlot = TpmCommandFrameHarness.BuildPasswordSlotOctets();
        byte[] authorizationArea = [.. realSlot, .. passwordSlot];
        byte[] frame = TpmCommandFrameHarness.FrameCommandWithRawAuthorizationArea(
            TpmCcConstants.TPM_CC_Certify, [0x8000_0001, 0x8000_0002], authorizationArea, authorizationArea.Length, [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 97: qualifyingData is TPM2_Certify()'s first parameter (index 0); on a real-session wire form its framing alone is checked, and a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_CertifyCreation()</c>'s <c>qualifyingData</c> (Table 99, parameter 1) reads on the password wire
    /// form (a lone <c>TPM_RS_PW</c> slot, no companion) unbounded, then is checked against
    /// <c>sizeof(TPMT_HA)</c> after the read: a declared size wider than the octets that follow is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, and a declared size within the octets that
    /// follow but past that bound is parameter-encoded <c>TPM_RC_SIZE</c> there.
    /// </summary>
    /// <param name="declaredQualifyingDataSize">The size to declare for qualifyingData's own <c>TPM2B</c>.</param>
    /// <param name="actualQualifyingDataLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "qualifyingData declared wider than its body")]
    [DataRow(Tpm2bData.MaxSize + 1, Tpm2bData.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "qualifyingData declared past sizeof(TPMT_HA)")]
    public async Task CertifyCreationWithAQualifyingDataParameterMalformedOnThePasswordFormAnswersTheDeclaredCode(int declaredQualifyingDataSize, int actualQualifyingDataLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(CertifyCreationWithAQualifyingDataParameterMalformedOnThePasswordFormAnswersTheDeclaredCode)}{declaredQualifyingDataSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualQualifyingDataLength], declaredQualifyingDataSize);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_CertifyCreation, [0x8000_0001, 0x8000_0002], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 0), code,
            "Table 99: qualifyingData is TPM2_CertifyCreation()'s first parameter (index 0); on the password wire form a malformed qualifyingData field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_CertifyCreation()</c>'s <c>creationHash</c> (Table 99, parameter 2) sits behind the first
    /// parameter, so it is decoded identically on both wire forms and read unbounded at parse time: a declared
    /// size wider than the octets that follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 1, the
    /// only wire shape this site reaches (no bound check follows the read here).
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationWithACreationHashParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(CertifyCreationWithACreationHashParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //qualifyingData: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10); //creationHash: malformed.

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_CertifyCreation, [0x8000_0001, 0x8000_0002], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 1), code,
            "Table 99: creationHash is TPM2_CertifyCreation()'s second parameter (index 1); it is read unbounded at parse time, so a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there, its only wire shape at this site.");
    }

    /// <summary>
    /// <c>TPM2_CertifyCreation()</c>'s <c>creationTicket</c> (Table 99, parameter 4, <c>TPMT_TK_CREATION</c>)
    /// carries its own digest field behind the ticket's <c>tag</c> and <c>hierarchy</c>, read unbounded at
    /// parse time: a declared size wider than the octets that follow is parameter-encoded
    /// <c>TPM_RC_INSUFFICIENT</c> at index 3, the only wire shape this site reaches (no bound check follows the
    /// read here).
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationWithATicketDigestParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(CertifyCreationWithATicketDigestParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //qualifyingData: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //creationHash: well-formed empty, parameter 1.
        TpmCommandFrameHarness.AppendUInt16(parameters, (ushort)TpmAlgIdConstants.TPM_ALG_NULL); //inScheme: the bare NULL selector, parameter 2.
        TpmCommandFrameHarness.AppendUInt16(parameters, (ushort)TpmStConstants.TPM_ST_CREATION); //creationTicket.tag.
        TpmCommandFrameHarness.AppendUInt32(parameters, (uint)TpmRh.TPM_RH_NULL); //creationTicket.hierarchy.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10); //creationTicket.digest: malformed.

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_CertifyCreation, [0x8000_0001, 0x8000_0002], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 3), code,
            "Table 99: the ticket's digest is a field of TPM2_CertifyCreation()'s fourth parameter (index 3); it is read unbounded at parse time, so a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there, its only wire shape at this site.");
    }

    /// <summary>
    /// <c>TPM2_GetTime()</c>'s <c>qualifyingData</c> (Table 107, parameter 1) reads on the all-password wire
    /// form (both authorizing slots <c>TPM_RS_PW</c>, no companion) unbounded, then is checked against
    /// <c>sizeof(TPMT_HA)</c> after the read: a declared size wider than the octets that follow is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, and a declared size within the octets that
    /// follow but past that bound is parameter-encoded <c>TPM_RC_SIZE</c> there.
    /// </summary>
    /// <param name="declaredQualifyingDataSize">The size to declare for qualifyingData's own <c>TPM2B</c>.</param>
    /// <param name="actualQualifyingDataLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "qualifyingData declared wider than its body")]
    [DataRow(Tpm2bData.MaxSize + 1, Tpm2bData.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "qualifyingData declared past sizeof(TPMT_HA)")]
    public async Task GetTimeWithAQualifyingDataParameterMalformedOnThePasswordFormAnswersTheDeclaredCode(int declaredQualifyingDataSize, int actualQualifyingDataLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(GetTimeWithAQualifyingDataParameterMalformedOnThePasswordFormAnswersTheDeclaredCode)}{declaredQualifyingDataSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualQualifyingDataLength], declaredQualifyingDataSize);

        byte[] passwordSlot = TpmCommandFrameHarness.BuildPasswordSlotOctets();
        byte[] authorizationArea = [.. passwordSlot, .. passwordSlot];
        byte[] frame = TpmCommandFrameHarness.FrameCommandWithRawAuthorizationArea(
            TpmCcConstants.TPM_CC_GetTime, [(uint)TpmRh.TPM_RH_ENDORSEMENT, 0x8000_0001], authorizationArea, authorizationArea.Length, [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 0), code,
            "Table 107: qualifyingData is TPM2_GetTime()'s first parameter (index 0); on the all-password wire form a malformed qualifyingData field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_GetTime()</c>'s <c>qualifyingData</c> (Table 107, parameter 1) is only skipped over, not
    /// decoded, on a wire form where at least one authorizing slot is a real session: a declared size wider
    /// than the octets that follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, the sole wire
    /// shape this form can reach.
    /// </summary>
    [TestMethod]
    public async Task GetTimeWithAQualifyingDataParameterMalformedOnASessionFormAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(GetTimeWithAQualifyingDataParameterMalformedOnASessionFormAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] realSlot = TpmCommandFrameHarness.BuildSessionSlotOctets(
            0x0300_0001, ReadOnlySpan<byte>.Empty, 0, default, ReadOnlySpan<byte>.Empty, 0);
        byte[] passwordSlot = TpmCommandFrameHarness.BuildPasswordSlotOctets();
        byte[] authorizationArea = [.. realSlot, .. passwordSlot];
        byte[] frame = TpmCommandFrameHarness.FrameCommandWithRawAuthorizationArea(
            TpmCcConstants.TPM_CC_GetTime, [(uint)TpmRh.TPM_RH_ENDORSEMENT, 0x8000_0001], authorizationArea, authorizationArea.Length, [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 107: qualifyingData is TPM2_GetTime()'s first parameter (index 0); on a real-session wire form its framing alone is checked, and a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_GetSessionAuditDigest()</c>'s <c>qualifyingData</c> (Table 103, parameter 1) reads on the
    /// all-password wire form (both authorizing slots <c>TPM_RS_PW</c>, no companion) unbounded, then is
    /// checked against <c>sizeof(TPMT_HA)</c> after the read: a declared size wider than the octets that follow
    /// is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, and a declared size within the octets that
    /// follow but past that bound is parameter-encoded <c>TPM_RC_SIZE</c> there.
    /// </summary>
    /// <param name="declaredQualifyingDataSize">The size to declare for qualifyingData's own <c>TPM2B</c>.</param>
    /// <param name="actualQualifyingDataLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "qualifyingData declared wider than its body")]
    [DataRow(Tpm2bData.MaxSize + 1, Tpm2bData.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "qualifyingData declared past sizeof(TPMT_HA)")]
    public async Task GetSessionAuditDigestWithAQualifyingDataParameterMalformedOnThePasswordFormAnswersTheDeclaredCode(int declaredQualifyingDataSize, int actualQualifyingDataLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(GetSessionAuditDigestWithAQualifyingDataParameterMalformedOnThePasswordFormAnswersTheDeclaredCode)}{declaredQualifyingDataSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualQualifyingDataLength], declaredQualifyingDataSize);

        byte[] passwordSlot = TpmCommandFrameHarness.BuildPasswordSlotOctets();
        byte[] authorizationArea = [.. passwordSlot, .. passwordSlot];
        byte[] frame = TpmCommandFrameHarness.FrameCommandWithRawAuthorizationArea(
            TpmCcConstants.TPM_CC_GetSessionAuditDigest, [(uint)TpmRh.TPM_RH_ENDORSEMENT, 0x8000_0001, 0x0200_0001], authorizationArea, authorizationArea.Length, [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 0), code,
            "Table 103: qualifyingData is TPM2_GetSessionAuditDigest()'s first parameter (index 0); on the all-password wire form a malformed qualifyingData field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_GetSessionAuditDigest()</c>'s <c>qualifyingData</c> (Table 103, parameter 1) is only skipped
    /// over, not decoded, on a wire form where at least one authorizing slot is a real session: a declared size
    /// wider than the octets that follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, the sole
    /// wire shape this form can reach.
    /// </summary>
    [TestMethod]
    public async Task GetSessionAuditDigestWithAQualifyingDataParameterMalformedOnASessionFormAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(GetSessionAuditDigestWithAQualifyingDataParameterMalformedOnASessionFormAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] realSlot = TpmCommandFrameHarness.BuildSessionSlotOctets(
            0x0300_0001, ReadOnlySpan<byte>.Empty, 0, default, ReadOnlySpan<byte>.Empty, 0);
        byte[] passwordSlot = TpmCommandFrameHarness.BuildPasswordSlotOctets();
        byte[] authorizationArea = [.. realSlot, .. passwordSlot];
        byte[] frame = TpmCommandFrameHarness.FrameCommandWithRawAuthorizationArea(
            TpmCcConstants.TPM_CC_GetSessionAuditDigest, [(uint)TpmRh.TPM_RH_ENDORSEMENT, 0x8000_0001, 0x0200_0001], authorizationArea, authorizationArea.Length, [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 103: qualifyingData is TPM2_GetSessionAuditDigest()'s first parameter (index 0); on a real-session wire form its framing alone is checked, and a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_NV_Certify()</c>'s <c>qualifyingData</c> (Table 271, parameter 1) reads on the all-password wire
    /// form (both authorizing slots <c>TPM_RS_PW</c>, no companion) unbounded, then is checked against
    /// <c>sizeof(TPMT_HA)</c> after the read: a declared size wider than the octets that follow is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, and a declared size within the octets that
    /// follow but past that bound is parameter-encoded <c>TPM_RC_SIZE</c> there.
    /// </summary>
    /// <param name="declaredQualifyingDataSize">The size to declare for qualifyingData's own <c>TPM2B</c>.</param>
    /// <param name="actualQualifyingDataLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "qualifyingData declared wider than its body")]
    [DataRow(Tpm2bData.MaxSize + 1, Tpm2bData.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "qualifyingData declared past sizeof(TPMT_HA)")]
    public async Task NvCertifyWithAQualifyingDataParameterMalformedOnThePasswordFormAnswersTheDeclaredCode(int declaredQualifyingDataSize, int actualQualifyingDataLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(NvCertifyWithAQualifyingDataParameterMalformedOnThePasswordFormAnswersTheDeclaredCode)}{declaredQualifyingDataSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualQualifyingDataLength], declaredQualifyingDataSize);

        byte[] passwordSlot = TpmCommandFrameHarness.BuildPasswordSlotOctets();
        byte[] authorizationArea = [.. passwordSlot, .. passwordSlot];
        byte[] frame = TpmCommandFrameHarness.FrameCommandWithRawAuthorizationArea(
            TpmCcConstants.TPM_CC_NV_Certify, [0x8000_0001, (uint)TpmRh.TPM_RH_OWNER, 0x0100_0001], authorizationArea, authorizationArea.Length, [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 0), code,
            "Table 271: qualifyingData is TPM2_NV_Certify()'s first parameter (index 0); on the all-password wire form a malformed qualifyingData field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_NV_Certify()</c>'s <c>qualifyingData</c> (Table 271, parameter 1) is only skipped over, not
    /// decoded, on a wire form where at least one authorizing slot is a real session: a declared size wider
    /// than the octets that follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, the sole wire
    /// shape this form can reach.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyWithAQualifyingDataParameterMalformedOnASessionFormAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(NvCertifyWithAQualifyingDataParameterMalformedOnASessionFormAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] realSlot = TpmCommandFrameHarness.BuildSessionSlotOctets(
            0x0300_0001, ReadOnlySpan<byte>.Empty, 0, default, ReadOnlySpan<byte>.Empty, 0);
        byte[] passwordSlot = TpmCommandFrameHarness.BuildPasswordSlotOctets();
        byte[] authorizationArea = [.. realSlot, .. passwordSlot];
        byte[] frame = TpmCommandFrameHarness.FrameCommandWithRawAuthorizationArea(
            TpmCcConstants.TPM_CC_NV_Certify, [0x8000_0001, (uint)TpmRh.TPM_RH_OWNER, 0x0100_0001], authorizationArea, authorizationArea.Length, [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 271: qualifyingData is TPM2_NV_Certify()'s first parameter (index 0); on a real-session wire form its framing alone is checked, and a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_MakeCredential()</c>'s <c>credential</c> (Table 28, parameter 1) reads on the
    /// <c>TPM_ST_NO_SESSIONS</c> wire form unbounded, then is checked against <c>sizeof(TPMU_HA)</c> after the
    /// read: a declared size wider than the octets that follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c>
    /// at index 0, and a declared size within the octets that follow but past that bound is parameter-encoded
    /// <c>TPM_RC_SIZE</c> there.
    /// </summary>
    /// <param name="declaredCredentialSize">The size to declare for credential's own <c>TPM2B</c>.</param>
    /// <param name="actualCredentialLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "credential declared wider than its body")]
    [DataRow(Tpm2bDigest.MaxSize + 1, Tpm2bDigest.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "credential declared past sizeof(TPMU_HA)")]
    public async Task MakeCredentialWithACredentialParameterMalformedOnTheNoSessionsFormAnswersTheDeclaredCode(int declaredCredentialSize, int actualCredentialLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(MakeCredentialWithACredentialParameterMalformedOnTheNoSessionsFormAnswersTheDeclaredCode)}{declaredCredentialSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualCredentialLength], declaredCredentialSize);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(
            TpmCcConstants.TPM_CC_MakeCredential, [0x8000_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 0), code,
            "Table 28: credential is TPM2_MakeCredential()'s first parameter (index 0); on the no-sessions wire form a malformed credential field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_MakeCredential()</c>'s <c>objectName</c> (Table 28, parameter 2) reads on the
    /// <c>TPM_ST_NO_SESSIONS</c> wire form unbounded, then is checked against <c>sizeof(TPMU_NAME)</c> after
    /// the read: a declared size wider than the octets that follow is parameter-encoded
    /// <c>TPM_RC_INSUFFICIENT</c> at index 1, and a declared size within the octets that follow but past that
    /// bound is parameter-encoded <c>TPM_RC_SIZE</c> there.
    /// </summary>
    /// <param name="declaredObjectNameSize">The size to declare for objectName's own <c>TPM2B</c>.</param>
    /// <param name="actualObjectNameLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "objectName declared wider than its body")]
    [DataRow(Tpm2bName.MaxSize + 1, Tpm2bName.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "objectName declared past sizeof(TPMU_NAME)")]
    public async Task MakeCredentialWithAnObjectNameParameterMalformedOnTheNoSessionsFormAnswersTheDeclaredCode(int declaredObjectNameSize, int actualObjectNameLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(MakeCredentialWithAnObjectNameParameterMalformedOnTheNoSessionsFormAnswersTheDeclaredCode)}{declaredObjectNameSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //credential: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, new byte[actualObjectNameLength], declaredObjectNameSize);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(
            TpmCcConstants.TPM_CC_MakeCredential, [0x8000_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 1), code,
            "Table 28: objectName is TPM2_MakeCredential()'s second parameter (index 1); on the no-sessions wire form a malformed objectName field is parameter-encoded at that index, whichever wire rule it breaks.");
    }

    /// <summary>
    /// <c>TPM2_MakeCredential()</c>'s <c>credential</c> (Table 28, parameter 1) reads on the
    /// <c>TPM_ST_SESSIONS</c> wire form through the shared no-authorization wrapper — the same parameter core
    /// the no-sessions form runs, over a genuinely resolved credential key and a genuinely verified companion
    /// session claiming <c>audit</c> alone (no other slot claims decrypt or encrypt, so the field is decoded
    /// unchanged by any session-based transform): a declared size wider than the octets that follow is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0, and a declared size within the octets that
    /// follow but past <c>sizeof(TPMU_HA)</c> is parameter-encoded <c>TPM_RC_SIZE</c> there — the same
    /// designation the no-sessions form's own proof gives this field.
    /// </summary>
    /// <param name="declaredCredentialSize">The size to declare for credential's own <c>TPM2B</c>.</param>
    /// <param name="actualCredentialLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "credential declared wider than its body")]
    [DataRow(Tpm2bDigest.MaxSize + 1, Tpm2bDigest.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "credential declared past sizeof(TPMU_HA)")]
    public async Task MakeCredentialWithACredentialParameterMalformedOnTheSessionsFormAnswersTheDeclaredCode(int declaredCredentialSize, int actualCredentialLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(MakeCredentialWithACredentialParameterMalformedOnTheSessionsFormAnswersTheDeclaredCode)}{declaredCredentialSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, pool, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential);

        using CreatePrimaryResponse signingKey = await HmacKeyHarness.CreateEccSigningPrimaryAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
                device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            try
            {
                using(session)
                {
                    session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                    var input = new RawMakeCredentialInput(
                        signingKey.ObjectHandle.Value, new byte[actualCredentialLength], declaredCredentialSize, ReadOnlyMemory<byte>.Empty, 0);
                    TpmResult<MakeCredentialResponse> result = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
                        device, input, [session], [signingKey.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.AreEqual(
                        HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 0), result.ResponseCode,
                        "Table 28: credential is TPM2_MakeCredential()'s first parameter (index 0); on the sessions-tag wire form, authorized by a genuinely verified audit companion session, a malformed credential field is parameter-encoded at that index, whichever wire rule it breaks — the same designation the no-sessions form's own proof gives it.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(device, registry, pool, signingKey.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_MakeCredential()</c>'s <c>objectName</c> (Table 28, parameter 2) reads on the
    /// <c>TPM_ST_SESSIONS</c> wire form through the shared no-authorization wrapper, behind a well-formed
    /// <c>credential</c>, over a genuinely resolved credential key and a genuinely verified companion session
    /// claiming <c>audit</c> alone: a declared size wider than the octets that follow is parameter-encoded
    /// <c>TPM_RC_INSUFFICIENT</c> at index 1, and a declared size within the octets that follow but past
    /// <c>sizeof(TPMU_NAME)</c> is parameter-encoded <c>TPM_RC_SIZE</c> there — the same designation the
    /// no-sessions form's own proof gives this field.
    /// </summary>
    /// <param name="declaredObjectNameSize">The size to declare for objectName's own <c>TPM2B</c>.</param>
    /// <param name="actualObjectNameLength">The octets actually written for it.</param>
    /// <param name="expectedBaseCode">The wire rule the shape breaks: <c>TPM_RC_INSUFFICIENT</c> or <c>TPM_RC_SIZE</c>.</param>
    [TestMethod]
    [DataRow(10, 0, TpmRcConstants.TPM_RC_INSUFFICIENT, DisplayName = "objectName declared wider than its body")]
    [DataRow(Tpm2bName.MaxSize + 1, Tpm2bName.MaxSize + 1, TpmRcConstants.TPM_RC_SIZE, DisplayName = "objectName declared past sizeof(TPMU_NAME)")]
    public async Task MakeCredentialWithAnObjectNameParameterMalformedOnTheSessionsFormAnswersTheDeclaredCode(int declaredObjectNameSize, int actualObjectNameLength, TpmRcConstants expectedBaseCode)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            $"{nameof(MakeCredentialWithAnObjectNameParameterMalformedOnTheSessionsFormAnswersTheDeclaredCode)}{declaredObjectNameSize}", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, pool, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential);

        using CreatePrimaryResponse signingKey = await HmacKeyHarness.CreateEccSigningPrimaryAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            (uint sessionHandle, TpmSession session) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
                device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            try
            {
                using(session)
                {
                    session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                    var input = new RawMakeCredentialInput(
                        signingKey.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, 0, new byte[actualObjectNameLength], declaredObjectNameSize);
                    TpmResult<MakeCredentialResponse> result = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
                        device, input, [session], [signingKey.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.AreEqual(
                        HmacKeyHarness.ParameterEncodedRc(expectedBaseCode, 1), result.ResponseCode,
                        "Table 28: objectName is TPM2_MakeCredential()'s second parameter (index 1); on the sessions-tag wire form, authorized by a genuinely verified audit companion session, a malformed objectName field is parameter-encoded at that index, whichever wire rule it breaks — the same designation the no-sessions form's own proof gives it.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(device, registry, pool, signingKey.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_PolicyAuthorize()</c>'s <c>approvedPolicy</c> (Table 170, parameter 1) reads on the command's own
    /// wire form (a lone command handle, no authorization area at all) unbounded: a declared size wider than the
    /// octets that follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithApprovedPolicyParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyAuthorizeWithApprovedPolicyParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(TpmCcConstants.TPM_CC_PolicyAuthorize, [0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 170: approvedPolicy is TPM2_PolicyAuthorize()'s first parameter (index 0); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_PolicyAuthorize()</c>'s <c>policyRef</c> (Table 170, parameter 2) reads behind a well-formed
    /// <c>approvedPolicy</c>: a declared size wider than the octets that follow is parameter-encoded
    /// <c>TPM_RC_INSUFFICIENT</c> at index 1.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithPolicyRefParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyAuthorizeWithPolicyRefParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //approvedPolicy: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(TpmCcConstants.TPM_CC_PolicyAuthorize, [0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 1), code,
            "Table 170: policyRef is TPM2_PolicyAuthorize()'s second parameter (index 1); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_PolicyAuthorize()</c>'s <c>keySign</c> (Table 170, parameter 3) reads behind well-formed
    /// <c>approvedPolicy</c> and <c>policyRef</c> fields: a declared size wider than the octets that follow is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 2.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithKeySignParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyAuthorizeWithKeySignParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //approvedPolicy: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //policyRef: well-formed empty, parameter 1.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(TpmCcConstants.TPM_CC_PolicyAuthorize, [0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 2), code,
            "Table 170: keySign is TPM2_PolicyAuthorize()'s third parameter (index 2); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_PolicyAuthorize()</c>'s <c>checkTicket</c> digest field (Table 170, parameter 4, the
    /// <c>TPMT_TK_VERIFIED</c> ticket's own <c>TPM2B_DIGEST</c>) reads behind well-formed <c>approvedPolicy</c>,
    /// <c>policyRef</c> and <c>keySign</c> fields and a well-formed NULL ticket header (<c>tag</c>,
    /// <c>hierarchy</c>): a declared size wider than the octets that follow is parameter-encoded
    /// <c>TPM_RC_INSUFFICIENT</c> at index 3, the ticket's whole parameter position.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithCheckTicketDigestParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyAuthorizeWithCheckTicketDigestParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //approvedPolicy: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //policyRef: well-formed empty, parameter 1.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //keySign: well-formed empty, parameter 2.
        TpmCommandFrameHarness.AppendUInt16(parameters, (ushort)TpmStConstants.TPM_ST_VERIFIED); //checkTicket.tag: the NULL Ticket form (Part 2, clause 10.6.5, Table 113).
        TpmCommandFrameHarness.AppendUInt32(parameters, (uint)TpmRh.TPM_RH_NULL); //checkTicket.hierarchy.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10); //checkTicket.hmac (the digest), malformed.

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(TpmCcConstants.TPM_CC_PolicyAuthorize, [0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 3), code,
            "Table 170: checkTicket is TPM2_PolicyAuthorize()'s fourth parameter (index 3); a declared size wider than the octets that follow, for the ticket's own digest field, is parameter-encoded TPM_RC_INSUFFICIENT at that index.");
    }

    /// <summary>
    /// <c>TPM2_PolicySecret()</c>'s <c>nonceTPM</c> (Table 146, parameter 1) reads behind the command's single
    /// password-authorized slot for <c>authHandle</c>: a declared size wider than the octets that follow is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretWithNonceTpmParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicySecretWithNonceTpmParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_PolicySecret, [(uint)TpmRh.TPM_RH_OWNER, 0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 146: nonceTPM is TPM2_PolicySecret()'s first parameter (index 0); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_PolicySecret()</c>'s <c>cpHashA</c> (Table 146, parameter 2) reads behind a well-formed
    /// <c>nonceTPM</c>: a declared size wider than the octets that follow is parameter-encoded
    /// <c>TPM_RC_INSUFFICIENT</c> at index 1.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretWithCpHashAParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicySecretWithCpHashAParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //nonceTPM: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_PolicySecret, [(uint)TpmRh.TPM_RH_OWNER, 0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 1), code,
            "Table 146: cpHashA is TPM2_PolicySecret()'s second parameter (index 1); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_PolicySecret()</c>'s <c>policyRef</c> (Table 146, parameter 3) reads behind well-formed
    /// <c>nonceTPM</c> and <c>cpHashA</c> fields: a declared size wider than the octets that follow is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 2.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretWithPolicyRefParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicySecretWithPolicyRefParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //nonceTPM: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //cpHashA: well-formed empty, parameter 1.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_PolicySecret, [(uint)TpmRh.TPM_RH_OWNER, 0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 2), code,
            "Table 146: policyRef is TPM2_PolicySecret()'s third parameter (index 2); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_PolicySigned()</c>'s <c>policyRef</c> (Table 144, parameter 3) reads behind well-formed
    /// <c>nonceTPM</c> and <c>cpHashA</c> fields on the command's own <c>TPM_ST_NO_SESSIONS</c> wire form: a
    /// declared size wider than the octets that follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at
    /// index 2.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithPolicyRefParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicySignedWithPolicyRefParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //nonceTPM: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //cpHashA: well-formed empty, parameter 1.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(
            TpmCcConstants.TPM_CC_PolicySigned, [0x8000_0001, 0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 2), code,
            "Table 144: policyRef is TPM2_PolicySigned()'s third parameter (index 2); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_PolicyTicket()</c>'s <c>timeout</c> (Table 148, parameter 1) reads on the command's own
    /// <c>TPM_ST_NO_SESSIONS</c> wire form unbounded: a declared size wider than the octets that follow is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithTimeoutParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyTicketWithTimeoutParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(TpmCcConstants.TPM_CC_PolicyTicket, [0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 148: timeout is TPM2_PolicyTicket()'s first parameter (index 0); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_PolicyTicket()</c>'s <c>cpHashA</c> (Table 148, parameter 2) reads behind a well-formed
    /// <c>timeout</c>: a declared size wider than the octets that follow is parameter-encoded
    /// <c>TPM_RC_INSUFFICIENT</c> at index 1.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithCpHashAParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyTicketWithCpHashAParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //timeout: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(TpmCcConstants.TPM_CC_PolicyTicket, [0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 1), code,
            "Table 148: cpHashA is TPM2_PolicyTicket()'s second parameter (index 1); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_PolicyTicket()</c>'s <c>policyRef</c> (Table 148, parameter 3) reads behind well-formed
    /// <c>timeout</c> and <c>cpHashA</c> fields: a declared size wider than the octets that follow is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 2.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithPolicyRefParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyTicketWithPolicyRefParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //timeout: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //cpHashA: well-formed empty, parameter 1.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(TpmCcConstants.TPM_CC_PolicyTicket, [0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 2), code,
            "Table 148: policyRef is TPM2_PolicyTicket()'s third parameter (index 2); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_PolicyTicket()</c>'s <c>authName</c> (Table 148, parameter 4) reads behind well-formed
    /// <c>timeout</c>, <c>cpHashA</c> and <c>policyRef</c> fields: a declared size wider than the octets that
    /// follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 3.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithAuthNameParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyTicketWithAuthNameParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //timeout: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //cpHashA: well-formed empty, parameter 1.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //policyRef: well-formed empty, parameter 2.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(TpmCcConstants.TPM_CC_PolicyTicket, [0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 3), code,
            "Table 148: authName is TPM2_PolicyTicket()'s fourth parameter (index 3); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_PolicyTicket()</c>'s <c>ticket</c> digest field (Table 148, parameter 5, the
    /// <c>TPMT_TK_AUTH</c> ticket's own <c>TPM2B_DIGEST</c>) reads behind well-formed <c>timeout</c>,
    /// <c>cpHashA</c>, <c>policyRef</c> and <c>authName</c> fields and a well-formed ticket header (<c>tag</c>,
    /// <c>hierarchy</c>): a declared size wider than the octets that follow is parameter-encoded
    /// <c>TPM_RC_INSUFFICIENT</c> at index 4, the ticket's whole parameter position.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithTicketDigestParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyTicketWithTicketDigestParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //timeout: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //cpHashA: well-formed empty, parameter 1.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //policyRef: well-formed empty, parameter 2.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //authName: well-formed empty, parameter 3.
        TpmCommandFrameHarness.AppendUInt16(parameters, (ushort)TpmStConstants.TPM_ST_AUTH_SECRET); //ticket.tag (Part 2, clause 10.6.4, Table 111).
        TpmCommandFrameHarness.AppendUInt32(parameters, (uint)TpmRh.TPM_RH_NULL); //ticket.hierarchy.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10); //ticket.digest, malformed.

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(TpmCcConstants.TPM_CC_PolicyTicket, [0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 4), code,
            "Table 148: ticket is TPM2_PolicyTicket()'s fifth parameter (index 4); a declared size wider than the octets that follow, for the ticket's own digest field, is parameter-encoded TPM_RC_INSUFFICIENT at that index.");
    }

    /// <summary>
    /// <c>TPM2_PolicyNV()</c>'s <c>operandB</c> (Table 156, parameter 1) reads behind the command's single
    /// password-authorized slot for <c>authHandle</c>: a declared size wider than the octets that follow is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvWithOperandBParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyNvWithOperandBParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_PolicyNV, [(uint)TpmRh.TPM_RH_OWNER, TpmHandleRanges.NV_INDEX_FIRST + 1, 0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 156: operandB is TPM2_PolicyNV()'s first parameter (index 0); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_PolicyCounterTimer()</c>'s <c>operandB</c> (Table 158, parameter 1) reads on the command's own
    /// <c>TPM_ST_NO_SESSIONS</c> wire form unbounded: a declared size wider than the octets that follow is
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 0.
    /// </summary>
    [TestMethod]
    public async Task PolicyCounterTimerWithOperandBParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyCounterTimerWithOperandBParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(TpmCcConstants.TPM_CC_PolicyCounterTimer, [0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 158: operandB is TPM2_PolicyCounterTimer()'s first parameter (index 0); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_PolicyDuplicationSelect()</c>'s <c>newParentName</c> (Table 168, parameter 2) reads behind a
    /// well-formed <c>objectName</c> on the command's own <c>TPM_ST_NO_SESSIONS</c> wire form: a declared size
    /// wider than the octets that follow is parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 1.
    /// </summary>
    [TestMethod]
    public async Task PolicyDuplicationSelectWithNewParentNameParameterMalformedAnswersInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyDuplicationSelectWithNewParentNameParameterMalformedAnswersInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //objectName: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty, declaredSize: 10);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(TpmCcConstants.TPM_CC_PolicyDuplicationSelect, [0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 1), code,
            "Table 168: newParentName is TPM2_PolicyDuplicationSelect()'s second parameter (index 1); a declared size wider than the octets that follow is parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>TPM2_PolicyAuthorize()</c>'s <c>checkTicket</c> carries a <c>TPM_ST_DIGEST_VERIFIED</c> tag whose
    /// <c>[tag]metadata</c> field (TPM 2.0 Library Part 2, clause 10.6.4, Table 111, the <c>digestVerified</c>
    /// arm) names a hash algorithm this TPM does not implement: <c>TPMI_ALG_HASH</c> "admits every TCG-assigned
    /// hash algorithm ID" (Part 2, clause 9.31, Table 77) and this simulator answers <c>TPM_RC_HASH</c> for one
    /// it does not support, parameter-encoded to <c>checkTicket</c>, Table 170's fourth parameter (index 3) —
    /// checked ahead of the ticket's own HMAC recompute, so no genuine authority key or ticket is needed to
    /// reach it.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeCheckTicketMetadataHashAlgorithmUnsupportedAnswersHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyAuthorizeCheckTicketMetadataHashAlgorithmUnsupportedAnswersHash), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_PolicyAuthorize, TpmResponseCodec.PolicyAuthorize);

        //A well-formed keySign Name (TPM_ALG_SHA256 selector + a 32-octet digest) so the earlier keySign
        //hash/size gates pass and this check is the one actually reached.
        byte[] keySign = new byte[sizeof(ushort) + 32];
        BinaryPrimitives.WriteUInt16BigEndian(keySign, (ushort)TpmAlgIdConstants.TPM_ALG_SHA256);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            using PolicyAuthorizeInput input = PolicyAuthorizeInput.Create(
                sessionHandle, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, keySign,
                (ushort)TpmStConstants.TPM_ST_DIGEST_VERIFIED, (uint)TpmRh.TPM_RH_OWNER,
                TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA1), new byte[32], pool);

            TpmResult<PolicyAuthorizeResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyAuthorizeResponse>(
                tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 3), result.ResponseCode,
                "Table 170: checkTicket is TPM2_PolicyAuthorize()'s fourth parameter (index 3); a TPM_ST_DIGEST_VERIFIED ticket whose [tag]metadata names an unsupported hash algorithm is parameter-encoded TPM_RC_HASH there.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_NV_Certify()</c>'s no-sessions (password) wire form answers <c>TPM_RC_HASH</c> for a scheme hash
    /// algorithm this TPM does not implement, parameter-encoded to <c>inScheme</c>, Table 271's second
    /// parameter (index 1) — TPM 2.0 Library Part 2, clause 6.6.2, Table 15's parameter designation, reached
    /// over a genuinely defined NV Index and a genuinely loaded signing key.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyWithAnUnsupportedSchemeHashAlgorithmAnswersHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(NvCertifyWithAnUnsupportedSchemeHashAlgorithmAnswersHash), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_Certify, TpmResponseCodec.NvCertify);

        const uint NvIndex = 0x0100_0F00;
        byte[] indexAuth = [0x51, 0x52, 0x53, 0x54];
        await DefineNvIndexForResponseCodeDesignationAsync(tpm, registry, pool, NvIndex, indexAuth).ConfigureAwait(false);

        using CreatePrimaryResponse signer = await HmacKeyHarness.CreateEccSigningPrimaryAsync(
            tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession indexAuthSession = TpmPasswordSession.Create(indexAuth, pool);
            using NvCertifyInput input = NvCertifyInput.ForEcdsa(
                signer.ObjectHandle, NvIndex, NvIndex, ReadOnlySpan<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA1, size: 1, offset: 0, pool);

            TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, input, [signAuth, indexAuthSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 1), result.ResponseCode,
                "Table 271: inScheme is TPM2_NV_Certify()'s second parameter (index 1); a scheme hash algorithm this TPM does not implement is parameter-encoded TPM_RC_HASH there.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, signer.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_NV_Certify()</c>'s wire form with a real, genuinely started HMAC session authorizing
    /// <c>signHandle</c> — Table 271's first authorizing slot — answers <c>TPM_RC_HASH</c> for a scheme hash
    /// algorithm this TPM does not implement, parameter-encoded to <c>inScheme</c>, Table 271's second
    /// parameter (index 1) — TPM 2.0 Library Part 2, clause 6.6.2, Table 15's parameter designation, reached
    /// over a genuinely defined NV Index, a genuinely loaded signing key, and a genuinely started session,
    /// ahead of any credential comparison on either authorizing slot: the same designation the all-password
    /// wire form's own proof gives this field.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverASessionWithAnUnsupportedSchemeHashAlgorithmAnswersHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(NvCertifyOverASessionWithAnUnsupportedSchemeHashAlgorithmAnswersHash), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, pool, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_Certify, TpmResponseCodec.NvCertify)
            .Register(TpmCcConstants.TPM_CC_NV_ReadPublic, TpmResponseCodec.NvReadPublic);

        const uint NvIndex = 0x0100_0F01;
        byte[] indexAuth = [0x61, 0x62, 0x63, 0x64];
        await DefineNvIndexForResponseCodeDesignationAsync(tpm, registry, pool, NvIndex, indexAuth).ConfigureAwait(false);

        TpmResult<NvReadPublicResponse> readPublicResult = await TpmCommandExecutor.ExecuteAsync<NvReadPublicResponse>(
            tpm, new NvReadPublicInput(NvIndex), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(readPublicResult.IsSuccess, $"NV_ReadPublic failed: '{readPublicResult.ResponseCode}'.");
        byte[] indexName;
        using(NvReadPublicResponse readPublic = readPublicResult.Value)
        {
            indexName = readPublic.NvName.Span.ToArray();
        }

        using CreatePrimaryResponse signer = await HmacKeyHarness.CreateEccSigningPrimaryAsync(
            tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            (uint sessionHandle, TpmSession signSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
                tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            try
            {
                using(signSession)
                {
                    using TpmPasswordSession indexAuthSession = TpmPasswordSession.Create(indexAuth, pool);
                    using NvCertifyInput input = NvCertifyInput.ForEcdsa(
                        signer.ObjectHandle, NvIndex, NvIndex, ReadOnlySpan<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA1, size: 1, offset: 0, pool);

                    //cpHash covers every command handle once any slot is a real session (Part 1, clause 15.7,
                    //equation 15), so the signing key's Name is supplied even though this proof never reaches
                    //command-HMAC verification - the HASH check answers before that stage runs.
                    ReadOnlyMemory<byte>[] handleNames = [signer.Name.AsReadOnlyMemory(), indexName, indexName];
                    TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                        tpm, input, [signSession, indexAuthSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.AreEqual(
                        HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 1), result.ResponseCode,
                        "Table 271: inScheme is TPM2_NV_Certify()'s second parameter (index 1); with a real HMAC session authorizing signHandle, a scheme hash algorithm this TPM does not implement is parameter-encoded TPM_RC_HASH there, the same designation the all-password form's own proof gives it.");
                }
            }
            finally
            {
                await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, signer.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_ActivateCredential()</c>'s wire form whose <c>keyHandle</c> authorizing slot names a real
    /// (non-password), well-typed session handle — Table 26's second session (index 1) — that names no loaded
    /// policy session answers the format-zero warning <c>TPM_RC_REFERENCE_S1</c>: TPM 2.0 Library Part 3,
    /// clause 5.5, step 4.2, "If the session is not loaded, the TPM will return the warning
    /// TPM_RC_REFERENCE_S0 + N where N is the number of the session", reached over two genuinely loaded objects
    /// and a correct password on the first (activate) slot, so the second slot's own handle is the only thing
    /// this proof leaves wrong.
    /// </summary>
    [TestMethod]
    public async Task ActivateCredentialOverASessionWithAnUnallocatedKeyPolicySessionAnswersReferenceS1()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(ActivateCredentialOverASessionWithAnUnallocatedKeyPolicySessionAnswersReferenceS1), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, pool, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse activateObject = await HmacKeyHarness.CreateStorageParentAsync(
            tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse key = await HmacKeyHarness.CreateStorageParentAsync(
                tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
            try
            {
                List<byte> parameters = [];
                TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //credentialBlob: well-formed empty, parameter 0.
                TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //secret: well-formed empty, parameter 1.

                byte[] passwordSlot = TpmCommandFrameHarness.BuildPasswordSlotOctets();
                byte[] unallocatedPolicySessionSlot = TpmCommandFrameHarness.BuildSessionSlotOctets(
                    0x0300_00FE, ReadOnlySpan<byte>.Empty, 0, default, ReadOnlySpan<byte>.Empty, 0);
                byte[] authorizationArea = [.. passwordSlot, .. unallocatedPolicySessionSlot];

                byte[] frame = TpmCommandFrameHarness.FrameCommandWithRawAuthorizationArea(
                    TpmCcConstants.TPM_CC_ActivateCredential, [activateObject.ObjectHandle.Value, key.ObjectHandle.Value],
                    authorizationArea, authorizationArea.Length, [.. parameters]);
                TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_REFERENCE_S1, code,
                    "Table 26: keyHandle's authorizing session is TPM2_ActivateCredential()'s second session (index 1); a well-typed handle naming no loaded policy session there is the format-zero TPM_RC_REFERENCE_S1, not a format-one session-encoded TPM_RC_HANDLE nor the bare handle-area code an unknown object handle would carry.");
            }
            finally
            {
                await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, key.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, activateObject.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_StartAuthSession()</c>'s handle area is <c>tpmKey</c> then <c>bind</c> (TPM 2.0 Library Part 3,
    /// clause 11.1, Table 14, handles 1 and 2): a frame carrying exactly the four octets that carry
    /// <c>tpmKey</c> and none for <c>bind</c> unmarshals <c>tpmKey</c> cleanly and fails on <c>bind</c>'s own
    /// read, handle-encoded <c>TPM_RC_INSUFFICIENT</c> at index 1 — not index 0, since <c>tpmKey</c> itself read
    /// without incident.
    /// </summary>
    [TestMethod]
    public async Task StartAuthSessionWithOnlyTpmKeyHandleOctetsAnswersBindHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(StartAuthSessionWithOnlyTpmKeyHandleOctetsAnswersBindHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(
            TpmCcConstants.TPM_CC_StartAuthSession, [(uint)TpmRh.TPM_RH_NULL], ReadOnlySpan<byte>.Empty);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 1), code,
            "Table 14: tpmKey (handle 1, index 0) reads cleanly from a four-octet handle area; bind (handle 2, index 1) is the field whose own read fails, so the refusal is handle-encoded TPM_RC_INSUFFICIENT at index 1.");
    }

    /// <summary>
    /// <c>TPM2_GetSessionAuditDigest()</c>'s handle area is <c>@privacyAdminHandle</c>, <c>@signHandle</c>, then
    /// <c>sessionHandle</c> (TPM 2.0 Library Part 3, clause 18.5, Table 103, handles 1 through 3): a frame
    /// carrying exactly the eight octets that carry the first two handles and none for the third unmarshals
    /// both cleanly and fails on <c>sessionHandle</c>'s own read, handle-encoded <c>TPM_RC_INSUFFICIENT</c> at
    /// index 2.
    /// </summary>
    [TestMethod]
    public async Task GetSessionAuditDigestWithOnlyTwoOfThreeHandleOctetsAnswersSessionHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(GetSessionAuditDigestWithOnlyTwoOfThreeHandleOctetsAnswersSessionHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);

        var body = new List<byte>();
        TpmCommandFrameHarness.AppendUInt32(body, (uint)TpmRh.TPM_RH_ENDORSEMENT);
        TpmCommandFrameHarness.AppendUInt32(body, (uint)TpmRh.TPM_RH_NULL);
        byte[] frame = TpmCommandFrameHarness.BuildFrame(
            (ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)TpmCcConstants.TPM_CC_GetSessionAuditDigest, [.. body]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 2), code,
            "Table 103: @privacyAdminHandle (index 0) and @signHandle (index 1) read cleanly from an eight-octet handle area; sessionHandle (index 2) is the field whose own read fails, so the refusal is handle-encoded TPM_RC_INSUFFICIENT at index 2.");
    }

    /// <summary>
    /// <c>TPM2_GetCapability()</c>'s parameter core is <c>capability</c>, <c>property</c>, then
    /// <c>propertyCount</c> (TPM 2.0 Library Part 3, clause 30.2, Table 238, three UINT32 parameters): a frame
    /// carrying exactly the four octets that carry <c>capability</c> and none for <c>property</c> unmarshals
    /// <c>capability</c> cleanly and fails on <c>property</c>'s own read, parameter-encoded
    /// <c>TPM_RC_INSUFFICIENT</c> at index 1.
    /// </summary>
    [TestMethod]
    public async Task GetCapabilityWithOnlyCapabilityOctetsAnswersPropertyParameter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(GetCapabilityWithOnlyCapabilityOctetsAnswersPropertyParameter), pool, TestContext.CancellationToken).ConfigureAwait(false);

        var body = new List<byte>();
        TpmCommandFrameHarness.AppendUInt32(body, (uint)TpmCapConstants.TPM_CAP_TPM_PROPERTIES);
        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(TpmCcConstants.TPM_CC_GetCapability, ReadOnlySpan<uint>.Empty, [.. body]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 1), code,
            "Table 238: capability (index 0) reads cleanly from a four-octet parameter area; property (index 1) is the field whose own read fails, so the refusal is parameter-encoded TPM_RC_INSUFFICIENT at index 1.");
    }

    /// <summary>
    /// The <c>propertyCount</c> counterpart of <see cref="GetCapabilityWithOnlyCapabilityOctetsAnswersPropertyParameter"/>:
    /// a frame carrying exactly the eight octets that carry <c>capability</c> and <c>property</c> unmarshals
    /// both cleanly and fails on <c>propertyCount</c>'s own read (Table 238), parameter-encoded
    /// <c>TPM_RC_INSUFFICIENT</c> at index 2.
    /// </summary>
    [TestMethod]
    public async Task GetCapabilityWithOnlyCapabilityAndPropertyOctetsAnswersPropertyCountParameter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(GetCapabilityWithOnlyCapabilityAndPropertyOctetsAnswersPropertyCountParameter), pool, TestContext.CancellationToken).ConfigureAwait(false);

        var body = new List<byte>();
        TpmCommandFrameHarness.AppendUInt32(body, (uint)TpmCapConstants.TPM_CAP_TPM_PROPERTIES);
        TpmCommandFrameHarness.AppendUInt32(body, 0);
        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(TpmCcConstants.TPM_CC_GetCapability, ReadOnlySpan<uint>.Empty, [.. body]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 2), code,
            "Table 238: capability (index 0) and property (index 1) read cleanly from an eight-octet parameter area; propertyCount (index 2) is the field whose own read fails, so the refusal is parameter-encoded TPM_RC_INSUFFICIENT at index 2.");
    }

    /// <summary>
    /// <c>TPM2_DictionaryAttackParameters()</c>'s parameter core is <c>newMaxTries</c>,
    /// <c>newRecoveryTime</c>, then <c>lockoutRecovery</c> (TPM 2.0 Library Part 3, clause 25.3, Table 212,
    /// three UINT32 parameters): a frame carrying exactly the four octets that carry <c>newMaxTries</c> and none
    /// for <c>newRecoveryTime</c> unmarshals <c>newMaxTries</c> cleanly and fails on <c>newRecoveryTime</c>'s
    /// own read, parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 1.
    /// </summary>
    [TestMethod]
    public async Task DictionaryAttackParametersWithOnlyNewMaxTriesOctetsAnswersNewRecoveryTimeParameter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(DictionaryAttackParametersWithOnlyNewMaxTriesOctetsAnswersNewRecoveryTimeParameter), pool, TestContext.CancellationToken).ConfigureAwait(false);

        var body = new List<byte>();
        TpmCommandFrameHarness.AppendUInt32(body, 3);
        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_DictionaryAttackParameters, [(uint)TpmRh.TPM_RH_LOCKOUT], [.. body]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 1), code,
            "Table 212: newMaxTries (index 0) reads cleanly from a four-octet parameter area; newRecoveryTime (index 1) is the field whose own read fails, so the refusal is parameter-encoded TPM_RC_INSUFFICIENT at index 1.");
    }

    /// <summary>
    /// <c>TPM2_HierarchyControl()</c>'s parameter core is <c>enable</c> then <c>state</c> (TPM 2.0 Library Part
    /// 3, clause 24.2, Table 193, a UINT32 followed by a one-octet <c>TPMI_YES_NO</c>): a frame carrying exactly
    /// the four octets that carry <c>enable</c> and none for <c>state</c> unmarshals <c>enable</c> cleanly and
    /// fails on <c>state</c>'s own read, parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 1 — TPM 2.0
    /// Library Part 2, clause 6.6.2, Table 15's parameter designation, reached on the password-authorized wire
    /// form.
    /// </summary>
    [TestMethod]
    public async Task HierarchyControlWithOnlyEnableOctetsAnswersStateParameter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(HierarchyControlWithOnlyEnableOctetsAnswersStateParameter), pool, TestContext.CancellationToken).ConfigureAwait(false);

        var body = new List<byte>();
        TpmCommandFrameHarness.AppendUInt32(body, (uint)TpmRh.TPM_RH_OWNER);
        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_HierarchyControl, [(uint)TpmRh.TPM_RH_OWNER], [.. body]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 1), code,
            "Table 193: enable (index 0) reads cleanly from a four-octet parameter area; state (index 1) is the field whose own read fails, so the refusal is parameter-encoded TPM_RC_INSUFFICIENT at index 1.");
    }

    /// <summary>
    /// <c>TPM2_NV_Read()</c>'s parameter core is <c>size</c> then <c>offset</c> (TPM 2.0 Library Part 3, clause
    /// 31.13, Table 265, two UINT16 parameters): a frame carrying exactly the two octets that carry <c>size</c>
    /// and none for <c>offset</c> unmarshals <c>size</c> cleanly and fails on <c>offset</c>'s own read,
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 1.
    /// </summary>
    [TestMethod]
    public async Task NvReadWithOnlySizeOctetsAnswersOffsetParameter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(NvReadWithOnlySizeOctetsAnswersOffsetParameter), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendUInt16(parameters, 4); //size present, parameter 0.

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_NV_Read, [(uint)TpmRh.TPM_RH_OWNER, TpmHandleRanges.NV_INDEX_FIRST + 1], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 1), code,
            "Table 265: size (index 0) reads cleanly from a two-octet parameter area; offset (index 1) is the field whose own read fails, so the refusal is parameter-encoded TPM_RC_INSUFFICIENT at index 1.");
    }

    /// <summary>
    /// <c>TPM2_NV_Certify()</c>'s parameter core continues with <c>size</c> then <c>offset</c> (TPM 2.0 Library
    /// Part 3, clause 31.16, Table 271, the third and fourth parameters): on the all-password wire form, a frame
    /// carrying a well-formed <c>qualifyingData</c> and <c>inScheme</c> (selector <c>TPM_ALG_NULL</c>) followed
    /// by exactly the two octets that carry <c>size</c> and none for <c>offset</c> unmarshals <c>size</c>
    /// cleanly and fails on <c>offset</c>'s own read, parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 3.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyWithOnlySizeOctetsAnswersOffsetParameter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(NvCertifyWithOnlySizeOctetsAnswersOffsetParameter), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //qualifyingData: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendUInt16(parameters, (ushort)TpmAlgIdConstants.TPM_ALG_NULL); //inScheme selector, parameter 1.
        TpmCommandFrameHarness.AppendUInt16(parameters, 4); //size present, parameter 2.

        byte[] passwordSlot = TpmCommandFrameHarness.BuildPasswordSlotOctets();
        byte[] authorizationArea = [.. passwordSlot, .. passwordSlot];
        byte[] frame = TpmCommandFrameHarness.FrameCommandWithRawAuthorizationArea(
            TpmCcConstants.TPM_CC_NV_Certify, [0x8000_0001, (uint)TpmRh.TPM_RH_OWNER, 0x0100_0001], authorizationArea, authorizationArea.Length, [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 3), code,
            "Table 271: size (index 2) reads cleanly once qualifyingData and inScheme have unmarshaled; offset (index 3) is the field whose own read fails, so the refusal is parameter-encoded TPM_RC_INSUFFICIENT at index 3.");
    }

    /// <summary>
    /// <c>TPM2_PolicyNV()</c>'s parameter core continues with <c>offset</c> then <c>operation</c> (TPM 2.0
    /// Library Part 3, clause 23.9, Table 156, the second and third parameters): a frame carrying a well-formed
    /// <c>operandB</c> followed by exactly the two octets that carry <c>offset</c> and none for
    /// <c>operation</c> unmarshals <c>offset</c> cleanly and fails on <c>operation</c>'s own read,
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 2.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvWithOnlyOffsetOctetsAnswersOperationParameter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyNvWithOnlyOffsetOctetsAnswersOperationParameter), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //operandB: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendUInt16(parameters, 0); //offset present, parameter 1.

        byte[] frame = TpmCommandFrameHarness.FramePasswordAuthorizedCommand(
            TpmCcConstants.TPM_CC_PolicyNV, [(uint)TpmRh.TPM_RH_OWNER, TpmHandleRanges.NV_INDEX_FIRST + 1, 0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 2), code,
            "Table 156: offset (index 1) reads cleanly once operandB has unmarshaled; operation (index 2) is the field whose own read fails, so the refusal is parameter-encoded TPM_RC_INSUFFICIENT at index 2.");
    }

    /// <summary>
    /// <c>TPM2_PolicyCounterTimer()</c>'s parameter core continues with <c>offset</c> then <c>operation</c>
    /// (TPM 2.0 Library Part 3, clause 23.10, Table 158, the second and third parameters): a frame carrying a
    /// well-formed <c>operandB</c> followed by exactly the two octets that carry <c>offset</c> and none for
    /// <c>operation</c> unmarshals <c>offset</c> cleanly and fails on <c>operation</c>'s own read,
    /// parameter-encoded <c>TPM_RC_INSUFFICIENT</c> at index 2.
    /// </summary>
    [TestMethod]
    public async Task PolicyCounterTimerWithOnlyOffsetOctetsAnswersOperationParameter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(PolicyCounterTimerWithOnlyOffsetOctetsAnswersOperationParameter), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendTpm2b(parameters, ReadOnlySpan<byte>.Empty); //operandB: well-formed empty, parameter 0.
        TpmCommandFrameHarness.AppendUInt16(parameters, 0); //offset present, parameter 1.

        byte[] frame = TpmCommandFrameHarness.FrameNoSessionsCommand(TpmCcConstants.TPM_CC_PolicyCounterTimer, [0x0300_0001], [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 2), code,
            "Table 158: offset (index 1) reads cleanly once operandB has unmarshaled; operation (index 2) is the field whose own read fails, so the refusal is parameter-encoded TPM_RC_INSUFFICIENT at index 2.");
    }

    /// <summary>
    /// <c>TPM2_PolicyAuthorizeNV()</c> reads its approved policy as a <c>TPMT_HA</c> out of an NV Index's OWN
    /// DATA — never out of a command parameter (TPM 2.0 Library Part 3, clause 23.22). Table 15 designates the
    /// handle, session, or PARAMETER in error; the Index's stored bytes are none of the three, so a truncated
    /// encoding, a failing algorithm check, or a digest that fails to equal the policy session's own
    /// policyDigest — a mismatch between the Index's stored content and the session, neither of which is one
    /// command parameter — answers bare, unmodified — Table 15's closing sentence: "If an implementation is not
    /// able to designate the handle, session, or parameter in error, then P and N will be zero." Proves all five
    /// sites this shape covers, so a later change cannot "fix" a condition that is not a property of one
    /// designable field.
    /// </summary>
    /// <param name="indexData">The NV Index's malformed <c>TPMT_HA</c> content.</param>
    /// <param name="expectedCode">The bare response code the malformation answers.</param>
    /// <param name="simulatorName">A per-case simulator identifier.</param>
    /// <param name="reason">The assertion message naming which <c>TPMT_HA</c> rule the row proves.</param>
    private async Task AssertPolicyAuthorizeNvIndexContentStaysBareAsync(byte[] indexData, TpmRcConstants expectedCode, string simulatorName, string reason)
    {
        const uint NvIndex = 0x0100_00C1;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync(simulatorName, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();

        await PolicySweepHarness.DefineOwnerReadableIndexAsync(tpm, registry, pool, NvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        await PolicySweepHarness.WriteOwnerIndexAsync(tpm, registry, pool, NvIndex, indexData, TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(PolicySweepHarness.SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
            using(StartAuthSessionResponse started = startResult.Value)
            {
                sessionHandle = started.SessionHandle.Value;
            }

            TpmResult<PolicyAuthorizeNvResponse> authorizeResult = await tpm.PolicyAuthorizeNvAsync(NvIndex, NvIndex, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(authorizeResult.IsSuccess, "A malformed Index TPMT_HA must be refused.");
            Assert.AreEqual(expectedCode, authorizeResult.ResponseCode, reason);
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An Index holding fewer octets than a <c>TPM_ALG_ID</c> needs stays bare <c>TPM_RC_INSUFFICIENT</c>.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeNvIndexTooShortForTheAlgorithmFieldStaysBare()
    {
        await AssertPolicyAuthorizeNvIndexContentStaysBareAsync(
            [0x00], TpmRcConstants.TPM_RC_INSUFFICIENT,
            nameof(PolicyAuthorizeNvIndexTooShortForTheAlgorithmFieldStaysBare),
            "A one-octet Index cannot even hold a TPM_ALG_ID; the reference's own unmarshal pass-through stays bare TPM_RC_INSUFFICIENT (Table 15's closing sentence).").ConfigureAwait(false);
    }

    /// <summary>
    /// An Index whose algorithm field is well-formed but whose digest is truncated stays bare
    /// <c>TPM_RC_INSUFFICIENT</c> — the SECOND, distinct <c>TPMT_HA</c> unmarshal shortfall from the one above.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeNvIndexDigestTruncatedStaysBare()
    {
        byte[] indexData = new byte[2 + 10];
        BinaryPrimitives.WriteUInt16BigEndian(indexData, (ushort)TpmAlgIdConstants.TPM_ALG_SHA256);

        await AssertPolicyAuthorizeNvIndexContentStaysBareAsync(
            indexData, TpmRcConstants.TPM_RC_INSUFFICIENT,
            nameof(PolicyAuthorizeNvIndexDigestTruncatedStaysBare),
            "A well-formed SHA-256 TPM_ALG_ID followed by fewer than 32 digest octets is the second, distinct TPMT_HA unmarshal shortfall; the reference's own pass-through stays bare TPM_RC_INSUFFICIENT (Table 15's closing sentence).").ConfigureAwait(false);
    }

    /// <summary>
    /// An Index naming a hash algorithm this simulator does not implement stays bare <c>TPM_RC_HASH</c>.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeNvIndexUnimplementedHashAlgorithmStaysBare()
    {
        byte[] indexData = new byte[2 + 32];
        BinaryPrimitives.WriteUInt16BigEndian(indexData, (ushort)TpmAlgIdConstants.TPM_ALG_SM3_256);

        await AssertPolicyAuthorizeNvIndexContentStaysBareAsync(
            indexData, TpmRcConstants.TPM_RC_HASH,
            nameof(PolicyAuthorizeNvIndexUnimplementedHashAlgorithmStaysBare),
            "An Index naming a hash algorithm this TPM does not implement is not a designable handle, session, or parameter fault, so it is refused bare TPM_RC_HASH (Table 15's closing sentence).").ConfigureAwait(false);
    }

    /// <summary>
    /// An Index naming an implemented hash algorithm that DIFFERS from the policy session's own stays bare
    /// <c>TPM_RC_HASH</c> — the SECOND, distinct algorithm check from the one above.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeNvIndexHashAlgorithmMismatchStaysBare()
    {
        byte[] indexData = new byte[2 + 20];
        BinaryPrimitives.WriteUInt16BigEndian(indexData, (ushort)TpmAlgIdConstants.TPM_ALG_SHA1);

        await AssertPolicyAuthorizeNvIndexContentStaysBareAsync(
            indexData, TpmRcConstants.TPM_RC_HASH,
            nameof(PolicyAuthorizeNvIndexHashAlgorithmMismatchStaysBare),
            "An Index naming an implemented algorithm that differs from the SHA-256 session's own is not a designable handle, session, or parameter fault, so it is refused bare TPM_RC_HASH (Table 15's closing sentence).").ConfigureAwait(false);
    }

    /// <summary>
    /// An Index holding a well-formed <c>TPMT_HA</c> — an implemented algorithm matching the policy session's
    /// own, a fully present digest — whose digest VALUE differs from the session's own policyDigest stays bare
    /// <c>TPM_RC_VALUE</c>: the FIFTH, last reference-bare site this shape covers. The mismatch is between the
    /// Index's stored content and the session's policyDigest, neither of which is one command parameter Table
    /// 15 can index.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeNvIndexDigestMismatchStaysBare()
    {
        byte[] indexData = new byte[2 + 32];
        BinaryPrimitives.WriteUInt16BigEndian(indexData, (ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        indexData.AsSpan(2).Fill(0xFF); //Any non-zero digest differs from a freshly started session's own Zero Digest.

        await AssertPolicyAuthorizeNvIndexContentStaysBareAsync(
            indexData, TpmRcConstants.TPM_RC_VALUE,
            nameof(PolicyAuthorizeNvIndexDigestMismatchStaysBare),
            "A well-formed SHA-256 TPMT_HA whose digest differs from the policy session's own policyDigest is not a property of one designable field — Table 15's closing sentence gives bare TPM_RC_VALUE.").ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_NV_Write()</c> updates an Ordinary or PIN Index only; a Counter, Bit Field or Extend Index is
    /// modified through its own dedicated command instead (TPM 2.0 Library Part 3, clause 31.7.1). The
    /// CONDITION is not "nvIndex is malformed", it is "this command does not apply to this Index's TYPE", which
    /// Table 15's three designable categories (handle, session, parameter) have no slot for — the mismatch
    /// answers bare <c>TPM_RC_ATTRIBUTES</c>, unmodified. Table 15's closing sentence: "If an implementation is
    /// not able to designate the handle, session, or parameter in error, then P and N will be zero."
    /// </summary>
    [TestMethod]
    public async Task NvWriteOfAnExtendIndexStaysBare()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(NvWriteOfAnExtendIndexStaysBare), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);

        const uint NvIndex = 0x0100_00C2;
        byte[] indexAuth = [0x71, 0x72, 0x73, 0x74];
        TpmaNv extendType = (TpmaNv)((uint)TpmNt.TPM_NT_EXTEND << TpmaNvFields.TPM_NT_SHIFT);
        await DefineNvIndexForResponseCodeDesignationAsync(tpm, registry, pool, NvIndex, indexAuth, extendType, dataSize: 32).ConfigureAwait(false);

        using TpmPasswordSession indexAuthSession = TpmPasswordSession.Create(indexAuth, pool);
        using Tpm2bMaxNvBuffer data = Tpm2bMaxNvBuffer.Create(new byte[1], pool);
        var input = new NvWriteInput(NvIndex, NvIndex, data, Offset: 0);

        TpmResult<NvWriteResponse> result = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, input, [indexAuthSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "TPM2_NV_Write() must refuse an Extend Index once authorization has succeeded.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode,
            "The command/Index-type mismatch is a property of neither a handle, a session nor a parameter, so the reference's own bare TPM_RC_ATTRIBUTES stays unmodified (Table 15's closing sentence).");
    }

    /// <summary>
    /// The SAME command/Index-type mismatch (TPM 2.0 Library Part 3, clause 31.7.1) reached through
    /// <c>TPM2_NV_Write()</c>'s SESSION wire form's owner arm, over a genuinely started HMAC session: Table 15's
    /// three designable categories (handle, session, parameter) have no slot for "this command does not apply
    /// to this Index's TYPE" on this wire form either, so it answers the same bare <c>TPM_RC_ATTRIBUTES</c> the
    /// all-password form's own proof gives it — Table 15's closing sentence: "If an implementation is not able
    /// to designate the handle, session, or parameter in error, then P and N will be zero."
    /// </summary>
    [TestMethod]
    public async Task NvWriteOfAnExtendIndexOverAnHmacSessionStaysBare()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(NvWriteOfAnExtendIndexOverAnHmacSessionStaysBare), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, pool, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_NV_ReadPublic, TpmResponseCodec.NvReadPublic);

        const uint NvIndex = 0x0100_00C3;
        byte[] indexAuth = [0x81, 0x82, 0x83, 0x84];
        TpmaNv extendType = (TpmaNv)((uint)TpmNt.TPM_NT_EXTEND << TpmaNvFields.TPM_NT_SHIFT);
        await DefineNvIndexForResponseCodeDesignationAsync(
            tpm, registry, pool, NvIndex, indexAuth, extendType | TpmaNv.TPMA_NV_OWNERWRITE, dataSize: 32).ConfigureAwait(false);

        TpmResult<NvReadPublicResponse> readPublicResult = await TpmCommandExecutor.ExecuteAsync<NvReadPublicResponse>(
            tpm, new NvReadPublicInput(NvIndex), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(readPublicResult.IsSuccess, $"NV_ReadPublic failed: '{readPublicResult.ResponseCode}'.");
        byte[] indexName;
        using(NvReadPublicResponse readPublic = readPublicResult.Value)
        {
            indexName = readPublic.NvName.Span.ToArray();
        }

        (uint sessionHandle, TpmSession ownerSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(
            tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(ownerSession)
            {
                using Tpm2bMaxNvBuffer data = Tpm2bMaxNvBuffer.Create(new byte[1], pool);
                var input = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, NvIndex, data, Offset: 0);

                //cpHash covers every command handle once any slot is a real session (Part 1, clause 15.7,
                //equation 15); the owner's Name IS its permanent handle value (Part 1, clause 13, Table 9).
                ReadOnlyMemory<byte>[] handleNames = [HandleFormName((uint)TpmRh.TPM_RH_OWNER), indexName];
                TpmResult<NvWriteResponse> result = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
                    tpm, input, [ownerSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(result.IsSuccess, "TPM2_NV_Write()'s session wire form must refuse an Extend Index once authorization has succeeded.");
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode,
                    "The command/Index-type mismatch is a property of neither a handle, a session nor a parameter on the session wire form either, so the reference's own bare TPM_RC_ATTRIBUTES stays unmodified (Table 15's closing sentence).");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>The handle-form Name of a permanent handle: its four big-endian octets (TPM 2.0 Library Part 1, clause 13, Table 9).</summary>
    /// <param name="handle">The permanent handle.</param>
    /// <returns>The Name.</returns>
    private static byte[] HandleFormName(uint handle)
    {
        byte[] name = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(name, handle);

        return name;
    }

    /// <summary>
    /// <c>TPM2_CreatePrimary()</c>'s hierarchy admissibility check runs ahead of the handle-area's own
    /// authorization walk (TPM 2.0 Library Part 3, clause 24.1, Table 191's <c>primaryHandle</c>; clause 5.4
    /// precedes clause 5.6; Part 1, clause 10.2): a hierarchy whose enable is CLEAR answers bare
    /// <c>TPM_RC_HIERARCHY</c>. The disabled state is itself neither a handle, session, nor parameter fault
    /// Table 15 can index, so P and N stay zero — Table 15's closing sentence: "If an implementation is not
    /// able to designate the handle, session, or parameter in error, then P and N will be zero."
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryOverADisabledHierarchyStaysBare()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(CreatePrimaryOverADisabledHierarchyStaysBare), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl);

        TpmResult<HierarchyControlResponse> disableResult = await tpm.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_ENDORSEMENT, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disableResult.IsSuccess, $"HierarchyControl (disable endorsement) failed: '{disableResult.ResponseCode}'.");

        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_ENDORSEMENT, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "TPM2_CreatePrimary() must refuse a disabled hierarchy.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_HIERARCHY, result.ResponseCode,
            "A disabled hierarchy's admissibility check is not a designable handle, session or parameter fault at this point in the handle-area walk, so the reference's own bare TPM_RC_HIERARCHY stays unmodified (Table 15's closing sentence).");
    }

    /// <summary>
    /// TPM 2.0 Library Part 3, clause 5.2 "Command Header Validation" defines three checks on the command
    /// header before any handle or parameter walk begins: the <c>tag</c> is either
    /// <c>TPM_ST_NO_SESSIONS</c> or <c>TPM_ST_SESSIONS</c> (<c>TPM_RC_BAD_TAG</c>); the declared
    /// <c>commandSize</c> agrees with the octet count actually received (<c>TPM_RC_COMMAND_SIZE</c>); and the
    /// command code is one this TPM implements (<c>TPM_RC_COMMAND_CODE</c>). The three rows below prove the
    /// tag check and the <c>commandSize</c> check in its two observable forms — a frame too short to hold the
    /// fixed 10-octet header at all, and a well-formed-length frame whose declared <c>commandSize</c>
    /// disagrees with the octets actually received — both of which precede the point at which a failure could
    /// be attributed to any handle, session, or parameter. All three answers are format-zero and carry no
    /// designation: Table 15's closing sentence, "If an implementation is not able to designate the handle,
    /// session, or parameter in error, then P and N will be zero," applies to each. This row proves the
    /// frame-too-short case.
    /// </summary>
    [TestMethod]
    public async Task AFrameShorterThanTheHeaderStaysBareCommandSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(AFrameShorterThanTheHeaderStaysBareCommandSize), pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] frame = new byte[TpmHeader.HeaderSize - 1];
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_COMMAND_SIZE, code,
            "A frame too short to hold even the fixed 10-octet header precedes any handle or parameter walk, so it is not a designable fault — the reference's own bare TPM_RC_COMMAND_SIZE stays unmodified (Table 15's closing sentence).");
    }

    /// <summary>
    /// The header's declared <c>commandSize</c> must equal the octet count actually received (TPM 2.0 Library
    /// Part 3, clause 5.2). A disagreement is answered bare for the same reason
    /// <see cref="AFrameShorterThanTheHeaderStaysBareCommandSize"/> is: nothing past the header has unmarshaled
    /// yet, so no handle or parameter can be blamed (Table 15's closing sentence).
    /// </summary>
    [TestMethod]
    public async Task ADeclaredSizeDisagreeingWithTheActualFrameStaysBareCommandSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(ADeclaredSizeDisagreeingWithTheActualFrameStaysBareCommandSize), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendUInt16(parameters, 4); //bytesRequested: TPM2_GetRandom()'s well-formed sole parameter.

        byte[] wellFormedFrame = TpmCommandFrameHarness.FrameNoSessionsCommand(TpmCcConstants.TPM_CC_GetRandom, [], [.. parameters]);
        byte[] truncatedFrame = wellFormedFrame[..^1]; //One octet short of the header's own declared commandSize.
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, truncatedFrame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_COMMAND_SIZE, code,
            "The declared commandSize and the octets actually received disagree before any handle or parameter walk begins, so it is not a designable fault — the reference's own bare TPM_RC_COMMAND_SIZE stays unmodified (Table 15's closing sentence).");
    }

    /// <summary>
    /// Only <c>TPM_ST_NO_SESSIONS</c> and <c>TPM_ST_SESSIONS</c> are structurally admissible command tags (TPM
    /// 2.0 Library Part 3, clause 5.2). Answered bare for the same reason the two size checks above are: the
    /// tag is read before any handle or parameter unmarshal begins, so no handle or parameter can be blamed
    /// (Table 15's closing sentence).
    /// </summary>
    [TestMethod]
    public async Task AStructurallyInadmissibleTagStaysBareBadTag()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(AStructurallyInadmissibleTagStaysBareBadTag), pool, TestContext.CancellationToken).ConfigureAwait(false);

        List<byte> parameters = [];
        TpmCommandFrameHarness.AppendUInt16(parameters, 4); //bytesRequested: TPM2_GetRandom()'s well-formed sole parameter.

        byte[] frame = TpmCommandFrameHarness.BuildFrame(0x0000, (uint)TpmCcConstants.TPM_CC_GetRandom, [.. parameters]);
        TpmRcConstants code = await TpmCommandFrameHarness.SubmitRawAsync(simulator, pool, frame, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_TAG, code,
            "A tag that is neither TPM_ST_NO_SESSIONS nor TPM_ST_SESSIONS is read before any handle or parameter unmarshal begins, so it is not a designable fault — the reference's own bare TPM_RC_BAD_TAG stays unmodified (Table 15's closing sentence).");
    }

    /// <summary>
    /// Defines a password-authorized NV Index (<c>TPMA_NV_AUTHREAD</c>/<c>TPMA_NV_AUTHWRITE</c> SET, plus
    /// <paramref name="typeAttributes"/>) under the owner hierarchy for a response-code designation proof — no
    /// data is written, since the proofs that use this fixture reach their target check before the Index's
    /// contents are ever read.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="auth">The Index's authorization value.</param>
    /// <param name="typeAttributes">
    /// The <c>TPMA_NV</c> Index-type shift (<see cref="TpmaNvFields.TPM_NT_SHIFT"/>) to OR in beyond the
    /// default read/write pair — zero (<c>TPM_NT_ORDINARY</c>) unless the caller needs a Counter, Bit Field or
    /// Extend Index.
    /// </param>
    /// <param name="dataSize">The Index's declared data size — 1 unless <paramref name="typeAttributes"/> names a type with its own required width (8 for Counter/Bits, the Name algorithm's digest size for Extend).</param>
    private async Task DefineNvIndexForResponseCodeDesignationAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, ReadOnlyMemory<byte> auth, TpmaNv typeAttributes = default, ushort dataSize = 1)
    {
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth indexAuth = Tpm2bAuth.Create(auth.Span, pool);
        using Tpm2bDigest emptyPolicy = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool);
        using var publicInfo = new TpmsNvPublic(
            nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | typeAttributes, emptyPolicy, dataSize);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, indexAuth, publicInfo);

        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, defineInput, [ownerAuth], null, pool, registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
    }

    /// <summary>
    /// A hand-marshaled <c>TPM2_MakeCredential()</c> input whose <c>credential</c> and <c>objectName</c>
    /// <c>TPM2B</c> fields each carry an independently declared size, so a malformed field can ride the
    /// production executor's own session authorization and command-HMAC computation over a genuine companion
    /// session — the sessions-tag wire form's own parser is reached only through a resolved handle and a
    /// verified authorization area, which only the executor's real session machinery can produce.
    /// </summary>
    /// <param name="handle">The credential key handle.</param>
    /// <param name="credentialOctets">The <c>credential</c> field's actual octets.</param>
    /// <param name="declaredCredentialSize">The size declared for <c>credential</c>, independent of <paramref name="credentialOctets"/>'s length.</param>
    /// <param name="objectNameOctets">The <c>objectName</c> field's actual octets.</param>
    /// <param name="declaredObjectNameSize">The size declared for <c>objectName</c>, independent of <paramref name="objectNameOctets"/>'s length.</param>
    private sealed class RawMakeCredentialInput(
        uint handle, ReadOnlyMemory<byte> credentialOctets, int declaredCredentialSize, ReadOnlyMemory<byte> objectNameOctets, int declaredObjectNameSize): ITpmCommandInput
    {
        /// <summary>The <c>TPM2_MakeCredential()</c> command code.</summary>
        public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_MakeCredential;

        /// <summary>
        /// <c>credential</c> is the first parameter and carries an explicit size field (TPM 2.0 Library Part 3,
        /// clause 12.6, Table 28), the shape Part 1, clause 18.1 requires of an encryptable parameter.
        /// </summary>
        public bool FirstCommandParameterIsEncryptable => true;

        /// <summary>
        /// <c>handle</c> carries Auth Index None (Table 28), so the first authorization-area slot over this
        /// command is always a companion, never an authorizer.
        /// </summary>
        public bool IsFirstHandleAuthorized => false;

        /// <summary>The handle area plus the two hand-declared <c>TPM2B</c> fields.</summary>
        /// <returns>The serialized size.</returns>
        public int GetSerializedSize() =>
            sizeof(uint) + sizeof(ushort) + credentialOctets.Length + sizeof(ushort) + objectNameOctets.Length;

        /// <summary>Writes <c>handle</c>.</summary>
        /// <param name="writer">The writer.</param>
        public void WriteHandles(ref TpmWriter writer) => writer.WriteUInt32(handle);

        /// <summary>Writes <c>credential</c> then <c>objectName</c>, each under its own declared size.</summary>
        /// <param name="writer">The writer.</param>
        public void WriteParameters(ref TpmWriter writer)
        {
            writer.WriteUInt16((ushort)declaredCredentialSize);
            writer.WriteBytes(credentialOctets.Span);
            writer.WriteUInt16((ushort)declaredObjectNameSize);
            writer.WriteBytes(objectNameOctets.Span);
        }
    }

    /// <summary>Marshals a well-formed HMAC-key <c>TPM2B_PUBLIC</c> the same way <see cref="HmacKeyHarness.CreateHmacKeyAsync"/> builds its template, for a parameter-area probe that needs an admissible <c>objectPublic</c> ahead of a later malformed field.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The marshaled <c>TPM2B_PUBLIC</c> octets.</returns>
    private static byte[] BuildWellFormedHmacKeyPublicAreaOctets(BaseMemoryPool pool)
    {
        using Tpm2bPublic template = Tpm2bPublic.CreateHmacKeyTemplate(
            HmacKeyHarness.NameAlg, TpmAlgIdConstants.TPM_ALG_SHA256, pool, authPolicy: ReadOnlySpan<byte>.Empty,
            noDa: true, userWithAuth: true, isDuplicable: true, isRestricted: false, isSensitiveDataOrigin: false);
        int size = template.GetSerializedSize();
        byte[] bytes = new byte[size];
        var writer = new TpmWriter(bytes);
        template.WriteTo(ref writer);

        return bytes;
    }
}
