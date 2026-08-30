using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Nv;
using Verifiable.Tpm.Extensions.Pin;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_NV_ChangeAuth</c> - atomic in-place rotation of an NV Index's own authorization value -
/// against the in-house behavioural <see cref="TpmSimulator"/>, entirely in-process and with no external
/// assets, through the same production command path production code uses
/// (<see cref="TpmCommandExecutor"/>, the real <see cref="NvChangeAuthInput"/>, and the
/// <c>ChangePinAsync</c> verb pair).
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the command exists.</b> Changing a PIN by undefining and redefining the Index destroys the Index
/// in between - its <c>pinLimit</c>, its written state, and its accumulated <c>pinCount</c> all go with it.
/// <c>TPM2_NV_ChangeAuth</c> replaces the authorization value alone
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, Section 31.15.1: "If successful, the authorization secret (authValue) of the
/// NV Index associated with nvIndex is changed"), so the Index never ceases to exist and its Name - computed
/// over <c>TPMS_NV_PUBLIC</c>, which does not contain the authValue - does not move.
/// </para>
/// <para>
/// <b>ADMIN role has no authValue path on an NV Index.</b> Part 3, Section 31.15.1 states the requirement
/// unconditionally: the command "requires that a policy session be used for authorization of nvIndex so that
/// the ADMIN role may be asserted and that commandCode in the policy session context shall be
/// TPM_CC_NV_ChangeAuth". Part 1, Section 16.2's ADMIN bullet offers an authValue alternative only for an
/// object whose <c>adminWithPolicy</c> is CLEAR, and an NV Index carries no such attribute, so a password or
/// plain HMAC session can never authorize this command - the negatives below pin exactly that.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorNvChangeAuthTests
{
    /// <summary>The session and policy hash algorithm used throughout; also the Name algorithm every PIN Fail Index the verbs define carries.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The SHA-256 digest width in octets - the <c>newAuth</c> ceiling for a SHA-256 nameAlg Index (Part 1, Section 16.6.4.2).</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>Every RSA storage-parent-shaped template this simulator builds fixes nameAlg to SHA-256.</summary>
    private const TpmAlgIdConstants TpmKeyNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA public exponent the framework RSA key generator uses (TPM 2.0 Library Part 2, Table 228).</summary>
    private const uint DefaultRsaExponent = 65537;

    /// <summary>The declared data area size of a <c>TPM_NT_PIN_FAIL</c> Index: the whole 8-octet <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> (Part 2, Section 13.3).</summary>
    private const ushort PinCounterParametersSize = 8;

    /// <summary>The primary PIN Fail Index handle: its most-significant octet is TPM_HT_NV_INDEX (0x01).</summary>
    private const uint PinIndexHandle = 0x0100_00C1;

    /// <summary>The <c>TPMA_NV</c> set of an ordinary, dictionary-attack-exempt Index the policy-structure negatives define directly.</summary>
    private const TpmaNv OrdinaryAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>
    /// The <c>TPMA_NV</c> set a provisioned PIN Fail Index carries, restated here rather than read back from the
    /// wire so the Name transcription depends on nothing the implementation under test reports:
    /// <c>TPM_NT_PIN_FAIL</c> with its spec-mandated <c>TPMA_NV_NO_DA</c> (TPM 2.0 Library Part 1, Section
    /// 35.2.6.1), Index-authValue reads, owner-hierarchy provisioning and reporting, and the
    /// <c>TPMA_NV_WRITTEN</c> the provisioning write sets.
    /// </summary>
    private const TpmaNv ProvisionedPinFailAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_OWNERREAD | TpmaNv.TPMA_NV_NO_DA
        | TpmaNv.TPMA_NV_WRITTEN | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_FAIL << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>
    /// The <c>TPMA_NV</c> set a PIN Fail Index is DEFINED with - <see cref="ProvisionedPinFailAttributes"/> minus
    /// the <c>TPMA_NV_WRITTEN</c> the first write sets (TPM 2.0 Library Part 3, Section 31.7) - for the Indexes
    /// this file defines directly rather than through the enrollment verb, so their authPolicy can be chosen.
    /// </summary>
    private const TpmaNv PinFailDefinitionAttributes = ProvisionedPinFailAttributes & ~TpmaNv.TPMA_NV_WRITTEN;

    /// <summary>The stored-PIN form an Index is enrolled with; the value every rotation here starts from.</summary>
    private static byte[] OldPinHash { get; } = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xEE, 0xFF];

    /// <summary>The replacement stored-PIN form every rotation here rotates to, distinct from <see cref="OldPinHash"/>.</summary>
    private static byte[] NewPinHash { get; } = [0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78];

    /// <summary>A wrong stored-PIN form, distinct from both <see cref="OldPinHash"/> and <see cref="NewPinHash"/>.</summary>
    private static byte[] WrongPinHash { get; } = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];

    /// <summary>A third stored-PIN form, distinct from every other value here, for a SECOND rotation of one Index.</summary>
    private static byte[] SecondNewPinHash { get; } = [0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8A, 0x9B, 0xAC, 0xBD, 0xCE, 0xDF, 0xE0, 0xF1, 0x02];

    /// <summary>The authorization value the directly-defined ordinary Indexes of the policy-structure negatives carry.</summary>
    private static byte[] OrdinaryIndexAuth { get; } = [0x0A, 0x0B, 0x0C, 0x0D];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The rotation end to end over the production executor: the correct old PIN rotates the Index authValue
    /// in place, the old value stops authorizing (a session-encoded <c>TPM_RC_BAD_AUTH</c> that burns a
    /// retry), the new value authorizes and resets <c>pinCount</c> - and the Index survives intact, because
    /// <c>TPM2_NV_ChangeAuth</c> changes "the authorization secret (authValue) of the NV Index" and nothing
    /// else (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 3, Section 31.15.1). <c>pinLimit</c>, <c>TPMA_NV_WRITTEN</c>, and the
    /// Index's Name are all read back across the rotation and must be unchanged, and no
    /// <c>TPM2_NV_UndefineSpace</c>/<c>TPM2_NV_DefineSpace</c> may appear on the wire - the Index is never
    /// destroyed and recreated, which is the whole point of the command.
    /// </summary>
    [TestMethod]
    public async Task ChangePinAsyncRotatesTheIndexAuthValueInPlaceWithoutEverUndefiningTheIndex()
    {
        const uint PinLimit = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync);

        await EnrollAsync(plainDevice, PinIndexHandle, OldPinHash, PinLimit).ConfigureAwait(false);

        TpmResult<TpmPinCounterParameters> beforeVerify = await plainDevice.VerifyPinAsync(
            PinIndexHandle, OldPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(beforeVerify.IsSuccess, $"The enrolled PIN must verify before the rotation: '{beforeVerify.ResponseCode}'.");
        Assert.AreEqual(PinLimit, beforeVerify.Value.PinLimit, "The enrolled Index must carry the provisioned pinLimit.");

        (byte[] nameBefore, TpmaNv attributesBefore) = await ReadPublicAsync(plainDevice, PinIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(attributesBefore.HasFlag(TpmaNv.TPMA_NV_WRITTEN), "The provisioning write must have set TPMA_NV_WRITTEN before the rotation.");

        var capturedCommands = new List<byte[]>();
        using TpmDevice capturingDevice = CreateCapturingDevice(simulator, capturedCommands);

        TpmResult<NvChangeAuthResponse> rotationResult = await capturingDevice.ChangePinAsync(
            PinIndexHandle, OldPinHash, NewPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rotationResult.IsSuccess, $"ChangePinAsync with the correct old PIN must succeed: '{rotationResult.ResponseCode}'.");

        bool sawChangeAuth = false;
        foreach(byte[] command in capturedCommands)
        {
            TpmCcConstants code = ReadCommandCode(command);
            sawChangeAuth |= code == TpmCcConstants.TPM_CC_NV_ChangeAuth;
            Assert.AreNotEqual(
                TpmCcConstants.TPM_CC_NV_UndefineSpace, code,
                "An atomic rotation must never undefine the Index - that is the destructive path this command replaces.");
            Assert.AreNotEqual(
                TpmCcConstants.TPM_CC_NV_DefineSpace, code,
                "An atomic rotation must never redefine the Index - a fresh definition would discard its counter window.");
        }

        Assert.IsTrue(sawChangeAuth, "The rotation must genuinely have gone out as TPM2_NV_ChangeAuth.");

        (byte[] nameAfter, TpmaNv attributesAfter) = await ReadPublicAsync(plainDevice, PinIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(
            nameAfter.AsSpan().SequenceEqual(nameBefore),
            "The Index Name must be byte-identical across the rotation: authValue lives outside TPMS_NV_PUBLIC, which is what the Name is computed over.");
        Assert.AreEqual(attributesBefore, attributesAfter, "TPMA_NV_WRITTEN and every other attribute must survive the rotation untouched.");

        TpmResult<TpmPinCounterParameters> oldPinResult = await plainDevice.VerifyPinAsync(
            PinIndexHandle, OldPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(oldPinResult.IsSuccess, "The OLD PIN must no longer authorize the rotated Index.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, oldPinResult.BaseError,
            "A PIN Fail Index is spec-mandated TPMA_NV_NO_DA, so a mismatch is TPM_RC_BAD_AUTH, never TPM_RC_AUTH_FAIL.");
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, oldPinResult.ResponseCode,
            "The mismatch is rejected by the HMAC session, so the raw wire code carries the session-index modifier.");

        TpmResult<TpmPinCounterParameters> afterOldFailure = await plainDevice.ReadPinCountersAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(afterOldFailure.IsSuccess, $"ReadPinCountersAsync failed: '{afterOldFailure.ResponseCode}'.");
        Assert.AreEqual(1u, afterOldFailure.Value.PinCount, "The rejected old-PIN attempt must have advanced the surviving counter by exactly one.");
        Assert.AreEqual(PinLimit, afterOldFailure.Value.PinLimit, "pinLimit must survive the rotation: the Index was never redefined.");

        TpmResult<TpmPinCounterParameters> newPinResult = await plainDevice.VerifyPinAsync(
            PinIndexHandle, NewPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(newPinResult.IsSuccess, $"The NEW PIN must authorize the rotated Index: '{newPinResult.ResponseCode}'.");
        Assert.AreEqual(0u, newPinResult.Value.PinCount, "A successful authorization below pinLimit resets pinCount to zero.");
        Assert.AreEqual(PinLimit, newPinResult.Value.PinLimit, "pinLimit must still be the provisioned one after the rotation.");
    }

    /// <summary>
    /// A rotation attempt is a PIN attempt: the composed policy folds <c>TPM2_PolicyAuthValue</c>, so a wrong
    /// old PIN is an HMAC mismatch answered with a session-encoded <c>TPM_RC_BAD_AUTH</c> and it burns a retry
    /// against the surviving counter (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 1, Section 16.6.5's policy note on the authValue term of the HMAC
    /// key, and Section 34.2.6.6's pinCount rule, which is written in terms of the authorization outcome). The
    /// Index authValue must be left alone, so the genuine old PIN still authorizes afterwards - rotation is
    /// not a throttle bypass.
    /// </summary>
    [TestMethod]
    public async Task ChangePinAsyncWithAWrongOldPinBurnsARetryAndLeavesTheAuthValueUnchanged()
    {
        const uint PinLimit = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        await EnrollAsync(device, PinIndexHandle, OldPinHash, PinLimit).ConfigureAwait(false);

        TpmResult<NvChangeAuthResponse> rotationResult = await device.ChangePinAsync(
            PinIndexHandle, WrongPinHash, NewPinHash, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(rotationResult.IsSuccess, "A rotation presenting the wrong current PIN must not be accepted.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, rotationResult.BaseError, "The wrong old PIN is an authorization mismatch on a TPMA_NV_NO_DA Index.");
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, rotationResult.ResponseCode,
            "The refusal names the offending session, so the raw wire code carries the session-index modifier.");

        TpmResult<TpmPinCounterParameters> countersResult = await device.ReadPinCountersAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(countersResult.IsSuccess, $"ReadPinCountersAsync failed: '{countersResult.ResponseCode}'.");
        Assert.AreEqual(1u, countersResult.Value.PinCount, "A single wrong-old-PIN rotation attempt must advance pinCount by exactly one.");

        TpmResult<TpmPinCounterParameters> unchangedResult = await device.VerifyPinAsync(
            PinIndexHandle, OldPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            unchangedResult.IsSuccess,
            $"A refused rotation must not have replaced the authValue, so the genuine PIN still authorizes: '{unchangedResult.ResponseCode}'.");

        TpmResult<TpmPinCounterParameters> newPinResult = await device.VerifyPinAsync(
            PinIndexHandle, NewPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, newPinResult.BaseError,
            "The replacement value of a refused rotation must never have been installed.");
    }

    /// <summary>
    /// Once <c>pinCount</c> reaches <c>pinLimit</c> the at-limit gate refuses the rotation with
    /// <c>TPM_RC_AUTH_UNAVAILABLE</c> even for the CORRECT old PIN, before any HMAC work runs
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, Section 34.2.6.6) - so the code carries no session-index modifier at all.
    /// Recovery is the owner's, not the PIN holder's: an owner-authorized counter reset restores the Index and
    /// the very same rotation then succeeds.
    /// </summary>
    [TestMethod]
    public async Task ChangePinAsyncAtPinLimitIsRefusedWithAuthUnavailableUntilTheOwnerResetsTheCounter()
    {
        const uint PinLimit = 1;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        await EnrollAsync(device, PinIndexHandle, OldPinHash, PinLimit).ConfigureAwait(false);

        TpmResult<TpmPinCounterParameters> exhaustingFailure = await device.VerifyPinAsync(
            PinIndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, exhaustingFailure.BaseError, "One wrong PIN against pinLimit == 1 must reach the limit.");

        TpmResult<NvChangeAuthResponse> blockedRotation = await device.ChangePinAsync(
            PinIndexHandle, OldPinHash, NewPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(blockedRotation.IsSuccess, "At pinLimit even the CORRECT old PIN must not rotate the Index.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, blockedRotation.ResponseCode,
            "The at-limit gate precedes the session-HMAC verification queue entirely, so no session-index modifier is applied.");

        TpmResult<NvWriteResponse> resetResult = await device.ResetPinCountAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(resetResult.IsSuccess, $"ResetPinCountAsync failed: '{resetResult.ResponseCode}'.");

        TpmResult<NvChangeAuthResponse> recoveredRotation = await device.ChangePinAsync(
            PinIndexHandle, OldPinHash, NewPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(recoveredRotation.IsSuccess, $"After the owner-authorized reset the same rotation must succeed: '{recoveredRotation.ResponseCode}'.");

        TpmResult<TpmPinCounterParameters> newPinResult = await device.VerifyPinAsync(
            PinIndexHandle, NewPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(newPinResult.IsSuccess, $"The recovered rotation must genuinely have installed the new PIN: '{newPinResult.ResponseCode}'.");
    }

    /// <summary>
    /// A plaintext password authorization on <c>nvIndex</c> is refused with <c>TPM_RC_AUTH_TYPE</c>: ADMIN role
    /// on an NV Index has no authValue path at all, so a password session is the wrong KIND of authorization
    /// rather than a wrong value (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3, Section 31.15.1's unconditional "requires that a policy session
    /// be used"; Part 1, Section 16.2 offers the authValue alternative only for an object with
    /// <c>adminWithPolicy</c> CLEAR, an attribute no NV Index has). The password carries the Index's genuine
    /// authValue here, so nothing but the authorization type can be what is refused.
    /// </summary>
    [TestMethod]
    public async Task NvChangeAuthOverAPasswordSessionIsRefusedWithAuthType()
    {
        const uint PinLimit = 3;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRotationRegistry();

        await EnrollAsync(device, PinIndexHandle, OldPinHash, PinLimit).ConfigureAwait(false);

        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(OldPinHash, pool);
        using Tpm2bAuth newAuth = Tpm2bAuth.Create(NewPinHash, pool);
        using NvChangeAuthInput input = new(PinIndexHandle, newAuth);

        TpmResult<NvChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<NvChangeAuthResponse>(
            device, input, [indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A password session must never authorize an ADMIN-role NV command.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode);

        TpmResult<TpmPinCounterParameters> unchangedResult = await device.VerifyPinAsync(
            PinIndexHandle, OldPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(unchangedResult.IsSuccess, $"The refused rotation must have left the authValue untouched: '{unchangedResult.ResponseCode}'.");
    }

    /// <summary>
    /// A plain HMAC session on <c>nvIndex</c> - a genuine cryptographic channel keyed on the Index's own
    /// authValue, everything short of a policy session - is refused with <c>TPM_RC_AUTH_TYPE</c> for the same
    /// reason the password arm is: Part 3, Section 31.15.1 requires a POLICY session, and the ADMIN role's
    /// authValue alternative in Part 1, Section 16.2 is scoped to objects with an <c>adminWithPolicy</c>
    /// attribute that NV Indexes do not have
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>). This is the case a design that treated "HMAC is stronger than a password" as
    /// sufficient would get wrong.
    /// </summary>
    [TestMethod]
    public async Task NvChangeAuthOverAnHmacSessionIsRefusedWithAuthType()
    {
        const uint PinLimit = 3;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRotationRegistry();

        await EnrollAsync(device, PinIndexHandle, OldPinHash, PinLimit).ConfigureAwait(false);
        byte[] indexName = await ReadNameAsync(device, PinIndexHandle).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (HMAC) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, pool);
            session.SetAuthValue(OldPinHash, pool);

            using Tpm2bAuth newAuth = Tpm2bAuth.Create(NewPinHash, pool);
            using NvChangeAuthInput input = new(PinIndexHandle, newAuth);

            TpmResult<NvChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<NvChangeAuthResponse>(
                device, input, [session], [indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "An HMAC session must never authorize an ADMIN-role NV command, however well keyed it is.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode);
        }
        finally
        {
            _ = await device.FlushContextAsync(sessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A policy session whose accumulated digest satisfies the Index's <c>authPolicy</c> but which never
    /// asserted <c>TPM2_PolicyCommandCode</c> at all is refused with <c>TPM_RC_POLICY_FAIL</c>: the ADMIN
    /// requirement is a conjunction, and its second half - "commandCode in the policy session context shall be
    /// TPM_CC_NV_ChangeAuth"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, Section 31.15.1; Part 1, Section 16.2's ADMIN note repeats it) - is
    /// unsatisfiable for a session that bound no command code, not merely unmatched. The Index here is defined
    /// with exactly the <c>PolicyAuthValue</c>-only digest the session reaches, so the digest half genuinely
    /// passes and only the missing command-code binding can be the refusal.
    /// </summary>
    [TestMethod]
    public async Task NvChangeAuthUnderAPolicyThatNeverBoundACommandCodeIsRefusedWithPolicyFail()
    {
        const uint IndexHandle = 0x0100_00C2;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRotationRegistry();

        byte[] authValueOnlyPolicy = ComputePolicyDigest(new TpmPolicyBuilder().WithAuthValue().Build());
        await DefineOrdinaryIndexAsync(device, pool, registry, IndexHandle, authValueOnlyPolicy).ConfigureAwait(false);

        TpmResult<NvChangeAuthResponse> result = await RotateOverPolicySessionAsync(
            device, pool, registry, IndexHandle, OrdinaryIndexAuth, NewPinHash, restrictedCommand: null).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A policy that binds no command code can never assert ADMIN role.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode);
    }

    /// <summary>
    /// A policy session that DID assert <c>TPM2_PolicyCommandCode</c>, satisfies the Index's
    /// <c>authPolicy</c> exactly, but bound a DIFFERENT command (<c>TPM_CC_NV_Read</c>) is refused with
    /// <c>TPM_RC_POLICY_CC</c> - a distinct answer from the missing-binding case above, because the caller's
    /// defect is different: the policy is the right shape but scoped to another command, which is precisely
    /// the situation Part 3, Section 31.15.1's note describes ("administrative actions on nvIndex require
    /// explicit approval while other commands may use policy that is not command-dependent",
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>). Collapsing the two codes would hide from a caller which half of the ADMIN
    /// conjunction it failed.
    /// </summary>
    [TestMethod]
    public async Task NvChangeAuthUnderAPolicyScopedToAnotherCommandIsRefusedWithPolicyCc()
    {
        const uint IndexHandle = 0x0100_00C3;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRotationRegistry();

        byte[] readScopedPolicy = ComputePolicyDigest(
            new TpmPolicyBuilder().WithAuthValue().WithCommandCode(TpmCcConstants.TPM_CC_NV_Read).Build());
        await DefineOrdinaryIndexAsync(device, pool, registry, IndexHandle, readScopedPolicy).ConfigureAwait(false);

        TpmResult<NvChangeAuthResponse> result = await RotateOverPolicySessionAsync(
            device, pool, registry, IndexHandle, OrdinaryIndexAuth, NewPinHash, TpmCcConstants.TPM_CC_NV_Read).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A policy scoped to another command must never authorize this one.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_CC, result.ResponseCode,
            "A bound-but-wrong command code is TPM_RC_POLICY_CC, distinct from the unbound case's TPM_RC_POLICY_FAIL.");
    }

    /// <summary>
    /// The <c>decrypt</c> attribute on the AUTHORIZING policy session is refused with a session-encoded
    /// <c>TPM_RC_ATTRIBUTES</c> rather than honoured. Part 1, Section 18.1's note is the reason: "A policy
    /// session that is used for parameter encryption uses authValue to calculate sessionValue even if the
    /// policy does not include TPM2_PolicyAuthValue()"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>) - an unbound, unsalted session of that shape would key the encryption of the NEW
    /// authorization value on the OLD one, protecting it against nobody who could not already guess the value
    /// being rotated away from. The attribute is set on the built command by an intervening transport, because
    /// the verb itself composes a SEPARATE decrypt session and never asks for this shape.
    /// </summary>
    [TestMethod]
    public async Task NvChangeAuthWithADecryptAttributedAuthorizingPolicySessionIsRefusedWithAttributes()
    {
        const uint PinLimit = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync);

        await EnrollAsync(plainDevice, PinIndexHandle, OldPinHash, PinLimit).ConfigureAwait(false);

        async ValueTask<TpmResult<TpmResponse>> ClaimDecryptOnChangeAuthAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == TpmCcConstants.TPM_CC_NV_ChangeAuth)
            {
                SetFirstSessionAttributeBit(bytes, handleCount: 1, (byte)TpmaSession.DECRYPT);

                return await simulator.SubmitAsync(bytes, commandPool, ct).ConfigureAwait(false);
            }

            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice tamperingDevice = TpmDevice.Create(ClaimDecryptOnChangeAuthAsync);

        TpmResult<NvChangeAuthResponse> result = await tamperingDevice.ChangePinAsync(
            PinIndexHandle, OldPinHash, NewPinHash, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A decrypt-attributed authorizing policy session must not be accepted.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, result.BaseError,
            "The refusal is about the session's attributes, not about a key or a value.");
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode,
            "The refusal names the offending session, so the raw wire code carries the session-index modifier.");

        TpmResult<TpmPinCounterParameters> unchangedResult = await plainDevice.VerifyPinAsync(
            PinIndexHandle, OldPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(unchangedResult.IsSuccess, $"The refused rotation must have left the authValue untouched: '{unchangedResult.ResponseCode}'.");
    }

    /// <summary>
    /// The size gate strips before it measures, and the order is normative rather than an optimization:
    /// "Trailing octets of zero are to be removed from any string before it is used as an authValue"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, Section 16.6.4.3) and only the remainder is measured against "the size of
    /// the digest produced by the nameAlg of the NV Index" (Part 3, Section 31.15.1; Part 1, Section 16.6.4.2).
    /// Against a SHA-256 nameAlg Index a genuine 33-octet value is therefore <c>TPM_RC_SIZE</c> while a
    /// 32-octet value padded out with trailing zeros is accepted - and the value actually installed is the
    /// stripped one, proven by verifying with the 32-octet form afterwards. A gate that measured first would
    /// reject the padded value; one that never measured would accept the 33-octet one.
    /// </summary>
    [TestMethod]
    public async Task NvChangeAuthStripsTrailingZerosBeforeMeasuringNewAuthAgainstTheNameAlgDigestSize()
    {
        const uint PinLimit = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        await EnrollAsync(device, PinIndexHandle, OldPinHash, PinLimit).ConfigureAwait(false);

        //One octet past the SHA-256 digest width with no trailing zero to strip: nothing can bring it inside
        //the limit, so the gate must refuse it. Every octet is non-zero, including the last.
        byte[] overlongNewAuth = new byte[Sha256DigestSize + 1];
        for(int i = 0; i < overlongNewAuth.Length; i++)
        {
            overlongNewAuth[i] = (byte)(i + 1);
        }

        TpmResult<NvChangeAuthResponse> overlongResult = await device.ChangePinAsync(
            PinIndexHandle, OldPinHash, overlongNewAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(overlongResult.IsSuccess, "A newAuth longer than the nameAlg digest size must not be accepted.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, overlongResult.ResponseCode);

        TpmResult<TpmPinCounterParameters> stillOldResult = await device.VerifyPinAsync(
            PinIndexHandle, OldPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(stillOldResult.IsSuccess, $"A refused over-long rotation must leave the authValue untouched: '{stillOldResult.ResponseCode}'.");

        //The same 32 meaningful octets padded past the limit with zeros: stripping brings it back to exactly
        //the digest width, so the gate must accept it and install the stripped form.
        byte[] strippedNewAuth = overlongNewAuth.AsSpan(0, Sha256DigestSize).ToArray();
        byte[] paddedNewAuth = new byte[Sha256DigestSize + 8];
        strippedNewAuth.CopyTo(paddedNewAuth.AsSpan());

        TpmResult<NvChangeAuthResponse> paddedResult = await device.ChangePinAsync(
            PinIndexHandle, OldPinHash, paddedNewAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            paddedResult.IsSuccess,
            $"A value that is over-long only because of trailing zero octets must be accepted after stripping: '{paddedResult.ResponseCode}'.");

        TpmResult<TpmPinCounterParameters> strippedVerify = await device.VerifyPinAsync(
            PinIndexHandle, strippedNewAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            strippedVerify.IsSuccess,
            $"The value installed must be the STRIPPED form, so the 32-octet value authorizes: '{strippedVerify.ResponseCode}'.");
    }

    /// <summary>
    /// The response-key changeover, pinned on both sides at once. Part 3, Section 31.15.1: "Since the NV Index
    /// authorization is changed before the response HMAC is calculated, the newAuth value is used when
    /// generating the response HMAC key if required"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>) - and it IS required here, because the composed policy asserts
    /// <c>TPM2_PolicyAuthValue</c>. This test recomputes both candidate response HMACs off-wire from the
    /// captured exchange (Part 1, Section 16.6.5's equation 17 over Section 15.8's rpHash): the NEW-keyed one
    /// must equal what the TPM actually framed, and an active transport that swaps in the OLD-keyed one - the
    /// exact response a TPM that had not yet committed the rotation would produce - must be REJECTED by the
    /// host session with <c>TPM_RC_AUTH_FAIL</c>. A host that failed to move its own key would accept it.
    /// </summary>
    [TestMethod]
    public async Task NvChangeAuthResponseIsKeyedOnTheNewAuthValueAndAnOldKeyedOneIsRejectedByTheHost()
    {
        const uint PinLimit = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync);

        await EnrollAsync(plainDevice, PinIndexHandle, OldPinHash, PinLimit).ConfigureAwait(false);

        bool forged = false;
        async ValueTask<TpmResult<TpmResponse>> ForgeOldKeyedResponseAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            byte[] commandBytes = command.ToArray();
            TpmResult<TpmResponse> genuine = await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
            if(ReadCommandCode(commandBytes) != TpmCcConstants.TPM_CC_NV_ChangeAuth || !genuine.IsSuccess)
            {
                return genuine;
            }

            byte[] responseBytes;
            using(TpmResponse genuineResponse = genuine.Value)
            {
                responseBytes = genuineResponse.AsReadOnlySpan().ToArray();
            }

            forged = true;

            //The authorizing session is the first in the command's authorization area and the first entry in
            //the response's, by the ordering the executor parses and verifies in.
            byte[] commandNonceCaller = ReadCommandSessionNonces(commandBytes, handleCount: 1)[0];
            (int hmacStart, int hmacLength, byte[] responseNonceTpm, byte sessionAttributes) = ReadFirstResponseSessionEntry(responseBytes);

            byte[] hmacData = await BuildResponseHmacDataAsync(
                responseBytes, responseNonceTpm, commandNonceCaller, sessionAttributes, commandPool).ConfigureAwait(false);

            byte[] newKeyedHmac = await ComputeSessionHmacAsync(StripTrailingZeros(NewPinHash), hmacData, commandPool).ConfigureAwait(false);
            byte[] oldKeyedHmac = await ComputeSessionHmacAsync(StripTrailingZeros(OldPinHash), hmacData, commandPool).ConfigureAwait(false);

            Assert.HasCount(hmacLength, newKeyedHmac, "The framed response HMAC must be the session hash's full width.");
            Assert.IsTrue(
                responseBytes.AsSpan(hmacStart, hmacLength).SequenceEqual(newKeyedHmac),
                "The TPM must key the response HMAC on the NEW authorization value: the rotation is committed before the response is framed.");
            Assert.IsFalse(
                newKeyedHmac.AsSpan().SequenceEqual(oldKeyedHmac),
                "The two candidate keys must produce different HMACs, or this test would prove nothing.");

            oldKeyedHmac.CopyTo(responseBytes.AsSpan(hmacStart));

            return CopyToResponse(responseBytes, commandPool);
        }

        using TpmDevice forgingDevice = TpmDevice.Create(ForgeOldKeyedResponseAsync);

        TpmResult<NvChangeAuthResponse> result = await forgingDevice.ChangePinAsync(
            PinIndexHandle, OldPinHash, NewPinHash, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(forged, "The forging transport must have observed and replaced the NV_ChangeAuth response.");
        Assert.IsFalse(result.IsSuccess, "A response keyed on the pre-rotation authorization value must never be accepted.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_FAIL, result.ResponseCode,
            "A response authorization that does not verify is an integrity failure, not a parse failure.");

        //The command itself was genuine, so the TPM did rotate; only the response framing was tampered with.
        //Verifying with the new value confirms the rejection was about the response key, not the command.
        TpmResult<TpmPinCounterParameters> newPinResult = await plainDevice.VerifyPinAsync(
            PinIndexHandle, NewPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(newPinResult.IsSuccess, $"The genuine command did rotate the Index: '{newPinResult.ResponseCode}'.");
    }

    /// <summary>
    /// The replacement value rides <c>TPM2_NV_ChangeAuth</c>'s <c>newAuth</c> parameter under a decrypt
    /// session, so it never appears as wire content, and the value being rotated away from never appears
    /// either - it only ever enters as the authorizing session's HMAC key term (Part 1, Section 16.6.5's
    /// equation 17, <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>). Every command byte the verb sends is captured and searched.
    /// </summary>
    [TestMethod]
    public async Task ChangePinAsyncNeverSendsEitherPinHashAsPlaintextOnTheWire()
    {
        const uint PinLimit = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync);

        await EnrollAsync(plainDevice, PinIndexHandle, OldPinHash, PinLimit).ConfigureAwait(false);

        var capturedCommands = new List<byte[]>();
        using TpmDevice capturingDevice = CreateCapturingDevice(simulator, capturedCommands);

        TpmResult<NvChangeAuthResponse> rotationResult = await capturingDevice.ChangePinAsync(
            PinIndexHandle, OldPinHash, NewPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rotationResult.IsSuccess, $"ChangePinAsync failed: '{rotationResult.ResponseCode}'.");

        Assert.IsNotEmpty(capturedCommands, "The capturing wrapper must have observed the rotation's commands.");
        foreach(byte[] command in capturedCommands)
        {
            Assert.IsFalse(
                ContainsSubsequence(command, NewPinHash),
                "The replacement stored PIN form must never appear as a contiguous byte sequence on the wire.");
            Assert.IsFalse(
                ContainsSubsequence(command, OldPinHash),
                "The stored PIN form being rotated away from must never appear as a contiguous byte sequence on the wire.");
        }
    }

    /// <summary>
    /// The confidentiality boundary of the replacement value, proven both ways by ONE independent keystream
    /// derivation, mirroring the enrollment KAT. A session that is neither bound nor salted has
    /// <c>sessionKey</c> = the Empty Buffer
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, Section 16.6.9), and a decrypt-only session's <c>sessionValue</c> is that
    /// session key alone (Section 18.1), so the XOR keystream over <c>newAuth</c> (Section 18.2) derives from
    /// the public <c>TPM2_StartAuthSession</c> nonces and nothing else: the unsalted default's encryption is
    /// structural, and this test recovers the replacement PIN form from the captured exchange to say so
    /// honestly. The salted overload folds a salt only the TPM can recover (Section 16.6.12, equation 25), so
    /// the SAME derivation no longer recovers it - that is where genuine confidentiality lives.
    /// </summary>
    [TestMethod]
    public async Task TheUnsaltedRotationYieldsToThePublicNonceKeystreamButTheSaltedOneDoesNot()
    {
        const uint PinLimit = 3;
        const uint UnsaltedIndexHandle = 0x0100_00D1;
        const uint SaltedIndexHandle = 0x0100_00D2;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRsaKeyRegistry();

        using(TpmDevice enrollDevice = TpmDevice.Create(simulator.SubmitAsync))
        {
            await EnrollAsync(enrollDevice, UnsaltedIndexHandle, OldPinHash, PinLimit).ConfigureAwait(false);
            await EnrollAsync(enrollDevice, SaltedIndexHandle, OldPinHash, PinLimit).ConfigureAwait(false);
        }

        var unsaltedPairs = new List<(TpmCcConstants Code, byte[] Command, byte[] Response)>();
        using(TpmDevice unsaltedDevice = CreateRecordingDevice(simulator, unsaltedPairs))
        {
            TpmResult<NvChangeAuthResponse> unsaltedResult = await unsaltedDevice.ChangePinAsync(
                UnsaltedIndexHandle, OldPinHash, NewPinHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(unsaltedResult.IsSuccess, $"The unsalted rotation failed: '{unsaltedResult.ResponseCode}'.");
        }

        byte[] unsaltedRecovered = await RecoverNewAuthWithTheEmptySessionKeyAsync(unsaltedPairs, pool).ConfigureAwait(false);
        Assert.IsTrue(
            unsaltedRecovered.AsSpan().SequenceEqual(NewPinHash),
            "The unsalted decrypt session's key is the Empty Buffer, so the public-nonce derivation recovers the replacement PIN form - structural encryption, not confidential.");

        var saltedPairs = new List<(TpmCcConstants Code, byte[] Command, byte[] Response)>();
        using(TpmDevice saltedDevice = CreateRecordingDevice(simulator, saltedPairs))
        {
            using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(saltedDevice, registry, pool).ConfigureAwait(false);
            uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

            try
            {
                ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
                TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

                TpmResult<NvChangeAuthResponse> saltedResult = await saltedDevice.ChangePinAsync(
                    SaltedIndexHandle, OldPinHash, NewPinHash,
                    tpmKeyHandle, modulus, DefaultRsaExponent, TpmKeyNameAlg, rsaBackend.EncryptOaep, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(saltedResult.IsSuccess, $"The salted rotation failed: '{saltedResult.ResponseCode}'.");
            }
            finally
            {
                _ = await saltedDevice.FlushContextAsync(tpmKeyHandle, CancellationToken.None).ConfigureAwait(false);
            }
        }

        byte[] saltedRecovered = await RecoverNewAuthWithTheEmptySessionKeyAsync(saltedPairs, pool).ConfigureAwait(false);
        Assert.IsFalse(
            saltedRecovered.AsSpan().SequenceEqual(NewPinHash),
            "The salted decrypt session folds a secret only the TPM can recover, so the public derivation that unlocked the unsalted default cannot recover the replacement PIN form.");
    }

    /// <summary>
    /// Every Index the PIN verbs enroll now carries the rotation <c>authPolicy</c>, which is inside
    /// <c>TPMS_NV_PUBLIC</c> and therefore inside the Name: <c>Name = nameAlg ‖ H_nameAlg(handle ‖
    /// TPMS_NV_PUBLIC)</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, Section 13, Table 9; Part 2, Section 13.6, Table 251). This transcribes
    /// that recipe independently - from the marshaled field order, with the policy digest re-derived from Part
    /// 3, Section 23.17's and Section 23.11's own extend formulas - and requires the Name the TPM reports to
    /// equal it. An enrollment that installed an Empty Policy (which can never satisfy an ADMIN check, Part 1,
    /// Section 10.2) would produce a different Name and fail here.
    /// </summary>
    [TestMethod]
    public async Task AnEnrolledPinIndexNameFoldsTheNonEmptyRotationAuthPolicy()
    {
        const uint PinLimit = 3;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        await EnrollAsync(device, PinIndexHandle, OldPinHash, PinLimit).ConfigureAwait(false);

        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(publicResult.IsSuccess, $"NvReadPublicAsync failed: '{publicResult.ResponseCode}'.");

        using NvReadPublicResponse indexPublic = publicResult.Value;

        byte[] expectedAuthPolicy = await ComputeRotationAuthPolicyAsync(pool).ConfigureAwait(false);
        Assert.IsTrue(
            indexPublic.NvPublic.AuthPolicy.AsReadOnlySpan().SequenceEqual(expectedAuthPolicy),
            "An enrolled PIN Index must carry the PolicyAuthValue-then-PolicyCommandCode(TPM_CC_NV_ChangeAuth) digest as its authPolicy - an Empty Policy is permanently rotation-incapable.");
        Assert.AreEqual(
            ProvisionedPinFailAttributes, indexPublic.NvPublic.Attributes,
            "Installing the rotation policy must not have changed any other field of the enrolled Index's public area.");

        byte[] expectedName = await ComputeIndependentNvNameAsync(
            pool, PinIndexHandle, SessionAlg, ProvisionedPinFailAttributes, expectedAuthPolicy, PinCounterParametersSize).ConfigureAwait(false);
        Assert.IsTrue(
            indexPublic.NvName.Span.SequenceEqual(expectedName),
            "The Index Name must equal the spec recipe transcribed over the public area INCLUDING the non-empty authPolicy.");
    }

    /// <summary>
    /// A rotation authorized by a policy that folds ONLY <c>TPM2_PolicyCommandCode(TPM_CC_NV_ChangeAuth)</c> is
    /// <c>pinCount</c>-neutral in BOTH directions. Part 3, Section 31.15.1 asks for nothing beyond that assertion
    /// to satisfy ADMIN role, and Part 1, Section 16.6.5's policy note confines the authValue term of the session
    /// HMAC key to a policy that ALSO asserted <c>TPM2_PolicyAuthValue</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>) - so this session proves nothing about the current PIN, and Section 34.2.6.6's
    /// counter rule, written entirely in terms of the authorization outcome, has no outcome to record. The
    /// session is unbound and unsalted, so its session key is the Empty Buffer (Section 16.6.9) and the whole
    /// HMAC key is empty: the command authorization is recomputed here from public transcript data alone, which
    /// is what "no authValue term" means concretely. The counter must therefore neither advance nor reset, and an
    /// Index AT its limit must still rotate - the at-limit gate hangs off the same authValue fold - while the
    /// value installed must genuinely become the live one.
    /// </summary>
    [TestMethod]
    public async Task NvChangeAuthUnderACommandCodeOnlyPolicyRotatesWithoutTouchingThePinThrottle()
    {
        const uint IndexHandle = 0x0100_00C5;
        const uint PinLimit = 3;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRotationRegistry();

        byte[] commandCodeOnlyPolicy = await ComputeCommandCodeOnlyRotationPolicyAsync(pool).ConfigureAwait(false);
        await DefinePinFailIndexDirectlyAsync(
            device, pool, registry, IndexHandle, OldPinHash, commandCodeOnlyPolicy, pinCount: 0, pinLimit: PinLimit).ConfigureAwait(false);

        var pairs = new List<(TpmCcConstants Code, byte[] Command, byte[] Response)>();
        using(TpmDevice recordingDevice = CreateRecordingDevice(simulator, pairs))
        {
            TpmResult<NvChangeAuthResponse> rotationResult = await RotateOverCommandCodeOnlyPolicySessionAsync(
                recordingDevice, pool, registry, IndexHandle, NewPinHash).ConfigureAwait(false);
            Assert.IsTrue(
                rotationResult.IsSuccess,
                $"A policy asserting only PolicyCommandCode(TPM_CC_NV_ChangeAuth) satisfies the ADMIN gate on its own: '{rotationResult.ResponseCode}'.");
        }

        byte[] indexName = await ComputeIndependentNvNameAsync(
            pool, IndexHandle, SessionAlg, ProvisionedPinFailAttributes, commandCodeOnlyPolicy, PinCounterParametersSize).ConfigureAwait(false);
        byte[] framedHmac = ReadCommandSessionHmac(FirstCommand(pairs, TpmCcConstants.TPM_CC_NV_ChangeAuth), handleCount: 1, sessionIndex: 0);
        byte[] emptyKeyedHmac = await RecomputeAuthorizingCommandHmacAsync(
            pairs, indexName, ReadOnlyMemory<byte>.Empty, pool).ConfigureAwait(false);
        Assert.IsTrue(
            framedHmac.AsSpan().SequenceEqual(emptyKeyedHmac),
            "Without PolicyAuthValue the HMAC key is the Empty Buffer end to end, so the authorization is reproducible from the transcript alone - no PIN was proven.");

        TpmResult<TpmPinCounterParameters> afterRotation = await device.ReadPinCountersAsync(
            ReadOnlyMemory<byte>.Empty, IndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(afterRotation.IsSuccess, $"ReadPinCountersAsync failed: '{afterRotation.ResponseCode}'.");
        Assert.AreEqual(0u, afterRotation.Value.PinCount, "A rotation that folded no authValue must not have reset a counter it never earned.");
        Assert.AreEqual(PinLimit, afterRotation.Value.PinLimit, "The rotation touches the authValue alone, never the data area the counter window lives in.");

        TpmResult<TpmPinCounterParameters> oldPinResult = await device.VerifyPinAsync(
            IndexHandle, OldPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, oldPinResult.BaseError, "The value rotated away from must no longer authorize the Index.");

        TpmResult<TpmPinCounterParameters> newPinResult = await device.VerifyPinAsync(
            IndexHandle, NewPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(newPinResult.IsSuccess, $"The replacement value must be the live one after the rotation: '{newPinResult.ResponseCode}'.");

        //Drive the Index to its threshold through the owner-authorized write arm rather than through failed
        //attempts, so the at-limit state is established without any authorization outcome of its own.
        await WritePinCounterParametersAsync(device, pool, registry, IndexHandle, pinCount: PinLimit, pinLimit: PinLimit).ConfigureAwait(false);

        TpmResult<TpmPinCounterParameters> atLimit = await device.ReadPinCountersAsync(
            ReadOnlyMemory<byte>.Empty, IndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(atLimit.IsSuccess, $"ReadPinCountersAsync failed: '{atLimit.ResponseCode}'.");
        Assert.AreEqual(PinLimit, atLimit.Value.PinCount, "The provisioning write must have put the Index exactly at its threshold.");

        TpmResult<NvChangeAuthResponse> atLimitRotation = await RotateOverCommandCodeOnlyPolicySessionAsync(
            device, pool, registry, IndexHandle, SecondNewPinHash).ConfigureAwait(false);
        Assert.IsTrue(
            atLimitRotation.IsSuccess,
            $"An at-limit Index must still rotate under a command-code-only policy - the at-limit gate is conditional on the policy having folded the authValue, so this rotation must never meet it: '{(atLimitRotation.IsTpmError ? atLimitRotation.ResponseCode : default)}'.");

        TpmResult<TpmPinCounterParameters> afterAtLimitRotation = await device.ReadPinCountersAsync(
            ReadOnlyMemory<byte>.Empty, IndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(afterAtLimitRotation.IsSuccess, $"ReadPinCountersAsync failed: '{afterAtLimitRotation.ResponseCode}'.");
        Assert.AreEqual(PinLimit, afterAtLimitRotation.Value.PinCount, "Neutrality runs the other way too: the rotation must not have cleared the exhausted counter.");

        TpmResult<NvWriteResponse> resetResult = await device.ResetPinCountAsync(
            ReadOnlyMemory<byte>.Empty, IndexHandle, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(resetResult.IsSuccess, $"ResetPinCountAsync failed: '{resetResult.ResponseCode}'.");

        TpmResult<TpmPinCounterParameters> secondNewPinResult = await device.VerifyPinAsync(
            IndexHandle, SecondNewPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            secondNewPinResult.IsSuccess,
            $"The at-limit rotation must genuinely have installed its replacement value: '{secondNewPinResult.ResponseCode}'.");
    }

    /// <summary>
    /// A command-HMAC failure on the DECRYPT companion refuses the rotation without moving <c>pinCount</c> in
    /// either direction. Part 1, Section 34.2.6.6 ties the counter to the authorization of the Index - "If the
    /// authorization fails, pinCount is incremented for a PIN Fail Index"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>) - and the companion session authorizes no entity at all (Part 1, Section 18.1: a
    /// session used only for parameter encryption keys on its own session key), so its failure says nothing about
    /// whether the caller knew the PIN. The counter is deliberately parked at one before the attempt: a refusal
    /// that burned a retry would read two, and one that credited the authorizing session's success would read
    /// zero, so only "untouched" passes.
    /// </summary>
    /// <summary>
    /// An NV Index whose <c>authPolicy</c> is the Empty Policy has no policy path at all: Part 4
    /// <c>IsAuthPolicyAvailable</c>'s NV arm tests the policy's SIZE ("If the policy size is not zero, check if
    /// policy can be used"), so <c>TPM2_NV_ChangeAuth()</c> over a policy session is refused
    /// <c>TPM_RC_AUTH_UNAVAILABLE</c> before the digest is ever compared — unlike a loaded object, whose policy is
    /// always available and whose empty authPolicy fails the compare instead.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6; clause 31.13; Part 4 CheckAuthSession/IsAuthPolicyAvailable</see>.
    /// </summary>
    [TestMethod]
    public async Task NvChangeAuthOnAnIndexWithNoAuthPolicyIsRefusedWithAuthUnavailable()
    {
        const uint IndexHandle = 0x0100_00C9;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRotationRegistry();
        await DefineOrdinaryIndexAsync(device, pool, registry, IndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        TpmResult<NvChangeAuthResponse> result = await RotateOverCommandCodeOnlyPolicySessionAsync(device, pool, registry, IndexHandle, NewPinHash).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "An Index with no authPolicy must not be rotated over a policy session.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, result.ResponseCode, "An NV Index with an empty authPolicy has no policy path: TPM_RC_AUTH_UNAVAILABLE.");
    }

    /// <summary>
    /// A <c>TPM2_PolicyParameters()</c> binding on the rotation policy is judged against
    /// <c>TPM2_NV_ChangeAuth()</c>'s real parameter area — <c>H(TPM_CC_NV_ChangeAuth || newAuth)</c> with the Index
    /// Name skipped: the policy <c>PolicyCommandCode(TPM_CC_NV_ChangeAuth)</c> then <c>PolicyParameters(pHash)</c>
    /// admits the rotation to exactly the bound <c>newAuth</c> and refuses any other value with a bare
    /// <c>TPM_RC_POLICY_FAIL</c> — a policy may pin the value an Index may be rotated TO.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.24; clause 31.13, Table 269; Part 4 CompareParametersHash</see>.
    /// </summary>
    [TestMethod]
    public async Task NvChangeAuthUnderAParametersBindingRotatesOnlyToTheBoundNewAuth()
    {
        const uint IndexHandle = 0x0100_00CA;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRotationRegistry();

        //pHash = SHA-256(TPM_CC_NV_ChangeAuth || TPM2B_AUTH(newAuth)) over the value the policy admits — an
        //independent in-test oracle over the wire shape of the command's one parameter.
        byte[] parametersHash = ComputeNvChangeAuthParametersHash(NewPinHash);
        byte[] policy = ComputePolicyDigest(new TpmPolicyBuilder()
            .WithCommandCode(TpmCcConstants.TPM_CC_NV_ChangeAuth)
            .WithParameters(parametersHash)
            .Build());
        await DefineOrdinaryIndexAsync(device, pool, registry, IndexHandle, policy).ConfigureAwait(false);

        TpmResult<NvChangeAuthResponse> otherResult = await RotateOverParametersPolicySessionAsync(
            device, pool, registry, IndexHandle, parametersHash, SecondNewPinHash).ConfigureAwait(false);
        Assert.IsFalse(otherResult.IsSuccess, "A newAuth other than the bound one must be refused.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, otherResult.ResponseCode, "The pHash binding mismatch is the policy's own bare TPM_RC_POLICY_FAIL.");

        TpmResult<NvChangeAuthResponse> boundResult = await RotateOverParametersPolicySessionAsync(
            device, pool, registry, IndexHandle, parametersHash, NewPinHash).ConfigureAwait(false);
        Assert.IsTrue(boundResult.IsSuccess, $"The bound newAuth must rotate: '{boundResult.ResponseCode}'.");
    }

    [TestMethod]
    public async Task NvChangeAuthWithATamperedDecryptSessionHmacIsRefusedWithoutMovingThePinCounter()
    {
        const uint PinLimit = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync);

        await EnrollAsync(plainDevice, PinIndexHandle, OldPinHash, PinLimit).ConfigureAwait(false);

        TpmResult<TpmPinCounterParameters> burn = await plainDevice.VerifyPinAsync(
            PinIndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, burn.BaseError, "The deliberate wrong attempt must have been refused, so the counter now stands at one.");

        bool spliced = false;
        async ValueTask<TpmResult<TpmResponse>> SpliceDecryptSessionHmacAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == TpmCcConstants.TPM_CC_NV_ChangeAuth)
            {
                FlipLastOctetOfSessionHmac(bytes, handleCount: 1, sessionIndex: 1);
                spliced = true;

                return await simulator.SubmitAsync(bytes, commandPool, ct).ConfigureAwait(false);
            }

            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice splicingDevice = TpmDevice.Create(SpliceDecryptSessionHmacAsync);

        TpmResult<NvChangeAuthResponse> result = await splicingDevice.ChangePinAsync(
            PinIndexHandle, OldPinHash, NewPinHash, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(spliced, "The splicing transport must have observed and altered the rotation command.");
        Assert.IsFalse(result.IsSuccess, "A session whose command HMAC does not verify must refuse the whole command.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError,
            "The companion session authorizes no dictionary-attack-protected entity, so its mismatch is a plain bad authorization.");
        Assert.AreEqual(
            2, result.ResponseCode.GetSessionNumber(),
            "The refusal must name the SECOND session - the one whose HMAC was altered - not the authorizing one.");

        TpmResult<TpmPinCounterParameters> counters = await plainDevice.ReadPinCountersAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(counters.IsSuccess, $"ReadPinCountersAsync failed: '{counters.ResponseCode}'.");
        Assert.AreEqual(1u, counters.Value.PinCount, "A companion session's failure is not a PIN attempt: the counter must be exactly where the earlier wrong attempt left it.");

        TpmResult<TpmPinCounterParameters> unchangedResult = await plainDevice.VerifyPinAsync(
            PinIndexHandle, OldPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(unchangedResult.IsSuccess, $"The refused rotation must have left the authValue untouched: '{unchangedResult.ResponseCode}'.");
    }

    /// <summary>
    /// Every refusal that precedes command-HMAC evaluation leaves <c>pinCount</c> exactly where it found it. Part
    /// 1, Section 34.2.6.6 makes the counter a function of the Index's own authorization outcome
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>), and a structural refusal - wrong authorization KIND (Part 3, Section 31.15.1), a
    /// policy of the wrong shape or scope (Part 1, Section 16.2's ADMIN note), or an inadmissible session
    /// attribute (Part 1, Section 18.1's note, refused by Part 3, Section 5.5 before Section 5.6's check 9 ever
    /// runs) - never produces such an outcome. The counter is parked at one first, so a burned retry and a
    /// credited success are both visible failures.
    /// </summary>
    /// <remarks>
    /// The Index here is defined directly with a <c>TPM_CC_NV_Read</c>-scoped rotation policy rather than
    /// enrolled through the verb, because <c>TPM_RC_POLICY_CC</c> is otherwise unreachable: the policyDigest gate
    /// precedes the commandCode gate, and any session reaching a rotation-capable Index's stored authPolicy has by
    /// construction asserted <c>TPM2_PolicyCommandCode(TPM_CC_NV_ChangeAuth)</c>. One Index carrying the
    /// read-scoped digest exercises all four refusals against the same counter.
    /// </remarks>
    [TestMethod]
    public async Task TheStructuralNvChangeAuthRefusalsLeaveThePinCounterWhereTheyFoundIt()
    {
        const uint IndexHandle = 0x0100_00C6;
        const uint PinLimit = 3;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRotationRegistry();

        byte[] readScopedPolicy = ComputePolicyDigest(
            new TpmPolicyBuilder().WithAuthValue().WithCommandCode(TpmCcConstants.TPM_CC_NV_Read).Build());
        await DefinePinFailIndexDirectlyAsync(
            device, pool, registry, IndexHandle, OldPinHash, readScopedPolicy, pinCount: 0, pinLimit: PinLimit).ConfigureAwait(false);

        TpmResult<TpmPinCounterParameters> burn = await device.VerifyPinAsync(
            IndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, burn.BaseError, "The deliberate wrong attempt must have been refused, so the counter now stands at one.");

        async ValueTask<TpmResult<TpmResponse>> ClaimDecryptOnChangeAuthAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == TpmCcConstants.TPM_CC_NV_ChangeAuth)
            {
                SetFirstSessionAttributeBit(bytes, handleCount: 1, (byte)TpmaSession.DECRYPT);

                return await simulator.SubmitAsync(bytes, commandPool, ct).ConfigureAwait(false);
            }

            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice decryptClaimingDevice = TpmDevice.Create(ClaimDecryptOnChangeAuthAsync);

        TpmResult<NvChangeAuthResponse> attributesResult = await RotateOverPolicySessionAsync(
            decryptClaimingDevice, pool, registry, IndexHandle, OldPinHash, NewPinHash, TpmCcConstants.TPM_CC_NV_Read).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, attributesResult.BaseError,
            "The session-attribute gate runs before the policy gates, so an otherwise digest-matching session is refused on its attributes.");
        await AssertPinCountIsAsync(device, IndexHandle, 1u, "an inadmissible session attribute").ConfigureAwait(false);

        using(TpmPasswordSession indexAuth = TpmPasswordSession.Create(OldPinHash, pool))
        {
            using Tpm2bAuth newAuth = Tpm2bAuth.Create(NewPinHash, pool);
            using NvChangeAuthInput input = new(IndexHandle, newAuth);

            TpmResult<NvChangeAuthResponse> authTypeResult = await TpmCommandExecutor.ExecuteAsync<NvChangeAuthResponse>(
                device, input, [indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_TYPE, authTypeResult.ResponseCode, "A password session is the wrong KIND of authorization for ADMIN role.");
        }

        await AssertPinCountIsAsync(device, IndexHandle, 1u, "a password authorization").ConfigureAwait(false);

        TpmResult<NvChangeAuthResponse> policyFailResult = await RotateOverPolicySessionAsync(
            device, pool, registry, IndexHandle, OldPinHash, NewPinHash, restrictedCommand: null).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, policyFailResult.ResponseCode, "A session that bound no command code can never assert ADMIN role.");
        await AssertPinCountIsAsync(device, IndexHandle, 1u, "a policy that bound no command code").ConfigureAwait(false);

        TpmResult<NvChangeAuthResponse> policyCcResult = await RotateOverPolicySessionAsync(
            device, pool, registry, IndexHandle, OldPinHash, NewPinHash, TpmCcConstants.TPM_CC_NV_Read).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_CC, policyCcResult.ResponseCode, "A policy scoped to another command is TPM_RC_POLICY_CC, the digest having matched.");
        await AssertPinCountIsAsync(device, IndexHandle, 1u, "a policy scoped to another command").ConfigureAwait(false);

        TpmResult<TpmPinCounterParameters> unchangedResult = await device.VerifyPinAsync(
            IndexHandle, OldPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(unchangedResult.IsSuccess, $"None of the refusals may have replaced the authValue: '{unchangedResult.ResponseCode}'.");
    }

    /// <summary>
    /// The offline oracle a captured rotation leaves behind, closed by salting BOTH of the verb's sessions. On the
    /// unsalted default every session key is the Empty Buffer (TPM 2.0 Library Part 1, Section 16.6.9), so the
    /// authorizing session's HMAC key is the stored PIN form alone (Section 16.6.5, equation 17): a transcript
    /// plus a candidate value reproduces the COMMAND authorization keyed on the OLD value and the RESPONSE
    /// authorization keyed on the NEW one - two guessing oracles over one exchange, and the second one is keyed on
    /// the value the caller was rotating TO
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, Section 31.15.1's response-key sentence). The salted overload folds a
    /// KDFa-derived session key only the TPM holding the salt key can reproduce (Section 16.6.12, equation 25) in
    /// FRONT of that term on both legs, so the same recomputation fails both ways. The two sessions must draw
    /// independent salts, and the authorizing one must negotiate no symmetric algorithm at all - a policy session
    /// carrying decrypt or encrypt would key parameter encryption on the authValue regardless of what the policy
    /// asserted (Section 19.1's note), which is the whole reason the replacement value rides a companion.
    /// </summary>
    [TestMethod]
    public async Task TheSaltedRotationClosesTheCommandAndResponseHmacOraclesTheUnsaltedOneLeavesOpen()
    {
        const uint PinLimit = 3;
        const uint UnsaltedIndexHandle = 0x0100_00D3;
        const uint SaltedIndexHandle = 0x0100_00D4;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRsaKeyRegistry();

        byte[] rotationPolicy = await ComputeRotationAuthPolicyAsync(pool).ConfigureAwait(false);
        byte[] unsaltedName = await ComputeIndependentNvNameAsync(
            pool, UnsaltedIndexHandle, SessionAlg, ProvisionedPinFailAttributes, rotationPolicy, PinCounterParametersSize).ConfigureAwait(false);
        byte[] saltedName = await ComputeIndependentNvNameAsync(
            pool, SaltedIndexHandle, SessionAlg, ProvisionedPinFailAttributes, rotationPolicy, PinCounterParametersSize).ConfigureAwait(false);

        var unsaltedPairs = new List<(TpmCcConstants Code, byte[] Command, byte[] Response)>();
        var saltedPairs = new List<(TpmCcConstants Code, byte[] Command, byte[] Response)>();

        using(TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync))
        {
            await EnrollAsync(plainDevice, UnsaltedIndexHandle, OldPinHash, PinLimit).ConfigureAwait(false);
            await EnrollAsync(plainDevice, SaltedIndexHandle, OldPinHash, PinLimit).ConfigureAwait(false);

            using(TpmDevice unsaltedDevice = CreateRecordingDevice(simulator, unsaltedPairs))
            {
                TpmResult<NvChangeAuthResponse> unsaltedResult = await unsaltedDevice.ChangePinAsync(
                    UnsaltedIndexHandle, OldPinHash, NewPinHash, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(unsaltedResult.IsSuccess, $"The unsalted rotation failed: '{unsaltedResult.ResponseCode}'.");
            }

            //The salt key is created and released OUTSIDE the recording bracket, so the salted transcript holds
            //exactly the exchanges the rotation itself composes.
            using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(plainDevice, registry, pool).ConfigureAwait(false);
            uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

            try
            {
                ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
                TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

                using TpmDevice saltedDevice = CreateRecordingDevice(simulator, saltedPairs);

                TpmResult<NvChangeAuthResponse> saltedResult = await saltedDevice.ChangePinAsync(
                    SaltedIndexHandle, OldPinHash, NewPinHash,
                    tpmKeyHandle, modulus, DefaultRsaExponent, TpmKeyNameAlg, rsaBackend.EncryptOaep, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(saltedResult.IsSuccess, $"The salted rotation failed: '{saltedResult.ResponseCode}'.");
            }
            finally
            {
                _ = await plainDevice.FlushContextAsync(tpmKeyHandle, CancellationToken.None).ConfigureAwait(false);
            }
        }

        ReadOnlyMemory<byte> oldKey = StripTrailingZeros(OldPinHash);
        ReadOnlyMemory<byte> newKey = StripTrailingZeros(NewPinHash);

        byte[] unsaltedFramedCommandHmac = ReadCommandSessionHmac(
            FirstCommand(unsaltedPairs, TpmCcConstants.TPM_CC_NV_ChangeAuth), handleCount: 1, sessionIndex: 0);
        byte[] unsaltedGuessedCommandHmac = await RecomputeAuthorizingCommandHmacAsync(unsaltedPairs, unsaltedName, oldKey, pool).ConfigureAwait(false);
        Assert.IsTrue(
            unsaltedFramedCommandHmac.AsSpan().SequenceEqual(unsaltedGuessedCommandHmac),
            "The unsalted default's command authorization is reproducible from the transcript and a candidate PIN - the positive control this test is measured against.");

        byte[] saltedFramedCommandHmac = ReadCommandSessionHmac(
            FirstCommand(saltedPairs, TpmCcConstants.TPM_CC_NV_ChangeAuth), handleCount: 1, sessionIndex: 0);
        byte[] saltedGuessedCommandHmac = await RecomputeAuthorizingCommandHmacAsync(saltedPairs, saltedName, oldKey, pool).ConfigureAwait(false);
        Assert.IsFalse(
            saltedFramedCommandHmac.AsSpan().SequenceEqual(saltedGuessedCommandHmac),
            "Salting the AUTHORIZING session puts a secret session key in front of the PIN term, so the correct PIN no longer reproduces the command authorization.");

        (byte[] Framed, byte[] Recomputed) unsaltedResponse =
            await RecomputeAuthorizingResponseHmacAsync(unsaltedPairs, newKey, pool).ConfigureAwait(false);
        Assert.IsTrue(
            unsaltedResponse.Framed.AsSpan().SequenceEqual(unsaltedResponse.Recomputed),
            "The unsalted default's response authorization is reproducible from the transcript and the REPLACEMENT PIN - the oracle that matters most, since it is keyed on the value being rotated to.");

        (byte[] Framed, byte[] Recomputed) saltedResponse =
            await RecomputeAuthorizingResponseHmacAsync(saltedPairs, newKey, pool).ConfigureAwait(false);
        Assert.IsFalse(
            saltedResponse.Framed.AsSpan().SequenceEqual(saltedResponse.Recomputed),
            "The same secret session key closes the response-side oracle as well, so a captured salted rotation tests neither the old nor the new value.");

        var startCommands = new List<byte[]>();
        foreach((TpmCcConstants Code, byte[] Command, byte[] Response) pair in saltedPairs)
        {
            if(pair.Code == TpmCcConstants.TPM_CC_StartAuthSession)
            {
                startCommands.Add(pair.Command);
            }
        }

        Assert.HasCount(2, startCommands, "The salted rotation composes exactly two sessions: the authorizing policy session and the decrypt companion.");

        StartAuthSessionWireFields first = ReadStartAuthSessionCommand(startCommands[0]);
        StartAuthSessionWireFields second = ReadStartAuthSessionCommand(startCommands[1]);

        Assert.IsNotEmpty(first.EncryptedSalt, "Both sessions of the salted overload carry an encrypted salt; an empty one would be the unsalted shape.");
        Assert.IsNotEmpty(second.EncryptedSalt, "Both sessions of the salted overload carry an encrypted salt; an empty one would be the unsalted shape.");
        Assert.IsFalse(
            first.EncryptedSalt.AsSpan().SequenceEqual(second.EncryptedSalt),
            "Each session must draw its own salt: one salt reused across both would make a single compromise recover both session keys.");
        Assert.IsFalse(
            first.NonceCaller.AsSpan().SequenceEqual(second.NonceCaller),
            "Each session must draw its own nonceCaller, which together with its own salt is what makes the two derived keys independent.");

        uint authorizingSessionHandle = ReadCommandSessionHandles(
            FirstCommand(saltedPairs, TpmCcConstants.TPM_CC_NV_ChangeAuth), handleCount: 1)[0];
        (byte[] Command, byte[] NonceTpm) authorizingExchange = FindStartAuthSessionExchange(saltedPairs, authorizingSessionHandle);
        StartAuthSessionWireFields authorizing = ReadStartAuthSessionCommand(authorizingExchange.Command);

        Assert.AreEqual(TpmSeConstants.TPM_SE_POLICY, authorizing.SessionType, "The session that authorizes an ADMIN-role command must be a POLICY session (Part 3, Section 31.15.1).");
        Assert.AreEqual((uint)TpmRh.TPM_RH_NULL, authorizing.Bind, "The authorizing session is unbound: Part 1, Section 34.2.8.3 forbids binding a session to a PIN Index outright.");
        Assert.AreNotEqual((uint)TpmRh.TPM_RH_NULL, authorizing.TpmKey, "The authorizing session of the salted overload is salted, so tpmKey names a loaded decrypt key.");
        Assert.AreEqual(
            TpmAlgIdConstants.TPM_ALG_NULL, authorizing.SymmetricAlgorithm,
            "No symmetric algorithm is negotiated on the authorizing session: it never carries decrypt or encrypt.");
        Assert.AreEqual(
            sizeof(ushort), authorizing.SymmetricLength,
            "A null TPMT_SYM_DEF collapses to its algorithm selector alone, so the negotiated definition occupies exactly two octets on the wire.");
    }

    /// <summary>
    /// Composes <c>TPM2_NV_ChangeAuth</c> over a policy session built to order, so a test can present a policy
    /// whose SHAPE is wrong rather than a value that is wrong: <c>TPM2_PolicyAuthValue</c> is always asserted,
    /// and <paramref name="restrictedCommand"/> selects whether a command code is bound at all and which one.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the rotation codecs.</param>
    /// <param name="nvIndex">The Index to attempt the rotation against.</param>
    /// <param name="currentAuth">The Index's current authorization value, folded into the session HMAC key.</param>
    /// <param name="newAuthValue">The replacement authorization value to send.</param>
    /// <param name="restrictedCommand">The command code to bind with <c>TPM2_PolicyCommandCode</c>, or <see langword="null"/> to bind none.</param>
    /// <returns>The rotation's raw result.</returns>
    private async Task<TpmResult<NvChangeAuthResponse>> RotateOverPolicySessionAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        uint nvIndex,
        ReadOnlyMemory<byte> currentAuth,
        ReadOnlyMemory<byte> newAuthValue,
        TpmCcConstants? restrictedCommand)
    {
        byte[] indexName = await ReadNameAsync(device, nvIndex).ConfigureAwait(false);

        TpmResult<StartAuthSessionResponse> startResult = await device.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartPolicySessionAsync failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, pool);

            TpmResult<PolicyAuthValueResponse> authValueResult = await device.PolicyAuthValueAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValueAsync failed: '{authValueResult.ResponseCode}'.");

            if(restrictedCommand is TpmCcConstants boundCommand)
            {
                TpmResult<PolicyCommandCodeResponse> commandCodeResult = await device.PolicyCommandCodeAsync(
                    sessionHandle, boundCommand, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCodeAsync failed: '{commandCodeResult.ResponseCode}'.");
            }

            session.SetAuthValue(currentAuth.Span, pool);

            using Tpm2bAuth newAuth = Tpm2bAuth.Create(newAuthValue.Span, pool);
            using NvChangeAuthInput input = new(nvIndex, newAuth);

            return await TpmCommandExecutor.ExecuteAsync<NvChangeAuthResponse>(
                device, input, [session], [indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await device.FlushContextAsync(sessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Composes <c>TPM2_NV_ChangeAuth</c> over a policy session that asserts <c>TPM2_PolicyCommandCode</c> and
    /// NOTHING else - the minimal shape Part 3, Section 31.15.1's ADMIN requirement actually demands. No
    /// authorization value is ever set on the session, so its HMAC key stays the Empty Buffer the unbound,
    /// unsalted session key already is (TPM 2.0 Library Part 1, Section 16.6.9) and the Index's own authValue
    /// takes no part in the authorization (Section 16.6.5's policy note).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the rotation codecs.</param>
    /// <param name="nvIndex">The Index to rotate.</param>
    /// <param name="newAuthValue">The replacement authorization value to send.</param>
    /// <returns>The rotation's raw result.</returns>
    /// <summary>
    /// The pHash <c>TPM2_PolicyParameters()</c> binds a rotation to: <c>SHA-256(TPM_CC_NV_ChangeAuth || TPM2B_AUTH(newAuth))</c>
    /// — the command code and the command's one parameter as framed, the Index Name skipped (TPM 2.0 Library Part
    /// 3, clause 23.24; clause 31.13, Table 269).
    /// </summary>
    /// <param name="newAuth">The replacement authValue the policy admits.</param>
    /// <returns>The pHash.</returns>
    private static byte[] ComputeNvChangeAuthParametersHash(ReadOnlySpan<byte> newAuth)
    {
        byte[] input = new byte[sizeof(uint) + sizeof(ushort) + newAuth.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, (uint)TpmCcConstants.TPM_CC_NV_ChangeAuth);
        BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(sizeof(uint)), (ushort)newAuth.Length);
        newAuth.CopyTo(input.AsSpan(sizeof(uint) + sizeof(ushort)));

        return SHA256.HashData(input);
    }

    /// <summary>
    /// Rotates the Index authValue over a REAL policy session asserting <c>PolicyCommandCode(TPM_CC_NV_ChangeAuth)</c>
    /// then <c>PolicyParameters(<paramref name="parametersHash"/>)</c>, sending <paramref name="newAuthValue"/>.
    /// </summary>
    /// <param name="device">The device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to rotate.</param>
    /// <param name="parametersHash">The pHash the session binds to.</param>
    /// <param name="newAuthValue">The replacement authValue sent.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<NvChangeAuthResponse>> RotateOverParametersPolicySessionAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> parametersHash, ReadOnlyMemory<byte> newAuthValue)
    {
        byte[] indexName = await ReadNameAsync(device, nvIndex).ConfigureAwait(false);
        TpmResult<StartAuthSessionResponse> startResult = await device.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartPolicySessionAsync failed: '{startResult.ResponseCode}'.");
        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;
        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, pool);
            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await device.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_NV_ChangeAuth, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCodeAsync failed: '{commandCodeResult.ResponseCode}'.");
            TpmResult<PolicyParametersResponse> parametersResult = await device.PolicyParametersAsync(sessionHandle, parametersHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(parametersResult.IsSuccess, $"PolicyParametersAsync failed: '{parametersResult.ResponseCode}'.");

            using Tpm2bAuth newAuth = Tpm2bAuth.Create(newAuthValue.Span, pool);
            using NvChangeAuthInput input = new(nvIndex, newAuth);

            return await TpmCommandExecutor.ExecuteAsync<NvChangeAuthResponse>(
                device, input, [session], [indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await device.FlushContextAsync(sessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async Task<TpmResult<NvChangeAuthResponse>> RotateOverCommandCodeOnlyPolicySessionAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        uint nvIndex,
        ReadOnlyMemory<byte> newAuthValue)
    {
        byte[] indexName = await ReadNameAsync(device, nvIndex).ConfigureAwait(false);

        TpmResult<StartAuthSessionResponse> startResult = await device.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartPolicySessionAsync failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, pool);

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await device.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_NV_ChangeAuth, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCodeAsync failed: '{commandCodeResult.ResponseCode}'.");

            using Tpm2bAuth newAuth = Tpm2bAuth.Create(newAuthValue.Span, pool);
            using NvChangeAuthInput input = new(nvIndex, newAuth);

            return await TpmCommandExecutor.ExecuteAsync<NvChangeAuthResponse>(
                device, input, [session], [indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await device.FlushContextAsync(sessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Defines a <c>TPM_NT_PIN_FAIL</c> Index directly with a caller-chosen <c>authPolicy</c> - a shape the
    /// enrollment verb never installs - and provisions its counter window, so a test can exercise Indexes whose
    /// rotation policy is deliberately the wrong one.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the NV_DefineSpace and NV_Write codecs.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="pinHash">The stored PIN form to install as the Index authValue.</param>
    /// <param name="authPolicy">The access policy digest to define with.</param>
    /// <param name="pinCount">The attempt count to provision.</param>
    /// <param name="pinLimit">The attempt threshold to provision.</param>
    /// <returns>A task that completes once the Index is defined and provisioned.</returns>
    private async Task DefinePinFailIndexDirectlyAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        uint nvIndex,
        ReadOnlyMemory<byte> pinHash,
        ReadOnlyMemory<byte> authPolicy,
        uint pinCount,
        uint pinLimit)
    {
        using(TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool))
        {
            using Tpm2bAuth auth = Tpm2bAuth.Create(pinHash.Span, pool);
            using Tpm2bDigest policyDigest = Tpm2bDigest.Create(authPolicy.Span, pool);
            using TpmsNvPublic publicInfo = new(nvIndex, SessionAlg, PinFailDefinitionAttributes, policyDigest, PinCounterParametersSize);
            using NvDefineSpaceInput input = new(TpmRh.TPM_RH_OWNER, auth, publicInfo);

            TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
                device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace (PIN Fail) failed: '{defineResult.ResponseCode}'.");
        }

        await WritePinCounterParametersAsync(device, pool, registry, nvIndex, pinCount, pinLimit).ConfigureAwait(false);
    }

    /// <summary>
    /// Writes a PIN Index's whole <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> window over the owner-authorized
    /// <c>TPM2_NV_Write</c> arm - the only write path a PIN Index has, since its own authValue authorizes reads
    /// alone (TPM 2.0 Library Part 1, Section 34.2.6.1) - so a test can establish an exact counter state without
    /// producing any authorization outcome of its own.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the NV_Write codec.</param>
    /// <param name="nvIndex">The PIN Index to provision.</param>
    /// <param name="pinCount">The attempt count to store.</param>
    /// <param name="pinLimit">The attempt threshold to store.</param>
    /// <returns>A task that completes once the counter window is written.</returns>
    private async Task WritePinCounterParametersAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, uint pinCount, uint pinLimit)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using IMemoryOwner<byte> blobOwner = pool.Rent(PinCounterParametersSize);
        Memory<byte> blob = blobOwner.Memory[..PinCounterParametersSize];
        BinaryPrimitives.WriteUInt32BigEndian(blob.Span, pinCount);
        BinaryPrimitives.WriteUInt32BigEndian(blob.Span[sizeof(uint)..], pinLimit);

        using Tpm2bMaxNvBuffer inputBuffer = Tpm2bMaxNvBuffer.Create(blob.Span, pool);
        var input = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, nvIndex, inputBuffer, Offset: 0);

        TpmResult<NvWriteResponse> result = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The owner-authorized counter write failed: '{result.ResponseCode}'.");
    }

    /// <summary>Reads a PIN Index's counter window back over the owner-authorized path and requires an exact attempt count.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The PIN Index to read.</param>
    /// <param name="expectedPinCount">The attempt count the counter must carry.</param>
    /// <param name="refusal">A phrase naming the refusal just driven, for the failure message.</param>
    /// <returns>A task that completes once the counter has been checked.</returns>
    private async Task AssertPinCountIsAsync(TpmDevice device, uint nvIndex, uint expectedPinCount, string refusal)
    {
        TpmResult<TpmPinCounterParameters> counters = await device.ReadPinCountersAsync(
            ReadOnlyMemory<byte>.Empty, nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(counters.IsSuccess, $"ReadPinCountersAsync failed: '{counters.ResponseCode}'.");
        Assert.AreEqual(expectedPinCount, counters.Value.PinCount, $"A rotation refused for {refusal} resolves no authorization, so it must leave pinCount alone.");
    }

    /// <summary>Enrolls a <c>TPM_NT_PIN_FAIL</c> Index through the production verb and asserts the enrollment succeeded.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pinIndexHandle">The Index handle to enroll.</param>
    /// <param name="pinHash">The stored PIN form to install as the Index authValue.</param>
    /// <param name="pinLimit">The attempt threshold to provision.</param>
    /// <returns>A task that completes once the Index is provisioned.</returns>
    private async Task EnrollAsync(TpmDevice device, uint pinIndexHandle, ReadOnlyMemory<byte> pinHash, uint pinLimit)
    {
        TpmResult<NvWriteResponse> defineResult = await device.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, pinIndexHandle, pinHash, pinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");
    }

    /// <summary>Defines an ordinary, dictionary-attack-exempt NV Index carrying a caller-chosen access policy, authorized by the (empty) owner authValue.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the NV_DefineSpace codec.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="authPolicy">The access policy digest to define with.</param>
    /// <returns>A task that completes once the Index is defined.</returns>
    private async Task DefineOrdinaryIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> authPolicy)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth auth = Tpm2bAuth.Create(OrdinaryIndexAuth, pool);
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(authPolicy.Span, pool);
        using TpmsNvPublic publicInfo = new(nvIndex, SessionAlg, OrdinaryAttributes, policyDigest, PinCounterParametersSize);
        using NvDefineSpaceInput input = new(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"NV_DefineSpace failed: '{result.ResponseCode}'.");
    }

    /// <summary>Reads an Index's Name and current attributes back over <c>TPM2_NV_ReadPublic</c>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Index handle to read.</param>
    /// <returns>The Index's Name and its current <c>TPMA_NV</c> attributes.</returns>
    private async Task<(byte[] Name, TpmaNv Attributes)> ReadPublicAsync(TpmDevice device, uint nvIndex)
    {
        TpmResult<NvReadPublicResponse> result = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"NvReadPublicAsync failed: '{result.ResponseCode}'.");

        using NvReadPublicResponse indexPublic = result.Value;

        return (indexPublic.NvName.Span.ToArray(), indexPublic.NvPublic.Attributes);
    }

    /// <summary>Reads an Index's Name back over <c>TPM2_NV_ReadPublic</c>, for the cpHash handle area a session-authorized command needs.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Index handle to read.</param>
    /// <returns>The Index's Name.</returns>
    private async Task<byte[]> ReadNameAsync(TpmDevice device, uint nvIndex)
    {
        (byte[] name, _) = await ReadPublicAsync(device, nvIndex).ConfigureAwait(false);

        return name;
    }

    /// <summary>
    /// Computes a policy description's digest through the project's own policy-digest fold, so a test can
    /// define an Index with a policy of a chosen SHAPE without hand-copying an extend formula.
    /// </summary>
    /// <param name="policy">The policy description to fold.</param>
    /// <returns>The policy digest under <see cref="SessionAlg"/>.</returns>
    private static byte[] ComputePolicyDigest(TpmPolicy policy)
    {
        byte[] digest = new byte[Sha256DigestSize];
        int written = policy.ComputeDigest(SessionAlg, digest);
        Assert.AreEqual(Sha256DigestSize, written, "A SHA-256 policy digest is the hash's full width.");

        return digest;
    }

    /// <summary>
    /// Transcribes the rotation <c>authPolicy</c> independently from the two extend formulas the specification
    /// states: <c>policyDigest = H(zeroes ‖ TPM_CC_PolicyAuthValue)</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, Section 23.17), then
    /// <c>policyDigest = H(policyDigest ‖ TPM_CC_PolicyCommandCode ‖ TPM_CC_NV_ChangeAuth)</c> (Section 23.11).
    /// Written out with <see cref="BinaryPrimitives"/> and the project's registered digest seam, never through
    /// the policy builder the production enrollment folds its own copy with.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The transcribed policy digest.</returns>
    private async Task<byte[]> ComputeRotationAuthPolicyAsync(BaseMemoryPool pool)
    {
        byte[] authValueInput = new byte[Sha256DigestSize + sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(authValueInput.AsSpan(Sha256DigestSize), (uint)TpmCcConstants.TPM_CC_PolicyAuthValue);

        using DigestValue afterAuthValue = await CryptographicKeyEvents.ComputeDigestAsync(
            authValueInput, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] commandCodeInput = new byte[Sha256DigestSize + sizeof(uint) + sizeof(uint)];
        afterAuthValue.AsReadOnlySpan().CopyTo(commandCodeInput);
        BinaryPrimitives.WriteUInt32BigEndian(commandCodeInput.AsSpan(Sha256DigestSize), (uint)TpmCcConstants.TPM_CC_PolicyCommandCode);
        BinaryPrimitives.WriteUInt32BigEndian(commandCodeInput.AsSpan(Sha256DigestSize + sizeof(uint)), (uint)TpmCcConstants.TPM_CC_NV_ChangeAuth);

        using DigestValue afterCommandCode = await CryptographicKeyEvents.ComputeDigestAsync(
            commandCodeInput, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return afterCommandCode.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Transcribes the MINIMAL rotation <c>authPolicy</c> - the one assertion Part 3, Section 31.15.1 actually
    /// requires - from its single extend formula: <c>policyDigest = H(policyDigest ‖ TPM_CC_PolicyCommandCode ‖
    /// TPM_CC_NV_ChangeAuth)</c> (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3, Section 23.11) folded over the all-zero starting digest a fresh
    /// policy session carries (Part 1, Section 16.7). Written out with <see cref="BinaryPrimitives"/> and the
    /// project's registered digest seam, never through the policy builder.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The transcribed policy digest.</returns>
    private async Task<byte[]> ComputeCommandCodeOnlyRotationPolicyAsync(BaseMemoryPool pool)
    {
        byte[] commandCodeInput = new byte[Sha256DigestSize + sizeof(uint) + sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(commandCodeInput.AsSpan(Sha256DigestSize), (uint)TpmCcConstants.TPM_CC_PolicyCommandCode);
        BinaryPrimitives.WriteUInt32BigEndian(commandCodeInput.AsSpan(Sha256DigestSize + sizeof(uint)), (uint)TpmCcConstants.TPM_CC_NV_ChangeAuth);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            commandCodeInput, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Independently transcribes an NV Index's Name: <c>nameAlg ‖ H_nameAlg(nvIndex ‖ nameAlg ‖ attributes ‖
    /// authPolicy ‖ dataSize)</c>, the whole marshaled <c>TPMS_NV_PUBLIC</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 13.6, Table 251) hashed per Part 1, Section 13, Table 9. Uses
    /// <see cref="BinaryPrimitives"/> and the project's registered digest seam directly, never
    /// <c>TpmsNvPublic.WriteTo</c> or the production Name helper.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle.</param>
    /// <param name="nameAlg">The Name hash algorithm.</param>
    /// <param name="attributes">The Index attributes to hash.</param>
    /// <param name="authPolicy">The access policy digest to hash.</param>
    /// <param name="dataSize">The declared data area size to hash.</param>
    /// <returns>The transcribed Name (nameAlg prefix followed by the digest).</returns>
    private async Task<byte[]> ComputeIndependentNvNameAsync(
        BaseMemoryPool pool, uint nvIndex, TpmAlgIdConstants nameAlg, TpmaNv attributes, ReadOnlyMemory<byte> authPolicy, ushort dataSize)
    {
        int marshaledLength = sizeof(uint) + sizeof(ushort) + sizeof(uint) + sizeof(ushort) + authPolicy.Length + sizeof(ushort);
        byte[] marshaled = new byte[marshaledLength];
        int offset = 0;

        BinaryPrimitives.WriteUInt32BigEndian(marshaled.AsSpan(offset, sizeof(uint)), nvIndex);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset, sizeof(ushort)), (ushort)nameAlg);
        offset += sizeof(ushort);
        BinaryPrimitives.WriteUInt32BigEndian(marshaled.AsSpan(offset, sizeof(uint)), (uint)attributes);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset, sizeof(ushort)), (ushort)authPolicy.Length);
        offset += sizeof(ushort);
        authPolicy.Span.CopyTo(marshaled.AsSpan(offset));
        offset += authPolicy.Length;
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset, sizeof(ushort)), dataSize);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            marshaled, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] name = new byte[sizeof(ushort) + Sha256DigestSize];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)nameAlg);
        digest.AsReadOnlySpan().CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>
    /// Assembles the data a response authorization HMAC is computed over:
    /// <c>rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes</c>, where
    /// <c>rpHash = H(responseCode ‖ commandCode ‖ parameters)</c> and <c>TPM2_NV_ChangeAuth</c> has no response
    /// parameters at all (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 1, clauses 15.8 and 16.6.5).
    /// </summary>
    /// <param name="responseBytes">The captured response bytes, whose header supplies the response code.</param>
    /// <param name="responseNonceTpm">The session entry's rolled nonceTPM.</param>
    /// <param name="commandNonceCaller">The caller nonce the command's own session entry carried.</param>
    /// <param name="sessionAttributes">The session entry's echoed attributes octet.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The assembled HMAC input.</returns>
    private async Task<byte[]> BuildResponseHmacDataAsync(
        byte[] responseBytes, byte[] responseNonceTpm, byte[] commandNonceCaller, byte sessionAttributes, BaseMemoryPool pool)
    {
        var reader = new TpmReader(responseBytes);
        TpmHeader header = TpmHeader.Parse(ref reader);

        byte[] rpHashInput = new byte[sizeof(uint) + sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(rpHashInput, header.Code);
        BinaryPrimitives.WriteUInt32BigEndian(rpHashInput.AsSpan(sizeof(uint)), (uint)TpmCcConstants.TPM_CC_NV_ChangeAuth);

        using DigestValue rpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            rpHashInput, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] data = new byte[Sha256DigestSize + responseNonceTpm.Length + commandNonceCaller.Length + sizeof(byte)];
        int offset = 0;
        rpHash.AsReadOnlySpan().CopyTo(data.AsSpan(offset));
        offset += Sha256DigestSize;
        responseNonceTpm.CopyTo(data.AsSpan(offset));
        offset += responseNonceTpm.Length;
        commandNonceCaller.CopyTo(data.AsSpan(offset));
        offset += commandNonceCaller.Length;
        data[offset] = sessionAttributes;

        return data;
    }

    /// <summary>
    /// Computes a session authorization HMAC: <c>HMAC_sessionAlg(sessionKey ‖ authValue, data)</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, Section 16.6.5, equation 17). Callers supply the whole concatenated key: for
    /// an unbound, unsalted session it reduces to the authorization value alone, since such a session's key is
    /// the Empty Buffer (Section 16.6.9); for a salted session it is the term a transcript observer cannot
    /// reconstruct, which is what makes the same recomputation fail there.
    /// </summary>
    /// <param name="sessionValue">The concatenated HMAC key, trailing zeros already removed from its authValue term.</param>
    /// <param name="data">The HMAC input.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The computed HMAC.</returns>
    private async Task<byte[]> ComputeSessionHmacAsync(ReadOnlyMemory<byte> sessionValue, ReadOnlyMemory<byte> data, BaseMemoryPool pool)
    {
        using HmacValue hmac = await CryptographicKeyEvents.ComputeHmacAsync(
            data, sessionValue, Sha256DigestSize, CryptoTags.HmacSha256Value, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return hmac.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Assembles a command parameter hash: <c>cpHash = H(commandCode ‖ handleNames ‖ parameters)</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, Section 15.7, equation 15), over the parameter area exactly as it crossed the
    /// wire - encrypted, when a decrypt session encrypted it, because parameter encryption precedes the hash
    /// (Section 18.1).
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="commandCode">The command code being hashed.</param>
    /// <param name="handleNames">The concatenated Names of the command's handles.</param>
    /// <param name="parameters">The command's parameter area as sent.</param>
    /// <returns>The command parameter hash.</returns>
    private async Task<byte[]> ComputeIndependentCpHashAsync(
        BaseMemoryPool pool, TpmCcConstants commandCode, ReadOnlyMemory<byte> handleNames, ReadOnlyMemory<byte> parameters)
    {
        byte[] input = new byte[sizeof(uint) + handleNames.Length + parameters.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, (uint)commandCode);
        handleNames.Span.CopyTo(input.AsSpan(sizeof(uint)));
        parameters.Span.CopyTo(input.AsSpan(sizeof(uint) + handleNames.Length));

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Recomputes the AUTHORIZING session's command authorization HMAC from captured wire data and a candidate
    /// key: <c>HMAC_sessionAlg(key, cpHash ‖ nonceCaller ‖ nonceTPM ‖ foldedNonces ‖ sessionAttributes)</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, Section 16.6.5, equation 17, with Section 16.6.3.4's
    /// <c>nonceTPMdecrypt</c> fold, which applies to the first session of a command that authorizes an entity).
    /// The session's <c>nonceTPM</c> is still its <c>TPM2_StartAuthSession</c> response nonce, since a policy
    /// assertion is a command handle rather than an authorization and rolls no nonce.
    /// </summary>
    /// <param name="pairs">The recorded command/response triples of one rotation.</param>
    /// <param name="indexName">The rotated Index's Name, transcribed independently.</param>
    /// <param name="hmacKey">The candidate key - <c>sessionKey ‖ authValue</c>, each term empty when it does not apply.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The HMAC the candidate key produces over the captured exchange.</returns>
    private async Task<byte[]> RecomputeAuthorizingCommandHmacAsync(
        List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs,
        ReadOnlyMemory<byte> indexName,
        ReadOnlyMemory<byte> hmacKey,
        BaseMemoryPool pool)
    {
        byte[] command = FirstCommand(pairs, TpmCcConstants.TPM_CC_NV_ChangeAuth);
        List<(uint Handle, byte[] NonceCaller, byte Attributes, int HmacStart, int HmacLength)> entries =
            ReadCommandSessionEntries(command, handleCount: 1);
        byte[] parameterArea = ReadCommandParameterArea(command, handleCount: 1);

        byte[] cpHash = await ComputeIndependentCpHashAsync(
            pool, TpmCcConstants.TPM_CC_NV_ChangeAuth, indexName, parameterArea).ConfigureAwait(false);
        byte[] nonceTpm = FindStartAuthSessionNonceTpm(pairs, entries[0].Handle);
        byte[] foldedNonces = entries.Count > 1 ? FindStartAuthSessionNonceTpm(pairs, entries[1].Handle) : [];

        byte[] data = new byte[cpHash.Length + entries[0].NonceCaller.Length + nonceTpm.Length + foldedNonces.Length + sizeof(byte)];
        int offset = 0;
        cpHash.CopyTo(data.AsSpan(offset));
        offset += cpHash.Length;
        entries[0].NonceCaller.CopyTo(data.AsSpan(offset));
        offset += entries[0].NonceCaller.Length;
        nonceTpm.CopyTo(data.AsSpan(offset));
        offset += nonceTpm.Length;
        foldedNonces.CopyTo(data.AsSpan(offset));
        offset += foldedNonces.Length;
        data[offset] = entries[0].Attributes;

        return await ComputeSessionHmacAsync(hmacKey, data, pool).ConfigureAwait(false);
    }

    /// <summary>
    /// Recomputes the AUTHORIZING session's RESPONSE authorization HMAC from captured wire data and a candidate
    /// key, and reports it alongside the one the TPM actually framed, so a test can require them to agree or to
    /// differ. The response key is the one the rotation installed, not the one it replaced (TPM 2.0 Library Part
    /// 3, Section 31.15.1).
    /// </summary>
    /// <param name="pairs">The recorded command/response triples of one rotation.</param>
    /// <param name="hmacKey">The candidate key - <c>sessionKey ‖ authValue</c>, each term empty when it does not apply.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The framed HMAC and the one the candidate key produces.</returns>
    private async Task<(byte[] Framed, byte[] Recomputed)> RecomputeAuthorizingResponseHmacAsync(
        List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs,
        ReadOnlyMemory<byte> hmacKey,
        BaseMemoryPool pool)
    {
        (byte[] Command, byte[] Response) exchange = FirstExchange(pairs, TpmCcConstants.TPM_CC_NV_ChangeAuth);
        byte[] commandNonceCaller = ReadCommandSessionNonces(exchange.Command, handleCount: 1)[0];
        (int hmacStart, int hmacLength, byte[] responseNonceTpm, byte sessionAttributes) = ReadFirstResponseSessionEntry(exchange.Response);

        byte[] hmacData = await BuildResponseHmacDataAsync(
            exchange.Response, responseNonceTpm, commandNonceCaller, sessionAttributes, pool).ConfigureAwait(false);
        byte[] recomputed = await ComputeSessionHmacAsync(hmacKey, hmacData, pool).ConfigureAwait(false);

        return (exchange.Response.AsSpan(hmacStart, hmacLength).ToArray(), recomputed);
    }

    /// <summary>
    /// Recovers what a passive bus observer would read out of a captured rotation's encrypted <c>newAuth</c>
    /// parameter, assuming the decrypt session is neither bound nor salted and its session key is therefore the
    /// Empty Buffer (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 1, Section 16.6.9): XOR-decrypts with the command-direction mask keyed
    /// on that value (Section 18.2, <c>nonceNewer</c> = nonceCaller, <c>nonceOlder</c> = the session's nonceTPM,
    /// still the <c>TPM2_StartAuthSession</c> response nonce for the session's first command). Uses the
    /// project's own parameter-encryption primitive, so a match means the keystream was genuinely public and a
    /// mismatch means it was not.
    /// </summary>
    /// <param name="pairs">The recorded command/response triples of one rotation.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The bytes the public derivation recovers from the encrypted <c>newAuth</c> parameter.</returns>
    private async Task<byte[]> RecoverNewAuthWithTheEmptySessionKeyAsync(
        List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs, BaseMemoryPool pool)
    {
        byte[] changeAuthCommand = FirstCommand(pairs, TpmCcConstants.TPM_CC_NV_ChangeAuth);
        uint[] sessionHandles = ReadCommandSessionHandles(changeAuthCommand, handleCount: 1);
        byte[][] sessionNonces = ReadCommandSessionNonces(changeAuthCommand, handleCount: 1);
        Assert.HasCount(2, sessionHandles, "The rotation carries the authorizing policy session and a separate decrypt companion.");

        byte[] startNonceTpm = FindStartAuthSessionNonceTpm(pairs, sessionHandles[1]);
        byte[] ciphertext = ReadNewAuthParameter(changeAuthCommand, handleCount: 1);
        byte[] recovered = (byte[])ciphertext.Clone();

        await TpmParameterEncryption.XorAsync(
            HashAlgorithmName.SHA256, ReadOnlyMemory<byte>.Empty, sessionNonces[1], startNonceTpm, recovered, pool, TestContext.CancellationToken).ConfigureAwait(false);

        return recovered;
    }

    /// <summary>
    /// Locates the <c>TPM2_StartAuthSession</c> exchange that created <paramref name="sessionHandle"/> and
    /// returns the nonceTPM its response carried - the session's <c>nonceOlder</c> for the first command sent
    /// over it (TPM 2.0 Library Part 1, Section 18.2).
    /// </summary>
    /// <param name="pairs">The recorded command/response triples.</param>
    /// <param name="sessionHandle">The session handle to find.</param>
    /// <returns>The session's initial nonceTPM.</returns>
    private static byte[] FindStartAuthSessionNonceTpm(List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs, uint sessionHandle)
    {
        (byte[] Command, byte[] NonceTpm) exchange = FindStartAuthSessionExchange(pairs, sessionHandle);

        return exchange.NonceTpm;
    }

    /// <summary>
    /// Locates the whole <c>TPM2_StartAuthSession</c> exchange that created <paramref name="sessionHandle"/>: the
    /// command that requested the session (whose parameters declare the shape it was started with) and the
    /// nonceTPM its response carried.
    /// </summary>
    /// <param name="pairs">The recorded command/response triples.</param>
    /// <param name="sessionHandle">The session handle to find.</param>
    /// <returns>The starting command's bytes and the session's initial nonceTPM.</returns>
    private static (byte[] Command, byte[] NonceTpm) FindStartAuthSessionExchange(
        List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs, uint sessionHandle)
    {
        foreach((TpmCcConstants Code, byte[] Command, byte[] Response) pair in pairs)
        {
            if(pair.Code != TpmCcConstants.TPM_CC_StartAuthSession || pair.Response.Length == 0)
            {
                continue;
            }

            var reader = new TpmReader(pair.Response);
            _ = TpmHeader.Parse(ref reader);
            if(reader.ReadUInt32() != sessionHandle)
            {
                continue;
            }

            ushort nonceSize = reader.ReadUInt16();

            return (pair.Command, reader.PeekBytes(nonceSize).ToArray());
        }

        throw new InvalidOperationException($"No captured TPM2_StartAuthSession created session handle 0x{sessionHandle:X8}.");
    }

    /// <summary>Returns the command bytes of the first recorded triple whose command code equals <paramref name="code"/>.</summary>
    /// <param name="pairs">The recorded command/response triples.</param>
    /// <param name="code">The command code to locate.</param>
    /// <returns>The matching command bytes.</returns>
    private static byte[] FirstCommand(List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs, TpmCcConstants code)
    {
        (byte[] Command, byte[] Response) exchange = FirstExchange(pairs, code);

        return exchange.Command;
    }

    /// <summary>Returns both halves of the first recorded triple whose command code equals <paramref name="code"/>.</summary>
    /// <param name="pairs">The recorded command/response triples.</param>
    /// <param name="code">The command code to locate.</param>
    /// <returns>The matching command and response bytes.</returns>
    private static (byte[] Command, byte[] Response) FirstExchange(
        List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs, TpmCcConstants code)
    {
        foreach((TpmCcConstants Code, byte[] Command, byte[] Response) pair in pairs)
        {
            if(pair.Code == code)
            {
                return (pair.Command, pair.Response);
            }
        }

        throw new InvalidOperationException($"No captured command with code '{code}' was recorded.");
    }

    /// <summary>
    /// Reads a captured <c>TPM2_StartAuthSession</c> command's declared shape straight off the wire: the two
    /// handles, then <c>nonceCaller ‖ encryptedSalt ‖ sessionType ‖ symmetric ‖ authHash</c> (TPM 2.0 Library
    /// Part 3, Section 11.1). <c>TPMT_SYM_DEF</c>'s <c>keyBits</c>/<c>mode</c> unions collapse to nothing under
    /// <c>TPM_ALG_NULL</c> (Part 2, Section 11.1.6, Table 162), and <c>authHash</c> is the last parameter, so the
    /// octets the definition occupied are what remains once <c>authHash</c> is set aside - which is what lets a
    /// caller assert that no symmetric algorithm was negotiated at all rather than merely selected as null.
    /// </summary>
    /// <param name="command">The captured command bytes.</param>
    /// <returns>The parsed fields.</returns>
    private static StartAuthSessionWireFields ReadStartAuthSessionCommand(byte[] command)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);

        uint tpmKey = reader.ReadUInt32();
        uint bind = reader.ReadUInt32();

        ushort nonceSize = reader.ReadUInt16();
        byte[] nonceCaller = reader.PeekBytes(nonceSize).ToArray();
        reader.Skip(nonceSize);

        ushort saltSize = reader.ReadUInt16();
        byte[] encryptedSalt = reader.PeekBytes(saltSize).ToArray();
        reader.Skip(saltSize);

        var sessionType = (TpmSeConstants)reader.ReadByte();

        int symmetricLength = command.Length - reader.Consumed - sizeof(ushort);
        var symmetricAlgorithm = (TpmAlgIdConstants)reader.ReadUInt16();
        reader.Skip(symmetricLength - sizeof(ushort));
        var authHash = (TpmAlgIdConstants)reader.ReadUInt16();

        return new StartAuthSessionWireFields(
            tpmKey, bind, nonceCaller, encryptedSalt, sessionType, symmetricAlgorithm, symmetricLength, authHash);
    }

    /// <summary>
    /// Reads every authorizing session's <c>sessionHandle</c> out of a built command's authorization area,
    /// navigating with a <see cref="TpmReader"/> so it holds regardless of nonce and HMAC widths.
    /// </summary>
    /// <param name="command">The captured command bytes.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <returns>The session handles, in authorization-area order.</returns>
    private static uint[] ReadCommandSessionHandles(byte[] command, int handleCount)
    {
        var handles = new List<uint>(2);
        foreach((uint Handle, byte[] NonceCaller, byte Attributes, int HmacStart, int HmacLength) entry in ReadCommandSessionEntries(command, handleCount))
        {
            handles.Add(entry.Handle);
        }

        return [.. handles];
    }

    /// <summary>Reads every authorizing session's <c>nonceCaller</c> out of a built command's authorization area, in authorization-area order.</summary>
    /// <param name="command">The captured command bytes.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <returns>The caller nonces, in authorization-area order.</returns>
    private static byte[][] ReadCommandSessionNonces(byte[] command, int handleCount)
    {
        var nonces = new List<byte[]>(2);
        foreach((uint Handle, byte[] NonceCaller, byte Attributes, int HmacStart, int HmacLength) entry in ReadCommandSessionEntries(command, handleCount))
        {
            nonces.Add(entry.NonceCaller);
        }

        return [.. nonces];
    }

    /// <summary>Reads one session entry's <c>hmac</c> octets out of a built command's authorization area.</summary>
    /// <param name="command">The captured command bytes.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <param name="sessionIndex">The zero-based position of the session within the authorization area.</param>
    /// <returns>The authorization HMAC as sent.</returns>
    private static byte[] ReadCommandSessionHmac(byte[] command, int handleCount, int sessionIndex)
    {
        (uint Handle, byte[] NonceCaller, byte Attributes, int HmacStart, int HmacLength) entry =
            ReadCommandSessionEntries(command, handleCount)[sessionIndex];

        return command.AsSpan(entry.HmacStart, entry.HmacLength).ToArray();
    }

    /// <summary>
    /// Inverts the last octet of one session entry's <c>hmac</c> field in a built command, leaving every other
    /// octet - including the parameter area the authorization is computed over - exactly as the caller composed
    /// it. Mutates <paramref name="command"/> in place.
    /// </summary>
    /// <param name="command">The built command bytes to modify.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <param name="sessionIndex">The zero-based position of the session whose HMAC is spliced.</param>
    private static void FlipLastOctetOfSessionHmac(byte[] command, int handleCount, int sessionIndex)
    {
        (uint Handle, byte[] NonceCaller, byte Attributes, int HmacStart, int HmacLength) entry =
            ReadCommandSessionEntries(command, handleCount)[sessionIndex];

        command[entry.HmacStart + entry.HmacLength - 1] ^= 0xFF;
    }

    /// <summary>
    /// Walks a built command's authorization area and yields each session entry's handle, caller nonce,
    /// attributes octet, and the position of its <c>hmac</c> field's data octets: handle area,
    /// <c>authorizationSize</c>, then one <c>sessionHandle ‖ nonceCaller ‖ sessionAttributes ‖ hmac</c> entry per
    /// session until the declared size is consumed (TPM 2.0 Library Part 1, Section 17.5).
    /// </summary>
    /// <param name="command">The captured command bytes.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <returns>The parsed session entries, in authorization-area order.</returns>
    private static List<(uint Handle, byte[] NonceCaller, byte Attributes, int HmacStart, int HmacLength)> ReadCommandSessionEntries(byte[] command, int handleCount)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < handleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint authorizationSize = reader.ReadUInt32();
        int authStart = reader.Consumed;

        var entries = new List<(uint Handle, byte[] NonceCaller, byte Attributes, int HmacStart, int HmacLength)>(2);
        while(reader.Consumed - authStart < (int)authorizationSize)
        {
            uint handle = reader.ReadUInt32();
            ushort nonceSize = reader.ReadUInt16();
            byte[] nonceCaller = reader.PeekBytes(nonceSize).ToArray();
            reader.Skip(nonceSize);
            byte attributes = reader.ReadByte();
            ushort hmacSize = reader.ReadUInt16();
            int hmacStart = reader.Consumed;
            reader.Skip(hmacSize);

            entries.Add((handle, nonceCaller, attributes, hmacStart, hmacSize));
        }

        return entries;
    }

    /// <summary>
    /// Reads a built command's whole parameter area - everything past the declared authorization area - so a test
    /// can hash it as the <c>parameters</c> term of <c>cpHash</c> exactly as it crossed the wire (TPM 2.0 Library
    /// Part 1, Section 15.7, equation 15).
    /// </summary>
    /// <param name="command">The captured command bytes.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <returns>The parameter area as sent.</returns>
    private static byte[] ReadCommandParameterArea(byte[] command, int handleCount)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < handleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint authorizationSize = reader.ReadUInt32();
        reader.Skip((int)authorizationSize);

        return command.AsSpan(reader.Consumed).ToArray();
    }

    /// <summary>
    /// Reads the (encrypted) <c>newAuth</c> parameter's data octets out of a built <c>TPM2_NV_ChangeAuth</c>
    /// command: the command's sole parameter, a <c>TPM2B_AUTH</c> whose size field is never encrypted (TPM 2.0
    /// Library Part 1, Section 18.1).
    /// </summary>
    /// <param name="command">The captured command bytes.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <returns>The parameter's data octets as sent.</returns>
    private static byte[] ReadNewAuthParameter(byte[] command, int handleCount)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < handleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint authorizationSize = reader.ReadUInt32();
        reader.Skip((int)authorizationSize);

        ushort newAuthSize = reader.ReadUInt16();

        return reader.PeekBytes(newAuthSize).ToArray();
    }

    /// <summary>
    /// Reads the FIRST session entry out of a framed response's authorization area and reports where its HMAC
    /// field's data octets sit, so a test can replace them: header, <c>parameterSize</c> (zero for a command
    /// with no response parameters), then <c>nonceTPM ‖ sessionAttributes ‖ hmac</c>.
    /// </summary>
    /// <param name="response">The captured response bytes.</param>
    /// <returns>The HMAC data's offset and length, the entry's rolled nonceTPM, and its echoed attributes octet.</returns>
    private static (int HmacStart, int HmacLength, byte[] NonceTpm, byte SessionAttributes) ReadFirstResponseSessionEntry(byte[] response)
    {
        var reader = new TpmReader(response);
        _ = TpmHeader.Parse(ref reader);
        _ = reader.ReadUInt32(); //parameterSize.

        ushort nonceSize = reader.ReadUInt16();
        byte[] nonceTpm = reader.PeekBytes(nonceSize).ToArray();
        reader.Skip(nonceSize);
        byte sessionAttributes = reader.ReadByte();
        ushort hmacSize = reader.ReadUInt16();

        return (reader.Consumed, hmacSize, nonceTpm, sessionAttributes);
    }

    /// <summary>
    /// Copies caller-assembled response octets into a pooled <see cref="TpmResponse"/> the executor under test
    /// consumes and disposes - the shape an active transport substitutes for the genuine framing.
    /// </summary>
    /// <param name="responseBytes">The response octets to hand back.</param>
    /// <param name="pool">The memory pool the response buffer is rented from.</param>
    /// <returns>The substituted response.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The rented buffer's ownership transfers to the TpmResponse, which is owned by the returned TpmResult and disposed by the executor under test.")]
    private static TpmResult<TpmResponse> CopyToResponse(byte[] responseBytes, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(responseBytes.Length);
        responseBytes.CopyTo(owner.Memory.Span);

        return TpmResult<TpmResponse>.Success(new TpmResponse(owner, responseBytes.Length));
    }

    /// <summary>
    /// Removes trailing zero octets, the transformation an authorization value always undergoes before it is
    /// used in an authorization computation (TPM 2.0 Library Part 1, Section 16.6.4.3).
    /// </summary>
    /// <param name="value">The value to strip.</param>
    /// <returns>The value with trailing zero octets removed.</returns>
    private static ReadOnlyMemory<byte> StripTrailingZeros(ReadOnlyMemory<byte> value)
    {
        int length = value.Length;
        while(length > 0 && value.Span[length - 1] == 0)
        {
            length--;
        }

        return value[..length];
    }

    /// <summary>
    /// Sets a bit in the first authorizing session's <c>sessionAttributes</c> octet of a built command,
    /// navigating the handle and authorization areas with a <see cref="TpmReader"/> so it holds regardless of
    /// nonce and HMAC sizes. Mutates <paramref name="command"/> in place.
    /// </summary>
    /// <param name="command">The built command bytes to modify.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <param name="bit">The <c>TPMA_SESSION</c> bit to set.</param>
    private static void SetFirstSessionAttributeBit(byte[] command, int handleCount, byte bit)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < handleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        _ = reader.ReadUInt32(); //authorizationSize.
        _ = reader.ReadUInt32(); //sessionHandle.
        ushort nonceSize = reader.ReadUInt16();
        reader.Skip(nonceSize);

        int attributesIndex = reader.Consumed;
        command[attributesIndex] |= bit;
    }

    /// <summary>Reads a captured TPM command's header <c>code</c> field, leaving every other field unexamined.</summary>
    /// <param name="command">The captured command bytes.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(byte[] command)
    {
        var reader = new TpmReader(command);
        TpmHeader header = TpmHeader.Parse(ref reader);

        return (TpmCcConstants)header.Code;
    }

    /// <summary>Reports whether <paramref name="needle"/> occurs as a contiguous byte sequence within <paramref name="haystack"/>.</summary>
    /// <param name="haystack">The bytes to search.</param>
    /// <param name="needle">The bytes to search for; an empty needle never matches.</param>
    /// <returns><see langword="true"/> when found.</returns>
    private static bool ContainsSubsequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if(needle.IsEmpty || needle.Length > haystack.Length)
        {
            return false;
        }

        for(int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            if(haystack.Slice(i, needle.Length).SequenceEqual(needle))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Wraps a device whose transport appends every command it forwards to <paramref name="capturedCommands"/>, in submission order.</summary>
    /// <param name="simulator">The simulator the capturing transport forwards to.</param>
    /// <param name="capturedCommands">The list each observed command is appended to.</param>
    /// <returns>A device the caller disposes; its transport captures as a side effect of forwarding.</returns>
    private static TpmDevice CreateCapturingDevice(TpmSimulator simulator, List<byte[]> capturedCommands)
    {
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            capturedCommands.Add(command.ToArray());

            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        return TpmDevice.Create(CaptureAsync);
    }

    /// <summary>
    /// Wraps a device whose transport records every <c>(commandCode, command bytes, response bytes)</c> triple
    /// into <paramref name="pairs"/> - the wire archaeology the confidentiality KAT needs, firewalled to the
    /// wire with no back-channel into session or simulator internals.
    /// </summary>
    /// <param name="simulator">The simulator the recording transport forwards to.</param>
    /// <param name="pairs">The list each observed triple is appended to, in submission order.</param>
    /// <returns>A device the caller disposes; its transport records as a side effect of forwarding.</returns>
    private static TpmDevice CreateRecordingDevice(TpmSimulator simulator, List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs)
    {
        async ValueTask<TpmResult<TpmResponse>> RecordAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            byte[] commandBytes = command.ToArray();
            TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
            byte[] responseBytes = result.IsSuccess ? result.Value.AsReadOnlySpan().ToArray() : [];
            pairs.Add((ReadCommandCode(commandBytes), commandBytes, responseBytes));

            return result;
        }

        return TpmDevice.Create(RecordAsync);
    }

    /// <summary>Creates the standard RSA endorsement-key-shaped decrypt key (RESTRICTED+DECRYPT, SHA-256 nameAlg) used as the salted overload's tpmKey.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry, already carrying the CreatePrimary codec.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The created primary key's response; the caller owns and disposes it.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaDecryptKeyAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_OWNER, pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a response codec registry for the raw rotation compositions this file drives directly.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRotationRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmResponseCodec.NvChangeAuth);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>Creates a response codec registry for the RSA-tpmKey creation the salted-overload KAT drives directly.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRsaKeyRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Creates a simulator with the RSA signing backend wired (the salted overload's tpmKey needs it), powers
    /// it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator("tpm-in-house-nv-changeauth", rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }

    /// <summary>
    /// The shape a captured <c>TPM2_StartAuthSession</c> command declares, read straight off the wire rather than
    /// from any host-side session object, so an assertion about how a session was started depends on nothing the
    /// implementation under test reports (TPM 2.0 Library Part 3, Section 11.1).
    /// </summary>
    /// <param name="TpmKey">The salt key handle, or <c>TPM_RH_NULL</c> for an unsalted session.</param>
    /// <param name="Bind">The bind entity handle, or <c>TPM_RH_NULL</c> for an unbound session.</param>
    /// <param name="NonceCaller">The caller nonce the session was started with.</param>
    /// <param name="EncryptedSalt">The encrypted salt, empty for an unsalted session.</param>
    /// <param name="SessionType">The requested session type.</param>
    /// <param name="SymmetricAlgorithm">The negotiated <c>TPMT_SYM_DEF</c>'s algorithm selector.</param>
    /// <param name="SymmetricLength">The octets the negotiated <c>TPMT_SYM_DEF</c> occupied on the wire.</param>
    /// <param name="AuthHash">The session's negotiated hash algorithm.</param>
    private sealed record StartAuthSessionWireFields(
        uint TpmKey,
        uint Bind,
        byte[] NonceCaller,
        byte[] EncryptedSalt,
        TpmSeConstants SessionType,
        TpmAlgIdConstants SymmetricAlgorithm,
        int SymmetricLength,
        TpmAlgIdConstants AuthHash);
}
