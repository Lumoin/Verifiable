using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_PolicyDuplicationSelect()</c> (TPM 2.0 Library Part 3, clause 23.15) against the in-house
/// <see cref="TpmSimulator"/> through the production command path: the two policyDigest folds, the shared
/// cpHash-slot and commandCode refusals, the parse bounds, and the use-time end to end — a duplicable sealed
/// object exported to the selected new parent under the assertion alone, refused toward another parent, and
/// exported as the selected object/parent pair under a <c>TPM2_PolicyAuthorize()</c> composition — plus the
/// <c>TPM2_PolicyParameters()</c> binding (clause 23.24) judged against <c>TPM2_Duplicate()</c>'s real
/// parameter area. Each test's own doc comment carries its clause anchor.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorPolicyDuplicationSelectTests
{
    /// <summary>The policy session hash every session here is started with.</summary>
    private const TpmAlgIdConstants SessionAlg = PolicySweepHarness.SessionAlg;

    /// <summary>The secret sealed into every duplicable object.</summary>
    private static byte[] SecretBytes { get; } = "Select the parent this secret may move to."u8.ToArray();

    /// <summary>A fixed 32-octet digest standing in for a caller-supplied nameHash, cpHash or pHash, never itself computed by SHA-256.</summary>
    private static byte[] DigestA { get; } = Convert.FromHexString("A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1");

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies <c>TPM2_PolicyDuplicationSelect()</c> with <c>includeObject</c> YES folds
    /// <c>H(policyDigest || TPM_CC_PolicyDuplicationSelect || objectName.name || newParentName.name || includeObject)</c>
    /// — the clause's own equation (8) — matching <see cref="TpmPolicyDigest.ExtendForDuplicationSelect"/> from a
    /// fresh policyDigest on a trial session, which takes the assertion exactly as a real one.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.15</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyDuplicationSelectWithIncludeObjectFoldsTheExpectedDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-dupselect-fold-yes", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        byte[] objectName = FabricatedName(0xD1);
        byte[] newParentName = FabricatedName(0xE2);
        byte[] predicted = PredictDuplicationSelect(objectName, newParentName, isObjectIncluded: true);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm, isTrial: true).ConfigureAwait(false);

            TpmResult<PolicyDuplicationSelectResponse> result = await tpm.PolicyDuplicationSelectAsync(
                sessionHandle, objectName, newParentName, isObjectIncluded: true, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"PolicyDuplicationSelect failed: '{result.ResponseCode}'.");

            byte[] actual = await GetDigestAsync(tpm, sessionHandle).ConfigureAwait(false);
            Assert.IsTrue(actual.AsSpan().SequenceEqual(predicted), "PolicyDuplicationSelect (includeObject YES) must fold both Names and a 0x01 octet after the command code.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyDuplicationSelect()</c> with <c>includeObject</c> NO folds
    /// <c>H(policyDigest || TPM_CC_PolicyDuplicationSelect || newParentName.name || includeObject)</c> — the object
    /// Name absent, the octet 0x00 — so the digest differs from the YES form over the same Names ("If
    /// includeObject is NO, policySession→policyDigest is updated by …").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.15</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyDuplicationSelectWithoutIncludeObjectFoldsTheExpectedDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-dupselect-fold-no", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        byte[] objectName = FabricatedName(0xD1);
        byte[] newParentName = FabricatedName(0xE2);
        byte[] predicted = PredictDuplicationSelect(objectName, newParentName, isObjectIncluded: false);
        byte[] withObject = PredictDuplicationSelect(objectName, newParentName, isObjectIncluded: true);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm, isTrial: true).ConfigureAwait(false);

            TpmResult<PolicyDuplicationSelectResponse> result = await tpm.PolicyDuplicationSelectAsync(
                sessionHandle, objectName, newParentName, isObjectIncluded: false, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"PolicyDuplicationSelect failed: '{result.ResponseCode}'.");

            byte[] actual = await GetDigestAsync(tpm, sessionHandle).ConfigureAwait(false);
            Assert.IsTrue(actual.AsSpan().SequenceEqual(predicted), "PolicyDuplicationSelect (includeObject NO) must fold the new parent Name and a 0x00 octet only.");
            Assert.IsFalse(actual.AsSpan().SequenceEqual(withObject), "The NO form must not equal the YES form over the same Names.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a TRIAL session takes <c>TPM2_PolicyDuplicationSelect()</c> whole, not only its fold: the slot is
    /// latched (a following <c>TPM2_PolicyNameHash()</c> is <c>TPM_RC_CPHASH</c>) and the <c>commandCode</c> is set
    /// (a following <c>TPM2_PolicyCommandCode(TPM_CC_Unseal)</c> is <c>TPM_RC_VALUE</c>) — the reference has no
    /// trial branch, so a trial session predicts exactly the state a real one reaches.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.15; clause 23.11; Part 1, clause 18.3</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyDuplicationSelectOnATrialSessionLatchesTheSlotAndSetsTheCommandCode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-dupselect-trial-state", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm, isTrial: true).ConfigureAwait(false);
            TpmResult<PolicyDuplicationSelectResponse> selectResult = await tpm.PolicyDuplicationSelectAsync(
                sessionHandle, FabricatedName(0xD1), FabricatedName(0xE2), isObjectIncluded: false, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(selectResult.IsSuccess, $"PolicyDuplicationSelect on a trial session failed: '{selectResult.ResponseCode}'.");

            TpmResult<PolicyNameHashResponse> nameHashResult = await tpm.PolicyNameHashAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_CPHASH, nameHashResult.ResponseCode, "The trial session's slot must be latched by the assertion.");

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(sessionHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), commandCodeResult.ResponseCode, "The trial session's commandCode must be set to TPM_CC_Duplicate by the assertion.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyDuplicationSelect()</c> refuses a session whose shared cpHash slot already holds a
    /// <c>TPM2_PolicyNameHash()</c> digest with <c>TPM_RC_CPHASH</c> ("If either policySession→cpHash or
    /// policySession→nameHash has been previously set, the TPM shall return TPM_RC_CPHASH").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.15</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyDuplicationSelectRefusesAnOccupiedSlotAfterPolicyNameHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-dupselect-after-namehash", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm, isTrial: false).ConfigureAwait(false);
            TpmResult<PolicyNameHashResponse> nameHashResult = await tpm.PolicyNameHashAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(nameHashResult.IsSuccess, $"PolicyNameHash failed: '{nameHashResult.ResponseCode}'.");

            TpmResult<PolicyDuplicationSelectResponse> result = await tpm.PolicyDuplicationSelectAsync(
                sessionHandle, FabricatedName(0xD1), FabricatedName(0xE2), isObjectIncluded: false, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A nameHash-occupied slot must refuse PolicyDuplicationSelect.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_CPHASH, result.ResponseCode, "An occupied cpHash/nameHash slot is TPM_RC_CPHASH.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyDuplicationSelect()</c> refuses a session whose shared cpHash slot holds a
    /// <c>TPM2_PolicyParameters()</c> pHash with <c>TPM_RC_CPHASH</c>: the reference tests the slot's occupancy,
    /// whichever sharer filled it (TPM 2.0 Library Part 1, Table 8 lists both among the sharers).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.15; Part 1, Table 8</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyDuplicationSelectRefusesAnOccupiedSlotAfterPolicyParameters()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-dupselect-after-parameters", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm, isTrial: false).ConfigureAwait(false);
            TpmResult<PolicyParametersResponse> parametersResult = await tpm.PolicyParametersAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(parametersResult.IsSuccess, $"PolicyParameters failed: '{parametersResult.ResponseCode}'.");

            TpmResult<PolicyDuplicationSelectResponse> result = await tpm.PolicyDuplicationSelectAsync(
                sessionHandle, FabricatedName(0xD1), FabricatedName(0xE2), isObjectIncluded: false, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A pHash-occupied slot must refuse PolicyDuplicationSelect.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_CPHASH, result.ResponseCode, "An occupied slot is TPM_RC_CPHASH whichever sharer filled it.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a second <c>TPM2_PolicyDuplicationSelect()</c> on the same session — the same Names included — is
    /// refused with <c>TPM_RC_CPHASH</c>: the first filled the nameHash slot AND the commandCode, and the slot's
    /// occupancy is the reference's first check, ahead of the commandCode check.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.15</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyDuplicationSelectRefusesASecondAssertionOnTheSameSessionWithCpHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-dupselect-twice", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        byte[] objectName = FabricatedName(0xD1);
        byte[] newParentName = FabricatedName(0xE2);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm, isTrial: false).ConfigureAwait(false);
            TpmResult<PolicyDuplicationSelectResponse> first = await tpm.PolicyDuplicationSelectAsync(
                sessionHandle, objectName, newParentName, isObjectIncluded: false, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(first.IsSuccess, $"The first PolicyDuplicationSelect failed: '{first.ResponseCode}'.");

            TpmResult<PolicyDuplicationSelectResponse> second = await tpm.PolicyDuplicationSelectAsync(
                sessionHandle, objectName, newParentName, isObjectIncluded: false, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(second.IsSuccess, "A second PolicyDuplicationSelect must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_CPHASH, second.ResponseCode, "The occupied slot answers ahead of the set commandCode.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyDuplicationSelect()</c> refuses a session whose <c>commandCode</c> is already set —
    /// here to <c>TPM_CC_Duplicate</c> itself by <c>TPM2_PolicyCommandCode()</c> — with <c>TPM_RC_COMMAND_CODE</c>,
    /// the reference's answer for any prior value ("commandCode in session context must be empty").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.15; Part 1, clause 16.7.8</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyDuplicationSelectRefusesASessionWhoseCommandCodeIsAlreadySet()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-dupselect-after-commandcode", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm, isTrial: false).ConfigureAwait(false);
            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(sessionHandle, TpmCcConstants.TPM_CC_Duplicate, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            TpmResult<PolicyDuplicationSelectResponse> result = await tpm.PolicyDuplicationSelectAsync(
                sessionHandle, FabricatedName(0xD1), FabricatedName(0xE2), isObjectIncluded: false, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A session with a set commandCode must refuse PolicyDuplicationSelect.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_COMMAND_CODE, result.ResponseCode, "A prior commandCode — TPM_CC_Duplicate included — is TPM_RC_COMMAND_CODE.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyCommandCode(TPM_CC_Duplicate)</c> is accepted after <c>TPM2_PolicyDuplicationSelect()</c>
    /// set the same <c>commandCode</c> ("the TPM does not return an error if code is the same"), folding its own
    /// term on top of the DuplicationSelect fold.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.11</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyCommandCodeForDuplicateIsAcceptedAfterPolicyDuplicationSelect()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-dupselect-then-same-commandcode", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        byte[] objectName = FabricatedName(0xD1);
        byte[] newParentName = FabricatedName(0xE2);
        byte[] afterSelect = PredictDuplicationSelect(objectName, newParentName, isObjectIncluded: false);
        byte[] predicted = new byte[afterSelect.Length];
        _ = TpmPolicyDigest.ExtendForCommandCode(afterSelect, TpmCcConstants.TPM_CC_Duplicate, SessionAlg, predicted, pool);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm, isTrial: false).ConfigureAwait(false);
            TpmResult<PolicyDuplicationSelectResponse> selectResult = await tpm.PolicyDuplicationSelectAsync(
                sessionHandle, objectName, newParentName, isObjectIncluded: false, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(selectResult.IsSuccess, $"PolicyDuplicationSelect failed: '{selectResult.ResponseCode}'.");

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(sessionHandle, TpmCcConstants.TPM_CC_Duplicate, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode(TPM_CC_Duplicate) after PolicyDuplicationSelect must be accepted: '{commandCodeResult.ResponseCode}'.");

            byte[] actual = await GetDigestAsync(tpm, sessionHandle).ConfigureAwait(false);
            Assert.IsTrue(actual.AsSpan().SequenceEqual(predicted), "The accepted repeat folds its own TPM_CC_PolicyCommandCode term on top of the DuplicationSelect fold.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyCommandCode()</c> for another command is refused with <c>TPM_RC_VALUE</c> after
    /// <c>TPM2_PolicyDuplicationSelect()</c> set the session's <c>commandCode</c> to <c>TPM_CC_Duplicate</c> ("If
    /// policySession→commandCode does not have its default value, then the TPM will return TPM_RC_VALUE if the
    /// two values are not the same").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.11; Part 1, clause 16.7.8</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyCommandCodeForAnotherCommandIsRefusedAfterPolicyDuplicationSelect()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-dupselect-then-other-commandcode", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm, isTrial: false).ConfigureAwait(false);
            TpmResult<PolicyDuplicationSelectResponse> selectResult = await tpm.PolicyDuplicationSelectAsync(
                sessionHandle, FabricatedName(0xD1), FabricatedName(0xE2), isObjectIncluded: false, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(selectResult.IsSuccess, $"PolicyDuplicationSelect failed: '{selectResult.ResponseCode}'.");

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(sessionHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(commandCodeResult.IsSuccess, "A different code on a restricted session must be refused.");
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), commandCodeResult.ResponseCode, "A different prior commandCode is TPM_RC_VALUE.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>policySession</c> is <c>TPM2_PolicyDuplicationSelect()</c>'s sole handle (index 0); a well-typed value
    /// naming no live policy session is a session in the handle area that is not present,
    /// <c>TPM_RC_REFERENCE_H0</c> — the refusal still releases the two parse-rented Name carriers, leaving the
    /// pool balanced.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.4, step 2.4</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyDuplicationSelectRefusesAnUnknownSessionAndBalancesThePool()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-dupselect-unknown-session", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;
        var input = new PolicyDuplicationSelectInput(0x03FFFFFFu, FabricatedName(0xD1), FabricatedName(0xE2), IsObjectIncluded: false);
        TpmResult<PolicyDuplicationSelectResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyDuplicationSelectResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "An unknown policy session must be refused.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, result.ResponseCode, "A well-typed but unloaded policySession at index 0 answers TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.4).");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The refusal must release both parse-rented Name carriers.");
    }

    /// <summary>
    /// Verifies a hand-framed <c>TPM2_PolicyDuplicationSelect()</c> whose <c>includeObject</c> octet is 2 is
    /// refused with <c>TPM_RC_VALUE</c>: <c>TPMI_YES_NO</c> "only has two allowed values, YES (1) and NO (0)"
    /// and Table 48 names <c>#TPM_RC_VALUE</c> for any other.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.2, Table 48; Part 3, clause 23.15, Table 168</see>.
    /// </summary>
    [TestMethod]
    public async Task HandFramedPolicyDuplicationSelectRefusesAnIncludeObjectOctetAboveOne()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-dupselect-yesno-value", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm, isTrial: false).ConfigureAwait(false);

            TpmRcConstants code = await SubmitDuplicationSelectFramedAsync(
                simulator, pool, sessionHandle, FabricatedName(0xD1), FabricatedName(0xE2), includeObject: 2, hasTrailingOctet: false).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 2), code,
                "Table 168: includeObject is TPM2_PolicyDuplicationSelect()'s third parameter (index 2); an octet outside {0, 1} is parameter-encoded TPM_RC_VALUE there.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a hand-framed <c>TPM2_PolicyDuplicationSelect()</c> whose <c>objectName</c> declares 67 octets is
    /// refused with <c>TPM_RC_SIZE</c>: a <c>TPM2B_NAME</c> is bounded by <c>sizeof(TPMU_NAME)</c> — a two-octet
    /// nameAlg plus the widest digest (<see cref="Tpm2bName.MaxSize"/>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.4.3, Table 105; Part 3, clause 23.15, Table 168</see>.
    /// </summary>
    [TestMethod]
    public async Task HandFramedPolicyDuplicationSelectRefusesANameOverTheTpm2bNameBound()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-dupselect-name-bound", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm, isTrial: false).ConfigureAwait(false);

            TpmRcConstants code = await SubmitDuplicationSelectFramedAsync(
                simulator, pool, sessionHandle, new byte[Tpm2bName.MaxSize + 1], FabricatedName(0xE2), includeObject: 0, hasTrailingOctet: false).ConfigureAwait(false);

            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), code, "objectName is TPM2_PolicyDuplicationSelect()'s first parameter (Table 168, index 0); one beyond sizeof(TPMU_NAME) is parameter-encoded TPM_RC_SIZE.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a hand-framed <c>TPM2_PolicyDuplicationSelect()</c> carrying an octet after <c>includeObject</c>
    /// is refused with <c>TPM_RC_SIZE</c>: <c>includeObject</c> is the final parameter and no octets may follow it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.2; clause 23.15, Table 168</see>.
    /// </summary>
    [TestMethod]
    public async Task HandFramedPolicyDuplicationSelectRefusesTrailingOctets()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-dupselect-trailing", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm, isTrial: false).ConfigureAwait(false);

            TpmRcConstants code = await SubmitDuplicationSelectFramedAsync(
                simulator, pool, sessionHandle, FabricatedName(0xD1), FabricatedName(0xE2), includeObject: 0, hasTrailingOctet: true).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "Octets after the final parameter are TPM_RC_SIZE.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The clause's own use: a duplicable sealed object whose authPolicy is the <c>includeObject</c> NO fold over
    /// the new parent's Name — computable before the object exists, since its own Name is not folded — is
    /// exported to that parent by <c>TPM2_Duplicate()</c> under a session that ran <c>TPM2_PolicyDuplicationSelect()</c>
    /// ALONE: the assertion set <c>policySession→commandCode</c> to <c>TPM_CC_Duplicate</c> ("If the command
    /// succeeds, policySession→commandCode is set to TPM_CC_Duplicate"), satisfying the DUP role without
    /// <c>TPM2_PolicyCommandCode()</c>, and its latched <c>H(objectName || newParentName)</c> equals the digest
    /// recomputed over the command's two handle Names at use.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.15; clause 13.1; Part 1, clause 16.7.7</see>.
    /// </summary>
    [TestMethod]
    public async Task DuplicationSelectedNewParentAdmitsDuplicateToThatParentWithoutPolicyCommandCode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-dupselect-e2e", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse newParent = await CreateDistinctStorageParentAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, noDa: false).ConfigureAwait(false);
        byte[] newParentName = newParent.Name.Span.ToArray();
        Assert.IsFalse(newParentName.AsSpan().SequenceEqual(parent.Name.Span), "The new parent must be a different key from the current parent.");

        //The policy binds the new parent alone, so it needs only the new parent's Name — the object's own Name
        //(which covers this very policy) plays no part.
        byte[] authPolicy = PredictDuplicationSelect(objectName: [], newParentName, isObjectIncluded: false);

        uint objectHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (objectHandle, byte[] objectName) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parent.ObjectHandle.Value, SecretBytes, authPolicy, isDuplicable: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            sessionHandle = await StartSessionAsync(tpm, isTrial: false).ConfigureAwait(false);
            TpmResult<PolicyDuplicationSelectResponse> selectResult = await tpm.PolicyDuplicationSelectAsync(
                sessionHandle, objectName, newParentName, isObjectIncluded: false, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(selectResult.IsSuccess, $"PolicyDuplicationSelect failed: '{selectResult.ResponseCode}'.");

            TpmResult<DuplicateResponse> duplicateResult = await DuplicateAsync(tpm, registry, pool, objectHandle, newParent.ObjectHandle.Value, sessionHandle, objectName, newParentName).ConfigureAwait(false);
            Assert.IsTrue(duplicateResult.IsSuccess, $"Duplicate to the selected new parent failed: '{duplicateResult.ResponseCode}'.");

            using DuplicateResponse duplicated = duplicateResult.Value;
            Assert.IsFalse(duplicated.Duplicate.IsEmpty, "The export must produce a duplication blob.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, objectHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, newParent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The pairing is exact: the same session, satisfied for the selected new parent, refuses
    /// <c>TPM2_Duplicate()</c> toward a THIRD storage parent with a <c>TPM_RC_POLICY_FAIL</c>, session-encoded to the same index — the
    /// policyDigest still matches (the policy named only the selected parent's Name, which the session folded),
    /// but the latched nameHash "is only valid for a specific pair of duplication object and new parent" and the
    /// digest recomputed over this command's handle Names differs.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.15; Part 4 CheckPolicyAuthSession/CompareNameHash</see>.
    /// </summary>
    [TestMethod]
    public async Task DuplicationSelectedNewParentRefusesDuplicateToAnotherParent()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-dupselect-other-parent", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse selectedParent = await CreateDistinctStorageParentAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, noDa: false).ConfigureAwait(false);
        using CreatePrimaryResponse otherParent = await CreateDistinctStorageParentAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, noDa: true).ConfigureAwait(false);
        byte[] selectedParentName = selectedParent.Name.Span.ToArray();
        byte[] otherParentName = otherParent.Name.Span.ToArray();
        Assert.IsFalse(otherParentName.AsSpan().SequenceEqual(selectedParentName), "The third parent must be a different key from the selected one.");

        byte[] authPolicy = PredictDuplicationSelect(objectName: [], selectedParentName, isObjectIncluded: false);

        uint objectHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (objectHandle, byte[] objectName) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parent.ObjectHandle.Value, SecretBytes, authPolicy, isDuplicable: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            sessionHandle = await StartSessionAsync(tpm, isTrial: false).ConfigureAwait(false);
            TpmResult<PolicyDuplicationSelectResponse> selectResult = await tpm.PolicyDuplicationSelectAsync(
                sessionHandle, objectName, selectedParentName, isObjectIncluded: false, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(selectResult.IsSuccess, $"PolicyDuplicationSelect failed: '{selectResult.ResponseCode}'.");

            TpmResult<DuplicateResponse> duplicateResult = await DuplicateAsync(tpm, registry, pool, objectHandle, otherParent.ObjectHandle.Value, sessionHandle, objectName, otherParentName).ConfigureAwait(false);

            Assert.IsFalse(duplicateResult.IsSuccess, "Duplicate toward a parent other than the selected one must be refused.");
            Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), duplicateResult.ResponseCode, "The nameHash binding mismatch is the policy's own TPM_RC_POLICY_FAIL, session-encoded to the sole authorizing policy session.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, objectHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, otherParent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, selectedParent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The clause's <c>includeObject</c> YES composition: "The Name can be known by the authorizing entity (a
    /// PolicyAuthorize Command) in which case includeObject may be SET … the authorizing entity would approve the
    /// policyDigest of Equation 8." A duplicable sealed object is created under the fixed
    /// <c>TPM2_PolicyAuthorize()</c> authPolicy; once its Name exists, the authority signs the YES fold over that
    /// Name and the new parent's Name (through the real <c>TPM2_Sign()</c>/<c>TPM2_VerifySignature()</c> wire
    /// path); the session runs <c>TPM2_PolicyDuplicationSelect(objectName, newParentName, YES)</c> then
    /// <c>TPM2_PolicyAuthorize()</c>, and <c>TPM2_Duplicate()</c> of exactly that pair succeeds — the
    /// nameHash-bound success the object's own policy could not express.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.15; clause 23.16</see>.
    /// </summary>
    [TestMethod]
    public async Task DuplicationSelectWithIncludeObjectComposesWithPolicyAuthorizeToDuplicateTheSelectedPair()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-dupselect-authorize", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse newParent = await CreateDistinctStorageParentAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, noDa: false).ConfigureAwait(false);
        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] newParentName = newParent.Name.Span.ToArray();
        byte[] keySign = authorityKey.Name.Span.ToArray();
        byte[] policyRef = "duplicationselect-ref"u8.ToArray();

        //The FIXED authPolicy the object is created under depends only on keySign and policyRef (Part 3, clause
        //23.16, equation 35) — the object's Name, which covers it, does not exist yet.
        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] authPolicy = new byte[size];
        _ = TpmPolicyDigest.ExtendForAuthorize(keySign, policyRef, SessionAlg, authPolicy, pool);

        uint objectHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (objectHandle, byte[] objectName) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parent.ObjectHandle.Value, SecretBytes, authPolicy, isDuplicable: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            //Now that the object's Name is known, the authority approves the YES fold over the exact pair.
            byte[] approvedPolicy = PredictDuplicationSelect(objectName, newParentName, isObjectIncluded: true);
            byte[] aHash = ComputeAuthorizeAHash(approvedPolicy, policyRef);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using SignInput signInput = SignInput.ForEcdsa(authorityKey.ObjectHandle, aHash, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (authority over aHash) failed: '{signResult.ResponseCode}'.");
            using SignResponse signature = signResult.Value;
            using Signature p1363Signature = ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan(), pool);

            using VerifySignatureInput verifyInput = VerifySignatureInput.ForEcdsa(authorityKey.ObjectHandle, aHash, p1363Signature.AsReadOnlySpan(), TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
                tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifySignature (authority ticket) failed: '{verifyResult.ResponseCode}'.");
            using VerifySignatureResponse verified = verifyResult.Value;

            sessionHandle = await StartSessionAsync(tpm, isTrial: false).ConfigureAwait(false);
            TpmResult<PolicyDuplicationSelectResponse> selectResult = await tpm.PolicyDuplicationSelectAsync(
                sessionHandle, objectName, newParentName, isObjectIncluded: true, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(selectResult.IsSuccess, $"PolicyDuplicationSelect failed: '{selectResult.ResponseCode}'.");

            TpmResult<PolicyAuthorizeResponse> authorizeResult = await tpm.PolicyAuthorizeAsync(
                sessionHandle, approvedPolicy, policyRef, keySign, verified.Validation, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authorizeResult.IsSuccess, $"PolicyAuthorize failed: '{authorizeResult.ResponseCode}'.");

            byte[] actual = await GetDigestAsync(tpm, sessionHandle).ConfigureAwait(false);
            Assert.IsTrue(actual.AsSpan().SequenceEqual(authPolicy), "After PolicyAuthorize the session must reach the object's fixed authPolicy.");

            TpmResult<DuplicateResponse> duplicateResult = await DuplicateAsync(tpm, registry, pool, objectHandle, newParent.ObjectHandle.Value, sessionHandle, objectName, newParentName).ConfigureAwait(false);
            Assert.IsTrue(duplicateResult.IsSuccess, $"Duplicate of the authorized pair failed: '{duplicateResult.ResponseCode}'.");

            using DuplicateResponse duplicated = duplicateResult.Value;
            Assert.IsFalse(duplicated.Duplicate.IsEmpty, "The export must produce a duplication blob.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, objectHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, authorityKey.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, newParent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies the <c>TPM2_PolicyParameters()</c> binding is judged against <c>TPM2_Duplicate()</c>'s REAL
    /// parameter area: the DUP policy <c>PolicyCommandCode(TPM_CC_Duplicate)</c> then
    /// <c>PolicyParameters(H(TPM_CC_Duplicate || encryptionKeyIn || symmetricAlg))</c> — the pHash over the command
    /// code and the parameters as sent, the Names skipped ("commandTag, commandSize and the Names of the
    /// associated objects are not included in pHash") — admits the export.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.24; clause 13.1, Table 36; Part 4 CompareParametersHash</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyParametersBoundToTheRealParameterAreaAdmitsDuplicate()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-parameters-duplicate", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse newParent = await CreateDistinctStorageParentAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, noDa: false).ConfigureAwait(false);
        byte[] newParentName = newParent.Name.Span.ToArray();
        byte[] parametersHash = DuplicateParametersHash();
        byte[] authPolicy = PredictCommandCodeThenParameters(TpmCcConstants.TPM_CC_Duplicate, parametersHash);

        uint objectHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (objectHandle, byte[] objectName) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parent.ObjectHandle.Value, SecretBytes, authPolicy, isDuplicable: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            sessionHandle = await StartSessionAsync(tpm, isTrial: false).ConfigureAwait(false);
            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(sessionHandle, TpmCcConstants.TPM_CC_Duplicate, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");
            TpmResult<PolicyParametersResponse> parametersResult = await tpm.PolicyParametersAsync(sessionHandle, parametersHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(parametersResult.IsSuccess, $"PolicyParameters failed: '{parametersResult.ResponseCode}'.");

            TpmResult<DuplicateResponse> duplicateResult = await DuplicateAsync(tpm, registry, pool, objectHandle, newParent.ObjectHandle.Value, sessionHandle, objectName, newParentName).ConfigureAwait(false);
            Assert.IsTrue(duplicateResult.IsSuccess, $"Duplicate under the matching pHash binding failed: '{duplicateResult.ResponseCode}'.");

            using DuplicateResponse duplicated = duplicateResult.Value;
            Assert.IsFalse(duplicated.Duplicate.IsEmpty, "The export must produce a duplication blob.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, objectHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, newParent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a <c>TPM2_PolicyParameters()</c> binding whose pHash was computed over a DIFFERENT parameter area
    /// refuses <c>TPM2_Duplicate()</c> with a <c>TPM_RC_POLICY_FAIL</c>, session-encoded to the same index even though the session's
    /// policyDigest reproduces the object's authPolicy: "the pHash is checked when policySession is used to
    /// authorize a command", against the parameters the command actually carries.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.24; Part 4 CheckPolicyAuthSession/CompareParametersHash</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyParametersBoundToAnotherParameterAreaRefusesDuplicate()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-parameters-duplicate-mismatch", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse newParent = await CreateDistinctStorageParentAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER, noDa: false).ConfigureAwait(false);
        byte[] newParentName = newParent.Name.Span.ToArray();

        //A pHash over TPM_CC_Duplicate and a parameter area this model's TPM2_Duplicate() never carries — an empty
        //encryptionKeyIn followed by symmetricAlg = TPM_ALG_AES (0x0006) rather than TPM_ALG_NULL — so the real
        //command's pHash cannot equal it.
        byte[] otherParameters = [0x00, 0x00, 0x01, 0x4B, 0x00, 0x00, 0x00, 0x06];
        byte[] parametersHash = SHA256.HashData(otherParameters);
        byte[] authPolicy = PredictCommandCodeThenParameters(TpmCcConstants.TPM_CC_Duplicate, parametersHash);

        uint objectHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (objectHandle, byte[] objectName) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parent.ObjectHandle.Value, SecretBytes, authPolicy, isDuplicable: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            sessionHandle = await StartSessionAsync(tpm, isTrial: false).ConfigureAwait(false);
            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(sessionHandle, TpmCcConstants.TPM_CC_Duplicate, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");
            TpmResult<PolicyParametersResponse> parametersResult = await tpm.PolicyParametersAsync(sessionHandle, parametersHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(parametersResult.IsSuccess, $"PolicyParameters failed: '{parametersResult.ResponseCode}'.");

            TpmResult<DuplicateResponse> duplicateResult = await DuplicateAsync(tpm, registry, pool, objectHandle, newParent.ObjectHandle.Value, sessionHandle, objectName, newParentName).ConfigureAwait(false);

            Assert.IsFalse(duplicateResult.IsSuccess, "A pHash over another parameter area must refuse the real Duplicate.");
            Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), duplicateResult.ResponseCode, "The pHash binding mismatch is the policy's own TPM_RC_POLICY_FAIL, session-encoded to the sole authorizing policy session.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, objectHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, newParent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A fabricated 34-octet Name — a SHA-256 <c>nameAlg</c> prefix (<c>0x000B</c>) over 32 octets of
    /// <paramref name="fill"/> — standing in for an object or parent Name where only its shape matters.
    /// </summary>
    /// <param name="fill">The octet the digest part is filled with.</param>
    /// <returns>The Name octets.</returns>
    private static byte[] FabricatedName(byte fill)
    {
        byte[] name = new byte[34];
        name[1] = 0x0B;
        name.AsSpan(2).Fill(fill);

        return name;
    }

    /// <summary>
    /// The host prediction of <c>TPM2_PolicyDuplicationSelect()</c>'s fold from a fresh session
    /// (<see cref="TpmPolicyDigest.ExtendForDuplicationSelect"/> over a Zero Digest).
    /// </summary>
    /// <param name="objectName">The object Name, read only when <paramref name="isObjectIncluded"/> is SET.</param>
    /// <param name="newParentName">The new parent Name.</param>
    /// <param name="isObjectIncluded">The <c>includeObject</c> value.</param>
    /// <returns>The predicted policyDigest.</returns>
    private static byte[] PredictDuplicationSelect(ReadOnlySpan<byte> objectName, ReadOnlySpan<byte> newParentName, bool isObjectIncluded)
    {
        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] predicted = new byte[size];
        _ = TpmPolicyDigest.ExtendForDuplicationSelect(new byte[size], objectName, newParentName, isObjectIncluded, SessionAlg, predicted, BaseMemoryPool.Shared);

        return predicted;
    }

    /// <summary>
    /// The host prediction of <c>TPM2_PolicyCommandCode()</c> then <c>TPM2_PolicyParameters()</c> from a fresh
    /// session — the DUP-role policy that also binds the command's parameters.
    /// </summary>
    /// <param name="commandCode">The command code the policy restricts to.</param>
    /// <param name="parametersHash">The pHash the policy binds to.</param>
    /// <returns>The predicted policyDigest.</returns>
    private static byte[] PredictCommandCodeThenParameters(TpmCcConstants commandCode, ReadOnlySpan<byte> parametersHash)
    {
        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] afterCommandCode = new byte[size];
        _ = TpmPolicyDigest.ExtendForCommandCode(new byte[size], commandCode, SessionAlg, afterCommandCode, BaseMemoryPool.Shared);
        byte[] predicted = new byte[size];
        _ = TpmPolicyDigest.ExtendForParameters(afterCommandCode, parametersHash, SessionAlg, predicted, BaseMemoryPool.Shared);

        return predicted;
    }

    /// <summary>
    /// The pHash of the <c>TPM2_Duplicate()</c> this model frames: <c>SHA-256(TPM_CC_Duplicate || encryptionKeyIn
    /// || symmetricAlg)</c> over the no-inner-wrapper form — an empty <c>TPM2B_DATA</c> (<c>0x0000</c>) and
    /// <c>TPM_ALG_NULL</c> (<c>0x0010</c>) — with the command's two handle Names skipped (TPM 2.0 Library Part 3,
    /// clause 23.24; clause 13.1, Table 36), computed in-test as an independent oracle.
    /// </summary>
    /// <returns>The pHash.</returns>
    private static byte[] DuplicateParametersHash()
    {
        byte[] input = [0x00, 0x00, 0x01, 0x4B, 0x00, 0x00, 0x00, 0x10];

        return SHA256.HashData(input);
    }

    /// <summary>
    /// Builds <c>TPM2_PolicyAuthorize()</c>'s <c>aHash = H(approvedPolicy || policyRef)</c> (TPM 2.0 Library Part
    /// 3, clause 23.16, equation 33) as an in-test SHA-256 oracle.
    /// </summary>
    /// <param name="approvedPolicy">The policy digest being approved.</param>
    /// <param name="policyRef">The policy qualifier.</param>
    /// <returns>The computed aHash.</returns>
    private static byte[] ComputeAuthorizeAHash(ReadOnlySpan<byte> approvedPolicy, ReadOnlySpan<byte> policyRef)
    {
        byte[] message = new byte[approvedPolicy.Length + policyRef.Length];
        approvedPolicy.CopyTo(message);
        policyRef.CopyTo(message.AsSpan(approvedPolicy.Length));

        return SHA256.HashData(message);
    }

    /// <summary>
    /// Concatenates the two ECDSA components into the IEEE P1363 <c>r || s</c> form
    /// <see cref="VerifySignatureInput.ForEcdsa"/> takes, each right-aligned in its 32-octet field.
    /// </summary>
    /// <param name="r">The <c>r</c> component.</param>
    /// <param name="s">The <c>s</c> component.</param>
    /// <param name="pool">The memory pool backing the returned signature.</param>
    /// <returns>The concatenated signature; the caller disposes it.</returns>
    private static Signature ConcatenateP1363(ReadOnlySpan<byte> r, ReadOnlySpan<byte> s, BaseMemoryPool pool)
    {
        const int P256ComponentSize = 32;
        IMemoryOwner<byte> owner = pool.Rent(2 * P256ComponentSize);
        Span<byte> destination = owner.Memory.Span[..(2 * P256ComponentSize)];
        destination.Clear();
        CopyFixed(r, destination[..P256ComponentSize]);
        CopyFixed(s, destination.Slice(P256ComponentSize, P256ComponentSize));

        return new Signature(owner, CryptoTags.P256Signature);

        //Copies a component right-aligned into the fixed field width, truncating leading octets when over-long.
        static void CopyFixed(ReadOnlySpan<byte> value, Span<byte> destination)
        {
            if(value.Length <= destination.Length)
            {
                value.CopyTo(destination[^value.Length..]);
            }
            else
            {
                value[^destination.Length..].CopyTo(destination);
            }
        }
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_PolicyDuplicationSelect()</c> the typed input cannot express — an out-of-set
    /// <c>includeObject</c> octet, an over-bound Name, or a trailing octet — and submits it, returning the
    /// response code.
    /// </summary>
    /// <param name="simulator">The simulator to submit to.</param>
    /// <param name="pool">The memory pool the frame is rented from.</param>
    /// <param name="sessionHandle">The policy session handle.</param>
    /// <param name="objectName">The objectName octets, framed as a <c>TPM2B_NAME</c> whatever their length.</param>
    /// <param name="newParentName">The newParentName octets.</param>
    /// <param name="includeObject">The includeObject octet as sent.</param>
    /// <param name="hasTrailingOctet">Whether one surplus octet follows includeObject.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitDuplicationSelectFramedAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint sessionHandle, byte[] objectName, byte[] newParentName, byte includeObject, bool hasTrailingOctet)
    {
        int length = TpmHeader.HeaderSize + sizeof(uint) + sizeof(ushort) + objectName.Length + sizeof(ushort) + newParentName.Length + sizeof(byte) + (hasTrailingOctet ? 1 : 0);
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_PolicyDuplicationSelect);
        header.WriteTo(ref writer);
        writer.WriteUInt32(sessionHandle);
        writer.WriteTpm2b(objectName);
        writer.WriteTpm2b(newParentName);
        writer.WriteByte(includeObject);
        if(hasTrailingOctet)
        {
            writer.WriteByte(0x00);
        }

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed PolicyDuplicationSelect must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// Issues <c>TPM2_Duplicate()</c> of <paramref name="objectHandle"/> to <paramref name="newParentHandle"/>
    /// over the policy session, the two handle Names supplied for the executor's cpHash.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="objectHandle">The loaded duplicable object.</param>
    /// <param name="newParentHandle">The new parent.</param>
    /// <param name="sessionHandle">The DUP-role policy session.</param>
    /// <param name="objectName">The object's Name.</param>
    /// <param name="newParentName">The new parent's Name.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<DuplicateResponse>> DuplicateAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint objectHandle, uint newParentHandle, uint sessionHandle, byte[] objectName, byte[] newParentName)
    {
        DuplicateInput input = new(objectHandle, newParentHandle);
        using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);

        return await TpmCommandExecutor.ExecuteAsync<DuplicateResponse>(
            tpm, input, [policySession], [objectName, newParentName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates an ECC P-256 storage parent under <paramref name="hierarchy"/> whose template differs from
    /// <see cref="PolicySweepHarness.CreateStorageParentAsync"/>'s by the <c>noDA</c> attribute or the hierarchy,
    /// so its Name differs from that deterministic parent's.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy to create the parent under.</param>
    /// <param name="noDa">The template's <c>noDA</c> attribute.</param>
    /// <returns>The CreatePrimary response; the caller owns and flushes it.</returns>
    private async Task<CreatePrimaryResponse> CreateDistinctStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, bool noDa)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(hierarchy, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary storage parent ({hierarchy}, noDA {noDa}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates an ECC P-256 ECDSA/SHA-256 signing key under the owner hierarchy, the authority whose Name is
    /// <c>keySign</c> in the <c>TPM2_PolicyAuthorize()</c> composition.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response; the caller owns and flushes it.</returns>
    private async Task<CreatePrimaryResponse> CreateEccAuthorityKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256 authority key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Starts a real or trial policy session with no assertions yet made against it.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="isTrial">Whether to start a trial session.</param>
    /// <returns>The started session handle.</returns>
    private async Task<uint> StartSessionAsync(TpmDevice tpm, bool isTrial)
    {
        TpmResult<StartAuthSessionResponse> startResult = isTrial
            ? await tpm.StartTrialPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false)
            : await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");
        using StartAuthSessionResponse session = startResult.Value;

        return session.SessionHandle.Value;
    }

    /// <summary>Reads a policy session's current policyDigest into an owned array.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="sessionHandle">The policy session handle.</param>
    /// <returns>A copy of the policyDigest octets.</returns>
    private async Task<byte[]> GetDigestAsync(TpmDevice tpm, uint sessionHandle)
    {
        TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");
        using PolicyGetDigestResponse digest = digestResult.Value;

        return digest.PolicyDigest.AsReadOnlySpan().ToArray();
    }

    /// <summary>The response codec registry every executor-driven command in this class needs.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Duplicate, TpmResponseCodec.Duplicate);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySignature, TpmResponseCodec.VerifySignature);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyDuplicationSelect, TpmResponseCodec.PolicyDuplicationSelect);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }
}
