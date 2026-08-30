using System;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using System.Security.Cryptography;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_PolicyCpHash()</c> (TPM 2.0 Library Part 3, Section 23.13), <c>TPM2_PolicyNameHash()</c>
/// (Section 23.14), <c>TPM2_PolicyTemplate()</c> (Section 23.21), and <c>TPM2_PolicyParameters()</c> (Section
/// 23.24) against the in-house <see cref="TpmSimulator"/> through the production command path: the four share a
/// single policy-session digest slot (Part 1, Table 8), so each one's own assertion also has to prove which of
/// the others it refuses to coexist with — and the slot's use-time compare is proved from the binding side,
/// refusing a non-matching command and, for the Name-free pHash, admitting a matching one.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorPolicyDigestSlotTests
{
    /// <summary>A fixed 32-octet digest standing in for a command parameter/Name/template hash, never itself computed by SHA-256.</summary>
    private static readonly byte[] DigestA = Convert.FromHexString("A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1");

    /// <summary>A second fixed 32-octet digest, distinct from <see cref="DigestA"/>.</summary>
    private static readonly byte[] DigestB = Convert.FromHexString("B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2");

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies <c>TPM2_PolicyCpHash()</c> folds <c>H(policyDigest || TPM_CC_PolicyCpHash || cpHashA)</c>
    /// (Part 3, Section 23.13), matching <see cref="TpmPolicyDigest.ExtendForCpHash"/> from a fresh policyDigest.
    /// </summary>
    [TestMethod]
    public async Task PolicyCpHashFoldsTheExpectedDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-cphash-fold", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] predicted = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForCpHash(zero, DigestA, PolicySweepHarness.SessionAlg, predicted);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);

            TpmResult<PolicyCpHashResponse> cpHashResult = await tpm.PolicyCpHashAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(cpHashResult.IsSuccess, $"PolicyCpHash failed: '{cpHashResult.ResponseCode}'.");

            byte[] actual = await GetDigestAsync(tpm, sessionHandle).ConfigureAwait(false);

            Assert.IsTrue(actual.AsSpan().SequenceEqual(predicted), "PolicyCpHash must fold H(policyDigest || TPM_CC_PolicyCpHash || cpHashA).");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyCpHash()</c> refuses a cpHashA whose size does not match the session's policyDigest
    /// width with <c>TPM_RC_SIZE</c> (Part 3, Section 23.13: "If cpHashA does not have the size of the
    /// policySession→policyDigest, the TPM shall return TPM_RC_SIZE").
    /// </summary>
    [TestMethod]
    public async Task PolicyCpHashRefusesAWrongSizeDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-cphash-size", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            ReadOnlyMemory<byte> wrongSize = DigestA.AsMemory(0, 31);

            TpmResult<PolicyCpHashResponse> result = await tpm.PolicyCpHashAsync(sessionHandle, wrongSize, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A 31-octet cpHashA against a SHA-256 session must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, result.ResponseCode, "A wrong-size cpHashA must refuse TPM_RC_SIZE.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyCpHash()</c> refuses a second, different cpHashA with <c>TPM_RC_CPHASH</c> (Part 3,
    /// Section 23.13: "If policySession→cpHash is already set and not the same as cpHashA... TPM_RC_CPHASH"),
    /// while re-asserting the SAME cpHashA is accepted ("the TPM does not return an error if cpHash is the
    /// same").
    /// </summary>
    [TestMethod]
    public async Task PolicyCpHashRefusesADifferentSecondCpHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-cphash-conflict", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        uint conflictSession = 0;
        uint repeatSession = 0;
        try
        {
            conflictSession = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyCpHashResponse> firstAssertion = await tpm.PolicyCpHashAsync(conflictSession, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(firstAssertion.IsSuccess, $"PolicyCpHash(A) failed: '{firstAssertion.ResponseCode}'.");

            TpmResult<PolicyCpHashResponse> conflicting = await tpm.PolicyCpHashAsync(conflictSession, DigestB, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(conflicting.IsSuccess, "A different second cpHashA must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_CPHASH, conflicting.ResponseCode, "A conflicting cpHashA must refuse TPM_RC_CPHASH.");

            repeatSession = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyCpHashResponse> repeatFirst = await tpm.PolicyCpHashAsync(repeatSession, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(repeatFirst.IsSuccess, $"PolicyCpHash(A) failed: '{repeatFirst.ResponseCode}'.");
            TpmResult<PolicyCpHashResponse> repeatSame = await tpm.PolicyCpHashAsync(repeatSession, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(repeatSame.IsSuccess, "The SAME cpHashA re-asserted must be accepted.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, conflictSession, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, repeatSession, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyNameHash()</c> folds <c>H(policyDigest || TPM_CC_PolicyNameHash || nameHash)</c>
    /// (Part 3, Section 23.14), matching <see cref="TpmPolicyDigest.ExtendForNameHash"/> from a fresh
    /// policyDigest.
    /// </summary>
    [TestMethod]
    public async Task PolicyNameHashFoldsTheExpectedDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-namehash-fold", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] predicted = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForNameHash(zero, DigestA, PolicySweepHarness.SessionAlg, predicted);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);

            TpmResult<PolicyNameHashResponse> nameHashResult = await tpm.PolicyNameHashAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(nameHashResult.IsSuccess, $"PolicyNameHash failed: '{nameHashResult.ResponseCode}'.");

            byte[] actual = await GetDigestAsync(tpm, sessionHandle).ConfigureAwait(false);

            Assert.IsTrue(actual.AsSpan().SequenceEqual(predicted), "PolicyNameHash must fold H(policyDigest || TPM_CC_PolicyNameHash || nameHash).");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyNameHash()</c> refuses ANY prior occupant of the shared cpHash slot with
    /// <c>TPM_RC_CPHASH</c> (Part 3, Section 23.14: "If policySession→cpHash is already set, the TPM shall
    /// return TPM_RC_CPHASH") — unlike <c>TPM2_PolicyCpHash()</c>, even the SAME nameHash re-asserted is refused,
    /// since the clause carries no equality escape.
    /// </summary>
    [TestMethod]
    public async Task PolicyNameHashRefusesAnyOccupiedSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-namehash-occupied", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        uint afterCpHashSession = 0;
        uint repeatSession = 0;
        try
        {
            afterCpHashSession = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyCpHashResponse> cpHashResult = await tpm.PolicyCpHashAsync(afterCpHashSession, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(cpHashResult.IsSuccess, $"PolicyCpHash failed: '{cpHashResult.ResponseCode}'.");

            TpmResult<PolicyNameHashResponse> afterCpHash = await tpm.PolicyNameHashAsync(afterCpHashSession, DigestB, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(afterCpHash.IsSuccess, "PolicyNameHash after a PolicyCpHash occupant must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_CPHASH, afterCpHash.ResponseCode, "PolicyNameHash after PolicyCpHash must refuse TPM_RC_CPHASH.");

            repeatSession = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyNameHashResponse> firstNameHash = await tpm.PolicyNameHashAsync(repeatSession, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(firstNameHash.IsSuccess, $"PolicyNameHash(A) failed: '{firstNameHash.ResponseCode}'.");
            TpmResult<PolicyNameHashResponse> repeatNameHash = await tpm.PolicyNameHashAsync(repeatSession, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(repeatNameHash.IsSuccess, "The SAME nameHash re-asserted must still be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_CPHASH, repeatNameHash.ResponseCode, "A re-asserted nameHash must refuse TPM_RC_CPHASH.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, afterCpHashSession, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, repeatSession, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyTemplate()</c> folds <c>H(policyDigest || TPM_CC_PolicyTemplate ||
    /// templateHash)</c> (Part 3, Section 23.21), matching <see cref="TpmPolicyDigest.ExtendForTemplate"/> from a
    /// fresh policyDigest.
    /// </summary>
    [TestMethod]
    public async Task PolicyTemplateFoldsTheExpectedDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-template-fold", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] predicted = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForTemplate(zero, DigestA, PolicySweepHarness.SessionAlg, predicted);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);

            TpmResult<PolicyTemplateResponse> templateResult = await tpm.PolicyTemplateAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(templateResult.IsSuccess, $"PolicyTemplate failed: '{templateResult.ResponseCode}'.");

            byte[] actual = await GetDigestAsync(tpm, sessionHandle).ConfigureAwait(false);

            Assert.IsTrue(actual.AsSpan().SequenceEqual(predicted), "PolicyTemplate must fold H(policyDigest || TPM_CC_PolicyTemplate || templateHash).");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyTemplate()</c> refuses a different second templateHash with <c>TPM_RC_VALUE</c>
    /// (Part 3, Section 23.21: "If policySession→isTemplateSet is SET and policySession→cpHash is not equal to
    /// templateHash, the TPM shall return TPM_RC_VALUE"), while the SAME templateHash re-asserted is accepted.
    /// </summary>
    [TestMethod]
    public async Task PolicyTemplateRefusesADifferentTemplateWithValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-template-value", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        uint conflictSession = 0;
        uint repeatSession = 0;
        try
        {
            conflictSession = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyTemplateResponse> firstAssertion = await tpm.PolicyTemplateAsync(conflictSession, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(firstAssertion.IsSuccess, $"PolicyTemplate(A) failed: '{firstAssertion.ResponseCode}'.");

            TpmResult<PolicyTemplateResponse> conflicting = await tpm.PolicyTemplateAsync(conflictSession, DigestB, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(conflicting.IsSuccess, "A different second templateHash must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, conflicting.ResponseCode, "A conflicting templateHash must refuse TPM_RC_VALUE.");

            repeatSession = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyTemplateResponse> repeatFirst = await tpm.PolicyTemplateAsync(repeatSession, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(repeatFirst.IsSuccess, $"PolicyTemplate(A) failed: '{repeatFirst.ResponseCode}'.");
            TpmResult<PolicyTemplateResponse> repeatSame = await tpm.PolicyTemplateAsync(repeatSession, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(repeatSame.IsSuccess, "The SAME templateHash re-asserted must be accepted.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, conflictSession, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, repeatSession, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyTemplate()</c> refuses a prior <c>TPM2_PolicyCpHash()</c> occupant with
    /// <c>TPM_RC_CPHASH</c> (Part 3, Section 23.21: "if policySession→cpHash is already set, the TPM shall
    /// return TPM_RC_CPHASH").
    /// </summary>
    [TestMethod]
    public async Task PolicyTemplateRefusesAfterACpHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-template-after-cphash", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyCpHashResponse> cpHashResult = await tpm.PolicyCpHashAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(cpHashResult.IsSuccess, $"PolicyCpHash failed: '{cpHashResult.ResponseCode}'.");

            TpmResult<PolicyTemplateResponse> templateResult = await tpm.PolicyTemplateAsync(sessionHandle, DigestB, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(templateResult.IsSuccess, "PolicyTemplate after a PolicyCpHash occupant must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_CPHASH, templateResult.ResponseCode, "PolicyTemplate after PolicyCpHash must refuse TPM_RC_CPHASH.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a policy session bound to an arbitrary cpHash (a digest deliberately different from the real
    /// command parameter digest) refuses <c>TPM2_Unseal()</c> with a bare <c>TPM_RC_POLICY_FAIL</c> even though
    /// its accumulated policyDigest matches the sealed object's authPolicy: the use-time binding check recomputes
    /// the REAL cpHash of the authorized command and finds it unequal to the latched value (Part 3, Section
    /// 23.13), proving the binding is enforced rather than merely folded.
    /// </summary>
    [TestMethod]
    public async Task PolicyCpHashBindingRefusesANonMatchingCommandAtUnseal()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] secret = "sealed-under-cphash-binding"u8.ToArray();

        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-cphash-binding", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] authPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForCpHash(zero, DigestA, PolicySweepHarness.SessionAlg, authPolicy);

        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (itemHandle, byte[] name) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parentHandle, secret, authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [name];

            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyCpHashResponse> cpHashResult = await tpm.PolicyCpHashAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(cpHashResult.IsSuccess, $"PolicyCpHash failed: '{cpHashResult.ResponseCode}'.");

            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, PolicySweepHarness.SessionAlg, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(itemHandle));
            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(unsealResult.IsSuccess, "A cpHash bound to an arbitrary digest must refuse an unseal whose real cpHash differs.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, unsealResult.ResponseCode, "The cpHash binding mismatch is the policy's own bare TPM_RC_POLICY_FAIL.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, itemHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a policy session bound to an arbitrary nameHash refuses <c>TPM2_Unseal()</c> with a bare
    /// <c>TPM_RC_POLICY_FAIL</c> even though its accumulated policyDigest matches the sealed object's authPolicy:
    /// the use-time binding check recomputes the REAL nameHash (the digest of the authorized command's target
    /// Name) and finds it unequal to the latched value (Part 3, Section 23.14).
    /// </summary>
    [TestMethod]
    public async Task PolicyNameHashBindingRefusesANonMatchingCommandAtUnseal()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] secret = "sealed-under-namehash-binding"u8.ToArray();

        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-namehash-binding", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] authPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForNameHash(zero, DigestA, PolicySweepHarness.SessionAlg, authPolicy);

        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (itemHandle, byte[] name) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parentHandle, secret, authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [name];

            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyNameHashResponse> nameHashResult = await tpm.PolicyNameHashAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(nameHashResult.IsSuccess, $"PolicyNameHash failed: '{nameHashResult.ResponseCode}'.");

            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, PolicySweepHarness.SessionAlg, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(itemHandle));
            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(unsealResult.IsSuccess, "A nameHash bound to an arbitrary digest must refuse an unseal whose real nameHash differs.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, unsealResult.ResponseCode, "The nameHash binding mismatch is the policy's own bare TPM_RC_POLICY_FAIL.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, itemHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a policy session bound to a creation template ALWAYS refuses <c>TPM2_Unseal()</c> with a bare
    /// <c>TPM_RC_POLICY_FAIL</c>, even though its accumulated policyDigest matches the sealed object's
    /// authPolicy: a template binding can only be satisfied by an object-creation command (Part 3, Section
    /// 23.21), and Unseal is not one, so the deferred use-time check (Part 4 <c>CheckPolicyAuthSession</c>)
    /// refuses unconditionally rather than comparing a recomputed digest.
    /// </summary>
    [TestMethod]
    public async Task PolicyTemplateAtUseAlwaysFailsUnseal()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] secret = "sealed-under-template-binding"u8.ToArray();

        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-template-binding", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] authPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForTemplate(zero, DigestA, PolicySweepHarness.SessionAlg, authPolicy);

        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (itemHandle, byte[] name) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parentHandle, secret, authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [name];

            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyTemplateResponse> templateResult = await tpm.PolicyTemplateAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(templateResult.IsSuccess, $"PolicyTemplate failed: '{templateResult.ResponseCode}'.");

            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, PolicySweepHarness.SessionAlg, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(itemHandle));
            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(unsealResult.IsSuccess, "A session carrying a template binding must never authorize an Unseal.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, unsealResult.ResponseCode, "A template binding at use is a bare TPM_RC_POLICY_FAIL regardless of the digest match.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, itemHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyParameters()</c> folds <c>H(policyDigest || TPM_CC_PolicyParameters || pHash)</c>
    /// (Part 3, Section 23.24), matching <see cref="TpmPolicyDigest.ExtendForParameters"/> from a fresh policyDigest.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.24</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyParametersFoldsTheExpectedDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-parameters-fold", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] predicted = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForParameters(zero, DigestA, PolicySweepHarness.SessionAlg, predicted);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);

            TpmResult<PolicyParametersResponse> parametersResult = await tpm.PolicyParametersAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(parametersResult.IsSuccess, $"PolicyParameters failed: '{parametersResult.ResponseCode}'.");

            byte[] actual = await GetDigestAsync(tpm, sessionHandle).ConfigureAwait(false);

            Assert.IsTrue(actual.AsSpan().SequenceEqual(predicted), "PolicyParameters must fold H(policyDigest || TPM_CC_PolicyParameters || pHash).");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyParameters()</c> refuses a pHash whose size does not match the session's policyDigest
    /// width with <c>TPM_RC_SIZE</c> ("If the size of pHash is not the size of policySession→policyDigest, the TPM
    /// shall return TPM_RC_SIZE").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.24</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyParametersRefusesAWrongSizeDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-parameters-size", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);

            TpmResult<PolicyParametersResponse> result = await tpm.PolicyParametersAsync(sessionHandle, DigestA.AsMemory(0, 20), TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A 20-octet pHash on a SHA-256 session must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, result.ResponseCode, "A pHash of the wrong width is TPM_RC_SIZE.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies the size check answers ahead of the occupancy check: a wrong-width pHash on a session whose slot
    /// is already occupied is <c>TPM_RC_SIZE</c>, not <c>TPM_RC_CPHASH</c> — the clause states the size rule first
    /// and the reference tests it first (Part 4 <c>PolicyParameters.c</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.24</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyParametersAnswersSizeAheadOfAnOccupiedSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-parameters-size-order", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyCpHashResponse> cpHashResult = await tpm.PolicyCpHashAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(cpHashResult.IsSuccess, $"PolicyCpHash failed: '{cpHashResult.ResponseCode}'.");

            TpmResult<PolicyParametersResponse> result = await tpm.PolicyParametersAsync(sessionHandle, DigestB.AsMemory(0, 20), TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A wrong-width pHash must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, result.ResponseCode, "The size rule answers before the occupied slot does.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyParameters()</c> refuses a session whose shared slot already holds a
    /// <c>TPM2_PolicyCpHash()</c> digest with <c>TPM_RC_CPHASH</c> ("Only one of the following … can be used for a
    /// policy session … If policySession→cpHash is already set, the TPM shall return TPM_RC_CPHASH").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.24</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyParametersRefusesAnOccupiedSlotAfterPolicyCpHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-parameters-after-cphash", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyCpHashResponse> cpHashResult = await tpm.PolicyCpHashAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(cpHashResult.IsSuccess, $"PolicyCpHash failed: '{cpHashResult.ResponseCode}'.");

            TpmResult<PolicyParametersResponse> result = await tpm.PolicyParametersAsync(sessionHandle, DigestB, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A cpHash-occupied slot must refuse PolicyParameters.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_CPHASH, result.ResponseCode, "An occupied slot is TPM_RC_CPHASH.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a second <c>TPM2_PolicyParameters()</c> with the SAME pHash is refused with <c>TPM_RC_CPHASH</c>:
    /// the reference tests the slot's occupancy with no equality escape (Part 4 <c>IsCpHashUnionOccupied</c>),
    /// unlike <c>TPM2_PolicyCpHash()</c>'s "the TPM does not return an error if cpHash is the same".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.24</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyParametersRefusesItselfAssertedTwice()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-parameters-twice", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyParametersResponse> first = await tpm.PolicyParametersAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(first.IsSuccess, $"The first PolicyParameters failed: '{first.ResponseCode}'.");

            TpmResult<PolicyParametersResponse> second = await tpm.PolicyParametersAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(second.IsSuccess, "The same pHash asserted twice must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_CPHASH, second.ResponseCode, "An occupied slot is TPM_RC_CPHASH even when the octets agree.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyCpHash()</c> refuses a session whose shared slot holds a <c>TPM2_PolicyParameters()</c>
    /// pHash with <c>TPM_RC_CPHASH</c> — the exclusion in the other direction: a pHash occupant is neither the
    /// empty slot nor a cpHash the same value could re-propose.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.13; clause 23.24; Part 1, Table 8</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyCpHashRefusesAnOccupiedSlotAfterPolicyParameters()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-cphash-after-parameters", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyParametersResponse> parametersResult = await tpm.PolicyParametersAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(parametersResult.IsSuccess, $"PolicyParameters failed: '{parametersResult.ResponseCode}'.");

            TpmResult<PolicyCpHashResponse> result = await tpm.PolicyCpHashAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A pHash-occupied slot must refuse PolicyCpHash, the same octets included.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_CPHASH, result.ResponseCode, "An occupant of another kind is TPM_RC_CPHASH.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a policy session bound to an arbitrary pHash refuses <c>TPM2_Unseal()</c> with a bare
    /// <c>TPM_RC_POLICY_FAIL</c> even though its accumulated policyDigest matches the sealed object's authPolicy:
    /// "This is a deferred assertion and the pHash is checked when policySession is used to authorize a command",
    /// and the digest recomputed over the command's code and (empty) parameters differs.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.24; Part 4 CheckPolicyAuthSession/CompareParametersHash</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyParametersBindingRefusesANonMatchingCommandAtUnseal()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] secret = "sealed-under-parameters-binding"u8.ToArray();

        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-parameters-binding", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] authPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForParameters(zero, DigestA, PolicySweepHarness.SessionAlg, authPolicy);

        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (itemHandle, byte[] name) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parentHandle, secret, authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [name];

            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyParametersResponse> parametersResult = await tpm.PolicyParametersAsync(sessionHandle, DigestA, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(parametersResult.IsSuccess, $"PolicyParameters failed: '{parametersResult.ResponseCode}'.");

            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, PolicySweepHarness.SessionAlg, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(itemHandle));
            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(unsealResult.IsSuccess, "A pHash bound to an arbitrary digest must refuse an unseal whose real pHash differs.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, unsealResult.ResponseCode, "The pHash binding mismatch is the policy's own bare TPM_RC_POLICY_FAIL.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, itemHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a policy session bound to <c>TPM2_Unseal()</c>'s real pHash — <c>H(TPM_CC_Unseal)</c>, the
    /// command carrying no parameters and its handle Name being skipped ("the Names of the associated objects
    /// are not included in pHash") — ADMITS the unseal: unlike a cpHash or nameHash, a pHash never covers the
    /// object's own Name, so the binding a sealed object's policy names can be satisfied by that very object.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.24; clause 12.7, Table 30; Part 4 CompareParametersHash</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyParametersBindingAdmitsUnsealWhosePHashMatches()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] secret = "sealed-under-matching-parameters-binding"u8.ToArray();

        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-parameters-binding-match", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        //pHash = SHA-256(TPM_CC_Unseal) — the four command-code octets alone, an independent in-test oracle.
        byte[] unsealParametersHash = SHA256.HashData([0x00, 0x00, 0x01, 0x5E]);
        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] authPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForParameters(zero, unsealParametersHash, PolicySweepHarness.SessionAlg, authPolicy);

        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (itemHandle, byte[] name) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parentHandle, secret, authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [name];

            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyParametersResponse> parametersResult = await tpm.PolicyParametersAsync(sessionHandle, unsealParametersHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(parametersResult.IsSuccess, $"PolicyParameters failed: '{parametersResult.ResponseCode}'.");

            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, PolicySweepHarness.SessionAlg, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(itemHandle));
            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(unsealResult.IsSuccess, $"Unseal under the matching pHash binding failed: '{unsealResult.ResponseCode}'.");

            using UnsealResponse unsealed = unsealResult.Value;
            Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(secret), "The unsealed data must equal the sealed secret.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, itemHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a policy session — here a fresh one — refuses <c>TPM2_Unseal()</c> of a sealed object whose
    /// authPolicy is EMPTY with <c>TPM_RC_POLICY_FAIL</c>: a loaded object's policy is always available to the
    /// session machinery (Part 4 <c>IsAuthPolicyAvailable</c>'s transient arm), and the compare of a digest-width
    /// policyDigest against an empty authPolicy can never succeed (<c>CheckPolicyAuthSession</c>), so an object
    /// with no policy cannot be authorized by any policy session — its authValue is the only way in.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6; clause 12.7; Part 1, clause 19.2; Part 4 CheckPolicyAuthSession</see>.
    /// </summary>
    [TestMethod]
    public async Task UnsealOverAPolicySessionRefusesAnObjectWithAnEmptyAuthPolicy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] secret = "sealed-with-no-policy"u8.ToArray();

        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-empty-authpolicy-unseal", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (itemHandle, byte[] name) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parentHandle, secret, ReadOnlyMemory<byte>.Empty, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [name];

            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);

            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, PolicySweepHarness.SessionAlg, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(itemHandle));
            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(unsealResult.IsSuccess, "An object with an empty authPolicy must not be unsealed over a policy session.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, unsealResult.ResponseCode, "An empty authPolicy never equals a session's policyDigest: TPM_RC_POLICY_FAIL.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, itemHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Starts a policy session with no assertions yet made against it.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <returns>The started policy session handle.</returns>
    private async Task<uint> StartSessionAsync(TpmDevice tpm)
    {
        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(PolicySweepHarness.SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
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
}
