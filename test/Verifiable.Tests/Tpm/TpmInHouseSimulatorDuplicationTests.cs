using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_Duplicate()</c> against the in-house behavioural <see cref="TpmSimulator"/> through the
/// production command path (<see cref="TpmCommandExecutor"/> with the real <see cref="DuplicateInput"/> and
/// response codec): a duplicable sealed object — its template's <c>fixedTPM</c>/<c>fixedParent</c> CLEAR and its
/// authPolicy the <c>TPM2_PolicyCommandCode(TPM_CC_Duplicate)</c> digest — is created and loaded under one
/// storage parent, a real policy session latches the command code, and the export is exercised under
/// elliptic-curve, RSA, and <c>TPM_RH_NULL</c> new parents alongside the DUP-role refusal ladder
/// (TPM 2.0 Library Part 3, clause 13.1; Part 1, Clause 20). <c>TPM2_Import()</c> completes the migration:
/// every exported blob is brought in under its new parent, loaded, and unsealed — the destination half of
/// clause 12.3 — alongside its own attribute and integrity refusals.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorDuplicationTests
{
    /// <summary>The session/name hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The SHA-256 digest width the policy digests carry.</summary>
    private const int DigestSize = 32;

    /// <summary>The fixed secret sealed into the duplicable object.</summary>
    private static byte[] SecretBytes { get; } = "Move this secret to a new parent."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The full export choreography under an elliptic-curve new parent: create a duplicable sealed object whose
    /// authPolicy is the <c>TPM2_PolicyCommandCode(TPM_CC_Duplicate)</c> digest, load it, latch the command code
    /// on a real policy session, and <c>TPM2_Duplicate()</c> to a second storage parent — the DUP role's minimal
    /// policy (TPM 2.0 Library Part 3, clause 13.1). The no-inner-wrapper form answers an empty
    /// <c>encryptionKeyOut</c>, a non-empty duplication blob, and the ephemeral-point seed transport
    /// (Part 1, clause 20.3.2.3); the command leaves the pool balanced once its response is released.
    /// </summary>
    [TestMethod]
    public async Task DuplicableSealedObjectDuplicatesUnderAnEccNewParent()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint parentHandle, byte[] _) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint objectHandle, byte[] objectName, byte[] _) = await CreateAndLoadDuplicableObjectAsync(tpm, registry, pool, parentHandle, DuplicationPolicyDigest()).ConfigureAwait(false);
        (uint newParentHandle, byte[] newParentName) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint sessionHandle = await StartRealPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            await AssertCommandCodeAsync(tpm, registry, pool, sessionHandle, TpmCcConstants.TPM_CC_Duplicate).ConfigureAwait(false);

            long baseline = trackingPool.OutstandingCount;

            {
                DuplicateInput input = new(objectHandle, newParentHandle);
                using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);

                TpmResult<DuplicateResponse> result = await TpmCommandExecutor.ExecuteAsync<DuplicateResponse>(
                    tpm, input, [policySession], [objectName, newParentName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"Duplicate (elliptic-curve new parent) failed: '{result.ResponseCode}'.");

                using DuplicateResponse response = result.Value;
                Assert.AreEqual(0, response.EncryptionKeyOut.Length, "The no-inner-wrapper form answers an empty encryptionKeyOut.");
                Assert.IsFalse(response.Duplicate.IsEmpty, "The export must produce a duplication blob.");

                //The seed transport to a P-256 parent is a marshaled TPMS_ECC_POINT: two TPM2B-prefixed
                //32-octet coordinates (Part 1, clause 20.3.2.3; Part 2, clause 11.2.5.2, Table 198).
                Assert.AreEqual(2 * (sizeof(ushort) + 32), response.OutSymSeed.Length, "The seed rides an ephemeral P-256 point.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The export must leave the pool balanced once its response carriers are released.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The same export under an RSA new parent: the outer-wrapper seed travels RSA-OAEP-encrypted to the new
    /// parent's modulus under the "DUPLICATE" label (TPM 2.0 Library Part 1, clause 20.3.2.3), so
    /// <c>outSymSeed</c> is one modulus-width ciphertext.
    /// </summary>
    [TestMethod]
    public async Task DuplicableSealedObjectDuplicatesUnderAnRsaNewParent()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint parentHandle, byte[] _) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint objectHandle, byte[] objectName, byte[] _) = await CreateAndLoadDuplicableObjectAsync(tpm, registry, pool, parentHandle, DuplicationPolicyDigest()).ConfigureAwait(false);

        using CreatePrimaryInput rsaParentInput = CreatePrimaryInput.ForRsaStorageParent(TpmRh.TPM_RH_OWNER, null, 2048, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> rsaParentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, rsaParentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rsaParentResult.IsSuccess, $"CreatePrimary (RSA new parent) failed: '{rsaParentResult.ResponseCode}'.");
        using CreatePrimaryResponse rsaParent = rsaParentResult.Value;

        uint sessionHandle = await StartRealPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            await AssertCommandCodeAsync(tpm, registry, pool, sessionHandle, TpmCcConstants.TPM_CC_Duplicate).ConfigureAwait(false);

            DuplicateInput input = new(objectHandle, rsaParent.ObjectHandle.Value);
            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);

            TpmResult<DuplicateResponse> result = await TpmCommandExecutor.ExecuteAsync<DuplicateResponse>(
                tpm, input, [policySession], [objectName, rsaParent.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Duplicate (RSA new parent) failed: '{result.ResponseCode}'.");

            using DuplicateResponse response = result.Value;
            Assert.IsFalse(response.Duplicate.IsEmpty, "The export must produce a duplication blob.");
            Assert.AreEqual(256, response.OutSymSeed.Length, "The seed rides one 2048-bit RSA-OAEP ciphertext.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The DUP-role refusal ladder (TPM 2.0 Library Part 3, clause 13.1; Part 1, clause 16.2): a satisfied
    /// policy session that never latched a command code is <c>TPM_RC_POLICY_FAIL</c>; one latched to a
    /// DIFFERENT command is <c>TPM_RC_POLICY_CC</c>; a non-duplicable object (<c>fixedParent</c> SET) under a
    /// correctly latched session is <c>TPM_RC_ATTRIBUTES</c>; and an object whose authPolicy is empty has no
    /// policy any session can reproduce, so its DUP role is unsatisfiable — <c>TPM_RC_POLICY_FAIL</c>.
    /// </summary>
    [TestMethod]
    public async Task DuplicateRefusalLadderAnswersTheClauseCodes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint parentHandle, byte[] _) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint newParentHandle, byte[] newParentName) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint duplicableHandle, byte[] duplicableName, byte[] _) = await CreateAndLoadDuplicableObjectAsync(tpm, registry, pool, parentHandle, DuplicationPolicyDigest()).ConfigureAwait(false);

        //A session that satisfied the (empty-assertion) policy but never latched a command code. Its digest
        //cannot equal the object's PolicyCommandCode-shaped authPolicy either, so the refusal is the same
        //POLICY_FAIL both readings give.
        uint unlatchedSession = await StartRealPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
        await AssertDuplicateRefusalAsync(tpm, registry, pool, duplicableHandle, newParentHandle, unlatchedSession, [duplicableName, newParentName], HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0),
            "A policy session that never latched a command code cannot carry the DUP role.").ConfigureAwait(false);

        //A session latched to a DIFFERENT command: its digest folded that command's code, so the policy gate —
        //which runs first, in the reference machinery's order — already cannot match this object's policy.
        //TPM_RC_POLICY_CC stays as the fail-closed arm behind a MATCHING digest, which no
        //PolicyCommandCode-shaped authPolicy can pair with a foreign latch.
        uint mislatchedSession = await StartRealPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
        await AssertCommandCodeAsync(tpm, registry, pool, mislatchedSession, TpmCcConstants.TPM_CC_Unseal).ConfigureAwait(false);
        await AssertDuplicateRefusalAsync(tpm, registry, pool, duplicableHandle, newParentHandle, mislatchedSession, [duplicableName, newParentName], HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0),
            "A foreign latch folds a foreign policy, refused at the digest gate.").ConfigureAwait(false);

        //A NON-duplicable object (fixedParent SET) with the same authPolicy, under a correctly latched and
        //satisfied session: the attribute row refuses.
        (uint boundHandle, byte[] boundName, byte[] _) = await CreateAndLoadBoundObjectAsync(tpm, registry, pool, parentHandle, DuplicationPolicyDigest()).ConfigureAwait(false);
        uint latchedSession = await StartRealPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
        await AssertCommandCodeAsync(tpm, registry, pool, latchedSession, TpmCcConstants.TPM_CC_Duplicate).ConfigureAwait(false);
        await AssertDuplicateRefusalAsync(tpm, registry, pool, boundHandle, newParentHandle, latchedSession, [boundName, newParentName], HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0),
            "An object with fixedParent SET may not leave its parent.").ConfigureAwait(false);

        //A duplicable object with an EMPTY authPolicy: no session digest can reproduce the empty value, so the
        //DUP role is unsatisfiable by construction.
        (uint policyFreeHandle, byte[] policyFreeName, byte[] _) = await CreateAndLoadDuplicableObjectAsync(tpm, registry, pool, parentHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        uint latchedSecondSession = await StartRealPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
        await AssertCommandCodeAsync(tpm, registry, pool, latchedSecondSession, TpmCcConstants.TPM_CC_Duplicate).ConfigureAwait(false);
        await AssertDuplicateRefusalAsync(tpm, registry, pool, policyFreeHandle, newParentHandle, latchedSecondSession, [policyFreeName, newParentName], HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0),
            "An empty authPolicy leaves the DUP role unsatisfiable.").ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that <c>TPM2_Duplicate()</c>'s DUP-role policy slot (session index 0, its only session) is
    /// refused with <c>TPM_RC_ATTRIBUTES</c> encoded to that index once its attributes octet claims
    /// <c>audit</c>: "This attribute is not allowed to be SET in a policy or trial policy session. This is
    /// because the context of the policy session would have to increase in order to hold the additional audit
    /// digest." (TPM 2.0 Library Part 1, clause 15.6.4, Table 15, the <c>audit</c> row).
    /// </summary>
    /// <remarks>
    /// The audit bit is planted onto the wire after the command is composed and satisfied through the real
    /// policy session, since no production caller composes such a claim.
    /// </remarks>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1</see>.
    [TestMethod]
    public async Task DuplicatePolicySlotClaimingAuditIsRefusedWithAttributesAtItsOwnIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint parentHandle, byte[] _) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint newParentHandle, byte[] newParentName) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint objectHandle, byte[] objectName, byte[] _) = await CreateAndLoadDuplicableObjectAsync(tpm, registry, pool, parentHandle, DuplicationPolicyDigest()).ConfigureAwait(false);

        uint sessionHandle = await StartRealPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            await AssertCommandCodeAsync(tpm, registry, pool, sessionHandle, TpmCcConstants.TPM_CC_Duplicate).ConfigureAwait(false);

            using TpmDevice plantingTpm = TpmDevice.Create(async (command, commandPool, cancellationToken) =>
            {
                byte[] bytes = command.ToArray();
                if(ReadCommandCode(bytes) == TpmCcConstants.TPM_CC_Duplicate)
                {
                    SetSessionAttributeBit(bytes, handleCount: 2, sessionIndex: 0, TpmaSession.AUDIT);
                }

                return await simulator.SubmitAsync(bytes, commandPool, cancellationToken).ConfigureAwait(false);
            }, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

            DuplicateInput input = new(objectHandle, newParentHandle);
            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);

            TpmResult<DuplicateResponse> result = await TpmCommandExecutor.ExecuteAsync<DuplicateResponse>(
                plantingTpm, input, [policySession], [objectName, newParentName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_ATTRIBUTES, result.BaseError,
                "A policy session may not claim audit, so the claim is an attribute error.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), result.ResponseCode,
                "The refusal names the DUP-role policy slot at index 0, session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies that <c>TPM2_Duplicate()</c>'s DUP-role policy slot is refused with <c>TPM_RC_ATTRIBUTES</c>
    /// encoded to its index when it claims <c>auditExclusive</c> or <c>auditReset</c> without also claiming
    /// <c>audit</c>: "This setting is only allowed if the audit attribute is SET (TPM_RC_ATTRIBUTES)" (TPM 2.0
    /// Library Part 2, clause 8.4, Table 38, bits 1 and 2).
    /// </summary>
    /// <param name="claimedAttribute">The bit claimed alone, without <c>audit</c>.</param>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.4</see>.
    [TestMethod]
    [DataRow(TpmaSession.AUDIT_EXCLUSIVE, DisplayName = "auditExclusive without audit")]
    [DataRow(TpmaSession.AUDIT_RESET, DisplayName = "auditReset without audit")]
    public async Task DuplicatePolicySlotClaimingAuditExclusiveOrAuditResetWithoutAuditIsRefusedWithAttributesAtItsOwnIndex(TpmaSession claimedAttribute)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint parentHandle, byte[] _) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint newParentHandle, byte[] newParentName) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint objectHandle, byte[] objectName, byte[] _) = await CreateAndLoadDuplicableObjectAsync(tpm, registry, pool, parentHandle, DuplicationPolicyDigest()).ConfigureAwait(false);

        uint sessionHandle = await StartRealPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            await AssertCommandCodeAsync(tpm, registry, pool, sessionHandle, TpmCcConstants.TPM_CC_Duplicate).ConfigureAwait(false);

            using TpmDevice plantingTpm = TpmDevice.Create(async (command, commandPool, cancellationToken) =>
            {
                byte[] bytes = command.ToArray();
                if(ReadCommandCode(bytes) == TpmCcConstants.TPM_CC_Duplicate)
                {
                    SetSessionAttributeBit(bytes, handleCount: 2, sessionIndex: 0, claimedAttribute);
                }

                return await simulator.SubmitAsync(bytes, commandPool, cancellationToken).ConfigureAwait(false);
            }, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

            DuplicateInput input = new(objectHandle, newParentHandle);
            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);

            TpmResult<DuplicateResponse> result = await TpmCommandExecutor.ExecuteAsync<DuplicateResponse>(
                plantingTpm, input, [policySession], [objectName, newParentName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_ATTRIBUTES, result.BaseError,
                $"{claimedAttribute} without audit is an attribute error.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), result.ResponseCode,
                "The refusal names the DUP-role policy slot at index 0, session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>symmetricAlg</c> other than <c>TPM_ALG_NULL</c> — the inner duplication wrapper this model does not
    /// implement — is refused <c>TPM_RC_SYMMETRIC</c> at the wire, before its key-size and mode fields are read
    /// (the recorded partial-modeling divergence; TPM 2.0 Library Part 3, clause 13.1 carries the same code for
    /// the encryptedDuplication consistency rows). The typed input cannot express the shape, so the command is
    /// hand-framed.
    /// </summary>
    [TestMethod]
    public async Task DuplicateWithAnInnerWrapperAlgorithmIsRefusedWithSymmetric()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint parentHandle, byte[] _) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint objectHandle, byte[] _, byte[] _) = await CreateAndLoadDuplicableObjectAsync(tpm, registry, pool, parentHandle, DuplicationPolicyDigest()).ConfigureAwait(false);
        uint sessionHandle = await StartRealPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
        await AssertCommandCodeAsync(tpm, registry, pool, sessionHandle, TpmCcConstants.TPM_CC_Duplicate).ConfigureAwait(false);

        //[objectHandle][TPM_RH_NULL][auth area: the policy session][TPM2B empty][TPMT_SYM_DEF_OBJECT = AES].
        TpmRcConstants responseCode = await SubmitDuplicateFramedAsync(
            simulator, pool, objectHandle, (uint)TpmRh.TPM_RH_NULL, sessionHandle, symmetricAlg: (ushort)TpmAlgIdConstants.TPM_ALG_AES).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SYMMETRIC, parameterIndex: 1), responseCode,
            "Table 36: symmetricAlg is TPM2_Duplicate()'s second parameter (index 1); an inner-wrapper symmetricAlg is refused with TPM_RC_SYMMETRIC there while only the NULL form is modeled.");
    }

    /// <summary>
    /// A <c>TPM_RH_NULL</c> new parent with no inner wrapper produces "a <c>TPM2B_SENSITIVE</c> [as] the only
    /// contents of the <c>TPM2B_PRIVATE</c> buffer" (TPM 2.0 Library Part 1, Clause 20) — no integrity value,
    /// no encryption, no transported seed. The blob is checked against the shape the specification derives:
    /// the marshaled <c>TPMT_SENSITIVE</c> with its KEYEDHASH selector, the authValue padded to its maximum
    /// size (clause 24.7.3), a nameAlg-width obfuscation value, and the sealed data IN THE CLEAR.
    /// </summary>
    [TestMethod]
    public async Task DuplicateToTheNullParentHandsOutTheBareSensitiveArea()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint parentHandle, byte[] _) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint objectHandle, byte[] objectName, byte[] _) = await CreateAndLoadDuplicableObjectAsync(tpm, registry, pool, parentHandle, DuplicationPolicyDigest()).ConfigureAwait(false);
        uint sessionHandle = await StartRealPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            await AssertCommandCodeAsync(tpm, registry, pool, sessionHandle, TpmCcConstants.TPM_CC_Duplicate).ConfigureAwait(false);

            DuplicateInput input = new(objectHandle, (uint)TpmRh.TPM_RH_NULL);
            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);

            //A permanent handle's Name is its own four big-endian octets (Part 1, clause 13, Table 9).
            byte[] nullParentName = new byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(nullParentName, (uint)TpmRh.TPM_RH_NULL);
            TpmResult<DuplicateResponse> result = await TpmCommandExecutor.ExecuteAsync<DuplicateResponse>(
                tpm, input, [policySession], [objectName, nullParentName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Duplicate (TPM_RH_NULL new parent) failed: '{result.ResponseCode}'.");

            using DuplicateResponse response = result.Value;
            Assert.AreEqual(0, response.OutSymSeed.Length, "No seed is transported when there is no new parent.");

            //The spec-derived bare shape: [UINT16 interior size][UINT16 TPM_ALG_KEYEDHASH]
            //[TPM2B authValue, padded to 64][TPM2B seedValue, one SHA-256 width][TPM2B data = the secret].
            ReadOnlySpan<byte> bare = response.Duplicate.Span;
            int offset = 0;
            ushort interiorSize = BinaryPrimitives.ReadUInt16BigEndian(bare);
            offset += sizeof(ushort);
            Assert.AreEqual(bare.Length - sizeof(ushort), interiorSize, "The TPM2B_SENSITIVE size prefix must cover exactly the marshaled TPMT_SENSITIVE.");

            Assert.AreEqual((ushort)TpmAlgIdConstants.TPM_ALG_KEYEDHASH, BinaryPrimitives.ReadUInt16BigEndian(bare[offset..]), "A sealed data object's sensitiveType is TPM_ALG_KEYEDHASH.");
            offset += sizeof(ushort);

            Assert.AreEqual(64, BinaryPrimitives.ReadUInt16BigEndian(bare[offset..]), "The authValue travels padded to its maximum size (clause 24.7.3).");
            offset += sizeof(ushort) + 64;

            Assert.AreEqual(DigestSize, BinaryPrimitives.ReadUInt16BigEndian(bare[offset..]), "The obfuscation value is one nameAlg digest wide.");
            offset += sizeof(ushort) + DigestSize;

            Assert.AreEqual(SecretBytes.Length, BinaryPrimitives.ReadUInt16BigEndian(bare[offset..]), "The sensitive data slot carries the sealed secret.");
            offset += sizeof(ushort);
            Assert.IsTrue(
                bare.Slice(offset, SecretBytes.Length).SequenceEqual(SecretBytes),
                "With no new parent and no inner wrapper, the sealed data leaves in the clear — the clause's own no-wrapper form.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The migration's destination half under an elliptic-curve parent (TPM 2.0 Library Part 3, clause 13.3):
    /// the exported blob and seed import under the new parent — the seed recovered by ECDH under the
    /// "DUPLICATE" label, the duplication wrap verified and undone, the sensitive area re-wrapped — and the
    /// re-wrapped <c>outPrivate</c> loads and unseals the original secret byte for byte.
    /// </summary>
    [TestMethod]
    public async Task DuplicatedObjectImportsLoadsAndUnsealsUnderTheEccNewParent()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint parentHandle, byte[] _) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint objectHandle, byte[] objectName, byte[] publicOctets) = await CreateAndLoadDuplicableObjectAsync(tpm, registry, pool, parentHandle, DuplicationPolicyDigest()).ConfigureAwait(false);
        (uint newParentHandle, byte[] newParentName) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        (byte[] duplicate, byte[] outSymSeed) = await DuplicateToAsync(tpm, registry, pool, objectHandle, objectName, newParentHandle, newParentName).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        uint importedHandle = await ImportLoadAndUnsealAsync(tpm, registry, pool, newParentHandle, publicOctets, duplicate, outSymSeed).ConfigureAwait(false);
        await FlushIfPresentAsync(tpm, registry, pool, importedHandle).ConfigureAwait(false);
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The whole import, load, unseal, and eviction chain must return every rental it made.");
    }

    /// <summary>
    /// The same destination half under an RSA parent: the seed recovered by RSA-OAEP under the "DUPLICATE"
    /// label (TPM 2.0 Library Part 1, clause 20.3.2.3), then the identical unwrap, re-wrap, load, and unseal.
    /// </summary>
    [TestMethod]
    public async Task DuplicatedObjectImportsLoadsAndUnsealsUnderTheRsaNewParent()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint parentHandle, byte[] _) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint objectHandle, byte[] objectName, byte[] publicOctets) = await CreateAndLoadDuplicableObjectAsync(tpm, registry, pool, parentHandle, DuplicationPolicyDigest()).ConfigureAwait(false);

        using CreatePrimaryInput rsaParentInput = CreatePrimaryInput.ForRsaStorageParent(TpmRh.TPM_RH_OWNER, null, 2048, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> rsaParentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, rsaParentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rsaParentResult.IsSuccess, $"CreatePrimary (RSA new parent) failed: '{rsaParentResult.ResponseCode}'.");
        using CreatePrimaryResponse rsaParent = rsaParentResult.Value;

        (byte[] duplicate, byte[] outSymSeed) = await DuplicateToAsync(
            tpm, registry, pool, objectHandle, objectName, rsaParent.ObjectHandle.Value, rsaParent.Name.Span.ToArray()).ConfigureAwait(false);

        await ImportLoadAndUnsealAsync(tpm, registry, pool, rsaParent.ObjectHandle.Value, publicOctets, duplicate, outSymSeed).ConfigureAwait(false);
    }

    /// <summary>
    /// A blob duplicated to <c>TPM_RH_NULL</c> — the bare marshaled <c>TPM2B_SENSITIVE</c> with no seed — is a
    /// valid import source: an empty <c>inSymSeed</c> selects the no-wrapper recovery (TPM 2.0 Library Part 3,
    /// clause 13.3), and the re-wrapped object loads and unseals under the real parent.
    /// </summary>
    [TestMethod]
    public async Task NullParentDuplicateImportsLoadsAndUnsealsUnderARealParent()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint parentHandle, byte[] _) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint objectHandle, byte[] objectName, byte[] publicOctets) = await CreateAndLoadDuplicableObjectAsync(tpm, registry, pool, parentHandle, DuplicationPolicyDigest()).ConfigureAwait(false);
        (uint newParentHandle, byte[] _) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        //A permanent handle's Name is its own four big-endian octets (Part 1, clause 13, Table 9).
        byte[] nullParentName = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(nullParentName, (uint)TpmRh.TPM_RH_NULL);
        (byte[] bareDuplicate, byte[] emptySeed) = await DuplicateToAsync(
            tpm, registry, pool, objectHandle, objectName, (uint)TpmRh.TPM_RH_NULL, nullParentName).ConfigureAwait(false);
        Assert.IsEmpty(emptySeed, "No seed is transported when there is no new parent.");

        await ImportLoadAndUnsealAsync(tpm, registry, pool, newParentHandle, publicOctets, bareDuplicate, emptySeed).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_Import()</c>'s attribute row: a public area with <c>fixedTPM</c> or <c>fixedParent</c> SET is
    /// refused <c>TPM_RC_ATTRIBUTES</c> — a duplicated object is definitionally unbound (TPM 2.0 Library
    /// Part 2, clauses 8.3.3.2 and 8.3.3.4; Part 3, clause 13.3) — and the gate answers before any integrity
    /// evaluation, so even a blob that could never verify refuses on the attributes alone.
    /// </summary>
    [TestMethod]
    public async Task ImportOfABoundPublicAreaIsRefusedWithAttributes()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint parentHandle, byte[] _) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint objectHandle, byte[] objectName, byte[] _) = await CreateAndLoadDuplicableObjectAsync(tpm, registry, pool, parentHandle, DuplicationPolicyDigest()).ConfigureAwait(false);
        (uint newParentHandle, byte[] newParentName) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (byte[] duplicate, byte[] outSymSeed) = await DuplicateToAsync(tpm, registry, pool, objectHandle, objectName, newParentHandle, newParentName).ConfigureAwait(false);

        //A BOUND public area (fixedTPM/fixedParent SET) presented with the exported blob.
        using Tpm2bPublic boundTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: true);
        byte[] boundOctets = new byte[boundTemplate.GetSerializedSize()];
        var boundWriter = new TpmWriter(boundOctets);
        boundTemplate.WriteTo(ref boundWriter);

        long baseline = trackingPool.OutstandingCount;

        {
            using ImportInput input = ImportInput.Create(newParentHandle, boundOctets, duplicate, outSymSeed, pool);
            using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
            TpmResult<ImportResponse> result = await TpmCommandExecutor.ExecuteAsync<ImportResponse>(
                tpm, input, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode,
                "A public area with fixedTPM or fixedParent SET cannot describe a duplicated object.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusing arm must release every request carrier the parse rented.");
    }

    /// <summary>
    /// Corruption refusals across both parent types (TPM 2.0 Library Part 3, clause 13.3): a flipped octet in
    /// the duplication blob's ciphertext fails the outer-HMAC compare with <c>TPM_RC_INTEGRITY</c>; a flipped
    /// octet in the RSA seed transport fails the OAEP decode, whose deferred substitution (the v184 Part 1,
    /// clause A.10.3 rule; its rationale survives as Part 3, clause 13.3.1) surfaces the SAME <c>TPM_RC_INTEGRITY</c> so a probe cannot tell the secret
    /// paths apart; and a flipped octet in the elliptic-curve transport takes the point off the curve — a
    /// public property of the octets — answering the dedicated <c>TPM_RC_ECC_POINT</c>.
    /// </summary>
    [TestMethod]
    public async Task TamperedDuplicateOrSeedIsRefusedWithIntegrityUnderBothParentTypes()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint parentHandle, byte[] _) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint objectHandle, byte[] objectName, byte[] publicOctets) = await CreateAndLoadDuplicableObjectAsync(tpm, registry, pool, parentHandle, DuplicationPolicyDigest()).ConfigureAwait(false);

        (uint eccParentHandle, byte[] eccParentName) = await CreateEccStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (byte[] eccDuplicate, byte[] eccSeed) = await DuplicateToAsync(tpm, registry, pool, objectHandle, objectName, eccParentHandle, eccParentName).ConfigureAwait(false);

        using CreatePrimaryInput rsaParentInput = CreatePrimaryInput.ForRsaStorageParent(TpmRh.TPM_RH_OWNER, null, 2048, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> rsaParentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, rsaParentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rsaParentResult.IsSuccess, $"CreatePrimary (RSA parent) failed: '{rsaParentResult.ResponseCode}'.");
        using CreatePrimaryResponse rsaParent = rsaParentResult.Value;
        (byte[] rsaDuplicate, byte[] rsaSeed) = await DuplicateToAsync(
            tpm, registry, pool, objectHandle, objectName, rsaParent.ObjectHandle.Value, rsaParent.Name.Span.ToArray()).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        //The blob's first integrity octet sits after the UINT16 width; the first ciphertext octet after the
        //SHA-256 integrity value.
        byte[] tamperedEccHmac = (byte[])eccDuplicate.Clone();
        tamperedEccHmac[sizeof(ushort)] ^= 0xFF;
        await AssertImportRefusalAsync(tpm, registry, pool, eccParentHandle, publicOctets, tamperedEccHmac, eccSeed,
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 2), "A corrupted outer HMAC must fail its own compare at duplicate, parameter 3 of Table 40.").ConfigureAwait(false);

        byte[] tamperedEccDuplicate = (byte[])eccDuplicate.Clone();
        tamperedEccDuplicate[sizeof(ushort) + DigestSize] ^= 0xFF;
        await AssertImportRefusalAsync(tpm, registry, pool, eccParentHandle, publicOctets, tamperedEccDuplicate, eccSeed,
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 2), "A corrupted duplication blob must fail its outer-HMAC compare at duplicate, parameter 3 of Table 40.").ConfigureAwait(false);

        //A flipped coordinate octet takes the transported point off the curve — a PUBLIC property of the
        //octets, so the dedicated point refusal leaks nothing an observer could not already compute.
        byte[] tamperedEccSeed = (byte[])eccSeed.Clone();
        tamperedEccSeed[sizeof(ushort)] ^= 0xFF;
        await AssertImportRefusalAsync(tpm, registry, pool, eccParentHandle, publicOctets, eccDuplicate, tamperedEccSeed,
            TpmRcConstants.TPM_RC_ECC_POINT, "An off-curve transported point is the dedicated public refusal (Part 2, clause 6.6.3, Table 18).").ConfigureAwait(false);

        byte[] tamperedRsaSeed = (byte[])rsaSeed.Clone();
        tamperedRsaSeed[0] ^= 0xFF;
        await AssertImportRefusalAsync(tpm, registry, pool, rsaParent.ObjectHandle.Value, publicOctets, rsaDuplicate, tamperedRsaSeed,
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 2), "A failed RSA-OAEP decode substitutes an unpredictable seed, so the refusal is the same TPM_RC_INTEGRITY at duplicate, parameter 3 of Table 40.").ConfigureAwait(false);

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Every refusing recovery arm must return the request carriers and its own scratch rentals.");
    }

    /// <summary>
    /// The "DUPLICATE" label and the whole outer-wrap construction proven against an INDEPENDENT transcription
    /// of the specification: this test builds its own duplication package — a fabricated sensitive area, a
    /// fresh seed RSA-OAEP-encrypted to the parent's modulus under the "DUPLICATE" label with its terminating
    /// zero (TPM 2.0 Library Part 1, clauses A.4 and 20.3.2.3), the zero-IV CFB encryption under
    /// <c>KDFa(nameAlg, seed, "STORAGE", name, 128)</c> and the outer HMAC under
    /// <c>KDFa(nameAlg, seed, "INTEGRITY")</c> over <c>dupSensitive ‖ name.buffer</c> (Clause 20, equations
    /// 40–43) — entirely from project crypto, never the simulator's wrap code. <c>TPM2_Import()</c> accepting
    /// it, and the loaded object unsealing the fabricated data, falsifies label or construction drift the
    /// round-trip tests (which share code on both sides) cannot see. The SAME seed and blob transported under
    /// the "IDENTITY" label are refused with the deferred-substitution <c>TPM_RC_INTEGRITY</c>: only the label
    /// differs, so the pair is the cross-label proof of clause 20.3.2.3's domain separation.
    /// </summary>
    [TestMethod]
    public async Task IndependentlyConstructedDuplicateImportsAndTheIdentityLabelIsRefused()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput rsaParentInput = CreatePrimaryInput.ForRsaStorageParent(TpmRh.TPM_RH_OWNER, null, 2048, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> rsaParentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, rsaParentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rsaParentResult.IsSuccess, $"CreatePrimary (RSA import parent) failed: '{rsaParentResult.ResponseCode}'.");
        using CreatePrimaryResponse rsaParent = rsaParentResult.Value;
        byte[] parentModulus = rsaParent.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();

        //The fabricated sensitive area: TPM2B_SENSITIVE over TPMT_SENSITIVE(KEYEDHASH ‖ 64-octet padded empty
        //authValue ‖ 32-octet obfuscation ‖ the test's own data) — Part 2, clause 12.3, Tables 240/241 by hand.
        byte[] fabricatedData = "Independently constructed migration payload."u8.ToArray();
        byte[] obfuscation = new byte[DigestSize];
        obfuscation.AsSpan().Fill(0x5A);
        int interiorLength = sizeof(ushort) + (sizeof(ushort) + 64) + (sizeof(ushort) + DigestSize) + (sizeof(ushort) + fabricatedData.Length);
        byte[] sensitive = new byte[sizeof(ushort) + interiorLength];
        var sensitiveWriter = new TpmWriter(sensitive);
        sensitiveWriter.WriteUInt16((ushort)interiorLength);
        sensitiveWriter.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_KEYEDHASH);
        sensitiveWriter.WriteTpm2b(new byte[64]);
        sensitiveWriter.WriteTpm2b(obfuscation);
        sensitiveWriter.WriteTpm2b(fabricatedData);

        //The public area is fabricated with the sensitive area, its unique = H_nameAlg(seedValue ‖ data) —
        //Part 2, clause 12.2.3.1, equation (8), the binding TPM2_Import() recomputes — and the Name it derives
        //(nameAlg ‖ H_nameAlg(TPMT_PUBLIC), Part 1, clause 13, Table 9) is what every wrap below binds to; both
        //come from the framework's SHA-256 as an independent oracle, never from the simulator's own composition.
        byte[] uniqueInput = new byte[DigestSize + fabricatedData.Length];
        obfuscation.CopyTo(uniqueInput, 0);
        fabricatedData.CopyTo(uniqueInput, DigestSize);
        byte[] fabricatedUnique = System.Security.Cryptography.SHA256.HashData(uniqueInput);

        using Tpm2bPublic fabricatedPublic = Tpm2bPublic.CreateKeyedHashTemplate(
            SessionAlg, TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA, TpmsKeyedHashParms.SealedData, DuplicationPolicyDigest().Span, pool, fabricatedUnique);
        int fabricatedPublicSize = fabricatedPublic.GetSerializedSize();
        byte[] publicOctets = new byte[fabricatedPublicSize];
        var fabricatedPublicWriter = new TpmWriter(publicOctets);
        fabricatedPublic.WriteTo(ref fabricatedPublicWriter);

        byte[] objectName = new byte[sizeof(ushort) + DigestSize];
        var fabricatedNameWriter = new TpmWriter(objectName);
        fabricatedNameWriter.WriteUInt16((ushort)SessionAlg);
        fabricatedNameWriter.WriteBytes(System.Security.Cryptography.SHA256.HashData(publicOctets.AsSpan(sizeof(ushort))));

        //The transport seed and both of its OAEP encryptions — one per label, terminating zero included.
        byte[] seedBytes = new byte[DigestSize];
        seedBytes.AsSpan().Fill(0xC3);
        TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();
        byte[] duplicateLabelSeed;
        using(IMemoryOwner<byte> encrypted = await rsaBackend.EncryptOaep(
            parentModulus, TpmsRsaParms.DefaultExponent, seedBytes, "DUPLICATE\0"u8.ToArray(),
            TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_SHA256, pool, TestContext.CancellationToken).ConfigureAwait(false))
        {
            duplicateLabelSeed = encrypted.Memory.ToArray();
        }

        byte[] identityLabelSeed;
        using(IMemoryOwner<byte> encrypted = await rsaBackend.EncryptOaep(
            parentModulus, TpmsRsaParms.DefaultExponent, seedBytes, "IDENTITY\0"u8.ToArray(),
            TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_SHA256, pool, TestContext.CancellationToken).ConfigureAwait(false))
        {
            identityLabelSeed = encrypted.Memory.ToArray();
        }

        //The outer wrap from the equations: symKey and HMACkey from KDFa over the seed, zero-IV CFB, HMAC over
        //dupSensitive ‖ name.buffer, integrity before ciphertext.
        byte[] encSensitive = (byte[])sensitive.Clone();
        using(IMemoryOwner<byte> symKey = await Kdfa.DeriveAsync(
            System.Security.Cryptography.HashAlgorithmName.SHA256, seedBytes, "STORAGE", objectName, ReadOnlyMemory<byte>.Empty, 128, pool, TestContext.CancellationToken).ConfigureAwait(false))
        {
            TpmParameterEncryption.AesCfb(symKey.Memory.Span[..16], new byte[16], encSensitive, encrypting: true);
        }

        byte[] hmacMessage = new byte[encSensitive.Length + objectName.Length];
        encSensitive.CopyTo(hmacMessage, 0);
        objectName.CopyTo(hmacMessage, encSensitive.Length);
        byte[] outerHmacOctets;
        using(IMemoryOwner<byte> hmacKey = await Kdfa.DeriveAsync(
            System.Security.Cryptography.HashAlgorithmName.SHA256, seedBytes, "INTEGRITY", ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, DigestSize * 8, pool, TestContext.CancellationToken).ConfigureAwait(false))
        using(HmacValue outerHmac = await CryptographicKeyEvents.ComputeHmacAsync(
            hmacMessage, hmacKey.Memory[..DigestSize], DigestSize, CryptoTags.HmacSha256Value, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            outerHmacOctets = outerHmac.AsReadOnlySpan().ToArray();
        }

        byte[] duplicateBlob = new byte[sizeof(ushort) + DigestSize + encSensitive.Length];
        var blobWriter = new TpmWriter(duplicateBlob);
        blobWriter.WriteUInt16(DigestSize);
        blobWriter.WriteBytes(outerHmacOctets);
        blobWriter.WriteBytes(encSensitive);

        //The DUPLICATE-labeled package imports, loads, and unseals the fabricated data.
        await ImportLoadAndUnsealAsync(
            tpm, registry, pool, rsaParent.ObjectHandle.Value, publicOctets, duplicateBlob, duplicateLabelSeed, fabricatedData).ConfigureAwait(false);

        //The SAME seed and blob under the IDENTITY label: the decode fails, the substitution defers, the outer
        //HMAC refuses.
        await AssertImportRefusalAsync(tpm, registry, pool, rsaParent.ObjectHandle.Value, publicOctets, duplicateBlob, identityLabelSeed,
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 2), "The IDENTITY label must not recover a DUPLICATE-use seed (Part 1, clause 20.3.2.3) at duplicate, parameter 3 of Table 40.").ConfigureAwait(false);

        //The elliptic-curve arm of the same proof: an ephemeral ECDH transport whose seed the test derives
        //itself with KDFe under the "DUPLICATE" label (Part 1, clauses 44.7.1 and 20.3.2.3, equation 63), wrapping
        //the same fabricated sensitive area — accepted, loaded, and unsealed, which falsifies KDFe label or
        //party-info drift the shared-constant round-trips cannot see.
        using CreatePrimaryInput eccDestinationInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession eccOwnerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> eccDestinationResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, eccDestinationInput, [eccOwnerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(eccDestinationResult.IsSuccess, $"CreatePrimary (elliptic-curve import parent) failed: '{eccDestinationResult.ResponseCode}'.");
        using CreatePrimaryResponse eccDestination = eccDestinationResult.Value;

        TpmsEccPoint destinationPoint = eccDestination.OutPublic.PublicArea.Unique.Ecc!;
        byte[] destinationX = destinationPoint.X.AsReadOnlySpan().ToArray();
        byte[] destinationSec1 = new byte[1 + (2 * destinationX.Length)];
        destinationSec1[0] = 0x04;
        destinationX.CopyTo(destinationSec1, 1);
        destinationPoint.Y.AsReadOnlySpan().CopyTo(destinationSec1.AsSpan(1 + destinationX.Length));

        TpmEccSigningBackend eccBackend = BouncyCastleTpmEccSigningBackend.Create();
        byte[] eccSeedBytes;
        byte[] marshaledEphemeralPoint;
        using(TpmGeneratedEccKey ephemeral = await eccBackend.GenerateKey(TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, TestContext.CancellationToken).ConfigureAwait(false))
        {
            byte[] ephemeralScalar = ephemeral.PrivateScalar.AsReadOnlySpan().ToArray();
            byte[] ephemeralX = ephemeral.PublicPoint.AsReadOnlySpan().Slice(1, destinationX.Length).ToArray();
            byte[] ephemeralY = ephemeral.PublicPoint.AsReadOnlySpan().Slice(1 + destinationX.Length, destinationX.Length).ToArray();

            marshaledEphemeralPoint = new byte[2 * (sizeof(ushort) + destinationX.Length)];
            var pointWriter = new TpmWriter(marshaledEphemeralPoint);
            pointWriter.WriteTpm2b(ephemeralX);
            pointWriter.WriteTpm2b(ephemeralY);

            using IMemoryOwner<byte> sharedValue = await eccBackend.ComputeSharedSecret(
                ephemeralScalar, destinationSec1, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, TestContext.CancellationToken).ConfigureAwait(false);
            using IMemoryOwner<byte> derivedSeed = await Kdfe.DeriveAsync(
                System.Security.Cryptography.HashAlgorithmName.SHA256, sharedValue.Memory[..destinationX.Length], "DUPLICATE", ephemeralX, destinationX,
                DigestSize * 8, pool, TestContext.CancellationToken).ConfigureAwait(false);
            eccSeedBytes = derivedSeed.Memory.Span[..DigestSize].ToArray();
        }

        byte[] eccEncSensitive = (byte[])sensitive.Clone();
        using(IMemoryOwner<byte> symKey = await Kdfa.DeriveAsync(
            System.Security.Cryptography.HashAlgorithmName.SHA256, eccSeedBytes, "STORAGE", objectName, ReadOnlyMemory<byte>.Empty, 128, pool, TestContext.CancellationToken).ConfigureAwait(false))
        {
            TpmParameterEncryption.AesCfb(symKey.Memory.Span[..16], new byte[16], eccEncSensitive, encrypting: true);
        }

        byte[] eccHmacMessage = new byte[eccEncSensitive.Length + objectName.Length];
        eccEncSensitive.CopyTo(eccHmacMessage, 0);
        objectName.CopyTo(eccHmacMessage, eccEncSensitive.Length);
        byte[] eccOuterHmacOctets;
        using(IMemoryOwner<byte> hmacKey = await Kdfa.DeriveAsync(
            System.Security.Cryptography.HashAlgorithmName.SHA256, eccSeedBytes, "INTEGRITY", ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, DigestSize * 8, pool, TestContext.CancellationToken).ConfigureAwait(false))
        using(HmacValue outerHmac = await CryptographicKeyEvents.ComputeHmacAsync(
            eccHmacMessage, hmacKey.Memory[..DigestSize], DigestSize, CryptoTags.HmacSha256Value, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            eccOuterHmacOctets = outerHmac.AsReadOnlySpan().ToArray();
        }

        byte[] eccDuplicateBlob = new byte[sizeof(ushort) + DigestSize + eccEncSensitive.Length];
        var eccBlobWriter = new TpmWriter(eccDuplicateBlob);
        eccBlobWriter.WriteUInt16(DigestSize);
        eccBlobWriter.WriteBytes(eccOuterHmacOctets);
        eccBlobWriter.WriteBytes(eccEncSensitive);

        await ImportLoadAndUnsealAsync(
            tpm, registry, pool, eccDestination.ObjectHandle.Value, publicOctets, eccDuplicateBlob, marshaledEphemeralPoint, fabricatedData).ConfigureAwait(false);
    }

    /// <summary>Runs the DUP-role export against the named new parent and returns the blob and seed octets.</summary>
    private async Task<(byte[] Duplicate, byte[] OutSymSeed)> DuplicateToAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint objectHandle, byte[] objectName, uint newParentHandle, byte[] newParentName)
    {
        uint sessionHandle = await StartRealPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            await AssertCommandCodeAsync(tpm, registry, pool, sessionHandle, TpmCcConstants.TPM_CC_Duplicate).ConfigureAwait(false);

            DuplicateInput input = new(objectHandle, newParentHandle);
            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);

            TpmResult<DuplicateResponse> result = await TpmCommandExecutor.ExecuteAsync<DuplicateResponse>(
                tpm, input, [policySession], [objectName, newParentName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Duplicate failed: '{result.ResponseCode}'.");

            using DuplicateResponse response = result.Value;

            return (response.Duplicate.Span.ToArray(), response.OutSymSeed.Span.ToArray());
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>Imports the blob under the parent, loads the re-wrapped object there, and asserts the unsealed secret matches byte for byte, returning the loaded handle.</summary>
    private Task<uint> ImportLoadAndUnsealAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, byte[] publicOctets, byte[] duplicate, byte[] outSymSeed) =>
        ImportLoadAndUnsealAsync(tpm, registry, pool, parentHandle, publicOctets, duplicate, outSymSeed, SecretBytes);

    /// <summary>Imports the blob under the parent, loads the re-wrapped object there, and asserts the unsealed data equals <paramref name="expectedData"/> byte for byte, returning the loaded handle.</summary>
    private async Task<uint> ImportLoadAndUnsealAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, byte[] publicOctets, byte[] duplicate, byte[] outSymSeed, byte[] expectedData)
    {
        using ImportInput importInput = ImportInput.Create(parentHandle, publicOctets, duplicate, outSymSeed, pool);
        using TpmPasswordSession importParentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ImportResponse> importResult = await TpmCommandExecutor.ExecuteAsync<ImportResponse>(
            tpm, importInput, [importParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(importResult.IsSuccess, $"Import failed: '{importResult.ResponseCode}'.");
        using ImportResponse imported = importResult.Value;

        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(imported.OutPrivate.Span, pool);
        var publicReader = new TpmReader(publicOctets);
        using Tpm2bPublic inPublic = Tpm2bPublic.Parse(ref publicReader, pool);
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (imported object) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        using TpmPasswordSession itemAuth = TpmPasswordSession.CreateEmpty(pool);
        UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
        TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
            tpm, unsealInput, [itemAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(unsealResult.IsSuccess, $"Unseal (imported object) failed: '{unsealResult.ResponseCode}'.");

        using UnsealResponse unsealed = unsealResult.Value;
        Assert.IsTrue(
            unsealed.OutData.AsReadOnlySpan().SequenceEqual(expectedData),
            "The migrated secret must unseal under the new parent byte for byte.");

        return loaded.ObjectHandle.Value;
    }

    /// <summary>Issues a <c>TPM2_Import()</c> expected to refuse and asserts the exact response code.</summary>
    private async Task AssertImportRefusalAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, byte[] publicOctets, byte[] duplicate, byte[] outSymSeed,
        TpmRcConstants expected, string because)
    {
        using ImportInput input = ImportInput.Create(parentHandle, publicOctets, duplicate, outSymSeed, pool);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ImportResponse> result = await TpmCommandExecutor.ExecuteAsync<ImportResponse>(
            tpm, input, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(expected, result.ResponseCode, because);
    }

    /// <summary>Computes the <c>TPM2_PolicyCommandCode(TPM_CC_Duplicate)</c> policy digest over a fresh session (TPM 2.0 Library Part 3, clause 23.11), the minimal DUP-role policy a duplicable object binds to.</summary>
    private static ReadOnlyMemory<byte> DuplicationPolicyDigest()
    {
        byte[] digest = new byte[DigestSize];
        _ = TpmPolicyDigest.ExtendForCommandCode(new byte[DigestSize], TpmCcConstants.TPM_CC_Duplicate, SessionAlg, digest, BaseMemoryPool.Shared);

        return digest;
    }

    /// <summary>Creates an elliptic-curve storage parent under the owner hierarchy and returns its handle and Name octets.</summary>
    private async Task<(uint Handle, byte[] Name)> CreateEccStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary (storage parent) failed: '{parentResult.ResponseCode}'.");

        using CreatePrimaryResponse parent = parentResult.Value;

        return (parent.ObjectHandle.Value, parent.Name.Span.ToArray());
    }

    /// <summary>Seals the fixed secret into a DUPLICABLE object under the given parent and loads it, returning the loaded handle, Name octets, and marshaled public area.</summary>
    private Task<(uint Handle, byte[] Name, byte[] PublicOctets)> CreateAndLoadDuplicableObjectAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, ReadOnlyMemory<byte> authPolicy) =>
        CreateAndLoadSealedObjectAsync(tpm, registry, pool, parentHandle, authPolicy, isDuplicable: true);

    /// <summary>Seals the fixed secret into a BOUND object (fixedTPM/fixedParent SET) under the given parent and loads it, returning the loaded handle, Name octets, and marshaled public area.</summary>
    private Task<(uint Handle, byte[] Name, byte[] PublicOctets)> CreateAndLoadBoundObjectAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, ReadOnlyMemory<byte> authPolicy) =>
        CreateAndLoadSealedObjectAsync(tpm, registry, pool, parentHandle, authPolicy, isDuplicable: false);

    /// <summary>Runs the Create-then-Load half of every choreography over the production wire path.</summary>
    private async Task<(uint Handle, byte[] Name, byte[] PublicOctets)> CreateAndLoadSealedObjectAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, ReadOnlyMemory<byte> authPolicy, bool isDuplicable)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy.Span, noDa: true, userWithAuth: true, isDuplicable: isDuplicable);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (sealed object) failed: '{createResult.ResponseCode}'.");
        using CreateResponse sealedObject = createResult.Value;

        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
        int publicSize = sealedObject.OutPublic.GetSerializedSize();
        byte[] publicOctets = new byte[publicSize];
        var publicWriter = new TpmWriter(publicOctets);
        sealedObject.OutPublic.WriteTo(ref publicWriter);
        var publicReader = new TpmReader(publicOctets);
        using Tpm2bPublic inPublic = Tpm2bPublic.Parse(ref publicReader, pool);

        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        return (loaded.ObjectHandle.Value, loaded.Name.Span.ToArray(), publicOctets);
    }

    /// <summary>Starts an unbound, unsalted REAL policy session and returns its handle.</summary>
    private async Task<uint> StartRealPolicySessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput input = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"StartAuthSession (policy) failed: '{result.ResponseCode}'.");

        using StartAuthSessionResponse response = result.Value;

        return response.SessionHandle.Value;
    }

    /// <summary>Issues a <c>TPM2_PolicyCommandCode()</c> over the session and asserts it succeeded.</summary>
    private async Task AssertCommandCodeAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint policySession, TpmCcConstants restrictedCommand)
    {
        PolicyCommandCodeInput input = PolicyCommandCodeInput.Create(policySession, restrictedCommand);
        TpmResult<PolicyCommandCodeResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyCommandCodeResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"PolicyCommandCode failed: '{result.ResponseCode}'.");
    }

    /// <summary>Issues a <c>TPM2_Duplicate()</c> expected to refuse and asserts the exact response code.</summary>
    private async Task AssertDuplicateRefusalAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint objectHandle, uint newParentHandle, uint sessionHandle,
        ReadOnlyMemory<byte>[] handleNames, TpmRcConstants expected, string because)
    {
        DuplicateInput input = new(objectHandle, newParentHandle);
        using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);

        TpmResult<DuplicateResponse> result = await TpmCommandExecutor.ExecuteAsync<DuplicateResponse>(
            tpm, input, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(expected, result.ResponseCode, because);
    }

    /// <summary>Reads a framed command's <c>commandCode</c> field (TPM 2.0 Library Part 1, clause 15.2.3's commandCode header field).</summary>
    /// <param name="command">The framed command.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(ReadOnlySpan<byte> command)
    {
        var reader = new TpmReader(command);
        TpmHeader header = TpmHeader.Parse(ref reader);

        return (TpmCcConstants)header.Code;
    }

    /// <summary>
    /// Sets attribute bits in one existing authorization slot's <c>sessionAttributes</c> octet, in place, leaving
    /// every other octet of the framed command untouched.
    /// </summary>
    /// <param name="command">The framed command to rewrite.</param>
    /// <param name="handleCount">The command's handle count, which fixes where its authorization area starts.</param>
    /// <param name="sessionIndex">The zero-based slot whose attributes octet is rewritten.</param>
    /// <param name="sessionAttributes">The attribute bits to set.</param>
    private static void SetSessionAttributeBit(byte[] command, int handleCount, int sessionIndex, TpmaSession sessionAttributes)
    {
        int offset = TpmHeader.HeaderSize + (handleCount * sizeof(uint)) + sizeof(uint);
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
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)) — a local mirror of the production session-index encoding, transcribed
    /// independently here since the production helper is private.
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>
    /// Hand-frames a <c>TPM2_Duplicate()</c> whose <c>symmetricAlg</c> the typed input cannot express and
    /// submits it, returning the response code.
    /// </summary>
    private async Task<TpmRcConstants> SubmitDuplicateFramedAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint objectHandle, uint newParentHandle, uint sessionHandle, ushort symmetricAlg)
    {
        //Session block: handle + empty TPM2B nonce + one attribute octet (continueSession) + empty TPM2B hmac.
        const int SessionBlockSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        int length = TpmHeader.HeaderSize + (2 * sizeof(uint)) + sizeof(uint) + SessionBlockSize + sizeof(ushort) + sizeof(ushort);
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_Duplicate);
        header.WriteTo(ref writer);
        writer.WriteUInt32(objectHandle);
        writer.WriteUInt32(newParentHandle);
        writer.WriteUInt32(SessionBlockSize);
        writer.WriteUInt32(sessionHandle);
        writer.WriteUInt16(0);
        writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
        writer.WriteUInt16(0);
        writer.WriteUInt16(0);
        writer.WriteUInt16(symmetricAlg);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed Duplicate must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>Flushes a transient or session handle when one is present, ignoring the result.</summary>
    private async Task FlushIfPresentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(handle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates the operational simulator with both signing backends, so elliptic-curve and RSA parents alike can be minted.</summary>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-duplication", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var startup = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + startup.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)startup.CommandCode);
        header.WriteTo(ref writer);
        startup.WriteHandles(ref writer);
        startup.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code);

        return simulator;
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyCommandCode, TpmResponseCodec.PolicyCommandCode);
        _ = registry.Register(TpmCcConstants.TPM_CC_Duplicate, TpmResponseCodec.Duplicate);
        _ = registry.Register(TpmCcConstants.TPM_CC_Import, TpmResponseCodec.Import);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }
}
