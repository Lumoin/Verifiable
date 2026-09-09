using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
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

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_ObjectChangeAuth()</c> over real HMAC sessions against the in-house behavioural
/// <see cref="TpmSimulator"/> through the production command path (<see cref="TpmCommandExecutor"/> and
/// <see cref="TpmSession"/>, which verifies every response HMAC and runs the parameter-encryption channel): the
/// ADMIN slot's command HMAC keyed on the object's authValue with and without the bind omission, the response
/// HMAC keyed on the OLD authValue, the <c>decrypt</c> channel over <c>newAuth</c> and the <c>encrypt</c> channel
/// over <c>outPrivate</c>, the dictionary-attack charge of a wrong HMAC, and the post-authorization width refusal
/// that rolls no nonce (TPM 2.0 Library Part 3, clause 12.8; Part 1, clauses 16.6, 16.8 and 18).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorObjectChangeAuthSessionTests
{
    /// <summary>The Name and session hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The digest width of <see cref="SessionAlg"/>, the cpHash and nonce width.</summary>
    private const int DigestSize = 32;

    /// <summary>The dictionary-attack-protected Ordinary Index a session is bound to for the charge case.</summary>
    private const uint DaProtectedBindIndexHandle = 0x0100_01A0;

    /// <summary>The bind Index's declared data size.</summary>
    private const ushort BindIndexDataSize = 16;

    /// <summary>Dictionary-attack-protected Ordinary Index attributes: <c>TPMA_NV_NO_DA</c> is CLEAR.</summary>
    private const TpmaNv DaProtectedIndexAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>The bind Index's authorization value.</summary>
    private static byte[] BindIndexAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>The secret the sealed data objects carry.</summary>
    private static byte[] SecretBytes { get; } = "Rewrap this secret over a real session."u8.ToArray();

    /// <summary>The authorization value the objects are created with.</summary>
    private static byte[] OriginalAuth { get; } = "original-session-object-auth"u8.ToArray();

    /// <summary>The replacement authorization value the command installs.</summary>
    private static byte[] NewAuth { get; } = "replacement-session-object-auth"u8.ToArray();

    /// <summary>The attribute word of an ordinary bound sealed object exempt from dictionary-attack protection.</summary>
    private const TpmaObject NoDaSealedAttributes = TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The ADMIN slot over an unbound, unsalted HMAC session whose key folds the object's authValue (TPM 2.0
    /// Library Part 1, clause 16.6.9, equation 19): the command succeeds, the executor verifies a response HMAC
    /// keyed on the OLD authValue — "the old authValue (of the TPM-resident object) is used when generating the
    /// response HMAC key if required" — and the returned private area reloads and authorizes with the new value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthOverAnUnboundHmacSessionKeysTheResponseOnTheOldAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthOverAnUnboundHmacSessionKeysTheResponseOnTheOldAuthValue), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, OriginalAuth, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            using(session)
            {
                TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject, parent, session, NewAuth).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_ObjectChangeAuth() over an HMAC session folding the object's authValue must succeed and its response HMAC must verify against the OLD value (Part 3, clause 12.8.1), but failed: '{result.ResponseCode}'.");
                using ObjectChangeAuthResponse response = result.Value;

                await AssertReloadAuthorizesWithAsync(tpm, registry, pool, parent.ObjectHandle.Value, response.OutPrivate, sealedObject.PublicArea, NewAuth).ConfigureAwait(false);
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The bind omission (TPM 2.0 Library Part 1, clause 16.6.10, equation 22): a session bound to the very
    /// object it authorizes already proved the authValue through its session key, so the command and response
    /// HMACs drop the term — the command succeeds and the executor, keying the same way, verifies the response.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthOverASessionBoundToTheObjectOmitsTheAuthValueFromTheHmacKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthOverASessionBoundToTheObjectOmitsTheAuthValueFromTheHmacKey), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, sealedObject.Handle, OriginalAuth, TpmtSymDef.Null, isBoundToAuthorizedEntity: true, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject, parent, session, NewAuth).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"A session bound to the object authorizes it with the authValue omitted from the HMAC key (Part 1, clause 16.6.10), but failed: '{result.ResponseCode}'.");
                using ObjectChangeAuthResponse response = result.Value;

                await AssertReloadAuthorizesWithAsync(tpm, registry, pool, parent.ObjectHandle.Value, response.OutPrivate, sealedObject.PublicArea, NewAuth).ConfigureAwait(false);
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>newAuth</c> is the command's first sized parameter, so a <c>decrypt</c> session protects it (TPM 2.0
    /// Library Part 1, clause 18.1): the executor encrypts it client-side under the session's XOR or AES-CFB
    /// keystream keyed on <c>sessionKey ‖ authValue</c>, and the object reloaded from the returned area
    /// authorizes with the PLAINTEXT value — the TPM recovered it before the rewrap.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8</see>.
    /// </summary>
    /// <param name="isAesCfb">Whether the session negotiates AES-128-CFB (else the XOR obfuscation).</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task ObjectChangeAuthOverADecryptSessionDeliversThePlaintextNewAuth(bool isAesCfb)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(ObjectChangeAuthOverADecryptSessionDeliversThePlaintextNewAuth)}-{isAesCfb}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, Symmetric(isAesCfb)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SetAuthValue(OriginalAuth, pool);
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject, parent, session, NewAuth).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_ObjectChangeAuth() over a {Symmetric(isAesCfb).Algorithm} decrypt session must succeed (Part 1, clause 18.1), but failed: '{result.ResponseCode}'.");
                using ObjectChangeAuthResponse response = result.Value;

                await AssertReloadAuthorizesWithAsync(tpm, registry, pool, parent.ObjectHandle.Value, response.OutPrivate, sealedObject.PublicArea, NewAuth).ConfigureAwait(false);
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The bind omission applies to the HMAC key only: a session bound to the object it authorizes still keys
    /// its parameter-encryption channel on <c>sessionKey ‖ authValue</c> — "the binding of the session is
    /// ignored" for the cipher key (TPM 2.0 Library Part 1, clause 18.1) — so a <c>decrypt</c> claim on such a
    /// session delivers the plaintext <c>newAuth</c> exactly as an unbound one does.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthOverASessionBoundToTheObjectWithDecryptKeepsTheAuthValueInTheCipherKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthOverASessionBoundToTheObjectWithDecryptKeepsTheAuthValueInTheCipherKey), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, sealedObject.Handle, OriginalAuth, TpmtSymDef.Xor(SessionAlg), isBoundToAuthorizedEntity: true, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SetAuthValue(OriginalAuth, pool);
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject, parent, session, NewAuth).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"A session bound to the object may still decrypt newAuth with the authValue folded into the cipher key (Part 1, clause 18.1), but failed: '{result.ResponseCode}'.");
                using ObjectChangeAuthResponse response = result.Value;

                await AssertReloadAuthorizesWithAsync(tpm, registry, pool, parent.ObjectHandle.Value, response.OutPrivate, sealedObject.PublicArea, NewAuth).ConfigureAwait(false);
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>outPrivate</c> is the response's first sized parameter, so an <c>encrypt</c> session protects it (TPM
    /// 2.0 Library Part 1, clause 18.1): the executor decrypts the returned area under the session's keystream
    /// keyed on the OLD authValue, and the decrypted area reloads and authorizes with the new value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8, Table 33</see>.
    /// </summary>
    /// <param name="isAesCfb">Whether the session negotiates AES-128-CFB (else the XOR obfuscation).</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task ObjectChangeAuthOverAnEncryptSessionReturnsAPrivateAreaTheExecutorDecrypts(bool isAesCfb)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(ObjectChangeAuthOverAnEncryptSessionReturnsAPrivateAreaTheExecutorDecrypts)}-{isAesCfb}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundSessionAsync(tpm, registry, pool, Symmetric(isAesCfb)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SetAuthValue(OriginalAuth, pool);
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject, parent, session, NewAuth).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_ObjectChangeAuth() over a {Symmetric(isAesCfb).Algorithm} encrypt session must succeed (Part 1, clause 18.1), but failed: '{result.ResponseCode}'.");
                using ObjectChangeAuthResponse response = result.Value;

                await AssertReloadAuthorizesWithAsync(tpm, registry, pool, parent.ObjectHandle.Value, response.OutPrivate, sealedObject.PublicArea, NewAuth).ConfigureAwait(false);
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A wrong command HMAC over a session bound to a dictionary-attack-protected NV Index is the
    /// session-index-encoded <c>TPM_RC_AUTH_FAIL</c> at index 0 and charges <c>failedTries</c> once — the
    /// failure counter moves "if either the entity being authorized is subject to DA protection or if the session
    /// is bound to an entity that has DA protection" (TPM 2.0 Library Part 1, clause 16.8.7), the authorized
    /// object itself being <c>noDA</c> here.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthWithAWrongHmacOverASessionBoundToADaProtectedIndexChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthWithAWrongHmacOverASessionBoundToADaProtectedIndexChargesFailedTries), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);
        await DefineDaProtectedIndexAsync(tpm, registry, pool).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, DaProtectedBindIndexHandle, BindIndexAuth, TpmtSymDef.Null, isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SetAuthValue(OriginalAuth, pool);
                TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

                byte[] command = await FrameOverSessionAsync(session, sealedObject, parent, parent.Name.AsReadOnlyMemory(), NewAuth, pool).ConfigureAwait(false);
                TamperLastHmacOctet(command);
                TpmRcConstants responseCode = await SubmitRawAsync(simulator, pool, command).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), responseCode,
                    "objectHandle's authorizing session, session 1 of Table 32, is refused with session-encoded TPM_RC_AUTH_FAIL when its command HMAC is wrong over a session bound to a DA-protected entity (Part 1, clause 16.8.7; Part 2, clause 6.6.2).");

                TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(before.Value.LockoutCounter + 1, after.Value.LockoutCounter, "The bind to a DA-protected Index charges failedTries once (Part 1, clause 16.8.7).");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A wrong command HMAC over an unbound session authorizing a <c>noDA</c> object is the session-index-encoded
    /// <c>TPM_RC_BAD_AUTH</c> at index 0 and charges nothing: neither the entity nor a bind lends the session
    /// dictionary-attack protection (TPM 2.0 Library Part 1, clause 16.8.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthWithAWrongHmacOverAnUnboundSessionIsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthWithAWrongHmacOverAnUnboundSessionIsBadAuthUncharged), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, OriginalAuth, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            using(session)
            {
                TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

                byte[] command = await FrameOverSessionAsync(session, sealedObject, parent, parent.Name.AsReadOnlyMemory(), NewAuth, pool).ConfigureAwait(false);
                TamperLastHmacOctet(command);
                TpmRcConstants responseCode = await SubmitRawAsync(simulator, pool, command).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), responseCode,
                    "objectHandle's authorizing session, session 1 of Table 32, is refused with session-encoded TPM_RC_BAD_AUTH when its command HMAC is wrong against a noDA object over an unbound session (Part 1, clause 16.8.1).");

                TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "Nothing lends the session dictionary-attack protection, so nothing is charged.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Check 5.1 of the authorization ladder over a real HMAC session (TPM 2.0 Library Part 3, clause 5.6): with
    /// <c>adminWithPolicy</c> SET the ADMIN role is a policy session's alone (TPM 2.0 Library Part 2, clause
    /// 8.3.3), so an HMAC session folding the object's authValue is refused with the bare <c>TPM_RC_AUTH_TYPE</c>
    /// exactly as a password is, and the dictionary-attack counter does not move.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthOverAnHmacSessionOnAnAdminWithPolicyObjectIsRefusedWithAuthType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthOverAnHmacSessionOnAnAdminWithPolicyObjectIsRefusedWithAuthType), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, NoDaSealedAttributes | TpmaObject.ADMIN_WITH_POLICY).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, OriginalAuth, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            using(session)
            {
                TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

                TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject, parent, session, NewAuth).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode,
                    "adminWithPolicy SET admits only a policy session at the ADMIN slot, so an HMAC session is refused exactly as a password is with the bare TPM_RC_AUTH_TYPE (Part 3, clause 5.6, check 5.1; Part 2, clause 8.3.3).");

                TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "Check 5.1 reads no credential, so it moves no dictionary-attack counter.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// cpHash folds both handle Names (TPM 2.0 Library Part 1, clause 15.7, equation 15): a command HMAC computed
    /// over a wrong <c>parentHandle</c> Name is an HMAC mismatch, while the same frame over the true Names
    /// succeeds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8, Table 32</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthCpHashFoldsBothHandleNames()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthCpHashFoldsBothHandleNames), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse otherParent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, OriginalAuth, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            using(session)
            {
                byte[] wrongNameCommand = await FrameOverSessionAsync(session, sealedObject, parent, otherParent.Name.AsReadOnlyMemory(), NewAuth, pool).ConfigureAwait(false);
                TpmRcConstants wrongNameCode = await SubmitRawAsync(simulator, pool, wrongNameCommand).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), wrongNameCode,
                    "objectHandle's authorizing session, session 1 of Table 32, is refused with session-encoded TPM_RC_BAD_AUTH when its HMAC is computed over a cpHash folding the wrong parent Name and cannot match the TPM's own (Part 1, clause 15.7, equation 15).");

                byte[] rightNameCommand = await FrameOverSessionAsync(session, sealedObject, parent, parent.Name.AsReadOnlyMemory(), NewAuth, pool).ConfigureAwait(false);
                TpmRcConstants rightNameCode = await SubmitRawAsync(simulator, pool, rightNameCommand).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, rightNameCode, "The same frame over both true Names succeeds.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The <c>newAuth</c> width rule is judged after the command HMAC has verified, and its refusal rolls no
    /// nonce: a 33-octet value under SHA-256 is the <c>TPM_RC_SIZE</c>, parameter-encoded to the same index, and the SAME session — with no
    /// restart and the executor's nonceTPM untouched — then succeeds on a 32-octet value, which it could not if
    /// the refusal had advanced the session.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthRefusesAnOverWideNewAuthAfterTheHmacWithoutRollingTheNonce()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthRefusesAnOverWideNewAuthAfterTheHmacWithoutRollingTheNonce), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, OriginalAuth, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            using(session)
            {
                byte[] overWide = new byte[DigestSize + 1];
                overWide.AsSpan().Fill(0x5C);
                TpmResult<ObjectChangeAuthResponse> refused = await ChangeAuthAsync(tpm, registry, pool, sealedObject, parent, session, overWide).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), refused.ResponseCode,
                    "A 33-octet newAuth under a SHA-256 Name algorithm is refused at newAuth, parameter 1 of Table 32, judged after the HMAC verified (Part 3, clause 12.8).");

                byte[] fitting = new byte[DigestSize];
                fitting.AsSpan().Fill(0x36);
                TpmResult<ObjectChangeAuthResponse> accepted = await ChangeAuthAsync(tpm, registry, pool, sealedObject, parent, session, fitting).ConfigureAwait(false);
                Assert.IsTrue(accepted.IsSuccess, $"The same session must succeed on a fitting newAuth without a restart — the SIZE refusal rolled no nonce — but failed: '{accepted.ResponseCode}'.");
                accepted.Value.Dispose();
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The generic <c>TPM2B_AUTH</c> structural bound (<c>sizeof(TPMU_HA)</c>, 64 octets, TPM 2.0 Library Part
    /// 2, clause 10.3.5, Table 93) is judged first, ahead of the narrower per-key nameAlg-digest-width rule
    /// <see cref="ObjectChangeAuthRefusesAnOverWideNewAuthAfterTheHmacWithoutRollingTheNonce"/> proves: a
    /// 65-octet <c>newAuth</c> — wider than any <c>TPM2B_AUTH</c> can ever be — is a failure of
    /// <c>newAuth</c>'s OWN content, never of the decrypt step, so it is parameter-encoded to <c>newAuth</c>
    /// itself, <c>TPM2_ObjectChangeAuth()</c>'s sole parameter (Table 32, index 0), judged after the command
    /// HMAC has verified, exactly as the narrower rule's own answer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8, Table 32; Part 2, clause 6.6.2, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthWithANewAuthWiderThanTpm2bAuthReturnsParameterEncodedSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthWithANewAuthWiderThanTpm2bAuthReturnsParameterEncodedSize), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, OriginalAuth, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            using(session)
            {
                byte[] overBound = new byte[Tpm2bAuth.MaxSize + 1];
                overBound.AsSpan().Fill(0x7E);

                byte[] command = await FrameOverSessionAsync(session, sealedObject, parent, parent.Name.AsReadOnlyMemory(), overBound, pool).ConfigureAwait(false);
                TpmRcConstants responseCode = await SubmitRawAsync(simulator, pool, command).ConfigureAwait(false);

                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, parameterIndex: 0), responseCode,
                    "newAuth is TPM2_ObjectChangeAuth()'s sole parameter (Table 32, index 0); a declared width past sizeof(TPMU_HA) is that parameter's own content failure, judged ahead of the narrower per-key rule.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Pool hygiene over a real session: a refused command (a wrong parent) and a successful one whose response is
    /// released leave the pool with exactly the carriers outstanding before them.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthOverASessionLeavesThePoolBalancedAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthOverASessionLeavesThePoolBalancedAcrossARefusalAndASuccess), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse otherParent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool, OriginalAuth, TpmtSymDef.Null).ConfigureAwait(false);
        try
        {
            using(session)
            {
                long baseline = trackingPool.OutstandingCount;

                TpmResult<ObjectChangeAuthResponse> refused = await ChangeAuthAsync(tpm, registry, pool, sealedObject, otherParent, session, NewAuth).ConfigureAwait(false);
                Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 1), refused.ResponseCode, "The wrong parent is refused with TPM_RC_TYPE at parentHandle, handle 2 of Table 32 (Part 3, clause 12.8.1).");
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refused session-authorized TPM2_ObjectChangeAuth() returns every carrier it rented.");

                TpmResult<ObjectChangeAuthResponse> accepted = await ChangeAuthAsync(tpm, registry, pool, sealedObject, parent, session, NewAuth).ConfigureAwait(false);
                Assert.IsTrue(accepted.IsSuccess, $"TPM2_ObjectChangeAuth() must succeed, but failed: '{accepted.ResponseCode}'.");
                accepted.Value.Dispose();
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A successful session-authorized TPM2_ObjectChangeAuth() returns every carrier once its response is released.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A loaded sealed object under test: its transient handle, an owned clone of its Name, and an owned clone of
    /// its public area (the unchanged area a rewrapped private area reloads with).
    /// </summary>
    private sealed class SealedObject: IDisposable
    {
        /// <summary>Whether the owned clones have been released.</summary>
        private bool isDisposed;

        /// <summary>Gets the loaded transient handle.</summary>
        public uint Handle { get; }

        /// <summary>Gets an owned clone of the loaded object's Name.</summary>
        public Tpm2bName Name { get; }

        /// <summary>Gets an owned clone of the object's public area.</summary>
        public Tpm2bPublic PublicArea { get; }

        /// <summary>Initializes the record, adopting <paramref name="name"/> and <paramref name="publicArea"/>.</summary>
        /// <param name="handle">The loaded transient handle.</param>
        /// <param name="name">An owned clone of the Name.</param>
        /// <param name="publicArea">An owned clone of the public area.</param>
        public SealedObject(uint handle, Tpm2bName name, Tpm2bPublic publicArea)
        {
            Handle = handle;
            Name = name;
            PublicArea = publicArea;
        }

        /// <summary>Releases the Name and public-area clones.</summary>
        public void Dispose()
        {
            if(!isDisposed)
            {
                Name.Dispose();
                PublicArea.Dispose();
                isDisposed = true;
            }
        }
    }

    /// <summary>Creates an operational simulator with the elliptic-curve backend.</summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool) =>
        HmacKeyHarness.CreateOperationalAsync($"tpm-in-house-object-change-auth-session-{name}", pool, TestContext.CancellationToken);

    /// <summary>Builds the codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_ObjectChangeAuth, TpmResponseCodec.ObjectChangeAuth)
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);

    /// <summary>The symmetric definition a parameter-encryption session negotiates.</summary>
    /// <param name="isAesCfb">Whether to negotiate AES-128-CFB (else the XOR obfuscation).</param>
    /// <returns>The symmetric definition.</returns>
    private static TpmtSymDef Symmetric(bool isAesCfb) =>
        isAesCfb ? TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB) : TpmtSymDef.Xor(SessionAlg);

    /// <summary>
    /// Seals <see cref="SecretBytes"/> into a KEYEDHASH object authorized by <see cref="OriginalAuth"/> with the
    /// given attribute word under <paramref name="parentHandle"/>, loads it, and returns the loaded object.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent.</param>
    /// <param name="attributes">The object's <c>TPMA_OBJECT</c> word.</param>
    /// <returns>The loaded object; the caller disposes it.</returns>
    private async Task<SealedObject> CreateAndLoadSealedObjectAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, TpmaObject attributes = NoDaSealedAttributes)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, OriginalAuth, pool);
        using Tpm2bPublic template = Tpm2bPublic.CreateKeyedHashTemplate(SessionAlg, attributes, TpmsKeyedHashParms.SealedData, default, pool);

        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateAsync(tpm, registry, pool, parentHandle, inSensitive, template, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (sealed object) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        Tpm2bPublic publicArea = HmacKeyHarness.ClonePublic(created.OutPublic, pool);
        try
        {
            TpmResult<LoadResponse> loadResult = await HmacKeyHarness.LoadAsync(
                tpm, registry, pool, parentHandle, created.OutPrivate, created.OutPublic, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");
            using LoadResponse loaded = loadResult.Value;

            return new SealedObject(loaded.ObjectHandle.Value, Tpm2bName.Create(loaded.Name.Span, pool), publicArea);
        }
        catch
        {
            publicArea.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Issues <c>TPM2_ObjectChangeAuth()</c> through the production executor over <paramref name="session"/>,
    /// the two handle Names supplied for cpHash, and returns the raw result.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sealedObject">The object whose authorization value is replaced.</param>
    /// <param name="parent">The parent presented.</param>
    /// <param name="session">The ADMIN slot's session; the caller owns and disposes it.</param>
    /// <param name="newAuth">The replacement authorization value.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<ObjectChangeAuthResponse>> ChangeAuthAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, SealedObject sealedObject, CreatePrimaryResponse parent, TpmSessionBase session, ReadOnlyMemory<byte> newAuth)
    {
        using Tpm2bAuth newAuthCarrier = Tpm2bAuth.Create(newAuth.Span, pool);
        var input = new ObjectChangeAuthInput(TpmiDhObject.FromValue(sealedObject.Handle), parent.ObjectHandle, newAuthCarrier);

        return await TpmCommandExecutor.ExecuteAsync<ObjectChangeAuthResponse>(
            tpm, input, [session], [sealedObject.Name.AsReadOnlyMemory(), parent.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reloads a returned private area under its parent with the unchanged public area and asserts the reloaded
    /// object unseals with <paramref name="password"/>.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent.</param>
    /// <param name="outPrivate">The private area to reload.</param>
    /// <param name="publicArea">The object's unchanged public area.</param>
    /// <param name="password">The authorization value the reloaded object must accept.</param>
    private async Task AssertReloadAuthorizesWithAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, Tpm2bPrivate outPrivate, Tpm2bPublic publicArea, ReadOnlyMemory<byte> password)
    {
        TpmResult<LoadResponse> reloadResult = await HmacKeyHarness.LoadAsync(tpm, registry, pool, parentHandle, outPrivate, publicArea, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(reloadResult.IsSuccess, $"The returned private area must load under the same parent (Part 3, clause 12.8.1), but failed: '{reloadResult.ResponseCode}'.");
        using LoadResponse reloaded = reloadResult.Value;

        using TpmPasswordSession itemAuth = HmacKeyHarness.PasswordSession(password, pool);
        TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
            tpm, UnsealInput.ForItem(reloaded.ObjectHandle), [itemAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(unsealResult.IsSuccess, $"The reloaded object must authorize with the new value (Part 3, clause 12.8.1), but failed: '{unsealResult.ResponseCode}'.");
        using UnsealResponse unsealed = unsealResult.Value;
        Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes), "The rewrapped sensitive data is the original secret, byte for byte.");
    }

    /// <summary>
    /// Starts an unbound, unsalted HMAC session negotiating <paramref name="symmetric"/> and composes the
    /// host-side session carrying <paramref name="authValue"/> as its authValue term (TPM 2.0 Library Part 1,
    /// clause 16.6.9, equation 19: an empty session key).
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authValue">The authValue the session proves.</param>
    /// <param name="symmetric">The symmetric definition to negotiate.</param>
    /// <returns>The session handle (to flush) and the composed session (to dispose).</returns>
    private async Task<(uint Handle, TpmSession Session)> StartUnboundSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, ReadOnlyMemory<byte> authValue, TpmtSymDef symmetric)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound) failed: '{startResult.ResponseCode}'.");

        //The response owns nothing but nonceTPM, which the session takes over.
        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);
        session.SetAuthValue(authValue.Span, pool);
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (started.SessionHandle.Value, session);
    }

    /// <summary>
    /// Starts an HMAC session bound to <c>TPM_RH_OWNER</c> — a permanent entity whose factory-empty authValue
    /// needs no installation and whose bind lends the session no dictionary-attack protection — negotiating
    /// <paramref name="symmetric"/> for parameter encryption.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="symmetric">The symmetric definition to negotiate.</param>
    /// <returns>The session handle and the host session.</returns>
    private Task<(uint Handle, TpmSession Session)> StartOwnerBoundSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtSymDef symmetric) =>
        HmacKeyHarness.StartBoundHmacSessionAsync(tpm, registry, pool, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, symmetric, isBoundToAuthorizedEntity: false, TestContext.CancellationToken);

    /// <summary>
    /// Defines the dictionary-attack-protected Ordinary Index at <see cref="DaProtectedBindIndexHandle"/> with
    /// <see cref="BindIndexAuth"/> as its authValue, authorized by the empty owner authValue over a password session.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task DefineDaProtectedIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using var auth = Tpm2bAuth.Create(BindIndexAuth, pool);
        using var publicInfo = new TpmsNvPublic(DaProtectedBindIndexHandle, SessionAlg, DaProtectedIndexAttributes, Tpm2bDigest.Empty, BindIndexDataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace(0x{DaProtectedBindIndexHandle:X8}) failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_ObjectChangeAuth()</c> over <paramref name="session"/> with a genuine command HMAC
    /// over cpHash — the command code, the object's Name, <paramref name="parentNameForCpHash"/> and the
    /// <c>TPM2B_AUTH</c> parameter area (TPM 2.0 Library Part 1, clause 15.7, equation 15) — so the Name a caller
    /// folds can be chosen independently of the handle it presents.
    /// </summary>
    /// <param name="session">The authorizing session, whose caller nonce this rolls.</param>
    /// <param name="sealedObject">The object presented at <c>objectHandle</c>.</param>
    /// <param name="parent">The parent presented at <c>parentHandle</c>.</param>
    /// <param name="parentNameForCpHash">The parent Name folded into cpHash.</param>
    /// <param name="newAuth">The replacement authorization value.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The exact octets to submit.</returns>
    private async Task<byte[]> FrameOverSessionAsync(
        TpmSession session, SealedObject sealedObject, CreatePrimaryResponse parent, ReadOnlyMemory<byte> parentNameForCpHash, ReadOnlyMemory<byte> newAuth, BaseMemoryPool pool)
    {
        int parametersLength = sizeof(ushort) + newAuth.Length;
        using IMemoryOwner<byte> parametersOwner = pool.Rent(parametersLength);
        Memory<byte> parameters = parametersOwner.Memory[..parametersLength];
        BinaryPrimitives.WriteUInt16BigEndian(parameters.Span[..sizeof(ushort)], (ushort)newAuth.Length);
        newAuth.Span.CopyTo(parameters.Span[sizeof(ushort)..]);

        session.RollNonceCaller(pool);

        int cpHashInputLength = sizeof(uint) + sealedObject.Name.Size + parentNameForCpHash.Length + parametersLength;
        using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
        Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
        {
            var cpHashWriter = new TpmWriter(cpHashInput.Span);
            cpHashWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_ObjectChangeAuth);
            cpHashWriter.WriteBytes(sealedObject.Name.Span);
            cpHashWriter.WriteBytes(parentNameForCpHash.Span);
            cpHashWriter.WriteBytes(parameters.Span);
        }

        using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            cpHashInput, outputByteLength: DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        int authAreaSize = sizeof(uint) + session.GetAuthCommandSize();
        int totalSize = TpmHeader.HeaderSize + (2 * sizeof(uint)) + authAreaSize + parametersLength;
        using IMemoryOwner<byte> commandOwner = pool.Rent(totalSize);
        Memory<byte> command = commandOwner.Memory[..totalSize];
        var writer = new TpmWriter(command.Span);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
        writer.WriteUInt32((uint)totalSize);
        writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_ObjectChangeAuth);
        writer.WriteUInt32(sealedObject.Handle);
        writer.WriteUInt32(parent.ObjectHandle.Value);
        writer.WriteUInt32((uint)session.GetAuthCommandSize());
        session.WriteAuthCommand(ref writer, hmac);
        writer.WriteBytes(parameters.Span);

        return command.Span.ToArray();
    }

    /// <summary>
    /// Flips every bit of the LAST octet of the authorization slot's <c>hmac</c> field, navigating to it from the
    /// front of the frame past the two handles so the offset follows the actual nonce and hmac widths.
    /// </summary>
    /// <param name="command">The framed command, mutated in place.</param>
    private static void TamperLastHmacOctet(byte[] command)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        _ = reader.ReadUInt32();
        _ = reader.ReadUInt32();
        _ = reader.ReadUInt32();
        _ = reader.ReadUInt32();

        ushort nonceSize = reader.ReadUInt16();
        reader.Skip(nonceSize);
        _ = reader.ReadByte();

        ushort hmacSize = reader.ReadUInt16();
        Assert.IsGreaterThan(0, hmacSize, "The arrangement must carry a non-empty hmac for the tamper to change one.");

        int lastHmacOctet = reader.Consumed + hmacSize - 1;
        command[lastHmacOctet] ^= 0xFF;
    }

    /// <summary>Submits raw, hand-framed octets straight to the simulator and returns the response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="command">The exact octets to submit.</param>
    /// <returns>The response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> SubmitRawAsync(TpmSimulator simulator, BaseMemoryPool pool, byte[] command)
    {
        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The transport itself must succeed even when the TPM refuses the command.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>The tag describing a raw SHA-256 digest for the cpHash computation.</summary>
    /// <returns>The tag.</returns>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);
}
