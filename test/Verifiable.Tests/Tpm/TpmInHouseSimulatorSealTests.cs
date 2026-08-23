using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
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

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives TPM sealing ("tie a secret to this computer") against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production command
/// path the production code uses (<see cref="TpmCommandExecutor"/> with the real <see cref="CreateInput"/>,
/// <see cref="LoadInput"/>, <see cref="UnsealInput"/>, and response codecs): <c>TPM2_CreatePrimary()</c> mints an
/// ECC storage parent, <c>TPM2_Create()</c> seals a secret into a KEYEDHASH object, <c>TPM2_Load()</c> brings the
/// wrapped object back into a transient slot, and <c>TPM2_Unseal()</c> recovers the data.
/// </summary>
/// <remarks>
/// <para>
/// The wrapped blob is persisted-and-reloaded through wire bytes only (the private blob is copied and the public
/// area reserialized), mirroring the disk round-trip a real deployment performs — the unseal shares no in-memory
/// object with the seal step beyond those bytes, so a divergence between what the simulator framed and what a
/// genuine TPM would return fails the byte-exact equality assertion.
/// </para>
/// <para>
/// The simulator models the sealed-data path under password authorization; it does not model the bound HMAC
/// session with AES-CFB parameter encryption a full unseal runs over, so the recovered secret is returned in the
/// clear on the (in-process) wire rather than over an encrypted channel. The parameter-encryption channel is a
/// separate concern exercised elsewhere.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorSealTests
{
    /// <summary>The session/name hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The fixed secret sealed and recovered by the test.</summary>
    private static byte[] SecretBytes { get; } = "Tie this secret to the in-house TPM."u8.ToArray();

    /// <summary>The lowered <c>maxTries</c> the F3 lockout regression uses to reach Lockout mode quickly.</summary>
    private const uint LockoutTestMaxTries = 2;

    /// <summary>The real password the parent-authValue verification proofs create the storage parent with.</summary>
    private const string ParentPassword = "create-parent-auth-proof";

    /// <summary>The parent's authValue in wire form — the UTF-8 octets of <see cref="ParentPassword"/>, matching the password-to-authValue convention <see cref="Tpm2bAuth.CreateFromPassword"/> applies on the creation side (the password carries no trailing zeros, so no trimming is in play).</summary>
    private static byte[] ParentPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(ParentPassword);

    /// <summary>A wrong guess at the parent's password, distinct from <see cref="ParentPasswordBytes"/>.</summary>
    private static byte[] WrongParentPasswordBytes { get; } = [0x9A, 0x9B, 0x9C, 0x9D];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task SealedSecretUnsealsAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //1. Create the storage parent under the owner hierarchy.
        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        //2. Seal the secret into a KEYEDHASH object under the parent. The parent has empty auth, so the new object
        //is authorized with an empty password session. noDa: the seal carries an empty authValue (nothing to
        //brute-force), so dictionary-attack protection is moot.
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: true);
        using CreateInput createInput = new(
            parentHandle,
            inSensitive,
            sealTemplate,
            Tpm2bData.Empty,
            TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (seal) failed: '{createResult.ResponseCode}'.");

        using CreateResponse sealedObject = createResult.Value;
        Assert.IsFalse(sealedObject.OutPrivate.IsEmpty, "Sealing must return a wrapped private blob.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_KEYEDHASH, sealedObject.OutPublic.PublicArea.Type, "The sealed object must be a KEYEDHASH object.");

        //3. Persist-then-reload through wire bytes only: copy the private blob and reserialize the public area, the
        //disk round-trip a real deployment performs, then TPM2_Load the wrapped object.
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");

        using LoadResponse loaded = loadResult.Value;
        Assert.IsFalse(loaded.Name.Span.IsEmpty, "Load must return the loaded object's Name.");

        //4. Unseal over a password session and confirm the recovered secret matches byte for byte. The sealed
        //object's authValue is empty, so the empty password session authorizes the unseal.
        using TpmPasswordSession itemAuth = TpmPasswordSession.CreateEmpty(pool);
        UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);

        TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
            tpm, unsealInput, [itemAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(unsealResult.IsSuccess, $"Unseal failed: '{unsealResult.ResponseCode}'.");

        using UnsealResponse unsealed = unsealResult.Value;
        Assert.IsTrue(
            unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes),
            "The unsealed data must equal the sealed secret, byte for byte, recovered from the wire blob alone.");
    }

    /// <summary>
    /// A KEYEDHASH object sealed with <c>userWithAuth</c> CLEAR, a non-empty authPolicy, and an EMPTY retained
    /// userAuth is never recoverable via a plain, empty-password <c>TPM_RS_PW</c> Unseal. <c>userWithAuth</c>
    /// CLEAR means only a policy session may ever authorize the USER role (TPM 2.0 Library Part 2, clause
    /// 8.3.3; Part 3, clause 5.6, check 7.1), and the session-shape gate refuses before the supplied password
    /// is ever compared against the (also empty) retained userAuth — were the compare reached, the empty
    /// password would match and the secret would return in the clear, choosing away the policy gate entirely.
    /// The HMAC-authorized path (<c>OnUnsealOverSessions</c>) enforces the identical check at the same
    /// pre-credential position; this pairs the plain-password path with it.
    /// </summary>
    [TestMethod]
    public async Task PlainPasswordUnsealRejectsUserWithAuthClearSealedObject()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        //A non-empty authPolicy (an arbitrary 32-octet digest stands in for a real TPM2_PolicyPCR() one; the
        //fix under test rejects on userWithAuth alone, never inspecting the policy's content) with userWithAuth
        //CLEAR. The retained userAuth is left empty (no userAuth argument to ForSealedData), matching the
        //exploit shape exactly: an empty supplied password against an empty retained userAuth.
        byte[] authPolicy = new byte[32];
        Array.Fill(authPolicy, (byte)0x5A);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy, noDa: true, userWithAuth: false);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (seal, userWithAuth CLEAR) failed: '{createResult.ResponseCode}'.");

        using CreateResponse sealedObject = createResult.Value;

        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");

        using LoadResponse loaded = loadResult.Value;

        //The exploit: an EMPTY-password plain TPM_RS_PW Unseal against the userWithAuth-CLEAR object above.
        using TpmPasswordSession itemAuth = TpmPasswordSession.CreateEmpty(pool);
        UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);

        TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
            tpm, unsealInput, [itemAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        if(unsealResult.IsSuccess)
        {
            unsealResult.Value.Dispose();
        }

        Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, unsealResult.ResponseCode,
            $"A userWithAuth-CLEAR, policy-gated sealed object must reject a plain-password Unseal with TPM_RC_POLICY_FAIL " +
            $"(Part 3, clause 5.6, check 7.1), never authorize it (got '{unsealResult.ResponseCode}').");
    }

    [TestMethod]
    public async Task UnsealWithUnknownItemHandleReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //No object was loaded, so the transient handle does not resolve (TPM 2.0 Part 3, clause 12.7).
        using TpmPasswordSession itemAuth = TpmPasswordSession.CreateEmpty(pool);
        UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase));

        TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
            tpm, unsealInput, [itemAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, unsealResult.ResponseCode);
    }

    [TestMethod]
    public async Task SealUnderNonStorageParentReturnsType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //A signing key is not a restricted storage key, so it cannot parent a TPM2_Create() child: the seal is
        //rejected with TPM_RC_TYPE (TPM 2.0 Part 3, clause 12.1).
        using CreatePrimaryInput signingInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> signingResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, signingInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signingResult.IsSuccess, $"CreatePrimary (ECC signing key) failed: '{signingResult.ResponseCode}'.");

        using CreatePrimaryResponse signingKey = signingResult.Value;

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: true);
        using CreateInput createInput = new(
            signingKey.ObjectHandle.Value,
            inSensitive,
            sealTemplate,
            Tpm2bData.Empty,
            TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_TYPE, createResult.ResponseCode);
    }

    /// <summary>
    /// F3 regression, plain single-password form (adversarial review, MINOR wrong RC — reviewer's "ALSO CHECK"
    /// note on the same clause): a locked-out TPM must reject the PLAIN, single-<c>TPM_RS_PW</c>
    /// <c>TPM2_Create()</c> (<c>OnCreateSealedObject</c>) with <c>TPM_RC_LOCKOUT</c> when the parent is
    /// DA-protected, exactly like every other DA-protected surface. Before the fix this function ran NO
    /// DA/Lockout check at all (TPM 2.0 Library Part 3, clause 5.6, check 3), so a locked-out TPM performed the
    /// Create unconditionally. This pairs with
    /// <see cref="TpmInHouseSimulatorParameterDecryptionTests.LockedOutTpmRejectsCreateOverPasswordAuthorizedDaProtectedParent"/>,
    /// which covers the same gate in the two-session (<c>OnCreateSealedObjectOverSessions</c>) form.
    /// </summary>
    [TestMethod]
    public async Task LockedOutTpmRejectsPlainPasswordCreateOverDaProtectedParent()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //A DA-protected storage parent (noDa: false) — the gate under test is keyed on this bit.
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: false);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary (DA-protected storage parent) failed: '{parentResult.ResponseCode}'.");

        using CreatePrimaryResponse parent = parentResult.Value;
        uint parentHandle = parent.ObjectHandle.Value;
        uint bruteForceItemHandle = 0;

        try
        {
            //1. Lower maxTries so a handful of failures reaches Lockout mode quickly.
            TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
                ReadOnlyMemory<byte>.Empty, LockoutTestMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
                TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

            //2. Seal+load a THROWAWAY DA-protected object under the same parent and fail its Unseal password
            //LockoutTestMaxTries times, engaging the ONE shared lockout counter (Part 1, clause 17.8).
            byte[] correctAuth = [0x71, 0x72, 0x73, 0x74];
            using Tpm2bSensitiveCreate bruteForceSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, correctAuth, pool);
            using Tpm2bPublic bruteForceTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: false);
            using CreateInput bruteForceCreateInput = new(parentHandle, bruteForceSensitive, bruteForceTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession bruteForceParentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<CreateResponse> bruteForceCreateResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, bruteForceCreateInput, [bruteForceParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(bruteForceCreateResult.IsSuccess, $"Create (throwaway DA-protected object) failed: '{bruteForceCreateResult.ResponseCode}'.");

            using CreateResponse bruteForceObject = bruteForceCreateResult.Value;
            using Tpm2bPrivate bruteForcePrivate = Tpm2bPrivate.Create(bruteForceObject.OutPrivate.Span, pool);
            using Tpm2bPublic bruteForcePublic = ClonePublic(bruteForceObject.OutPublic, pool);
            using LoadInput bruteForceLoadInput = new(parentHandle, bruteForcePrivate, bruteForcePublic);
            using TpmPasswordSession bruteForceLoadAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<LoadResponse> bruteForceLoadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
                tpm, bruteForceLoadInput, [bruteForceLoadAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(bruteForceLoadResult.IsSuccess, $"Load (throwaway DA-protected object) failed: '{bruteForceLoadResult.ResponseCode}'.");

            using LoadResponse bruteForceLoaded = bruteForceLoadResult.Value;
            bruteForceItemHandle = bruteForceLoaded.ObjectHandle.Value;

            byte[] wrongPassword = [0xFF, 0xEE, 0xDD, 0xCC];
            for(uint attempt = 1; attempt <= LockoutTestMaxTries; attempt++)
            {
                using TpmPasswordSession wrongAuth = TpmPasswordSession.Create(wrongPassword, pool);
                UnsealInput bruteForceUnsealInput = UnsealInput.ForItem(bruteForceLoaded.ObjectHandle);
                TpmResult<UnsealResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                    tpm, bruteForceUnsealInput, [wrongAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(wrongResult.IsSuccess, $"Attempt {attempt} of {LockoutTestMaxTries} with a wrong password must fail.");
            }

            TpmResult<TpmDictionaryAttackParameters> lockoutState = await tpm.GetDictionaryAttackParametersAsync(
                pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(lockoutState.IsSuccess, $"GetDictionaryAttackParameters failed: '{lockoutState.ResponseCode}'.");
            Assert.IsTrue(lockoutState.Value.IsLockedOut, "The TPM must be in Lockout mode before the Create exploit runs.");

            //3. THE EXPLOIT: TPM2_Create() with a SINGLE plain TPM_RS_PW session against the (now globally
            //locked-out) DA-protected parent — the single-session form OnCreateSealedObject handles directly.
            using Tpm2bSensitiveCreate exploitSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
            using Tpm2bPublic exploitTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: false);
            using CreateInput exploitCreateInput = new(parentHandle, exploitSensitive, exploitTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession exploitParentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<CreateResponse> exploitResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, exploitCreateInput, [exploitParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            if(exploitResult.IsSuccess)
            {
                exploitResult.Value.Dispose();
            }

            Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, exploitResult.ResponseCode,
                "A locked-out TPM must reject the plain single-password TPM2_Create() over a DA-protected parent " +
                $"with TPM_RC_LOCKOUT (got '{exploitResult.ResponseCode}').");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, bruteForceItemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// TPM2_Create()'s parent slot (Auth Index 1, Auth Role USER; TPM 2.0 Library Part 3, clause 12.1) is
    /// verified against the parent's retained authValue over a plain <c>TPM_RS_PW</c> session: a DA-protected
    /// storage parent created with a real password admits a seal authorized by the CORRECT password and moves
    /// no dictionary-attack counter, while a WRONG password is refused with the session-index-encoded
    /// <c>TPM_RC_AUTH_FAIL</c> (Part 2, clause 6.6.2) and charges <c>failedTries</c> exactly once (Part 1,
    /// clause 17.8.7).
    /// </summary>
    [TestMethod]
    public async Task PlainCreateVerifiesTheParentsAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreatePasswordProtectedStorageParentAsync(
            tpm, registry, pool, ParentPassword, noDa: false).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using Tpm2bSensitiveCreate correctSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
        using Tpm2bPublic correctTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: false);
        using CreateInput correctCreateInput = new(parentHandle, correctSensitive, correctTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession correctParentAuth = TpmPasswordSession.Create(ParentPasswordBytes, pool);

        TpmResult<CreateResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, correctCreateInput, [correctParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(correctResult.IsSuccess, $"Create (seal) with the parent's correct password must succeed, but failed: '{correctResult.ResponseCode}'.");
        correctResult.Value.Dispose();

        TpmResult<TpmDictionaryAttackParameters> afterCorrect = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, afterCorrect.Value.LockoutCounter, "A correctly-authorized Create must move no dictionary-attack counter.");

        using Tpm2bSensitiveCreate wrongSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
        using Tpm2bPublic wrongTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: false);
        using CreateInput wrongCreateInput = new(parentHandle, wrongSensitive, wrongTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession wrongParentAuth = TpmPasswordSession.Create(WrongParentPasswordBytes, pool);

        TpmResult<CreateResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, wrongCreateInput, [wrongParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(wrongResult.IsTpmError, "A wrong parent password must be refused.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), wrongResult.ResponseCode,
            "A wrong parent password over a plain TPM_RS_PW session names the parent slot (index 0), session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            afterCorrect.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
            "A wrong parent password against a DA-protected parent must charge failedTries exactly once (TPM 2.0 Library Part 1, clause 17.8.7).");
    }

    /// <summary>
    /// The non-DA-protected counterpart of <see cref="PlainCreateVerifiesTheParentsAuthValue"/>: a storage
    /// parent created with a real password but <c>TPMA_OBJECT.NO_DA</c> SET rejects a wrong plain-password seal
    /// with a plain session-index-encoded <c>TPM_RC_BAD_AUTH</c> instead of <c>TPM_RC_AUTH_FAIL</c>, and moves
    /// no dictionary-attack counter — only a DA-protected authValue's failure is ever charged to
    /// <c>failedTries</c> (TPM 2.0 Library Part 1, clause 17.8.1).
    /// </summary>
    [TestMethod]
    public async Task PlainCreateWithWrongAuthOverNoDaParentReturnsBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreatePasswordProtectedStorageParentAsync(
            tpm, registry, pool, ParentPassword, noDa: true).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: true);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession wrongParentAuth = TpmPasswordSession.Create(WrongParentPasswordBytes, pool);

        TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [wrongParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTpmError, "A wrong parent password must be refused.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
            "A wrong password against a NON-DA-protected (NO_DA SET) parent must be a plain session-encoded TPM_RC_BAD_AUTH, never TPM_RC_AUTH_FAIL.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "A NO_DA parent's wrong-password rejection must never move the dictionary-attack counter.");
    }

    /// <summary>
    /// TPM2_Create()'s parent slot is verified against the parent's retained authValue over an UNBOUND,
    /// unsalted HMAC session that explicitly folds it as the command HMAC's entity term (TPM 2.0 Library Part
    /// 1, clause 17.6.9, equation 19; Part 3, clause 12.1): a session folding the CORRECT password succeeds and
    /// moves no dictionary-attack counter, while one folding a WRONG password fails command-HMAC verification
    /// with the session-index-encoded <c>TPM_RC_AUTH_FAIL</c> and charges <c>failedTries</c> exactly once.
    /// </summary>
    [TestMethod]
    public async Task CreateOverUnboundHmacSessionVerifiesTheParentsAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreatePasswordProtectedStorageParentAsync(
            tpm, registry, pool, ParentPassword, noDa: false).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        ReadOnlyMemory<byte> parentName = parent.Name.Span.ToArray();

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<CreateResponse> correct = await CreateSealedObjectOverUnboundHmacSessionAsync(
            tpm, registry, pool, parentHandle, parentName, ParentPasswordBytes).ConfigureAwait(false);
        Assert.IsTrue(correct.IsSuccess, $"Create over an HMAC session folding the parent's CORRECT authValue must succeed, but failed: '{correct.ResponseCode}'.");
        correct.Value.Dispose();

        TpmResult<TpmDictionaryAttackParameters> afterCorrect = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, afterCorrect.Value.LockoutCounter, "A correctly-authorized Create must move no dictionary-attack counter.");

        TpmResult<CreateResponse> wrong = await CreateSealedObjectOverUnboundHmacSessionAsync(
            tpm, registry, pool, parentHandle, parentName, WrongParentPasswordBytes).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_FAIL, wrong.BaseError,
            "A session folding the WRONG parent authValue must fail the command HMAC with TPM_RC_AUTH_FAIL (the parent is DA-protected).");
        Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), wrong.ResponseCode);

        TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            afterCorrect.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
            "A wrong parent authValue on a DA-protected parent must charge failedTries exactly once.");
    }

    /// <summary>
    /// A session BOUND TO THE PARENT ITSELF attests with no authValue folded into the command HMAC: binding
    /// already incorporated the parent's authValue into the session key (TPM 2.0 Library Part 1, clause
    /// 17.6.10, equation 20), so the command HMAC omits it (equations 21/22) — the bind-omission
    /// <c>OnCreateSealedObjectOverSessions</c> applies to the parent slot exactly as
    /// <c>OnNvCertifyOverSession</c> applies it to a signing key's own sign slot. Proves TPM2_Create()'s
    /// parent-slot bind-omission path.
    /// </summary>
    [TestMethod]
    public async Task CreateOverSessionBoundToTheParentItselfSeals()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreatePasswordProtectedStorageParentAsync(
            tpm, registry, pool, ParentPassword, noDa: false).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(parentHandle, SessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to the parent) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession boundSession = await TpmSession.CreateBoundAsync(
                new TpmHandle(sessionHandle), ParentPasswordBytes, startInput.NonceCaller, started.NonceTPM,
                SessionAlg, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            boundSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;

            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: false);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);

            ReadOnlyMemory<byte>[] handleNames = [parent.Name.Span.ToArray()];

            TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [boundSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                result.IsSuccess,
                $"Create over a session bound to the parent itself must succeed with the authValue folded into the bind, but failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// TPM2_Create()'s parent slot is verified against the parent's retained authValue when the session area
    /// pairs a plain <c>TPM_RS_PW</c> parent-auth slot (slot 0) with a SEPARATE decrypt-attributed HMAC
    /// companion (slot 1) that protects <c>inSensitive</c> (TPM 2.0 Library Part 1, clauses 19 and 21; Part 3,
    /// clause 12.1) — the inline-compare discipline <c>OnCreateSealedObjectOverSessions</c> applies identically
    /// to the single-session plain form: a session pair carrying the CORRECT password succeeds and moves no
    /// dictionary-attack counter, while one carrying a WRONG password is refused with the session-index-encoded
    /// <c>TPM_RC_AUTH_FAIL</c> and charges <c>failedTries</c> exactly once, before the companion session's own
    /// HMAC is ever evaluated.
    /// </summary>
    [TestMethod]
    public async Task CreateOverPasswordSlotWithDecryptSessionVerifiesTheParentsAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreatePasswordProtectedStorageParentAsync(
            tpm, registry, pool, ParentPassword, noDa: false).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        ReadOnlyMemory<byte> parentName = parent.Name.Span.ToArray();

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<CreateResponse> correct = await CreateSealedObjectOverPasswordAndDecryptSessionAsync(
            tpm, registry, pool, parentHandle, parentName, ParentPasswordBytes).ConfigureAwait(false);
        Assert.IsTrue(correct.IsSuccess, $"Create over [TPM_RS_PW, decrypt HMAC] with the parent's correct password must succeed, but failed: '{correct.ResponseCode}'.");
        correct.Value.Dispose();

        TpmResult<TpmDictionaryAttackParameters> afterCorrect = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, afterCorrect.Value.LockoutCounter, "A correctly-authorized Create must move no dictionary-attack counter.");

        TpmResult<CreateResponse> wrong = await CreateSealedObjectOverPasswordAndDecryptSessionAsync(
            tpm, registry, pool, parentHandle, parentName, WrongParentPasswordBytes).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), wrong.ResponseCode,
            "A wrong parent password at the plain TPM_RS_PW slot must be refused with the session-index-encoded TPM_RC_AUTH_FAIL, whatever the companion decrypt session's own standing.");

        TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            afterCorrect.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
            "A wrong parent password against a DA-protected parent must charge failedTries exactly once.");
    }

    /// <summary>
    /// TPM2_Load()'s parent slot (Auth Index 1, Auth Role USER; TPM 2.0 Library Part 3, clause 12.2) is
    /// verified against the parent's retained authValue over a plain <c>TPM_RS_PW</c> session: a
    /// DA-protected storage parent created with a real password admits a Load authorized by the
    /// CORRECT password and moves no dictionary-attack counter, while a WRONG password is refused with
    /// the session-index-encoded <c>TPM_RC_AUTH_FAIL</c> (Part 2, clause 6.6.2) and charges
    /// <c>failedTries</c> exactly once (Part 1, clause 17.8.7).
    /// </summary>
    [TestMethod]
    public async Task LoadVerifiesTheParentsAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreatePasswordProtectedStorageParentAsync(
            tpm, registry, pool, ParentPassword, noDa: false).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint loadedHandle = 0;

        try
        {
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: false);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession createParentAuth = TpmPasswordSession.Create(ParentPasswordBytes, pool);

            TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(createResult.IsSuccess, $"Create (seal) with the parent's correct password must succeed, but failed: '{createResult.ResponseCode}'.");

            using CreateResponse sealedObject = createResult.Value;

            TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

            using Tpm2bPrivate correctPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
            using Tpm2bPublic correctPublic = ClonePublic(sealedObject.OutPublic, pool);
            using LoadInput correctLoadInput = new(parentHandle, correctPrivate, correctPublic);
            using TpmPasswordSession correctLoadAuth = TpmPasswordSession.Create(ParentPasswordBytes, pool);

            TpmResult<LoadResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
                tpm, correctLoadInput, [correctLoadAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(correctResult.IsSuccess, $"Load with the parent's correct password must succeed, but failed: '{correctResult.ResponseCode}'.");
            loadedHandle = correctResult.Value.ObjectHandle.Value;
            correctResult.Value.Dispose();

            TpmResult<TpmDictionaryAttackParameters> afterCorrect = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(before.Value.LockoutCounter, afterCorrect.Value.LockoutCounter, "A correctly-authorized Load must move no dictionary-attack counter.");

            using Tpm2bPrivate wrongPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
            using Tpm2bPublic wrongPublic = ClonePublic(sealedObject.OutPublic, pool);
            using LoadInput wrongLoadInput = new(parentHandle, wrongPrivate, wrongPublic);
            using TpmPasswordSession wrongLoadAuth = TpmPasswordSession.Create(WrongParentPasswordBytes, pool);

            TpmResult<LoadResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
                tpm, wrongLoadInput, [wrongLoadAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(wrongResult.IsTpmError, "A wrong parent password must be refused.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), wrongResult.ResponseCode,
                "A wrong parent password over a plain TPM_RS_PW session names the parent slot (index 0), session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");

            TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                afterCorrect.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
                "A wrong parent password against a DA-protected parent must charge failedTries exactly once (TPM 2.0 Library Part 1, clause 17.8.7).");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, loadedHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The non-DA-protected counterpart of <see cref="LoadVerifiesTheParentsAuthValue"/>: a storage
    /// parent created with a real password but <c>TPMA_OBJECT.NO_DA</c> SET rejects a wrong
    /// plain-password Load with a plain session-index-encoded <c>TPM_RC_BAD_AUTH</c> instead of
    /// <c>TPM_RC_AUTH_FAIL</c> (TPM 2.0 Library Part 1, clause 17.8.7's DA-exempt downgrade), and moves
    /// no dictionary-attack counter — only a DA-protected authValue's failure is ever charged to
    /// <c>failedTries</c> (Part 1, clause 17.8.1).
    /// </summary>
    [TestMethod]
    public async Task LoadWithWrongAuthOverNoDaParentReturnsBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreatePasswordProtectedStorageParentAsync(
            tpm, registry, pool, ParentPassword, noDa: true).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: true);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.Create(ParentPasswordBytes, pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (seal) with the parent's correct password must succeed, but failed: '{createResult.ResponseCode}'.");

        using CreateResponse sealedObject = createResult.Value;

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession wrongLoadAuth = TpmPasswordSession.Create(WrongParentPasswordBytes, pool);

        TpmResult<LoadResponse> result = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [wrongLoadAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTpmError, "A wrong parent password must be refused.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
            "A wrong password against a NON-DA-protected (NO_DA SET) parent must be a plain session-encoded TPM_RC_BAD_AUTH, never TPM_RC_AUTH_FAIL.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "A NO_DA parent's wrong-password rejection must never move the dictionary-attack counter.");
    }

    /// <summary>
    /// A locked-out TPM must reject even a Load carrying the parent's CORRECT password with the bare,
    /// non-session-encoded <c>TPM_RC_LOCKOUT</c> (TPM 2.0 Library Part 1, clause 17.8.3: "While in
    /// Lockout mode, any use of a DA-protected authValue will return TPM_RC_LOCKOUT") whenever the
    /// parent is DA-protected: the Lockout gate precedes the authValue compare entirely, so the correct
    /// password is never evaluated and <c>failedTries</c> moves no further. <c>maxTries</c> is lowered
    /// first so a handful of wrong-password Load attempts against the same DA-protected parent reaches
    /// Lockout mode quickly (Part 1, clause 17.8.7's charge rule).
    /// </summary>
    [TestMethod]
    public async Task LoadWhileInLockoutReturnsLockout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreatePasswordProtectedStorageParentAsync(
            tpm, registry, pool, ParentPassword, noDa: false).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        try
        {
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: false);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession createParentAuth = TpmPasswordSession.Create(ParentPasswordBytes, pool);

            TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(createResult.IsSuccess, $"Create (seal) with the parent's correct password must succeed, but failed: '{createResult.ResponseCode}'.");

            using CreateResponse sealedObject = createResult.Value;

            TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
                ReadOnlyMemory<byte>.Empty, LockoutTestMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
                TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

            for(uint attempt = 1; attempt <= LockoutTestMaxTries; attempt++)
            {
                using Tpm2bPrivate wrongPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
                using Tpm2bPublic wrongPublic = ClonePublic(sealedObject.OutPublic, pool);
                using LoadInput wrongLoadInput = new(parentHandle, wrongPrivate, wrongPublic);
                using TpmPasswordSession wrongLoadAuth = TpmPasswordSession.Create(WrongParentPasswordBytes, pool);

                TpmResult<LoadResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
                    tpm, wrongLoadInput, [wrongLoadAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(wrongResult.IsSuccess, $"Attempt {attempt} of {LockoutTestMaxTries} with a wrong parent password must fail.");
            }

            TpmResult<TpmDictionaryAttackParameters> lockoutState = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(lockoutState.IsSuccess, $"GetDictionaryAttackParameters failed: '{lockoutState.ResponseCode}'.");
            Assert.IsTrue(lockoutState.Value.IsLockedOut, "The TPM must be in Lockout mode before the correct-password Load runs.");

            using Tpm2bPrivate correctPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
            using Tpm2bPublic correctPublic = ClonePublic(sealedObject.OutPublic, pool);
            using LoadInput correctLoadInput = new(parentHandle, correctPrivate, correctPublic);
            using TpmPasswordSession correctLoadAuth = TpmPasswordSession.Create(ParentPasswordBytes, pool);

            TpmResult<LoadResponse> lockedOutResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
                tpm, correctLoadInput, [correctLoadAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            if(lockedOutResult.IsSuccess)
            {
                lockedOutResult.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_LOCKOUT, lockedOutResult.ResponseCode,
                "A locked-out TPM must reject even a CORRECT-password Load over a DA-protected parent " +
                $"with the bare TPM_RC_LOCKOUT (TPM 2.0 Library Part 1, clause 17.8.3), got '{lockedOutResult.ResponseCode}'.");

            TpmResult<TpmDictionaryAttackParameters> afterLockedOutAttempt = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                lockoutState.Value.LockoutCounter, afterLockedOutAttempt.Value.LockoutCounter,
                "A LOCKOUT rejection must never move failedTries further.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// TPM2_Create()'s parent slot (Auth Index 1, Auth Role USER; TPM 2.0 Library Part 3, clause 12.1) applies
    /// check 7.1 of clause 5.6: when the parent's <c>TPMA_OBJECT.userWithAuth</c> is CLEAR, a plain
    /// <c>TPM_RS_PW</c> session is refused with the bare <c>TPM_RC_POLICY_FAIL</c> even when it carries the
    /// parent's genuine password — the credential is never compared, and <c>failedTries</c> does not move
    /// (clause 5.6's closing rule: a non-<c>TPM_RC_AUTH_FAIL</c> error "shall not alter any TPM state"). Only a
    /// policy session remains admissible for this parent's USER role.
    /// </summary>
    [TestMethod]
    public async Task PlainPasswordCreateUnderUserWithAuthClearParentIsRefusedWithoutComparingThePassword()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateUserWithAuthClearStorageParentAsync(
            tpm, registry, pool, ParentPassword, noDa: false).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: false);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.Create(ParentPasswordBytes, pool);

        TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode,
            "A userWithAuth-CLEAR parent must refuse a plain TPM_RS_PW TPM2_Create() with the bare TPM_RC_POLICY_FAIL " +
            $"(Part 3, clause 5.6, check 7.1) even though the session carries the parent's genuine password " +
            $"(got '{result.ResponseCode}').");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "check 7.1 answers uncharged (Part 3, clause 5.6's closing rule: a non-AUTH_FAIL error shall not alter any TPM state).");
    }

    /// <summary>
    /// TPM2_Create()'s parent slot, over an UNBOUND unsalted HMAC session (the two-session
    /// <c>OnCreateSealedObjectOverSessions</c> path), applies check 7.1 of clause 5.6 BEFORE the queued command
    /// HMAC verification (checks 9/10): a userWithAuth-CLEAR parent refuses with the bare
    /// <c>TPM_RC_POLICY_FAIL</c> even when the session folds a WRONG authValue guess as its entity term (TPM
    /// 2.0 Library Part 1, clause 17.6.9, equation 19) — never the session-index-encoded
    /// <c>TPM_RC_AUTH_FAIL</c> a completed HMAC comparison would produce against this DA-protected parent — and
    /// <c>failedTries</c> does not move, proving the guess is never evaluated.
    /// </summary>
    [TestMethod]
    public async Task CreateOverUnboundHmacSessionUnderUserWithAuthClearParentIsRefusedWithoutComparingTheGuess()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateUserWithAuthClearStorageParentAsync(
            tpm, registry, pool, ParentPassword, noDa: false).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        ReadOnlyMemory<byte> parentName = parent.Name.Span.ToArray();

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<CreateResponse> result = await CreateSealedObjectOverUnboundHmacSessionAsync(
            tpm, registry, pool, parentHandle, parentName, WrongParentPasswordBytes).ConfigureAwait(false);

        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode,
            "A userWithAuth-CLEAR parent must refuse an over-session TPM2_Create() with the bare TPM_RC_POLICY_FAIL " +
            $"(Part 3, clause 5.6, check 7.1) before the queued command HMAC is ever evaluated, never the " +
            $"session-index-encoded TPM_RC_AUTH_FAIL (got '{result.ResponseCode}').");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "check 7.1 answers uncharged (Part 3, clause 5.6's closing rule): failedTries must not move even though the folded guess was wrong.");
    }

    /// <summary>
    /// TPM2_Create()'s parent slot, authorized by a plain <c>TPM_RS_PW</c> session (slot 0) paired with a
    /// separate decrypt-attributed HMAC companion (slot 1) protecting <c>inSensitive</c> — the inline-compare
    /// arm of <c>OnCreateSealedObjectOverSessions</c> — applies check 7.1 of clause 5.6 identically to the
    /// single-session plain form: a userWithAuth-CLEAR parent refuses with the bare <c>TPM_RC_POLICY_FAIL</c>
    /// even when the TPM_RS_PW slot carries the parent's genuine password, before the companion session's own
    /// HMAC (checks 9/10) is ever evaluated.
    /// </summary>
    [TestMethod]
    public async Task CreateOverPasswordSlotWithDecryptSessionUnderUserWithAuthClearParentIsRefused()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateUserWithAuthClearStorageParentAsync(
            tpm, registry, pool, ParentPassword, noDa: false).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        ReadOnlyMemory<byte> parentName = parent.Name.Span.ToArray();

        TpmResult<CreateResponse> result = await CreateSealedObjectOverPasswordAndDecryptSessionAsync(
            tpm, registry, pool, parentHandle, parentName, ParentPasswordBytes).ConfigureAwait(false);

        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode,
            "A userWithAuth-CLEAR parent must refuse the [TPM_RS_PW, decrypt HMAC] two-session TPM2_Create() " +
            $"with the bare TPM_RC_POLICY_FAIL (Part 3, clause 5.6, check 7.1) even though the TPM_RS_PW slot " +
            $"carries the parent's genuine password (got '{result.ResponseCode}').");
    }

    /// <summary>
    /// TPM2_Load()'s parent slot (Auth Index 1, Auth Role USER; TPM 2.0 Library Part 3, clause 12.2) applies
    /// check 7.1 of clause 5.6 before the private blob is ever unwrapped (checks 9/10): a userWithAuth-CLEAR
    /// parent refuses a plain <c>TPM_RS_PW</c> Load with the bare <c>TPM_RC_POLICY_FAIL</c> even when the
    /// session carries the parent's genuine password, whatever blob is presented — the wrapped object loaded
    /// here is sealed under an ordinary parent (well-formed wire bytes, cryptographically foreign to the gated
    /// parent), so a Load that reached the unwrap step ahead of the gate would fail differently instead of with
    /// this bare code.
    /// </summary>
    [TestMethod]
    public async Task LoadUnderUserWithAuthClearParentIsRefusedWithoutComparingThePassword()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //A well-formed wrapped blob, sealed under an ORDINARY (userWithAuth SET) parent — its cryptographic
        //content is foreign to the userWithAuth-CLEAR parent below.
        using CreatePrimaryResponse foreignParent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        using Tpm2bSensitiveCreate foreignSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
        using Tpm2bPublic foreignTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: true);
        using CreateInput foreignCreateInput = new(
            foreignParent.ObjectHandle.Value, foreignSensitive, foreignTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession foreignParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> foreignCreateResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, foreignCreateInput, [foreignParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(foreignCreateResult.IsSuccess, $"Create (foreign-parent seal) failed: '{foreignCreateResult.ResponseCode}'.");

        using CreateResponse foreignSealed = foreignCreateResult.Value;

        using CreatePrimaryResponse gatedParent = await CreateUserWithAuthClearStorageParentAsync(
            tpm, registry, pool, ParentPassword, noDa: false).ConfigureAwait(false);
        uint gatedParentHandle = gatedParent.ObjectHandle.Value;

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(foreignSealed.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(foreignSealed.OutPublic, pool);
        using LoadInput loadInput = new(gatedParentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.Create(ParentPasswordBytes, pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        if(loadResult.IsSuccess)
        {
            loadResult.Value.Dispose();
        }

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_FAIL, loadResult.ResponseCode,
            "A userWithAuth-CLEAR parent must refuse a plain TPM_RS_PW TPM2_Load() with the bare TPM_RC_POLICY_FAIL " +
            $"(Part 3, clause 5.6, check 7.1) even though the session carries the parent's genuine password " +
            $"(got '{loadResult.ResponseCode}').");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "check 7.1 answers uncharged (Part 3, clause 5.6's closing rule: a non-AUTH_FAIL error shall not alter any TPM state).");
    }

    /// <summary>
    /// TPM2_Unseal()'s item slot (Auth Index 1, Auth Role USER; TPM 2.0 Library Part 3, clause 12.7) applies
    /// check 7.1 of clause 5.6 before the queued command HMAC verification (check 9), exactly as the
    /// parent-slot proofs above: a KEYEDHASH object sealed with <c>userWithAuth</c> CLEAR, a non-empty
    /// authPolicy, and a real, non-empty userAuth refuses an over-session Unseal carrying a WRONG authValue
    /// guess as the folded entity term with the bare <c>TPM_RC_POLICY_FAIL</c> — never the
    /// session-index-encoded <c>TPM_RC_AUTH_FAIL</c> a completed HMAC comparison would produce — and
    /// <c>failedTries</c> does not move. The object is sealed WITHOUT <c>NO_DA</c> so a charge, had one
    /// occurred, would have been visible.
    /// </summary>
    [TestMethod]
    public async Task UnsealOverHmacSessionAgainstUserWithAuthClearObjectIsRefusedWithoutComparingTheGuess()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        byte[] correctItemAuth = [0x51, 0x52, 0x53, 0x54];
        byte[] wrongItemAuthGuess = [0xA1, 0xA2, 0xA3, 0xA4];
        byte[] authPolicy = new byte[32];
        Array.Fill(authPolicy, (byte)0x7B);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, correctItemAuth, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy, noDa: false, userWithAuth: false);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (seal, userWithAuth CLEAR) failed: '{createResult.ResponseCode}'.");

        using CreateResponse sealedObject = createResult.Value;

        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");

        using LoadResponse loaded = loadResult.Value;

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (item slot) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession itemAuthSession = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, pool);
            itemAuthSession.SetAuthValue(wrongItemAuthGuess, pool);

            UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
            ReadOnlyMemory<byte>[] handleNames = [loaded.Name.Span.ToArray()];

            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [itemAuthSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            if(unsealResult.IsSuccess)
            {
                unsealResult.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_POLICY_FAIL, unsealResult.ResponseCode,
                "A userWithAuth-CLEAR sealed object must refuse an over-session Unseal with the bare TPM_RC_POLICY_FAIL " +
                $"(Part 3, clause 5.6, check 7.1) before the queued command HMAC ever evaluates the guess, never the " +
                $"session-index-encoded TPM_RC_AUTH_FAIL (got '{unsealResult.ResponseCode}').");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "check 7.1 answers uncharged (Part 3, clause 5.6's closing rule): failedTries must not move even though the guess was wrong and the object is not noDA-exempt.");
    }

    /// <summary>
    /// Creates the deterministic ECC storage parent under the owner hierarchy and returns the response (the caller
    /// owns it).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response for the storage parent.</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");

        return parentResult.Value;
    }

    /// <summary>
    /// Creates an ECC storage parent under the owner hierarchy with a real, non-empty password — the fixture
    /// the parent-authValue verification proofs need to exercise TPM2_Create()'s Auth Index 1, Auth Role USER
    /// slot (TPM 2.0 Library Part 3, clause 12.1) against a genuine retained authValue rather than the empty
    /// one <see cref="CreateStorageParentAsync"/>'s parent carries.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="password">The parent's password.</param>
    /// <param name="noDa">Whether the parent is dictionary-attack exempt (<c>TPMA_OBJECT.NO_DA</c>).</param>
    /// <returns>The CreatePrimary response for the storage parent (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreatePasswordProtectedStorageParentAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, string password, bool noDa)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, password, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary (password-protected storage parent) failed: '{parentResult.ResponseCode}'.");

        return parentResult.Value;
    }

    /// <summary>
    /// Creates an ECC storage parent (<c>TPMA_OBJECT.RESTRICTED | DECRYPT</c>) under the owner hierarchy,
    /// composed from the same public pieces <see cref="CreatePrimaryInput.ForEccStorageParent"/> assembles
    /// internally, but with <see cref="TpmaObject.USER_WITH_AUTH"/> omitted: USER-role authorization of this
    /// parent (Auth Index 1 on TPM2_Create() and TPM2_Load(), TPM 2.0 Library Part 3, clauses 12.1 and 12.2)
    /// can never be satisfied by a password or HMAC session (Part 3, clause 5.6, check 7.1) — only a policy
    /// session remains admissible. Creation itself is authorized by the owner hierarchy, which "operates as if
    /// userWithAuth is SET" per clause 5.6, so it still succeeds.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="password">The parent's authValue — retained on the object, but never usable through check 7.1's authValue-based paths.</param>
    /// <param name="noDa">Whether the parent is dictionary-attack exempt (<c>TPMA_OBJECT.NO_DA</c>).</param>
    /// <returns>The CreatePrimary response for the storage parent (the caller owns it).</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the CreatePrimaryInput, whose Dispose releases them.")]
    private async Task<CreatePrimaryResponse> CreateUserWithAuthClearStorageParentAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, string password, bool noDa)
    {
        TpmaObject attributes = TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.RESTRICTED | TpmaObject.DECRYPT;

        if(noDa)
        {
            attributes |= TpmaObject.NO_DA;
        }

        Tpm2bSensitiveCreate inSensitive = string.IsNullOrEmpty(password)
            ? Tpm2bSensitiveCreate.CreateEmpty(pool)
            : Tpm2bSensitiveCreate.WithPassword(password, pool);
        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccStorageParent(
            TpmAlgIdConstants.TPM_ALG_SHA256, attributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmsEccPoint.Empty, pool);
        using CreatePrimaryInput parentInput = new(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (userWithAuth-CLEAR storage parent) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Seals <see cref="SecretBytes"/> under <paramref name="parentHandle"/> over a fresh, UNBOUND, unsalted
    /// HMAC session at the parent slot carrying <paramref name="suppliedParentAuth"/> as its folded entity term
    /// (TPM 2.0 Library Part 1, clause 17.6.9, equation 19). The session is flushed before return; on success
    /// the wrapped object's response is left for the caller to dispose.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent's transient handle.</param>
    /// <param name="parentName">The storage parent's Name, for cpHash.</param>
    /// <param name="suppliedParentAuth">The authValue term folded into the session's command HMAC.</param>
    /// <returns>The Create result.</returns>
    private async Task<TpmResult<CreateResponse>> CreateSealedObjectOverUnboundHmacSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, ReadOnlyMemory<byte> parentName, ReadOnlyMemory<byte> suppliedParentAuth)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (parent slot) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession parentAuthSession = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, pool);
            parentAuthSession.SetAuthValue(suppliedParentAuth.Span, pool);

            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: false);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);

            ReadOnlyMemory<byte>[] handleNames = [parentName];

            return await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [parentAuthSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Seals <see cref="SecretBytes"/> under <paramref name="parentHandle"/>, authorized by a plain
    /// <c>TPM_RS_PW</c> session carrying <paramref name="suppliedParentPassword"/> at slot 0, paired with a
    /// fresh, UNBOUND, unsalted HMAC companion at slot 1 carrying the DECRYPT attribute over
    /// <c>inSensitive</c> — the two-session shape <c>TryParseCreate</c> routes to
    /// <c>OnCreateSealedObjectOverSessions</c>'s password-slot arm. The companion session is flushed before
    /// return.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent's transient handle.</param>
    /// <param name="parentName">The storage parent's Name, for cpHash.</param>
    /// <param name="suppliedParentPassword">The plaintext password carried at slot 0.</param>
    /// <returns>The Create result.</returns>
    private async Task<TpmResult<CreateResponse>> CreateSealedObjectOverPasswordAndDecryptSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, ReadOnlyMemory<byte> parentName, ReadOnlyMemory<byte> suppliedParentPassword)
    {
        StartAuthSessionInput decryptStartInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TpmtSymDef.Xor(SessionAlg));
        TpmResult<StartAuthSessionResponse> decryptStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, decryptStartInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(decryptStartResult.IsSuccess, $"StartAuthSession (decrypt companion) failed: '{decryptStartResult.ResponseCode}'.");

        StartAuthSessionResponse decryptStarted = decryptStartResult.Value;
        uint decryptSessionHandle = decryptStarted.SessionHandle.Value;

        try
        {
            using TpmSession decryptSession = new(
                new TpmHandle(decryptSessionHandle), decryptStarted.NonceTPM, SessionAlg, pool, TpmtSymDef.Xor(SessionAlg));
            decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: false);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession parentAuth = TpmPasswordSession.Create(suppliedParentPassword.Span, pool);

            ReadOnlyMemory<byte>[] handleNames = [parentName];

            return await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [parentAuth, decryptSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(decryptSessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
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
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase. The ECC backend is required so the simulator services
    /// <c>TPM2_CreatePrimary()</c>; the storage parent is used only as a handle to parent the sealed object here.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-seal", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
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

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>Flushes a transient object or session handle when one is present (non-zero), ignoring the result.</summary>
    private async Task FlushIfPresentAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        if(!registry.TryGet(TpmCcConstants.TPM_CC_FlushContext, out _))
        {
            _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        }

        var flush = FlushContextInput.ForHandle(handle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, BaseMemoryPool.Shared, registry, TestContext.CancellationToken).ConfigureAwait(false);
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
}
