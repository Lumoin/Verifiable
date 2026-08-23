using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
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
/// Drives <c>TPM2_CreatePrimary()</c> then <c>TPM2_Sign()</c> against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production
/// command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="CreatePrimaryInput"/>, <see cref="SignInput"/>, and response codecs), then verifies the signature
/// <b>off-TPM</b> against a public key reconstructed solely from the simulator's exported public area
/// (<c>outPublic</c>).
/// </summary>
/// <remarks>
/// <para>
/// The verifier shares no in-memory state with the signer beyond the wire bytes, so a divergence between what
/// the simulator framed and what a genuine TPM would sign fails here. The signing backend is injected so the
/// production <c>Verifiable.Tpm</c> assembly stays provider-agnostic.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorSignTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus size in bits used by the RSA signing test.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The fixed message whose SHA-256 digest is signed.</summary>
    private static byte[] MessageBytes { get; } = "Verifiable in-house TPM signing acceptance test."u8.ToArray();

    /// <summary>The real password the signing key's own-authValue verification proof creates the key with.</summary>
    private const string SigningKeyPassword = "sign-key-auth-proof";

    /// <summary>
    /// <see cref="SigningKeyPassword"/>'s UTF-8 octets, matching the password-to-authValue convention
    /// <see cref="Tpm2bAuth.CreateFromPassword"/> applies on the creation side (the password carries no trailing
    /// zeros, so no trimming is in play).
    /// </summary>
    private static byte[] SigningKeyPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(SigningKeyPassword);

    /// <summary>A wrong guess at the signing key's password, distinct from <see cref="SigningKeyPasswordBytes"/>.</summary>
    private static byte[] WrongSigningKeyPasswordBytes { get; } = [0x7A, 0x7B, 0x7C, 0x7D];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task EcdsaP256CreateSignVerifiesAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (ECDSA) failed: '{signResult.ResponseCode}'.");

        using SignResponse signature = signResult.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, signature.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.HashAlgorithm);
        Assert.IsNotNull(signature.Signature.SignatureR);
        Assert.IsNotNull(signature.Signature.SignatureS);

        //Firewalled verify: reconstruct the public key from the simulator's exported public area only.
        TpmsEccPoint point = primary.OutPublic.PublicArea.Unique.Ecc!;
        var ecParameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = ToFixed(point.X.AsReadOnlySpan(), P256ComponentSize),
                Y = ToFixed(point.Y.AsReadOnlySpan(), P256ComponentSize)
            }
        };

        //.NET's VerifyHash expects the raw IEEE P1363 r || s concatenation, each component fixed-width.
        byte[] p1363Signature = new byte[2 * P256ComponentSize];
        ToFixed(signature.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(signature.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        //Independent-oracle carve-out: framework ECDsa verifies against wire-exported simulator output, sharing
        //no code path with the signer, so a divergence in either implementation fails here.
        using ECDsa ecdsa = ECDsa.Create(ecParameters);
        Assert.IsTrue(
            ecdsa.VerifyHash(digest, p1363Signature),
            "An ECDSA signature produced by the in-house simulator must verify against its exported public key.");
    }

    /// <summary>
    /// <c>TPM2_Sign()</c>'s key slot (Auth Index 1, Auth Role USER; TPM 2.0 Library Part 3, clause 20.2) is
    /// verified against the signing key's own retained authValue over a plain <c>TPM_RS_PW</c> session: a
    /// DA-protected ECC signing key (<c>TPMA_OBJECT.NO_DA</c> clear) created with a real password signs when the
    /// CORRECT password authorizes it and moves no dictionary-attack counter, while a WRONG password is refused
    /// with the session-index-encoded <c>TPM_RC_AUTH_FAIL</c> (Part 2, clause 6.6.2) and charges
    /// <c>failedTries</c> exactly once (Part 1, clause 17.8.7).
    /// </summary>
    [TestMethod]
    public async Task SignVerifiesTheSigningKeysOwnAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            SigningKeyPassword,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: false);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (password-protected ECC signing key) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession correctKeyAuth = TpmPasswordSession.Create(SigningKeyPasswordBytes, pool);
        using SignInput correctSignInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, correctSignInput, [correctKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(correctResult.IsSuccess, $"TPM2_Sign with the key's correct password must succeed, but failed: '{correctResult.ResponseCode}'.");
        correctResult.Value.Dispose();

        TpmResult<TpmDictionaryAttackParameters> afterCorrect = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, afterCorrect.Value.LockoutCounter, "A correctly-authorized Sign must move no dictionary-attack counter.");

        using TpmPasswordSession wrongKeyAuth = TpmPasswordSession.Create(WrongSigningKeyPasswordBytes, pool);
        using SignInput wrongSignInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, wrongSignInput, [wrongKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(wrongResult.IsTpmError, "A wrong key password must be refused.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), wrongResult.ResponseCode,
            "A wrong key password over a plain TPM_RS_PW session names the key slot (index 0), session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            afterCorrect.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
            "A wrong key password against a DA-protected signing key must charge failedTries exactly once (TPM 2.0 Library Part 1, clause 17.8.7).");
    }

    /// <summary>
    /// Proves TPM 2.0 Library Part 3, clause 5.6, check 7.1: <c>TPM2_Sign()</c>'s key slot (Auth Index 1, Auth
    /// Role USER) refuses ANY authValue-based session against a key whose <c>TPMA_OBJECT.userWithAuth</c> is
    /// CLEAR — including a plain <c>TPM_RS_PW</c> session carrying the key's own CORRECT password — with a bare
    /// <c>TPM_RC_POLICY_FAIL</c>, because it is the session's SHAPE that is inadmissible, not its credential; a
    /// <c>userWithAuth</c>-CLEAR object admits only a policy session for the USER role (TPM 2.0 Library Part 2,
    /// clause 8.3.3). Check 7.1 precedes checks 9/10 in clause 5.6's mandatory order, so the correct password is
    /// never even compared, and the refusal is uncharged: <c>TPM_RC_POLICY_FAIL</c> is not <c>TPM_RC_AUTH_FAIL</c>,
    /// and clause 5.6's closing rule bars a non-<c>AUTH_FAIL</c> error from altering any TPM state, so
    /// <c>failedTries</c> does not move (TPM 2.0 Library Part 1, clause 17.8.7).
    /// </summary>
    [TestMethod]
    public async Task SignWithUserWithAuthClearKeyIsRefusedWithoutComparingThePassword()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreateUserWithAuthClearEccSigningKeyInput(SigningKeyPassword, pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (userWithAuth-CLEAR ECC signing key) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        //The exploit shape: a plain TPM_RS_PW session carrying the CORRECT password against a userWithAuth-CLEAR key.
        using TpmPasswordSession correctKeyAuth = TpmPasswordSession.Create(SigningKeyPasswordBytes, pool);
        using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [correctKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        if(signResult.IsSuccess)
        {
            signResult.Value.Dispose();
        }

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_FAIL, signResult.ResponseCode,
            $"A userWithAuth-CLEAR signing key must refuse a password session with a bare TPM_RC_POLICY_FAIL " +
            $"(TPM 2.0 Library Part 3, clause 5.6, check 7.1), even when the password is correct (got '{signResult.ResponseCode}').");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "A check 7.1 refusal must not alter any TPM state (Part 3, clause 5.6's closing rule): failedTries must not move, even though the supplied password was correct.");
    }

    /// <summary>
    /// Proves TPM 2.0 Library Part 3, clause 5.6, check 7.1 runs strictly before checks 9/10: against the SAME
    /// <c>userWithAuth</c>-CLEAR signing key as
    /// <see cref="SignWithUserWithAuthClearKeyIsRefusedWithoutComparingThePassword"/>, a WRONG password over a
    /// plain <c>TPM_RS_PW</c> session is refused with the identical bare <c>TPM_RC_POLICY_FAIL</c> — never the
    /// session-index-encoded <c>TPM_RC_AUTH_FAIL</c> a wrong authValue would otherwise produce (TPM 2.0 Library
    /// Part 2, clause 6.6.2) — because check 7.1 rejects the session's shape before checks 9/10 (the authValue
    /// compare that would distinguish a wrong password from a correct one) ever run. The key is created without
    /// <c>TPMA_OBJECT.noDA</c>, so had check 7.1 been skipped and the compare reached, a rejected wrong password
    /// would have charged <c>failedTries</c> (TPM 2.0 Library Part 1, clause 17.8.7); it does not.
    /// </summary>
    [TestMethod]
    public async Task SignWithUserWithAuthClearKeyRefusesWrongPasswordWithoutChargingFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreateUserWithAuthClearEccSigningKeyInput(SigningKeyPassword, pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (userWithAuth-CLEAR ECC signing key) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession wrongKeyAuth = TpmPasswordSession.Create(WrongSigningKeyPasswordBytes, pool);
        using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [wrongKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        if(signResult.IsSuccess)
        {
            signResult.Value.Dispose();
        }

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_FAIL, signResult.ResponseCode,
            $"A userWithAuth-CLEAR signing key must refuse a wrong password with the same bare TPM_RC_POLICY_FAIL " +
            $"as a correct one (TPM 2.0 Library Part 3, clause 5.6, check 7.1), never TPM_RC_AUTH_FAIL (got '{signResult.ResponseCode}').");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "Check 7.1 precedes checks 9/10 (the authValue compare), so a wrong password against a DA-protected, userWithAuth-CLEAR key still must not charge failedTries.");
    }

    [TestMethod]
    public async Task RsaCreateSignVerifiesAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //A NULL scheme makes this an unrestricted signing key, so the scheme (RSASSA or RSAPSS) is chosen per
        //TPM2_Sign — both are exercised against one (expensive) RSA key generation, as a real caller would.
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Null, pool, noDa: true);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (RSA 2048) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSA, primary.OutPublic.PublicArea.Type, "The created key must be an RSA key.");

        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        //Firewalled verify: reconstruct the public key from the simulator's exported modulus only, with the
        //conventional public exponent F4 (65537).
        var rsaParameters = new RSAParameters
        {
            Modulus = primary.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
            Exponent = [0x01, 0x00, 0x01]
        };

        await SignAndVerifyRsaAsync(tpm, registry, pool, primary.ObjectHandle, digest, rsaParameters, usePss: false).ConfigureAwait(false);
        await SignAndVerifyRsaAsync(tpm, registry, pool, primary.ObjectHandle, digest, rsaParameters, usePss: true).ConfigureAwait(false);
    }

    [TestMethod]
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "The PrivateKey takes ownership of the handle memory and is disposed by its using declaration.")]
    public async Task TpmBackedPrivateKeySignsAndVerifiesThroughTheVerifiableAbstraction()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;

        //Surface the in-house TPM key as a first-class Verifiable signing key: the private-key memory carries only
        //the handle, and the TPM signing function is bound as the SigningDelegate. The TpmDevice and scheme travel
        //through the per-call context, not a closure. The PrivateKey owns the handle memory.
        using var privateKey = new PrivateKey(
            TpmCryptographicFunctions.CreateHandleKeyMemory(primary.ObjectHandle.Value, CryptoTags.P256PrivateKey, pool),
            "tpm-p256",
            TpmCryptographicFunctions.SignAsync,
            TpmCryptographicFunctions.CreateP256SigningContext(tpm));

        using Signature signature = await privateKey.SignAsync(MessageBytes, pool).ConfigureAwait(false);

        //Verify with the library's registered software P-256 verifier, from a public key reconstructed solely from
        //the TPM's exported public area (compressed SEC1 point, as the verifier requires).
        byte[] compressedPublicKey = TpmEccWireFixtures.BuildCompressedPublicKey(primary.OutPublic.PublicArea.Unique.Ecc!, P256ComponentSize);

        VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(
            CryptoAlgorithm.P256, Purpose.Verification);

        (bool verified, CryptoEvent? _) = await verify(MessageBytes, signature.AsReadOnlyMemory(), compressedPublicKey, null, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verified, "A signature produced by a TPM-backed PrivateKey must verify through the library's P-256 verifier.");
    }

    [TestMethod]
    public async Task CreatePrimaryReturnsFaithfulNameCreationDataAndTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;

        //The object Name is nameAlg || H_nameAlg(TPMT_PUBLIC) (TPM 2.0 Part 1, clause 14, Table 6). Recompute the digest
        //independently from the exported public area and confirm the response carries the real Name.
        byte[] marshaledPublic = MarshalPublicArea(primary.OutPublic, pool);
        byte[] expectedNameDigest = await ComputeSha256Async(marshaledPublic, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual((ushort)TpmAlgIdConstants.TPM_ALG_SHA256, primary.Name.NameAlgorithm, "The Name must carry the SHA-256 name algorithm.");
        Assert.IsTrue(expectedNameDigest.AsSpan().SequenceEqual(primary.Name.Digest), "The Name digest must be H(TPMT_PUBLIC).");

        //creationHash is H_nameAlg(creationData) (TPM 2.0 Part 2, clause 15.1). Recompute it from the exported
        //creationData bytes.
        byte[] expectedCreationHash = await ComputeSha256Async(primary.CreationData.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(expectedCreationHash.AsSpan().SequenceEqual(primary.CreationHash.AsReadOnlySpan()), "creationHash must be H(creationData).");

        //creationData for a primary under the owner hierarchy: a NULL parentNameAlg and the owner handle as the
        //parent Name and Qualified Name (TPM 2.0 Library Part 2, clause 15.1).
        TpmsCreationData creationData = primary.CreationData.CreationData;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_NULL, creationData.ParentNameAlg, "A primary's parentNameAlg is TPM_ALG_NULL.");
        Assert.AreEqual((uint)TpmRh.TPM_RH_OWNER, creationData.ParentName.Handle, "parentName is the owner-hierarchy handle.");
        Assert.AreEqual((uint)TpmRh.TPM_RH_OWNER, creationData.ParentQualifiedName.Handle, "parentQualifiedName is the owner-hierarchy handle.");

        //The creation ticket is a real HMAC bound to the owner hierarchy (TPM 2.0 Library Part 2, clause 10.7),
        //not a NULL ticket.
        Assert.AreEqual(TpmStConstants.TPM_ST_CREATION, primary.CreationTicket.Tag, "The ticket tag must be TPM_ST_CREATION.");
        Assert.AreEqual(TpmiRhHierarchy.Owner, primary.CreationTicket.Hierarchy, "The ticket hierarchy must be the owner hierarchy.");
        Assert.IsFalse(primary.CreationTicket.IsNull, "The creation ticket must be a real HMAC, not a NULL ticket.");
        Assert.HasCount(P256ComponentSize, primary.CreationTicket.Digest, "The creation ticket digest is a SHA-256 HMAC.");
    }

    [TestMethod]
    public async Task CreationTicketIsAVerifiableHmacOfTheInjectedSeed()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //A fixed seed stands in for the hierarchy's persistent random proof secret; injecting it makes the
        //creation ticket reproducible and lets this test recompute it.
        byte[] seed = Convert.FromHexString("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");

        using var simulator = new TpmSimulator("tpm-in-house-seed", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), seed: seed);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;

        //Recompute the ticket exactly as TPM2_CertifyCreation would: the proof is H(seed || hierarchy), and the
        //ticket digest is HMAC(proof, TPM_ST_CREATION || name || creationHash). A match proves the ticket is a
        //real, verifiable HMAC bound to the injected seed — not an opaque or stubbed value.
        byte[] proof = await ComputeSha256Async(BuildProofInput(seed, (uint)TpmRh.TPM_RH_OWNER, pool), pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] ticketMessage = BuildTicketMessage(primary.Name.Span, primary.CreationHash.AsReadOnlySpan(), pool);
        byte[] expectedTicket = await ComputeHmacSha256Async(ticketMessage, proof, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            expectedTicket.AsSpan().SequenceEqual(primary.CreationTicket.Digest),
            "The creation ticket must be HMAC(H(seed || hierarchy), TPM_ST_CREATION || name || creationHash), verifiable against the injected seed.");
    }

    [TestMethod]
    public async Task SignWithUnknownKeyHandleReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //No key was created, so the transient handle does not resolve (TPM 2.0 Part 3, clause 20.2).
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(
            TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase), digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, signResult.ResponseCode);
    }

    [TestMethod]
    public async Task CreatePrimaryWithoutSigningBackendReturnsCommandCode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //A simulator with no signing backend does not implement key creation: it answers TPM_RC_COMMAND_CODE.
        using var simulator = new TpmSimulator("tpm-in-house-no-backend");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_COMMAND_CODE, primaryResult.ResponseCode);
    }

    /// <summary>
    /// Signs the digest with the given RSA scheme through the production command path and verifies the result
    /// off-TPM against the public key reconstructed from the simulator's exported modulus.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The handle of the loaded RSA signing key.</param>
    /// <param name="digest">The pre-computed SHA-256 digest to sign.</param>
    /// <param name="rsaParameters">The public key reconstructed from the exported modulus.</param>
    /// <param name="usePss">When <see langword="true"/>, signs and verifies RSAPSS; otherwise RSASSA (PKCS#1 v1.5).</param>
    private async Task SignAndVerifyRsaAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] digest, RSAParameters rsaParameters, bool usePss)
    {
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = usePss
            ? SignInput.ForRsaPss(keyHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool)
            : SignInput.ForRsaSsa(keyHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        string schemeName = usePss ? "RSAPSS" : "RSASSA";
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign ({schemeName}) failed: '{signResult.ResponseCode}'.");

        using SignResponse signature = signResult.Value;
        Assert.AreEqual(usePss ? TpmAlgIdConstants.TPM_ALG_RSAPSS : TpmAlgIdConstants.TPM_ALG_RSASSA, signature.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.HashAlgorithm);
        Assert.IsFalse(signature.Signature.RsaSignature.IsEmpty, $"The {schemeName} signature buffer must not be empty.");

        RSASignaturePadding padding = usePss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;

        //Independent-oracle carve-out: framework RSA verifies against wire-exported simulator output, sharing
        //no code path with the signer, so a divergence in either implementation fails here.
        using RSA rsa = RSA.Create(rsaParameters);
        Assert.IsTrue(
            rsa.VerifyHash(digest, signature.Signature.RsaSignature.Buffer.ToArray(), HashAlgorithmName.SHA256, padding),
            $"An {schemeName} signature produced by the in-house simulator must verify against its exported modulus.");
    }

    /// <summary>
    /// Composes a CreatePrimary input for a DA-protected ECC signing key whose <c>TPMA_OBJECT.userWithAuth</c>
    /// bit is CLEAR — no production factory omits it, so the public template is built directly, mirroring
    /// <see cref="CreatePrimaryInput.ForEccSigningKey"/> with that one attribute bit withheld and
    /// <c>TPMA_OBJECT.noDA</c> never set. Creation itself is authorized by the owner hierarchy, which is exempt
    /// from check 7.1 ("a hierarchy operates as if userWithAuth is SET", TPM 2.0 Library Part 3, clause 5.6).
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

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers
    /// it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-sign",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());
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
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)) — a local mirror of the production session-index encoding, transcribed
    /// independently here since the production helper is private.
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);

        return registry;
    }

    /// <summary>
    /// Computes a SHA-256 digest through the registered digest seam (not a direct framework hash).
    /// </summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 32-byte digest.</returns>
    private static async Task<byte[]> ComputeSha256Async(ReadOnlyMemory<byte> message, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        Tag tag = Tag.Create(HashAlgorithmName.SHA256)
            .With(Purpose.Digest)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(message),
            outputByteLength: P256ComponentSize,
            tag: tag,
            pool: pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Marshals the exported public area into its canonical TPMT_PUBLIC wire form (no TPM2B size prefix) — the
    /// hash input the object Name is computed over.
    /// </summary>
    /// <param name="outPublic">The exported public area.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The marshaled TPMT_PUBLIC bytes.</returns>
    private static byte[] MarshalPublicArea(Tpm2bPublic outPublic, BaseMemoryPool pool)
    {
        int size = outPublic.PublicArea.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        outPublic.PublicArea.WriteTo(ref writer);

        return owner.Memory.Span[..size].ToArray();
    }

    /// <summary>Computes an HMAC-SHA256 through the registered HMAC seam.</summary>
    /// <param name="message">The message to authenticate.</param>
    /// <param name="key">The HMAC key.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 32-byte HMAC.</returns>
    private static async Task<byte[]> ComputeHmacSha256Async(ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> key, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using HmacValue hmac = await CryptographicKeyEvents.ComputeHmacAsync(
            message, key, P256ComponentSize, CryptoTags.HmacSha256Value, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return hmac.AsReadOnlySpan().ToArray();
    }

    /// <summary>Builds the creation-ticket proof-derivation input: the seed followed by the hierarchy handle.</summary>
    /// <param name="seed">The TPM seed.</param>
    /// <param name="hierarchy">The hierarchy handle.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The proof-derivation input bytes.</returns>
    private static byte[] BuildProofInput(byte[] seed, uint hierarchy, BaseMemoryPool pool)
    {
        int length = seed.Length + sizeof(uint);
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span);
        writer.WriteBytes(seed);
        writer.WriteUInt32(hierarchy);

        return owner.Memory.Span[..length].ToArray();
    }

    /// <summary>Builds the creation-ticket HMAC message: TPM_ST_CREATION (UINT16) followed by the Name and creation hash.</summary>
    /// <param name="name">The object Name bytes.</param>
    /// <param name="creationHash">The creation hash bytes.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The ticket message bytes.</returns>
    private static byte[] BuildTicketMessage(ReadOnlySpan<byte> name, ReadOnlySpan<byte> creationHash, BaseMemoryPool pool)
    {
        int length = sizeof(ushort) + name.Length + creationHash.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_CREATION);
        writer.WriteBytes(name);
        writer.WriteBytes(creationHash);

        return owner.Memory.Span[..length].ToArray();
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
}
