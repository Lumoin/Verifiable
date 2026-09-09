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
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

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
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
    /// "If the sign attribute is not SET in the key referenced by handle, then the TPM shall return TPM_RC_KEY"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.5.1): a storage parent's <c>sign</c> (SIGN_ENCRYPT)
    /// attribute is CLEAR, so <c>TPM2_Sign()</c> refuses its handle before the scheme gate — the custody root's
    /// private scalar never serves as a signing oracle, and unlike <c>TPM2_SignDigest()</c> no validation ticket
    /// stands in the way of reaching it.
    /// </summary>
    [TestMethod]
    public async Task SignAgainstAnEccStorageParentHandleReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");

        using CreatePrimaryResponse parent = parentResult.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(parent.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), signResult.ResponseCode,
            "A storage parent's sign attribute is CLEAR; TPM2_Sign() must refuse it with TPM_RC_KEY, not sign with it.");
    }

    /// <summary>
    /// <c>TPM2_Sign()</c>'s key slot (Auth Index 1, Auth Role USER; TPM 2.0 Library Part 3, clause 20.5) is
    /// verified against the signing key's own retained authValue over a plain <c>TPM_RS_PW</c> session: a
    /// DA-protected ECC signing key (<c>TPMA_OBJECT.NO_DA</c> clear) created with a real password signs when the
    /// CORRECT password authorizes it and moves no dictionary-attack counter, while a WRONG password is refused
    /// with the session-index-encoded <c>TPM_RC_AUTH_FAIL</c> (Part 2, clause 6.6.2) and charges
    /// <c>failedTries</c> exactly once (Part 1, clause 16.8.7).
    /// </summary>
    [TestMethod]
    public async Task SignVerifiesTheSigningKeysOwnAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
            "A wrong key password against a DA-protected signing key must charge failedTries exactly once (TPM 2.0 Library Part 1, clause 16.8.7).");
    }

    /// <summary>
    /// Proves TPM 2.0 Library Part 3, clause 5.6, check 7.1: <c>TPM2_Sign()</c>'s key slot (Auth Index 1, Auth
    /// Role USER) refuses ANY authValue-based session against a key whose <c>TPMA_OBJECT.userWithAuth</c> is
    /// CLEAR — including a plain <c>TPM_RS_PW</c> session carrying the key's own CORRECT password — with
    /// <c>TPM_RC_POLICY_FAIL</c> naming keyHandle, session 1 of Table 122, because it is the session's SHAPE that
    /// is inadmissible, not its credential; a
    /// <c>userWithAuth</c>-CLEAR object admits only a policy session for the USER role (TPM 2.0 Library Part 2,
    /// clause 8.3.3). Check 7.1 precedes checks 9/10 in clause 5.6's mandatory order, so the correct password is
    /// never even compared, and the refusal is uncharged: <c>TPM_RC_POLICY_FAIL</c> is not <c>TPM_RC_AUTH_FAIL</c>,
    /// and clause 5.6's closing rule bars a non-<c>AUTH_FAIL</c> error from altering any TPM state, so
    /// <c>failedTries</c> does not move (TPM 2.0 Library Part 1, clause 16.8.7).
    /// </summary>
    [TestMethod]
    public async Task SignWithUserWithAuthClearKeyIsRefusedWithoutComparingThePassword()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), signResult.ResponseCode,
            $"A userWithAuth-CLEAR signing key must refuse a password session at keyHandle, session 1 of Table 122, " +
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
    /// plain <c>TPM_RS_PW</c> session is refused with the identical <c>TPM_RC_POLICY_FAIL</c>, session-encoded to
    /// the same index — never the session-index-encoded <c>TPM_RC_AUTH_FAIL</c> a wrong authValue would otherwise
    /// produce (TPM 2.0 Library
    /// Part 2, clause 6.6.2) — because check 7.1 rejects the session's shape before checks 9/10 (the authValue
    /// compare that would distinguish a wrong password from a correct one) ever run. The key is created without
    /// <c>TPMA_OBJECT.noDA</c>, so had check 7.1 been skipped and the compare reached, a rejected wrong password
    /// would have charged <c>failedTries</c> (TPM 2.0 Library Part 1, clause 16.8.7); it does not.
    /// </summary>
    [TestMethod]
    public async Task SignWithUserWithAuthClearKeyRefusesWrongPasswordWithoutChargingFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), signResult.ResponseCode,
            $"A userWithAuth-CLEAR signing key must refuse a wrong password at the same keyHandle, session 1 of Table 122, " +
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
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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

    /// <summary>
    /// An RSA key's <c>inScheme</c> is gated to the schemes the key's type admits: an ECDSA scheme against an
    /// RSA key fails closed with <c>TPM_RC_SCHEME</c> rather than reaching <see cref="TpmuSignature.Create"/>,
    /// which does not carry an RSA-keyed ECDSA member and would otherwise throw
    /// <see cref="NotSupportedException"/> out of the effect loop (TPM 2.0 Library Part 3, clause 20.5: "If
    /// inScheme is not a valid signing scheme for the type of keyHandle (or TPM_ALG_NULL), then the TPM shall
    /// return TPM_RC_SCHEME"). A NULL <c>inScheme</c> against the same key instead succeeds, resolving to the
    /// model's RSASSA default exactly as a NULL <c>inScheme</c> against an ECC key resolves to ECDSA.
    /// </summary>
    [TestMethod]
    public async Task SignWithASchemeIncompatibleWithAnRsaKeyFailsClosedWhileNullResolvesToRsassa()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Null, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (RSA 2048) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession ecdsaAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput ecdsaInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> ecdsaResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, ecdsaInput, [ecdsaAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        if(ecdsaResult.IsSuccess)
        {
            ecdsaResult.Value.Dispose();
        }

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SCHEME, 1), ecdsaResult.ResponseCode,
            $"An ECDSA inScheme against an RSA key must fail closed with TPM_RC_SCHEME, not escape as an " +
            $"unhandled exception (got '{ecdsaResult.ResponseCode}').");

        using TpmPasswordSession nullAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput nullInput = SignInput.Create(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, pool);
        TpmResult<SignResponse> nullResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, nullInput, [nullAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(nullResult.IsSuccess, $"A NULL inScheme against an RSA key must succeed: '{nullResult.ResponseCode}'.");

        using SignResponse nullResponse = nullResult.Value;
        Assert.AreEqual(
            TpmAlgIdConstants.TPM_ALG_RSASSA, nullResponse.SignatureAlgorithm,
            "A NULL scheme against an RSA key resolves to the model's fixed default, TPM_ALG_RSASSA.");
        Assert.AreNotEqual(
            TpmAlgIdConstants.TPM_ALG_NULL, nullResponse.HashAlgorithm,
            "TPMS_SIGNATURE_RSA.hash must never be TPM_ALG_NULL (Table 212), even when the request's inScheme was NULL.");
    }

    /// <summary>
    /// TPM 2.0 Library Part 3, clause 20.5.1: "The size of digest must match that of the hash algorithm in the
    /// scheme." The digest-width branch of the command's ticket-or-size alternative (taken when no ticket
    /// applies) answers <c>TPM_RC_SIZE</c> for a 20-octet (SHA-1-width) digest presented under a SHA-256 scheme — never
    /// signed with the wrong-width bytes, which both injected backends (<c>RSA.SignHash</c>,
    /// <c>ECDsaSigner.GenerateSignature</c>) would otherwise pad or treat as a big integer without complaint.
    /// Proven on ECDSA, RSASSA and RSAPSS alike, each against an unrestricted key so the ticket branch never
    /// diverts the refusal.
    /// </summary>
    [TestMethod]
    public async Task SignWithAWrongWidthDigestReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] wrongWidthDigest = new byte[20];

        using CreatePrimaryInput eccPrimaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession eccOwnerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> eccPrimaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, eccPrimaryInput, [eccOwnerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(eccPrimaryResult.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{eccPrimaryResult.ResponseCode}'.");
        using CreatePrimaryResponse eccPrimary = eccPrimaryResult.Value;

        using TpmPasswordSession ecdsaAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput ecdsaInput = SignInput.ForEcdsa(eccPrimary.ObjectHandle, wrongWidthDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> ecdsaResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, ecdsaInput, [ecdsaAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        if(ecdsaResult.IsSuccess)
        {
            ecdsaResult.Value.Dispose();
        }

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), ecdsaResult.ResponseCode,
            $"A 20-octet digest under a SHA-256 ECDSA scheme must be refused with TPM_RC_SIZE, not signed (got '{ecdsaResult.ResponseCode}').");

        using CreatePrimaryInput rsaPrimaryInput = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Null, pool, noDa: true);
        using TpmPasswordSession rsaOwnerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> rsaPrimaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, rsaPrimaryInput, [rsaOwnerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rsaPrimaryResult.IsSuccess, $"CreatePrimary (RSA 2048) failed: '{rsaPrimaryResult.ResponseCode}'.");
        using CreatePrimaryResponse rsaPrimary = rsaPrimaryResult.Value;

        using TpmPasswordSession rsaSsaAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput rsaSsaInput = SignInput.ForRsaSsa(rsaPrimary.ObjectHandle, wrongWidthDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> rsaSsaResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, rsaSsaInput, [rsaSsaAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        if(rsaSsaResult.IsSuccess)
        {
            rsaSsaResult.Value.Dispose();
        }

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), rsaSsaResult.ResponseCode,
            $"A 20-octet digest under a SHA-256 RSASSA scheme must be refused with TPM_RC_SIZE (got '{rsaSsaResult.ResponseCode}').");

        using TpmPasswordSession rsaPssAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput rsaPssInput = SignInput.ForRsaPss(rsaPrimary.ObjectHandle, wrongWidthDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> rsaPssResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, rsaPssInput, [rsaPssAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        if(rsaPssResult.IsSuccess)
        {
            rsaPssResult.Value.Dispose();
        }

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), rsaPssResult.ResponseCode,
            $"A 20-octet digest under a SHA-256 RSAPSS scheme must be refused with TPM_RC_SIZE (got '{rsaPssResult.ResponseCode}').");
    }

    /// <summary>
    /// TPM 2.0 Library Part 3, clause 20.5.1: "If keyHandle references a restricted signing key, then validation
    /// shall be provided." <see cref="SignInput"/> always frames the NULL Ticket (TPM 2.0 Library Part 2, clause
    /// 10.6.2), so a restricted signing key presented through the production command path is refused with
    /// <c>TPM_RC_TICKET</c> naming validation, parameter 3 of Table 122, before
    /// <see cref="TpmEccSigningBackend"/> is ever reached.
    /// </summary>
    [TestMethod]
    public async Task SignAgainstARestrictedSigningKeyWithTheNullTicketReturnsTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreateRestrictedEccSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (restricted ECC signing key) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        if(signResult.IsSuccess)
        {
            signResult.Value.Dispose();
        }

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 2), signResult.ResponseCode,
            $"A restricted signing key presented with the NULL ticket must be refused with TPM_RC_TICKET, never signed (got '{signResult.ResponseCode}').");
    }

    /// <summary>
    /// The RSA counterpart of <see cref="SignAgainstARestrictedSigningKeyWithTheNullTicketReturnsTicket"/>: clause
    /// 20.5.1's validation requirement is not ECC-specific — a restricted RSA signing key presented with
    /// <see cref="SignInput"/>'s NULL ticket is likewise refused with <c>TPM_RC_TICKET</c> naming validation,
    /// parameter 3 of Table 122, before <see cref="TpmRsaSigningBackend"/> is ever reached.
    /// </summary>
    [TestMethod]
    public async Task SignAgainstARestrictedRsaSigningKeyWithTheNullTicketReturnsTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreateRestrictedRsaSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (restricted RSA signing key) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForRsaSsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        if(signResult.IsSuccess)
        {
            signResult.Value.Dispose();
        }

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 2), signResult.ResponseCode,
            $"A restricted RSA signing key presented with the NULL ticket must be refused with TPM_RC_TICKET, never signed (got '{signResult.ResponseCode}').");
    }

    /// <summary>
    /// The command's ticket branch, the success arm: a restricted ECC key presented with a VALID
    /// <c>TPMT_TK_HASHCHECK</c> — minted by <c>TPM2_Hash()</c> under <c>TPM_RH_OWNER</c> over the SAME digest —
    /// is re-verified (the ticket's HMAC recomputed over its own hierarchy proof and the digest) and signs; the
    /// signature verifies off-TPM against the key's exported public point.
    /// </summary>
    [TestMethod]
    public async Task SignAgainstARestrictedEccKeyWithAValidHashcheckTicketMintedOverTheSameDigestSucceedsAndVerifiesOffTpm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreateRestrictedEccSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (restricted ECC signing key) failed: '{primaryResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = primaryResult.Value;

        using HashResponse hash = await SubmitHashAsync(tpm, registry, pool, MessageBytes, Sha256, TpmiRhHierarchy.Owner).ConfigureAwait(false);

        using IMemoryOwner<byte> commandOwner = FrameSignCommandWithTicket(
            pool, primary.ObjectHandle.Value, hash.OutHash.AsReadOnlySpan(), hash.Validation.Hierarchy, hash.Validation.Digest, out int length);
        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed ticketed TPM2_Sign() must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(
            (uint)TpmRcConstants.TPM_RC_SUCCESS, responseHeader.Code,
            $"A restricted key with a valid hashcheck ticket over the same digest must sign (got '{(TpmRcConstants)responseHeader.Code}').");

        using SignResponse signature = SignResponse.Parse(ref reader, pool);
        Assert.IsTrue(
            VerifyEcdsaSignatureOffTpm(primary.OutPublic.PublicArea.Unique.Ecc!, hash.OutHash.AsReadOnlySpan().ToArray(), signature.Signature),
            "The restricted key's signature over the ticketed digest must verify off-TPM.");
    }

    /// <summary>
    /// The mismatch counterpart: a ticket minted by <c>TPM2_Hash()</c> over ONE digest presented alongside a
    /// DIFFERENT digest fails the recomputed <c>HMAC(proof, TPM_ST_HASHCHECK || digest)</c> — computed over the
    /// wrong digest, it differs from the ticket's own HMAC — so the restricted key is refused with
    /// <c>TPM_RC_TICKET</c> naming validation, parameter 3 of Table 122, exactly as a caller-forged ticket is.
    /// </summary>
    [TestMethod]
    public async Task SignAgainstARestrictedEccKeyWithATicketMintedOverADifferentDigestReturnsTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreateRestrictedEccSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (restricted ECC signing key) failed: '{primaryResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = primaryResult.Value;

        using HashResponse hash = await SubmitHashAsync(tpm, registry, pool, MessageBytes, Sha256, TpmiRhHierarchy.Owner).ConfigureAwait(false);
        byte[] differentDigest = await ComputeSha256Async("A different message entirely."u8.ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        using IMemoryOwner<byte> commandOwner = FrameSignCommandWithTicket(
            pool, primary.ObjectHandle.Value, differentDigest, hash.Validation.Hierarchy, hash.Validation.Digest, out int length);
        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed ticketed TPM2_Sign() must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        Assert.AreEqual(
            (uint)HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 2), responseHeader.Code,
            $"validation is TPM2_Sign()'s third parameter (Table 122, index 2); a ticket minted over a different digest must fail re-verification with parameter-encoded TPM_RC_TICKET (got '{(TpmRcConstants)responseHeader.Code}').");
    }

    /// <summary>
    /// <c>TPM2_Hash()</c> under <c>TPM_RH_NULL</c> answers the NULL Ticket unconditionally (TPM 2.0 Library Part
    /// 3, clause 15.4.1: "If hierarchy is TPM_RH_NULL, then digest in the ticket will be the Empty Buffer"), so a
    /// caller who deliberately names a hierarchy still receives a ticket a restricted OWNER-hierarchy key cannot
    /// use: the NULL Ticket (Part 2, clause 10.6.2) is refused exactly as an omitted ticket would be.
    /// </summary>
    [TestMethod]
    public async Task SignAgainstARestrictedOwnerHierarchyKeyWithATicketMintedUnderTheNullHierarchyReturnsTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreateRestrictedEccSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (restricted ECC signing key) failed: '{primaryResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = primaryResult.Value;

        using HashResponse hash = await SubmitHashAsync(tpm, registry, pool, MessageBytes, Sha256, TpmiRhHierarchy.Null).ConfigureAwait(false);
        Assert.IsTrue(hash.Validation.IsNull, "TPM2_Hash() under TPM_RH_NULL must answer the NULL ticket, the premise of this test.");

        using IMemoryOwner<byte> commandOwner = FrameSignCommandWithTicket(
            pool, primary.ObjectHandle.Value, hash.OutHash.AsReadOnlySpan(), hash.Validation.Hierarchy, hash.Validation.Digest, out int length);
        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed ticketed TPM2_Sign() must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        Assert.AreEqual(
            (uint)HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 2), responseHeader.Code,
            $"A restricted key presented with the NULL ticket TPM2_Hash(TPM_RH_NULL) minted must be refused with TPM_RC_TICKET (got '{(TpmRcConstants)responseHeader.Code}').");
    }

    /// <summary>
    /// The command's ticket-or-size alternative is mutually exclusive, not two gates in series: a non-empty
    /// validation ticket, or a restricted key, takes the ticket branch, whose re-verification
    /// checks only the HMAC over the presented digest — it never runs the <c>else</c> arm's digest-width compare.
    /// An UNRESTRICTED key with a supplied VALID ticket therefore signs (the ticket branch, not the SIZE gate,
    /// decides), and it signs AGAIN when the ticket was minted over a SHA-512-width digest that does not match
    /// the ECDSA/SHA-256 scheme's width at all — the wrong-width digest never reaches the SIZE check because the
    /// ticket branch was entered first and never falls through to it.
    /// </summary>
    [TestMethod]
    public async Task UnrestrictedKeyWithAValidTicketSignsRegardlessOfDigestWidthSinceTheTicketBranchNeverChecksSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (unrestricted ECC signing key) failed: '{primaryResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = primaryResult.Value;

        using HashResponse correctWidthHash = await SubmitHashAsync(tpm, registry, pool, MessageBytes, Sha256, TpmiRhHierarchy.Owner).ConfigureAwait(false);
        using IMemoryOwner<byte> correctWidthCommand = FrameSignCommandWithTicket(
            pool, primary.ObjectHandle.Value, correctWidthHash.OutHash.AsReadOnlySpan(), correctWidthHash.Validation.Hierarchy,
            correctWidthHash.Validation.Digest, out int correctWidthLength);
        TpmResult<TpmResponse> correctWidthSubmit = await simulator.SubmitAsync(correctWidthCommand.Memory[..correctWidthLength], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(correctWidthSubmit.IsSuccess, "The hand-framed ticketed TPM2_Sign() must reach the simulator.");
        using(TpmResponse correctWidthResponse = correctWidthSubmit.Value)
        {
            var correctWidthReader = new TpmReader(correctWidthResponse.AsReadOnlySpan());
            TpmHeader correctWidthHeader = TpmHeader.Parse(ref correctWidthReader);
            Assert.AreEqual(
                (uint)TpmRcConstants.TPM_RC_SUCCESS, correctWidthHeader.Code,
                $"An unrestricted key with a valid ticket over a correct-width digest must sign (got '{(TpmRcConstants)correctWidthHeader.Code}').");
        }

        using HashResponse wrongWidthHash = await SubmitHashAsync(tpm, registry, pool, MessageBytes, Sha512, TpmiRhHierarchy.Owner).ConfigureAwait(false);
        Assert.AreEqual(64, wrongWidthHash.OutHash.Size, "SHA-512 must produce a 64-octet digest, the wrong width for the SHA-256 ECDSA scheme.");

        using IMemoryOwner<byte> wrongWidthCommand = FrameSignCommandWithTicket(
            pool, primary.ObjectHandle.Value, wrongWidthHash.OutHash.AsReadOnlySpan(), wrongWidthHash.Validation.Hierarchy,
            wrongWidthHash.Validation.Digest, out int wrongWidthLength);
        TpmResult<TpmResponse> wrongWidthSubmit = await simulator.SubmitAsync(wrongWidthCommand.Memory[..wrongWidthLength], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(wrongWidthSubmit.IsSuccess, "The hand-framed ticketed TPM2_Sign() must reach the simulator.");
        using TpmResponse wrongWidthResponse = wrongWidthSubmit.Value;
        var wrongWidthReader = new TpmReader(wrongWidthResponse.AsReadOnlySpan());
        TpmHeader wrongWidthHeader = TpmHeader.Parse(ref wrongWidthReader);
        Assert.AreEqual(
            (uint)TpmRcConstants.TPM_RC_SUCCESS, wrongWidthHeader.Code,
            $"A valid ticket over a wrong-width (SHA-512) digest must still sign — the ticket branch, entered because a ticket was supplied, never runs the SIZE check (got '{(TpmRcConstants)wrongWidthHeader.Code}').");
    }

    /// <summary>
    /// <c>TPM2_Sign()</c>'s over-session form runs the SAME command rules its password form does, after
    /// authorization: a 20-octet (SHA-1-width) digest under a SHA-256 ECDSA scheme is refused with the same
    /// unmodified <c>TPM_RC_SIZE</c> base error naming digest, parameter 1 of Table 122, whether the key slot is
    /// authorized by <c>TPM_RS_PW</c> or by a real HMAC session (TPM 2.0 Library Part 3, clause 20.5.1; clause 5.6
    /// precedes clause 5.7 precedes clause 5.8).
    /// </summary>
    [TestMethod]
    public async Task SignOverAnHmacSessionWithAWrongWidthDigestReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{primaryResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = primaryResult.Value;

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            byte[] wrongWidthDigest = new byte[20];
            using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, wrongWidthDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [primary.Name.Span.ToArray()];

            TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(signResult.IsSuccess)
            {
                signResult.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SIZE, signResult.BaseError,
                $"A 20-octet digest under a SHA-256 ECDSA scheme over an HMAC session must carry the TPM_RC_SIZE base error, exactly as the password form does (got '{signResult.ResponseCode}').");
        }
        finally
        {
            session.Dispose();
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A pool-metered pass over three <c>TPM2_Sign()</c> outcomes — a SIZE refusal, a TICKET refusal, and a
    /// ticket-branch SUCCESS — each releases every carrier its own path rented, the retained validation digest
    /// included: the pool balance returns to its pre-command baseline after every one.
    /// </summary>
    [TestMethod]
    public async Task SignPoolBalanceIsFlatAcrossASizeRefusalATicketRefusalAndATicketSuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput unrestrictedInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession unrestrictedOwnerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> unrestrictedResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, unrestrictedInput, [unrestrictedOwnerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(unrestrictedResult.IsSuccess, $"CreatePrimary (unrestricted ECC signing key) failed: '{unrestrictedResult.ResponseCode}'.");
        using CreatePrimaryResponse unrestricted = unrestrictedResult.Value;

        using CreatePrimaryInput restrictedInput = CreateRestrictedEccSigningKeyInput(pool);
        using TpmPasswordSession restrictedOwnerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> restrictedResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, restrictedInput, [restrictedOwnerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(restrictedResult.IsSuccess, $"CreatePrimary (restricted ECC signing key) failed: '{restrictedResult.ResponseCode}'.");
        using CreatePrimaryResponse restricted = restrictedResult.Value;

        long baseline = trackingPool.OutstandingCount;

        using(TpmPasswordSession sizeAuth = TpmPasswordSession.CreateEmpty(pool))
        using(SignInput sizeInput = SignInput.ForEcdsa(unrestricted.ObjectHandle, new byte[20], TpmAlgIdConstants.TPM_ALG_SHA256, pool))
        {
            TpmResult<SignResponse> sizeResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, sizeInput, [sizeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(sizeResult.IsSuccess)
            {
                sizeResult.Value.Dispose();
            }
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), sizeResult.ResponseCode, "The seeding SIZE case must actually refuse with TPM_RC_SIZE.");
        }
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A SIZE refusal must leave the pool at its pre-command baseline.");

        byte[] messageDigest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using(TpmPasswordSession ticketAuth = TpmPasswordSession.CreateEmpty(pool))
        using(SignInput ticketRefusalInput = SignInput.ForEcdsa(restricted.ObjectHandle, messageDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool))
        {
            TpmResult<SignResponse> ticketRefusalResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, ticketRefusalInput, [ticketAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(ticketRefusalResult.IsSuccess)
            {
                ticketRefusalResult.Value.Dispose();
            }
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 2), ticketRefusalResult.ResponseCode, "The seeding TICKET case must actually refuse with TPM_RC_TICKET.");
        }
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A TICKET refusal must leave the pool at its pre-command baseline.");

        using(HashResponse hash = await SubmitHashAsync(tpm, registry, pool, MessageBytes, Sha256, TpmiRhHierarchy.Owner).ConfigureAwait(false))
        using(IMemoryOwner<byte> ticketSuccessCommand = FrameSignCommandWithTicket(
            pool, restricted.ObjectHandle.Value, hash.OutHash.AsReadOnlySpan(), hash.Validation.Hierarchy, hash.Validation.Digest, out int ticketSuccessLength))
        {
            TpmResult<TpmResponse> ticketSuccessSubmit = await simulator.SubmitAsync(ticketSuccessCommand.Memory[..ticketSuccessLength], pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(ticketSuccessSubmit.IsSuccess, "The hand-framed ticketed TPM2_Sign() must reach the simulator.");
            using TpmResponse ticketSuccessResponse = ticketSuccessSubmit.Value;
            var ticketSuccessReader = new TpmReader(ticketSuccessResponse.AsReadOnlySpan());
            TpmHeader ticketSuccessHeader = TpmHeader.Parse(ref ticketSuccessReader);
            Assert.AreEqual(
                (uint)TpmRcConstants.TPM_RC_SUCCESS, ticketSuccessHeader.Code,
                $"The seeding ticket-success case must actually succeed (got '{(TpmRcConstants)ticketSuccessHeader.Code}').");
            using SignResponse ticketSuccessSignature = SignResponse.Parse(ref ticketSuccessReader, pool);
            ticketSuccessSignature.Dispose();
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A ticket-branch SUCCESS must release the retained validation digest and every other rented carrier: the pool returns to baseline.");
    }

    /// <summary>
    /// Issues <c>TPM2_Hash()</c> through the production executor and returns the response — the caller owns it.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry, already carrying the TPM2_Hash codec.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="data">The data to hash.</param>
    /// <param name="hashAlg">The hash algorithm.</param>
    /// <param name="hierarchy">The ticket hierarchy.</param>
    /// <returns>The response; the caller disposes it.</returns>
    private async Task<HashResponse> SubmitHashAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, byte[] data, TpmiAlgHash hashAlg, TpmiRhHierarchy hierarchy)
    {
        using HashInput input = HashInput.Create(data, hashAlg, hierarchy, pool);
        TpmResult<HashResponse> result = await TpmCommandExecutor.ExecuteAsync<HashResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_Hash() failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Starts an unbound, unsalted HMAC session negotiating no symmetric algorithm, with <c>continueSession</c> SET.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle and the host session; the caller disposes the session and flushes the handle.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartUnboundHmacSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants.TPM_ALG_SHA256, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound, unsalted HMAC) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, TpmAlgIdConstants.TPM_ALG_SHA256, TestEntropy.NewCounterStream(), pool)
        {
            SessionAttributes = TpmaSession.CONTINUE_SESSION
        };

        return (started.SessionHandle.Value, session);
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_Sign()</c> command over ECDSA/SHA-256 whose <c>validation</c> ticket carries a
    /// caller-supplied hierarchy and digest — <see cref="SignInput"/> always frames the NULL ticket, so a real
    /// ticket needs its own wire recipe, mirroring <see cref="FrameSignCommand"/>'s password-authorized shape
    /// exactly except for this one field.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle value.</param>
    /// <param name="digest">The <c>digest</c> parameter's octets.</param>
    /// <param name="ticketHierarchy">The validation ticket's <c>hierarchy</c> field.</param>
    /// <param name="ticketDigest">The validation ticket's HMAC octets.</param>
    /// <param name="length">The framed command's total length.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameSignCommandWithTicket(
        BaseMemoryPool pool, uint keyHandle, ReadOnlySpan<byte> digest, TpmiRhHierarchy ticketHierarchy, ReadOnlySpan<byte> ticketDigest, out int length)
    {
        const int PasswordSlotSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        const int SchemeBodySize = 2 * sizeof(ushort);
        int ticketSize = sizeof(ushort) + sizeof(uint) + sizeof(ushort) + ticketDigest.Length;

        length =
            TpmHeader.HeaderSize
            + sizeof(uint)
            + sizeof(uint) + PasswordSlotSize
            + sizeof(ushort) + digest.Length
            + SchemeBodySize
            + ticketSize;

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_Sign);
            header.WriteTo(ref writer);
            writer.WriteUInt32(keyHandle);
            writer.WriteUInt32((uint)PasswordSlotSize);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteTpm2b(digest);
            writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_ECDSA);
            writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_SHA256);

            writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_HASHCHECK);
            writer.WriteUInt32(ticketHierarchy.Value);
            writer.WriteTpm2b(ticketDigest);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Composes a restricted RSA signing key template — <c>TPMA_OBJECT.restricted</c> SET alongside <c>sign</c>
    /// — mirroring <c>TpmInHouseSimulatorSignDigestTests.CreateRestrictedRsaSigningKeyInput</c>'s own local copy
    /// of the same template for this file's own tests.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the returned CreatePrimaryInput, whose Dispose releases them.")]
    private static CreatePrimaryInput CreateRestrictedRsaSigningKeyInput(BaseMemoryPool pool)
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

        Tpm2bPublic inPublic = Tpm2bPublic.CreateRsaSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            attributes,
            Rsa2048KeyBits,
            TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256));

        return new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
    }

    /// <summary>
    /// Verifies a P-256 ECDSA signature off-TPM against a public key reconstructed solely from the exported
    /// public point — sharing no code path with the signer.
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

    /// <summary>The SHA-256 hash algorithm selector for <c>TPM2_Hash()</c>.</summary>
    private static TpmiAlgHash Sha256 => TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256);

    /// <summary>The SHA-512 hash algorithm selector for <c>TPM2_Hash()</c> — the wrong-width digest source.</summary>
    private static TpmiAlgHash Sha512 => TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA512);

    /// <summary>
    /// Composes a restricted ECC signing key template — <c>TPMA_OBJECT.restricted</c> SET alongside <c>sign</c>
    /// — since no production factory builds a restricted signing key, mirroring
    /// <c>TpmInHouseSimulatorSignDigestTests.CreateRestrictedEccSigningKeyInput</c>'s own local copy of the
    /// same template for this file's own tests.
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

    [TestMethod]
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "The PrivateKey takes ownership of the handle memory and is disposed by its using declaration.")]
    public async Task TpmBackedPrivateKeySignsAndVerifiesThroughTheVerifiableAbstraction()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
            TpmCryptographicFunctionsAdapter.SignAsync,
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
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;

        //The object Name is nameAlg || H_nameAlg(TPMT_PUBLIC) (TPM 2.0 Library Part 1, clause 13, Table 9). Recompute the digest
        //independently from the exported public area and confirm the response carries the real Name.
        byte[] marshaledPublic = MarshalPublicArea(primary.OutPublic, pool);
        byte[] expectedNameDigest = await ComputeSha256Async(marshaledPublic, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual((ushort)TpmAlgIdConstants.TPM_ALG_SHA256, primary.Name.NameAlgorithm, "The Name must carry the SHA-256 name algorithm.");
        Assert.IsTrue(expectedNameDigest.AsSpan().SequenceEqual(primary.Name.Digest), "The Name digest must be H(TPMT_PUBLIC).");

        //creationHash is H_nameAlg(creationData) (TPM 2.0 Library Part 2, clause 15.1). Recompute it from the exported
        //creationData bytes.
        byte[] expectedCreationHash = await ComputeSha256Async(primary.CreationData.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(expectedCreationHash.AsSpan().SequenceEqual(primary.CreationHash.AsReadOnlySpan()), "creationHash must be H(creationData).");

        //creationData for a primary under the owner hierarchy: a NULL parentNameAlg and the owner handle as the
        //parent Name and Qualified Name (TPM 2.0 Library Part 2, clause 15.1).
        TpmsCreationData creationData = primary.CreationData.CreationData;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_NULL, creationData.ParentNameAlg, "A primary's parentNameAlg is TPM_ALG_NULL.");
        Assert.AreEqual((uint)TpmRh.TPM_RH_OWNER, creationData.ParentName.Handle, "parentName is the owner-hierarchy handle.");
        Assert.AreEqual((uint)TpmRh.TPM_RH_OWNER, creationData.ParentQualifiedName.Handle, "parentQualifiedName is the owner-hierarchy handle.");

        //The creation ticket is a real HMAC bound to the owner hierarchy (TPM 2.0 Library Part 2, clause 10.6),
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

        using var simulator = new TpmSimulator("tpm-in-house-seed", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), seed: seed, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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

    /// <summary>
    /// <c>TPM2_Sign()</c>'s <c>keyHandle</c> is its sole handle (index 0); a transient-range value that resolves
    /// to no loaded object answers <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0 Library Part 3, clause 5.4, step 2.1).
    /// </summary>
    [TestMethod]
    public async Task SignWithUnknownKeyHandleAnswersReferenceH0()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(
            TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase), digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, signResult.ResponseCode, "An unloaded transient keyHandle at index 0 answers TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1).");
    }

    /// <summary>
    /// <c>inScheme</c>'s leading <c>+</c> admits <c>TPM_ALG_NULL</c> (<c>isNullAdmitted: true</c>, unlike
    /// <c>TPM2_VerifySignature()</c>'s/<c>TPM2_PolicySigned()</c>'s signature) — it means "use the key's default
    /// scheme": this simulator's ECC signing effect ignores the scheme selector entirely and always signs ECDSA,
    /// so a NULL <c>inScheme</c> against an ECC key still succeeds (TPM 2.0 Library Part 2, clause 11.2.1.5,
    /// Table 183). The response's <c>TPMS_SIGNATURE_ECC.hash</c> must still be a genuine hash algorithm, never
    /// <c>TPM_ALG_NULL</c> (clause 11.3.2, Table 214: "<c>TPM_ALG_NULL</c> is not allowed"), so a NULL scheme
    /// hash resolves to <c>TPM_ALG_SHA256</c> — the fixed default this model substitutes in place of a per-key
    /// default scheme it does not retain. Hand-framed, bypassing <see cref="TpmCommandExecutor"/>: the true
    /// Table 183 wire shape for a NULL scheme is two octets with no trailing detail pair at all.
    /// </summary>
    [TestMethod]
    public async Task SignWithNullInSchemeAgainstAnEccKeySucceedsUnderTheKeysDefaultEcdsaBehavior()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] nullInScheme = BuildInSchemeBody(TpmAlgIdConstants.TPM_ALG_NULL, includeHashAlg: false);
        (TpmRcConstants code, TpmAlgIdConstants? hashAlgorithm) = await SubmitSignCommandForHashAlgAsync(
            simulator, pool, primary.ObjectHandle.Value, digest, nullInScheme).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, code,
            "A NULL inScheme against an ECC key must still succeed: the ECC signing effect ignores the scheme selector and always signs ECDSA.");
        Assert.AreNotEqual(
            TpmAlgIdConstants.TPM_ALG_NULL, hashAlgorithm,
            "TPMS_SIGNATURE_ECC.hash must never be TPM_ALG_NULL (Table 214), even when the request's inScheme was NULL.");
        Assert.AreEqual(
            TpmAlgIdConstants.TPM_ALG_SHA256, hashAlgorithm,
            "A NULL scheme hash resolves to the model's fixed default, TPM_ALG_SHA256.");
    }

    /// <summary>
    /// <see cref="SignInput"/> frames a NULL <c>inScheme</c> as the true Table 183 two-octet shape (the scheme
    /// selector alone, no trailing <c>hashAlg</c> detail pair), so a NULL-scheme <c>TPM2_Sign()</c> issued
    /// through the shipped public command path — not hand-framed — still succeeds against an ECC key (TPM 2.0
    /// Library Part 2, clause 11.2.1.5, Table 183).
    /// </summary>
    [TestMethod]
    public async Task SignInputWithNullSchemeAgainstAnEccKeySucceedsThroughTheProductionCommandPath()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.Create(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, pool);

        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(signResult.IsSuccess, $"Sign with a NULL inScheme via SignInput must succeed: '{signResult.ResponseCode}'.");

        using SignResponse signResponse = signResult.Value;
        Assert.AreNotEqual(
            TpmAlgIdConstants.TPM_ALG_NULL, signResponse.HashAlgorithm,
            "TPMS_SIGNATURE_ECC.hash must never be TPM_ALG_NULL (Table 214), even when SignInput's own SignatureScheme was NULL.");
    }

    /// <summary>
    /// An <c>inScheme.scheme</c> naming an algorithm that is not an admitted signing scheme at all (a hash
    /// algorithm ID) is refused with <c>TPM_RC_SCHEME</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.2.1.5, Table 183; clause 9.37, Table 83). Hand-framed
    /// with an arbitrary key handle: the refusal fires in the parser, before <c>keyHandle</c> ever resolves.
    /// </summary>
    [TestMethod]
    public async Task SignWithUnsupportedInSchemeAlgorithmReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] digest = new byte[P256ComponentSize];
        byte[] body = BuildInSchemeBody(TpmAlgIdConstants.TPM_ALG_SHA256, includeHashAlg: true, hashAlg: TpmAlgIdConstants.TPM_ALG_SHA256);

        TpmRcConstants code = await SubmitSignCommandAsync(simulator, pool, TpmSimulatorState.TransientHandleBase, digest, body).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SCHEME, 1), code,
            "Table 122: inScheme is TPM2_Sign()'s second parameter (index 1); a scheme naming no signing scheme at all must be refused with TPM_RC_SCHEME there (Table 183).");
    }

    [TestMethod]
    public async Task CreatePrimaryWithoutSigningBackendReturnsCommandCode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //A simulator with no signing backend does not implement key creation: it answers TPM_RC_COMMAND_CODE.
        using var simulator = new TpmSimulator("tpm-in-house-no-backend", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
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
        _ = registry.Register(TpmCcConstants.TPM_CC_Hash, TpmResponseCodec.Hash);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

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
    /// Hand-frames a <c>TPM2_Sign()</c> command whose <c>inScheme</c> body is supplied verbatim, bypassing
    /// <see cref="TpmCommandExecutor"/> and <see cref="SignInput"/> entirely — letting a caller submit an
    /// arbitrary, possibly non-Table-180-shaped <c>inScheme</c> directly against the simulator (for example an
    /// unadmitted scheme selector) without going through <see cref="SignInput"/>'s own admitted-shape framing. A
    /// single empty <c>TPM_RS_PW</c> password slot authorizes <c>@keyHandle</c>; a NULL <c>validation</c> ticket
    /// follows <c>inScheme</c>, mirroring <see cref="SignInput.WriteParameters"/>'s own NULL-ticket convention.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle value.</param>
    /// <param name="digest">The <c>digest</c> parameter's octets.</param>
    /// <param name="inSchemeBody">The already-marshaled <c>TPMT_SIG_SCHEME</c> body, verbatim.</param>
    /// <param name="length">The framed command's total length.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameSignCommand(
        BaseMemoryPool pool, uint keyHandle, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> inSchemeBody, out int length)
    {
        const int PasswordSlotSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        const int NullValidationTicketSize = sizeof(ushort) + sizeof(uint) + sizeof(ushort);

        length =
            TpmHeader.HeaderSize
            + sizeof(uint)                              //Handle area: @keyHandle.
            + sizeof(uint) + PasswordSlotSize            //authorizationSize + one TPM_RS_PW slot.
            + sizeof(ushort) + digest.Length             //TPM2B_DIGEST.
            + inSchemeBody.Length
            + NullValidationTicketSize;

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_Sign);
            header.WriteTo(ref writer);
            writer.WriteUInt32(keyHandle);
            writer.WriteUInt32((uint)PasswordSlotSize);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteTpm2b(digest);
            writer.WriteBytes(inSchemeBody);

            //NULL ticket: tag = TPM_ST_HASHCHECK, hierarchy = TPM_RH_NULL, digest size = 0 (SignInput.WriteParameters's own convention).
            writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_HASHCHECK);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_NULL);
            writer.WriteUInt16(0);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_Sign()</c> built by <see cref="FrameSignCommand"/> straight to the simulator
    /// (bypassing <see cref="TpmCommandExecutor"/>) and yields the response code.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle value.</param>
    /// <param name="digest">The <c>digest</c> parameter's octets.</param>
    /// <param name="inSchemeBody">The already-marshaled <c>TPMT_SIG_SCHEME</c> body, verbatim.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSignCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint keyHandle, byte[] digest, byte[] inSchemeBody)
    {
        using IMemoryOwner<byte> commandOwner = FrameSignCommand(pool, keyHandle, digest, inSchemeBody, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// The counterpart of <see cref="SubmitSignCommandAsync"/> that also parses a successful response's
    /// <c>TPMT_SIGNATURE</c> to expose the hash algorithm it frames, so a caller can inspect
    /// <c>TPMS_SIGNATURE_ECC.hash</c> directly rather than trusting the response code alone.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle value.</param>
    /// <param name="digest">The <c>digest</c> parameter's octets.</param>
    /// <param name="inSchemeBody">The already-marshaled <c>TPMT_SIG_SCHEME</c> body, verbatim.</param>
    /// <returns>The response code, and the framed signature's hash algorithm on success (<see langword="null"/> otherwise).</returns>
    private async Task<(TpmRcConstants Code, TpmAlgIdConstants? HashAlgorithm)> SubmitSignCommandForHashAlgAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint keyHandle, byte[] digest, byte[] inSchemeBody)
    {
        using IMemoryOwner<byte> commandOwner = FrameSignCommand(pool, keyHandle, digest, inSchemeBody, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        var code = (TpmRcConstants)responseHeader.Code;
        if(code != TpmRcConstants.TPM_RC_SUCCESS)
        {
            return (code, null);
        }

        using SignResponse signResponse = SignResponse.Parse(ref reader, pool);

        return (code, signResponse.HashAlgorithm);
    }

    /// <summary>
    /// Builds a <c>TPMT_SIG_SCHEME</c> body: the <c>scheme</c> selector, followed by a hash-only
    /// <c>TPMU_SIG_SCHEME</c> detail pair when <paramref name="includeHashAlg"/> is <see langword="true"/> — the
    /// true Table 183 wire shape omits the detail entirely for <c>TPM_ALG_NULL</c>.
    /// </summary>
    /// <param name="scheme">The scheme selector to write.</param>
    /// <param name="includeHashAlg">Whether to also write a hash-only detail pair.</param>
    /// <param name="hashAlg">The hash algorithm to write when <paramref name="includeHashAlg"/> is <see langword="true"/>.</param>
    /// <returns>The marshaled body.</returns>
    private static byte[] BuildInSchemeBody(TpmAlgIdConstants scheme, bool includeHashAlg, TpmAlgIdConstants hashAlg = TpmAlgIdConstants.TPM_ALG_SHA256)
    {
        byte[] body = new byte[includeHashAlg ? 2 * sizeof(ushort) : sizeof(ushort)];
        var writer = new TpmWriter(body);
        writer.WriteUInt16((ushort)scheme);
        if(includeHashAlg)
        {
            writer.WriteUInt16((ushort)hashAlg);
        }

        return body;
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
