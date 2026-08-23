using System;
using System.Buffers;
using System.Buffers.Binary;
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
/// Drives <c>TPM2_Certify()</c> (object attestation) against the in-house behavioural <see cref="TpmSimulator"/> —
/// entirely in-process, with no external assets — through the same production command path the production code
/// uses (<see cref="TpmCommandExecutor"/> with the real <see cref="CreatePrimaryInput"/>, <see cref="CertifyInput"/>,
/// and response codecs): <c>TPM2_CreatePrimary()</c> mints a subject signing key under the owner hierarchy and a
/// separate attestation key (AK) under the endorsement hierarchy, then the AK certifies the subject over a caller
/// nonce.
/// </summary>
/// <remarks>
/// <para>
/// The result is verified <b>off-TPM</b> from wire bytes only: the magic / type / nonce fields, that the attested
/// Name equals the subject's Name recomputed independently from its exported public area
/// (<c>nameAlg ‖ H(TPMT_PUBLIC)</c>), and the ECDSA signature over the raw attestation bytes against the AK's
/// exported public key reconstructed from <c>outPublic</c> alone. The verifier shares no in-memory state with the
/// signer beyond the wire bytes, so a divergence between what the simulator framed and what a genuine TPM would
/// attest and sign fails here. Distinct hierarchy seeds give the subject and the AK genuinely distinct keys, so
/// this is a real cross-key certification rather than a self-certify.
/// </para>
/// <para>
/// <c>TPM2_Certify()</c> authorizes two handles — the certified object and the signing key — so the executor
/// receives two authorization sessions in handle order; both are empty-auth password sessions (an attestation
/// carries no secret, so no HMAC/encrypt session is needed). The signing backend is injected so the production
/// <c>Verifiable.Tpm</c> assembly stays provider-agnostic.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorCertifyTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus size in bits used by the RSA certify tests.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The fixed caller nonce (qualifyingData) echoed into the attestation's extraData.</summary>
    private static byte[] Nonce { get; } = "Certify nonce for the in-house TPM."u8.ToArray();

    /// <summary>The real password the certified-object authValue verification proof creates the subject with.</summary>
    private const string CertifiedObjectPassword = "certify-certified-object-auth";

    /// <summary>
    /// The certified object's authValue in wire form — the UTF-8 octets of <see cref="CertifiedObjectPassword"/>,
    /// matching the password-to-authValue convention <see cref="Tpm2bAuth.CreateFromPassword"/> applies on the
    /// creation side (the password carries no trailing zeros, so no trimming is in play).
    /// </summary>
    private static byte[] CertifiedObjectAuth { get; } = System.Text.Encoding.UTF8.GetBytes(CertifiedObjectPassword);

    /// <summary>A wrong guess at the certified object's password, distinct from <see cref="CertifiedObjectAuth"/>.</summary>
    private static byte[] WrongCertifiedObjectAuth { get; } = [0xC5, 0xC6, 0xC7, 0xC8];

    /// <summary>The real password the signing-key authValue verification proof creates the AK with.</summary>
    private const string SigningKeyPassword = "certify-signing-key-auth";

    /// <summary>
    /// The signing key's authValue in wire form — the UTF-8 octets of <see cref="SigningKeyPassword"/>, matching
    /// the password-to-authValue convention <see cref="Tpm2bAuth.CreateFromPassword"/> applies on the creation
    /// side (the password carries no trailing zeros, so no trimming is in play).
    /// </summary>
    private static byte[] SigningKeyAuth { get; } = System.Text.Encoding.UTF8.GetBytes(SigningKeyPassword);

    /// <summary>A wrong guess at the signing key's password, distinct from <see cref="SigningKeyAuth"/>.</summary>
    private static byte[] WrongSigningKeyAuth { get; } = [0xD5, 0xD6, 0xD7, 0xD8];

    /// <summary>The hash algorithm for every HMAC-arm session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// The Name algorithm of the ECC decrypt key a salted session's <c>tpmKey</c> is created with — independent
    /// of <see cref="HmacSessionAlg"/> (TPM 2.0 Library Part 1, Annex C.6.1).
    /// </summary>
    private const TpmAlgIdConstants TpmKeyNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// An HMAC-session-range handle this file never starts through <c>TPM2_StartAuthSession()</c> — the fixture
    /// for the session-not-loaded regression.
    /// </summary>
    private const uint UnloadedSessionHandle = 0x0200_FFFE;

    /// <summary>The SHA-256 digest width, in octets — the size of the placeholder nonceTPM the unloaded-session-handle regression constructs.</summary>
    private const int HmacSessionDigestSize = 32;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task EcdsaP256CertifyVerifiesAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //The subject (certified) key under the owner hierarchy and the AK (signer) under the endorsement
        //hierarchy: distinct hierarchy seeds give genuinely distinct keys, so this is a real cross-key
        //certification rather than a self-certify.
        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        //Certify the subject with the AK. objectHandle auth first, signHandle auth second; both empty-auth
        //password sessions (an attestation carries no secret, so no HMAC/encrypt session).
        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput certifyInput = CertifyInput.ForEcdsa(
            subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyResponse> certifyResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(certifyResult.IsSuccess, $"TPM2_Certify failed: '{certifyResult.ResponseCode}'.");

        using CertifyResponse certify = certifyResult.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, certify.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, certify.HashAlgorithm);

        //1. Attestation envelope: TPM-generated marker, certify type, and the nonce echoed verbatim.
        TpmsAttest attest = certify.CertifyInfo.AttestationData;
        Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attest.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_CERTIFY, attest.Type);
        Assert.IsTrue(attest.ExtraData.Span.SequenceEqual(Nonce), "extraData must echo the caller's qualifyingData nonce.");
        Assert.IsNotNull(attest.Attested.Certify);

        //2. Name binding: the attested Name must equal the subject's Name recomputed independently from its
        //exported public area (nameAlg || H(TPMT_PUBLIC)) — firewalled, not taken from the simulator's own
        //CreatePrimary name field.
        byte[] expectedName = await ComputeObjectNameAsync(subject.OutPublic, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.Attested.Certify!.Name.Span.SequenceEqual(expectedName),
            "The certified Name must equal the subject's Name recomputed from its exported public area.");

        //Cross-check: the recomputation matches the Name the simulator returned for the subject at creation.
        Assert.IsTrue(expectedName.AsSpan().SequenceEqual(subject.Name.Span),
            "The independently recomputed Name must match the simulator-reported subject Name.");

        //2b. Qualified Name realism: qualifiedSigner and attested.certify.qualifiedName must equal the
        //independent off-TPM recomputation nameAlg || H(hierarchyHandle || Name) — and must NOT equal the plain
        //Name (the regression a Name/QN collapse would otherwise pass).
        byte[] expectedSignerQn = await ComputeQualifiedNameAsync(
            (uint)TpmRh.TPM_RH_ENDORSEMENT, ak.Name.Span.ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.QualifiedSigner.Span.SequenceEqual(expectedSignerQn),
            "qualifiedSigner must equal the AK's independently recomputed Qualified Name.");
        Assert.IsFalse(
            attest.QualifiedSigner.Span.SequenceEqual(ak.Name.Span),
            "qualifiedSigner must not collapse to the AK's plain Name.");

        byte[] expectedSubjectQn = await ComputeQualifiedNameAsync(
            (uint)TpmRh.TPM_RH_OWNER, subject.Name.Span.ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.Attested.Certify!.QualifiedName.Span.SequenceEqual(expectedSubjectQn),
            "attested.certify.qualifiedName must equal the subject's independently recomputed Qualified Name.");
        Assert.IsFalse(
            attest.Attested.Certify!.QualifiedName.Span.SequenceEqual(subject.Name.Span),
            "attested.certify.qualifiedName must not collapse to the subject's plain Name.");

        //3. Signature: over the RAW attestation bytes, against the AK public key reconstructed from the
        //simulator's exported public area only.
        byte[] attestDigest = await ComputeSha256Async(certify.CertifyInfo.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        //Independent-oracle site: framework ECDsa reconstructs the AK's public key from wire-exported outPublic
        //and verifies the signature against it, a self-consistency firewall proving the library's signature
        //against .NET's independent ECDSA implementation rather than minting fixture key material.
        TpmsEccPoint akPoint = ak.OutPublic.PublicArea.Unique.Ecc!;
        var ecParameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = ToFixed(akPoint.X.AsReadOnlySpan(), P256ComponentSize),
                Y = ToFixed(akPoint.Y.AsReadOnlySpan(), P256ComponentSize)
            }
        };

        //.NET's VerifyHash expects the raw IEEE P1363 r || s concatenation, each component fixed-width.
        byte[] p1363Signature = new byte[2 * P256ComponentSize];
        ToFixed(certify.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(certify.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        using ECDsa ecdsa = ECDsa.Create(ecParameters);
        Assert.IsTrue(
            ecdsa.VerifyHash(attestDigest, p1363Signature),
            "The certify signature must verify over the raw attestation bytes against the AK's exported public key.");
    }

    [TestMethod]
    public async Task CertifyWithUnknownObjectHandleReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //No object was created, so the certified transient handle does not resolve (TPM 2.0 Part 3, clause 18.2).
        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput certifyInput = CertifyInput.ForEcdsa(
            TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase),
            TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase + 1),
            Nonce,
            TpmAlgIdConstants.TPM_ALG_SHA256,
            pool);

        TpmResult<CertifyResponse> certifyResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, certifyResult.ResponseCode);
    }

    [TestMethod]
    public async Task CertifyWithUnknownSignKeyReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //A real, loaded subject but no loaded signing key, so the signHandle does not resolve (Part 3, clause 18.2).
        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput certifyInput = CertifyInput.ForEcdsa(
            subject.ObjectHandle,
            TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase + 0x100u),
            Nonce,
            TpmAlgIdConstants.TPM_ALG_SHA256,
            pool);

        TpmResult<CertifyResponse> certifyResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, certifyResult.ResponseCode);
    }

    [TestMethod]
    public async Task RsaCertifyVerifiesAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //The subject (certified) key under the owner hierarchy and the RSA AK (signer) under the endorsement
        //hierarchy: distinct hierarchy seeds give genuinely distinct keys, so this is a real cross-key
        //certification rather than a self-certify.
        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        var rsaParameters = new RSAParameters
        {
            Modulus = ak.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
            Exponent = [0x01, 0x00, 0x01]
        };

        await CertifyAndVerifyRsaAsync(tpm, registry, pool, subject, ak, rsaParameters, usePss: false).ConfigureAwait(false);
        await CertifyAndVerifyRsaAsync(tpm, registry, pool, subject, ak, rsaParameters, usePss: true).ConfigureAwait(false);
    }

    [TestMethod]
    public async Task CertifyWithSchemeMismatchedToSignerKeyTypeReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //An ECC signing key certified with an RSA scheme (RSASSA) is a genuine scheme/key-type mismatch, distinct
        //from an unresolved handle (TPM 2.0 Library Part 3, clause 18.2).
        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput certifyInput = CertifyInput.ForRsaSsa(
            subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyResponse> certifyResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, certifyResult.ResponseCode);
    }

    /// <summary>
    /// Verifies that a storage parent (RESTRICTED|DECRYPT, no SIGN_ENCRYPT) as the certify's signHandle is
    /// rejected with <c>TPM_RC_KEY</c>: "If the sign attribute is not SET in the key referenced by signHandle then
    /// the TPM shall return TPM_RC_KEY" (TPM 2.0 Library Part 3, clause 18.1).
    /// </summary>
    [TestMethod]
    public async Task CertifyWithNonSigningKeyReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput certifyInput = CertifyInput.ForEcdsa(
            subject.ObjectHandle, parent.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyResponse> certifyResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, certifyResult.ResponseCode);
    }

    /// <summary>
    /// Verifies the TPM2B_DATA qualifyingData size bound (TPM 2.0 Library Part 2, clause 10.4.3: bounded by the
    /// size of a marshaled TPMT_HA, 66 octets for the largest supported digest): a 66-octet qualifyingData
    /// succeeds, and a 67-octet qualifyingData is rejected with <c>TPM_RC_SIZE</c>.
    /// </summary>
    [TestMethod]
    public async Task CertifyWithOversizedQualifyingDataReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        byte[] atBound = new byte[Tpm2bData.MaxSize];
        byte[] overBound = new byte[Tpm2bData.MaxSize + 1];

        using TpmPasswordSession atBoundObjectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession atBoundSignAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput atBoundInput = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, atBound, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<CertifyResponse> atBoundResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, atBoundInput, [atBoundObjectAuth, atBoundSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(atBoundResult.IsSuccess, $"A 66-octet qualifyingData is exactly at the TPM2B_DATA bound and must succeed: '{atBoundResult.ResponseCode}'.");
        atBoundResult.Value.Dispose();

        using TpmPasswordSession overBoundObjectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession overBoundSignAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput overBoundInput = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, overBound, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<CertifyResponse> overBoundResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, overBoundInput, [overBoundObjectAuth, overBoundSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, overBoundResult.ResponseCode);
    }

    /// <summary>
    /// TPM2_Certify()'s objectHandle slot (Auth Index 1, Auth Role ADMIN, session index 0; TPM 2.0 Library Part
    /// 3, clause 18.2, Table 89) is verified against the certified object's own retained authValue over a plain
    /// <c>TPM_RS_PW</c> session: a DA-protected subject created with a real password admits a certification
    /// authorized by the CORRECT password and moves no dictionary-attack counter, while a WRONG password is
    /// refused with the session-index-encoded <c>TPM_RC_AUTH_FAIL</c> at index 0 (Part 2, clause 6.6.2) and
    /// charges <c>failedTries</c> exactly once (Part 1, clause 17.8.7). The signHandle slot carries its own
    /// (empty, correct) auth throughout, isolating the objectHandle arm.
    /// </summary>
    [TestMethod]
    public async Task CertifyVerifiesTheCertifiedObjectsAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, CertifiedObjectPassword).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession correctObjectAuth = TpmPasswordSession.Create(CertifiedObjectAuth, pool);
        using TpmPasswordSession correctSignAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput correctInput = CertifyInput.ForEcdsa(
            subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<CertifyResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, correctInput, [correctObjectAuth, correctSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(correctResult.IsSuccess, $"TPM2_Certify with the certified object's correct password must succeed, but failed: '{correctResult.ResponseCode}'.");
        correctResult.Value.Dispose();

        TpmResult<TpmDictionaryAttackParameters> afterCorrect = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, afterCorrect.Value.LockoutCounter,
            "A correctly-authorized Certify must move no dictionary-attack counter.");

        using TpmPasswordSession wrongObjectAuth = TpmPasswordSession.Create(WrongCertifiedObjectAuth, pool);
        using TpmPasswordSession wrongSignAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput wrongInput = CertifyInput.ForEcdsa(
            subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<CertifyResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, wrongInput, [wrongObjectAuth, wrongSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(wrongResult.IsTpmError, "A wrong certified-object password must be refused.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), wrongResult.ResponseCode,
            "A wrong objectHandle password over a plain TPM_RS_PW session names the objectHandle slot (session index 0), session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            afterCorrect.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
            "A wrong certified-object password against a DA-protected object must charge failedTries exactly once (TPM 2.0 Library Part 1, clause 17.8.7).");
    }

    /// <summary>
    /// TPM2_Certify()'s signHandle slot (Auth Index 2, Auth Role USER, session index 1; TPM 2.0 Library Part 3,
    /// clause 18.2, Table 89) is verified against the signing key's own retained authValue over a plain
    /// <c>TPM_RS_PW</c> session: a DA-protected AK created with a real password admits a certification
    /// authorized by the CORRECT password and moves no dictionary-attack counter, while a WRONG password is
    /// refused with the session-index-encoded <c>TPM_RC_AUTH_FAIL</c> at index 1 (Part 2, clause 6.6.2) and
    /// charges <c>failedTries</c> exactly once (Part 1, clause 17.8.7). The objectHandle slot carries its own
    /// (empty, correct) auth throughout, isolating the signHandle arm — the differing session index from
    /// <see cref="CertifyVerifiesTheCertifiedObjectsAuthValue"/> proves the two slots are checked independently
    /// rather than one compare covering both.
    /// </summary>
    [TestMethod]
    public async Task CertifyVerifiesTheSigningKeysAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, SigningKeyPassword).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession correctObjectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession correctSignAuth = TpmPasswordSession.Create(SigningKeyAuth, pool);
        using CertifyInput correctInput = CertifyInput.ForEcdsa(
            subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<CertifyResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, correctInput, [correctObjectAuth, correctSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(correctResult.IsSuccess, $"TPM2_Certify with the signing key's correct password must succeed, but failed: '{correctResult.ResponseCode}'.");
        correctResult.Value.Dispose();

        TpmResult<TpmDictionaryAttackParameters> afterCorrect = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, afterCorrect.Value.LockoutCounter,
            "A correctly-authorized Certify must move no dictionary-attack counter.");

        using TpmPasswordSession wrongObjectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession wrongSignAuth = TpmPasswordSession.Create(WrongSigningKeyAuth, pool);
        using CertifyInput wrongInput = CertifyInput.ForEcdsa(
            subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<CertifyResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, wrongInput, [wrongObjectAuth, wrongSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(wrongResult.IsTpmError, "A wrong signing-key password must be refused.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), wrongResult.ResponseCode,
            "A wrong signHandle password over a plain TPM_RS_PW session names the signHandle slot (session index 1), session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            afterCorrect.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
            "A wrong signing-key password against a DA-protected key must charge failedTries exactly once (TPM 2.0 Library Part 1, clause 17.8.7).");
    }

    /// <summary>
    /// TPM2_Certify()'s signHandle slot is Auth Role USER (Auth Index 2, session index 1; TPM 2.0 Library Part
    /// 3, clause 18.2, Table 89). When the signing key's <c>TPMA_OBJECT.userWithAuth</c> attribute is CLEAR,
    /// USER-role authorization by authValue — a plain <c>TPM_RS_PW</c> password here — is inadmissible: the
    /// command is refused with a bare <c>TPM_RC_POLICY_FAIL</c> (not session-index-encoded), returned before
    /// any credential is compared and before any command HMAC is queued (TPM 2.0 Library Part 3, clause 5.6,
    /// check 7.1 precedes checks 9/10 in the mandatory check order). Supplying the CORRECT password on both
    /// the objectHandle and the signHandle slots proves the refusal is attribute-gated rather than a comparison
    /// outcome, and the shared dictionary-attack counter must be left untouched — check 7.1's rejection is not
    /// <c>TPM_RC_AUTH_FAIL</c>, so clause 5.6's closing rule ("shall not alter any TPM state") applies.
    /// </summary>
    [TestMethod]
    public async Task CertifyWithUserWithAuthClearSignerIsRefusedWithoutComparingThePassword()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, CertifiedObjectPassword).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateUserWithAuthClearSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, SigningKeyPassword, noDa: false).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.Create(CertifiedObjectAuth, pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.Create(SigningKeyAuth, pool);
        using CertifyInput certifyInput = CertifyInput.ForEcdsa(
            subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyResponse> certifyResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        if(certifyResult.IsSuccess)
        {
            certifyResult.Value.Dispose();
        }

        Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, certifyResult.ResponseCode,
            $"A userWithAuth-CLEAR signHandle must reject password authorization with a bare TPM_RC_POLICY_FAIL " +
            $"(TPM 2.0 Library Part 3, clause 5.6, check 7.1), even with the correct password supplied (got '{certifyResult.ResponseCode}').");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "check 7.1's refusal is not TPM_RC_AUTH_FAIL, so per clause 5.6's closing rule it must leave failedTries untouched (TPM 2.0 Library Part 3, clause 5.6).");
    }

    /// <summary>
    /// TPM2_Certify()'s objectHandle slot is Auth Role ADMIN (Auth Index 1, session index 0; TPM 2.0 Library
    /// Part 3, clause 18.2, Table 89), governed by check 5.1: while <c>TPMA_OBJECT.adminWithPolicy</c> is
    /// CLEAR, ADMIN-role authorization by password (authValue) remains admissible regardless of
    /// <c>TPMA_OBJECT.userWithAuth</c> on the same object — the USER-role check 7.1 userWithAuth gate applies
    /// only to the USER-role slot (signHandle) and never leaks onto the ADMIN-role slot. Certifying a subject
    /// whose userWithAuth AND adminWithPolicy are both CLEAR, authorized on objectHandle by a plain
    /// <c>TPM_RS_PW</c> password, must SUCCEED and return a valid attestation once the signHandle side is an
    /// ordinary userWithAuth-SET signer.
    /// </summary>
    [TestMethod]
    public async Task CertifyingAUserWithAuthClearObjectByPasswordSucceedsOnTheAdminRoleSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //The certified object: userWithAuth CLEAR (and, since ADMIN_WITH_POLICY is never included in the
        //composed attributes either, adminWithPolicy CLEAR too), an empty retained authValue, still a
        //signing-capable template so creation under the owner hierarchy succeeds.
        using CreatePrimaryResponse subject = await CreateUserWithAuthClearSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null, noDa: true).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput certifyInput = CertifyInput.ForEcdsa(
            subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyResponse> certifyResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(certifyResult.IsSuccess,
            $"A password-authorized objectHandle must succeed under check 5.1 while adminWithPolicy is CLEAR, even though userWithAuth is also CLEAR on the same object: '{certifyResult.ResponseCode}'.");

        using CertifyResponse certify = certifyResult.Value;

        //A valid attestation: TPM-generated marker, certify type, and the certified Name recomputed
        //independently from the subject's exported public area (nameAlg || H(TPMT_PUBLIC)).
        TpmsAttest attest = certify.CertifyInfo.AttestationData;
        Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attest.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_CERTIFY, attest.Type);
        Assert.IsNotNull(attest.Attested.Certify);

        byte[] expectedName = await ComputeObjectNameAsync(subject.OutPublic, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.Attested.Certify!.Name.Span.SequenceEqual(expectedName),
            "The certified Name must equal the userWithAuth-CLEAR subject's Name recomputed from its exported public area.");
    }

    /// <summary>
    /// Certifies the subject with the RSA AK under the given scheme through the production command path,
    /// verifies the attestation off-TPM (magic/type/nonce/Name/Qualified Name), and verifies the signature against
    /// the AK's exported modulus with an independent RSA verifier.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="subject">The certified object's CreatePrimary response.</param>
    /// <param name="ak">The RSA attestation key's CreatePrimary response.</param>
    /// <param name="rsaParameters">The public key reconstructed from the AK's exported modulus.</param>
    /// <param name="usePss">When <see langword="true"/>, certifies and verifies RSAPSS; otherwise RSASSA (PKCS#1 v1.5).</param>
    private async Task CertifyAndVerifyRsaAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse subject, CreatePrimaryResponse ak, RSAParameters rsaParameters, bool usePss)
    {
        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput certifyInput = usePss
            ? CertifyInput.ForRsaPss(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool)
            : CertifyInput.ForRsaSsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyResponse> certifyResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        string schemeName = usePss ? "RSAPSS" : "RSASSA";
        Assert.IsTrue(certifyResult.IsSuccess, $"TPM2_Certify ({schemeName}) failed: '{certifyResult.ResponseCode}'.");

        using CertifyResponse certify = certifyResult.Value;
        Assert.AreEqual(usePss ? TpmAlgIdConstants.TPM_ALG_RSAPSS : TpmAlgIdConstants.TPM_ALG_RSASSA, certify.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, certify.HashAlgorithm);

        //1. Attestation envelope: TPM-generated marker, certify type, and the nonce echoed verbatim.
        TpmsAttest attest = certify.CertifyInfo.AttestationData;
        Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attest.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_CERTIFY, attest.Type);
        Assert.IsTrue(attest.ExtraData.Span.SequenceEqual(Nonce), "extraData must echo the caller's qualifyingData nonce.");
        Assert.IsNotNull(attest.Attested.Certify);

        //2. Name binding: firewalled recomputation from the wire-exported public area.
        byte[] expectedName = await ComputeObjectNameAsync(subject.OutPublic, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.Attested.Certify!.Name.Span.SequenceEqual(expectedName),
            "The certified Name must equal the subject's Name recomputed from its exported public area.");

        //3. Qualified Name realism: qualifiedSigner and attested.certify.qualifiedName must equal the independent
        //off-TPM recomputation and must NOT equal the plain Name.
        byte[] expectedSignerQn = await ComputeQualifiedNameAsync(
            (uint)TpmRh.TPM_RH_ENDORSEMENT, ak.Name.Span.ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.QualifiedSigner.Span.SequenceEqual(expectedSignerQn),
            "qualifiedSigner must equal the RSA AK's independently recomputed Qualified Name.");
        Assert.IsFalse(
            attest.QualifiedSigner.Span.SequenceEqual(ak.Name.Span),
            "qualifiedSigner must not collapse to the RSA AK's plain Name.");

        byte[] expectedSubjectQn = await ComputeQualifiedNameAsync(
            (uint)TpmRh.TPM_RH_OWNER, subject.Name.Span.ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.Attested.Certify!.QualifiedName.Span.SequenceEqual(expectedSubjectQn),
            "attested.certify.qualifiedName must equal the subject's independently recomputed Qualified Name.");
        Assert.IsFalse(
            attest.Attested.Certify!.QualifiedName.Span.SequenceEqual(subject.Name.Span),
            "attested.certify.qualifiedName must not collapse to the subject's plain Name.");

        //4. Signature: over the RAW attestation bytes, against the RSA AK public key reconstructed from the
        //simulator's exported modulus only.
        byte[] attestDigest = await ComputeSha256Async(certify.CertifyInfo.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        RSASignaturePadding padding = usePss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        using RSA rsa = RSA.Create(rsaParameters);
        Assert.IsTrue(
            rsa.VerifyHash(attestDigest, certify.Signature.RsaSignature.Buffer.ToArray(), HashAlgorithmName.SHA256, padding),
            $"The {schemeName} certify signature must verify against the RSA AK's exported modulus.");
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the given hierarchy and returns the response (the caller
    /// owns it).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a DA-protected primary ECC P-256 signing key under the given hierarchy with a real, non-empty
    /// authValue and returns the response (the caller owns it) — the fixture the objectHandle/signHandle
    /// authValue verification proofs need to exercise a genuine retained authValue rather than the empty one
    /// <see cref="CreateSigningPrimaryAsync"/>'s key carries.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <param name="password">The key's password.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreatePasswordProtectedSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, string password)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy,
            password,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: false);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (password-protected ECC P-256, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the given hierarchy with <c>TPMA_OBJECT.userWithAuth</c>
    /// CLEAR — the attributes are composed directly from <see cref="TpmaObject"/> flags rather than through
    /// <see cref="CreatePrimaryInput.ForEccSigningKey"/>, which always sets <see cref="TpmaObject.USER_WITH_AUTH"/>
    /// — and returns the response (the caller owns it). <see cref="TpmaObject.ADMIN_WITH_POLICY"/> is likewise
    /// never included, so the returned key's adminWithPolicy attribute is CLEAR too. Creation itself succeeds
    /// unconditionally: it is authorized by the hierarchy, which is exempt from the USER-role userWithAuth gate
    /// ("a hierarchy operates as if userWithAuth is SET", TPM 2.0 Library Part 3, clause 5.6).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <param name="password">The key's retained password, or <see langword="null"/> for an empty authValue.</param>
    /// <param name="noDa">
    /// When <see langword="true"/>, sets TPMA_OBJECT.noDA so that authorization failures against the key do not
    /// advance the TPM's dictionary-attack lockout counter.
    /// </param>
    /// <returns>The CreatePrimary response.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the CreatePrimaryInput, whose Dispose releases them.")]
    private async Task<CreatePrimaryResponse> CreateUserWithAuthClearSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, string? password, bool noDa)
    {
        var attributes = TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN | TpmaObject.SIGN_ENCRYPT;   // userWithAuth CLEAR.
        if(noDa)
        {
            attributes |= TpmaObject.NO_DA;
        }

        Tpm2bSensitiveCreate inSensitive = string.IsNullOrEmpty(password)
            ? Tpm2bSensitiveCreate.CreateEmpty(pool)
            : Tpm2bSensitiveCreate.WithPassword(password, pool);
        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            attributes,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));
        using CreatePrimaryInput input = new(hierarchy, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (userWithAuth-CLEAR ECC P-256, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a primary RSA-2048 signing key under the given hierarchy and returns the response (the caller owns
    /// it). A NULL scheme makes this an unrestricted signing key, so the scheme (RSASSA or RSAPSS) is chosen per
    /// <c>TPM2_Certify()</c>, as a real caller would.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(
            hierarchy, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Null, pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA 2048, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates an ECC storage parent (RESTRICTED|DECRYPT, no SIGN_ENCRYPT) under the given hierarchy and returns
    /// the response (the caller owns it) — a key that cannot sign, for the negative sign-attribute test.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the parent.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            hierarchy, authPassword: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC storage parent, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Recomputes a loaded object's Name from its exported public area: <c>nameAlg || H_nameAlg(TPMT_PUBLIC)</c>
    /// (TPM 2.0 Library Part 1, clause 14, Table 6), through the registered digest seam. The test keys use a SHA-256 nameAlg.
    /// </summary>
    /// <param name="outPublic">The object's exported public area.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recomputed Name (2-byte nameAlg prefix + digest).</returns>
    private static async Task<byte[]> ComputeObjectNameAsync(Tpm2bPublic outPublic, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        TpmAlgIdConstants nameAlg = outPublic.PublicArea.NameAlg;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, nameAlg, "This test assumes a SHA-256 nameAlg.");

        byte[] marshaledPublic = MarshalPublicArea(outPublic, pool);
        byte[] digest = await ComputeSha256Async(marshaledPublic, pool, cancellationToken).ConfigureAwait(false);

        byte[] name = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)nameAlg);
        digest.CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>
    /// Recomputes an object's Qualified Name independently: <c>nameAlg || H(hierarchyHandle || Name)</c> (TPM 2.0
    /// Library Part 1, clause 14, Table 6), through the registered digest seam. Every object this simulator certifies is a
    /// primary created directly under a permanent hierarchy, so the hierarchy's own Qualified Name is its 4-octet
    /// big-endian handle value — this test never calls the production <c>TpmObjectName</c> helper, matching the
    /// file's firewalled, off-TPM oracle style.
    /// </summary>
    /// <param name="hierarchy">The permanent hierarchy handle the object was created under.</param>
    /// <param name="name">The object's own Name.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recomputed Qualified Name.</returns>
    private static async Task<byte[]> ComputeQualifiedNameAsync(uint hierarchy, ReadOnlyMemory<byte> name, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        ushort nameAlg = BinaryPrimitives.ReadUInt16BigEndian(name.Span[..sizeof(ushort)]);
        Assert.AreEqual((ushort)TpmAlgIdConstants.TPM_ALG_SHA256, nameAlg, "This test assumes a SHA-256 nameAlg.");

        byte[] message = new byte[sizeof(uint) + name.Length];
        BinaryPrimitives.WriteUInt32BigEndian(message, hierarchy);
        name.Span.CopyTo(message.AsSpan(sizeof(uint)));

        byte[] digest = await ComputeSha256Async(message, pool, cancellationToken).ConfigureAwait(false);

        byte[] qualifiedName = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(qualifiedName, nameAlg);
        digest.CopyTo(qualifiedName.AsSpan(sizeof(ushort)));

        return qualifiedName;
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

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers it
    /// on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase. Both backends are required
    /// so the simulator services <c>TPM2_CreatePrimary()</c> for either key type and signs the attestation for
    /// <c>TPM2_Certify()</c> with either an ECC or an RSA attestation key.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-certify",
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

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Certify, TpmResponseCodec.Certify);

        return registry;
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
            //Defensive: drop any leading zero padding the simulator may have included.
            value[^length..].CopyTo(result);
        }

        return result;
    }

    /// <summary>
    /// TPM2_Certify()'s signHandle slot (Auth Index 2, USER role, session index 1; TPM 2.0 Library Part 3, clause
    /// 18.2, Table 89) admits a genuine, unbound HMAC session exactly as it admits a password: a DA-protected AK
    /// created with a real authValue attests once the session folds the CORRECT value into its command HMAC (TPM
    /// 2.0 Library Part 1, clause 17.6.5, equation 17), with the objectHandle slot authorized by an ordinary
    /// password session — the mixed password-object/HMAC-sign area. A SECOND certify issued over the SAME
    /// session succeeds again and adopts a genuinely rolled nonceTPM from its own response entry: the response
    /// HMAC (clause 17.6.5) verifies, and only then is the new value adopted, so a byte-identical nonceTPM across
    /// two commands would mean the roll never happened.
    /// </summary>
    [TestMethod]
    public async Task CertifySignSlotOverUnboundHmacSessionAttestsAndAdoptsARolledNonceOnASecondCommand()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, SigningKeyPassword).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            signSession.SetAuthValue(SigningKeyAuth, pool);

            using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
            ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

            using CertifyInput firstInput = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<CertifyResponse> firstResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, firstInput, [objectAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(firstResult.IsSuccess, $"TPM2_Certify (unbound HMAC sign slot, correct auth) failed: '{firstResult.ResponseCode}'.");

            byte[] expectedName = await ComputeObjectNameAsync(subject.OutPublic, pool, TestContext.CancellationToken).ConfigureAwait(false);
            using(CertifyResponse firstCertify = firstResult.Value)
            {
                Assert.IsTrue(
                    firstCertify.CertifyInfo.AttestationData.Attested.Certify!.Name.Span.SequenceEqual(expectedName),
                    "The certified Name must equal the subject's Name recomputed from its exported public area.");
            }

            byte[] nonceTpmBeforeSecond = signSession.NonceTpm.ToArray();

            using CertifyInput secondInput = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<CertifyResponse> secondResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, secondInput, [objectAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secondResult.IsSuccess, $"A second TPM2_Certify over the same session must succeed, but failed: '{secondResult.ResponseCode}'.");
            secondResult.Value.Dispose();

            Assert.IsFalse(
                signSession.NonceTpm.Span.SequenceEqual(nonceTpmBeforeSecond),
                "The sign slot must adopt a genuinely rolled nonceTPM from its own response entry on the second command.");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The HMAC-arm DA-charge companion to <see cref="CertifyVerifiesTheSigningKeysAuthValue"/>: a WRONG guess at
    /// a DA-protected signing key's authValue, folded into an unbound HMAC session at the signHandle slot (Auth
    /// Index 2, USER role, session index 1), fails the session's command HMAC verification server-side (TPM 2.0
    /// Library Part 1, clause 17.6.5, equation 17) and is refused with the session-encoded <c>TPM_RC_AUTH_FAIL</c>
    /// at index 1 (Part 2, clause 6.6.2), charging <c>failedTries</c> exactly once (Part 1, clause 17.8.1).
    /// </summary>
    [TestMethod]
    public async Task CertifyOverHmacSignSlotWithWrongAuthOnDaProtectedSignerChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, SigningKeyPassword).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<CertifyResponse> result = await CertifyOverHmacSignSlotAsync(
            tpm, registry, pool, subject, ak, WrongSigningKeyAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_FAIL, result.BaseError,
            "A wrong signing-key authValue folded into an HMAC sign session must fail the command HMAC with TPM_RC_AUTH_FAIL (the key is DA-protected).");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), result.ResponseCode,
            "The mismatch names the sign slot (session index 1), so the wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter + 1, after.Value.LockoutCounter,
            "A wrong signing-key authValue against a DA-protected key must charge failedTries exactly once (TPM 2.0 Library Part 1, clause 17.8.1).");
    }

    /// <summary>
    /// The NO_DA-half contrast to <see cref="CertifyOverHmacSignSlotWithWrongAuthOnDaProtectedSignerChargesFailedTries"/>
    /// (TPM 2.0 Library Part 2, Table 233, bit 25): a wrong guess folded into an unbound HMAC session at the
    /// signHandle slot against a dictionary-attack-EXEMPT signing key answers the plain <c>TPM_RC_BAD_AUTH</c>
    /// rather than the DA-counted <c>TPM_RC_AUTH_FAIL</c> — still session-encoded at index 1 (Part 2, clause
    /// 6.6.2) — and leaves <c>failedTries</c> untouched.
    /// </summary>
    [TestMethod]
    public async Task CertifyOverHmacSignSlotWithWrongAuthOnNoDaSignerLeavesFailedTriesUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateNoDaPasswordProtectedSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, SigningKeyPassword).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<CertifyResponse> result = await CertifyOverHmacSignSlotAsync(
            tpm, registry, pool, subject, ak, WrongSigningKeyAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError,
            "A wrong signing-key authValue against a NO_DA signing key must fail the command HMAC with TPM_RC_BAD_AUTH, never the DA-counted TPM_RC_AUTH_FAIL.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), result.ResponseCode,
            "The mismatch names the sign slot (session index 1), so the wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "A NO_DA signing key's authorization failure must move no dictionary-attack counter.");
    }

    /// <summary>
    /// A sign session BOUND TO THE SIGNING KEY ITSELF attests with no authValue folded into its command HMAC:
    /// binding already incorporated the key's authValue into the session key (TPM 2.0 Library Part 1, clause
    /// 17.6.10, equation 20), so the command HMAC omits it (equations 21/22) — the sign-slot bind-omission path,
    /// the reason a session bound to the entity it authorizes needs no separate per-command authValue.
    /// </summary>
    [TestMethod]
    public async Task CertifyOverSignSessionBoundToTheSigningKeyItselfAttests()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, SigningKeyPassword).ConfigureAwait(false);

        StartAuthSessionInput signStartInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(ak.ObjectHandle.Value, HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> signStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, signStartInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signStartResult.IsSuccess, $"StartAuthSession (sign slot bound to the signing key) failed: '{signStartResult.ResponseCode}'.");

        StartAuthSessionResponse signStarted = signStartResult.Value;
        uint signSessionHandle = signStarted.SessionHandle.Value;

        try
        {
            using TpmSession signSession = await TpmSession.CreateBoundAsync(
                new TpmHandle(signSessionHandle), SigningKeyAuth, signStartInput.NonceCaller, signStarted.NonceTPM,
                HmacSessionAlg, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            signSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;

            using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
            using CertifyInput certifyInput = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

            TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, certifyInput, [objectAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                result.IsSuccess,
                $"A sign session bound to the signing key itself must attest with the authValue folded into the bind, but failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, signSessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A salted-and-bound HMAC session at the objectHandle slot (Auth Index 1, ADMIN role, session index 0),
    /// bound DIRECTLY to the certified object with NO per-command authValue supplied, attests: the ADMIN slot
    /// admits an HMAC session exactly as it admits a password, and only the eq. 26 (TPM 2.0 Library Part 1,
    /// clause 17.6.12) bind-omission — the bound entity's real, non-empty authValue folded into the session key
    /// derived from the ECDH-recovered salt (Annex C.6.1/C.6.2) — lets this succeed, proving salting composes
    /// with genuine bind resolution to a non-empty authValue on the ADMIN-role slot.
    /// </summary>
    [TestMethod]
    public async Task CertifyOverSaltedAndBoundObjectSessionOmittingAuthValueAttests()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse tpmKey = await CreateStorageParentAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;
        using CreatePrimaryResponse subject = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, CertifiedObjectPassword).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        ReadOnlyMemory<byte> point = ExtractEccPoint(tpmKey);
        TpmEccSigningBackend eccBackend = BouncyCastleTpmEccSigningBackend.Create();

        (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateBoundAndSaltedHmacSession(
            tpmKeyHandle, subject.ObjectHandle.Value, point, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmKeyNameAlg, HmacSessionAlg,
            eccBackend.GenerateKey, eccBackend.ComputeSharedSecret, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using(salt)
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (salted-and-bound object slot) failed: '{startResult.ResponseCode}'.");
            StartAuthSessionResponse startResponse = startResult.Value;
            uint sessionHandle = startResponse.SessionHandle.Value;

            try
            {
                using TpmSession objectSession = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), CertifiedObjectAuth, startInput.NonceCaller,
                    startResponse.NonceTPM, HmacSessionAlg, pool, symmetric: TpmtSymDef.Null, salt: salt.Memory[..saltLength],
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                objectSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;

                //Deliberately NOT calling objectSession.SetAuthValue: the per-command authValue stays empty,
                //relying entirely on the bind-omission to authorize the certified object's ADMIN-role slot.
                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                using CertifyInput certifyInput = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

                TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                    tpm, certifyInput, [objectSession, signAuth], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(
                    result.IsSuccess,
                    $"A salted-and-bound object session relying on the bind-omission must attest, but failed: '{result.ResponseCode}'.");

                using CertifyResponse certify = result.Value;
                byte[] expectedName = await ComputeObjectNameAsync(subject.OutPublic, pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(
                    certify.CertifyInfo.AttestationData.Attested.Certify!.Name.Span.SequenceEqual(expectedName),
                    "The certified Name must equal the subject's Name recomputed from its exported public area.");
            }
            finally
            {
                await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// TPM2_Certify()'s objectHandle slot (Auth Index 1, ADMIN role, session index 0; TPM 2.0 Library Part 3,
    /// clause 18.2, Table 89) admits a genuine, unbound HMAC session exactly as it admits a password: a
    /// DA-protected certified object created with a real authValue attests once the session folds that CORRECT
    /// value into its command HMAC (TPM 2.0 Library Part 1, clause 17.6.5, equation 17), with the signHandle
    /// slot authorized by an ordinary password session — the mixed HMAC-object/password-sign area, the mirror
    /// composition to <see cref="CertifySignSlotOverUnboundHmacSessionAttestsAndAdoptsARolledNonceOnASecondCommand"/>.
    /// </summary>
    [TestMethod]
    public async Task CertifyOverHmacObjectSlotWithItsOwnRealAuthValueAndPasswordSignSlotAttests()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, CertifiedObjectPassword).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        TpmResult<CertifyResponse> result = await CertifyOverHmacObjectSlotAsync(
            tpm, registry, pool, subject, ak, CertifiedObjectAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_Certify (HMAC object slot with its own real authValue) failed: '{result.ResponseCode}'.");

        using CertifyResponse certify = result.Value;
        byte[] expectedName = await ComputeObjectNameAsync(subject.OutPublic, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            certify.CertifyInfo.AttestationData.Attested.Certify!.Name.Span.SequenceEqual(expectedName),
            "The certified Name must equal the subject's Name recomputed from its exported public area.");
    }

    /// <summary>
    /// Two REAL, unbound/unsalted HMAC sessions — one at objectHandle's slot, one at signHandle's slot — both
    /// succeed and both adopt a genuinely rolled nonceTPM from their own response entry: a session's nonceTPM
    /// changes on every use, command and response alike (TPM 2.0 Library Part 1, clause 17.6.3.1), and the HMAC
    /// that authenticates a response entry (clause 17.6.5, equation 17) verifies — and only then lets the
    /// session adopt the new value — solely when that entry is genuine.
    /// </summary>
    [TestMethod]
    public async Task CertifyOverTwoRealHmacSessionsAttestsAndBothSlotsAdoptARolledNonceTpm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        StartAuthSessionInput objectStartInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> objectStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, objectStartInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(objectStartResult.IsSuccess, $"StartAuthSession (object slot) failed: '{objectStartResult.ResponseCode}'.");
        StartAuthSessionResponse objectStarted = objectStartResult.Value;
        uint objectSessionHandle = objectStarted.SessionHandle.Value;

        StartAuthSessionInput signStartInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> signStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, signStartInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signStartResult.IsSuccess, $"StartAuthSession (sign slot) failed: '{signStartResult.ResponseCode}'.");
        StartAuthSessionResponse signStarted = signStartResult.Value;
        uint signSessionHandle = signStarted.SessionHandle.Value;

        try
        {
            using TpmSession objectSession = new(new TpmHandle(objectSessionHandle), objectStarted.NonceTPM, HmacSessionAlg, pool);
            using TpmSession signSession = new(new TpmHandle(signSessionHandle), signStarted.NonceTPM, HmacSessionAlg, pool);

            byte[] nonceTpmBeforeObject = objectSession.NonceTpm.ToArray();
            byte[] nonceTpmBeforeSign = signSession.NonceTpm.ToArray();

            using CertifyInput certifyInput = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

            TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, certifyInput, [objectSession, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_Certify (two real HMAC sessions) failed: '{result.ResponseCode}'.");

            using CertifyResponse certify = result.Value;
            byte[] expectedName = await ComputeObjectNameAsync(subject.OutPublic, pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                certify.CertifyInfo.AttestationData.Attested.Certify!.Name.Span.SequenceEqual(expectedName),
                "The certified Name must equal the subject's Name recomputed from its exported public area.");

            Assert.IsFalse(
                objectSession.NonceTpm.Span.SequenceEqual(nonceTpmBeforeObject),
                "The object slot must adopt a genuinely rolled nonceTPM from its own response entry.");
            Assert.IsFalse(
                signSession.NonceTpm.Span.SequenceEqual(nonceTpmBeforeSign),
                "The sign slot must likewise adopt a genuinely rolled nonceTPM from its own response entry.");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, objectSessionHandle).ConfigureAwait(false);
            await FlushHandleAsync(tpm, registry, pool, signSessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A single real HMAC session named in BOTH authorization slots is refused: "a specific HMAC or policy
    /// session handle can occur only once in the Authorization Area; TPM_RS_PW may repeat" (TPM 2.0 Library Part
    /// 1, clause 16.6.3). Composing the SAME live <see cref="TpmSession"/> into both slots through the
    /// production <see cref="TpmCommandExecutor"/> already produces the identical wire scenario the rule
    /// forbids (two <c>TPMS_AUTH_COMMAND</c> entries naming the same real sessionHandle), through the same
    /// request-framing code path every other test in this file uses. Part 1 names no response code for the
    /// violation; the reference does, its <c>RetrieveSessionData</c> comparing each unmarshaled slot against
    /// every earlier one and answering <c>TPM_RCS_HANDLE + errorIndex</c>, so the refusal is a handle error
    /// naming the SECOND occurrence (session index 1, TPM 2.0 Library Part 2, clause 6.6.2), the offending
    /// re-claim.
    /// </summary>
    [TestMethod]
    public async Task CertifyWithTheSameRealSessionHandleInBothSlotsIsRefused()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);

            using CertifyInput certifyInput = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

            //The SAME session names both the objectHandle slot and the signHandle slot, so the wire's two
            //TPMS_AUTH_COMMAND entries carry the identical real sessionHandle - the exact composition clause
            //16.6.3 forbids.
            TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, certifyInput, [session, session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, result.BaseError);
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 1), result.ResponseCode,
                "The duplicate-handle refusal blames the second occurrence (session index 1), session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The session arm's USER-role gate (TPM 2.0 Library Part 3, clause 5.6, check 7.1) for a userWithAuth-CLEAR
    /// signer runs before any sign-slot command HMAC is queued for verification: a REAL, unbound/unsalted HMAC
    /// sign session carrying a WRONG guess at the signer's authValue still answers the BARE
    /// <c>TPM_RC_POLICY_FAIL</c>, never a session-encoded <c>TPM_RC_AUTH_FAIL</c> — proving the gate precedes
    /// the queued command-HMAC verification that would otherwise fail and charge the dictionary-attack counter
    /// for a wrong guess against a DA-protected signer. Uncharged, because <c>TPM_RC_POLICY_FAIL</c> is not
    /// <c>TPM_RC_AUTH_FAIL</c> (clause 5.6's closing rule).
    /// </summary>
    [TestMethod]
    public async Task CertifyOverSessionWithUserWithAuthClearSignerAndWrongHmacSignSlotGuessReturnsPolicyFailNotAuthFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse clearSigner = await CreateUserWithAuthClearSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, SigningKeyPassword, noDa: false).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<CertifyResponse> result = await CertifyOverHmacSignSlotAsync(
            tpm, registry, pool, subject, clearSigner, WrongSigningKeyAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_FAIL, result.BaseError,
            "A wrong guess folded into a real HMAC sign session against a userWithAuth-CLEAR signer must still answer TPM_RC_POLICY_FAIL, never an auth failure.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode,
            "The refusal is the BARE constant, not the session-encoded form a genuine command-HMAC mismatch would carry - the userWithAuth gate runs before that verification is ever queued.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "TPM_RC_POLICY_FAIL is not TPM_RC_AUTH_FAIL, so the userWithAuth gate must move no counter, even though the guess was wrong.");
    }

    /// <summary>
    /// The session arm's sign slot carries the signing key's own DA/Lockout gate (TPM 2.0 Library Part 3, clause
    /// 5.6, check 3), answering before EITHER sign-slot credential shape is evaluated: with the TPM in Lockout
    /// mode, a DA-protected signing key answers the bare <c>TPM_RC_LOCKOUT</c> even though the sign slot's real
    /// HMAC session carries the CORRECT authValue. The certified object is dictionary-attack exempt (created via
    /// <see cref="CreateSigningPrimaryAsync"/>), so the objectHandle slot's own lockout gate cannot be the one
    /// answering: the refusal is attributable to the sign slot's gate alone.
    /// </summary>
    [TestMethod]
    public async Task CertifyOverSessionWithDaProtectedSignerUnderLockoutReturnsLockoutBeforeSignSlotEvaluation()
    {
        const uint SingleAttemptMaxTries = 1;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse signer = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, SigningKeyPassword).ConfigureAwait(false);

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, SingleAttemptMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        //A single wrong sign password over the all-password arm charges the DA-protected signer and, with
        //maxTries at one, enters Lockout mode as a side effect.
        using(TpmPasswordSession seedingObjectAuth = TpmPasswordSession.CreateEmpty(pool))
        using(TpmPasswordSession wrongSignAuth = TpmPasswordSession.Create(WrongSigningKeyAuth, pool))
        using(CertifyInput seedingInput = CertifyInput.ForEcdsa(subject.ObjectHandle, signer.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool))
        {
            TpmResult<CertifyResponse> seedingResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, seedingInput, [seedingObjectAuth, wrongSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), seedingResult.ResponseCode,
                "The seeding mismatch must be a charged sign-slot auth failure at session index 1.");
        }

        //An unbound, unsalted HMAC session needs no authorization to start, so Lockout mode admits it (Part 3,
        //clause 11.1.1); the lockout answer must come from the sign slot's own gate instead.
        TpmResult<CertifyResponse> result = await CertifyOverHmacSignSlotAsync(
            tpm, registry, pool, subject, signer, SigningKeyAuth).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode,
            "A DA-protected signing key in Lockout mode must be refused before its HMAC sign slot is evaluated, correct auth or not (TPM 2.0 Library Part 3, clause 5.6's check 3 precedes checks 7.1 and 9/10).");
    }

    /// <summary>
    /// Resolving one attest-command authorization slot's session handle (TPM 2.0 Library Part 3, clause 5.6,
    /// step 2 of the entry ladder): a handle naming a genuine POLICY session — a kind of authorization
    /// TPM2_Certify()'s session arm does not model — is refused with the BARE <c>TPM_RC_AUTH_TYPE</c> (not
    /// session-encoded), before any credential is evaluated. Placed at the objectHandle slot (session index 0).
    /// </summary>
    [TestMethod]
    public async Task CertifyOverSessionWithAPolicySessionHandleOnTheObjectSlotReturnsAuthType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        StartAuthSessionInput policyStartInput = StartAuthSessionInputExtensions.CreateUnboundUnsaltedPolicySession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> policyStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, policyStartInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");

        StartAuthSessionResponse policyStarted = policyStartResult.Value;
        uint policySessionHandle = policyStarted.SessionHandle.Value;

        try
        {
            //A client-side TpmSession wraps the handle of a session the simulator actually started as a POLICY
            //session (TpmSeConstants.TPM_SE_POLICY): the wire carries this real handle at the object slot, but
            //the simulator's TryResolveCommandSession finds it only in PolicySessions, never in HmacSessions.
            using TpmSession objectSession = new(new TpmHandle(policySessionHandle), policyStarted.NonceTPM, HmacSessionAlg, pool);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using CertifyInput certifyInput = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

            TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, certifyInput, [objectSession, signAuth], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode,
                "A policy-session handle on the object slot must be refused with the bare TPM_RC_AUTH_TYPE, before any credential is evaluated.");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, policySessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A session handle naming NO loaded HMAC or policy session at all is blamed on its own slot: <c>TPM_RC_REFERENCE_S1</c>
    /// (TPM 2.0 Library Part 2, clause 6.6.2's <c>TPM_RC_REFERENCE_S*</c> block) for a handle at the signHandle
    /// slot (session index 1) that this file never started through <c>TPM2_StartAuthSession()</c>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The random nonceTPM's ownership transfers into the using-scoped TpmSession, whose Dispose releases it; the sign session handle is unloaded, so the command is refused at TPM_RC_REFERENCE_S1 before the nonce is ever used.")]
    public async Task CertifyOverSessionWithAnUnloadedSignSessionHandleReturnsReferenceMiss()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmSession signSession = new(new TpmHandle(UnloadedSessionHandle), Tpm2bNonce.CreateRandom(HmacSessionDigestSize, pool), HmacSessionAlg, pool);

        using CertifyInput certifyInput = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

        TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_REFERENCE_S1, result.ResponseCode,
            "A session handle naming no loaded session at all is blamed on its own slot (session index 1).");
    }

    /// <summary>
    /// A refused HMAC-session area and a successful one each return every carrier they rented — the session
    /// key, the supplied command HMAC, and every intermediate digest buffer — proven with real pool telemetry
    /// (<see cref="MeteredHousePool"/>) over the real wire rather than an internal hook. Both areas fold a
    /// NON-EMPTY signing-key authValue into the sign session (a WRONG guess, then the CORRECT one), so the
    /// carriers under accounting are genuine authorization-value rentals, not the degenerate empty-buffer case.
    /// A mid-scenario liveness assertion proves the live session genuinely held a rental before either balance
    /// assertion, so neither is vacuous.
    /// </summary>
    [TestMethod]
    public async Task CertifyOverSessionKeepsPoolBalanceExactAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, SigningKeyPassword).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        StartAuthSessionInput refusedStartInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> refusedStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, refusedStartInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(refusedStartResult.IsSuccess, $"StartAuthSession failed: '{refusedStartResult.ResponseCode}'.");
        StartAuthSessionResponse refusedStarted = refusedStartResult.Value;
        uint refusedSessionHandle = refusedStarted.SessionHandle.Value;

        try
        {
            using TpmSession refusedSession = new(new TpmHandle(refusedSessionHandle), refusedStarted.NonceTPM, HmacSessionAlg, trackingPool.Pool);
            refusedSession.SetAuthValue(WrongSigningKeyAuth, trackingPool.Pool);

            Assert.IsGreaterThan(
                baseline, trackingPool.OutstandingCount,
                "A live HMAC session carrying a non-empty authValue must hold at least one rented carrier, or the balance assertion below is vacuous.");

            using TpmPasswordSession refusedObjectAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using CertifyInput refusedInput = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);
            ReadOnlyMemory<byte>[] refusedHandleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

            TpmResult<CertifyResponse> refused = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, refusedInput, [refusedObjectAuth, refusedSession], refusedHandleNames, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(refused.IsTpmError, "The wrong sign-slot authValue must be refused.");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, trackingPool.Pool, refusedSessionHandle).ConfigureAwait(false);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A refused HMAC-session area must return every rented carrier to the pool.");

        StartAuthSessionInput successStartInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> successStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, successStartInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(successStartResult.IsSuccess, $"StartAuthSession failed: '{successStartResult.ResponseCode}'.");
        StartAuthSessionResponse successStarted = successStartResult.Value;
        uint successSessionHandle = successStarted.SessionHandle.Value;

        try
        {
            using TpmSession successSession = new(new TpmHandle(successSessionHandle), successStarted.NonceTPM, HmacSessionAlg, trackingPool.Pool);
            successSession.SetAuthValue(SigningKeyAuth, trackingPool.Pool);

            Assert.IsGreaterThan(
                baseline, trackingPool.OutstandingCount,
                "A live HMAC session carrying a non-empty authValue must hold at least one rented carrier, or the balance assertion below is vacuous.");

            using TpmPasswordSession successObjectAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using CertifyInput successInput = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);
            ReadOnlyMemory<byte>[] successHandleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

            TpmResult<CertifyResponse> succeeded = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, successInput, [successObjectAuth, successSession], successHandleNames, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(succeeded.IsSuccess, $"The correct sign-slot authValue must attest, but failed: '{succeeded.ResponseCode}'.");
            succeeded.Value.Dispose();
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, trackingPool.Pool, successSessionHandle).ConfigureAwait(false);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A successful HMAC-session area must likewise return every rented carrier to the pool.");
    }

    /// <summary>
    /// The USER-vs-ADMIN sharpness pair over a real HMAC session: the identical userWithAuth-CLEAR key is
    /// refused with the bare <c>TPM_RC_POLICY_FAIL</c> (TPM 2.0 Library Part 3, clause 5.6, check 7.1) when
    /// placed at signHandle (Auth Index 2, USER role, session index 1) — the userWithAuth gate governs only the
    /// USER-role slot — yet ATTESTS when the SAME key is placed at objectHandle (Auth Index 1, ADMIN role,
    /// session index 0) instead, proving check 7.1 never leaks onto the ADMIN slot even over a genuine HMAC
    /// session (mirroring the all-password pair
    /// <see cref="CertifyWithUserWithAuthClearSignerIsRefusedWithoutComparingThePassword"/> and
    /// <see cref="CertifyingAUserWithAuthClearObjectByPasswordSucceedsOnTheAdminRoleSlot"/>).
    /// </summary>
    [TestMethod]
    public async Task CertifyOverSessionWithUserWithAuthClearKeyRefusesAsSignHandleButAttestsAsObjectHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse clearKey = await CreateUserWithAuthClearSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_OWNER, password: null, noDa: true).ConfigureAwait(false);
        using CreatePrimaryResponse otherParty = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        //As signHandle (USER role, session index 1): refused, uncharged, before any command HMAC is queued -
        //even though the session's authValue is left empty, matching the clear key's own (correct) empty auth.
        TpmResult<CertifyResponse> asSigner = await CertifyOverHmacSignSlotAsync(
            tpm, registry, pool, otherParty, clearKey, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_FAIL, asSigner.ResponseCode,
            "A userWithAuth-CLEAR key at signHandle must be refused with the bare TPM_RC_POLICY_FAIL, even over a real HMAC session and even with its correct (empty) authValue supplied.");

        //As objectHandle (ADMIN role, session index 0): attests - check 5.1, not check 7.1, governs this slot.
        TpmResult<CertifyResponse> asObject = await CertifyOverHmacObjectSlotAsync(
            tpm, registry, pool, clearKey, otherParty, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(
            asObject.IsSuccess,
            $"The identical userWithAuth-CLEAR key must attest when placed at objectHandle instead, but failed: '{asObject.ResponseCode}'.");

        using CertifyResponse certify = asObject.Value;
        byte[] expectedName = await ComputeObjectNameAsync(clearKey.OutPublic, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            certify.CertifyInfo.AttestationData.Attested.Certify!.Name.Span.SequenceEqual(expectedName),
            "The certified Name must equal the userWithAuth-CLEAR object's Name recomputed from its exported public area.");
    }

    /// <summary>Extends <see cref="CreateRegistry"/> with the StartAuthSession/FlushContext codecs the over-session tests need.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateHmacArmRegistry()
    {
        TpmResponseRegistry registry = CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Creates a dictionary-attack-EXEMPT (<c>TPMA_OBJECT.noDA</c> SET) primary ECC P-256 signing key under the
    /// given hierarchy with a real, non-empty authValue — the NO_DA contrast fixture the sign-slot HMAC-arm
    /// needs: a wrong guess against this key must answer <c>TPM_RC_BAD_AUTH</c>, never the dictionary-attack-
    /// counted <c>TPM_RC_AUTH_FAIL</c> <see cref="CreatePasswordProtectedSigningPrimaryAsync"/>'s DA-protected
    /// key answers (TPM 2.0 Library Part 1, clause 17.8.1).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <param name="password">The key's password.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateNoDaPasswordProtectedSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, string password)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy,
            password,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (NO_DA password-protected ECC P-256, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Certifies <paramref name="subject"/> with <paramref name="ak"/>, authorizing the SIGN slot with a fresh,
    /// real, unbound/unsalted HMAC session (TPM 2.0 Library Part 1, clause 17.6.9, equation 19) carrying
    /// <paramref name="signSlotAuthValue"/>, and the objectHandle slot with an empty-auth password session — the
    /// mirror composition to <see cref="CertifyOverHmacObjectSlotAsync"/>, which puts the real session at the
    /// object slot instead.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="subject">The certified object's CreatePrimary response.</param>
    /// <param name="ak">The signing key's CreatePrimary response.</param>
    /// <param name="signSlotAuthValue">The authValue term folded into the sign session; empty to leave it unset.</param>
    /// <returns>The Certify result.</returns>
    private async Task<TpmResult<CertifyResponse>> CertifyOverHmacSignSlotAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse subject, CreatePrimaryResponse ak, ReadOnlyMemory<byte> signSlotAuthValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (sign slot) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            if(!signSlotAuthValue.IsEmpty)
            {
                signSession.SetAuthValue(signSlotAuthValue.Span, pool);
            }

            using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
            using CertifyInput certifyInput = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

            return await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, certifyInput, [objectAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Certifies <paramref name="subject"/> with <paramref name="ak"/>, authorizing the OBJECT slot with a
    /// fresh, real, unbound/unsalted HMAC session (TPM 2.0 Library Part 1, clause 17.6.9, equation 19) carrying
    /// <paramref name="objectSlotAuthValue"/>, and the signHandle slot with an empty-auth password session — the
    /// mirror composition to <see cref="CertifyOverHmacSignSlotAsync"/>, which puts the real session at the sign
    /// slot instead.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="subject">The certified object's CreatePrimary response.</param>
    /// <param name="ak">The signing key's CreatePrimary response.</param>
    /// <param name="objectSlotAuthValue">The authValue term folded into the object session; empty to leave it unset.</param>
    /// <returns>The Certify result.</returns>
    private async Task<TpmResult<CertifyResponse>> CertifyOverHmacObjectSlotAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse subject, CreatePrimaryResponse ak, ReadOnlyMemory<byte> objectSlotAuthValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (object slot) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession objectSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            if(!objectSlotAuthValue.IsEmpty)
            {
                objectSession.SetAuthValue(objectSlotAuthValue.Span, pool);
            }

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using CertifyInput certifyInput = CertifyInput.ForEcdsa(subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

            return await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, certifyInput, [objectSession, signAuth], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>Extracts a primary ECC key's exported public point, SEC1 uncompressed (<c>0x04 ‖ X ‖ Y</c>) — the point a salted <c>TPM2_StartAuthSession()</c> encrypts its salt to (TPM 2.0 Library Part 1, Annex C.6.1).</summary>
    /// <param name="primary">The primary's CreatePrimary response.</param>
    /// <returns>The uncompressed public point.</returns>
    private static ReadOnlyMemory<byte> ExtractEccPoint(CreatePrimaryResponse primary)
    {
        TpmsEccPoint point = primary.OutPublic.PublicArea.Unique.Ecc!;

        return EllipticCurveUtilities.CombineToUncompressedPoint(point.X.AsReadOnlySpan(), point.Y.AsReadOnlySpan());
    }

    /// <summary>Flushes a session or transient-object handle through <c>TPM2_FlushContext()</c> for best-effort teardown in a <c>finally</c> block, ignoring the result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    private static async Task FlushHandleAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(handle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
    }
}
