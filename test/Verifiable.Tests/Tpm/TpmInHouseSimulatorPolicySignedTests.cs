using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
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
/// Drives <c>TPM2_PolicySigned()</c> against the in-house behavioural <see cref="TpmSimulator"/> — entirely
/// in-process, with no external assets — through the same production command path the production code uses (the
/// <see cref="TpmDeviceExtensions"/> policy commands, <see cref="TpmCommandExecutor"/>, and the real
/// command/response codecs). Each test starts a real or trial policy session, builds <c>aHash</c> from the
/// session's real, retained nonceTPM, signs it through the production <c>TPM2_Sign()</c> wire path, and drives
/// <c>TPM2_PolicySigned()</c> itself over the wire (TPM 2.0 Library Part 3, Section 23.3).
/// </summary>
/// <remarks>
/// <para>
/// The flagship test independently predicts the policyDigest with <see cref="TpmPolicyDigest.ExtendForSigned"/>
/// <b>before</b> creating the sealed object, seals a secret under that predicted <c>authPolicy</c>, then drives a
/// real signed authorization to the same digest and unseals — proving the host prediction and the simulator's
/// on-device fold agree end to end, not merely that the two happen to call the same formula.
/// </para>
/// <para>
/// The negative tests each isolate one rung of the check ladder (TPM 2.0 Library Part 3, Section 23.2.2): a
/// mismatched non-empty caller nonce, an expired deadline, a wrong-sized <c>cpHashA</c>, a cpHash latch conflict,
/// and a corrupted signature. Because the ladder runs nonceTPM → expiration → cpHashA → scheme/verification in
/// that order, several negative tests use a placeholder signature that is never actually reached.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorPolicySignedTests
{
    /// <summary>The policy session hash algorithm used throughout (independent of the signature's own scheme hash).</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA modulus size in bits used by the RSA/mixed-hash test.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The fixed secret sealed and recovered by the flagship flow test.</summary>
    private static byte[] SecretBytes { get; } = "Bind this secret to a TPM2_PolicySigned() authorization."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Flagship flow: predicts the policyDigest a PolicySigned authorization over an ECC authority key will
    /// produce, seals a secret under that prediction as the object's authPolicy, drives a real signed
    /// authorization through the production wire path to the same digest, and unseals — proving the host
    /// prediction and the on-device fold agree end to end.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedEccFlowSealsAndUnsealsUnderThePredictedPolicy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;
        byte[] authorityName = authorityKey.Name.Span.ToArray();
        byte[] policyRef = "wave-w2-policysigned-ref"u8.ToArray();

        //Predict the digest independently, BEFORE the sealed object exists, so its authPolicy is fixed to the
        //value a real, signature-verified PolicySigned authorization will later produce.
        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] authPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForSigned(zero, authorityName, policyRef, SessionAlg, authPolicy);

        uint policyHandle = 0;
        uint itemHandle = 0;
        try
        {
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy, noDa: true);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(createResult.IsSuccess, $"Create (seal under the PolicySigned-predicted policy) failed: '{createResult.ResponseCode}'.");

            using CreateResponse sealedObject = createResult.Value;

            using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
            using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
            using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
            using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
                tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");

            using LoadResponse loaded = loadResult.Value;
            itemHandle = loaded.ObjectHandle.Value;
            ReadOnlyMemory<byte>[] handleNames = [loaded.Name.Span.ToArray()];

            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            policyHandle = session.SessionHandle.Value;

            //The session's nonceTPM must be a real, per-session value: PolicySigned's aHash binds to it, so a
            //fixed zero placeholder would make every authority signature reusable across sessions.
            Assert.IsFalse(session.NonceTPM.IsEmpty, "A policy session's nonceTPM must be a real, non-placeholder value.");
            byte[] nonceTpm = session.NonceTPM.AsReadOnlySpan().ToArray();

            const int Expiration = 0;
            byte[] aHash = await ComputeAHashAsync(
                nonceTpm, Expiration, ReadOnlyMemory<byte>.Empty, policyRef, 32, CryptoTags.Sha256Digest, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using SignInput signInput = SignInput.ForEcdsa(authorityKey.ObjectHandle, aHash, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (authority over aHash) failed: '{signResult.ResponseCode}'.");

            using SignResponse signature = signResult.Value;
            using Signature p1363Signature = ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan(), pool);

            TpmResult<PolicySignedResponse> policySignedResult = await tpm.PolicySignedAsync(
                authorityHandle, policyHandle, nonceTpm, ReadOnlyMemory<byte>.Empty, policyRef, Expiration, p1363Signature.AsReadOnlyMemory(),
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(policySignedResult.IsSuccess, $"PolicySigned (ECDSA) failed: '{policySignedResult.ResponseCode}'.");

            using(PolicySignedResponse policySigned = policySignedResult.Value)
            {
                Assert.IsTrue(policySigned.PolicyTicket.IsNull(), "This wave's PolicySigned always frames a NULL ticket; the real mint is deferred.");
            }

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;
            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(authPolicy),
                "The simulator's policyDigest after PolicySigned must match the independently predicted ExtendForSigned value.");

            using TpmPolicySession policySession = TpmPolicySession.ForSession(policyHandle, SessionAlg, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);

            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(unsealResult.IsSuccess, $"Unseal gated on the PolicySigned digest failed: '{unsealResult.ResponseCode}'.");

            using UnsealResponse unsealed = unsealResult.Value;
            Assert.IsTrue(
                unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes),
                "The unsealed data must equal the secret sealed under the PolicySigned-predicted authPolicy.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, policyHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, authorityHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, parentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a trial session skips every parameter and signature check (Part 3, Section 23.3: "the TPM will
    /// not check the signature... as if a properly signed authorization was received") and folds the digest
    /// identically to the host prediction, even fed a placeholder signature that is never verified.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedTrialSessionPredictsTheSameDigestAsAHostPrediction()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;
        byte[] authorityName = authorityKey.Name.Span.ToArray();
        byte[] policyRef = "trial-parity-ref"u8.ToArray();
        byte[] placeholderSignature = new byte[64];

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicySignedResponse> policySignedResult = await tpm.PolicySignedAsync(
                authorityHandle, sessionHandle, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, policyRef, 0, placeholderSignature,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(policySignedResult.IsSuccess, $"PolicySigned (trial) failed: '{policySignedResult.ResponseCode}'.");
            policySignedResult.Value.Dispose();

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;

            int size = TpmPolicyDigest.Size(SessionAlg);
            byte[] predicted = new byte[size];
            Span<byte> zero = stackalloc byte[size];
            zero.Clear();
            _ = TpmPolicyDigest.ExtendForSigned(zero, authorityName, policyRef, SessionAlg, predicted);

            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                "A trial PolicySigned must fold the digest identically to the host ExtendForSigned prediction, without checking the (placeholder) signature.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a corrupted signature is rejected with <c>TPM_RC_SIGNATURE</c> on a real (non-trial) session
    /// (TPM 2.0 Library Part 3, Section 23.3).
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithCorruptedSignatureReturnsSignature()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;
        byte[] policyRef = "corrupted-signature-ref"u8.ToArray();

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;
            byte[] nonceTpm = session.NonceTPM.AsReadOnlySpan().ToArray();

            byte[] aHash = await ComputeAHashAsync(
                nonceTpm, 0, ReadOnlyMemory<byte>.Empty, policyRef, 32, CryptoTags.Sha256Digest, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using SignInput signInput = SignInput.ForEcdsa(authorityKey.ObjectHandle, aHash, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (authority over aHash) failed: '{signResult.ResponseCode}'.");

            using SignResponse signature = signResult.Value;

            //Flip one octet of the s component in a pooled scratch copy so the signature no longer verifies
            //against aHash; the r component and the framing stay intact.
            int sLength = signature.Signature.SignatureS!.AsReadOnlySpan().Length;
            using IMemoryOwner<byte> corruptedS = pool.Rent(sLength);
            signature.Signature.SignatureS!.AsReadOnlySpan().CopyTo(corruptedS.Memory.Span);
            corruptedS.Memory.Span[sLength - 1] ^= 0xFF;
            using Signature p1363Signature = ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), corruptedS.Memory.Span[..sLength], pool);

            TpmResult<PolicySignedResponse> policySignedResult = await tpm.PolicySignedAsync(
                authorityHandle, sessionHandle, nonceTpm, ReadOnlyMemory<byte>.Empty, policyRef, 0, p1363Signature.AsReadOnlyMemory(),
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(policySignedResult.IsSuccess, "A corrupted signature must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_SIGNATURE, policySignedResult.ResponseCode);
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a non-empty caller nonceTPM that does not match the session's retained nonce is rejected with
    /// <c>TPM_RC_NONCE</c>, before the (placeholder, never-reached) signature is ever verified (TPM 2.0 Library
    /// Part 3, Section 23.2.2).
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithMismatchedCallerNonceReturnsNonce()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;
        byte[] placeholderSignature = new byte[64];

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            byte[] wrongNonce = new byte[session.NonceTPM.Size];
            Array.Fill(wrongNonce, (byte)0xAB);
            Assert.IsFalse(wrongNonce.AsSpan().SequenceEqual(session.NonceTPM.AsReadOnlySpan()), "Test setup: the wrong nonce must actually differ.");

            TpmResult<PolicySignedResponse> policySignedResult = await tpm.PolicySignedAsync(
                authorityHandle, sessionHandle, wrongNonce, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, 0, placeholderSignature,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(policySignedResult.IsSuccess, "A mismatched non-empty caller nonce must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_NONCE, policySignedResult.ResponseCode);
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a positive expiration whose absolute (empty-nonce) deadline has already passed is rejected with
    /// <c>TPM_RC_EXPIRED</c>, ahead of the (placeholder, never-reached) signature verification (TPM 2.0 Library
    /// Part 3, Section 23.2.2). The simulator advances a large fixed quantum per command, so the deadline is
    /// already behind <c>state.Time</c> by the time <c>TPM2_PolicySigned()</c> itself is dispatched.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithExpiredDeadlineReturnsExpired()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool, clockAdvanceQuantumMs: 5000).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;
        byte[] placeholderSignature = new byte[64];

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            //Empty caller nonce: an absolute Time-base deadline of |expiration|*1000 ms, already exceeded because
            //StartAuthSession alone already advanced Time by the 5000ms quantum.
            TpmResult<PolicySignedResponse> policySignedResult = await tpm.PolicySignedAsync(
                authorityHandle, sessionHandle, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, 1, placeholderSignature,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(policySignedResult.IsSuccess, "An already-expired deadline must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_EXPIRED, policySignedResult.ResponseCode);
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a non-empty <c>cpHashA</c> whose size does not equal the session's digest width is rejected with
    /// <c>TPM_RC_SIZE</c>, ahead of the (placeholder, never-reached) signature verification (TPM 2.0 Library Part
    /// 3, Section 23.2.2).
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithWrongSizedCpHashAReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;
        byte[] placeholderSignature = new byte[64];
        byte[] wrongSizedCpHash = new byte[16];

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicySignedResponse> policySignedResult = await tpm.PolicySignedAsync(
                authorityHandle, sessionHandle, ReadOnlyMemory<byte>.Empty, wrongSizedCpHash, ReadOnlyMemory<byte>.Empty, 0, placeholderSignature,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(policySignedResult.IsSuccess, "A cpHashA of the wrong size must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, policySignedResult.ResponseCode);
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies the session's cpHash latch is first-writer-wins (TPM 2.0 Library Part 3, Section 23.2.4): a first,
    /// genuinely signature-verified PolicySigned latches <c>cpHashA</c>, and a second call on the same session with
    /// a different (but correctly sized) <c>cpHashA</c> is rejected with <c>TPM_RC_CPHASH</c> ahead of its own
    /// (placeholder, never-reached) signature verification.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedCpHashLatchConflictReturnsCpHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;

        byte[] firstCpHash = new byte[32];
        Array.Fill(firstCpHash, (byte)0x11);
        byte[] secondCpHash = new byte[32];
        Array.Fill(secondCpHash, (byte)0x22);
        byte[] placeholderSignature = new byte[64];

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;
            byte[] nonceTpm = session.NonceTPM.AsReadOnlySpan().ToArray();

            //First call: a genuine signature over aHash bound to firstCpHash, so the session actually latches it.
            byte[] firstAHash = await ComputeAHashAsync(
                nonceTpm, 0, firstCpHash, ReadOnlyMemory<byte>.Empty, 32, CryptoTags.Sha256Digest, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using SignInput signInput = SignInput.ForEcdsa(authorityKey.ObjectHandle, firstAHash, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (first aHash) failed: '{signResult.ResponseCode}'.");

            using SignResponse firstSignature = signResult.Value;
            using Signature firstP1363Signature = ConcatenateP1363(firstSignature.Signature.SignatureR!.AsReadOnlySpan(), firstSignature.Signature.SignatureS!.AsReadOnlySpan(), pool);

            TpmResult<PolicySignedResponse> firstPolicySignedResult = await tpm.PolicySignedAsync(
                authorityHandle, sessionHandle, nonceTpm, firstCpHash, ReadOnlyMemory<byte>.Empty, 0, firstP1363Signature.AsReadOnlyMemory(),
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(firstPolicySignedResult.IsSuccess, $"PolicySigned (latching cpHashA) failed: '{firstPolicySignedResult.ResponseCode}'.");
            firstPolicySignedResult.Value.Dispose();

            //Second call: a DIFFERENT cpHashA on the same session. The latch conflict is checked before signature
            //verification, so a placeholder signature is never actually reached.
            TpmResult<PolicySignedResponse> secondPolicySignedResult = await tpm.PolicySignedAsync(
                authorityHandle, sessionHandle, nonceTpm, secondCpHash, ReadOnlyMemory<byte>.Empty, 0, placeholderSignature,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(secondPolicySignedResult.IsSuccess, "A cpHashA conflicting with the session's latch must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_CPHASH, secondPolicySignedResult.ResponseCode);
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies an RSA authority key signing under RSASSA with a SHA-384 scheme hash succeeds against a policy
    /// session started with a SHA-256 policy hash — the three-hash-algorithm separation R-5 requires (aHash's
    /// H_authAlg, the session's own policy hash, and the ticket-HMAC hash — the last not reached this wave since
    /// no ticket is minted) are never conflated: <c>aHash</c> is built and verified under SHA-384, while the
    /// policyDigest fold that follows still runs under the session's SHA-256 policy hash.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedAcceptsAnRsaSignatureUnderAMixedSchemeHashAgainstTheSessionsPolicyHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateRsaAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;
        byte[] authorityName = authorityKey.Name.Span.ToArray();
        byte[] policyRef = "mixed-hash-ref"u8.ToArray();

        uint sessionHandle = 0;
        try
        {
            //The policy session's own hash algorithm (sizes the policyDigest fold) is SHA-256.
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;
            byte[] nonceTpm = session.NonceTPM.AsReadOnlySpan().ToArray();

            //aHash is built and signed under SHA-384 — H_authAlg, independent of the session's own SHA-256 policy hash.
            byte[] aHash = await ComputeAHashAsync(
                nonceTpm, 0, ReadOnlyMemory<byte>.Empty, policyRef, 48, CryptoTags.Sha384Digest, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using SignInput signInput = SignInput.ForRsaSsa(authorityKey.ObjectHandle, aHash, TpmAlgIdConstants.TPM_ALG_SHA384, pool);
            TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (RSASSA, SHA-384) failed: '{signResult.ResponseCode}'.");

            using SignResponse signature = signResult.Value;
            byte[] rsaSignature = signature.Signature.RsaSignature.Buffer.ToArray();

            TpmResult<PolicySignedResponse> policySignedResult = await tpm.PolicySignedAsync(
                authorityHandle, sessionHandle, nonceTpm, ReadOnlyMemory<byte>.Empty, policyRef, 0, rsaSignature,
                TpmAlgIdConstants.TPM_ALG_RSASSA, TpmAlgIdConstants.TPM_ALG_SHA384, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(policySignedResult.IsSuccess, $"PolicySigned (RSASSA, mixed SHA-384/SHA-256) failed: '{policySignedResult.ResponseCode}'.");
            policySignedResult.Value.Dispose();

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;

            //The digest FOLD still runs under the SESSION's own SHA-256 policy hash, never the SHA-384 scheme hash
            //aHash was built with.
            int size = TpmPolicyDigest.Size(SessionAlg);
            byte[] predicted = new byte[size];
            Span<byte> zero = stackalloc byte[size];
            zero.Clear();
            _ = TpmPolicyDigest.ExtendForSigned(zero, authorityName, policyRef, SessionAlg, predicted);

            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                "The policyDigest fold must use the session's own (SHA-256) policy hash, independent of the SHA-384 scheme hash aHash was built with.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Creates the deterministic ECC storage parent under the owner hierarchy and returns the response (the
    /// caller owns it and flushes <see cref="CreatePrimaryResponse.ObjectHandle"/>).
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
    /// Creates an ECC P-256 ECDSA/SHA-256 signing key under the owner hierarchy, used as PolicySigned's authObject.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response for the authority key.</returns>
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

    /// <summary>
    /// Creates an RSA-2048 signing key (NULL scheme, so the scheme/hash is chosen freely at TPM2_Sign() time)
    /// under the owner hierarchy, used as PolicySigned's authObject in the mixed-hash test.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response for the authority key.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaAuthorityKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Null, pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA-2048 authority key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Builds <c>aHash = H_authAlg(nonceTPM || expiration || cpHashA || policyRef)</c> (TPM 2.0 Library Part 3,
    /// Section 23.3, equation 13) through the registered async digest seam: raw TPM2B payload bytes only, no size
    /// prefixes, expiration as a 4-octet big-endian two's complement integer. Independent of
    /// <see cref="TpmPolicyDigest"/>, which computes an entirely different hash (the policyDigest fold).
    /// </summary>
    /// <param name="nonceTpm">The nonceTPM bytes.</param>
    /// <param name="expiration">The signed expiration.</param>
    /// <param name="cpHashA">The cpHashA bytes.</param>
    /// <param name="policyRef">The policyRef bytes.</param>
    /// <param name="hashLength">H_authAlg's digest width in bytes.</param>
    /// <param name="hashTag">H_authAlg's registered digest tag.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The computed aHash.</returns>
    private static async Task<byte[]> ComputeAHashAsync(
        ReadOnlyMemory<byte> nonceTpm, int expiration, ReadOnlyMemory<byte> cpHashA, ReadOnlyMemory<byte> policyRef,
        int hashLength, Tag hashTag, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        byte[] message = new byte[nonceTpm.Length + sizeof(int) + cpHashA.Length + policyRef.Length];
        var writer = new TpmWriter(message);
        writer.WriteBytes(nonceTpm.Span);
        writer.WriteInt32(expiration);
        writer.WriteBytes(cpHashA.Span);
        writer.WriteBytes(policyRef.Span);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            message, hashLength, hashTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Concatenates the ECDSA r and s components into the IEEE P1363 <c>r ‖ s</c> form, left-padding each to the
    /// P-256 field width (32 bytes).
    /// </summary>
    /// <param name="r">The signature's r component.</param>
    /// <param name="s">The signature's s component.</param>
    /// <param name="pool">The memory pool backing the returned signature.</param>
    /// <returns>The concatenated, fixed-width P1363 signature as a pooled carrier the caller disposes.</returns>
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

    /// <summary>
    /// Creates a response codec registry covering the executor-driven commands these tests issue directly (the
    /// policy assertion device verbs run through their own self-contained extension-method registries).
    /// </summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);

        return registry;
    }

    /// <summary>
    /// Flushes a transient object or session handle when one is present (non-zero), ignoring the result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="handle">The handle to flush, or 0 when none was acquired.</param>
    private async Task FlushIfPresentAsync(TpmDevice tpm, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        _ = await tpm.FlushContextAsync(handle, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers it
    /// on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="clockAdvanceQuantumMs">The fixed per-command clock advance, in milliseconds.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, ulong clockAdvanceQuantumMs = TpmSimulatorState.DefaultClockAdvanceQuantumMs)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-policysigned",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(),
            clockAdvanceQuantumMs: clockAdvanceQuantumMs);
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
}
