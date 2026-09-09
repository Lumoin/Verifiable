using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
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
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_PolicySigned()</c> against the in-house behavioural <see cref="TpmSimulator"/> — entirely
/// in-process, with no external assets — through the same production command path the production code uses (the
/// <see cref="TpmDeviceExtensions"/> policy commands, <see cref="TpmCommandExecutor"/>, and the real
/// command/response codecs). Each test starts a real or trial policy session, builds <c>aHash</c> from the
/// session's real, retained nonceTPM, signs it through the production <c>TPM2_Sign()</c> wire path, and drives
/// <c>TPM2_PolicySigned()</c> itself over the wire (TPM 2.0 Library Part 3, clause 23.3).
/// </summary>
/// <remarks>
/// <para>
/// The flagship test independently predicts the policyDigest with <see cref="TpmPolicyDigest.ExtendForSigned"/>
/// <b>before</b> creating the sealed object, seals a secret under that predicted <c>authPolicy</c>, then drives a
/// real signed authorization to the same digest and unseals — proving the host prediction and the simulator's
/// on-device fold agree end to end, not merely that the two happen to call the same formula.
/// </para>
/// <para>
/// The negative tests each isolate one rung of the check ladder (TPM 2.0 Library Part 3, clause 23.2.2): a
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

    /// <summary>
    /// A transient handle value naming no loaded object in a freshly-brought-operational simulator — stands in
    /// for <c>authObject</c> in tests whose refusal fires at the parse, before either handle resolves.
    /// </summary>
    private const uint ArbitraryAuthObjectHandle = 0x8000_0001;

    /// <summary>The <c>policySession</c> counterpart of <see cref="ArbitraryAuthObjectHandle"/>, distinct from it.</summary>
    private const uint ArbitraryPolicySessionHandle = 0x0300_0001;

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
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;
        byte[] authorityName = authorityKey.Name.Span.ToArray();
        byte[] policyRef = "policysigned-ref"u8.ToArray();

        //Predict the digest independently, BEFORE the sealed object exists, so its authPolicy is fixed to the
        //value a real, signature-verified PolicySigned authorization will later produce.
        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] authPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForSigned(zero, authorityName, policyRef, SessionAlg, authPolicy, pool);

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
                Assert.IsTrue(policySigned.PolicyTicket.IsNull, "PolicySigned always frames a NULL ticket; the real mint is deferred.");
            }

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;
            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(authPolicy),
                "The simulator's policyDigest after PolicySigned must match the independently predicted ExtendForSigned value.");

            using TpmPolicySession policySession = TpmPolicySession.ForSession(policyHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);
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
    /// Verifies a trial session skips every parameter and signature check (Part 3, clause 23.3: "the TPM will
    /// not check the signature... as if a properly signed authorization was received") and folds the digest
    /// identically to the host prediction, even fed a placeholder signature that is never verified.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedTrialSessionPredictsTheSameDigestAsAHostPrediction()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
            _ = TpmPolicyDigest.ExtendForSigned(zero, authorityName, policyRef, SessionAlg, predicted, pool);

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
    /// (TPM 2.0 Library Part 3, clause 23.3).
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithCorruptedSignatureReturnsSignature()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIGNATURE, 4), policySignedResult.ResponseCode, "A corrupted signature (auth) must be refused with TPM_RC_SIGNATURE at auth, parameter 5 of Table 144.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a non-empty caller nonceTPM that does not match the session's retained nonce is rejected with
    /// <c>TPM_RC_VALUE</c>, before the (placeholder, never-reached) signature is ever verified. TPM 2.0 Library
    /// Part 3, clause 23.2.2, printed page 209, rule 1 names the code: "nonceTPM - If this parameter is not the
    /// Empty Buffer, and it does not match policySession&#8594;nonceTPM, then the TPM shall return
    /// TPM_RC_VALUE."
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithMismatchedCallerNonceReturnsValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), policySignedResult.ResponseCode, "Table 144: nonceTPM is TPM2_PolicySigned()'s first parameter (parameter 1); a mismatched non-empty caller nonce is parameter-encoded TPM_RC_VALUE at index 0.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a positive expiration whose absolute (empty-nonce) deadline has already passed is rejected with
    /// <c>TPM_RC_EXPIRED</c>, ahead of the (placeholder, never-reached) signature verification (TPM 2.0 Library
    /// Part 3, clause 23.2.2). The simulator advances a large fixed quantum per command, so the deadline is
    /// already behind <c>state.Time</c> by the time <c>TPM2_PolicySigned()</c> itself is dispatched.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithExpiredDeadlineReturnsExpired()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, clockAdvanceQuantumMs: 5000).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_EXPIRED, 3), policySignedResult.ResponseCode, "Table 144: expiration is TPM2_PolicySigned()'s fourth parameter (parameter 4); an already-expired deadline is parameter-encoded TPM_RC_EXPIRED at index 3.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a non-empty <c>cpHashA</c> whose size does not equal the session's digest width is rejected with
    /// <c>TPM_RC_SIZE</c>, ahead of the (placeholder, never-reached) signature verification (TPM 2.0 Library Part
    /// 3, clause 23.2.2).
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithWrongSizedCpHashAReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), policySignedResult.ResponseCode, "Table 144: cpHashA is TPM2_PolicySigned()'s second parameter (parameter 2); a cpHashA of the wrong size is parameter-encoded TPM_RC_SIZE at index 1.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies the session's cpHash latch is first-writer-wins (TPM 2.0 Library Part 3, clause 23.2.4): a first,
    /// genuinely signature-verified PolicySigned latches <c>cpHashA</c>, and a second call on the same session with
    /// a different (but correctly sized) <c>cpHashA</c> is rejected with <c>TPM_RC_CPHASH</c> ahead of its own
    /// (placeholder, never-reached) signature verification.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedCpHashLatchConflictReturnsCpHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
    /// A signature that fails to verify must NOT latch <c>cpHashA</c> onto the session (TPM 2.0 Library Part 3,
    /// clause 23.2.4's latch is part of a SUCCESSFUL <c>PolicyUpdate()</c>, not a pre-verification side effect
    /// of merely proposing a cpHashA): a first call carrying a non-empty <c>cpHashA</c> but a signature that does
    /// not verify is rejected with <c>TPM_RC_SIGNATURE</c>, and a SECOND, genuinely verified call on the SAME
    /// session with a DIFFERENT <c>cpHashA</c> must then succeed — proving the failed first call left the
    /// session's cpHash latch empty rather than poisoning it.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedFailedVerificationLeavesTheSessionCpHashLatchEmpty()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;

        byte[] firstCpHash = new byte[32];
        Array.Fill(firstCpHash, (byte)0x11);
        byte[] secondCpHash = new byte[32];
        Array.Fill(secondCpHash, (byte)0x22);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;
            byte[] nonceTpm = session.NonceTPM.AsReadOnlySpan().ToArray();

            //First call: a non-empty cpHashA, but a genuine signature over that same aHash with one octet of its
            //S component flipped, so it fails to verify (mirrors PolicySignedWithCorruptedSignatureReturnsSignature's
            //safe corruption technique rather than an all-zero placeholder, which risks the ECC backend rejecting
            //a structurally degenerate r=0/s=0 signature before this test can observe the intended RC). Must fail
            //WITHOUT latching firstCpHash onto the session.
            byte[] firstAHash = await ComputeAHashAsync(
                nonceTpm, 0, firstCpHash, ReadOnlyMemory<byte>.Empty, 32, CryptoTags.Sha256Digest, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using TpmPasswordSession firstSignAuth = TpmPasswordSession.CreateEmpty(pool);
            using SignInput firstSignInput = SignInput.ForEcdsa(authorityKey.ObjectHandle, firstAHash, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> firstSignResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, firstSignInput, [firstSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(firstSignResult.IsSuccess, $"TPM2_Sign (first aHash) failed: '{firstSignResult.ResponseCode}'.");

            using SignResponse firstSignature = firstSignResult.Value;
            int firstSLength = firstSignature.Signature.SignatureS!.AsReadOnlySpan().Length;
            using IMemoryOwner<byte> corruptedS = pool.Rent(firstSLength);
            firstSignature.Signature.SignatureS!.AsReadOnlySpan().CopyTo(corruptedS.Memory.Span);
            corruptedS.Memory.Span[firstSLength - 1] ^= 0xFF;
            using Signature corruptedFirstSignature = ConcatenateP1363(firstSignature.Signature.SignatureR!.AsReadOnlySpan(), corruptedS.Memory.Span[..firstSLength], pool);

            TpmResult<PolicySignedResponse> firstResult = await tpm.PolicySignedAsync(
                authorityHandle, sessionHandle, nonceTpm, firstCpHash, ReadOnlyMemory<byte>.Empty, 0, corruptedFirstSignature.AsReadOnlyMemory(),
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(firstResult.IsSuccess, "A signature that does not verify must be rejected.");
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIGNATURE, 4), firstResult.ResponseCode, "A signature that does not verify (auth) must be refused with TPM_RC_SIGNATURE at auth, parameter 5 of Table 144.");

            //Second call, same session: a genuine signature over a DIFFERENT cpHashA. If the failed first call
            //had latched firstCpHash, this would be rejected with TPM_RC_CPHASH instead of succeeding.
            byte[] secondAHash = await ComputeAHashAsync(
                nonceTpm, 0, secondCpHash, ReadOnlyMemory<byte>.Empty, 32, CryptoTags.Sha256Digest, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using SignInput signInput = SignInput.ForEcdsa(authorityKey.ObjectHandle, secondAHash, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (second aHash) failed: '{signResult.ResponseCode}'.");

            using SignResponse secondSignature = signResult.Value;
            using Signature secondP1363Signature = ConcatenateP1363(secondSignature.Signature.SignatureR!.AsReadOnlySpan(), secondSignature.Signature.SignatureS!.AsReadOnlySpan(), pool);

            TpmResult<PolicySignedResponse> secondResult = await tpm.PolicySignedAsync(
                authorityHandle, sessionHandle, nonceTpm, secondCpHash, ReadOnlyMemory<byte>.Empty, 0, secondP1363Signature.AsReadOnlyMemory(),
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(secondResult.IsSuccess, $"PolicySigned with a different cpHashA after a failed verification must succeed: '{secondResult.ResponseCode}'.");
            secondResult.Value.Dispose();
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies an RSA authority key signing under RSASSA with a SHA-384 scheme hash succeeds against a policy
    /// session started with a SHA-256 policy hash — the three-hash-algorithm separation this session enforces (aHash's
    /// H_authAlg, the session's own policy hash, and the ticket-HMAC hash — the last not reached here since
    /// no ticket is minted) are never conflated: <c>aHash</c> is built and verified under SHA-384, while the
    /// policyDigest fold that follows still runs under the session's SHA-256 policy hash.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedAcceptsAnRsaSignatureUnderAMixedSchemeHashAgainstTheSessionsPolicyHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
            _ = TpmPolicyDigest.ExtendForSigned(zero, authorityName, policyRef, SessionAlg, predicted, pool);

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
    /// Verifies a negative <c>expiration</c> on a real (non-trial) session mints a genuine
    /// <c>TPMT_TK_AUTH</c> — tag <c>TPM_ST_AUTH_SIGNED</c>, the authority key's own hierarchy, a non-empty
    /// SHA-256-width digest, and an 8-byte <c>TPM2B_TIMEOUT</c> — instead of the NULL ticket a non-negative
    /// expiration produces (TPM 2.0 Library Part 3, clause 23.2.5). An empty caller nonceTPM makes the
    /// deadline absolute (Time-base, not session-relative), so the ticket's bit 63 (expires-on-reset,
    /// clause 10.3.10) must be set.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithNegativeExpirationAndEmptyNonceMintsARealTicketThatExpiresOnReset()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;
        byte[] policyRef = "ticket-mint-empty-nonce-ref"u8.ToArray();

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            byte[] aHash = await ComputeAHashAsync(
                ReadOnlyMemory<byte>.Empty, -3600, ReadOnlyMemory<byte>.Empty, policyRef, 32, CryptoTags.Sha256Digest, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using SignInput signInput = SignInput.ForEcdsa(authorityKey.ObjectHandle, aHash, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (authority over aHash) failed: '{signResult.ResponseCode}'.");

            using SignResponse signature = signResult.Value;
            using Signature p1363Signature = ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan(), pool);

            TpmResult<PolicySignedResponse> policySignedResult = await tpm.PolicySignedAsync(
                authorityHandle, sessionHandle, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, policyRef, -3600, p1363Signature.AsReadOnlyMemory(),
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(policySignedResult.IsSuccess, $"PolicySigned (negative expiration) failed: '{policySignedResult.ResponseCode}'.");

            using PolicySignedResponse policySigned = policySignedResult.Value;
            Assert.IsFalse(policySigned.PolicyTicket.IsNull, "A negative expiration on a real session must mint a real ticket, not a NULL ticket.");
            Assert.AreEqual(TpmStConstants.TPM_ST_AUTH_SIGNED, policySigned.PolicyTicket.Tag, "The ticket tag must be TPM_ST_AUTH_SIGNED.");
            Assert.AreEqual(TpmiRhHierarchy.Owner, policySigned.PolicyTicket.Hierarchy, "The ticket hierarchy must be the authority key's own hierarchy.");
            int ticketDigestLength = policySigned.PolicyTicket.Digest.Length;
            int timeoutLength = policySigned.Timeout.Length;
            Assert.AreEqual(32, ticketDigestLength, "The ticket digest is a SHA-256 HMAC.");
            Assert.AreEqual(8, timeoutLength, "A real ticket's TPM2B_TIMEOUT is exactly 8 bytes.");

            ulong rawTimeout = BinaryPrimitives.ReadUInt64BigEndian(policySigned.Timeout);
            Assert.AreNotEqual(0UL, rawTimeout & (1UL << 63), "An empty caller nonceTPM (absolute deadline) must set the expires-on-reset bit (bit 63).");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies the same real-ticket mint as
    /// <see cref="PolicySignedWithNegativeExpirationAndEmptyNonceMintsARealTicketThatExpiresOnReset"/>, but with
    /// the session's real (non-empty) nonceTPM supplied — a session-relative deadline — so bit 63
    /// (expires-on-reset) must be CLEAR: the nonceTPM presence, not the sign of expiration alone, decides that
    /// bit (TPM 2.0 Library Part 2, clause 10.3.10).
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithNegativeExpirationAndNonEmptyNonceMintsARealTicketThatDoesNotExpireOnReset()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;
        byte[] policyRef = "ticket-mint-real-nonce-ref"u8.ToArray();

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
                nonceTpm, -3600, ReadOnlyMemory<byte>.Empty, policyRef, 32, CryptoTags.Sha256Digest, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using SignInput signInput = SignInput.ForEcdsa(authorityKey.ObjectHandle, aHash, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (authority over aHash) failed: '{signResult.ResponseCode}'.");

            using SignResponse signature = signResult.Value;
            using Signature p1363Signature = ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan(), pool);

            TpmResult<PolicySignedResponse> policySignedResult = await tpm.PolicySignedAsync(
                authorityHandle, sessionHandle, nonceTpm, ReadOnlyMemory<byte>.Empty, policyRef, -3600, p1363Signature.AsReadOnlyMemory(),
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(policySignedResult.IsSuccess, $"PolicySigned (negative expiration) failed: '{policySignedResult.ResponseCode}'.");

            using PolicySignedResponse policySigned = policySignedResult.Value;
            Assert.IsFalse(policySigned.PolicyTicket.IsNull, "A negative expiration on a real session must mint a real ticket, not a NULL ticket.");
            int timeoutLength = policySigned.Timeout.Length;
            Assert.AreEqual(8, timeoutLength, "A real ticket's TPM2B_TIMEOUT is exactly 8 bytes.");

            ulong rawTimeout = BinaryPrimitives.ReadUInt64BigEndian(policySigned.Timeout);
            Assert.AreEqual(0UL, rawTimeout & (1UL << 63), "A non-empty caller nonceTPM (session-relative deadline) must leave the expires-on-reset bit (bit 63) clear.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a positive (not yet expired) <c>expiration</c> on a real session still returns a NULL ticket:
    /// only a NEGATIVE expiration requests a ticket (TPM 2.0 Library Part 3, clause 23.2.5) — the deadline
    /// magnitude is identical either way, so this isolates the sign as the sole "mint a ticket" signal.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithPositiveExpirationOnARealSessionStillReturnsANullTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;
        byte[] policyRef = "ticket-mint-positive-expiration-ref"u8.ToArray();

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            //A large positive expiration (absolute Time-base deadline, far in the future) never trips
            //TPM_RC_EXPIRED, isolating the "no ticket" outcome from the separate expired-deadline ladder rung.
            byte[] aHash = await ComputeAHashAsync(
                ReadOnlyMemory<byte>.Empty, 3600, ReadOnlyMemory<byte>.Empty, policyRef, 32, CryptoTags.Sha256Digest, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using SignInput signInput = SignInput.ForEcdsa(authorityKey.ObjectHandle, aHash, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (authority over aHash) failed: '{signResult.ResponseCode}'.");

            using SignResponse signature = signResult.Value;
            using Signature p1363Signature = ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan(), pool);

            TpmResult<PolicySignedResponse> policySignedResult = await tpm.PolicySignedAsync(
                authorityHandle, sessionHandle, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, policyRef, 3600, p1363Signature.AsReadOnlyMemory(),
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(policySignedResult.IsSuccess, $"PolicySigned (positive expiration) failed: '{policySignedResult.ResponseCode}'.");

            using PolicySignedResponse policySigned = policySignedResult.Value;
            Assert.IsTrue(policySigned.PolicyTicket.IsNull, "A non-negative expiration must return a NULL ticket, even when the deadline itself is valid and far in the future.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>auth.sigAlg</c> of <c>TPM_ALG_NULL</c> is refused with <c>TPM_RC_SCHEME</c> at the wire, before
    /// either handle resolves — the same refusal <c>TPM2_VerifySignature()</c>'s <c>signature</c> parameter
    /// enforces, and for the same reason: <c>TPMT_SIGNATURE.sigAlg</c> is itself marked
    /// <c>+TPMI_ALG_SIG_SCHEME</c> (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 2: Structures, clause 11.3.6, Table 219), but a NULL selector picks
    /// no <c>TPMU_SIGNATURE</c> member at all, and Table 219's own note requires <c>[sigAlg]signature</c> to be
    /// "the actual signature information" — <c>auth</c> needs a genuine signature to authorize the session.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithNullSigAlgReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] body = BuildSigAlgOnlyBody(TpmAlgIdConstants.TPM_ALG_NULL);
        TpmRcConstants code = await SubmitPolicySignedCommandAsync(simulator, pool, ArbitraryAuthObjectHandle, ArbitraryPolicySessionHandle, body).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SCHEME, 4), code,
            "Table 144: auth is TPM2_PolicySigned()'s fifth parameter (index 4); a NULL auth.sigAlg must be refused there at the wire (Table 219).");
    }

    /// <summary>
    /// A <c>auth.sigAlg</c> naming an algorithm that is not a signing scheme at all is refused with
    /// <c>TPM_RC_SCHEME</c> (TPM 2.0 Library Part 2, Structures, clause 11.3.6, Table 219).
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithUnsupportedSigAlgReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] body = BuildSigAlgOnlyBody(TpmAlgIdConstants.TPM_ALG_SHA256);
        TpmRcConstants code = await SubmitPolicySignedCommandAsync(simulator, pool, ArbitraryAuthObjectHandle, ArbitraryPolicySessionHandle, body).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SCHEME, 4), code,
            "Table 144: auth is TPM2_PolicySigned()'s fifth parameter (index 4); a sigAlg naming no signing scheme at all must be refused there (Table 219).");
    }

    /// <summary>
    /// An ECDSA <c>signatureR</c> declaring more than <see cref="Tpm2bEccParameter.MaxSize"/> is refused with
    /// <c>TPM_RC_SIZE</c> — the same bound <c>TPM2_VerifySignature()</c> enforces (TPM 2.0 Library Part 2,
    /// clause 11.3.2, Table 214's <c>signatureR</c>, itself a <c>TPM2B_ECC_PARAMETER</c>, clause 11.2.5.1,
    /// Table 197) — even though the parse resolves neither handle.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithSignatureROverBoundReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] body = BuildEcdsaSignatureBody(
            TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256,
            declaredRSize: Tpm2bEccParameter.MaxSize + 1, actualRBytesProvided: Tpm2bEccParameter.MaxSize + 1,
            declaredSSize: 32, actualSBytesProvided: 32);
        TpmRcConstants code = await SubmitPolicySignedCommandAsync(simulator, pool, ArbitraryAuthObjectHandle, ArbitraryPolicySessionHandle, body).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 4), code, "auth is TPM2_PolicySigned()'s fifth parameter (Table 144, index 4); signatureR over Tpm2bEccParameter.MaxSize must be parameter-encoded TPM_RC_SIZE (Table 214/197).");
    }

    /// <summary>The <c>signatureS</c> counterpart of <see cref="PolicySignedWithSignatureROverBoundReturnsSize"/>.</summary>
    [TestMethod]
    public async Task PolicySignedWithSignatureSOverBoundReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] body = BuildEcdsaSignatureBody(
            TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256,
            declaredRSize: 32, actualRBytesProvided: 32,
            declaredSSize: Tpm2bEccParameter.MaxSize + 1, actualSBytesProvided: Tpm2bEccParameter.MaxSize + 1);
        TpmRcConstants code = await SubmitPolicySignedCommandAsync(simulator, pool, ArbitraryAuthObjectHandle, ArbitraryPolicySessionHandle, body).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 4), code, "auth is TPM2_PolicySigned()'s fifth parameter (Table 144, index 4); signatureS over Tpm2bEccParameter.MaxSize must be parameter-encoded TPM_RC_SIZE (Table 214/197).");
    }

    /// <summary>
    /// An RSA <c>rsaSignature</c> declaring more than <see cref="Tpm2bPublicKeyRsa.MaxRsaKeyBytes"/> is refused
    /// with <c>TPM_RC_SIZE</c> (TPM 2.0 Library Part 2, clause 11.3.1, Table 212's <c>sig</c>, itself a
    /// <c>TPM2B_PUBLIC_KEY_RSA</c>, clause 11.2.4.6, Table 194).
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithRsaSignatureOverBoundReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] body = BuildRsaSignatureBody(
            TpmAlgIdConstants.TPM_ALG_RSASSA, TpmAlgIdConstants.TPM_ALG_SHA256,
            declaredSigSize: Tpm2bPublicKeyRsa.MaxRsaKeyBytes + 1, actualSigBytesProvided: Tpm2bPublicKeyRsa.MaxRsaKeyBytes + 1);
        TpmRcConstants code = await SubmitPolicySignedCommandAsync(simulator, pool, ArbitraryAuthObjectHandle, ArbitraryPolicySessionHandle, body).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 4), code, "auth is TPM2_PolicySigned()'s fifth parameter (Table 144, index 4); rsaSignature over Tpm2bPublicKeyRsa.MaxRsaKeyBytes must be parameter-encoded TPM_RC_SIZE (Table 212/194).");
    }

    /// <summary>
    /// A <c>signatureR</c> that is BOTH over <see cref="Tpm2bEccParameter.MaxSize"/> AND truncated is refused
    /// with <c>TPM_RC_SIZE</c>, not <c>TPM_RC_INSUFFICIENT</c> — bound-before-truncation, the same order
    /// <see cref="TpmInHouseSimulatorVerifySignatureTests.VerifySignatureWithOverBoundAndTruncatedSignatureRReturnsSize"/>
    /// pins for <c>TPM2_VerifySignature()</c>.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithOverBoundAndTruncatedSignatureRReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] body = BuildEcdsaSignatureBody(
            TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256,
            declaredRSize: Tpm2bEccParameter.MaxSize + 68, actualRBytesProvided: 10,
            declaredSSize: 0, actualSBytesProvided: 0);
        TpmRcConstants code = await SubmitPolicySignedCommandAsync(simulator, pool, ArbitraryAuthObjectHandle, ArbitraryPolicySessionHandle, body).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 4), code, "auth is TPM2_PolicySigned()'s fifth parameter (Table 144, index 4); an over-bound signatureR is parameter-encoded TPM_RC_SIZE even when the frame is also too short to supply it.");
    }

    /// <summary>
    /// The within-bound complement of <see cref="PolicySignedWithOverBoundAndTruncatedSignatureRReturnsSize"/>,
    /// mirroring
    /// <see cref="TpmInHouseSimulatorVerifySignatureTests.VerifySignatureWithWithinBoundTruncatedSignatureRReturnsInsufficient"/>:
    /// a <c>signatureR</c> declared WITHIN <see cref="Tpm2bEccParameter.MaxSize"/> but whose frame carries fewer
    /// octets than declared is refused with <c>TPM_RC_INSUFFICIENT</c>, not <c>TPM_RC_SIZE</c>.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithWithinBoundTruncatedSignatureRReturnsInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] body = BuildEcdsaSignatureBody(
            TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256,
            declaredRSize: 32, actualRBytesProvided: 10,
            declaredSSize: 0, actualSBytesProvided: 0);
        TpmRcConstants code = await SubmitPolicySignedCommandAsync(simulator, pool, ArbitraryAuthObjectHandle, ArbitraryPolicySessionHandle, body).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 4), code,
            "auth is TPM2_PolicySigned()'s fifth parameter (Table 144, index 4); a within-bound signatureR whose frame is too short to supply it is parameter-encoded TPM_RC_INSUFFICIENT, not TPM_RC_SIZE.");
    }

    /// <summary>
    /// The <c>TPM2_PolicySigned()</c> counterpart of
    /// <see cref="TpmInHouseSimulatorVerifySignatureTests.VerifySignatureWithOddCombinedSignatureRAndSLengthDoesNotReturnSize"/>:
    /// an ECDSA <c>signatureR</c>/<c>signatureS</c> pair whose independently-bounded, independently-supplied
    /// lengths combine to an ODD total is accepted at the wire, not refused with <c>TPM_RC_SIZE</c> — Table 214
    /// relates neither field's size to the other — so the parse reaches <c>policySession</c> (the 2nd handle in
    /// the handle area, index 1, checked before <c>authObject</c>), which is not loaded and answers
    /// <c>TPM_RC_REFERENCE_H1</c> (TPM 2.0 Library Part 3, clause 5.4, step 2.4).
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithOddCombinedSignatureRAndSLengthDoesNotReturnSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] body = BuildEcdsaSignatureBody(
            TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256,
            declaredRSize: 32, actualRBytesProvided: 32,
            declaredSSize: 31, actualSBytesProvided: 31);
        TpmRcConstants code = await SubmitPolicySignedCommandAsync(simulator, pool, ArbitraryAuthObjectHandle, ArbitraryPolicySessionHandle, body).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_REFERENCE_H1, code,
            "An ECDSA signature whose r and s independently-supplied lengths combine to an odd total must parse cleanly, reaching the unloaded policySession (index 1) check, TPM_RC_REFERENCE_H1 (TPM 2.0 Library Part 3, clause 5.4, step 2.4), rather than being refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// A trial session with a genuinely non-empty, in-bound signature skips ALL signature verification (TPM 2.0
    /// Library Part 3, clause 23.3) and still folds the digest, exactly as
    /// <see cref="PolicySignedTrialSessionPredictsTheSameDigestAsAHostPrediction"/> proves with a placeholder —
    /// and, against an ABSOLUTE metered-pool baseline, the parsed <c>TpmtSignature</c> carrier is released by the
    /// trial arm rather than leaking a pinned rental it never verifies.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedTrialSessionWithNonEmptySignatureBalancesThePool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;
        byte[] policyRef = "trial-pool-balance-ref"u8.ToArray();
        byte[] nonEmptySignature = new byte[64];
        Array.Fill(nonEmptySignature, (byte)0x5A);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            long baseline = trackingPool.OutstandingCount;

            TpmResult<PolicySignedResponse> policySignedResult = await tpm.PolicySignedAsync(
                authorityHandle, sessionHandle, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, policyRef, 0, nonEmptySignature,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(policySignedResult.IsSuccess, $"PolicySigned (trial, non-empty signature) failed: '{policySignedResult.ResponseCode}'.");
            policySignedResult.Value.Dispose();

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The trial arm must release the parsed, non-empty TpmtSignature carrier — it verifies no signature at all.");
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
    /// clause 23.3, equation 13) through the registered async digest seam: raw TPM2B payload bytes only, no size
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
    /// Hand-frames a <c>TPM2_PolicySigned()</c> command whose <c>auth</c> (<c>TPMT_SIGNATURE</c>) body is
    /// supplied verbatim — letting a caller express a declared/actual TPM2B size mismatch or an over-bound
    /// declared size that <see cref="TpmDeviceExtensions.PolicySignedAsync"/>'s typed parameters cannot. No
    /// authorization area: neither <c>authObject</c> nor <c>policySession</c> requires authorization (TPM 2.0
    /// Library Part 3, Table 144), the same as <c>TPM2_VerifySignature()</c>. nonceTPM, cpHashA and policyRef are
    /// framed empty and expiration zero, since these tests only probe the trailing signature body.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authObject">The <c>authObject</c> handle value.</param>
    /// <param name="policySession">The <c>policySession</c> handle value.</param>
    /// <param name="signatureBody">The already-marshaled <c>TPMT_SIGNATURE</c> body (sigAlg, and whatever follows it), verbatim.</param>
    /// <param name="length">The framed command's total length.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FramePolicySignedCommand(
        BaseMemoryPool pool, uint authObject, uint policySession, ReadOnlySpan<byte> signatureBody, out int length)
    {
        length = TpmHeader.HeaderSize + 2 * sizeof(uint) + 3 * sizeof(ushort) + sizeof(int) + signatureBody.Length;
        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_PolicySigned);
            header.WriteTo(ref writer);
            writer.WriteUInt32(authObject);
            writer.WriteUInt32(policySession);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteInt32(0);
            writer.WriteBytes(signatureBody);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_PolicySigned()</c> built by <see cref="FramePolicySignedCommand"/> straight
    /// to the simulator (bypassing <see cref="TpmDeviceExtensions.PolicySignedAsync"/>) and yields the response
    /// code.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authObject">The <c>authObject</c> handle value.</param>
    /// <param name="policySession">The <c>policySession</c> handle value.</param>
    /// <param name="signatureBody">The already-marshaled <c>TPMT_SIGNATURE</c> body, verbatim.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitPolicySignedCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint authObject, uint policySession, byte[] signatureBody)
    {
        using IMemoryOwner<byte> commandOwner = FramePolicySignedCommand(pool, authObject, policySession, signatureBody, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>Builds a <c>TPMT_SIGNATURE</c> body carrying only the <c>sigAlg</c> selector — enough to probe the wire-level scheme gate, which refuses before reading anything past it.</summary>
    /// <param name="sigAlg">The selector value to write.</param>
    /// <returns>The two-octet body.</returns>
    private static byte[] BuildSigAlgOnlyBody(TpmAlgIdConstants sigAlg)
    {
        byte[] body = new byte[sizeof(ushort)];
        var writer = new TpmWriter(body);
        writer.WriteUInt16((ushort)sigAlg);

        return body;
    }

    /// <summary>
    /// Builds an ECDSA <c>TPMT_SIGNATURE</c> body: sigAlg, hashAlg, then signatureR and signatureS each as an
    /// independently declared/actual TPM2B pair.
    /// </summary>
    /// <param name="sigAlg">The signature algorithm selector.</param>
    /// <param name="hashAlg">The hash algorithm carried inside the member.</param>
    /// <param name="declaredRSize">signatureR's declared TPM2B size.</param>
    /// <param name="actualRBytesProvided">The octets the frame actually carries for signatureR.</param>
    /// <param name="declaredSSize">signatureS's declared TPM2B size.</param>
    /// <param name="actualSBytesProvided">The octets the frame actually carries for signatureS.</param>
    /// <returns>The marshaled body.</returns>
    private static byte[] BuildEcdsaSignatureBody(
        TpmAlgIdConstants sigAlg, TpmAlgIdConstants hashAlg,
        int declaredRSize, int actualRBytesProvided, int declaredSSize, int actualSBytesProvided)
    {
        byte[] body = new byte[2 * sizeof(ushort) + sizeof(ushort) + actualRBytesProvided + sizeof(ushort) + actualSBytesProvided];
        var writer = new TpmWriter(body);
        writer.WriteUInt16((ushort)sigAlg);
        writer.WriteUInt16((ushort)hashAlg);
        writer.WriteUInt16((ushort)declaredRSize);
        if(actualRBytesProvided > 0)
        {
            writer.WriteBytes(new byte[actualRBytesProvided]);
        }

        writer.WriteUInt16((ushort)declaredSSize);
        if(actualSBytesProvided > 0)
        {
            writer.WriteBytes(new byte[actualSBytesProvided]);
        }

        return body;
    }

    /// <summary>
    /// The RSA counterpart of <see cref="BuildEcdsaSignatureBody"/>: sigAlg, hashAlg, then the single
    /// <c>rsaSignature</c> TPM2B with an independently declared/actual size.
    /// </summary>
    /// <param name="sigAlg">The signature algorithm selector (RSASSA or RSAPSS).</param>
    /// <param name="hashAlg">The hash algorithm carried inside the member.</param>
    /// <param name="declaredSigSize">rsaSignature's declared TPM2B size.</param>
    /// <param name="actualSigBytesProvided">The octets the frame actually carries for rsaSignature.</param>
    /// <returns>The marshaled body.</returns>
    private static byte[] BuildRsaSignatureBody(TpmAlgIdConstants sigAlg, TpmAlgIdConstants hashAlg, int declaredSigSize, int actualSigBytesProvided)
    {
        byte[] body = new byte[2 * sizeof(ushort) + sizeof(ushort) + actualSigBytesProvided];
        var writer = new TpmWriter(body);
        writer.WriteUInt16((ushort)sigAlg);
        writer.WriteUInt16((ushort)hashAlg);
        writer.WriteUInt16((ushort)declaredSigSize);
        if(actualSigBytesProvided > 0)
        {
            writer.WriteBytes(new byte[actualSigBytesProvided]);
        }

        return body;
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
            clockAdvanceQuantumMs: clockAdvanceQuantumMs, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
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
