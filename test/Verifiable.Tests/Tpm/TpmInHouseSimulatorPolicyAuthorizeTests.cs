using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
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
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_PolicyAuthorize()</c> against the in-house behavioural <see cref="TpmSimulator"/> — entirely
/// in-process, with no external assets — through the same production command path the production code uses (the
/// <see cref="TpmDeviceExtensions"/> policy commands, <see cref="TpmCommandExecutor"/>, and the real
/// command/response codecs). Each test builds a session's digest to a known "approved" value, has an authority
/// key sign off on it through the production <c>TPM2_Sign()</c>/<c>TPM2_VerifySignature()</c> wire path, and
/// drives <c>TPM2_PolicyAuthorize()</c> itself over the wire (TPM 2.0 Library Part 3, Section 23.16).
/// </summary>
/// <remarks>
/// <para>
/// The flagship test independently predicts the FIXED authPolicy <see cref="TpmPolicyDigest.ExtendForAuthorize"/>
/// produces <b>before</b> creating the sealed object, seals a secret under it, then drives a session through a
/// revisable sub-policy (<c>PolicyCommandCode</c>) the authority signs off on, replaces that digest with the
/// fixed one via a real, ticket-verified <c>TPM2_PolicyAuthorize()</c>, and unseals — proving the host prediction
/// and the simulator's on-device fold agree end to end, not merely that the two happen to call the same formula.
/// </para>
/// <para>
/// The negative tests each isolate one rung of the check ladder (TPM 2.0 Library Part 3, Section 23.16): a
/// tampered <c>approvedPolicy</c>, a forged <c>checkTicket</c>, a <c>checkTicket</c> claiming the wrong hierarchy,
/// an unrecognized <c>keySign</c> hash algorithm, and a <c>keySign</c> whose remainder is the wrong length. A
/// trial session with a NULL ticket exercises the reset-and-fold without any real verification. The builder
/// round-trip test drives <see cref="TpmPolicyBuilder.WithSigned"/> then <see cref="TpmPolicyBuilder.WithAuthorize"/>
/// through <see cref="TpmPolicy.ExecuteAsync"/> and checks the executed digest against
/// <see cref="TpmPolicy.ComputeDigest"/>'s own prediction.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorPolicyAuthorizeTests
{
    /// <summary>The policy session hash algorithm used throughout (also keySign's nameAlg in every test here).</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The fixed secret sealed and recovered by the flagship flow test.</summary>
    private static byte[] SecretBytes { get; } = "Bind this secret to a TPM2_PolicyAuthorize() authorization."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Caller-supplied context for <see cref="SignViaDeviceAsync"/>, threaded explicitly (no closure capture):
    /// the live device and its response registry, the memory pool, the authority key's handle, and the scheme
    /// hash algorithm to sign under.
    /// </summary>
    /// <param name="Tpm">The TPM device to sign through.</param>
    /// <param name="Registry">The response codec registry covering <c>TPM2_Sign</c>.</param>
    /// <param name="Pool">The memory pool.</param>
    /// <param name="AuthorityHandle">The authority key's handle.</param>
    /// <param name="HashAlg">The scheme hash algorithm to sign under.</param>
    private sealed record SignedAssertionSigningContext(
        TpmDevice Tpm, TpmResponseRegistry Registry, BaseMemoryPool Pool, TpmiDhObject AuthorityHandle, TpmAlgIdConstants HashAlg);

    /// <summary>
    /// Flagship flow: predicts the FIXED authPolicy <c>ExtendForAuthorize</c> will produce, seals a secret under
    /// that prediction, drives a session through a revisable sub-policy the authority signs off on, replaces it
    /// with the fixed digest via a real, ticket-verified <c>TPM2_PolicyAuthorize()</c>, and unseals — proving the
    /// host prediction and the on-device fold agree end to end.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeEccFlowRevisesThePolicyAndUnsealsUnderThePredictedAuthPolicy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] keySign = authorityKey.Name.Span.ToArray();
        byte[] policyRef = "wave-w2-policyauthorize-ref"u8.ToArray();

        //The revisable sub-policy the authority is willing to sign off on: PolicyCommandCode(TPM_CC_Unseal),
        //predicted independently so the authority signs exactly the value the session will later reach.
        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] approvedPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForCommandCode(zero, TpmCcConstants.TPM_CC_Unseal, SessionAlg, approvedPolicy);

        //The FIXED authPolicy the sealed object is created under: depends only on keySign + policyRef (Part 3,
        //Section 23.16, equation 35) — predicted BEFORE the sealed object exists, independent of approvedPolicy.
        byte[] authPolicy = new byte[size];
        _ = TpmPolicyDigest.ExtendForAuthorize(keySign, policyRef, SessionAlg, authPolicy);

        //The authority signs aHash = H(approvedPolicy || policyRef) (Part 3, Section 23.16, equation 33) via the
        //production TPM2_Sign() wire path, then TPM2_VerifySignature() mints the real TPMT_TK_VERIFIED
        //TPM2_PolicyAuthorize() re-verifies.
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

        //The response stays alive for the rest of the flow so the ticket is a borrow of the response's own
        //memory — no copy, no naked buffer.
        using VerifySignatureResponse verified = verifyResult.Value;
        Assert.IsFalse(verified.Validation.IsNull, "A real-hierarchy authority key must produce a usable (non-NULL) ticket.");

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
            Assert.IsTrue(createResult.IsSuccess, $"Create (seal under the PolicyAuthorize-predicted authPolicy) failed: '{createResult.ResponseCode}'.");

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

            //Reach approvedPolicy first (the revisable sub-policy).
            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(
                policyHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            //Then authorize: the session's digest (== approvedPolicy) plus the authority's real ticket replaces
            //it with the fixed, authority-controlled digest the sealed object's authPolicy was set to.
            TpmResult<PolicyAuthorizeResponse> authorizeResult = await tpm.PolicyAuthorizeAsync(
                policyHandle, approvedPolicy, policyRef, keySign, verified.Validation, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authorizeResult.IsSuccess, $"PolicyAuthorize failed: '{authorizeResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;
            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(authPolicy),
                "The simulator's policyDigest after PolicyAuthorize must match the independently predicted ExtendForAuthorize value.");

            using TpmPolicySession policySession = TpmPolicySession.ForSession(policyHandle, SessionAlg, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);

            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(unsealResult.IsSuccess, $"Unseal gated on the PolicyAuthorize digest failed: '{unsealResult.ResponseCode}'.");

            using UnsealResponse unsealed = unsealResult.Value;
            Assert.IsTrue(
                unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes),
                "The unsealed data must equal the secret sealed under the PolicyAuthorize-predicted authPolicy.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, policyHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, authorityKey.ObjectHandle.Value).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, parentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a tampered <c>approvedPolicy</c> (not equal to the session's actual digest) is rejected with
    /// <c>TPM_RC_VALUE</c>, ahead of the (placeholder, never-reached) ticket re-verification (TPM 2.0 Library
    /// Part 3, Section 23.16).
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithTamperedApprovedPolicyReturnsValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] keySign = authorityKey.Name.Span.ToArray();
        byte[] policyRef = "tampered-approved-policy-ref"u8.ToArray();

        //A syntactically valid ticket under the right hierarchy; its digest content never matters because the
        //approvedPolicy equality check rejects first.
        using TpmtTkVerified placeholderTicket = MintFilledTicket(TpmRh.TPM_RH_OWNER, fill: 0x00, pool);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            //The session's actual digest is PolicyCommandCode(TPM_CC_Unseal), not this all-zero value.
            byte[] tamperedApprovedPolicy = new byte[TpmPolicyDigest.Size(SessionAlg)];

            TpmResult<PolicyAuthorizeResponse> authorizeResult = await tpm.PolicyAuthorizeAsync(
                sessionHandle, tamperedApprovedPolicy, policyRef, keySign, placeholderTicket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(authorizeResult.IsSuccess, "A tampered approvedPolicy must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, authorizeResult.ResponseCode);
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a forged <c>checkTicket</c> digest (approvedPolicy matches, but the ticket does not reproduce) is
    /// rejected with <c>TPM_RC_VALUE</c> — never <c>TPM_RC_TICKET</c>, never <c>TPM_RC_POLICY</c> (TPM 2.0
    /// Library Part 3, Section 23.16).
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithForgedCheckTicketReturnsValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] keySign = authorityKey.Name.Span.ToArray();
        byte[] policyRef = "forged-ticket-ref"u8.ToArray();

        //An attacker-chosen digest no genuine proof produced.
        using TpmtTkVerified forgedTicket = MintFilledTicket(TpmRh.TPM_RH_OWNER, fill: 0xAB, pool);

        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] approvedPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForCommandCode(zero, TpmCcConstants.TPM_CC_Unseal, SessionAlg, approvedPolicy);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            TpmResult<PolicyAuthorizeResponse> authorizeResult = await tpm.PolicyAuthorizeAsync(
                sessionHandle, approvedPolicy, policyRef, keySign, forgedTicket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(authorizeResult.IsSuccess, "A forged checkTicket must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, authorizeResult.ResponseCode);
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a genuine ticket digest re-submitted under the WRONG claimed hierarchy is rejected with
    /// <c>TPM_RC_VALUE</c>: the proof re-derives from the caller-supplied hierarchy, so a mismatched hierarchy
    /// claim produces a non-matching HMAC even though the digest bytes are otherwise authentic (TPM 2.0 Library
    /// Part 3, Section 23.16).
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithWrongHierarchyCheckTicketReturnsValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] keySign = authorityKey.Name.Span.ToArray();
        byte[] policyRef = "wrong-hierarchy-ref"u8.ToArray();

        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] approvedPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForCommandCode(zero, TpmCcConstants.TPM_CC_Unseal, SessionAlg, approvedPolicy);

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
        Assert.IsFalse(verified.Validation.IsNull, "A real-hierarchy authority key must produce a usable (non-NULL) ticket.");
        Assert.AreEqual(TpmRh.TPM_RH_OWNER, verified.Validation.Hierarchy, "Test setup: the authority key must be created under Owner.");

        //The genuine digest re-claimed under TPM_RH_ENDORSEMENT rather than the authority key's own
        //TPM_RH_OWNER — the re-derived proof differs, so the recomputed HMAC no longer matches.
        using TpmtTkVerified wrongHierarchyTicket = MintTicket(TpmRh.TPM_RH_ENDORSEMENT, verified.Validation.Digest, pool);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            TpmResult<PolicyAuthorizeResponse> authorizeResult = await tpm.PolicyAuthorizeAsync(
                sessionHandle, approvedPolicy, policyRef, keySign, wrongHierarchyTicket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(authorizeResult.IsSuccess, "A checkTicket claiming the wrong hierarchy must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, authorizeResult.ResponseCode);
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies an unrecognized <c>keySign</c> hash algorithm (its first two octets) is rejected with
    /// <c>TPM_RC_HASH</c>, ahead of any other check (TPM 2.0 Library Part 3, Section 23.16) — this check runs
    /// even for what would otherwise look like a trial-session shortcut, since it precedes the trial/real split.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithUnrecognizedKeySignHashAlgReturnsHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        byte[] keySignWithUnrecognizedHashAlg = new byte[sizeof(ushort) + 32];
        BinaryPrimitives.WriteUInt16BigEndian(keySignWithUnrecognizedHashAlg, (ushort)TpmAlgIdConstants.TPM_ALG_NULL);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            //keySign validation rejects before the ticket is ever consulted, so a placeholder ticket suffices.
            using TpmtTkVerified placeholderTicket = MintFilledTicket(TpmRh.TPM_RH_OWNER, fill: 0x00, pool);
            TpmResult<PolicyAuthorizeResponse> authorizeResult = await tpm.PolicyAuthorizeAsync(
                sessionHandle, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, keySignWithUnrecognizedHashAlg,
                placeholderTicket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(authorizeResult.IsSuccess, "An unrecognized keySign hash algorithm must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_HASH, authorizeResult.ResponseCode);
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a <c>keySign</c> whose remainder is not exactly the width of the hash algorithm its first two
    /// octets select is rejected with <c>TPM_RC_SIZE</c> (TPM 2.0 Library Part 3, Section 23.16).
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithKeySignLengthMismatchReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        //SHA-256's nameAlg tag, but only 16 digest octets (SHA-256 needs 32).
        byte[] keySignWithWrongLength = new byte[sizeof(ushort) + 16];
        BinaryPrimitives.WriteUInt16BigEndian(keySignWithWrongLength, (ushort)TpmAlgIdConstants.TPM_ALG_SHA256);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            //keySign validation rejects before the ticket is ever consulted, so a placeholder ticket suffices.
            using TpmtTkVerified placeholderTicket = MintFilledTicket(TpmRh.TPM_RH_OWNER, fill: 0x00, pool);
            TpmResult<PolicyAuthorizeResponse> authorizeResult = await tpm.PolicyAuthorizeAsync(
                sessionHandle, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, keySignWithWrongLength,
                placeholderTicket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(authorizeResult.IsSuccess, "A keySign whose remainder is the wrong length must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, authorizeResult.ResponseCode);
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a trial session with a NULL checkTicket folds the digest identically to the host
    /// <see cref="TpmPolicyDigest.ExtendForAuthorize"/> prediction, without checking approvedPolicy or the ticket
    /// (TPM 2.0 Library Part 3, Section 23.16, Note 2: "A NULL ticket is useful in a trial policy").
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeTrialSessionWithNullTicketFoldsCorrectlyAndMatchesHostPrediction()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] keySign = authorityKey.Name.Span.ToArray();
        byte[] policyRef = "trial-authorize-ref"u8.ToArray();

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyAuthorizeResponse> authorizeResult = await tpm.PolicyAuthorizeAsync(
                sessionHandle, ReadOnlyMemory<byte>.Empty, policyRef, keySign,
                TpmtTkVerified.Null, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authorizeResult.IsSuccess, $"PolicyAuthorize (trial) failed: '{authorizeResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;

            int size = TpmPolicyDigest.Size(SessionAlg);
            byte[] predicted = new byte[size];
            _ = TpmPolicyDigest.ExtendForAuthorize(keySign, policyRef, SessionAlg, predicted);

            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                "A trial PolicyAuthorize must fold the digest identically to the host ExtendForAuthorize prediction, without checking the (placeholder) approvedPolicy/ticket.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Builder round-trip: a policy built as <c>WithSigned</c> then <c>WithAuthorize</c> must produce the same
    /// digest whether predicted via <see cref="TpmPolicy.ComputeDigest"/> or replayed on a live session via
    /// <see cref="TpmPolicy.ExecuteAsync"/> — proving the two operations the builder promises from one
    /// description never drift apart.
    /// </summary>
    [TestMethod]
    public async Task BuilderRoundTripPredictedDigestMatchesExecutedDigestForWithSignedThenWithAuthorize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] authorityName = authorityKey.Name.Span.ToArray();
        byte[] signedPolicyRef = "builder-roundtrip-signed-ref"u8.ToArray();
        byte[] authorizeRef = "builder-roundtrip-authorize-ref"u8.ToArray();

        //WithSigned is the policy's only prior assertion, so its digest contribution starting from zero IS
        //approvedPolicy — the value the authority must sign for WithAuthorize's own re-verification.
        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] approvedPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForSigned(zero, authorityName, signedPolicyRef, SessionAlg, approvedPolicy);

        byte[] aHash = ComputeAuthorizeAHash(approvedPolicy, authorizeRef);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(authorityKey.ObjectHandle, aHash, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (authorize aHash) failed: '{signResult.ResponseCode}'.");

        using SignResponse authorizeSignature = signResult.Value;
        using Signature authorizeP1363Signature = ConcatenateP1363(authorizeSignature.Signature.SignatureR!.AsReadOnlySpan(), authorizeSignature.Signature.SignatureS!.AsReadOnlySpan(), pool);

        using VerifySignatureInput verifyInput = VerifySignatureInput.ForEcdsa(authorityKey.ObjectHandle, aHash, authorizeP1363Signature.AsReadOnlySpan(), TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifySignature (authorize ticket) failed: '{verifyResult.ResponseCode}'.");

        //The response stays alive for the rest of the flow so the ticket is a borrow of the response's own
        //memory — no copy, no naked buffer.
        using VerifySignatureResponse verified = verifyResult.Value;
        Assert.IsFalse(verified.Validation.IsNull, "A real-hierarchy authority key must produce a usable (non-NULL) ticket.");

        var signingContext = new SignedAssertionSigningContext(tpm, registry, pool, authorityKey.ObjectHandle, TpmAlgIdConstants.TPM_ALG_SHA256);
        TpmPolicy policy = new TpmPolicyBuilder()
            .WithSigned(authorityKey.ObjectHandle.Value, authorityName, signedPolicyRef, SignViaDeviceAsync, signingContext, TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256)
            .WithAuthorize(approvedPolicy, authorizeRef, authorityName, verified.Validation)
            .Build();

        byte[] predicted = new byte[size];
        int written = policy.ComputeDigest(SessionAlg, predicted);
        Assert.AreEqual(size, written);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<uint> executeResult = await policy.ExecuteAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(executeResult.IsSuccess, $"Policy replay (WithSigned + WithAuthorize) failed: '{executeResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;
            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                "The executed digest (WithSigned then WithAuthorize) must equal the builder's own ComputeDigest prediction.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, authorityKey.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Signs <paramref name="aHash"/> through the live device named by <paramref name="context"/>, over the
    /// authority key's own retained private key (TPM2_Sign()) — the delegate a <see cref="SignedPolicyAssertion"/>
    /// replay invokes, with its context passed as an explicit parameter (no closure capture).
    /// </summary>
    /// <param name="aHash">The aHash to sign, carried as the digest it is.</param>
    /// <param name="context">The <see cref="SignedAssertionSigningContext"/> naming the device, registry, pool, key, and hash algorithm.</param>
    /// <param name="pool">The memory pool backing the returned signature.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The IEEE P1363 <c>r ‖ s</c> signature as a pooled carrier the caller disposes.</returns>
    private static async ValueTask<Signature> SignViaDeviceAsync(DigestValue aHash, object? context, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        var signingContext = (SignedAssertionSigningContext)context!;

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(signingContext.Pool);
        using SignInput signInput = SignInput.ForEcdsa(signingContext.AuthorityHandle, aHash.AsReadOnlySpan(), signingContext.HashAlg, signingContext.Pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            signingContext.Tpm, signInput, [signAuth], null, signingContext.Pool, signingContext.Registry, cancellationToken).ConfigureAwait(false);
        if(!signResult.IsSuccess)
        {
            throw new InvalidOperationException($"TPM2_Sign (WithSigned replay) failed: '{signResult.ResponseCode}'.");
        }

        using SignResponse signature = signResult.Value;

        return ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan(), pool);
    }

    /// <summary>
    /// Builds TPM2_PolicyAuthorize's <c>aHash = H(approvedPolicy || policyRef)</c> (TPM 2.0 Library Part 3,
    /// Section 23.16, equation 33) as an in-test SHA-256 oracle, independent of the simulator's own effect
    /// computation.
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
    /// Creates an ECC P-256 ECDSA/SHA-256 signing key under the owner hierarchy, used as the authority key that
    /// signs off on approved policies (its Name is <c>keySign</c>).
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
    /// Composes a TPMT_TK_VERIFIED value claiming <paramref name="hierarchy"/> over <paramref name="digest"/>
    /// exactly as an attacker would submit one on the wire (TPM 2.0 Library Part 2, Section 10.7.4), parsed back
    /// through the production wire shape so the result is a genuine ticket value with a caller-chosen claim.
    /// </summary>
    /// <param name="hierarchy">The hierarchy the ticket claims.</param>
    /// <param name="digest">The ticket digest octets.</param>
    /// <param name="pool">The memory pool backing the parsed ticket.</param>
    /// <returns>The composed ticket; the caller disposes it.</returns>
    private static TpmtTkVerified MintTicket(TpmRh hierarchy, ReadOnlySpan<byte> digest, BaseMemoryPool pool)
    {
        int size = sizeof(ushort) + sizeof(uint) + sizeof(ushort) + digest.Length;
        using IMemoryOwner<byte> owner = pool.Rent(size);
        Span<byte> wire = owner.Memory.Span[..size];
        var writer = new TpmWriter(wire);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_VERIFIED);
        writer.WriteUInt32((uint)hierarchy);
        writer.WriteUInt16((ushort)digest.Length);
        writer.WriteBytes(digest);
        var reader = new TpmReader(wire);

        return TpmtTkVerified.Parse(ref reader, pool);
    }

    /// <summary>
    /// Mints a ticket whose 32-octet digest repeats <paramref name="fill"/> — for negatives where an earlier
    /// check rejects before the ticket is ever consulted. Non-secret fixture content in a bounded stack buffer.
    /// </summary>
    /// <param name="hierarchy">The hierarchy the ticket claims.</param>
    /// <param name="fill">The octet the digest repeats.</param>
    /// <param name="pool">The memory pool backing the parsed ticket.</param>
    /// <returns>The composed ticket; the caller disposes it.</returns>
    private static TpmtTkVerified MintFilledTicket(TpmRh hierarchy, byte fill, BaseMemoryPool pool)
    {
        //Non-secret fixture octets, tiny and bounded, so the stack buffer is safe.
        Span<byte> digest = stackalloc byte[32];
        digest.Fill(fill);

        return MintTicket(hierarchy, digest, pool);
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
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySignature, TpmResponseCodec.VerifySignature);

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
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-policyauthorize",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create());
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
