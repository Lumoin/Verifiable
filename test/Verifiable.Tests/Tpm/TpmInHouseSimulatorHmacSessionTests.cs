using System;
using System.Buffers.Binary;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Acceptance tests for the session-authorized forms of <c>TPM2_HMAC()</c> and <c>TPM2_HMAC_Start()</c> against
/// a loaded KEYEDHASH HMAC key (TPM 2.0 Library Part 3, clauses 15.5 and 17.2, Tables 71/80): a bound or unbound
/// HMAC session, a <c>TPM2_PolicyAuthValue()</c> or <c>TPM2_PolicyPassword()</c> policy session that folds the
/// key's authorization value at use, a plain policy session over an empty-auth key, and session-based parameter
/// encryption over the authorizing session in both directions — <c>buffer</c>/<c>auth</c> protected by the
/// <c>decrypt</c> attribute on the way in and <c>outHMAC</c> by the <c>encrypt</c> attribute on the way out
/// (Part 1, clause 18). The positive cases key the simulator's HMAC seam with the published RFC 4231 test-vector
/// keys and assert the returned <c>outHMAC</c> equals the published value, so the oracle is the specification's
/// own vector and a keystream disagreement in either direction is an HMAC over different octets or a garbled
/// <c>outHMAC</c>; every real HMAC session additionally verifies the simulator's response authorization end to
/// end (<see cref="TpmSession.VerifyAndUpdateAsync"/>), so a wrong response HMAC surfaces as a failed exchange.
/// The session-area negatives the host executor would pre-empt client-side plant their attribute bits on the
/// wire through a rewriting device: Part 3, clause 5.5's area checks run before clause 5.6's HMAC check, so a
/// planted bit is refused for the area rule under test.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorHmacSessionTests
{
    /// <summary>The MSTest-provided per-test context, its cancellation token observed across every exchange.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The session hash algorithm for every session these tests start.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The command header's fixed width: tag (UINT16), commandSize (UINT32), commandCode (UINT32).</summary>
    private const int HeaderSize = 10;

    /// <summary>The authorization value a decrypt-protected <c>TPM2_HMAC_Start()</c> installs on its sequence.</summary>
    private static byte[] SequencePassword { get; } = "hmac-sequence-auth"u8.ToArray();

    /// <summary>RFC 4231 test case 1 key: 20 octets of 0x0b.</summary>
    private static byte[] Rfc4231Case1Key { get; } = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

    /// <summary>RFC 4231 test case 1 data: "Hi There".</summary>
    private static byte[] Rfc4231Case1Data { get; } = Convert.FromHexString("4869205468657265");

    /// <summary>RFC 4231 test case 1 published HMAC-SHA-256.</summary>
    private static byte[] Rfc4231Case1Sha256 { get; } = Convert.FromHexString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    /// <summary>RFC 4231 test case 3 key: 20 octets of 0xaa.</summary>
    private static byte[] Rfc4231Case3Key { get; } = Convert.FromHexString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    /// <summary>RFC 4231 test case 3 data: 50 octets of 0xdd.</summary>
    private static byte[] Rfc4231Case3Data { get; } = Convert.FromHexString("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");

    /// <summary>RFC 4231 test case 3 published HMAC-SHA-256.</summary>
    private static byte[] Rfc4231Case3Sha256 { get; } = Convert.FromHexString("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    /// <summary>The key authorization value the folding cases install and present.</summary>
    private static byte[] KeyPassword { get; } = "hmac-key-auth"u8.ToArray();

    /// <summary>A value that is not the key's authorization value.</summary>
    private static byte[] WrongKeyPassword { get; } = "hmac-key-wrong"u8.ToArray();

    /// <summary>
    /// <c>TPM2_HMAC()</c> authorized by a bound HMAC session whose key folds the key's authorization value
    /// returns the published value, and its response authorization verifies end to end: the command HMAC keys
    /// on <c>sessionKey ‖ authValue</c> (TPM 2.0 Library Part 1, clause 16.6.5, equation 17), and the simulator's
    /// response HMAC keys on the same, so <see cref="TpmSession.VerifyAndUpdateAsync"/> accepts it
    /// (<see href="https://www.rfc-editor.org/rfc/rfc4231#section-4.2">RFC 4231, section 4.2</see>).
    /// </summary>
    [TestMethod]
    public async Task HmacOverAnHmacSessionFoldingTheAuthValueReturnsThePublishedValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAnHmacSessionFoldingTheAuthValueReturnsThePublishedValue), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(tpm, registry, pool, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(KeyPassword, pool);

            TpmResult<HmacResponse> result = await HmacKeyHarness.HmacOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsSuccess, $"TPM2_HMAC() over a bound HMAC session must succeed: '{result.ResponseCode}'.");
            using HmacResponse outHmac = result.Value;
            Assert.IsTrue(outHmac.OutHmac.AsReadOnlySpan().SequenceEqual(Rfc4231Case1Sha256), "The session-authorized HMAC must equal the published RFC 4231 case 1 value.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Two consecutive <c>TPM2_HMAC()</c> commands over one continued HMAC session each return the published
    /// value: the second exchange's command and response HMACs key on the nonceTPM the first response rolled
    /// (TPM 2.0 Library Part 1, clause 16.6.5; Part 4 <c>UpdateAllNonceTPM</c>), so a nonceTPM that failed to roll
    /// would fail the second exchange's verification.
    /// </summary>
    [TestMethod]
    public async Task TwoConsecutiveHmacsOverOneSessionEachReturnThePublishedValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(TwoConsecutiveHmacsOverOneSessionEachReturnThePublishedValue), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(tpm, registry, pool, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            for(int attempt = 0; attempt < 2; attempt++)
            {
                TpmResult<HmacResponse> result = await HmacKeyHarness.HmacOverSessionAsync(
                    tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(result.IsSuccess, $"TPM2_HMAC() exchange {attempt} over the continued session must succeed: '{result.ResponseCode}'.");
                using HmacResponse outHmac = result.Value;
                Assert.IsTrue(outHmac.OutHmac.AsReadOnlySpan().SequenceEqual(Rfc4231Case1Sha256), $"Exchange {attempt} must equal the published RFC 4231 case 1 value.");
            }
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A wrong authorization value over a bound HMAC session on a dictionary-attack-EXEMT key is refused
    /// <c>TPM_RC_BAD_AUTH</c> on session 0, uncharged: the command HMAC does not match, and neither the key
    /// (noDA) nor the bound entity (the noDA storage parent) is DA protected, so the failure does not increment
    /// the counter (TPM 2.0 Library Part 3, clause 5.6; Part 4 <c>IncrementLockout</c>).
    /// </summary>
    [TestMethod]
    public async Task HmacOverAnHmacSessionWithAWrongAuthValueOnANoDaKeyIsBadAuthAndUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAnHmacSessionWithAWrongAuthValueOnANoDaKeyIsBadAuthAndUncharged), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, isNoDa: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(tpm, registry, pool, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(WrongKeyPassword, pool);

            TpmResult<HmacResponse> result = await HmacKeyHarness.HmacOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A wrong authValue over an HMAC session must refuse the HMAC.");
            Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode, "A wrong authValue against a noDA key must answer TPM_RC_BAD_AUTH on session 0.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_HMAC_Start()</c> authorized by a bound HMAC session opens a sequence; the sequence completes over
    /// its own password authorization to the published value, proving the session form returns the sequence
    /// handle in the response handle area and admits the same accumulation the password form does (RFC 4231
    /// case 3, <see href="https://www.rfc-editor.org/rfc/rfc4231#section-4.4">section 4.4</see>).
    /// </summary>
    [TestMethod]
    public async Task HmacStartOverAnHmacSessionThenCompletesToThePublishedValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartOverAnHmacSessionThenCompletesToThePublishedValue), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(tpm, registry, pool, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        uint sequenceHandle = 0;
        try
        {
            TpmResult<HmacStartResponse> startResult = await HmacKeyHarness.HmacStartOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), TpmAlgIdConstants.TPM_ALG_SHA256, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"TPM2_HMAC_Start() over a bound HMAC session must succeed: '{startResult.ResponseCode}'.");
            sequenceHandle = startResult.Value.SequenceHandle.Value;

            TpmResult<SequenceUpdateResponse> updateResult = await HmacKeyHarness.SequenceUpdateAsync(
                tpm, registry, pool, TpmiDhObject.FromValue(sequenceHandle), Rfc4231Case3Data, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(updateResult.IsSuccess, $"TPM2_SequenceUpdate() failed: '{updateResult.ResponseCode}'.");

            TpmResult<SequenceCompleteResponse> completeResult = await HmacKeyHarness.SequenceCompleteAsync(
                tpm, registry, pool, TpmiDhObject.FromValue(sequenceHandle), ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() failed: '{completeResult.ResponseCode}'.");
            using SequenceCompleteResponse completed = completeResult.Value;
            sequenceHandle = 0;

            Assert.IsTrue(completed.Result.AsReadOnlySpan().SequenceEqual(Rfc4231Case3Sha256), "The session-started HMAC sequence must complete to the published RFC 4231 case 3 value.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The S4 closure: <c>TPM2_HMAC()</c> authorized by a policy session that asserted
    /// <c>TPM2_PolicyAuthValue()</c> folds the key's authorization value into the command HMAC at use (TPM 2.0
    /// Library Part 1, clause 16.6.12, equation 26) and returns the published value — the key's authValue is
    /// checked through a real HMAC at a command that consumes the key, which the password-only forms could not do.
    /// </summary>
    [TestMethod]
    public async Task HmacOverAPolicyAuthValueSessionReturnsThePublishedValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAPolicyAuthValueSessionReturnsThePublishedValue), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] authPolicy = PolicyAuthValueDigest();
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, authPolicy: authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
            StartAuthSessionResponse started = startResult.Value;
            sessionHandle = started.SessionHandle.Value;

            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, pool);
            TpmResult<PolicyAuthValueResponse> authValueResult = await tpm.PolicyAuthValueAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue failed: '{authValueResult.ResponseCode}'.");

            session.SetAuthValue(KeyPassword, pool);

            TpmResult<HmacResponse> result = await HmacKeyHarness.HmacOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsSuccess, $"TPM2_HMAC() over a PolicyAuthValue session must succeed: '{result.ResponseCode}'.");
            using HmacResponse outHmac = result.Value;
            Assert.IsTrue(outHmac.OutHmac.AsReadOnlySpan().SequenceEqual(Rfc4231Case1Sha256), "The PolicyAuthValue-authorized HMAC must equal the published RFC 4231 case 1 value.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A wrong authorization value over a <c>TPM2_PolicyAuthValue()</c> session on a dictionary-attack-PROTECTED
    /// key is refused <c>TPM_RC_AUTH_FAIL</c> on session 0 and charged: the folded authValue does not match, and
    /// the key IS DA protected, so the failure increments the counter (TPM 2.0 Library Part 1, clause 16.8.7).
    /// </summary>
    [TestMethod]
    public async Task HmacOverAPolicyAuthValueSessionWithAWrongAuthValueOnADaKeyIsAuthFailAndCharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAPolicyAuthValueSessionWithAWrongAuthValueOnADaKeyIsAuthFailAndCharged), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] authPolicy = PolicyAuthValueDigest();
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, isNoDa: false, authPolicy: authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
            StartAuthSessionResponse started = startResult.Value;
            sessionHandle = started.SessionHandle.Value;

            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, pool);
            TpmResult<PolicyAuthValueResponse> authValueResult = await tpm.PolicyAuthValueAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue failed: '{authValueResult.ResponseCode}'.");

            session.SetAuthValue(WrongKeyPassword, pool);

            TpmResult<HmacResponse> result = await HmacKeyHarness.HmacOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A wrong PolicyAuthValue must refuse the HMAC.");
            Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode, "A wrong folded authValue against a DA key must answer TPM_RC_AUTH_FAIL on session 0.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_HMAC()</c> authorized by a policy session that asserted <c>TPM2_PolicyPassword()</c> presents the
    /// key's authorization value in the clear in the session's hmac field, compared as a password at use (TPM 2.0
    /// Library Part 3, Section 23.18), and returns the published value.
    /// </summary>
    [TestMethod]
    public async Task HmacOverAPolicyPasswordSessionReturnsThePublishedValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAPolicyPasswordSessionReturnsThePublishedValue), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] authPolicy = PolicyAuthValueDigest();
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, authPolicy: authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
            using StartAuthSessionResponse started = startResult.Value;
            sessionHandle = started.SessionHandle.Value;

            TpmResult<PolicyPasswordResponse> passwordResult = await tpm.PolicyPasswordAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(passwordResult.IsSuccess, $"PolicyPassword failed: '{passwordResult.ResponseCode}'.");

            using TpmPolicySession session = TpmPolicySession.ForSessionWithPassword(sessionHandle, SessionAlg, KeyPassword, pool);

            TpmResult<HmacResponse> result = await HmacKeyHarness.HmacOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsSuccess, $"TPM2_HMAC() over a PolicyPassword session must succeed: '{result.ResponseCode}'.");
            using HmacResponse outHmac = result.Value;
            Assert.IsTrue(outHmac.OutHmac.AsReadOnlySpan().SequenceEqual(Rfc4231Case1Sha256), "The PolicyPassword-authorized HMAC must equal the published RFC 4231 case 1 value.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A wrong password over a <c>TPM2_PolicyPassword()</c> session on a noDA key is refused
    /// <c>TPM_RC_BAD_AUTH</c> on session 0: the cleartext hmac field is compared against the key's authValue and
    /// does not match (TPM 2.0 Library Part 3, Section 23.18; Part 4 <c>CheckPWAuthSession</c>).
    /// </summary>
    [TestMethod]
    public async Task HmacOverAPolicyPasswordSessionWithAWrongPasswordIsBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAPolicyPasswordSessionWithAWrongPasswordIsBadAuth), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] authPolicy = PolicyAuthValueDigest();
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, authPolicy: authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
            using StartAuthSessionResponse started = startResult.Value;
            sessionHandle = started.SessionHandle.Value;

            TpmResult<PolicyPasswordResponse> passwordResult = await tpm.PolicyPasswordAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(passwordResult.IsSuccess, $"PolicyPassword failed: '{passwordResult.ResponseCode}'.");

            using TpmPolicySession session = TpmPolicySession.ForSessionWithPassword(sessionHandle, SessionAlg, WrongKeyPassword, pool);

            TpmResult<HmacResponse> result = await HmacKeyHarness.HmacOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A wrong PolicyPassword must refuse the HMAC.");
            Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode, "A wrong PolicyPassword against a noDA key must answer TPM_RC_BAD_AUTH on session 0.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_HMAC()</c> authorized by a plain policy session that asserted only
    /// <c>TPM2_PolicyCommandCode(TPM_CC_HMAC)</c> over an empty-auth key returns the published value: the session
    /// key is the Empty Buffer and no authValue is folded, so the command HMAC is matched by the empty-key rule
    /// and the response HMAC is empty (TPM 2.0 Library Part 4 <c>ComputeCommandHMAC</c>/<c>ComputeResponseHMAC</c>).
    /// </summary>
    [TestMethod]
    public async Task HmacOverAPlainPolicyCommandCodeSessionReturnsThePublishedValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAPlainPolicyCommandCodeSessionReturnsThePublishedValue), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] authPolicy = PolicyCommandCodeDigest(TpmCcConstants.TPM_CC_HMAC);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, authPolicy: authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
            StartAuthSessionResponse started = startResult.Value;
            sessionHandle = started.SessionHandle.Value;

            using TpmPolicySession session = TpmPolicySession.ForSession(sessionHandle, SessionAlg, pool);
            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(sessionHandle, TpmCcConstants.TPM_CC_HMAC, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            TpmResult<HmacResponse> result = await HmacKeyHarness.HmacOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsSuccess, $"TPM2_HMAC() over a plain PolicyCommandCode session must succeed: '{result.ResponseCode}'.");
            using HmacResponse outHmac = result.Value;
            Assert.IsTrue(outHmac.OutHmac.AsReadOnlySpan().SequenceEqual(Rfc4231Case1Sha256), "The plain-policy-authorized HMAC must equal the published RFC 4231 case 1 value.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A policy session whose accumulated digest matches the key's authPolicy but whose bound command code is not
    /// <c>TPM_CC_HMAC</c> is refused <c>TPM_RC_POLICY_CC</c> at use: the deferred command-code assertion is
    /// checked against the command it authorizes (TPM 2.0 Library Part 3, Section 23.4; Part 4
    /// <c>CheckPolicyAuthSession</c>).
    /// </summary>
    [TestMethod]
    public async Task HmacOverAPolicySessionBoundToAnotherCommandCodeIsRefusedWithPolicyCc()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAPolicySessionBoundToAnotherCommandCodeIsRefusedWithPolicyCc), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] authPolicy = PolicyCommandCodeDigest(TpmCcConstants.TPM_CC_Unseal);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, authPolicy: authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
            using StartAuthSessionResponse started = startResult.Value;
            sessionHandle = started.SessionHandle.Value;

            using TpmPolicySession session = TpmPolicySession.ForSession(sessionHandle, SessionAlg, pool);
            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(sessionHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            TpmResult<HmacResponse> result = await HmacKeyHarness.HmacOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A policy bound to another command code must refuse TPM2_HMAC().");
            Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_CC, result.ResponseCode, "A command-code mismatch must be refused with TPM_RC_POLICY_CC.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A policy session whose accumulated digest does not equal the key's authPolicy is refused
    /// <c>TPM_RC_POLICY_FAIL</c>: the session asserted nothing, so its zero digest cannot satisfy a key sealed
    /// under a non-empty policy (TPM 2.0 Library Part 3, clause 5.6; Part 4 <c>CheckPolicyAuthSession</c>).
    /// </summary>
    [TestMethod]
    public async Task HmacOverAPolicySessionWhoseDigestDoesNotMatchIsRefusedWithPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAPolicySessionWhoseDigestDoesNotMatchIsRefusedWithPolicyFail), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] authPolicy = PolicyAuthValueDigest();
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, authPolicy: authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
            using StartAuthSessionResponse started = startResult.Value;
            sessionHandle = started.SessionHandle.Value;

            using TpmPolicySession session = TpmPolicySession.ForSession(sessionHandle, SessionAlg, pool);
            TpmResult<HmacResponse> result = await HmacKeyHarness.HmacOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "An unsatisfied policy must refuse TPM2_HMAC().");
            Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode, "A policyDigest mismatch must be refused with TPM_RC_POLICY_FAIL.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An HMAC session authorizing a <c>userWithAuth</c>-CLEAR key is refused <c>TPM_RC_POLICY_FAIL</c>: an
    /// object whose USER role may be authorized only by a policy session refuses an HMAC session before its HMAC
    /// is evaluated (TPM 2.0 Library Part 3, clause 5.6, check 7.1).
    /// </summary>
    [TestMethod]
    public async Task HmacOverAnHmacSessionOnAUserWithAuthClearKeyIsRefusedWithPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAnHmacSessionOnAUserWithAuthClearKeyIsRefusedWithPolicyFail), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] authPolicy = PolicyAuthValueDigest();
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, isUserWithAuth: false, authPolicy: authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(tpm, registry, pool, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(KeyPassword, pool);

            TpmResult<HmacResponse> result = await HmacKeyHarness.HmacOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "An HMAC session must not authorize a userWithAuth-CLEAR key.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode, "An HMAC session on a userWithAuth-CLEAR key must be refused with TPM_RC_POLICY_FAIL.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicyAuthValue()</c> session authorizes the same <c>userWithAuth</c>-CLEAR key the HMAC session
    /// was refused, returning the published value: a policy session is exactly the authorization a
    /// <c>userWithAuth</c>-CLEAR object requires (TPM 2.0 Library Part 3, clause 5.6, check 7.1).
    /// </summary>
    [TestMethod]
    public async Task HmacOverAPolicyAuthValueSessionOnAUserWithAuthClearKeyReturnsThePublishedValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAPolicyAuthValueSessionOnAUserWithAuthClearKeyReturnsThePublishedValue), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] authPolicy = PolicyAuthValueDigest();
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, isUserWithAuth: false, authPolicy: authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
            StartAuthSessionResponse started = startResult.Value;
            sessionHandle = started.SessionHandle.Value;

            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, pool);
            TpmResult<PolicyAuthValueResponse> authValueResult = await tpm.PolicyAuthValueAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue failed: '{authValueResult.ResponseCode}'.");

            session.SetAuthValue(KeyPassword, pool);

            TpmResult<HmacResponse> result = await HmacKeyHarness.HmacOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsSuccess, $"A policy session must authorize a userWithAuth-CLEAR key: '{result.ResponseCode}'.");
            using HmacResponse outHmac = result.Value;
            Assert.IsTrue(outHmac.OutHmac.AsReadOnlySpan().SequenceEqual(Rfc4231Case1Sha256), "The policy-authorized HMAC over a userWithAuth-CLEAR key must equal the published RFC 4231 case 1 value.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A key whose <c>authPolicy</c> is the Empty Policy cannot be authorized by a policy session: a loaded
    /// object's policy is always available to the session machinery (Part 4 <c>IsAuthPolicyAvailable</c>'s
    /// transient arm), so the session's digest-width policyDigest is compared against the empty authPolicy and
    /// never matches — <c>TPM2_HMAC()</c> over a policy session is refused <c>TPM_RC_POLICY_FAIL</c>
    /// (TPM 2.0 Library Part 3, clause 5.6, check 8.4; Part 4 <c>CheckPolicyAuthSession</c>).
    /// </summary>
    [TestMethod]
    public async Task HmacOverAPolicySessionOnAKeyWithNoAuthPolicyIsRefusedWithPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAPolicySessionOnAKeyWithNoAuthPolicyIsRefusedWithPolicyFail), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
            using StartAuthSessionResponse started = startResult.Value;
            sessionHandle = started.SessionHandle.Value;

            using TpmPolicySession session = TpmPolicySession.ForSession(sessionHandle, SessionAlg, pool);
            TpmResult<HmacResponse> result = await HmacKeyHarness.HmacOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A policy session cannot authorize a key with the Empty Policy.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode, "An empty authPolicy never equals a session's policyDigest: TPM_RC_POLICY_FAIL.");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_HMAC()</c> over a bound HMAC session carrying the <c>decrypt</c> attribute with XOR obfuscation
    /// returns the published value: <c>buffer</c> — the sized first parameter (TPM 2.0 Library Part 3, clause
    /// 15.5, Table 71) — crosses the wire obfuscated and the simulator recovers it over the same
    /// <c>sessionKey ‖ authValue</c> keystream the host derived (Part 1, clauses 18.1 and 18.2), so the HMAC is
    /// computed over the caller's plaintext.
    /// </summary>
    [TestMethod]
    public async Task HmacOverADecryptSessionWithXorObfuscationReturnsThePublishedValue() =>
        await RunProtectedHmacAsync(nameof(HmacOverADecryptSessionWithXorObfuscationReturnsThePublishedValue), TpmtSymDef.Xor(SessionAlg), TpmaSession.DECRYPT, isBoundToKey: false).ConfigureAwait(false);

    /// <summary>
    /// <c>TPM2_HMAC()</c> over a bound HMAC session carrying the <c>decrypt</c> attribute with AES-128-CFB
    /// returns the published value (TPM 2.0 Library Part 1, clause 18.3: the platform-specific CFB mode, keyed and
    /// IV'd from the session's KDFa).
    /// </summary>
    [TestMethod]
    public async Task HmacOverADecryptSessionWithAesCfbReturnsThePublishedValue() =>
        await RunProtectedHmacAsync(nameof(HmacOverADecryptSessionWithAesCfbReturnsThePublishedValue), TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), TpmaSession.DECRYPT, isBoundToKey: false).ConfigureAwait(false);

    /// <summary>
    /// <c>TPM2_HMAC()</c> over a bound HMAC session carrying the <c>encrypt</c> attribute with XOR obfuscation
    /// returns the published value: <c>outHMAC</c> — the sized first response parameter (TPM 2.0 Library Part 3,
    /// clause 15.5, Table 72) — leaves the simulator obfuscated under the rolled nonceTPM, after the nonce roll
    /// and before rpHash (Part 1, clause 18.1: "Parameters in responses are encrypted before any rpHash is
    /// computed"), and the host's response decryption recovers the published value.
    /// </summary>
    [TestMethod]
    public async Task HmacOverAnEncryptSessionWithXorObfuscationReturnsThePublishedValue() =>
        await RunProtectedHmacAsync(nameof(HmacOverAnEncryptSessionWithXorObfuscationReturnsThePublishedValue), TpmtSymDef.Xor(SessionAlg), TpmaSession.ENCRYPT, isBoundToKey: false).ConfigureAwait(false);

    /// <summary>
    /// <c>TPM2_HMAC()</c> over a bound HMAC session carrying the <c>encrypt</c> attribute with AES-128-CFB
    /// returns the published value (TPM 2.0 Library Part 1, clause 18.3, response direction).
    /// </summary>
    [TestMethod]
    public async Task HmacOverAnEncryptSessionWithAesCfbReturnsThePublishedValue() =>
        await RunProtectedHmacAsync(nameof(HmacOverAnEncryptSessionWithAesCfbReturnsThePublishedValue), TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), TpmaSession.ENCRYPT, isBoundToKey: false).ConfigureAwait(false);

    /// <summary>
    /// One session may claim both attributes (TPM 2.0 Library Part 1, clause 18.1: "The attributes can be SET in
    /// different sessions or in the same session"): <c>TPM2_HMAC()</c> over a bound AES-128-CFB session carrying
    /// <c>decrypt</c> and <c>encrypt</c> returns the published value, both directions keyed off one session.
    /// </summary>
    [TestMethod]
    public async Task HmacOverASessionProtectingBothDirectionsReturnsThePublishedValue() =>
        await RunProtectedHmacAsync(nameof(HmacOverASessionProtectingBothDirectionsReturnsThePublishedValue), TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), TpmaSession.DECRYPT | TpmaSession.ENCRYPT, isBoundToKey: false).ConfigureAwait(false);

    /// <summary>
    /// The two keys of one session differ: a session bound to the KEY ITSELF omits the key's authorization value
    /// from its command HMAC key (TPM 2.0 Library Part 1, clause 16.6.10, equation 22) but the cipher key keeps
    /// it — "the binding of the session is ignored" for parameter encryption (clause 18.1) — so a
    /// decrypt-protected <c>TPM2_HMAC()</c> over such a session returns the published value only when the
    /// simulator folds the key's LIVE authorization value into the keystream regardless of the bind.
    /// </summary>
    [TestMethod]
    public async Task HmacOverADecryptSessionBoundToTheKeyItselfFoldsTheLiveAuthValueIntoTheCipherKey() =>
        await RunProtectedHmacAsync(nameof(HmacOverADecryptSessionBoundToTheKeyItselfFoldsTheLiveAuthValueIntoTheCipherKey), TpmtSymDef.Xor(SessionAlg), TpmaSession.DECRYPT, isBoundToKey: true).ConfigureAwait(false);

    /// <summary>
    /// <c>TPM2_HMAC_Start()</c>'s <c>auth</c> — its sized first parameter (TPM 2.0 Library Part 3, clause 17.2,
    /// Table 80) — crosses decrypt-protected and is installed as the sequence's authorization value in plaintext:
    /// the sequence then updates and completes under that password to the published RFC 4231 case 3 value, which
    /// a mis-recovered <c>auth</c> would fail at the sequence's own password compare.
    /// </summary>
    [TestMethod]
    public async Task HmacStartOverADecryptSessionRecoversTheSequenceAuthAndCompletesToThePublishedValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacStartOverADecryptSessionRecoversTheSequenceAuthAndCompletesToThePublishedValue), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(SessionAlg), isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        uint sequenceHandle = 0;
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

            TpmResult<HmacStartResponse> startResult = await HmacKeyHarness.HmacStartOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), TpmAlgIdConstants.TPM_ALG_SHA256, SequencePassword, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"TPM2_HMAC_Start() over a decrypt session must succeed: '{startResult.ResponseCode}'.");
            sequenceHandle = startResult.Value.SequenceHandle.Value;

            TpmResult<SequenceUpdateResponse> updateResult = await HmacKeyHarness.SequenceUpdateAsync(
                tpm, registry, pool, TpmiDhObject.FromValue(sequenceHandle), Rfc4231Case3Data, SequencePassword, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(updateResult.IsSuccess, $"TPM2_SequenceUpdate() under the recovered sequence password failed: '{updateResult.ResponseCode}'.");

            TpmResult<SequenceCompleteResponse> completeResult = await HmacKeyHarness.SequenceCompleteAsync(
                tpm, registry, pool, TpmiDhObject.FromValue(sequenceHandle), ReadOnlyMemory<byte>.Empty, SequencePassword, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() under the recovered sequence password failed: '{completeResult.ResponseCode}'.");
            using SequenceCompleteResponse completed = completeResult.Value;
            sequenceHandle = 0;

            Assert.IsTrue(completed.Result.AsReadOnlySpan().SequenceEqual(Rfc4231Case3Sha256), "The sequence opened under a decrypt-protected auth must complete to the published RFC 4231 case 3 value.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sequenceHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Confidentiality on the wire: the <c>TPM2_HMAC()</c> command bytes sent over a decrypt session carry no
    /// octet of the message, while the same command over the same session without the attribute carries it in
    /// the clear (TPM 2.0 Library Part 1, clause 18.1 — the data portion of the first parameter is transformed,
    /// its size field is not).
    /// </summary>
    [TestMethod]
    public async Task TheDecryptProtectedCommandCarriesNoMessageOctetsWhileThePlainControlDoes()
    {
        (byte[] protectedBytes, byte[] plainBytes) = await CaptureHmacWireAsync(
            nameof(TheDecryptProtectedCommandCarriesNoMessageOctetsWhileThePlainControlDoes), TpmaSession.DECRYPT, captureResponse: false).ConfigureAwait(false);

        Assert.IsLessThan(0, protectedBytes.AsSpan().IndexOf(Rfc4231Case1Data), "A decrypt-protected command must not carry the message in the clear.");
        Assert.IsGreaterThanOrEqualTo(0, plainBytes.AsSpan().IndexOf(Rfc4231Case1Data), "The unprotected control must carry the message in the clear.");
    }

    /// <summary>
    /// Confidentiality on the wire: the <c>TPM2_HMAC()</c> response bytes returned over an encrypt session carry
    /// no octet of the published HMAC, while the same command over the same session without the attribute
    /// returns it in the clear (TPM 2.0 Library Part 1, clause 18.1, response direction; Part 3, clause 15.5,
    /// Table 72).
    /// </summary>
    [TestMethod]
    public async Task TheEncryptProtectedResponseCarriesNoHmacOctetsWhileThePlainControlDoes()
    {
        (byte[] protectedBytes, byte[] plainBytes) = await CaptureHmacWireAsync(
            nameof(TheEncryptProtectedResponseCarriesNoHmacOctetsWhileThePlainControlDoes), TpmaSession.ENCRYPT, captureResponse: true).ConfigureAwait(false);

        Assert.IsLessThan(0, protectedBytes.AsSpan().IndexOf(Rfc4231Case1Sha256), "An encrypt-protected response must not carry outHMAC in the clear.");
        Assert.IsGreaterThanOrEqualTo(0, plainBytes.AsSpan().IndexOf(Rfc4231Case1Sha256), "The unprotected control must carry outHMAC in the clear.");
    }

    /// <summary>
    /// <c>TPM2_HMAC_Start()</c> returns no parameter (TPM 2.0 Library Part 3, clause 17.2, Table 81), so a
    /// session claiming <c>encrypt</c> on it is refused <c>TPM_RC_ATTRIBUTES</c> session-encoded to the slot
    /// (Part 1, clause 18.1: only a sized first response parameter can be encrypted; Part 2, clause 6.6.2). The
    /// host executor refuses the claim client-side for the same reason, so the bit is planted on the wire.
    /// </summary>
    [TestMethod]
    public async Task HmacStartWithAPlantedEncryptAttributeIsRefusedWithAttributes()
    {
        TpmRcConstants responseCode = await PlantAttributeOnKeyedHashCommandAsync(
            nameof(HmacStartWithAPlantedEncryptAttributeIsRefusedWithAttributes), TpmCcConstants.TPM_CC_HMAC_Start, TpmtSymDef.Xor(SessionAlg), TpmaSession.ENCRYPT).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), responseCode, "encrypt on a command with no response parameter must be TPM_RC_ATTRIBUTES at slot 0.");
    }

    /// <summary>
    /// No audit trail is modelled for the HMAC family, so a session claiming <c>audit</c> on <c>TPM2_HMAC()</c> is
    /// refused <c>TPM_RC_ATTRIBUTES</c> session-encoded to the slot rather than echoed back unaudited (TPM 2.0
    /// Library Part 3, clause 5.5; Part 2, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task HmacWithAPlantedAuditAttributeIsRefusedWithAttributes()
    {
        TpmRcConstants responseCode = await PlantAttributeOnKeyedHashCommandAsync(
            nameof(HmacWithAPlantedAuditAttributeIsRefusedWithAttributes), TpmCcConstants.TPM_CC_HMAC, TpmtSymDef.Null, TpmaSession.AUDIT).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), responseCode, "audit on an unaudited command must be TPM_RC_ATTRIBUTES at slot 0.");
    }

    /// <summary>
    /// "If the symmetric algorithm is TPM_ALG_NULL and encryption or decryption is specified, the TPM returns
    /// TPM_RC_SYMMETRIC" (TPM 2.0 Library Part 1, clause 18.1): a <c>decrypt</c> claim planted on a session that
    /// negotiated no symmetric algorithm is refused <c>TPM_RC_SYMMETRIC</c> session-encoded to the slot.
    /// </summary>
    [TestMethod]
    public async Task HmacWithAPlantedDecryptAttributeOnANullSymmetricSessionIsRefusedWithSymmetric()
    {
        TpmRcConstants responseCode = await PlantAttributeOnKeyedHashCommandAsync(
            nameof(HmacWithAPlantedDecryptAttributeOnANullSymmetricSessionIsRefusedWithSymmetric), TpmCcConstants.TPM_CC_HMAC, TpmtSymDef.Null, TpmaSession.DECRYPT).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_SYMMETRIC, sessionIndex: 0), responseCode, "decrypt over a TPM_ALG_NULL session must be TPM_RC_SYMMETRIC at slot 0.");
    }

    /// <summary>
    /// Runs one <c>TPM2_HMAC()</c> over a bound HMAC session negotiating <paramref name="symmetric"/> and carrying
    /// <paramref name="attributes"/>, against a key whose authorization value is <see cref="KeyPassword"/>, and
    /// asserts the published RFC 4231 case 1 value came back — the one observable that pins both keystream
    /// directions.
    /// </summary>
    /// <param name="testName">The calling test's name, naming the simulator instance.</param>
    /// <param name="symmetric">The symmetric definition the session negotiates.</param>
    /// <param name="attributes">The parameter-encryption attributes the session carries beside <c>continueSession</c>.</param>
    /// <param name="isBoundToKey">Whether the session is bound to the HMAC key itself (its authorization value in the bind) rather than to the empty-auth parent.</param>
    private async Task RunProtectedHmacAsync(string testName, TpmtSymDef symmetric, TpmaSession attributes, bool isBoundToKey)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(testName, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = isBoundToKey
            ? await HmacKeyHarness.StartBoundHmacSessionAsync(tpm, registry, pool, key.Handle, KeyPassword, symmetric, isBoundToAuthorizedEntity: true, TestContext.CancellationToken).ConfigureAwait(false)
            : await HmacKeyHarness.StartBoundHmacSessionAsync(tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, symmetric, isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            session.SetAuthValue(KeyPassword, pool);
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | attributes;

            TpmResult<HmacResponse> result = await HmacKeyHarness.HmacOverSessionAsync(
                tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsSuccess, $"TPM2_HMAC() over a '{symmetric.Algorithm}' session carrying '{attributes}' must succeed: '{result.ResponseCode}'.");
            using HmacResponse outHmac = result.Value;
            Assert.IsTrue(outHmac.OutHmac.AsReadOnlySpan().SequenceEqual(Rfc4231Case1Sha256), "The parameter-protected HMAC must equal the published RFC 4231 case 1 value.");
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Captures the <c>TPM2_HMAC()</c> wire bytes twice over one XOR session — once carrying
    /// <paramref name="attribute"/> and once carrying nothing — so a confidentiality claim can be checked against
    /// its own control.
    /// </summary>
    /// <param name="testName">The calling test's name, naming the simulator instance.</param>
    /// <param name="attribute">The attribute the protected run's session carries.</param>
    /// <param name="captureResponse">Whether to capture the response bytes rather than the command bytes.</param>
    /// <returns>The protected bytes and the unprotected ones.</returns>
    private async Task<(byte[] Protected, byte[] Plain)> CaptureHmacWireAsync(string testName, TpmaSession attribute, bool captureResponse)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(testName, pool, TestContext.CancellationToken).ConfigureAwait(false);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        byte[]? captured = null;
        using TpmDevice tpm = TpmDevice.Create(async (command, commandPool, cancellationToken) =>
        {
            bool isHmac = ReadCommandCode(command.Span) == TpmCcConstants.TPM_CC_HMAC;
            if(isHmac && !captureResponse)
            {
                captured = command.ToArray();
            }

            TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, commandPool, cancellationToken).ConfigureAwait(false);
            if(isHmac && captureResponse && result.IsSuccess)
            {
                captured = result.Value.AsReadOnlySpan().ToArray();
            }

            return result;
        });

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(SessionAlg), isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | attribute;
            await HmacOnceAsync(tpm, registry, pool, session, key).ConfigureAwait(false);
            byte[] protectedBytes = captured!;
            captured = null;

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION;
            await HmacOnceAsync(tpm, registry, pool, session, key).ConfigureAwait(false);

            return (protectedBytes, captured!);
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Issues one <c>TPM2_HMAC()</c> over <paramref name="session"/> that must succeed and return the published case 1 value.</summary>
    /// <param name="tpm">The device to submit through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The authorizing session, its attributes already set.</param>
    /// <param name="key">The loaded RFC 4231 case 1 key.</param>
    private async Task HmacOnceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSession session, HmacKeyHarness.LoadedHmacKey key)
    {
        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacOverSessionAsync(
            tpm, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HMAC() over the session carrying '{session.SessionAttributes}' must succeed: '{result.ResponseCode}'.");
        using HmacResponse outHmac = result.Value;
        Assert.IsTrue(outHmac.OutHmac.AsReadOnlySpan().SequenceEqual(Rfc4231Case1Sha256), "The HMAC must equal the published RFC 4231 case 1 value.");
    }

    /// <summary>
    /// Runs <paramref name="commandCode"/> (<c>TPM2_HMAC()</c> or <c>TPM2_HMAC_Start()</c>) over a bound HMAC
    /// session negotiating <paramref name="symmetric"/> with <paramref name="attribute"/> planted onto the slot's
    /// attributes octet on the wire, and returns what the simulator answered.
    /// </summary>
    /// <param name="testName">The calling test's name, naming the simulator instance.</param>
    /// <param name="commandCode">The command whose wire bytes are rewritten.</param>
    /// <param name="symmetric">The symmetric definition the session negotiates.</param>
    /// <param name="attribute">The attribute planted onto the slot.</param>
    /// <returns>The response code the simulator answered.</returns>
    private async Task<TpmRcConstants> PlantAttributeOnKeyedHashCommandAsync(string testName, TpmCcConstants commandCode, TpmtSymDef symmetric, TpmaSession attribute)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(testName, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, symmetric, isBoundToAuthorizedEntity: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using TpmDevice plantingDevice = CreateRewritingDevice(simulator, commandCode, command => WithSlotZeroAttribute(command, attribute));

            if(commandCode == TpmCcConstants.TPM_CC_HMAC)
            {
                TpmResult<HmacResponse> result = await HmacKeyHarness.HmacOverSessionAsync(
                    plantingDevice, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(result.IsSuccess, "A planted session-area attribute must be refused.");

                return result.ResponseCode;
            }

            TpmResult<HmacStartResponse> startResult = await HmacKeyHarness.HmacStartOverSessionAsync(
                plantingDevice, registry, pool, session, key.Handle, key.Name.AsReadOnlyMemory(), TpmAlgIdConstants.TPM_ALG_SHA256, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(startResult.IsSuccess, "A planted session-area attribute must be refused.");

            return startResult.ResponseCode;
        }
        finally
        {
            session.Dispose();
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Reads a framed command's <c>commandCode</c> field (TPM 2.0 Library Part 1, clause 15.2.3's commandCode header field).</summary>
    /// <param name="command">The framed command.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(ReadOnlySpan<byte> command) =>
        (TpmCcConstants)BinaryPrimitives.ReadUInt32BigEndian(command[(sizeof(ushort) + sizeof(uint))..]);

    /// <summary>
    /// Wraps the simulator in a device that rewrites the wire bytes of exactly one command code on their way in,
    /// leaving every other command untouched.
    /// </summary>
    /// <param name="simulator">The simulator the rewritten command is submitted to.</param>
    /// <param name="commandCode">The command whose bytes are rewritten.</param>
    /// <param name="rewrite">The rewrite to apply.</param>
    /// <returns>The rewriting device; the caller owns it.</returns>
    private static TpmDevice CreateRewritingDevice(TpmSimulator simulator, TpmCcConstants commandCode, Func<byte[], byte[]> rewrite)
    {
        return TpmDevice.Create(async (command, commandPool, cancellationToken) =>
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == commandCode)
            {
                bytes = rewrite(bytes);
            }

            return await simulator.SubmitAsync(bytes, commandPool, cancellationToken).ConfigureAwait(false);
        });
    }

    /// <summary>
    /// Sets attribute bits in the <c>sessionAttributes</c> octet of the single <c>TPMS_AUTH_COMMAND</c> block of
    /// a one-handle command, leaving every other octet of the frame alone.
    /// </summary>
    /// <param name="command">The framed command.</param>
    /// <param name="attribute">The attribute bits to set.</param>
    /// <returns>The rewritten command.</returns>
    private static byte[] WithSlotZeroAttribute(byte[] command, TpmaSession attribute)
    {
        byte[] rewritten = (byte[])command.Clone();

        //Header, the one handle, authorizationSize, the slot's session handle, then the slot's nonceCaller.
        int cursor = HeaderSize + sizeof(uint) + sizeof(uint) + sizeof(uint);
        ushort nonceSize = BinaryPrimitives.ReadUInt16BigEndian(rewritten.AsSpan(cursor));
        cursor += sizeof(ushort) + nonceSize;
        rewritten[cursor] |= (byte)attribute;

        return rewritten;
    }

    /// <summary>The <c>TPM2_PolicyAuthValue()</c> policyDigest for <see cref="SessionAlg"/> — H(0 ‖ TPM_CC_PolicyAuthValue).</summary>
    /// <returns>The predicted digest.</returns>
    private static byte[] PolicyAuthValueDigest()
    {
        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] digest = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForAuthValue(zero, SessionAlg, digest);

        return digest;
    }

    /// <summary>The <c>TPM2_PolicyCommandCode()</c> policyDigest for <see cref="SessionAlg"/> binding <paramref name="commandCode"/>.</summary>
    /// <param name="commandCode">The command code the policy binds.</param>
    /// <returns>The predicted digest.</returns>
    private static byte[] PolicyCommandCodeDigest(TpmCcConstants commandCode)
    {
        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] digest = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForCommandCode(zero, commandCode, SessionAlg, digest);

        return digest;
    }
}
