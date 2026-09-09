using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
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
/// Drives the audit-session mechanic (TPM 2.0 Library Part 1, clause 17; Part 2, clause 8.4, Table 38) over
/// <c>TPM2_GetRandom()</c> and the zero-handle authorization-slot table it shares with <c>TPM2_StirRandom()</c>
/// and <c>TPM2_TestParms()</c>, against the in-house behavioural <see cref="TpmSimulator"/>, entirely in-process.
/// Every audit digest a test asserts is chained by the test itself from the command's own octets — cpHash per
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.7</see>
/// equation 15, rpHash per clause 15.8 equation 16, and the fold per clause 17.1 equation 30 — using the
/// project's own digest primitive, never <see cref="TpmSession"/>'s internal computation; the readback runs
/// through the production <see cref="TpmCommandExecutor"/> with <c>TPM2_GetSessionAuditDigest()</c>'s NULL
/// signer. A companion session's own command and response HMACs are still driven and verified through the
/// production <see cref="TpmSession"/>/<see cref="TpmCommandExecutor"/> path (the same cross-implementation
/// end-to-end check <c>TpmInHouseSimulatorHmacSessionTests</c> already establishes) — an unbound, unauthorizing
/// companion authorizes no entity, so its authValue and sessionKey are both the Empty Buffer and no HMAC
/// computation is performed at all (TPM 2.0 Library Part 1, clause 17.1).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorAuditSessionTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The session hash algorithm every session in this class negotiates.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The SHA-256 digest width, in octets — the audit digest width for every session here.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The octet count <c>TPM2_GetRandom()</c> is asked to draw in every case.</summary>
    private const ushort RandomDrawLength = 16;

    /// <summary>The Zero Digest an audit session's first use or an <c>auditReset</c> extends from (TPM 2.0 Library Part 1, clause 17.1).</summary>
    private static byte[] ZeroDigestSha256 { get; } = new byte[Sha256DigestSize];

    /// <summary>
    /// The parameter area every <c>TPM2_GetRandom()</c> this class audits carries on the wire — <c>bytesRequested</c>
    /// as a <c>UINT16</c> (TPM 2.0 Library Part 3, clause 16.1, Table 75) — the <c>parameters</c> term of equation
    /// 15's cpHash, laid out here by the same writer the command input uses rather than read back from any state.
    /// </summary>
    private static byte[] GetRandomParameters { get; } = [(byte)(RandomDrawLength >> 8), (byte)(RandomDrawLength & 0xFF)];

    /// <summary>
    /// The <c>TPMT_PUBLIC_PARMS</c> a <c>TPM2_TestParms()</c> case carries: RSA-2048 with RSASSA over SHA-256 and
    /// no symmetric definition — a combination this simulator implements, so its own response is never a parse
    /// refusal masquerading as a session-mechanic one.
    /// </summary>
    private static TpmtPublicParms RsaSigningParms { get; } = TpmtPublicParms.Create(
        TpmAlgIdConstants.TPM_ALG_RSA,
        TpmuPublicParms.Rsa(TpmsRsaParms.ForSigning(2048, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256))));

    /// <summary>
    /// A companion claiming <c>audit</c> alone on <c>TPM2_GetRandom()</c> succeeds and the response echoes
    /// <c>audit</c> SET, <c>auditExclusive</c> SET (a first use always grants exclusivity), and
    /// <c>auditReset</c> CLEAR — the response authorization verifying end to end through the production session.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1; Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    [TestMethod]
    public async Task UnboundAuditCompanionOnGetRandomSucceedsAndEchoesTheAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(UnboundAuditCompanionOnGetRandomSucceedsAndEchoesTheAttributes), pool).ConfigureAwait(false);
        List<byte[]> responses = [];
        using TpmDevice device = CreateResponseCapturingDevice(simulator, responses);
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"An audit-only companion must be admitted on TPM2_GetRandom(): '{result.ResponseCode}'.");
            result.Value.Dispose();

            (TpmRcConstants code, byte[] parameters, TpmsAuthResponse session0) = ParseSingleSessionResponse(responses[^1], pool);
            using(session0)
            {
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "The captured response header must report success.");
                Assert.IsNotEmpty(parameters, "GetRandom's response must carry randomBytes.");
                Assert.AreEqual(TpmaSession.AUDIT, session0.SessionAttributes & TpmaSession.AUDIT, "audit must be echoed SET in the response.");
                Assert.AreEqual(TpmaSession.AUDIT_EXCLUSIVE, session0.SessionAttributes & TpmaSession.AUDIT_EXCLUSIVE, "auditExclusive must be SET on a first use.");
                Assert.AreEqual((TpmaSession)0, session0.SessionAttributes & TpmaSession.AUDIT_RESET, "auditReset must be CLEAR in the response.");
            }
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A first audit use extends the digest to <c>H(0...0 ‖ cpHash ‖ rpHash)</c>, which the test chains itself
    /// from the wire and which <c>TPM2_GetSessionAuditDigest()</c>'s NULL signer reads back unchanged.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1, equation 30; Part 3, clause 18.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task UnboundAuditCompanionOnGetRandomExtendsTheDigestFromZero()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(UnboundAuditCompanionOnGetRandomExtendsTheDigestFromZero), pool).ConfigureAwait(false);
        List<byte[]> responses = [];
        using TpmDevice device = CreateResponseCapturingDevice(simulator, responses);
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            await RunGetRandomAsync(device, registry, pool, session).ConfigureAwait(false);

            using DigestValue expected = await ComputeExpectedDigestAsync(ZeroDigestSha256, TpmCcConstants.TPM_CC_GetRandom, GetRandomParameters, responses[^1], pool).ConfigureAwait(false);
            (TpmiYesNo exclusive, byte[] digest) = await ReadAuditDigestAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);

            Assert.IsTrue(digest.AsSpan().SequenceEqual(expected.AsReadOnlySpan()), "The attested sessionDigest must equal H(0...0 || cpHash || rpHash) chained from the wire.");
            Assert.IsTrue(exclusive.IsYes, "A first-use session is exclusive: exclusiveSession must be YES.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A session claiming <c>CONTINUE_SESSION | ENCRYPT | AUDIT</c> on <c>TPM2_GetRandom()</c> chains its audit
    /// digest over the CIPHERTEXT response octets, not the plaintext the session decrypts: "Audit within an
    /// encrypted session will record the encrypted cpHash and/or rpHash, which is unlikely to be useful at the
    /// application level." Encryption runs before rpHash is computed (Part 1, clause 18.1), so the digest the
    /// test chains from the RAW wire octets matches the attested digest, while the same fold computed over the
    /// decrypted plaintext does not.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1</see>.
    /// </summary>
    [TestMethod]
    public async Task AnAuditCompanionAlsoClaimingEncryptChainsTheDigestOverTheCiphertextNotThePlaintext()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(AnAuditCompanionAlsoClaimingEncryptChainsTheDigestOverTheCiphertextNotThePlaintext), pool).ConfigureAwait(false);
        List<byte[]> responses = [];
        using TpmDevice device = CreateResponseCapturingDevice(simulator, responses);
        TpmResponseRegistry registry = CreateRegistry();

        TpmtSymDef symmetric = TpmtSymDef.Xor(SessionAlg);
        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry, symmetric).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT | TpmaSession.AUDIT;
            TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"An audit companion also claiming encrypt must succeed: '{result.ResponseCode}'.");

            byte[] plaintextRandomBytes;
            using(GetRandomResponse response = result.Value)
            {
                plaintextRandomBytes = response.RandomBytes.AsReadOnlySpan().ToArray();
            }

            byte[] capturedCiphertextResponse = responses[^1];
            using DigestValue ciphertextDigest = await ComputeExpectedDigestAsync(
                ZeroDigestSha256, TpmCcConstants.TPM_CC_GetRandom, GetRandomParameters, capturedCiphertextResponse, pool).ConfigureAwait(false);

            int cipherOctetsOffset = TpmHeader.HeaderSize + sizeof(uint) + sizeof(ushort);
            byte[] syntheticPlaintextResponse = (byte[])capturedCiphertextResponse.Clone();
            plaintextRandomBytes.CopyTo(syntheticPlaintextResponse.AsSpan(cipherOctetsOffset, plaintextRandomBytes.Length));
            using DigestValue plaintextDigest = await ComputeExpectedDigestAsync(
                ZeroDigestSha256, TpmCcConstants.TPM_CC_GetRandom, GetRandomParameters, syntheticPlaintextResponse, pool).ConfigureAwait(false);

            (_, byte[] readBack) = await ReadAuditDigestAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);

            Assert.IsTrue(
                readBack.AsSpan().SequenceEqual(ciphertextDigest.AsReadOnlySpan()),
                "The attested digest must equal H(0...0 || cpHash || rpHash) chained over the CIPHERTEXT response octets as framed on the wire.");
            Assert.IsFalse(
                readBack.AsSpan().SequenceEqual(plaintextDigest.AsReadOnlySpan()),
                "The same fold computed over the decrypted PLAINTEXT must not match the attested digest — the audit digest records the encrypted octets.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A second successful audited command extends the PRIOR digest, not the Zero Digest: digest2 =
    /// <c>H(digest1 ‖ cpHash2 ‖ rpHash2)</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1, equation 30</see>.
    /// </summary>
    [TestMethod]
    public async Task TwoAuditedGetRandomCommandsChainTheDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(TwoAuditedGetRandomCommandsChainTheDigest), pool).ConfigureAwait(false);
        List<byte[]> responses = [];
        using TpmDevice device = CreateResponseCapturingDevice(simulator, responses);
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            await RunGetRandomAsync(device, registry, pool, session).ConfigureAwait(false);
            using DigestValue digest1 = await ComputeExpectedDigestAsync(ZeroDigestSha256, TpmCcConstants.TPM_CC_GetRandom, GetRandomParameters, responses[^1], pool).ConfigureAwait(false);

            await RunGetRandomAsync(device, registry, pool, session).ConfigureAwait(false);
            using DigestValue digest2 = await ComputeExpectedDigestAsync(digest1.AsReadOnlyMemory(), TpmCcConstants.TPM_CC_GetRandom, GetRandomParameters, responses[^1], pool).ConfigureAwait(false);

            (_, byte[] readBack) = await ReadAuditDigestAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
            Assert.IsTrue(readBack.AsSpan().SequenceEqual(digest2.AsReadOnlySpan()), "The second command's digest must chain onto the first, not restart from zero.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A session that has never claimed <c>audit</c> successfully is not an audit session: <c>TPM2_GetSessionAuditDigest()</c>
    /// refuses it with <c>TPM_RC_TYPE</c> naming sessionHandle, handle 3 of Table 103 — "A session does not
    /// become an audit session until the successful completion of the command in which the session is first
    /// used as an audit session."
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ANeverAuditedSessionIsAnsweredTypeAtGetSessionAuditDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ANeverAuditedSessionIsAnsweredTypeAtGetSessionAuditDigest), pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        try
        {
            using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(sessionHandle), ReadOnlySpan<byte>.Empty, pool);
            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                device, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A session never used for audit must not attest a digest.");
            Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 2), result.ResponseCode, "A session that is not an audit session is refused at sessionHandle, handle 3 of Table 103.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A bad command HMAC on a session's own first audit-claiming use leaves the session as it was: "if a session
    /// was not an audit session before the command was executed, it will not be an audit session after the
    /// command fails" — the session answers <c>TPM_RC_TYPE</c> at sessionHandle, handle 3 of Table 103, just as
    /// an untouched session would.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.5</see>.
    /// </summary>
    [TestMethod]
    public async Task ABadCommandHmacOnAnAuditSlotsFirstUseNeverBecomesAudit()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ABadCommandHmacOnAnAuditSlotsFirstUseNeverBecomesAudit), pool).ConfigureAwait(false);
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(plainDevice, pool, registry).ConfigureAwait(false);
        try
        {
            using TpmDevice corruptingDevice = CreateHmacCorruptingDevice(simulator, TpmCcConstants.TPM_CC_GetRandom, session);
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                corruptingDevice, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(result.IsSuccess, "A wire-corrupted command HMAC must be refused.");

            using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(sessionHandle), ReadOnlySpan<byte>.Empty, pool);
            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            TpmResult<GetSessionAuditDigestResponse> readBack = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                plainDevice, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 2), readBack.ResponseCode, "A failed first use must leave the session non-audit.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(plainDevice, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A bad command HMAC on an ALREADY-established audit session's later use leaves its digest unchanged: "when
    /// a command fails, the audit session digest is not changed."
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ABadCommandHmacOnAnEstablishedAuditSessionLeavesItsDigestUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ABadCommandHmacOnAnEstablishedAuditSessionLeavesItsDigestUnchanged), pool).ConfigureAwait(false);
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        List<byte[]> responses = [];
        using TpmDevice capturingDevice = CreateResponseCapturingDevice(simulator, responses);
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(plainDevice, pool, registry).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            await RunGetRandomAsync(capturingDevice, registry, pool, session).ConfigureAwait(false);
            using DigestValue established = await ComputeExpectedDigestAsync(ZeroDigestSha256, TpmCcConstants.TPM_CC_GetRandom, GetRandomParameters, responses[^1], pool).ConfigureAwait(false);

            using TpmDevice corruptingDevice = CreateHmacCorruptingDevice(simulator, TpmCcConstants.TPM_CC_GetRandom, session);
            TpmResult<GetRandomResponse> failed = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                corruptingDevice, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(failed.IsSuccess, "The wire-corrupted second command must be refused.");

            (_, byte[] readBack) = await ReadAuditDigestAsync(plainDevice, registry, pool, sessionHandle).ConfigureAwait(false);
            Assert.IsTrue(readBack.AsSpan().SequenceEqual(established.AsReadOnlySpan()), "A failed command must not extend the established digest.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(plainDevice, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>auditReset</c> on an established audit session re-zeroes the digest before extending: the read-back
    /// digest equals <c>H(0...0 ‖ cpHash2 ‖ rpHash2)</c> of the reset command alone, and the response echoes
    /// <c>auditReset</c> CLEAR (Table 38: "this bit is always CLEAR in a response") with <c>auditExclusive</c> SET.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1; Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    [TestMethod]
    public async Task AuditResetReZeroesThenExtendsAndClearsInTheResponse()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(AuditResetReZeroesThenExtendsAndClearsInTheResponse), pool).ConfigureAwait(false);
        List<byte[]> responses = [];
        using TpmDevice device = CreateResponseCapturingDevice(simulator, responses);
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            await RunGetRandomAsync(device, registry, pool, session).ConfigureAwait(false);

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_RESET;
            await RunGetRandomAsync(device, registry, pool, session).ConfigureAwait(false);

            (TpmRcConstants code, _, TpmsAuthResponse resetEntry) = ParseSingleSessionResponse(responses[^1], pool);
            using(resetEntry)
            {
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "auditReset on an established session must succeed.");
                Assert.AreEqual((TpmaSession)0, resetEntry.SessionAttributes & TpmaSession.AUDIT_RESET, "auditReset must be CLEAR in the response (Table 38).");
                Assert.AreEqual(TpmaSession.AUDIT_EXCLUSIVE, resetEntry.SessionAttributes & TpmaSession.AUDIT_EXCLUSIVE, "auditReset re-obtains exclusivity.");
            }

            using DigestValue expected = await ComputeExpectedDigestAsync(ZeroDigestSha256, TpmCcConstants.TPM_CC_GetRandom, GetRandomParameters, responses[^1], pool).ConfigureAwait(false);
            (_, byte[] readBack) = await ReadAuditDigestAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
            Assert.IsTrue(readBack.AsSpan().SequenceEqual(expected.AsReadOnlySpan()), "auditReset's digest must equal H(0...0 || cpHash || rpHash) of the reset command ALONE, excluding the prior command.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>auditExclusive</c> claimed on a session's first audit use is admitted (a first use always grants
    /// exclusivity), and the response echoes it SET — the Reference Code's behaviour, followed here over the
    /// published narrative's own consequence sentences. TPM 2.0 Library Part 1, Table 15, the <c>auditExclusive</c>
    /// row: "Evaluation of the exclusive status is done at the start of the command. A session does not obtain
    /// the exclusive status until the end of the command (this prevents a session from becoming exclusive if the
    /// command fails). The implication of this processing is that, if this attribute is SET in the command that
    /// starts the audit sequence, the command will fail because the session has not yet become exclusive." Part
    /// 2, clause 8.4, Table 38, bit 1: "SET (1): In a command, this setting indicates that the command should
    /// only be executed if the session is exclusive at the start of the command." Against both, this TPM admits
    /// the claim exactly as the Reference Code does: a reset of the audit session, or the session's first use as
    /// an audit session, grants exclusivity immediately regardless of the exclusive state at the start of the
    /// command — under the interface-behaviour rule Part 1, clause 2.5 states for every implementation: "A TPM
    /// need not be implemented using the Reference Code. However, any implementation
    /// should provide equivalent or, in most cases, identical results as observed at the TPM interface or
    /// demonstrated through evaluation."
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.3</see>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    [TestMethod]
    public async Task AuditExclusiveOnFirstUseIsAdmittedAndSetInTheResponse()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(AuditExclusiveOnFirstUseIsAdmittedAndSetInTheResponse), pool).ConfigureAwait(false);
        List<byte[]> responses = [];
        using TpmDevice device = CreateResponseCapturingDevice(simulator, responses);
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE;
            TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"auditExclusive claimed on a first use must be admitted: '{result.ResponseCode}'.");
            result.Value.Dispose();

            (_, _, TpmsAuthResponse entry) = ParseSingleSessionResponse(responses[^1], pool);
            using(entry)
            {
                Assert.AreEqual(TpmaSession.AUDIT_EXCLUSIVE, entry.SessionAttributes & TpmaSession.AUDIT_EXCLUSIVE, "The response must echo auditExclusive SET.");
            }
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>auditExclusive</c> claimed on an established, non-exclusive session is refused with the format-zero
    /// <c>TPM_RC_EXCLUSIVE</c> (RC_VER1 + 0x019, carrying no handle, session, or parameter designation) once a
    /// plain <c>TPM_ST_NO_SESSIONS</c> <c>TPM2_GetRandom()</c> has run without it
    /// — the refusal leaves the session untouched (its digest unchanged) and a following plain audited command
    /// still succeeds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.3</see>.
    /// </summary>
    [TestMethod]
    public async Task AuditExclusiveAfterAPlainNoSessionsGetRandomIsRefusedExclusiveAndDigestUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(AuditExclusiveAfterAPlainNoSessionsGetRandomIsRefusedExclusiveAndDigestUnchanged), pool).ConfigureAwait(false);
        List<byte[]> responses = [];
        using TpmDevice device = CreateResponseCapturingDevice(simulator, responses);
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            await RunGetRandomAsync(device, registry, pool, session).ConfigureAwait(false);
            using DigestValue established = await ComputeExpectedDigestAsync(ZeroDigestSha256, TpmCcConstants.TPM_CC_GetRandom, GetRandomParameters, responses[^1], pool).ConfigureAwait(false);

            TpmResult<GetRandomResponse> plain = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, new GetRandomInput(RandomDrawLength), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(plain.IsSuccess, "The intervening plain, sessionless TPM2_GetRandom() must itself succeed.");
            plain.Value.Dispose();

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE;
            TpmResult<GetRandomResponse> refused = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(refused.IsSuccess, "auditExclusive must be refused once the session is no longer exclusive.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_EXCLUSIVE, refused.ResponseCode, "TPM_RC_EXCLUSIVE is the format-zero RC_VER1 + 0x019, never session-encoded.");

            (_, byte[] readBack) = await ReadAuditDigestAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
            Assert.IsTrue(readBack.AsSpan().SequenceEqual(established.AsReadOnlySpan()), "The EXCLUSIVE refusal must leave the digest unchanged.");

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            TpmResult<GetRandomResponse> followUp = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(followUp.IsSuccess, "A following plain audited claim (without auditExclusive) must still succeed.");
            followUp.Value.Dispose();
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The exclusive session is cleared by a successful session-admitting command run without an audit session
    /// — here <c>TPM2_GetCapability()</c> over <c>TPM_ST_NO_SESSIONS</c> — so a subsequent <c>auditExclusive</c>
    /// claim on the previously-exclusive session is refused.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ExclusiveStatusClearedByGetCapabilityOverNoSessions()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ExclusiveStatusClearedByGetCapabilityOverNoSessions), pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            await RunGetRandomAsync(device, registry, pool, session).ConfigureAwait(false);

            TpmResult<GetCapabilityResponse> capabilityResult = await TpmCommandExecutor.ExecuteAsync<GetCapabilityResponse>(
                device, GetCapabilityInput.ForFixedProperties(1), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(capabilityResult.IsSuccess, $"TPM2_GetCapability() must succeed: '{capabilityResult.ResponseCode}'.");
            capabilityResult.Value.Dispose();

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE;
            TpmResult<GetRandomResponse> refused = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(refused.IsSuccess, "A prior TPM2_GetCapability() without an audit session must clear exclusivity.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_EXCLUSIVE, refused.ResponseCode, "The claim must be refused with the format-zero TPM_RC_EXCLUSIVE.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The exclusive session is cleared by a successful <c>TPM2_ReadClock()</c> run without an audit session:
    /// Part 3's own command table admits an audit session on <c>TPM2_ReadClock()</c> (Table 232) and Part 4
    /// carries no <c>NO_SESSIONS</c> flag for it, so it clears exclusivity like any other session-admitting
    /// command — the published text's own list in clause 17.2 naming it among the commands that never change
    /// exclusivity is the divergence the model does not follow (Part 3/Part 4 govern).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.2; Part 3, clause 29.1, Table 232</see>.
    /// </summary>
    [TestMethod]
    public async Task ExclusiveStatusClearedByReadClock()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ExclusiveStatusClearedByReadClock), pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            await RunGetRandomAsync(device, registry, pool, session).ConfigureAwait(false);

            TpmResult<ReadClockResponse> readClockResult = await TpmCommandExecutor.ExecuteAsync<ReadClockResponse>(
                device, new ReadClockInput(), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(readClockResult.IsSuccess, $"TPM2_ReadClock() must succeed: '{readClockResult.ResponseCode}'.");

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE;
            TpmResult<GetRandomResponse> refused = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(refused.IsSuccess, "A prior TPM2_ReadClock() without an audit session must clear exclusivity.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_EXCLUSIVE, refused.ResponseCode, "The claim must be refused with the format-zero TPM_RC_EXCLUSIVE.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The exclusive session is cleared by an audited command over a DIFFERENT audit session: a session becomes
    /// the current exclusive audit session "when it is first used as an audit session," displacing whoever held
    /// it, so the first session's own follow-up <c>auditExclusive</c> claim is then refused.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ExclusiveStatusClearedByAnotherAuditSessionsCommand()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ExclusiveStatusClearedByAnotherAuditSessionsCommand), pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint firstHandle, TpmSession first) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        (uint secondHandle, TpmSession second) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        try
        {
            first.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            await RunGetRandomAsync(device, registry, pool, first).ConfigureAwait(false);

            second.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            TpmResult<GetRandomResponse> secondUse = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, new GetRandomInput(RandomDrawLength), [second], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secondUse.IsSuccess, $"The second session's own first audit use must succeed: '{secondUse.ResponseCode}'.");
            secondUse.Value.Dispose();

            first.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE;
            TpmResult<GetRandomResponse> refused = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, new GetRandomInput(RandomDrawLength), [first], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(refused.IsSuccess, "The second session's own first use must have displaced the first session's exclusivity.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_EXCLUSIVE, refused.ResponseCode, "The claim must be refused with the format-zero TPM_RC_EXCLUSIVE.");
        }
        finally
        {
            first.Dispose();
            second.Dispose();
            await FlushIfPresentAsync(device, registry, pool, firstHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(device, registry, pool, secondHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_FlushContext()</c> of an UNRELATED session does not clear the exclusive session: "the session is
    /// no longer the current exclusive audit session if IT is flushed" — flushing a different handle leaves the
    /// exclusive session's own status intact, so its <c>auditExclusive</c> claim still succeeds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ExclusiveStatusNotClearedByFlushContextOfAnotherSession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ExclusiveStatusNotClearedByFlushContextOfAnotherSession), pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint exclusiveHandle, TpmSession exclusiveSession) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        (uint unrelatedHandle, TpmSession unrelatedSession) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        try
        {
            exclusiveSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            await RunGetRandomAsync(device, registry, pool, exclusiveSession).ConfigureAwait(false);

            unrelatedSession.Dispose();
            await FlushIfPresentAsync(device, registry, pool, unrelatedHandle).ConfigureAwait(false);
            unrelatedHandle = 0;

            exclusiveSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE;
            TpmResult<GetRandomResponse> stillExclusive = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, new GetRandomInput(RandomDrawLength), [exclusiveSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(stillExclusive.IsSuccess, $"Flushing an unrelated session must not clear the exclusive session's own status: '{stillExclusive.ResponseCode}'.");
            stillExclusive.Value.Dispose();
        }
        finally
        {
            exclusiveSession.Dispose();
            await FlushIfPresentAsync(device, registry, pool, exclusiveHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(device, registry, pool, unrelatedHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_ContextSave()</c>/<c>TPM2_ContextLoad()</c> of an UNRELATED loaded object does not clear the
    /// exclusive session: both commands are among Part 3's own four fixed <c>TPM_ST_NO_SESSIONS</c> tables,
    /// which "will not change the current exclusive audit session," regardless of which resource they carry.
    /// The object is created BEFORE the session's audited use, since <c>TPM2_CreatePrimary()</c> admits sessions
    /// and would itself clear the exclusive session were it to run afterwards.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ExclusiveStatusNotClearedByContextSaveAndLoadOfAnUnrelatedObject()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ExclusiveStatusNotClearedByContextSaveAndLoadOfAnUnrelatedObject), pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(device, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        uint reloadedHandle = 0;
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            await RunGetRandomAsync(device, registry, pool, session).ConfigureAwait(false);

            ContextSaveInput saveInput = ContextSaveInput.ForHandle(parentHandle);
            TpmResult<ContextSaveResponse> saveResult = await TpmCommandExecutor.ExecuteAsync<ContextSaveResponse>(
                device, saveInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(saveResult.IsSuccess, $"TPM2_ContextSave() of the unrelated parent failed: '{saveResult.ResponseCode}'.");
            using ContextSaveResponse saved = saveResult.Value;

            var loadInput = new ContextLoadInput(saved.Context);
            TpmResult<ContextLoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<ContextLoadResponse>(
                device, loadInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(loadResult.IsSuccess, $"TPM2_ContextLoad() of the unrelated parent failed: '{loadResult.ResponseCode}'.");
            reloadedHandle = loadResult.Value.LoadedHandle.Value;

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE;
            TpmResult<GetRandomResponse> stillExclusive = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(stillExclusive.IsSuccess, $"ContextSave/ContextLoad of an unrelated object must not clear exclusivity: '{stillExclusive.ResponseCode}'.");
            stillExclusive.Value.Dispose();
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(device, registry, pool, reloadedHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "This attribute has no meaning for a password authorization and is required to be CLEAR" — a
    /// <c>TPM_RS_PW</c> slot claiming <c>audit</c> on <c>TPM2_GetRandom()</c>'s zero-handle slot is refused
    /// session-encoded <c>TPM_RC_ATTRIBUTES</c> regardless of whether an audit session is otherwise admitted.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.6.4, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task APasswordSlotClaimingAuditOnGetRandomIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(APasswordSlotClaimingAuditOnGetRandomIsRefusedWithAttributes), pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmPasswordSession passwordSlot = TpmPasswordSession.CreateEmpty(pool);
        passwordSlot.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, new GetRandomInput(RandomDrawLength), [passwordSlot], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A password slot must never be admitted as an audit session.");
        Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), result.ResponseCode, "The refusal must be session-encoded ATTRIBUTES at slot 0.");
    }

    /// <summary>
    /// "audit may only be SET in one session per command or response" — two real sessions both claiming
    /// <c>audit</c> at <c>TPM2_GetSessionAuditDigest()</c>'s two authorizing slots is refused session-encoded
    /// <c>TPM_RC_ATTRIBUTES</c> at the SECOND slot.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.4</see>.
    /// </summary>
    [TestMethod]
    public async Task TwoAuditClaimsOnGetSessionAuditDigestAreRefusedAtTheSecondSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(TwoAuditClaimsOnGetSessionAuditDigestAreRefusedAtTheSecondSlot), pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint firstHandle, TpmSession first) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        (uint secondHandle, TpmSession second) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        try
        {
            first.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            second.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

            using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(firstHandle), ReadOnlySpan<byte>.Empty, pool);
            TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                device, input, [first, second], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A second audit claim in the same command must be refused.");
            Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), result.ResponseCode, "The refusal must be session-encoded ATTRIBUTES at the SECOND slot.");
        }
        finally
        {
            first.Dispose();
            second.Dispose();
            await FlushIfPresentAsync(device, registry, pool, firstHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(device, registry, pool, secondHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_TestParms()</c>'s over-session form has no command or response parameter for a slot to claim
    /// <c>decrypt</c> or <c>encrypt</c> over, but an audit-only companion is admitted and the command succeeds
    /// with the echo — the cell the family-wide audit flip closes for TestParms specifically.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1; Part 3, clause 30.3</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsOverAnAuditOnlyCompanionSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(TestParmsOverAnAuditOnlyCompanionSucceeds), pool).ConfigureAwait(false);
        List<byte[]> responses = [];
        using TpmDevice device = CreateResponseCapturingDevice(simulator, responses);
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            TpmResult<TestParmsResponse> result = await TpmCommandExecutor.ExecuteAsync<TestParmsResponse>(
                device, new TestParmsInput(RsaSigningParms), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_TestParms() over an audit-only companion must succeed: '{result.ResponseCode}'.");

            (TpmRcConstants code, _, TpmsAuthResponse entry) = ParseSingleSessionResponse(responses[^1], pool);
            using(entry)
            {
                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "The captured response must report success.");
                Assert.AreEqual(TpmaSession.AUDIT, entry.SessionAttributes & TpmaSession.AUDIT, "audit must be echoed SET.");
            }
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An audited session's <c>TPM2_ContextSave()</c> then <c>TPM2_ContextLoad()</c> keeps its digest, its audit
    /// status, and its exclusivity: the two new <see cref="HmacSessionState"/> fields ride the same serialized
    /// session record N7/N8 already move, and neither ContextSave nor ContextLoad ever change the exclusive
    /// session (Part 3's fixed <c>TPM_ST_NO_SESSIONS</c> tables).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.5</see>.
    /// </summary>
    [TestMethod]
    public async Task AnAuditedSessionSavedThenLoadedKeepsItsDigestStatusAndExclusivity()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(AnAuditedSessionSavedThenLoadedKeepsItsDigestStatusAndExclusivity), pool).ConfigureAwait(false);
        List<byte[]> responses = [];
        using TpmDevice device = CreateResponseCapturingDevice(simulator, responses);
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        uint reloadedHandle = 0;
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            await RunGetRandomAsync(device, registry, pool, session).ConfigureAwait(false);
            using DigestValue established = await ComputeExpectedDigestAsync(ZeroDigestSha256, TpmCcConstants.TPM_CC_GetRandom, GetRandomParameters, responses[^1], pool).ConfigureAwait(false);

            ContextSaveInput saveInput = ContextSaveInput.ForHandle(sessionHandle);
            TpmResult<ContextSaveResponse> saveResult = await TpmCommandExecutor.ExecuteAsync<ContextSaveResponse>(
                device, saveInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(saveResult.IsSuccess, $"TPM2_ContextSave() of the audited session failed: '{saveResult.ResponseCode}'.");
            using ContextSaveResponse saved = saveResult.Value;

            var loadInput = new ContextLoadInput(saved.Context);
            TpmResult<ContextLoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<ContextLoadResponse>(
                device, loadInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(loadResult.IsSuccess, $"TPM2_ContextLoad() of the audited session failed: '{loadResult.ResponseCode}'.");
            reloadedHandle = loadResult.Value.LoadedHandle.Value;
            Assert.AreEqual(sessionHandle, reloadedHandle, "A session reloads at its saved handle exactly (N7/N8).");

            (TpmiYesNo exclusive, byte[] readBack) = await ReadAuditDigestAsync(device, registry, pool, reloadedHandle).ConfigureAwait(false);
            Assert.IsTrue(readBack.AsSpan().SequenceEqual(established.AsReadOnlySpan()), "The reloaded session must keep its digest.");
            Assert.IsTrue(exclusive.IsYes, "The reloaded session must keep its exclusivity: nothing session-admitting ran between save and load.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(device, registry, pool, reloadedHandle == 0 ? sessionHandle : reloadedHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The house pool balances across a success, an EXCLUSIVE refusal, and a failed audited command: every
    /// rented carrier the exchange touches — cpHash inputs, the fold input, the command and response HMAC
    /// buffers — comes back, regardless of which of the three outcomes the command reaches.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17</see>.
    /// </summary>
    [TestMethod]
    public async Task TheMeteredPoolBalancesAcrossSuccessExclusiveRefusalAndFailedAuditedCommands()
    {
        using var metered = new MeteredHousePool();
        BaseMemoryPool pool = metered.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(TheMeteredPoolBalancesAcrossSuccessExclusiveRefusalAndFailedAuditedCommands), pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundAuditSessionAsync(device, pool, registry).ConfigureAwait(false);
        try
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            await RunGetRandomAsync(device, registry, pool, session).ConfigureAwait(false);

            TpmResult<GetRandomResponse> plain = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, new GetRandomInput(RandomDrawLength), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(plain.IsSuccess, "The intervening plain command must succeed.");
            plain.Value.Dispose();

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE;
            TpmResult<GetRandomResponse> exclusiveRefusal = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(exclusiveRefusal.IsSuccess, "The EXCLUSIVE case must be refused.");

            using TpmDevice corruptingDevice = CreateHmacCorruptingDevice(simulator, TpmCcConstants.TPM_CC_GetRandom, session);
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            TpmResult<GetRandomResponse> failedHmac = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                corruptingDevice, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(failedHmac.IsSuccess, "The corrupted-HMAC case must be refused.");
        }
        finally
        {
            session.Dispose();
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }

        Assert.AreEqual(metered.RentedCount, metered.ReturnedCount, "Every rented carrier across the three outcomes must have been returned.");
    }

    /// <summary>
    /// Starts an unbound, unsalted HMAC session (TPM 2.0 Library Part 1, clause 16.6.9) with an empty
    /// authorization value — an unauthorizing companion, whose sessionKey and authValue are therefore both the
    /// Empty Buffer for any command it merely audits.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <returns>The started session handle and its client-side wrapper.</returns>
    private async Task<(uint Handle, TpmSession Session)> StartUnboundAuditSessionAsync(TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);

        return (started.SessionHandle.Value, session);
    }

    /// <summary>
    /// Starts an unbound, unsalted HMAC session negotiating <paramref name="symmetric"/> for session-based
    /// parameter encryption (TPM 2.0 Library Part 1, clause 18.1) — the encrypt-capable form of
    /// <see cref="StartUnboundAuditSessionAsync(TpmDevice, BaseMemoryPool, TpmResponseRegistry)"/>, otherwise
    /// identical: an unauthorizing companion whose sessionKey and authValue are both the Empty Buffer.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="symmetric">The symmetric definition to negotiate.</param>
    /// <returns>The started session handle and its client-side wrapper.</returns>
    private async Task<(uint Handle, TpmSession Session)> StartUnboundAuditSessionAsync(TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmtSymDef symmetric)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound, encrypt-capable) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Runs one <c>TPM2_GetRandom()</c> over <paramref name="session"/> and asserts it succeeds.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The authorizing/auditing session.</param>
    private async Task RunGetRandomAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSession session)
    {
        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_GetRandom() over the audit session must succeed: '{result.ResponseCode}'.");
        result.Value.Dispose();
    }

    /// <summary>Flushes <paramref name="handle"/> if it names a started session.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The session handle, or zero when none was started.</param>
    private async Task FlushIfPresentAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            device, FlushContextInput.ForHandle(handle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates the deterministic ECC storage parent under the owner hierarchy, an empty-auth resource unrelated to any audit session.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response; the caller disposes it.</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, parentInput, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary storage parent failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Reads back an audit session's status through <c>TPM2_GetSessionAuditDigest()</c>'s NULL signer (Part 3,
    /// clause 18.1: "the attestation block is 'signed' with the NULL Signature"), authorized against the
    /// Empty Buffer at both slots — the privacy administrator's and, for the NULL signer, <c>TPM_RH_NULL</c>'s.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sessionHandle">The audit session's handle.</param>
    /// <returns>Whether the session is currently exclusive, and its attested digest.</returns>
    private async Task<(TpmiYesNo Exclusive, byte[] Digest)> ReadAuditDigestAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, uint sessionHandle)
    {
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(sessionHandle), ReadOnlySpan<byte>.Empty, pool);
        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<GetSessionAuditDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
            device, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_GetSessionAuditDigest(NULL signer) failed: '{result.ResponseCode}'.");

        using GetSessionAuditDigestResponse response = result.Value;
        TpmsSessionAuditInfo info = response.SessionAudit;

        return (info.ExclusiveSession, info.SessionDigest.AsReadOnlySpan().ToArray());
    }

    /// <summary>
    /// Chains the audit digest fold the test itself computes from the octets it sent and read: cpHash =
    /// H(commandCode || <paramref name="commandParameters"/>) — GetRandom carries no @-handle, so equation 15's
    /// Name terms are empty and the command code and the parameter octets AS SENT are what the audit slot's
    /// command HMAC covered — rpHash = H(TPM_RC_SUCCESS || commandCode || the response parameter octets AS READ)
    /// per equation 16, and the fold H(<paramref name="oldDigest"/> || cpHash || rpHash) per equation 30. This
    /// mirrors production nowhere: every input is the caller-supplied prior digest, the parameter octets the
    /// caller laid out itself, or bytes parsed straight off the wire.
    /// </summary>
    /// <param name="oldDigest">The digest before this command — the Zero Digest on a first use or reset.</param>
    /// <param name="commandCode">The audited command's code — the first term of both hashes; a response header carries no command code of its own, only the response code (TPM 2.0 Library Part 1, clause 15.2.3).</param>
    /// <param name="commandParameters">The command's parameter area exactly as the caller sent it.</param>
    /// <param name="capturedResponse">The raw response octets the simulator returned for the audited command.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The expected post-command audit digest; the caller disposes it.</returns>
    private async Task<DigestValue> ComputeExpectedDigestAsync(ReadOnlyMemory<byte> oldDigest, TpmCcConstants commandCode, ReadOnlyMemory<byte> commandParameters, byte[] capturedResponse, BaseMemoryPool pool)
    {
        (TpmRcConstants code, byte[] responseParameters, TpmsAuthResponse entry) = ParseSingleSessionResponse(capturedResponse, pool);
        entry.Dispose();
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "Only a successful command's octets extend the audit digest.");

        int cpHashInputLength = sizeof(uint) + commandParameters.Length;
        using IMemoryOwner<byte> cpHashOwner = pool.Rent(cpHashInputLength);
        Memory<byte> cpHashInput = cpHashOwner.Memory[..cpHashInputLength];
        {
            var writer = new TpmWriter(cpHashInput.Span);
            writer.WriteUInt32((uint)commandCode);
            writer.WriteBytes(commandParameters.Span);
        }

        using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            cpHashInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        int rpHashInputLength = sizeof(uint) + sizeof(uint) + responseParameters.Length;
        using IMemoryOwner<byte> rpHashOwner = pool.Rent(rpHashInputLength);
        Memory<byte> rpHashInput = rpHashOwner.Memory[..rpHashInputLength];
        {
            var writer = new TpmWriter(rpHashInput.Span);
            writer.WriteUInt32((uint)TpmRcConstants.TPM_RC_SUCCESS);
            writer.WriteUInt32((uint)commandCode);
            writer.WriteBytes(responseParameters);
        }

        using DigestValue rpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            rpHashInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        int foldInputLength = oldDigest.Length + cpHash.Length + rpHash.Length;
        using IMemoryOwner<byte> foldOwner = pool.Rent(foldInputLength);
        Memory<byte> foldInput = foldOwner.Memory[..foldInputLength];
        oldDigest.Span.CopyTo(foldInput.Span);
        cpHash.AsReadOnlySpan().CopyTo(foldInput.Span[oldDigest.Length..]);
        rpHash.AsReadOnlySpan().CopyTo(foldInput.Span[(oldDigest.Length + cpHash.Length)..]);

        return await CryptographicKeyEvents.ComputeDigestAsync(
            foldInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Parses a captured response's header, and — when it carries exactly one session entry — its parameter octets and its <c>TPMS_AUTH_RESPONSE</c>.</summary>
    /// <param name="capturedResponse">The raw response octets.</param>
    /// <param name="pool">The memory pool the session entry's owned carriers are allocated from.</param>
    /// <returns>The response code, the parameter octets (empty on a <c>TPM_ST_NO_SESSIONS</c> response), and the one session entry (a dispose-immune default when there is none).</returns>
    private static (TpmRcConstants Code, byte[] Parameters, TpmsAuthResponse Entry) ParseSingleSessionResponse(byte[] capturedResponse, BaseMemoryPool pool)
    {
        var reader = new TpmReader(capturedResponse);
        TpmHeader header = TpmHeader.Parse(ref reader);
        var code = (TpmRcConstants)header.Code;

        if(header.Tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            return (code, [], EmptySessionEntry(pool));
        }

        uint parameterSize = reader.ReadUInt32();
        byte[] parameters = reader.ReadBytes((int)parameterSize).ToArray();
        TpmsAuthResponse entry = TpmsAuthResponse.Parse(ref reader, pool);

        return (code, parameters, entry);
    }

    /// <summary>Builds a harmless, immediately-disposable session entry for the no-session response shape.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>A zero-attribute, empty-nonce, empty-hmac entry.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of both carriers transfers into the constructed TpmsAuthResponse, which every caller disposes.")]
    private static TpmsAuthResponse EmptySessionEntry(BaseMemoryPool pool) =>
        new(Tpm2bNonce.Create(ReadOnlySpan<byte>.Empty, pool), default, Tpm2bAuth.Create(ReadOnlySpan<byte>.Empty, pool));

    /// <summary>Reads a framed command's <c>commandCode</c> header field (TPM 2.0 Library Part 1, clause 15.2.3) — a command's, never a response's, whose header carries the response code at that offset instead.</summary>
    /// <param name="framedCommand">The framed command octets.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(ReadOnlySpan<byte> framedCommand) =>
        (TpmCcConstants)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(framedCommand[(sizeof(ushort) + sizeof(uint))..]);

    /// <summary>
    /// Wraps the simulator in a device that records every response's raw octets, in submission order, so a test
    /// can independently re-derive cpHash/rpHash from what the wire actually carried.
    /// </summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="responses">The list every response's octets are appended to (empty on a refusal).</param>
    /// <returns>The capturing device; the caller owns it.</returns>
    private static TpmDevice CreateResponseCapturingDevice(TpmSimulator simulator, List<byte[]> responses) =>
        TpmDevice.Create(async (command, pool, cancellationToken) =>
        {
            TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, cancellationToken).ConfigureAwait(false);
            responses.Add(result.IsSuccess ? result.Value.AsReadOnlySpan().ToArray() : []);

            return result;
        }, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

    /// <summary>
    /// Wraps the simulator in a device that flips the last octet of the ONE matching command's own
    /// <c>TPMS_AUTH_COMMAND</c> block — the last octet of its <c>hmac</c> field, since <c>hmac</c> is the
    /// block's last-written member — after <paramref name="corruptedSession"/> has already computed a genuine
    /// HMAC over the original octet, leaving every other command untouched.
    /// </summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="targetCommandCode">The zero-handle command whose auth block is corrupted.</param>
    /// <param name="corruptedSession">The session whose auth block size locates the hmac field to flip.</param>
    /// <returns>The corrupting device; the caller owns it.</returns>
    private static TpmDevice CreateHmacCorruptingDevice(TpmSimulator simulator, TpmCcConstants targetCommandCode, TpmSessionBase corruptedSession) =>
        TpmDevice.Create(async (command, pool, cancellationToken) =>
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == targetCommandCode)
            {
                int hmacFieldEnd = TpmHeader.HeaderSize + sizeof(uint) + corruptedSession.GetAuthCommandSize();
                bytes[hmacFieldEnd - 1] ^= 0xFF;
            }

            return await simulator.SubmitAsync(bytes, pool, cancellationToken).ConfigureAwait(false);
        }, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

    /// <summary>The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S + TPM_RC_n(0x100·(index+1)).</summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>Builds the digest <see cref="Tag"/> used to independently compute cpHash/rpHash/the audit fold: SHA-256, raw encoding, direct material.</summary>
    /// <returns>The digest tag.</returns>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    /// <summary>Creates the response codec registry for every command this class drives through the production executor.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext)
            .Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom)
            .Register(TpmCcConstants.TPM_CC_StirRandom, TpmResponseCodec.StirRandom)
            .Register(TpmCcConstants.TPM_CC_TestParms, TpmResponseCodec.TestParms)
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest)
            .Register(TpmCcConstants.TPM_CC_ContextSave, TpmResponseCodec.ContextSave)
            .Register(TpmCcConstants.TPM_CC_ContextLoad, TpmResponseCodec.ContextLoad)
            .Register(TpmCcConstants.TPM_CC_ReadClock, TpmResponseCodec.ReadClock)
            .Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability)
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);

    /// <summary>
    /// Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational
    /// phase — the precondition every command in this class carries.
    /// </summary>
    /// <param name="name">A per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(name, signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var startup = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + startup.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)startup.CommandCode);
        header.WriteTo(ref writer);
        startup.WriteHandles(ref writer);
        startup.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The transport itself must succeed for TPM2_Startup(CLEAR).");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
