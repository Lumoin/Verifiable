using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the no-authorization commands' <c>TPM_ST_SESSIONS</c> form through the production
/// <see cref="TpmCommandExecutor"/> with real companion sessions attached, rather than the hand-framed wire octets
/// <see cref="TpmInHouseSimulatorNoAuthSessionTests"/> and <see cref="TpmInHouseSimulatorZeroHandleSessionTests"/>
/// compose: a genuinely authorized command's first session still folds a companion's <c>nonceTPM</c> into its own
/// command HMAC (TPM 2.0 Library Part 1, clause 16.6.5), while a no-authorization command's companion-only first
/// session must NOT (<see cref="ITpmCommandInput.IsFirstHandleAuthorized"/>) — both are exercised here, alongside
/// multi-companion pairs and triples the executor's client-side parameter-encryption path recovers and protects
/// end to end. TPM 2.0 Library Part 3, clauses 4.3, 5.5, 5.7 and 5.9; Part 1, clauses 15.6.1, 15.7, 16.6.5, 17.1
/// and 18.
/// </summary>
[TestClass]
internal sealed class TpmNoAuthSessionExecutorTests
{
    /// <summary>The symmetric definition a slot claiming <c>decrypt</c> or <c>encrypt</c> negotiates in these tests.</summary>
    private static TpmtSymDef SessionSymmetric { get; } = TpmtSymDef.Xor(TpmAlgIdConstants.TPM_ALG_SHA256);

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// <c>TPM2_NV_ReadPublic()</c> over an audit companion at index 0 and an encrypt companion at index 1
    /// succeeds through the production executor: the addressed Index's own Name folds into cpHash ahead of the
    /// authorization area (clause 5.4 precedes clause 5.5), and the decrypted <c>nvPublic</c>/<c>nvName</c> equal
    /// the plain form's own answer exactly.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.6, Tables 251 and 252; Part 1, clauses 15.7, 16.6.5 and 18.1</see>
    [TestMethod]
    public async Task NvReadPublicOverAnAuditAndEncryptCompanionPairSucceedsThroughTheExecutor()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(NvReadPublicOverAnAuditAndEncryptCompanionPairSucceedsThroughTheExecutor), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_ReadPublic, TpmResponseCodec.NvReadPublic);

        const uint NvIndex = 0x0100_0301;
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth indexAuth = Tpm2bAuth.Create([0x0A, 0x0B], pool);
        using var publicInfo = new TpmsNvPublic(NvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE, Tpm2bDigest.Empty, dataSize: 8);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, indexAuth, publicInfo);
        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, defineInput, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"TPM2_NV_DefineSpace() must succeed: '{defineResult.ResponseCode}'.");

        TpmResult<NvReadPublicResponse> plainResult = await TpmCommandExecutor.ExecuteAsync<NvReadPublicResponse>(
            device, new NvReadPublicInput(NvIndex), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(plainResult.IsSuccess, $"The plain TPM2_NV_ReadPublic() form must succeed: '{plainResult.ResponseCode}'.");
        using NvReadPublicResponse plainResponse = plainResult.Value;
        byte[] indexName = plainResponse.NvName.Span.ToArray();

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(encryptSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                TpmResult<NvReadPublicResponse> sessionResult = await TpmCommandExecutor.ExecuteAsync<NvReadPublicResponse>(
                    device, new NvReadPublicInput(NvIndex), [auditSession, encryptSession], [indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(sessionResult.IsSuccess, $"TPM2_NV_ReadPublic() over an audit companion at index 0 and an encrypt companion at index 1 must succeed: '{sessionResult.ResponseCode}'.");
                using NvReadPublicResponse sessionResponse = sessionResult.Value;
                Assert.AreSequenceEqual(indexName, sessionResponse.NvName.Span.ToArray(), "The Name must equal the plain form's.");
                Assert.AreEqual(plainResponse.NvPublic.NvIndex, sessionResponse.NvPublic.NvIndex, "The decrypted nvPublic's nvIndex must equal the plain form's own answer.");
                Assert.AreEqual(plainResponse.NvPublic.NameAlg, sessionResponse.NvPublic.NameAlg, "The decrypted nvPublic's nameAlg must equal the plain form's own answer.");
                Assert.AreEqual(plainResponse.NvPublic.DataSize, sessionResponse.NvPublic.DataSize, "The decrypted nvPublic's dataSize must equal the plain form's own answer.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_GetTestResult()</c> over an audit companion at index 0 and an encrypt companion at index 1
    /// succeeds through the production executor: the framed <c>outData</c> decrypts to a zero-length buffer
    /// (this simulator emits it empty on every success, and the ciphertext of an empty buffer is itself empty,
    /// TPM 2.0 Library Part 1, clause 18.1) and the audit session's digest still extends to
    /// <c>H(0…0 ‖ cpHash ‖ rpHash)</c>, proving a second companion claiming encrypt in the same area changes
    /// nothing about the audit fold.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 10.4, Table 12; Part 1, clauses 15.6.1, 17.1 and 18.1</see>
    [TestMethod]
    public async Task GetTestResultOverAnAuditAndEncryptCompanionPairSucceedsWithTheDigestChained()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_GetTestResult, TpmResponseCodec.GetTestResult)
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(encryptSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                TpmResult<GetTestResultResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTestResultResponse>(
                    device, new GetTestResultInput(), [auditSession, encryptSession], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(result.IsSuccess, $"TPM2_GetTestResult() over an audit companion at index 0 and an encrypt companion at index 1 must succeed: '{result.ResponseCode}'.");
                using GetTestResultResponse response = result.Value;
                Assert.AreEqual(0, response.OutData.Length, "outData is framed empty on this simulator, so the ciphertext of an empty buffer is itself empty.");

                byte[] cpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeZeroHandleCpHashAsync(
                    TpmCcConstants.TPM_CC_GetTestResult, ReadOnlyMemory<byte>.Empty, pool, TestContext.CancellationToken).ConfigureAwait(false);
                //outData: TPM2B_MAX_BUFFER, size 0; testResult: TPM_RC_SUCCESS — the only shape this simulator ever emits.
                byte[] responseParameters = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                byte[] rpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeRpHashAsync(
                    TpmCcConstants.TPM_CC_GetTestResult, responseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] expectedDigest = await TpmInHouseSimulatorZeroHandleSessionTests.ExtendAuditDigestAsync(priorDigest: null, cpHash, rpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);

                using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                using GetSessionAuditDigestResponse? auditDigestResponse = digestResult.IsSuccess ? digestResult.Value : null;

                Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() over the freshly audited session must succeed: '{digestResult.ResponseCode}'.");
                Assert.IsTrue(
                    expectedDigest.AsSpan().SequenceEqual(auditDigestResponse!.SessionAudit.SessionDigest.AsReadOnlySpan()),
                    "The audit session's digest must equal H(0…0 ‖ cpHash ‖ rpHash) chained from this exchange's own wire octets, regardless of the second companion's own encrypt claim (TPM 2.0 Library Part 1, clause 17.1, equation 30).");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_PCR_Read()</c> over an audit-only companion succeeds with a <c>TPM_ST_SESSIONS</c>-tagged
    /// response, and the audit session's digest extends to <c>H(0…0 ‖ cpHash ‖ rpHash)</c> chained from this
    /// exchange's own wire octets and read back through <c>TPM2_GetSessionAuditDigest()</c>'s NULL signer.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 22.4, Table 134; Part 1, clauses 15.6.1, 17.1 and 18.1</see>
    [TestMethod]
    public async Task PcrReadOverAnAuditSlotSucceedsWithTheAuditDigestChained()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        byte[] parameters;
        using(PcrReadInput input = PcrReadInput.ForBootPcrs(TpmAlgIdConstants.TPM_ALG_SHA256, pool))
        {
            parameters = SerializeParameters(input, pool);
        }

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(auditSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                byte[] authArea = await TpmInHouseSimulatorZeroHandleSessionTests.BuildSessionAuthAreaAsync(
                    auditSession, TpmCcConstants.TPM_CC_PCR_Read, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);

                (TpmRcConstants code, byte[] response) = await TpmInHouseSimulatorZeroHandleSessionTests.SubmitZeroHandleForAuditAsync(
                    simulator, pool, TpmCcConstants.TPM_CC_PCR_Read, authArea, parameters, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "TPM2_PCR_Read() over an audit-only companion must succeed (Table 134's tag rule).");
                Assert.AreEqual(
                    (ushort)TpmStConstants.TPM_ST_SESSIONS, TpmInHouseSimulatorNoAuthSessionTests.ReadResponseTag(response),
                    "A successful over-session response is TPM_ST_SESSIONS-tagged.");

                byte[] responseParameters = TpmInHouseSimulatorZeroHandleSessionTests.ReadResponseParameters(response, outHandleCount: 0);
                byte[] cpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeZeroHandleCpHashAsync(
                    TpmCcConstants.TPM_CC_PCR_Read, parameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] rpHash = await TpmInHouseSimulatorZeroHandleSessionTests.ComputeRpHashAsync(
                    TpmCcConstants.TPM_CC_PCR_Read, responseParameters, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] expectedDigest = await TpmInHouseSimulatorZeroHandleSessionTests.ExtendAuditDigestAsync(priorDigest: null, cpHash, rpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);

                using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(auditHandle), ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                using GetSessionAuditDigestResponse? auditDigestResponse = digestResult.IsSuccess ? digestResult.Value : null;

                Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() over the freshly audited session must succeed: '{digestResult.ResponseCode}'.");
                Assert.IsTrue(
                    expectedDigest.AsSpan().SequenceEqual(auditDigestResponse!.SessionAudit.SessionDigest.AsReadOnlySpan()),
                    "The audit session's digest must equal H(0…0 ‖ cpHash ‖ rpHash) chained from this exchange's own wire octets (TPM 2.0 Library Part 1, clause 17.1, equation 30).");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_Hash()</c> over a decrypt companion at index 0 and an encrypt companion at index 1 together
    /// succeeds through the production executor: the executor encrypts <c>data</c> client-side under the decrypt
    /// session's own key before the command travels, the simulator hashes the RECOVERED plaintext, and the
    /// executor decrypts <c>outHash</c> under the encrypt session's own key before parsing, so the typed response
    /// already carries the plaintext digest.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.4, Table 69; Part 1, clauses 15.6.1 and 18.1</see>
    [TestMethod]
    public async Task HashOverADecryptAndEncryptCompanionPairSucceedsThroughTheExecutor()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_Hash, TpmResponseCodec.Hash);

        byte[] data = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        byte[] expectedHash = SHA256.HashData(data);
        TpmiAlgHash hashAlg = TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256);

        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(decryptSession)
            using(encryptSession)
            {
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                using HashInput input = HashInput.Create(data, hashAlg, TpmiRhHierarchy.Null, pool);
                TpmResult<HashResponse> result = await TpmCommandExecutor.ExecuteAsync<HashResponse>(
                    device, input, [decryptSession, encryptSession], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(result.IsSuccess, $"TPM2_Hash() over a decrypt companion at index 0 and an encrypt companion at index 1 must succeed: '{result.ResponseCode}'.");
                using HashResponse response = result.Value;
                Assert.AreSequenceEqual(
                    expectedHash, response.OutHash.AsReadOnlySpan().ToArray(),
                    "The simulator hashes the plaintext the executor recovered from the decrypt claim, and the executor decrypts outHash under the encrypt claim before parsing.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_SignSequenceStart()</c> over an audit companion at index 0 and a decrypt companion at index 1
    /// together succeeds through the production executor — <c>keyHandle</c> carries no Auth Index (Table 87), so
    /// neither companion authorizes it and <see cref="ITpmCommandInput.IsFirstHandleAuthorized"/> is
    /// <see langword="false"/> — and the SAME plaintext password the decrypt companion recovered completes the
    /// opened sequence afterward.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.5, Table 87 and Table 88; Part 1, clauses 15.6.1 and 18.1</see>
    [TestMethod]
    public async Task SignSequenceStartOverAnAuditAndDecryptCompanionPairSucceedsAndTheSequenceCompletes()
    {
        const string SequenceAuthPassword = "sign-sequence-audit-decrypt-auth";

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SignSequenceStartOverAnAuditAndDecryptCompanionPairSucceedsAndTheSequenceCompletes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart)
            .Register(TpmCcConstants.TPM_CC_SignSequenceComplete, TpmResponseCodec.SignSequenceComplete);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_CreatePrimary() must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(decryptSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                using SignSequenceStartInput startInput = SignSequenceStartInput.CreateFromPassword(primary.ObjectHandle, SequenceAuthPassword, pool);
                TpmResult<SignSequenceStartResponse> startResult = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
                    device, startInput, [auditSession, decryptSession], handleNames: [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(startResult.IsSuccess, $"TPM2_SignSequenceStart() over an audit companion at index 0 and a decrypt companion at index 1 must succeed: '{startResult.ResponseCode}'.");
                SignSequenceStartResponse started = startResult.Value;

                using SignSequenceCompleteInput completeInput = SignSequenceCompleteInput.Create(started.SequenceHandle, primary.ObjectHandle, [0x0A, 0x0B, 0x0C], pool);
                using TpmPasswordSession sequencePassword = TpmPasswordSession.Create(SequenceAuthPassword, pool);
                using TpmPasswordSession keyPassword = TpmPasswordSession.CreateEmpty(pool);
                TpmResult<SignSequenceCompleteResponse> completeResult = await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
                    device, completeInput, [sequencePassword, keyPassword], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(
                    completeResult.IsSuccess,
                    $"TPM2_SignSequenceComplete() over the sequence's own plaintext password must succeed, proving the decrypted (not ciphertext) auth was installed: '{completeResult.ResponseCode}'.");
                completeResult.Value.Dispose();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_RSA_Encrypt()</c> over an audit companion at index 0, a decrypt companion at index 1 and an
    /// encrypt companion at index 2 — the routed shape's three admissible companion kinds at once — succeeds
    /// through the production executor, and <c>TPM2_RSA_Decrypt()</c> on the SAME key recovers the exact
    /// plaintext the triple-companion exchange protected, proving the plaintext (not garbage) reached the RSA
    /// engine intact.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2, Table 44; Part 1, clauses 15.6.1 and 18.1</see>
    [TestMethod]
    public async Task RsaEncryptOverAnAuditDecryptAndEncryptCompanionTripleSucceedsAndRsaDecryptRecoversThePlaintext()
    {
        const string KeyPassword = "rsa-triple-companion-auth";
        const TpmAlgIdConstants Alg = TpmAlgIdConstants.TPM_ALG_SHA256;
        const ushort RsaKeyBits = 2048;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateRsaOperationalAsync(
            nameof(RsaEncryptOverAnAuditDecryptAndEncryptCompanionTripleSucceedsAndRsaDecryptRecoversThePlaintext), pool).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_RSA_Encrypt, TpmResponseCodec.RsaEncrypt)
            .Register(TpmCcConstants.TPM_CC_RSA_Decrypt, TpmResponseCodec.RsaDecrypt)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForRsaDecryptKey(TpmRh.TPM_RH_OWNER, KeyPassword, RsaKeyBits, TpmtRsaScheme.Oaep(Alg), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"CreatePrimary (RSA decrypt key) must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        byte[] message = Encoding.ASCII.GetBytes("no-authorization RSA triple");

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(auditSession)
            using(decryptSession)
            using(encryptSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                using Tpm2bPublicKeyRsa messageCarrier = Tpm2bPublicKeyRsa.Create(message, pool);
                using Tpm2bData label = Tpm2bData.Empty;
                var encryptInput = new RsaEncryptInput(primary.ObjectHandle, messageCarrier, TpmtRsaDecrypt.Oaep(Alg), label);

                TpmResult<RsaEncryptResponse> encryptResult = await TpmCommandExecutor.ExecuteAsync<RsaEncryptResponse>(
                    device, encryptInput, [auditSession, decryptSession, encryptSession], [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(
                    encryptResult.IsSuccess,
                    $"TPM2_RSA_Encrypt() over an audit companion at index 0, a decrypt companion at index 1 and an encrypt companion at index 2 must succeed: '{encryptResult.ResponseCode}'.");
                using RsaEncryptResponse encryptResponse = encryptResult.Value;
                byte[] ciphertext = encryptResponse.OutData.Buffer.ToArray();

                using Tpm2bPublicKeyRsa cipherCarrier = Tpm2bPublicKeyRsa.Create(ciphertext, pool);
                var decryptInput = new RsaDecryptInput(primary.ObjectHandle, cipherCarrier, TpmtRsaDecrypt.Oaep(Alg), Tpm2bData.Empty);
                using TpmPasswordSession decryptKeyAuth = TpmPasswordSession.Create(KeyPassword, pool);
                TpmResult<RsaDecryptResponse> decryptResult = await TpmCommandExecutor.ExecuteAsync<RsaDecryptResponse>(
                    device, decryptInput, [decryptKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(decryptResult.IsSuccess, $"TPM2_RSA_Decrypt() over the same key must recover the message: '{decryptResult.ResponseCode}'.");
                using RsaDecryptResponse decryptResponse = decryptResult.Value;
                Assert.AreSequenceEqual(
                    message, decryptResponse.Message.Buffer.ToArray(),
                    "TPM2_RSA_Decrypt() on the same key must recover the exact plaintext the triple-companion TPM2_RSA_Encrypt() protected.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_LoadExternal()</c> over an audit companion at index 0, a decrypt companion at index 1 and an
    /// encrypt companion at index 2 together succeeds through the production executor: the routed shape admits
    /// all three at once, and the decrypted response Name is non-empty, proving the executor's own decrypt of the
    /// response completed cleanly alongside the other two companions.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3, Table 22 and Table 23; Part 1, clauses 15.6.1 and 18.1</see>
    [TestMethod]
    public async Task LoadExternalOverAnAuditDecryptAndEncryptCompanionTripleSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(LoadExternalOverAnAuditDecryptAndEncryptCompanionTripleSucceeds), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_LoadExternal, TpmResponseCodec.LoadExternal);

        (uint auditHandle, TpmSession auditSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        (uint encryptHandle, TpmSession encryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        uint loadedHandle = 0;
        try
        {
            using(auditSession)
            using(decryptSession)
            using(encryptSession)
            {
                auditSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                using Tpm2bPublic inPublic = BuildLoadExternalPublicArea(pool);
                using LoadExternalInput input = LoadExternalInput.PublicOnly(inPublic, TpmiRhHierarchy.Owner);

                TpmResult<LoadExternalResponse> result = await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(
                    device, input, [auditSession, decryptSession, encryptSession], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(
                    result.IsSuccess,
                    $"TPM2_LoadExternal() over an audit companion at index 0, a decrypt companion at index 1 and an encrypt companion at index 2 must succeed: '{result.ResponseCode}'.");
                using LoadExternalResponse response = result.Value;
                loadedHandle = response.ObjectHandle.Value;
                Assert.IsGreaterThan(0, response.Name.Span.Length, "The decrypted Name is non-empty.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, auditHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, encryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, loadedHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A decrypt claim against <c>TPM2_GetCapability()</c> — whose first command parameter (<c>capability</c>,
    /// a <c>TPM_CAP</c> selector) is not a sized buffer at all — is refused by the production executor's own
    /// client-side guard with an <see cref="ArgumentException"/> before any octet reaches the transport, rather
    /// than being sent for the TPM to refuse.
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.7; Part 1, clause 18.1</see>
    [TestMethod]
    public async Task GetCapabilityOverADecryptClaimingSessionThrowsBeforeAnyOctetIsSent()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await TpmInHouseSimulatorZeroHandleSessionTests.CreateOperationalAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = TpmInHouseSimulatorZeroHandleSessionTests.CreateSessionRegistry()
            .Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);

        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(decryptSession)
            {
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
                    _ = await TpmCommandExecutor.ExecuteAsync<GetCapabilityResponse>(
                        device, GetCapabilityInput.ForFixedProperties(), [decryptSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

                Assert.AreEqual(
                    "sessions", exception.ParamName,
                    "The executor's own client-side guard refuses a decrypt claim against a command with no encryptable first command parameter before any octet reaches the transport.");
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_Sign()</c> over its own key's authorizing HMAC session (index 0, ASSOCIATED with <c>keyHandle</c>,
    /// Auth Index <c>@</c>) plus a separate decrypt companion (index 1, unassociated) still succeeds: the
    /// executor folds the decrypt companion's <c>nonceTPM</c> into session 0's command HMAC because session 0
    /// genuinely authorizes the command's handle, and the simulator computes the identical fold, so the two
    /// sides agree — the fold's POSITIVE case, the mirror of the no-authorization commands' own companion-only
    /// first session, which must never fold (<see cref="ITpmCommandInput.IsFirstHandleAuthorized"/>).
    /// </summary>
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.5; Part 3, clause 20.5, Table 122</see>
    [TestMethod]
    public async Task SignOverItsKeysHmacSessionAndADecryptCompanionFoldsTheCompanionsNonceIntoSessionZerosHmac()
    {
        const string KeyPassword = "sign-fold-positive-case-auth";

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            nameof(SignOverItsKeysHmacSessionAndADecryptCompanionFoldsTheCompanionsNonceIntoSessionZerosHmac), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, KeyPassword, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, createInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_CreatePrimary() must succeed: '{createResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = createResult.Value;

        (uint keySessionHandle, TpmSession keySession) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            device, registry, pool, primary.ObjectHandle.Value, Encoding.ASCII.GetBytes(KeyPassword), TpmtSymDef.Null,
            isBoundToAuthorizedEntity: true, TestContext.CancellationToken).ConfigureAwait(false);
        (uint decryptHandle, TpmSession decryptSession) = await TpmInHouseSimulatorZeroHandleSessionTests.StartUnboundSessionAsync(device, registry, pool, TestContext.CancellationToken, SessionSymmetric).ConfigureAwait(false);
        try
        {
            using(keySession)
            using(decryptSession)
            {
                keySession.SessionAttributes = TpmaSession.CONTINUE_SESSION;
                decryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

                byte[] digest = SHA256.HashData([0x11, 0x22, 0x33]);
                using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

                TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                    device, signInput, [keySession, decryptSession], handleNames: [primary.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(
                    signResult.IsSuccess,
                    $"TPM2_Sign() over its key's own authorizing HMAC session (index 0) plus a decrypt companion (index 1) must succeed: the executor folds the companion's nonceTPM into session 0's command HMAC and the simulator computes the same fold, so the two agree — '{signResult.ResponseCode}'.");
                signResult.Value.Dispose();
            }
        }
        finally
        {
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, keySessionHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, decryptHandle).ConfigureAwait(false);
            await TpmInHouseSimulatorZeroHandleSessionTests.FlushIfPresentAsync(device, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>Serializes a <see cref="PcrReadInput"/>'s parameter area (excluding any handle area) into a standalone array.</summary>
    /// <param name="input">The command input.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parameter octets.</returns>
    private static byte[] SerializeParameters(PcrReadInput input, BaseMemoryPool pool)
    {
        int length = input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(Math.Max(length, 1));
        Memory<byte> parameters = owner.Memory[..length];
        var writer = new TpmWriter(parameters.Span);
        input.WriteParameters(ref writer);

        return parameters.Span.ToArray();
    }

    /// <summary>The NIST P-256 base point G's X coordinate — a point genuinely on the curve, so a load in this file never fails on the point's own validity.</summary>
    private static byte[] NistP256BasePointX { get; } =
        Convert.FromHexString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");

    /// <summary>The NIST P-256 base point G's Y coordinate.</summary>
    private static byte[] NistP256BasePointY { get; } =
        Convert.FromHexString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");

    /// <summary>Builds a minimal ECC P-256 ECDSA-SHA-256 signing public area, over the curve's own base point, for a public-only <c>TPM2_LoadExternal()</c> load.</summary>
    /// <param name="pool">The memory pool the point carrier is rented from.</param>
    /// <returns>The public area; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the point carrier transfers to the returned public area, which its caller disposes.")]
    private static Tpm2bPublic BuildLoadExternalPublicArea(BaseMemoryPool pool) =>
        Tpm2bPublic.CreateEccSigningKey(
            TpmAlgIdConstants.TPM_ALG_SHA256, TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT | TpmaObject.NO_DA,
            TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            TpmsEccPoint.Create(NistP256BasePointX, NistP256BasePointY, pool), pool);

    /// <summary>Creates an RSA-only operational simulator (no ECC backend), powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c>.</summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateRsaOperationalAsync(string name, BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator($"tpm-in-house-no-auth-executor-rsa-{name}", signingBackend: null, rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
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
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)TpmHeader.Parse(ref reader).Code, "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
