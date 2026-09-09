using System;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_PolicyAuthorizeNV()</c> (TPM 2.0 Library Part 3, clause 23.22) against the in-house
/// <see cref="TpmSimulator"/> through the production command path: it lets an object's fixed authPolicy accept a
/// policy an authority can later REVOKE, by holding the approved policyDigest — marshaled as a <c>TPMT_HA</c>
/// (a two-octet <c>TPM_ALG_ID</c> then a digest of that algorithm's width) — inside an NV Index rather than in a
/// signed ticket.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorPolicyAuthorizeNvTests
{
    /// <summary>The NV Index this class defines and reads back in every test (each test runs against a fresh simulator).</summary>
    private const uint NvIndexHandle = 0x0100_00B1u;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies <c>TPM2_PolicyAuthorizeNV()</c> succeeds once the session's policyDigest equals the Index's
    /// approved digest, replacing the session's digest with the fold over the Index's own Name (Part 3, clause
    /// 23.22, equation 9): the resulting digest is a reset-then-fold whose exact value depends on the Index's
    /// Name, so this test asserts success and that the resulting digest is neither the Zero Digest nor the
    /// pre-authorization approved digest, rather than predicting the Name itself.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeNvFoldsTheIndexNameAfterAMatch()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-authorizenv-match", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] zeroDigest = new byte[size];
        byte[] approvedDigest = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForCommandCode(zero, TpmCcConstants.TPM_CC_Unseal, PolicySweepHarness.SessionAlg, approvedDigest, pool);
        byte[] indexData = BuildTpmtHa((ushort)TpmAlgIdConstants.TPM_ALG_SHA256, approvedDigest);

        await PolicySweepHarness.DefineOwnerReadableIndexAsync(tpm, registry, pool, NvIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        await PolicySweepHarness.WriteOwnerIndexAsync(tpm, registry, pool, NvIndexHandle, indexData, TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(sessionHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            byte[] beforeDigest = await GetDigestAsync(tpm, sessionHandle).ConfigureAwait(false);
            Assert.IsTrue(beforeDigest.AsSpan().SequenceEqual(approvedDigest), "The session digest must equal the Index's approved digest before PolicyAuthorizeNV.");

            TpmResult<PolicyAuthorizeNvResponse> authorizeResult = await tpm.PolicyAuthorizeNvAsync(NvIndexHandle, NvIndexHandle, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authorizeResult.IsSuccess, $"PolicyAuthorizeNV failed: '{authorizeResult.ResponseCode}'.");

            byte[] afterDigest = await GetDigestAsync(tpm, sessionHandle).ConfigureAwait(false);

            Assert.IsFalse(afterDigest.AsSpan().SequenceEqual(zeroDigest), "PolicyAuthorizeNV must not leave the digest at the Zero Digest.");
            Assert.IsFalse(afterDigest.AsSpan().SequenceEqual(approvedDigest), "PolicyAuthorizeNV must replace the digest with the fold over the Index's Name.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyAuthorizeNV()</c> refuses with <c>TPM_RC_VALUE</c> when the session's policyDigest
    /// does not equal the Index's held approved digest (Part 3, clause 23.22).
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeNvRefusesAMismatchedDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-authorizenv-mismatch", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] approvedDigest = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForCommandCode(zero, TpmCcConstants.TPM_CC_Unseal, PolicySweepHarness.SessionAlg, approvedDigest, pool);
        byte[] indexData = BuildTpmtHa((ushort)TpmAlgIdConstants.TPM_ALG_SHA256, approvedDigest);

        await PolicySweepHarness.DefineOwnerReadableIndexAsync(tpm, registry, pool, NvIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        await PolicySweepHarness.WriteOwnerIndexAsync(tpm, registry, pool, NvIndexHandle, indexData, TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(sessionHandle, TpmCcConstants.TPM_CC_NV_Read, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            TpmResult<PolicyAuthorizeNvResponse> authorizeResult = await tpm.PolicyAuthorizeNvAsync(NvIndexHandle, NvIndexHandle, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(authorizeResult.IsSuccess, "A session digest that does not equal the Index's approved digest must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, authorizeResult.ResponseCode, "A mismatched digest must refuse TPM_RC_VALUE.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyAuthorizeNV()</c> refuses with <c>TPM_RC_NV_UNINITIALIZED</c> when the Index has
    /// never been written (Part 3, clause 23.22: a real session requires the Index to have been written).
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeNvRefusesAnUnwrittenIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-authorizenv-unwritten", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();

        await PolicySweepHarness.DefineOwnerReadableIndexAsync(tpm, registry, pool, NvIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);

            TpmResult<PolicyAuthorizeNvResponse> authorizeResult = await tpm.PolicyAuthorizeNvAsync(NvIndexHandle, NvIndexHandle, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(authorizeResult.IsSuccess, "An unwritten Index must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_NV_UNINITIALIZED, authorizeResult.ResponseCode, "An unwritten Index must refuse TPM_RC_NV_UNINITIALIZED.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyAuthorizeNV()</c> refuses with <c>TPM_RC_HASH</c> when the Index's held
    /// <c>TPMT_HA</c> names an implemented hash algorithm (SHA-1) that DIFFERS from the session's own algorithm
    /// (SHA-256) (Part 3, clause 23.22: the digest's algorithm must equal the session's own).
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeNvRefusesAMismatchedHashAlgorithm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-authorizenv-hash-mismatch", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();

        byte[] indexData = BuildTpmtHa((ushort)TpmAlgIdConstants.TPM_ALG_SHA1, new byte[20]);
        await PolicySweepHarness.DefineOwnerReadableIndexAsync(tpm, registry, pool, NvIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        await PolicySweepHarness.WriteOwnerIndexAsync(tpm, registry, pool, NvIndexHandle, indexData, TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);

            TpmResult<PolicyAuthorizeNvResponse> authorizeResult = await tpm.PolicyAuthorizeNvAsync(NvIndexHandle, NvIndexHandle, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(authorizeResult.IsSuccess, "A SHA-1 Index digest against a SHA-256 session must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_HASH, authorizeResult.ResponseCode, "An implemented hash that differs from the session's own must refuse TPM_RC_HASH.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyAuthorizeNV()</c> refuses with <c>TPM_RC_HASH</c> when the Index's held
    /// <c>TPMT_HA</c> names a hash algorithm (SM3_256) this simulator does not implement (Part 3, clause 23.22).
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeNvRefusesAnUnimplementedHashAlgorithm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-authorizenv-hash-unimplemented", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();

        byte[] indexData = BuildTpmtHa((ushort)TpmAlgIdConstants.TPM_ALG_SM3_256, new byte[32]);
        await PolicySweepHarness.DefineOwnerReadableIndexAsync(tpm, registry, pool, NvIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        await PolicySweepHarness.WriteOwnerIndexAsync(tpm, registry, pool, NvIndexHandle, indexData, TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);

            TpmResult<PolicyAuthorizeNvResponse> authorizeResult = await tpm.PolicyAuthorizeNvAsync(NvIndexHandle, NvIndexHandle, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(authorizeResult.IsSuccess, "An unimplemented hash algorithm must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_HASH, authorizeResult.ResponseCode, "An unimplemented hash algorithm must refuse TPM_RC_HASH.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyAuthorizeNV()</c> refuses with <c>TPM_RC_INSUFFICIENT</c> when the Index holds
    /// fewer octets than a <c>TPM_ALG_ID</c> needs (Part 3, clause 23.22: the data must hold a properly
    /// formatted <c>TPMT_HA</c>).
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeNvRefusesAnInsufficientIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-authorizenv-insufficient", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();

        byte[] indexData = [0x00];
        await PolicySweepHarness.DefineOwnerReadableIndexAsync(tpm, registry, pool, NvIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        await PolicySweepHarness.WriteOwnerIndexAsync(tpm, registry, pool, NvIndexHandle, indexData, TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);

            TpmResult<PolicyAuthorizeNvResponse> authorizeResult = await tpm.PolicyAuthorizeNvAsync(NvIndexHandle, NvIndexHandle, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(authorizeResult.IsSuccess, "An Index holding fewer octets than a TPM_ALG_ID must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_INSUFFICIENT, authorizeResult.ResponseCode, "A one-octet Index must refuse TPM_RC_INSUFFICIENT.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Marshals a <c>TPMT_HA</c>: a two-octet big-endian <c>TPM_ALG_ID</c> followed by the digest octets, with no length prefix (Part 2, clause 10.2.2, Table 89).</summary>
    /// <param name="algId">The hash algorithm identifier.</param>
    /// <param name="digest">The digest octets.</param>
    /// <returns>The marshaled <c>TPMT_HA</c> octets.</returns>
    private static byte[] BuildTpmtHa(ushort algId, ReadOnlySpan<byte> digest)
    {
        byte[] data = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(data, algId);
        digest.CopyTo(data.AsSpan(sizeof(ushort)));

        return data;
    }

    /// <summary>Starts a policy session with no assertions yet made against it.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <returns>The started policy session handle.</returns>
    private async Task<uint> StartSessionAsync(TpmDevice tpm)
    {
        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(PolicySweepHarness.SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
        using StartAuthSessionResponse session = startResult.Value;

        return session.SessionHandle.Value;
    }

    /// <summary>Reads a policy session's current policyDigest into an owned array.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="sessionHandle">The policy session handle.</param>
    /// <returns>A copy of the policyDigest octets.</returns>
    private async Task<byte[]> GetDigestAsync(TpmDevice tpm, uint sessionHandle)
    {
        TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");
        using PolicyGetDigestResponse digest = digestResult.Value;

        return digest.PolicyDigest.AsReadOnlySpan().ToArray();
    }
}
