using System;
using System.Buffers;
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
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the TPM policy (enhanced authorization) command family against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production command
/// path the production code uses (the <see cref="TpmDeviceExtensions"/> policy commands over
/// <see cref="TpmCommandExecutor"/> and the real command/response codecs). Each test starts a trial or policy
/// session, issues policy assertions, reads the accumulated policyDigest back via <c>TPM2_PolicyGetDigest()</c>,
/// and asserts it equals the host prediction the shipped <see cref="TpmPolicyDigest"/> computes for the same
/// assertions (TPM 2.0 Library Part 1, clause 19.7).
/// </summary>
/// <remarks>
/// <para>
/// The simulator advances each session's policyDigest by calling the SAME <see cref="TpmPolicyDigest"/> methods the
/// host prediction uses, so the on-device digest and the host prediction cannot diverge by construction. These
/// tests therefore exercise the wire round-trip, the production command path, and assertion composition; the raw
/// spec formula is the independent-oracle role of <see cref="TpmPolicyDigest"/>'s own unit tests.
/// </para>
/// <para>
/// The <c>PolicySecret(TPM_RH_ENDORSEMENT)</c> case additionally asserts the accumulated digest equals the
/// well-known endorsement-key authorization policy constant, a fixed public value independent of this codebase.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorPolicyTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task PolicyCommandCodeDrivesTheSessionPolicyDigestAsPredicted()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;

        //A trial session accumulates a policyDigest without authorizing anything, exactly as a real policy
        //session would, so its digest is what an object's authPolicy would be set to.
        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
            PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            TpmResult<PolicyCommandCodeResponse> policyResult = await tpm.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_Sign, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(policyResult.IsSuccess, $"PolicyCommandCode failed: '{policyResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;

            //Require the simulator's accumulated policyDigest to equal the host prediction: a fresh session starts
            //at all zeros, and PolicyCommandCode extends it by H(zeros || TPM_CC_PolicyCommandCode || TPM_CC_Sign).
            Assert.IsTrue(
                MatchesCommandCodePolicy(digest.PolicyDigest.AsReadOnlySpan(), TpmCcConstants.TPM_CC_Sign, PolicyHash),
                "The simulator's policyDigest after PolicyCommandCode must match the host-computed value.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task StartPolicySessionRejectsUnsupportedSha1PolicyHash()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        //The enhanced-authorization digest fold does not compute SHA-1, so a SHA-1 policy session must be refused
        //at StartAuthSession with TPM_RC_HASH rather than created and left to fault on its first assertion.
        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA1, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(startResult.IsSuccess, "A SHA-1 policy session must be rejected.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_HASH, startResult.ResponseCode);
    }

    [TestMethod]
    public async Task PolicySecretRejectsNonPermanentAuthHandle()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            //An NV Index handle is not a permanent hierarchy; PolicySecret over it would fold the raw handle as a
            //Name and skip the entity's authValue, so the simulator rejects it with TPM_RC_HANDLE rather than
            //advancing the policyDigest as if the entity's secret had been proven.
            const uint NvIndexHandle = 0x01000001u;
            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                NvIndexHandle, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(secretResult.IsSuccess, "PolicySecret over a non-permanent handle must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, secretResult.ResponseCode);
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task PolicySecretNullTicketTagSatisfiesIsPolicySecret()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            //Regression pin for R-1: TpmtTkAuth.IsPolicySecret()/IsPolicySigned() must reference the shared,
            //correct TpmStConstants.TPM_ST_AUTH_SECRET/TPM_ST_AUTH_SIGNED values (0x8023/0x8025), not the
            //previously-wrong private consts (0x8003/0x8002 — 0x8002 is actually TPM_ST_SESSIONS). A ticket parsed
            //back off the production wire from a genuine PolicySecret response must satisfy IsPolicySecret();
            //this failed under the old, incorrect private consts.
            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret failed: '{secretResult.ResponseCode}'.");

            using(secretResult.Value)
            {
                Assert.IsTrue(secretResult.Value.PolicyTicket.IsPolicySecret(), "A PolicySecret-produced ticket must satisfy IsPolicySecret().");
                Assert.IsFalse(secretResult.Value.PolicyTicket.IsPolicySigned(), "A PolicySecret-produced ticket must not satisfy IsPolicySigned().");
            }
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task PolicyOrRejectsBranchCountBelowTwo()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            //TPM2_PolicyOR requires two to eight branches (Part 3, clause 23.6); a single-branch pHashList is a
            //malformed command the simulator must reject with TPM_RC_SIZE rather than fold silently.
            var oneBranch = new ReadOnlyMemory<byte>[] { new byte[32] };
            TpmResult<PolicyOrResponse> orResult = await tpm.PolicyOrAsync(
                sessionHandle, oneBranch, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(orResult.IsSuccess, "PolicyOR with fewer than two branches must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, orResult.ResponseCode);
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task PolicyAuthValueThenPolicyCommandCodeComposeAsPredicted()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
            PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            TpmResult<PolicyAuthValueResponse> authValueResult = await tpm.PolicyAuthValueAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue failed: '{authValueResult.ResponseCode}'.");

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_Sign, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;

            //Two assertions must chain: zeros -> H(zeros || PolicyAuthValue) -> H(that || PolicyCommandCode || Sign).
            Assert.IsTrue(
                MatchesAuthValueThenCommandCode(digest.PolicyDigest.AsReadOnlySpan(), TpmCcConstants.TPM_CC_Sign, PolicyHash),
                "The simulator's policyDigest after PolicyAuthValue + PolicyCommandCode must match the host-computed chain.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task PolicyPcrDrivesTheSessionPolicyDigestAsPredicted()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        const TpmAlgIdConstants PcrBank = TpmAlgIdConstants.TPM_ALG_SHA256;
        int[] pcrIndices = [0];

        //On a trial session the TPM uses the caller's pcrDigest verbatim, so the prediction does not depend on
        //live PCR contents — the test stays deterministic. Computed through the registered digest seam (not a
        //direct framework hash), matching this file's ComputeNvNameAsync convention.
        using DigestValue pcrDigestValue = await CryptographicKeyEvents.ComputeDigestAsync(
            "policy-pcr-test"u8.ToArray(), 32, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        byte[] pcrDigest = pcrDigestValue.AsReadOnlySpan().ToArray();

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
            PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            TpmResult<PolicyPcrResponse> pcrResult = await tpm.PolicyPcrAsync(
                sessionHandle, PcrBank, pcrIndices, pcrDigest, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(pcrResult.IsSuccess, $"PolicyPCR failed: '{pcrResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;

            Assert.IsTrue(
                MatchesPcrPolicy(digest.PolicyDigest.AsReadOnlySpan(), PcrBank, pcrIndices, pcrDigest, PolicyHash),
                "The simulator's policyDigest after PolicyPCR must match the host-computed value.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task PolicySecretBindsToTheEndorsementKeyPolicy()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;

        //PolicySecret authorizes a hierarchy for real, so this uses a real policy session (not a trial one); the
        //resulting policyDigest is identical either way.
        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret failed: '{secretResult.ResponseCode}'.");

            using(secretResult.Value)
            {
                TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                    sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

                using PolicyGetDigestResponse digest = digestResult.Value;

                //PolicySecret(TPM_RH_ENDORSEMENT) extends zeros by H(zeros || TPM_CC_PolicySecret || endorsementName)
                //followed by the (empty) policyRef hash.
                Assert.IsTrue(
                    MatchesEndorsementSecretPolicy(digest.PolicyDigest.AsReadOnlySpan(), PolicyHash),
                    "The simulator's policyDigest after PolicySecret(endorsement) must match the host-computed value.");

                //That value is the well-known endorsement-key authorization policy.
                Assert.IsTrue(
                    digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(WellKnownEndorsementKeyPolicySha256),
                    "PolicySecret(endorsement) must yield the well-known EK authorization policy.");
            }
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    //The well-known endorsement-key authorization policy for SHA-256:
    //H(0x00...00(32) || TPM_CC_PolicySecret || TPM_RH_ENDORSEMENT) with an empty policyRef — a fixed public value
    //independent of this codebase (TPM 2.0 endorsement-key authorization).
    private static readonly byte[] WellKnownEndorsementKeyPolicySha256 =
    [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
        0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa
    ];

    /// <summary>
    /// Predicts the policyDigest of a fresh policy session after PolicySecret(TPM_RH_ENDORSEMENT) and compares it
    /// to <paramref name="actualDigest"/>. Kept synchronous so the stack buffers never span an await.
    /// </summary>
    /// <param name="actualDigest">The policyDigest reported by the TPM.</param>
    /// <param name="policyHash">The session's policy hash algorithm.</param>
    /// <returns><see langword="true"/> when the prediction matches.</returns>
    private static bool MatchesEndorsementSecretPolicy(ReadOnlySpan<byte> actualDigest, TpmAlgIdConstants policyHash)
    {
        int size = TpmPolicyDigest.Size(policyHash);
        Span<byte> current = stackalloc byte[size];
        current.Clear();

        //The Name of a permanent handle is its 4-byte handle value.
        Span<byte> endorsementName = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(endorsementName, (uint)TpmRh.TPM_RH_ENDORSEMENT);

        Span<byte> predicted = stackalloc byte[size];
        TpmPolicyDigest.ExtendForSecret(current, endorsementName, ReadOnlySpan<byte>.Empty, policyHash, predicted);

        return actualDigest.SequenceEqual(predicted);
    }

    [TestMethod]
    public async Task PolicyOrAuthorizesAMatchingBranchAndCollapsesToTheOrDigest()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        int size = TpmPolicyDigest.Size(PolicyHash);

        //PolicyOR's match check runs on a real session, so this uses one (not a trial session).
        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            //Drive the session to a known digest so it equals one of the OR branches.
            TpmResult<PolicyAuthValueResponse> authValueResult = await tpm.PolicyAuthValueAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue failed: '{authValueResult.ResponseCode}'.");

            byte[] matchingBranch = new byte[size];
            Span<byte> zero = stackalloc byte[size];
            zero.Clear();
            TpmPolicyDigest.ExtendForAuthValue(zero, PolicyHash, matchingBranch);

            byte[] otherBranch = new byte[size];
            Array.Fill(otherBranch, (byte)0x5A);

            var branches = new ReadOnlyMemory<byte>[] { matchingBranch, otherBranch };

            //The session's current digest equals matchingBranch, so PolicyOR authorizes and collapses to the OR digest.
            TpmResult<PolicyOrResponse> orResult = await tpm.PolicyOrAsync(
                sessionHandle, branches, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(orResult.IsSuccess, $"PolicyOR failed: '{orResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;

            byte[] predicted = new byte[size];
            TpmPolicyDigest.ExtendForOr(branches, PolicyHash, predicted);

            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                "The simulator's policyDigest after PolicyOR must equal H(0 || TPM_CC_PolicyOR || branches).");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task PolicyNvDrivesTheSessionPolicyDigestAsPredicted()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        const uint NvIndex = 0x0100_0012;
        const ushort Offset = 0;
        const ushort DataSize = 8;
        const TpmEoConstants Operation = TpmEoConstants.TPM_EO_EQ;
        int size = TpmPolicyDigest.Size(PolicyHash);
        byte[] operandB = [0x10, 0x20, 0x30, 0x40];
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA;

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

        //A trial session needs only the Index's Name, not its data, so the Index can stay unwritten.
        _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineNvAsync(tpm, registry, pool, NvIndex, attributes, DataSize).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
                PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            uint sessionHandle = session.SessionHandle.Value;
            try
            {
                TpmResult<PolicyNvResponse> nvResult = await tpm.PolicyNvAsync(
                    NvIndex, NvIndex, sessionHandle, operandB, Offset, Operation, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(nvResult.IsSuccess, $"PolicyNV failed: '{nvResult.ResponseCode}'.");

                TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                    sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

                using PolicyGetDigestResponse digest = digestResult.Value;

                //policyDigest = H(zeros || TPM_CC_PolicyNV || H(operandB || offset || operation) || nvName).
                byte[] nvName = await ComputeNvNameAsync(NvIndex, PolicyHash, attributes, DataSize, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] predicted = new byte[size];
                Span<byte> zero = stackalloc byte[size];
                zero.Clear();
                TpmPolicyDigest.ExtendForNv(zero, operandB, Offset, (ushort)Operation, nvName, PolicyHash, predicted);

                Assert.IsTrue(
                    digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                    "The simulator's policyDigest after PolicyNV must match the host-computed value.");
            }
            finally
            {
                _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies that a REAL (non-trial) TPM2_PolicyNV session compares the retained Index data at the offset and,
    /// on a true comparison, authorizes and folds the digest exactly as the host predicts — closing the tracked
    /// gap where the simulator's PolicyNV always succeeded regardless of the Index's actual contents.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvLiveComparisonAcceptsATrueOperandOnAWrittenIndex()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        const uint NvIndex = 0x0100_0013;
        const ushort Offset = 0;
        const ushort DataSize = 8;
        const TpmEoConstants Operation = TpmEoConstants.TPM_EO_EQ;
        int size = TpmPolicyDigest.Size(PolicyHash);
        byte[] writtenData = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA;

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

        _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineNvAsync(tpm, registry, pool, NvIndex, attributes, DataSize).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
        try
        {
            await WriteNvAsync(tpm, registry, pool, NvIndex, writtenData).ConfigureAwait(false);
            TpmaNv writtenAttributes = attributes | TpmaNv.TPMA_NV_WRITTEN;

            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (real) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            uint sessionHandle = session.SessionHandle.Value;
            try
            {
                //operandB equals the written data at offset 0, so TPM_EO_EQ must hold against the live Index.
                TpmResult<PolicyNvResponse> nvResult = await tpm.PolicyNvAsync(
                    NvIndex, NvIndex, sessionHandle, writtenData, Offset, Operation, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(nvResult.IsSuccess, $"PolicyNV (true comparison) failed: '{nvResult.ResponseCode}'.");

                TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                    sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

                using PolicyGetDigestResponse digest = digestResult.Value;

                byte[] nvName = await ComputeNvNameAsync(NvIndex, PolicyHash, writtenAttributes, DataSize, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] predicted = new byte[size];
                Span<byte> zero = stackalloc byte[size];
                zero.Clear();
                TpmPolicyDigest.ExtendForNv(zero, writtenData, Offset, (ushort)Operation, nvName, PolicyHash, predicted);

                Assert.IsTrue(
                    digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                    "The simulator's policyDigest after a live, true PolicyNV comparison must match the host-computed value.");
            }
            finally
            {
                _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies that a REAL (non-trial) TPM2_PolicyNV session rejects with TPM_RC_POLICY when the retained Index
    /// data does not satisfy the comparison, and leaves the session's policyDigest untouched.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvLiveComparisonRejectsAFalseOperand()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        const uint NvIndex = 0x0100_0014;
        const ushort Offset = 0;
        const ushort DataSize = 8;
        byte[] writtenData = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        byte[] mismatchingOperand = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA;

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

        _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineNvAsync(tpm, registry, pool, NvIndex, attributes, DataSize).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
        try
        {
            await WriteNvAsync(tpm, registry, pool, NvIndex, writtenData).ConfigureAwait(false);

            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (real) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            uint sessionHandle = session.SessionHandle.Value;
            try
            {
                TpmResult<PolicyNvResponse> nvResult = await tpm.PolicyNvAsync(
                    NvIndex, NvIndex, sessionHandle, mismatchingOperand, Offset, TpmEoConstants.TPM_EO_EQ, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(nvResult.IsSuccess, "PolicyNV must reject a false comparison against the live Index data.");
                Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY, nvResult.ResponseCode, "A false PolicyNV comparison must reject with TPM_RC_POLICY.");
            }
            finally
            {
                _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Exploit-becomes-regression test: an undefined <c>TPM_EO</c> value (0x0100, outside the 12 Table 22 defines)
    /// on a REAL policy session must reject with <c>TPM_RC_VALUE</c> through the production wire path, not throw
    /// an unhandled exception out of <c>TpmSimulator.SubmitAsync</c> (TPM 2.0 Library Part 3, clause 5.1: an
    /// undefined selector is rejected at unmarshal).
    /// </summary>
    [TestMethod]
    public async Task PolicyNvWithAnUndefinedOperationReturnsValueOnARealSession()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        const uint NvIndex = 0x0100_0015;
        const ushort Offset = 0;
        const ushort DataSize = 8;
        const TpmEoConstants UndefinedOperation = (TpmEoConstants)0x0100;
        byte[] writtenData = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA;

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

        _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineNvAsync(tpm, registry, pool, NvIndex, attributes, DataSize).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
        try
        {
            await WriteNvAsync(tpm, registry, pool, NvIndex, writtenData).ConfigureAwait(false);

            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (real) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            uint sessionHandle = session.SessionHandle.Value;
            try
            {
                TpmResult<PolicyNvResponse> nvResult = await tpm.PolicyNvAsync(
                    NvIndex, NvIndex, sessionHandle, writtenData, Offset, UndefinedOperation, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(nvResult.IsSuccess, "An undefined TPM_EO must be rejected, not silently accepted.");
                Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, nvResult.ResponseCode, "An undefined TPM_EO must reject with TPM_RC_VALUE at unmarshal.");
            }
            finally
            {
                _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a TRIAL session rejects the same undefined <c>TPM_EO</c> identically to a REAL session (the FIX
    /// 1 uniformity requirement): the parse-time check runs before the trial/real branch, so the trial session's
    /// "skip the comparison, fold unconditionally" path never gets a chance to silently accept it.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvWithAnUndefinedOperationReturnsValueOnATrialSessionToo()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        const uint NvIndex = 0x0100_0016;
        const ushort Offset = 0;
        const ushort DataSize = 8;
        const TpmEoConstants UndefinedOperation = (TpmEoConstants)0x0100;
        byte[] operandB = [0x10, 0x20, 0x30, 0x40];
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA;

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

        //A trial session needs only the Index's Name, not its data, so the Index can stay unwritten.
        _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineNvAsync(tpm, registry, pool, NvIndex, attributes, DataSize).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
                PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            uint sessionHandle = session.SessionHandle.Value;
            try
            {
                TpmResult<PolicyNvResponse> nvResult = await tpm.PolicyNvAsync(
                    NvIndex, NvIndex, sessionHandle, operandB, Offset, UndefinedOperation, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(nvResult.IsSuccess, "A trial session must reject an undefined TPM_EO too, not silently fold it.");
                Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, nvResult.ResponseCode, "A trial session's undefined TPM_EO must also reject with TPM_RC_VALUE at unmarshal.");
            }
            finally
            {
                _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Writes <paramref name="data"/> in full to <paramref name="nvIndex"/>, authorized by the Index's own (empty)
    /// auth value, setting TPMA_NV_WRITTEN.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The NV Index handle.</param>
    /// <param name="data">The data to write.</param>
    private async Task WriteNvAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, uint nvIndex, byte[] data)
    {
        using TpmPasswordSession writeAuth = TpmPasswordSession.CreateEmpty(pool);
        var writeInput = new NvWriteInput(nvIndex, nvIndex, new Tpm2bMaxBuffer(data), Offset: 0);

        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"NV_Write failed: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// Defines a small NV Index authorized by its own (empty) auth value.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The NV Index handle.</param>
    /// <param name="attributes">The Index attributes.</param>
    /// <param name="dataSize">The data area size.</param>
    /// <returns>The NV_DefineSpace result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineNvAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, uint nvIndex, TpmaNv attributes, ushort dataSize)
    {
        using Tpm2bAuth indexAuth = Tpm2bAuth.CreateEmpty(pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, dataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, indexAuth, publicInfo);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Undefines an NV Index, returning the result for the caller to assert or ignore.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The NV Index handle.</param>
    /// <returns>The NV_UndefineSpace result.</returns>
    private async Task<TpmResult<NvUndefineSpaceResponse>> UndefineNvAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, uint nvIndex)
    {
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Computes an NV Index Name (<c>nameAlg || H(TPMS_NV_PUBLIC)</c>) from its public-area fields, through the
    /// registered digest seam (not a direct framework hash).
    /// </summary>
    /// <param name="nvIndex">The NV Index handle.</param>
    /// <param name="nameAlg">The Name hash algorithm (SHA-256).</param>
    /// <param name="attributes">The Index attributes, exactly as stored (include TPMA_NV_WRITTEN once written).</param>
    /// <param name="dataSize">The data area size.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The Name bytes.</returns>
    private static async Task<byte[]> ComputeNvNameAsync(uint nvIndex, TpmAlgIdConstants nameAlg, TpmaNv attributes, ushort dataSize, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using var nvPublic = new TpmsNvPublic(nvIndex, nameAlg, attributes, Tpm2bDigest.Empty, dataSize);
        int publicSize = nvPublic.SerializedSize;
        using IMemoryOwner<byte> owner = pool.Rent(publicSize);
        Span<byte> publicArea = owner.Memory.Span[..publicSize];
        var writer = new TpmWriter(publicArea);
        nvPublic.WriteTo(ref writer);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            owner.Memory[..publicSize], 32, CryptoTags.Sha256Digest, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        byte[] name = new byte[sizeof(ushort) + 32];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)nameAlg);
        digest.AsReadOnlySpan().CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>
    /// Predicts the policyDigest of a fresh policy session restricted with a single PolicyCommandCode and
    /// compares it to <paramref name="actualDigest"/>. Kept synchronous so the stack buffers never span an await.
    /// </summary>
    /// <param name="actualDigest">The policyDigest reported by the TPM.</param>
    /// <param name="restrictedCommand">The command code the policy was restricted to.</param>
    /// <param name="policyHash">The session's policy hash algorithm.</param>
    /// <returns><see langword="true"/> when the prediction matches.</returns>
    private static bool MatchesCommandCodePolicy(ReadOnlySpan<byte> actualDigest, TpmCcConstants restrictedCommand, TpmAlgIdConstants policyHash)
    {
        int size = TpmPolicyDigest.Size(policyHash);

        //These buffers hold only non-secret public policy material (a policyDigest over public inputs) and are
        //test-local, so stack allocation is acceptable rather than the BaseMemoryPool containment used for
        //sensitive material. A fresh session's policyDigest is all zeros (stackalloc is zero-initialized).
        Span<byte> initial = stackalloc byte[size];
        Span<byte> expected = stackalloc byte[size];
        int expectedLength = TpmPolicyDigest.ExtendForCommandCode(initial, restrictedCommand, policyHash, expected);

        return actualDigest.SequenceEqual(expected[..expectedLength]);
    }

    /// <summary>
    /// Predicts the policyDigest of a fresh policy session after PolicyAuthValue then a PolicyCommandCode and
    /// compares it to <paramref name="actualDigest"/>. Kept synchronous so the stack buffers never span an await.
    /// </summary>
    /// <param name="actualDigest">The policyDigest reported by the TPM.</param>
    /// <param name="restrictedCommand">The command code the policy was restricted to.</param>
    /// <param name="policyHash">The session's policy hash algorithm.</param>
    /// <returns><see langword="true"/> when the prediction matches.</returns>
    private static bool MatchesAuthValueThenCommandCode(ReadOnlySpan<byte> actualDigest, TpmCcConstants restrictedCommand, TpmAlgIdConstants policyHash)
    {
        int size = TpmPolicyDigest.Size(policyHash);

        //Non-secret public policy material, test-local: stack allocation is acceptable rather than the
        //BaseMemoryPool containment used for sensitive material. Fresh session is all zeros (zero-initialized).
        Span<byte> afterAuthValue = stackalloc byte[size];
        int afterAuthValueLength = TpmPolicyDigest.ExtendForAuthValue(stackalloc byte[size], policyHash, afterAuthValue);

        Span<byte> expected = stackalloc byte[size];
        int expectedLength = TpmPolicyDigest.ExtendForCommandCode(afterAuthValue[..afterAuthValueLength], restrictedCommand, policyHash, expected);

        return actualDigest.SequenceEqual(expected[..expectedLength]);
    }

    /// <summary>
    /// Predicts the policyDigest of a fresh policy session after a single PolicyPCR and compares it to
    /// <paramref name="actualDigest"/>. Kept synchronous so the stack buffers never span an await.
    /// </summary>
    /// <param name="actualDigest">The policyDigest reported by the TPM.</param>
    /// <param name="pcrBank">The PCR bank selected.</param>
    /// <param name="pcrIndices">The PCR indices selected.</param>
    /// <param name="pcrDigest">The PCR digest the policy bound to.</param>
    /// <param name="policyHash">The session's policy hash algorithm.</param>
    /// <returns><see langword="true"/> when the prediction matches.</returns>
    private static bool MatchesPcrPolicy(ReadOnlySpan<byte> actualDigest, TpmAlgIdConstants pcrBank, int[] pcrIndices, ReadOnlySpan<byte> pcrDigest, TpmAlgIdConstants policyHash)
    {
        using TpmlPcrSelection pcrs = TpmlPcrSelection.Create(pcrBank, pcrIndices, BaseMemoryPool.Shared);

        //Non-secret public policy material (marshaled PCR selection and a policyDigest over public inputs) and
        //test-local, so stack allocation is acceptable rather than the BaseMemoryPool containment used for
        //sensitive material.
        Span<byte> marshaled = stackalloc byte[pcrs.GetSerializedSize()];
        var writer = new TpmWriter(marshaled);
        pcrs.WriteTo(ref writer);

        int size = TpmPolicyDigest.Size(policyHash);
        Span<byte> expected = stackalloc byte[size];
        int expectedLength = TpmPolicyDigest.ExtendForPcr(stackalloc byte[size], marshaled[..writer.Written], pcrDigest, policyHash, expected);

        return actualDigest.SequenceEqual(expected[..expectedLength]);
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase. The policy commands themselves need no signing
    /// backend, but the backend is wired for parity with the other in-house simulator tests.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-policy", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
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
    private async Task BringOperationalAsync(TpmSimulator simulator, MemoryPool<byte> pool)
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
