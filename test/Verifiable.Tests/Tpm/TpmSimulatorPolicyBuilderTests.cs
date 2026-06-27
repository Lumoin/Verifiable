using System;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.TestInfrastructure.TpmSimulator;
using Verifiable.Tpm;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Acceptance tests for <see cref="TpmPolicyBuilder"/> / <see cref="TpmPolicy"/> against the TCG ms-tpm-20-ref
/// software TPM simulator. They confirm a policy described once drives a live session to exactly the policyDigest
/// the same description predicts host-side — i.e. the two duals (predict and execute) cannot drift apart.
/// </summary>
/// <remarks>
/// The tests are gated on a running simulator (start the container from
/// <c>test/Verifiable.Tests/TestInfrastructure/TpmSimulator/Dockerfile</c>, publishing ports 2321/2322); they
/// report <see cref="Assert.Inconclusive(string)"/> when none is reachable, so they are safe in any run.
/// </remarks>
[ConditionalTestClass]
[SkipIfNoTpmSimulator]
[DoNotParallelize]
[TestCategory("RequiresTpmSimulator")]
internal sealed class TpmSimulatorPolicyBuilderTests
{
    /// <summary>The connection to the simulator, established once for the class.</summary>
    private static MsTpmSimulatorConnection? Connection { get; set; }

    /// <summary>The TPM device created over the simulator connection.</summary>
    private static TpmDevice? Tpm { get; set; }

    /// <summary>Whether a simulator was reachable at class initialization.</summary>
    private static bool HasSimulator { get; set; }

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>Connects to the simulator (if one is reachable) and brings up a TPM device for the class.</summary>
    /// <param name="context">The class-level test context.</param>
    [ClassInitialize]
    public static async Task ClassInit(TestContext context)
    {
        if(!MsTpmSimulatorConnection.IsAvailable("localhost", MsTpmSimulatorConnection.DefaultCommandPort, TimeSpan.FromSeconds(1)))
        {
            return;
        }

        Connection = await MsTpmSimulatorConnection.ConnectAsync(
            "localhost", MsTpmSimulatorConnection.DefaultCommandPort, context.CancellationToken).ConfigureAwait(false);
        Tpm = TpmDevice.Create(Connection.SubmitAsync);
        HasSimulator = true;
    }

    /// <summary>Releases the TPM device and simulator connection.</summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        Tpm?.Dispose();
        Connection?.Dispose();
    }

    /// <summary>Skips the test when no simulator is reachable.</summary>
    [TestInitialize]
    public void TestInit()
    {
        if(!HasSimulator)
        {
            Assert.Inconclusive("No TPM simulator is reachable on localhost:2321/2322. Start the container from TestInfrastructure/TpmSimulator/Dockerfile.");
        }
    }

    [TestMethod]
    public async Task BuiltPolicyExecutesToItsComputedDigest()
    {
        TpmDevice tpm = Tpm!;
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;

        //One description: require the object's authValue, then restrict the session to TPM2_Sign.
        TpmPolicy policy = new TpmPolicyBuilder()
            .WithAuthValue()
            .WithCommandCode(TpmCcConstants.TPM_CC_Sign)
            .Build();

        byte[] predicted = new byte[TpmPolicyDigest.Size(PolicyHash)];
        _ = policy.ComputeDigest(PolicyHash, predicted);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            TpmResult<uint> executeResult = await policy.ExecuteAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(executeResult.IsSuccess, $"Policy execution failed: '{executeResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;
            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                "The executed policy's digest must equal the host-computed digest from the same description.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task BuiltOrPolicyExecutesToItsComputedDigest()
    {
        TpmDevice tpm = Tpm!;
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        int size = TpmPolicyDigest.Size(PolicyHash);

        //Two alternative branches; the session will satisfy the first.
        byte[] branchA = new byte[size];
        _ = new TpmPolicyBuilder().WithAuthValue().Build().ComputeDigest(PolicyHash, branchA);

        byte[] branchB = new byte[size];
        _ = new TpmPolicyBuilder().WithCommandCode(TpmCcConstants.TPM_CC_Sign).Build().ComputeDigest(PolicyHash, branchB);

        var branches = new ReadOnlyMemory<byte>[] { branchA, branchB };

        //Satisfy branch A (PolicyAuthValue), then OR the alternatives — exactly what an "A or B" policy is.
        TpmPolicy policy = new TpmPolicyBuilder()
            .WithAuthValue()
            .WithOr(branches)
            .Build();

        byte[] predicted = new byte[size];
        _ = policy.ComputeDigest(PolicyHash, predicted);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            TpmResult<uint> executeResult = await policy.ExecuteAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(executeResult.IsSuccess, $"OR policy execution failed: '{executeResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;
            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                "The executed OR policy's digest must equal the host-computed digest from the same description.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }
}
