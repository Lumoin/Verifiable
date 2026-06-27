using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Coverage for <see cref="TpmEntropyProvider"/>: drawing nonces and salts from a simulated TPM device,
/// the <see cref="EntropySource.Tpm"/> provenance carried on the accompanying events, chunking draws
/// larger than the device's per-call maximum, the self-test health assessment, and emission through the
/// live <see cref="CryptographicKeyEvents"/> factory path. All scenarios run against the in-process
/// simulator; no real TPM hardware is touched.
/// </summary>
[TestClass]
internal sealed class TpmEntropyProviderTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task GenerateNonceCarriesTpmProvenance()
    {
        const int ByteLength = 16;
        using TpmDevice device = await CreateOperationalDeviceAsync("tpm-entropy-nonce").ConfigureAwait(false);
        var provider = new TpmEntropyProvider(device, BaseMemoryPool.Shared, emittedBy: "tpm-entropy-nonce");

        (Nonce result, CryptoEvent? evt) = provider.GenerateNonce(ByteLength, Tag.Create((typeof(Purpose), Purpose.Nonce)), BaseMemoryPool.Shared);

        using(result)
        {
            Assert.AreEqual(ByteLength, result.Length);
        }

        var consumed = evt as EntropyConsumedEvent;
        Assert.IsNotNull(consumed, "A TPM draw must emit an EntropyConsumedEvent.");
        Assert.AreEqual(EntropySource.Tpm, consumed.Source);
        Assert.AreEqual(ByteLength, consumed.ByteCount);
        Assert.AreEqual(Purpose.Nonce, consumed.Purpose);
    }

    [TestMethod]
    public async Task GenerateSaltCarriesTpmProvenance()
    {
        const int ByteLength = 24;
        using TpmDevice device = await CreateOperationalDeviceAsync("tpm-entropy-salt").ConfigureAwait(false);
        var provider = new TpmEntropyProvider(device, BaseMemoryPool.Shared, emittedBy: "tpm-entropy-salt");

        (Salt result, CryptoEvent? evt) = provider.GenerateSalt(ByteLength, Tag.Create((typeof(Purpose), Purpose.Salt)), BaseMemoryPool.Shared);

        using(result)
        {
            Assert.AreEqual(ByteLength, result.Length);
        }

        var consumed = evt as EntropyConsumedEvent;
        Assert.IsNotNull(consumed);
        Assert.AreEqual(EntropySource.Tpm, consumed.Source);
        Assert.AreEqual(Purpose.Salt, consumed.Purpose);
    }

    [TestMethod]
    public async Task GenerateNonceChunksRequestLargerThanDeviceMaximum()
    {
        //Larger than a single TPM2_GetRandom can return, so FillFromTpm must issue several draws.
        const int ByteLength = TpmLifecycleTransitions.MaxRandomBytes * 2 + 5;
        using TpmDevice device = await CreateOperationalDeviceAsync("tpm-entropy-chunk").ConfigureAwait(false);
        var provider = new TpmEntropyProvider(device, BaseMemoryPool.Shared, emittedBy: "tpm-entropy-chunk");

        (Nonce result, _) = provider.GenerateNonce(ByteLength, Tag.Empty, BaseMemoryPool.Shared);

        using(result)
        {
            Assert.AreEqual(ByteLength, result.Length);
        }
    }

    [TestMethod]
    public async Task AssessHealthReportsHealthyForPassingSelfTest()
    {
        using TpmDevice device = await CreateOperationalDeviceAsync("tpm-entropy-healthy").ConfigureAwait(false);
        var provider = new TpmEntropyProvider(device, BaseMemoryPool.Shared, emittedBy: "tpm-entropy-healthy");

        (EntropyHealthObservation observation, EntropyHealthAssessedEvent assessed) = await provider.AssessHealthAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EntropySource.Tpm, observation.Source);
        Assert.AreEqual(EntropyAssessor.Source, observation.Assessor);
        Assert.AreEqual(EntropyAssessmentMethod.SelfTest, observation.Method);
        Assert.AreEqual(EntropyOutcome.Healthy, observation.Outcome);
        Assert.IsTrue(observation.IsHealthy);
        Assert.AreEqual(observation, assessed.Observation);

        //The assessed health is stamped onto subsequent draws.
        (Nonce nonce, CryptoEvent? evt) = provider.GenerateNonce(16, Tag.Empty, BaseMemoryPool.Shared);
        nonce.Dispose();
        var consumed = evt as EntropyConsumedEvent;
        Assert.IsNotNull(consumed);
        Assert.AreEqual(EntropyOutcome.Healthy, consumed.HealthAtGeneration.Outcome);
    }

    [TestMethod]
    public async Task AssessHealthReportsFailedForFailingSelfTest()
    {
        using TpmDevice device = await CreateOperationalDeviceAsync("tpm-entropy-failed", TpmSelfTestBehavior.Fails).ConfigureAwait(false);
        var provider = new TpmEntropyProvider(device, BaseMemoryPool.Shared, emittedBy: "tpm-entropy-failed");

        (EntropyHealthObservation observation, _) = await provider.AssessHealthAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EntropyOutcome.Failed, observation.Outcome);
        Assert.IsFalse(observation.IsHealthy);
        Assert.AreEqual(EntropySource.Tpm, observation.Source);
    }

    [TestMethod]
    public async Task FactoryPathEmitsTpmEntropyEvent()
    {
        const string TpmId = "tpm-entropy-factory";
        using TpmDevice device = await CreateOperationalDeviceAsync(TpmId).ConfigureAwait(false);
        var provider = new TpmEntropyProvider(device, BaseMemoryPool.Shared, emittedBy: TpmId);

        //A qualifier unique to this test isolates the registration from other tests sharing the
        //process-wide factory.
        CryptographicKeyFactory.RegisterFunction(
            typeof(GenerateNonceDelegate), (GenerateNonceDelegate)provider.GenerateNonce, qualifier: TpmId);

        var observed = new List<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(new CollectingObserver(observed)))
        {
            using Nonce nonce = CryptographicKeyEvents.GenerateNonce(
                32, Tag.Create((typeof(Purpose), Purpose.Nonce)), BaseMemoryPool.Shared, qualifier: TpmId);

            Assert.AreEqual(32, nonce.Length);
        }

        //Filter by emitter to ignore any concurrent entropy events from parallel tests.
        EntropyConsumedEvent emitted = observed
            .OfType<EntropyConsumedEvent>()
            .Single(e => e.EmittedBy == TpmId);

        Assert.AreEqual(EntropySource.Tpm, emitted.Source);
        Assert.AreEqual(32, emitted.ByteCount);
        Assert.AreEqual(Purpose.Nonce, emitted.Purpose);
    }

    [TestMethod]
    public async Task AssessHealthReportsUnknownWhenSelfTestStillRunning()
    {
        //A device whose TPM2_SelfTest reports TPM_RC_TESTING (tests in progress, not failed). The
        //in-process simulator never emits this, so a scripted device exercises the mapping.
        ValueTask<TpmResult<TpmResponse>> TestingHandler(ReadOnlyMemory<byte> command, MemoryPool<byte> handlerPool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(HeaderOnlyResponse(TpmRcConstants.TPM_RC_TESTING, handlerPool));

        using TpmDevice device = TpmDevice.Create(TestingHandler);
        var provider = new TpmEntropyProvider(device, BaseMemoryPool.Shared, emittedBy: "tpm-entropy-testing");

        (EntropyHealthObservation observation, _) = await provider.AssessHealthAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //Tests-in-progress is a warning, not a failure: health is not yet determined.
        Assert.AreEqual(EntropyOutcome.Unknown, observation.Outcome);
        Assert.AreEqual("TPM_RC_TESTING", observation.EvidenceReference);
    }

    [TestMethod]
    public async Task AssessHealthRecordsTransportEvidenceOnTransportError()
    {
        const uint TransportCode = 0x8028400Au;

        //A device whose self-test round-trip fails at the transport layer (no self-test verdict).
        ValueTask<TpmResult<TpmResponse>> TransportFailHandler(ReadOnlyMemory<byte> command, MemoryPool<byte> handlerPool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(TpmResult<TpmResponse>.TransportError(TransportCode));

        using TpmDevice device = TpmDevice.Create(TransportFailHandler);
        var provider = new TpmEntropyProvider(device, BaseMemoryPool.Shared, emittedBy: "tpm-entropy-transport");

        (EntropyHealthObservation observation, _) = await provider.AssessHealthAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //A transport loss yields no verdict; the evidence must record the transport cause, never a
        //self-test response code.
        Assert.AreEqual(EntropyOutcome.Unknown, observation.Outcome);
        Assert.AreEqual($"transport-error:0x{TransportCode:X8}", observation.EvidenceReference);
    }

    private async Task<TpmDevice> CreateOperationalDeviceAsync(string tpmId, TpmSelfTestBehavior selfTest = TpmSelfTestBehavior.Passes)
    {
        var simulator = new TpmSimulator(tpmId, selfTest);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> owner = FrameCommand(new StartupInput(TpmSuConstants.TPM_SU_CLEAR), pool, out int length);
        TpmResult<TpmResponse> startup = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        startup.Value.Dispose();

        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);

        return TpmDevice.Create(simulator.SubmitAsync);
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented command buffer transfers to the caller, which disposes it.")]
    private static IMemoryOwner<byte> FrameCommand<TInput>(TInput input, MemoryPool<byte> pool, out int length)
        where TInput: ITpmCommandInput
    {
        length = TpmHeader.HeaderSize + input.GetSerializedSize();
        IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        return owner;
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The TpmResponse takes ownership of the rented buffer and is owned by the returned TpmResult, which the caller under test disposes.")]
    private static TpmResult<TpmResponse> HeaderOnlyResponse(TpmRcConstants responseCode, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(TpmHeader.HeaderSize);
        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)TpmHeader.HeaderSize, (uint)responseCode);
        header.WriteTo(ref writer);

        return TpmResult<TpmResponse>.Success(new TpmResponse(owner, TpmHeader.HeaderSize));
    }

    private sealed class CollectingObserver(List<CryptoEvent> sink): IObserver<CryptoEvent>
    {
        public void OnCompleted()
        {
        }

        public void OnError(Exception error)
        {
        }

        public void OnNext(CryptoEvent value) => sink.Add(value);
    }
}
