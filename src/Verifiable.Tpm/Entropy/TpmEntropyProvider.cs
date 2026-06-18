using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm;

/// <summary>
/// Exposes a <see cref="TpmDevice"/> as an auditable entropy source for the library's cryptographic
/// factory. Each draw runs <c>TPM2_GetRandom()</c> against the device and is accompanied by an
/// <see cref="EntropyConsumedEvent"/> tagged <see cref="EntropySource.Tpm"/>, carrying the source's
/// most recent health observation. This is the provenance layer: the device itself only returns octets,
/// while this provider records <em>where they came from and how healthy the source was</em>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Registration.</strong> The <see cref="GenerateNonce"/> and <see cref="GenerateSalt"/> methods
/// match <see cref="GenerateNonceDelegate"/> and <see cref="GenerateSaltDelegate"/>, so the application
/// registers them with the factory and the events flow on
/// <see cref="CryptographicKeyEvents.Events"/>:
/// </para>
/// <code>
/// var provider = new TpmEntropyProvider(device, pool);
/// CryptographicKeyFactory.RegisterFunction(
///     typeof(GenerateNonceDelegate), (GenerateNonceDelegate)provider.GenerateNonce, qualifier: "tpm");
///
/// //Drawn through the factory; the EntropyConsumedEvent(Source=Tpm) is emitted automatically.
/// Nonce nonce = CryptographicKeyEvents.GenerateNonce(32, tag, pool, qualifier: "tpm");
/// </code>
/// <para>
/// <strong>Synchronous bridge.</strong> The entropy delegates are synchronous, while a TPM round-trip
/// is asynchronous. This provider therefore requires a synchronously-completing device — the in-process
/// simulator, the virtual replay device, and the synchronous Windows TBS path all qualify. A genuinely
/// asynchronous backend (the Linux kernel resource manager, a network HSM) cannot be consumed from the
/// synchronous entropy path and causes <see cref="GenerateNonce"/>/<see cref="GenerateSalt"/> to throw,
/// mirroring <see cref="CryptographicKeyEvents.ComputeDigestSyncBridge(ReadOnlyMemory{byte}, int, Tag, MemoryPool{byte}, string?)"/>.
/// </para>
/// <para>
/// <strong>Health.</strong> <see cref="AssessHealthAsync"/> runs <c>TPM2_SelfTest()</c> and maps the
/// response code to an <see cref="EntropyHealthObservation"/> (<see cref="EntropyAssessmentMethod.SelfTest"/>,
/// self-attested by the source). The observation becomes <see cref="CurrentHealth"/> and is stamped onto
/// every subsequent <see cref="EntropyConsumedEvent.HealthAtGeneration"/>. A TPM that has failed self-test
/// is reported <see cref="EntropyOutcome.Failed"/> — a signal that its RNG output must not be trusted for
/// key material.
/// </para>
/// </remarks>
/// <seealso cref="EntropySource"/>
/// <seealso cref="EntropyConsumedEvent"/>
public sealed class TpmEntropyProvider
{
    private readonly TpmDevice device;
    private readonly TpmResponseRegistry registry;
    private readonly MemoryPool<byte> pool;
    private readonly TimeProvider timeProvider;
    private readonly string emittedBy;
    private EntropyHealthObservation currentHealth = EntropyHealthObservation.Unknown;

    /// <summary>
    /// Creates a provider drawing entropy from the supplied device.
    /// </summary>
    /// <param name="device">
    /// The TPM device. Must complete <c>TPM2_GetRandom()</c> synchronously for the entropy-delegate path
    /// (simulator, virtual device, or Windows TBS).
    /// </param>
    /// <param name="pool">The memory pool used for the device round-trip buffers.</param>
    /// <param name="emittedBy">
    /// The component identity stamped on emitted events. Defaults to <c>nameof(TpmEntropyProvider)</c>;
    /// callers that run several providers in one process (or one test host) should pass a distinct value
    /// so events can be attributed and filtered.
    /// </param>
    /// <param name="timeProvider">The time source for event and observation timestamps.</param>
    public TpmEntropyProvider(TpmDevice device, MemoryPool<byte> pool, string? emittedBy = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(pool);

        this.device = device;
        this.pool = pool;
        this.timeProvider = timeProvider ?? TimeProvider.System;
        this.emittedBy = string.IsNullOrWhiteSpace(emittedBy) ? nameof(TpmEntropyProvider) : emittedBy;
        registry = new TpmResponseRegistry().Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
    }

    /// <summary>
    /// Gets the most recent health observation of the TPM entropy source, or
    /// <see cref="EntropyHealthObservation.Unknown"/> until <see cref="AssessHealthAsync"/> has run.
    /// </summary>
    public EntropyHealthObservation CurrentHealth => currentHealth;

    /// <summary>
    /// Generates a <see cref="Nonce"/> from TPM entropy. Matches <see cref="GenerateNonceDelegate"/>.
    /// </summary>
    /// <param name="byteLength">The number of random octets to draw.</param>
    /// <param name="tag">Metadata identifying the purpose; the <see cref="Purpose"/> it carries (or
    /// <see cref="Purpose.Nonce"/> by default) is recorded on the event.</param>
    /// <param name="pool">The memory pool for the returned nonce's buffer.</param>
    /// <returns>The nonce and an <see cref="EntropyConsumedEvent"/> tagged <see cref="EntropySource.Tpm"/>.</returns>
    public (Nonce Result, CryptoEvent? Event) GenerateNonce(int byteLength, Tag tag, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        EntropyHealthObservation health = currentHealth;
        Nonce result = Nonce.Generate(byteLength, tag, Fill, health, pool);
        Purpose purpose = tag.TryGet<Purpose>(out Purpose carried) ? carried : Purpose.Nonce;
        CryptoEvent consumed = EntropyConsumedEvent.Create(EntropySource.Tpm, byteLength, purpose, health, emittedBy, timeProvider);

        return (result, consumed);
    }

    /// <summary>
    /// Generates a <see cref="Salt"/> from TPM entropy. Matches <see cref="GenerateSaltDelegate"/>.
    /// </summary>
    /// <param name="byteLength">The number of random octets to draw.</param>
    /// <param name="tag">Metadata identifying the purpose; the <see cref="Purpose"/> it carries (or
    /// <see cref="Purpose.Salt"/> by default) is recorded on the event.</param>
    /// <param name="pool">The memory pool for the returned salt's buffer.</param>
    /// <returns>The salt and an <see cref="EntropyConsumedEvent"/> tagged <see cref="EntropySource.Tpm"/>.</returns>
    public (Salt Result, CryptoEvent? Event) GenerateSalt(int byteLength, Tag tag, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        EntropyHealthObservation health = currentHealth;
        Salt result = Salt.Generate(byteLength, tag, Fill, health, pool);
        Purpose purpose = tag.TryGet<Purpose>(out Purpose carried) ? carried : Purpose.Salt;
        CryptoEvent consumed = EntropyConsumedEvent.Create(EntropySource.Tpm, byteLength, purpose, health, emittedBy, timeProvider);

        return (result, consumed);
    }

    /// <summary>
    /// Assesses the entropy source's health by running <c>TPM2_SelfTest()</c> and mapping its response
    /// code to an <see cref="EntropyHealthObservation"/> (TPM 2.0 Library Part 1, clause 10.3). The
    /// observation is retained as <see cref="CurrentHealth"/> and stamped on subsequent draws.
    /// </summary>
    /// <param name="cancellationToken">Token observed across the device round-trip.</param>
    /// <returns>The observation and an <see cref="EntropyHealthAssessedEvent"/> describing the assessment.</returns>
    public async ValueTask<(EntropyHealthObservation Observation, EntropyHealthAssessedEvent Event)> AssessHealthAsync(CancellationToken cancellationToken = default)
    {
        SelfTestResult selfTest = await SubmitSelfTestAsync(cancellationToken).ConfigureAwait(false);

        //Map the self-test outcome (Part 1, clause 10.3): SUCCESS is healthy; TPM_RC_TESTING is a
        //warning (tests still in progress) so health is not yet determined; any other code is a genuine
        //failure. A transport loss yields no verdict at all, so it is likewise indeterminate — and its
        //evidence records the transport code, never a self-test code, so the two causes are not conflated.
        EntropyOutcome outcome;
        string evidenceReference;
        if(selfTest.IsTransportError)
        {
            outcome = EntropyOutcome.Unknown;
            evidenceReference = $"transport-error:0x{selfTest.TransportErrorCode:X8}";
        }
        else
        {
            outcome = selfTest.ResponseCode switch
            {
                TpmRcConstants.TPM_RC_SUCCESS => EntropyOutcome.Healthy,
                TpmRcConstants.TPM_RC_TESTING => EntropyOutcome.Unknown,
                _ => EntropyOutcome.Failed
            };
            evidenceReference = selfTest.ResponseCode.ToString();
        }

        var observation = new EntropyHealthObservation
        {
            Source = EntropySource.Tpm,
            Assessor = EntropyAssessor.Source,
            Method = EntropyAssessmentMethod.SelfTest,
            Outcome = outcome,
            ObservedAt = timeProvider.GetUtcNow(),
            EvidenceReference = evidenceReference
        };

        currentHealth = observation;
        EntropyHealthAssessedEvent assessed = EntropyHealthAssessedEvent.Create(EntropySource.Tpm, observation, emittedBy, timeProvider);

        return (observation, assessed);
    }

    /// <summary>
    /// Fills <paramref name="destination"/> with random octets drawn from the TPM via
    /// <c>TPM2_GetRandom()</c>, chunking by the largest digest the TPM returns per call (TPM 2.0
    /// Library Part 3, clause 16.1). Matches <see cref="FillEntropyDelegate"/>, so the provider can
    /// also be registered as a raw entropy fill source.
    /// </summary>
    /// <param name="destination">The span to fill completely.</param>
    /// <remarks>
    /// Synchronous by the entropy-delegate contract: the device must complete <c>TPM2_GetRandom()</c>
    /// synchronously (the in-process simulator, the virtual device, and Windows TBS do); an
    /// asynchronous backend throws, as does a failed or empty draw — a degraded entropy source surfaces
    /// rather than silently weakening the output.
    /// </remarks>
    public void Fill(Span<byte> destination)
    {
        int offset = 0;
        while(offset < destination.Length)
        {
            int chunk = Math.Min(destination.Length - offset, TpmLifecycleTransitions.MaxRandomBytes);

            ValueTask<TpmResult<GetRandomResponse>> task = TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, new GetRandomInput((ushort)chunk), [], pool, registry);

            if(!task.IsCompleted)
            {
                throw new InvalidOperationException(
                    "TpmEntropyProvider requires a synchronously-completing TPM device for the entropy "
                    + "delegate; an asynchronous backend cannot be consumed from this synchronous path.");
            }

            TpmResult<GetRandomResponse> result = task.GetAwaiter().GetResult();
            if(!result.IsSuccess)
            {
                throw new InvalidOperationException(DescribeDrawFailure(result));
            }

            using GetRandomResponse response = result.Value;
            int produced = response.RandomBytes.Size;
            if(produced == 0)
            {
                throw new InvalidOperationException(
                    "TPM2_GetRandom returned no octets; the entropy source cannot satisfy the request.");
            }

            int copy = Math.Min(produced, chunk);
            response.RandomBytes.AsReadOnlySpan()[..copy].CopyTo(destination.Slice(offset, copy));
            offset += copy;
        }
    }

    //Composes a draw-failure message preserving the transport-vs-TPM distinction the result carries;
    //reading ResponseCode on a transport-error result would itself throw.
    private static string DescribeDrawFailure(TpmResult<GetRandomResponse> result) =>
        result.IsTransportError
            ? $"TPM2_GetRandom failed while drawing entropy: transport error 0x{result.TransportErrorCode:X8}."
            : $"TPM2_GetRandom failed while drawing entropy: response code '{result.ResponseCode}'.";

    //Frames a sessionless TPM2_SelfTest(fullTest) command, submits it, and reports the self-test
    //outcome. SelfTest carries no response parameters, so the header response code is the whole TPM
    //verdict (no codec needed); a transport loss is surfaced distinctly so it is never recorded as a
    //self-test failure.
    private async ValueTask<SelfTestResult> SubmitSelfTestAsync(CancellationToken cancellationToken)
    {
        var input = new SelfTestInput(IsFullTest: true);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();

        using IMemoryOwner<byte> commandOwner = pool.Rent(length);
        Memory<byte> command = commandOwner.Memory[..length];
        WriteSessionlessCommand(command.Span, input, length);

        TpmResult<TpmResponse> result = await device.SubmitAsync(command, pool, cancellationToken).ConfigureAwait(false);
        if(result.IsTransportError)
        {
            return new SelfTestResult(IsTransportError: true, result.TransportErrorCode, TpmRcConstants.TPM_RC_FAILURE);
        }

        if(!result.IsSuccess)
        {
            return new SelfTestResult(IsTransportError: false, TransportErrorCode: 0u, TpmRcConstants.TPM_RC_FAILURE);
        }

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader header = TpmHeader.Parse(ref reader);

        return new SelfTestResult(IsTransportError: false, TransportErrorCode: 0u, (TpmRcConstants)header.Code);
    }

    //Writes a sessionless command (header, handles, parameters) into the supplied span. The TpmWriter
    //is a ref struct, so it is born and buried in this synchronous helper. Generic over the input type
    //so a value-type ITpmCommandInput is framed without boxing.
    private static void WriteSessionlessCommand<TInput>(Span<byte> destination, TInput input, int length)
        where TInput: ITpmCommandInput
    {
        var writer = new TpmWriter(destination);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);
    }

    //The outcome of a self-test submission: either a transport failure (no verdict obtained) or a TPM
    //verdict carried in the response header's code.
    private readonly record struct SelfTestResult(bool IsTransportError, uint TransportErrorCode, TpmRcConstants ResponseCode);
}
