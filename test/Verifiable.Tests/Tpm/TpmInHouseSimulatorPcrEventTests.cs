using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
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
/// <c>TPM2_PCR_Event()</c> on the in-house simulator through the production executor and codecs (TPM 2.0
/// Library Part 3, clause 22.3): the event digested under every implemented hash algorithm, the named register
/// extended with the SHA-256 digest, and the <c>TPM_RH_NULL</c>, bound, locality and authorization rules. Digest
/// oracles are the framework's own SHA-1/SHA-2 implementations, independent of the simulator's digest seam.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorPcrEventTests
{
    private const int Sha256DigestSize = 32;

    private const uint Locality3Pcr = 18;

    private const uint ApplicationPcr = 23;

    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Clause 22.3.1: "The data in eventData is hashed using the hash algorithm associated with each bank ...
    /// After the data is hashed, the digests list is returned ... the digests list is processed as in
    /// TPM2_PCR_Extend()"; Part 1, clause 14.4: one digest per implemented hash algorithm — SHA-1, SHA-256,
    /// SHA-384, SHA-512 in that order — and PCR 0 reads back as SHA-256(0³² ‖ SHA-256(event)).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 22.3.1; Part 1, clauses 14.2 and 14.4</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrEventReturnsOneDigestPerImplementedHashInOrderAndExtendsTheRegisterWithTheSha256One()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] eventData = RandomNumberGenerator.GetBytes(700);
        byte[] sha256 = SHA256.HashData(eventData);
        uint counterBefore = await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<PcrEventResponse> result = await SubmitEventAsync(tpm, registry, pool, 0, eventData, []).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_PCR_Event() failed: '{result.ResponseCode}'.");

        using PcrEventResponse response = result.Value;
        AssertImplementedDigests(response.Digests, eventData);

        Assert.AreSequenceEqual(SHA256.HashData([.. new byte[Sha256DigestSize], .. sha256]), await ReadPcrAsync(tpm, registry, pool, 0).ConfigureAwait(false), "PCR 0 must be extended with the SHA-256 digest of the event.");
        Assert.AreEqual(counterBefore + 1u, await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false), "One counted register changed once.");
    }

    /// <summary>
    /// Clause 22.3.1: "If pcrHandle is TPM_RH_NULL, the TPM may return either an empty list or a digest for
    /// each bank" — this TPM returns a digest for each implemented hash and extends nothing.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 22.3.2, Table 132</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrEventWithTheNullHandleReturnsTheDigestsAndChangesNothing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] eventData = RandomNumberGenerator.GetBytes(64);
        uint counterBefore = await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<PcrEventResponse> result = await SubmitEventAsync(tpm, registry, pool, (uint)TpmRh.TPM_RH_NULL, eventData, []).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_PCR_Event() with TPM_RH_NULL failed: '{result.ResponseCode}'.");

        using PcrEventResponse response = result.Value;
        AssertImplementedDigests(response.Digests, eventData);
        Assert.AreEqual(counterBefore, await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false), "No register changed, so the counter must not move.");
    }

    /// <summary>
    /// Clause 22.3.1: "An eventData.size of zero indicates that there is no data, but the indicated operations
    /// will still occur" — the digests are those of the empty message and the register is extended with
    /// SHA-256("").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 22.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrEventWithEmptyEventDataDigestsTheEmptyMessageAndStillExtends()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<PcrEventResponse> result = await SubmitEventAsync(tpm, registry, pool, 2, [], []).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_PCR_Event() with an empty event failed: '{result.ResponseCode}'.");

        using PcrEventResponse response = result.Value;
        AssertImplementedDigests(response.Digests, []);
        Assert.AreSequenceEqual(SHA256.HashData([.. new byte[Sha256DigestSize], .. SHA256.HashData([])]), await ReadPcrAsync(tpm, registry, pool, 2).ConfigureAwait(false), "PCR 2 must be extended with SHA-256 of the empty message.");
    }

    /// <summary>
    /// Part 2, Table 95: <c>TPM2B_EVENT</c> is bounded at 1,024 octets — a 1,025-octet event is <c>TPM_RC_SIZE</c>,
    /// and Table 132's <c>TPM_ST_SESSIONS</c> tag makes a no-sessions frame <c>TPM_RC_AUTH_MISSING</c> (Part 3, clause 5.5).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.3.7, Table 95; Part 3, clauses 5.5 and 22.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrEventHandFramedOverTheEventBoundReturnsSizeAndWithoutSessionsReturnsAuthMissing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] oversized = [0x04, 0x01, .. new byte[Tpm2bEvent.MaxSize + 1]];
        TpmRcConstants size = await SubmitPasswordCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_PCR_Event, (ushort)TpmStConstants.TPM_ST_SESSIONS, [0u], [[]], oversized).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), size, "eventData is TPM2_PCR_Event()'s sole parameter (Table 132, index 0); one over 1,024 octets must be refused with parameter-encoded TPM_RC_SIZE.");

        TpmRcConstants noSessions = await SubmitPasswordCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_PCR_Event, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, [0u], [], [0x00, 0x01, 0xAA]).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_MISSING, noSessions, "A TPM_ST_NO_SESSIONS frame must be refused with TPM_RC_AUTH_MISSING.");
    }

    /// <summary>
    /// PTP 1.07 Table 14, "Extended by TPM2_PCR_Extend, Locality = 0": N for PCR 18 (Locality 3) — the command's
    /// own locality check answers <c>TPM_RC_LOCALITY</c> before hashing anything.
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/">PC Client PTP 1.07, Table 14</see>;
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 22.3</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrEventOnTheLocality3PcrReturnsLocality()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<PcrEventResponse> result = await SubmitEventAsync(tpm, registry, pool, Locality3Pcr, RandomNumberGenerator.GetBytes(8), []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCALITY, result.ResponseCode, "PCR 18 cannot be extended at locality 0.");
    }

    /// <summary>
    /// PTP 1.07 Table 14 marks PCR 23 <c>TPM_PT_PCR_NO_INCREMENT</c>: the event extends it but the counter does
    /// not move (Part 3, clause 22.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 22.1; PC Client PTP 1.07, Table 14</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrEventOnTheApplicationPcrExtendsButLeavesTheCounter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] eventData = RandomNumberGenerator.GetBytes(20);
        uint counterBefore = await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<PcrEventResponse> result = await SubmitEventAsync(tpm, registry, pool, ApplicationPcr, eventData, []).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_PCR_Event() on PCR 23 failed: '{result.ResponseCode}'.");
        result.Value.Dispose();

        Assert.AreSequenceEqual(SHA256.HashData([.. new byte[Sha256DigestSize], .. SHA256.HashData(eventData)]), await ReadPcrAsync(tpm, registry, pool, ApplicationPcr).ConfigureAwait(false), "PCR 23 must be extended.");
        Assert.AreEqual(counterBefore, await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false), "PCR 23 is excluded from the counter.");
    }

    /// <summary>
    /// PTP 1.07, clause 4.7, item 5: the PCR's authorization value is the Empty Auth; Part 1, clause 14.7: the
    /// failure never touches the dictionary-attack protection.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 14.7; PC Client PTP 1.07, clause 4.7</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrEventWithANonEmptyPasswordReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<PcrEventResponse> refused = await SubmitEventAsync(tpm, registry, pool, 0, RandomNumberGenerator.GetBytes(8), [0x07]).ConfigureAwait(false);
        Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), refused.ResponseCode, "A non-empty PCR password must be refused with TPM_RC_BAD_AUTH on session 1.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A PCR authorization failure must not charge the dictionary-attack counter.");
        Assert.AreSequenceEqual(new byte[Sha256DigestSize], await ReadPcrAsync(tpm, registry, pool, 0).ConfigureAwait(false), "A refused event must change nothing.");
    }

    /// <summary>
    /// Asserts a returned digest list is exactly the four implemented hashes of <paramref name="message"/> in the
    /// reference's algorithm order — SHA-1, SHA-256, SHA-384, SHA-512 — each against the framework's own
    /// implementation.
    /// </summary>
    /// <param name="digests">The returned list.</param>
    /// <param name="message">The event data.</param>
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms",
        Justification = "SHA-1 is one of the TCG hash algorithms the simulator implements and returns a digest under; the framework's SHA1 is the independent oracle for that entry, not a security use.")]
    private static void AssertImplementedDigests(TpmlDigestValues digests, byte[] message)
    {
        Assert.AreEqual(4, digests.Count, "One digest per implemented hash algorithm must be returned.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA1, digests[0].HashAlg.Value);
        Assert.AreSequenceEqual(SHA1.HashData(message), digests[0].Digest.ToArray());
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, digests[1].HashAlg.Value);
        Assert.AreSequenceEqual(SHA256.HashData(message), digests[1].Digest.ToArray());
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA384, digests[2].HashAlg.Value);
        Assert.AreSequenceEqual(SHA384.HashData(message), digests[2].Digest.ToArray());
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA512, digests[3].HashAlg.Value);
        Assert.AreSequenceEqual(SHA512.HashData(message), digests[3].Digest.ToArray());
    }

    /// <summary>Submits <c>TPM2_PCR_Event()</c> through the production executor.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="pcrHandle">The raw <c>pcrHandle</c> value.</param>
    /// <param name="eventData">The event data.</param>
    /// <param name="pcrPassword">The password presented for the PCR slot.</param>
    /// <returns>The executor result; the caller owns a successful value.</returns>
    private async Task<TpmResult<PcrEventResponse>> SubmitEventAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint pcrHandle, byte[] eventData, byte[] pcrPassword)
    {
        using PcrEventInput input = PcrEventInput.Create(TpmiDhPcr.FromValue(pcrHandle), eventData, pool);
        using TpmPasswordSession pcrAuth = pcrPassword.Length == 0 ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(pcrPassword, pool);

        return await TpmCommandExecutor.ExecuteAsync<PcrEventResponse>(
            tpm, input, [pcrAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads one SHA-256 register through <c>TPM2_PCR_Read()</c>.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="pcr">The register index.</param>
    /// <returns>The register's value.</returns>
    private async Task<byte[]> ReadPcrAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint pcr)
    {
        using PcrReadInput input = PcrReadInput.ForPcrs(TpmAlgIdConstants.TPM_ALG_SHA256, [(int)pcr], pool);
        TpmResult<PcrReadResponse> result = await TpmCommandExecutor.ExecuteAsync<PcrReadResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_PCR_Read() failed: '{result.ResponseCode}'.");

        using PcrReadResponse response = result.Value;

        return response.PcrValues[0].AsReadOnlySpan().ToArray();
    }

    /// <summary>Reads <c>pcrUpdateCounter</c> through a <c>TPM2_PCR_Read()</c> of PCR 0.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The counter.</returns>
    private async Task<uint> ReadPcrUpdateCounterAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using PcrReadInput input = PcrReadInput.ForPcrs(TpmAlgIdConstants.TPM_ALG_SHA256, [0], pool);
        TpmResult<PcrReadResponse> result = await TpmCommandExecutor.ExecuteAsync<PcrReadResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_PCR_Read() failed: '{result.ResponseCode}'.");

        using PcrReadResponse response = result.Value;

        return response.PcrUpdateCounter;
    }

    /// <summary>
    /// Hand-frames an authorized command — header, the given handles, an authorization area of one
    /// <c>TPM_RS_PW</c> slot per password (none for a <c>TPM_ST_NO_SESSIONS</c> frame), then the raw parameter
    /// octets — and returns the response code.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="commandCode">The command code.</param>
    /// <param name="tag">The command tag.</param>
    /// <param name="handles">The handle area's raw values.</param>
    /// <param name="passwords">One password per <c>TPM_RS_PW</c> slot; empty for no authorization area.</param>
    /// <param name="parameters">The raw parameter area.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitPasswordCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmCcConstants commandCode, ushort tag, uint[] handles, byte[][] passwords, byte[] parameters)
    {
        int authorizationSize = 0;
        foreach(byte[] password in passwords)
        {
            authorizationSize += sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort) + password.Length;
        }

        int length = TpmHeader.HeaderSize + (handles.Length * sizeof(uint)) + (passwords.Length > 0 ? sizeof(uint) + authorizationSize : 0) + parameters.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader(tag, (uint)length, (uint)commandCode);
        header.WriteTo(ref writer);
        foreach(uint handle in handles)
        {
            writer.WriteUInt32(handle);
        }

        if(passwords.Length > 0)
        {
            writer.WriteUInt32((uint)authorizationSize);
            foreach(byte[] password in passwords)
            {
                writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
                writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
                writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
                writer.WriteTpm2b(password);
            }
        }

        writer.WriteBytes(parameters);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)).
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PCR_Read, TpmResponseCodec.PcrRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_PCR_Event, TpmResponseCodec.PcrEvent);

        return registry;
    }

    /// <summary>Creates a powered-on simulator brought to the Operational phase with <c>TPM2_Startup(CLEAR)</c>.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The simulator (the caller owns it).</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-pcr-event", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

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
        Assert.AreEqual((uint)TpmRcConstants.TPM_RC_SUCCESS, responseHeader.Code, "TPM2_Startup(CLEAR) must answer TPM_RC_SUCCESS.");

        return simulator;
    }
}
