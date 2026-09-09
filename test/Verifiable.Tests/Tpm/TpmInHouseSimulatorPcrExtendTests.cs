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
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// PCR extend and reset on the in-house simulator through the production executor and codecs:
/// <c>TPM2_PCR_Extend()</c> (TPM 2.0 Library Part 3, clause 22.2), <c>TPM2_PCR_Reset()</c> (clause 22.8), the
/// PC Client reset image and the <c>TPM2_Startup()</c> rule (Part 1, clause 14.1; PTP 1.07 Tables 14 and 15),
/// and <c>pcrUpdateCounter</c> (clause 22.1) — all read back through <c>TPM2_PCR_Read()</c>, with the framework's
/// own SHA-256 as the extend oracle, independent of the simulator's digest seam.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorPcrExtendTests
{
    private const int Sha256DigestSize = 32;

    /// <summary>PTP 1.07 Table 14 marks PCR 16, 21, 22 and 23 <c>TPM_PT_PCR_NO_INCREMENT</c>, so 24 − 4 registers are counted.</summary>
    private const uint CountedPcrs = 20;

    /// <summary>Of the registers a TPM Resume re-initializes (16–23), PCR 17–20 are counted (Table 14).</summary>
    private const uint CountedPcrsResetByResume = 4;

    private const uint DebugPcr = 16;

    private const uint Locality4Pcr = 17;

    private const uint ApplicationPcr = 23;

    private const uint OutOfRangePcr = 24;

    private static TpmiAlgHash Sha256 => TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256);

    private static TpmiAlgHash Sha384 => TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA384);

    private static TpmiDhPcr NullPcr => TpmiDhPcr.FromValue((uint)TpmRh.TPM_RH_NULL);

    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// PTP 1.07 Table 15 (Startup(CLEAR), no S-HCRTM): PCR 1–16 and 23 initialize to 0, the D-RTM registers
    /// 17–22 to −1 (all ones); Part 4 <c>PCRStartup</c> clears <c>pcrUpdateCounter</c> at a TPM Reset and then
    /// counts every register it initializes, so a fresh TPM reports the number of counted registers — 20 by
    /// Table 14's <c>TPM_PT_PCR_NO_INCREMENT</c> column.
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/">PC Client PTP 1.07, Table 15; Table 14</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrReadAtResetShowsTheTable15ImageAndTheCounterAtTheCountedRegisterCount()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] allOnes = new byte[Sha256DigestSize];
        allOnes.AsSpan().Fill(0xFF);

        Assert.AreSequenceEqual(new byte[Sha256DigestSize], await ReadPcrAsync(tpm, registry, pool, 0).ConfigureAwait(false), "PCR 0 initializes to the locality-0 indicator, all zeros.");
        Assert.AreSequenceEqual(new byte[Sha256DigestSize], await ReadPcrAsync(tpm, registry, pool, DebugPcr).ConfigureAwait(false), "PCR 16 initializes to 0 (Table 15).");
        Assert.AreSequenceEqual(allOnes, await ReadPcrAsync(tpm, registry, pool, Locality4Pcr).ConfigureAwait(false), "PCR 17 initializes to -1, all ones (Table 15).");
        Assert.AreSequenceEqual(allOnes, await ReadPcrAsync(tpm, registry, pool, 22).ConfigureAwait(false), "PCR 22 initializes to -1, all ones (Table 15).");
        Assert.AreSequenceEqual(new byte[Sha256DigestSize], await ReadPcrAsync(tpm, registry, pool, ApplicationPcr).ConfigureAwait(false), "PCR 23 initializes to 0 (Table 15).");
        Assert.AreEqual(CountedPcrs, await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false), "A TPM Reset clears the counter and then counts every register it initializes.");
    }

    /// <summary>
    /// Clause 22.2.1: "PCR.digestnew[pcrNum][alg] = Halg(PCR.digestold[pcrNum][alg] ‖ data[alg].buffer)" — an
    /// extend of PCR 0 reads back as SHA-256(0³² ‖ digest); clause 22.1: the counter moves once for the one
    /// bank extended.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 22.1 and 22.2.1; Part 1, clause 14.2, equation 13</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrExtendOnPcrZeroReadsBackAsSha256OfOldAndDigestAndMovesTheCounterOnce()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] digest = RandomNumberGenerator.GetBytes(Sha256DigestSize);
        byte[] expected = SHA256.HashData([.. new byte[Sha256DigestSize], .. digest]);
        uint counterBefore = await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<PcrExtendResponse> result = await ExtendSha256Async(tpm, registry, pool, 0, digest, []).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_PCR_Extend() failed: '{result.ResponseCode}'.");

        Assert.AreSequenceEqual(expected, await ReadPcrAsync(tpm, registry, pool, 0).ConfigureAwait(false), "PCR 0 must read back as SHA-256(old ‖ digest).");
        Assert.AreEqual(counterBefore + 1u, await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false), "One extend of a counted register moves pcrUpdateCounter once.");
    }

    /// <summary>
    /// Clause 22.2.1: "the semantics of this command allow multiple extends to a single PCR bank" — two SHA-256
    /// entries fold in list order, and each extend performed moves the counter (Part 4 <c>PCRExtend</c> calls
    /// <c>PCRChanged</c> per bank extended).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 22.1 and 22.2.1</see>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of both TPMT_HA entries transfers to the adopted list, then to the input, whose using declaration releases them.")]
    public async Task PcrExtendWithTwoSha256EntriesFoldsThemInOrderAndMovesTheCounterTwice()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] first = RandomNumberGenerator.GetBytes(Sha256DigestSize);
        byte[] second = RandomNumberGenerator.GetBytes(Sha256DigestSize);
        byte[] afterFirst = SHA256.HashData([.. new byte[Sha256DigestSize], .. first]);
        byte[] expected = SHA256.HashData([.. afterFirst, .. second]);
        uint counterBefore = await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmlDigestValues digests = TpmlDigestValues.Adopt([TpmtHa.Create(Sha256, first, pool), TpmtHa.Create(Sha256, second, pool)]);
        using PcrExtendInput input = PcrExtendInput.Create(TpmiDhPcr.FromValue(3), digests);
        using TpmPasswordSession pcrAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<PcrExtendResponse> result = await TpmCommandExecutor.ExecuteAsync<PcrExtendResponse>(
            tpm, input, [pcrAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_PCR_Extend() failed: '{result.ResponseCode}'.");

        Assert.AreSequenceEqual(expected, await ReadPcrAsync(tpm, registry, pool, 3).ConfigureAwait(false), "Two entries must fold in list order.");
        Assert.AreEqual(counterBefore + 2u, await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false), "Two extends performed move pcrUpdateCounter twice.");
    }

    /// <summary>
    /// Clause 22.2.1: "If a digest is present and the PCR in that bank is not implemented, the digest value is
    /// not used" — a SHA-384 entry (an implemented hash with no bank) is accepted and changes nothing.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 22.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrExtendWithOnlyASha384EntryIsAcceptedAndLeavesTheRegisterAndTheCounterUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] before = await ReadPcrAsync(tpm, registry, pool, 5).ConfigureAwait(false);
        uint counterBefore = await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false);

        using PcrExtendInput input = PcrExtendInput.Create(TpmiDhPcr.FromValue(5), Sha384, RandomNumberGenerator.GetBytes(48), pool);
        using TpmPasswordSession pcrAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<PcrExtendResponse> result = await TpmCommandExecutor.ExecuteAsync<PcrExtendResponse>(
            tpm, input, [pcrAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"An entry for an unimplemented bank must be accepted: '{result.ResponseCode}'.");

        Assert.AreSequenceEqual(before, await ReadPcrAsync(tpm, registry, pool, 5).ConfigureAwait(false), "The register must be unchanged.");
        Assert.AreEqual(counterBefore, await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false), "No extend was performed, so the counter must not move.");
    }

    /// <summary>
    /// Clause 22.2.1: "If the TPM unmarshals the hashAlg of a list entry and the unmarshaled value is not a hash
    /// algorithm implemented on the TPM, the TPM shall return TPM_RC_HASH" — an SM3-256 entry (a TCG hash the
    /// simulator does not implement) and a <c>TPM_ALG_NULL</c> entry (no <c>+</c> in Table 127) are both refused.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 22.2.1; Part 2, clause 10.8.6, Table 127</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrExtendWithAnUnimplementedOrNullHashEntryHandFramedReturnsHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] sm3List = [0x00, 0x00, 0x00, 0x01, 0x00, 0x12, .. new byte[Sha256DigestSize]];
        TpmRcConstants sm3 = await SubmitPasswordCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_PCR_Extend, (ushort)TpmStConstants.TPM_ST_SESSIONS, [0u], [[]], sm3List).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 0), sm3,
            "Table 130: digests is TPM2_PCR_Extend()'s sole parameter (index 0); an SM3-256 entry must be refused with TPM_RC_HASH there.");

        byte[] nullList = [0x00, 0x00, 0x00, 0x01, 0x00, 0x10];
        TpmRcConstants nullAlg = await SubmitPasswordCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_PCR_Extend, (ushort)TpmStConstants.TPM_ST_SESSIONS, [0u], [[]], nullList).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 0), nullAlg,
            "Table 130: digests is TPM2_PCR_Extend()'s sole parameter (index 0); a TPM_ALG_NULL entry must be refused with TPM_RC_HASH there.");
    }

    /// <summary>
    /// Part 2, Table 127: <c>digests[count]{:HASH_COUNT}</c> is <c>#TPM_RC_SIZE</c> — the simulator implements
    /// four hash algorithms, so a fifth entry is refused before anything is extended.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.8.6, Table 127</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrExtendWithFiveEntriesHandFramedReturnsSizeAndLeavesTheRegister()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] entry = [0x00, 0x0B, .. new byte[Sha256DigestSize]];
        byte[] fiveEntries = [0x00, 0x00, 0x00, 0x05, .. entry, .. entry, .. entry, .. entry, .. entry];

        TpmRcConstants code = await SubmitPasswordCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_PCR_Extend, (ushort)TpmStConstants.TPM_ST_SESSIONS, [0u], [[]], fiveEntries).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), code,
            "Table 130: digests is TPM2_PCR_Extend()'s sole parameter (index 0); a list longer than the implemented hash count must be refused with TPM_RC_SIZE there.");
        Assert.AreSequenceEqual(new byte[Sha256DigestSize], await ReadPcrAsync(tpm, registry, pool, 0).ConfigureAwait(false), "A refused list must extend nothing.");
    }

    /// <summary>
    /// Clause 22.2.1: "The pcrHandle parameter is allowed to reference TPM_RH_NULL. If so, the input parameters
    /// are processed but no action is taken by the TPM."
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 22.2.2, Table 130</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrExtendWithTheNullHandleSucceedsAndChangesNothing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint counterBefore = await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<PcrExtendResponse> result = await ExtendSha256Async(tpm, registry, pool, (uint)TpmRh.TPM_RH_NULL, RandomNumberGenerator.GetBytes(Sha256DigestSize), []).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM_RH_NULL must be accepted: '{result.ResponseCode}'.");

        Assert.AreEqual(counterBefore, await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false), "No register changed, so the counter must not move.");
    }

    /// <summary>
    /// PTP 1.07 Table 14, "Extended by TPM2_PCR_Extend, Locality = 0": N for the D-RTM registers 17–22 — the
    /// reference's <c>PCRIsExtendAllowed</c> answers <c>TPM_RC_LOCALITY</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/">PC Client PTP 1.07, Table 14</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrExtendOnTheLocality4PcrReturnsLocality()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<PcrExtendResponse> result = await ExtendSha256Async(tpm, registry, pool, Locality4Pcr, RandomNumberGenerator.GetBytes(Sha256DigestSize), []).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCALITY, result.ResponseCode, "PCR 17 cannot be extended at locality 0.");
    }

    /// <summary>
    /// Part 2, Table 53: a <c>TPMI_DH_PCR</c> outside <c>PCR_FIRST..PCR_LAST</c> is <c>#TPM_RC_VALUE</c> — PCR 24 on
    /// a 24-register bank.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.7, Table 53; Part 3, clause 22.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrExtendOnPcr24ReturnsValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<PcrExtendResponse> result = await ExtendSha256Async(tpm, registry, pool, OutOfRangePcr, RandomNumberGenerator.GetBytes(Sha256DigestSize), []).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode, "pcrHandle is TPM2_PCR_Extend()'s sole handle (Table 130, index 0); a handle past PCR_LAST must be refused with handle-encoded TPM_RC_VALUE.");
    }

    /// <summary>
    /// PTP 1.07, clause 4.7, item 5: every PCR's authorization value is the Empty Auth; Part 1, clause 14.7: a
    /// PCR authorization failure never touches the dictionary-attack protection ("PCR have an implied noDA
    /// attribute SET").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 14.7 and 14.7.1; PC Client PTP 1.07, clause 4.7</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrExtendWithANonEmptyPasswordReturnsBadAuthUnchargedAndLeavesTheRegister()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<PcrExtendResponse> refused = await ExtendSha256Async(tpm, registry, pool, 0, RandomNumberGenerator.GetBytes(Sha256DigestSize), [0x01]).ConfigureAwait(false);
        Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), refused.ResponseCode, "A non-empty PCR password must be refused with TPM_RC_BAD_AUTH on session 1.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A PCR authorization failure must not charge the dictionary-attack counter.");
        Assert.AreSequenceEqual(new byte[Sha256DigestSize], await ReadPcrAsync(tpm, registry, pool, 0).ConfigureAwait(false), "A refused extend must change nothing.");
    }

    /// <summary>
    /// PTP 1.07 Table 14 marks PCR 16 <c>TPM_PT_PCR_NO_INCREMENT</c>: it extends, but the counter does not move
    /// (Part 3, clause 22.1: "unless the platform-specific specification explicitly excludes the PCR from being
    /// counted").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 22.1; Part 1, clause 14.9; PC Client PTP 1.07, Table 14</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrExtendOnTheDebugPcrExtendsButLeavesTheCounter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] digest = RandomNumberGenerator.GetBytes(Sha256DigestSize);
        uint counterBefore = await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<PcrExtendResponse> result = await ExtendSha256Async(tpm, registry, pool, DebugPcr, digest, []).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_PCR_Extend() on PCR 16 failed: '{result.ResponseCode}'.");

        Assert.AreSequenceEqual(SHA256.HashData([.. new byte[Sha256DigestSize], .. digest]), await ReadPcrAsync(tpm, registry, pool, DebugPcr).ConfigureAwait(false), "PCR 16 must be extended.");
        Assert.AreEqual(counterBefore, await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false), "PCR 16 is excluded from the counter.");
    }

    /// <summary>
    /// Table 130: the tag is <c>TPM_ST_SESSIONS</c> (an authorized handle) — <c>TPM_ST_NO_SESSIONS</c> is
    /// <c>TPM_RC_AUTH_MISSING</c> (Part 3, clause 5.5); an octet after the final parameter is <c>TPM_RC_SIZE</c>
    /// (clause 5.2).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.2 and 5.5; Table 130</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrExtendFramedWithoutSessionsReturnsAuthMissingAndATrailingOctetReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] list = [0x00, 0x00, 0x00, 0x01, 0x00, 0x0B, .. new byte[Sha256DigestSize]];

        TpmRcConstants noSessions = await SubmitPasswordCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_PCR_Extend, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, [0u], [], list).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_MISSING, noSessions, "A TPM_ST_NO_SESSIONS frame must be refused with TPM_RC_AUTH_MISSING.");

        TpmRcConstants trailing = await SubmitPasswordCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_PCR_Extend, (ushort)TpmStConstants.TPM_ST_SESSIONS, [0u], [[]], [.. list, 0x00]).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, trailing, "An octet after the final parameter must be refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// Part 1, clause 14.1: "All platform configuration registers (PCR) are reset to their default initial
    /// condition on TPM Reset and TPM Restart"; Part 4 <c>PCRStartup</c>: a TPM Reset clears
    /// <c>pcrUpdateCounter</c> and then counts each register initialized, a TPM Restart only counts them.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 14.1; Part 3, clause 22.1; Part 4, PCRStartup</see>.
    /// </summary>
    [TestMethod]
    public async Task TpmResetAndTpmRestartAfterAnExtendRestoreTheResetImageAndCountTheRegistersInitialized()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<PcrExtendResponse> extend = await ExtendSha256Async(tpm, registry, pool, 0, RandomNumberGenerator.GetBytes(Sha256DigestSize), []).ConfigureAwait(false);
        Assert.IsTrue(extend.IsSuccess, $"TPM2_PCR_Extend() failed: '{extend.ResponseCode}'.");
        uint counterAfterExtend = await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false);

        await IssueShutdownAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        Assert.AreSequenceEqual(new byte[Sha256DigestSize], await ReadPcrAsync(tpm, registry, pool, 0).ConfigureAwait(false), "A TPM Restart returns PCR 0 to its reset image.");
        Assert.AreEqual(counterAfterExtend + CountedPcrs, await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false), "A TPM Restart counts every counted register it initializes without clearing the counter.");

        TpmResult<PcrExtendResponse> extendAgain = await ExtendSha256Async(tpm, registry, pool, 0, RandomNumberGenerator.GetBytes(Sha256DigestSize), []).ConfigureAwait(false);
        Assert.IsTrue(extendAgain.IsSuccess, $"TPM2_PCR_Extend() after the restart failed: '{extendAgain.ResponseCode}'.");

        await IssueShutdownAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        Assert.AreSequenceEqual(new byte[Sha256DigestSize], await ReadPcrAsync(tpm, registry, pool, 0).ConfigureAwait(false), "A TPM Reset returns PCR 0 to its reset image.");
        Assert.AreEqual(CountedPcrs, await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false), "A TPM Reset clears the counter and then counts every counted register it initializes.");
    }

    /// <summary>
    /// Part 1, clause 14.1: "Some PCR may be designated as being preserved by TPM Resume" — PTP 1.07 Table 14's
    /// <c>TPM_PT_PCR_SAVE</c> column preserves PCR 0–15 and re-initializes 16–23; Part 4 <c>PCRStartup</c> counts
    /// each re-initialized counted register (17–20).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 14.1; PC Client PTP 1.07, Table 14; Part 4, PCRStartup</see>.
    /// </summary>
    [TestMethod]
    public async Task TpmResumePreservesTheStaticPcrsReinitializesTheRestAndCountsTheCountedOnes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<PcrExtendResponse> extendStatic = await ExtendSha256Async(tpm, registry, pool, 0, RandomNumberGenerator.GetBytes(Sha256DigestSize), []).ConfigureAwait(false);
        Assert.IsTrue(extendStatic.IsSuccess, $"TPM2_PCR_Extend() on PCR 0 failed: '{extendStatic.ResponseCode}'.");
        TpmResult<PcrExtendResponse> extendDebug = await ExtendSha256Async(tpm, registry, pool, DebugPcr, RandomNumberGenerator.GetBytes(Sha256DigestSize), []).ConfigureAwait(false);
        Assert.IsTrue(extendDebug.IsSuccess, $"TPM2_PCR_Extend() on PCR 16 failed: '{extendDebug.ResponseCode}'.");

        byte[] staticValue = await ReadPcrAsync(tpm, registry, pool, 0).ConfigureAwait(false);
        uint counterBefore = await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false);

        await IssueShutdownAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE).ConfigureAwait(false);

        byte[] allOnes = new byte[Sha256DigestSize];
        allOnes.AsSpan().Fill(0xFF);
        Assert.AreSequenceEqual(staticValue, await ReadPcrAsync(tpm, registry, pool, 0).ConfigureAwait(false), "A TPM Resume preserves PCR 0.");
        Assert.AreSequenceEqual(new byte[Sha256DigestSize], await ReadPcrAsync(tpm, registry, pool, DebugPcr).ConfigureAwait(false), "A TPM Resume re-initializes PCR 16.");
        Assert.AreSequenceEqual(allOnes, await ReadPcrAsync(tpm, registry, pool, Locality4Pcr).ConfigureAwait(false), "A TPM Resume re-initializes PCR 17 to all ones.");
        Assert.AreEqual(counterBefore + CountedPcrsResetByResume, await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false), "A TPM Resume counts the four counted registers it re-initializes.");
    }

    /// <summary>
    /// Clause 22.8.1: a resettable PCR (PCR 16 at locality 0, PTP 1.07 Table 14) is "set ... in all banks to
    /// zero"; PCR 16 is excluded from the counter, so the reset does not move it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 22.1 and 22.8.1; PC Client PTP 1.07, Tables 14 and 15</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrResetOnTheDebugPcrAfterAnExtendReadsZerosAndLeavesTheCounter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<PcrExtendResponse> extend = await ExtendSha256Async(tpm, registry, pool, DebugPcr, RandomNumberGenerator.GetBytes(Sha256DigestSize), []).ConfigureAwait(false);
        Assert.IsTrue(extend.IsSuccess, $"TPM2_PCR_Extend() on PCR 16 failed: '{extend.ResponseCode}'.");
        Assert.IsFalse(new ReadOnlySpan<byte>(await ReadPcrAsync(tpm, registry, pool, DebugPcr).ConfigureAwait(false)).SequenceEqual(new byte[Sha256DigestSize]), "PCR 16 must be non-zero before the reset, or the reset proves nothing.");
        uint counterBefore = await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<PcrResetResponse> reset = await ResetAsync(tpm, registry, pool, DebugPcr, []).ConfigureAwait(false);
        Assert.IsTrue(reset.IsSuccess, $"TPM2_PCR_Reset() on PCR 16 failed: '{reset.ResponseCode}'.");

        Assert.AreSequenceEqual(new byte[Sha256DigestSize], await ReadPcrAsync(tpm, registry, pool, DebugPcr).ConfigureAwait(false), "A reset register reads all zeros.");
        Assert.AreEqual(counterBefore, await ReadPcrUpdateCounterAsync(tpm, registry, pool).ConfigureAwait(false), "PCR 16 is excluded from the counter, so its reset must not move it.");
    }

    /// <summary>
    /// Clause 22.8.1: "If pcrHandle references a PCR that cannot be reset, the TPM shall return TPM_RC_LOCALITY"
    /// — a static RTM register (PCR 0) and a D-RTM register (PCR 17) at locality 0 (PTP 1.07 Table 14).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 22.8.1; PC Client PTP 1.07, Table 14</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrResetOnAStaticPcrAndOnTheLocality4PcrReturnsLocality()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<PcrResetResponse> staticPcr = await ResetAsync(tpm, registry, pool, 0, []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCALITY, staticPcr.ResponseCode, "PCR 0 cannot be reset by TPM2_PCR_Reset() at any locality.");

        TpmResult<PcrResetResponse> dynamicPcr = await ResetAsync(tpm, registry, pool, Locality4Pcr, []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCALITY, dynamicPcr.ResponseCode, "PCR 17 cannot be reset at locality 0.");
    }

    /// <summary>
    /// Table 142 types <c>pcrHandle</c> as <c>TPMI_DH_PCR</c> without <c>+</c>, so <c>TPM_RH_NULL</c> fails the
    /// unmarshal with <c>TPM_RC_VALUE</c>, as does PCR 24; and clause 22.8.1's other resettable register, PCR 23,
    /// resets to zeros after an extend.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 22.8, Table 142; Part 2, clause 9.7, Table 53</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrResetWithTheNullHandleOrPcr24ReturnsValueAndTheApplicationPcrResets()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<PcrResetResponse> nullHandle = await ResetAsync(tpm, registry, pool, (uint)TpmRh.TPM_RH_NULL, []).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), nullHandle.ResponseCode, "pcrHandle is TPM2_PCR_Reset()'s sole handle (Table 142, index 0); TPM_RH_NULL is not admitted by TPMI_DH_PCR without the + form, refused handle-encoded TPM_RC_VALUE.");

        TpmResult<PcrResetResponse> outOfRange = await ResetAsync(tpm, registry, pool, OutOfRangePcr, []).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), outOfRange.ResponseCode, "pcrHandle is TPM2_PCR_Reset()'s sole handle (Table 142, index 0); PCR 24 is past PCR_LAST, refused handle-encoded TPM_RC_VALUE.");

        TpmResult<PcrExtendResponse> extend = await ExtendSha256Async(tpm, registry, pool, ApplicationPcr, RandomNumberGenerator.GetBytes(Sha256DigestSize), []).ConfigureAwait(false);
        Assert.IsTrue(extend.IsSuccess, $"TPM2_PCR_Extend() on PCR 23 failed: '{extend.ResponseCode}'.");
        TpmResult<PcrResetResponse> application = await ResetAsync(tpm, registry, pool, ApplicationPcr, []).ConfigureAwait(false);
        Assert.IsTrue(application.IsSuccess, $"TPM2_PCR_Reset() on PCR 23 failed: '{application.ResponseCode}'.");
        Assert.AreSequenceEqual(new byte[Sha256DigestSize], await ReadPcrAsync(tpm, registry, pool, ApplicationPcr).ConfigureAwait(false), "PCR 23 reads zeros after its reset.");
    }

    /// <summary>
    /// Table 142 has no parameters, so an octet after the authorization area is <c>TPM_RC_SIZE</c> (clause 5.2);
    /// a non-empty PCR password is refused uncharged (Part 1, clause 14.7).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.2 and 22.8, Table 142; Part 1, clause 14.7</see>.
    /// </summary>
    [TestMethod]
    public async Task PcrResetWithATrailingOctetReturnsSizeAndWithANonEmptyPasswordReturnsBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmRcConstants trailing = await SubmitPasswordCommandAsync(
            simulator, pool, TpmCcConstants.TPM_CC_PCR_Reset, (ushort)TpmStConstants.TPM_ST_SESSIONS, [DebugPcr], [[]], [0x00]).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, trailing, "An octet after the authorization area must be refused with TPM_RC_SIZE.");

        TpmResult<PcrResetResponse> refused = await ResetAsync(tpm, registry, pool, DebugPcr, [0x42]).ConfigureAwait(false);
        Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), refused.ResponseCode, "A non-empty PCR password must be refused with TPM_RC_BAD_AUTH on session 1.");
    }

    /// <summary>
    /// Part 1, clause 14.6.2: a quote attests the PCR values as they are — after an extend, the quote's
    /// <c>pcrDigest</c> is the composite over the EXTENDED registers a <c>TPM2_PCR_Read()</c> returns.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 14.6.2; Part 3, clauses 18.4 and 22.2</see>.
    /// </summary>
    [TestMethod]
    public async Task QuoteAfterAnExtendAttestsTheExtendedRegisters()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<PcrExtendResponse> extend = await ExtendSha256Async(tpm, registry, pool, 7, RandomNumberGenerator.GetBytes(Sha256DigestSize), []).ConfigureAwait(false);
        Assert.IsTrue(extend.IsSuccess, $"TPM2_PCR_Extend() on PCR 7 failed: '{extend.ResponseCode}'.");

        byte[] pcr0 = await ReadPcrAsync(tpm, registry, pool, 0).ConfigureAwait(false);
        byte[] pcr7 = await ReadPcrAsync(tpm, registry, pool, 7).ConfigureAwait(false);
        byte[] expectedComposite = SHA256.HashData([.. pcr0, .. pcr7]);

        using CreatePrimaryInput akInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> akResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, akInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(akResult.IsSuccess, $"CreatePrimary (ECC P-256 AK) failed: '{akResult.ResponseCode}'.");
        using CreatePrimaryResponse ak = akResult.Value;

        using TpmlPcrSelection selection = TpmlPcrSelection.Create(TpmAlgIdConstants.TPM_ALG_SHA256, [0, 7], pool);
        using QuoteInput quoteInput = QuoteInput.ForEcdsa(ak.ObjectHandle, RandomNumberGenerator.GetBytes(16), TpmAlgIdConstants.TPM_ALG_SHA256, selection, pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(quoteResult.IsSuccess, $"TPM2_Quote() failed: '{quoteResult.ResponseCode}'.");

        using QuoteResponse quote = quoteResult.Value;
        Assert.AreSequenceEqual(expectedComposite, quote.Quoted.AttestationData.Attested.Quote!.PcrDigest.AsReadOnlySpan().ToArray(), "The quote's pcrDigest must be the composite over the extended registers.");
    }

    /// <summary>Submits a one-entry SHA-256 <c>TPM2_PCR_Extend()</c> through the production executor.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="pcrHandle">The raw <c>pcrHandle</c> value.</param>
    /// <param name="digest">The SHA-256 digest to extend.</param>
    /// <param name="pcrPassword">The password presented for the PCR slot.</param>
    /// <returns>The executor result.</returns>
    private async Task<TpmResult<PcrExtendResponse>> ExtendSha256Async(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint pcrHandle, byte[] digest, byte[] pcrPassword)
    {
        using PcrExtendInput input = PcrExtendInput.Create(TpmiDhPcr.FromValue(pcrHandle), Sha256, digest, pool);
        using TpmPasswordSession pcrAuth = pcrPassword.Length == 0 ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(pcrPassword, pool);

        return await TpmCommandExecutor.ExecuteAsync<PcrExtendResponse>(
            tpm, input, [pcrAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Submits <c>TPM2_PCR_Reset()</c> through the production executor.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="pcrHandle">The raw <c>pcrHandle</c> value.</param>
    /// <param name="pcrPassword">The password presented for the PCR slot.</param>
    /// <returns>The executor result.</returns>
    private async Task<TpmResult<PcrResetResponse>> ResetAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint pcrHandle, byte[] pcrPassword)
    {
        var input = new PcrResetInput(TpmiDhPcr.FromValue(pcrHandle));
        using TpmPasswordSession pcrAuth = pcrPassword.Length == 0 ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(pcrPassword, pool);

        return await TpmCommandExecutor.ExecuteAsync<PcrResetResponse>(
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
        Assert.AreEqual(1, response.PcrValues.Count, "One register was selected.");

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
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_PCR_Read, TpmResponseCodec.PcrRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_PCR_Extend, TpmResponseCodec.PcrExtend);
        _ = registry.Register(TpmCcConstants.TPM_CC_PCR_Reset, TpmResponseCodec.PcrReset);
        _ = registry.Register(TpmCcConstants.TPM_CC_Quote, TpmResponseCodec.Quote);

        return registry;
    }

    /// <summary>Creates a powered-on simulator brought to the Operational phase with <c>TPM2_Startup(CLEAR)</c>.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The simulator (the caller owns it).</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-pcr-extend",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Submits <c>TPM2_Startup()</c> of the given type to a powered-on simulator, asserting success.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="startupType">The startup type.</param>
    /// <returns>A task that completes when the TPM is Operational.</returns>
    private async Task IssueStartupAsync(TpmSimulator simulator, BaseMemoryPool pool, TpmSuConstants startupType)
    {
        var input = new StartupInput(startupType);
        await SubmitUnauthorizedAsync(simulator, pool, input, $"TPM2_Startup({startupType})").ConfigureAwait(false);
    }

    /// <summary>Submits <c>TPM2_Shutdown()</c> of the given type, asserting success.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="shutdownType">The shutdown type.</param>
    /// <returns>A task that completes when the shutdown has been recorded.</returns>
    private async Task IssueShutdownAsync(TpmSimulator simulator, BaseMemoryPool pool, TpmSuConstants shutdownType)
    {
        var input = new ShutdownInput(shutdownType);
        await SubmitUnauthorizedAsync(simulator, pool, input, $"TPM2_Shutdown({shutdownType})").ConfigureAwait(false);
    }

    /// <summary>Frames and submits an unauthorized, parameter-only command directly, asserting <c>TPM_RC_SUCCESS</c>.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The command input.</param>
    /// <param name="commandName">The command's name for the assertion messages.</param>
    /// <returns>A task that completes when the command has succeeded.</returns>
    private async Task SubmitUnauthorizedAsync(TpmSimulator simulator, BaseMemoryPool pool, ITpmCommandInput input, string commandName)
    {
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"{commandName} must succeed at the transport level.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual((uint)TpmRcConstants.TPM_RC_SUCCESS, responseHeader.Code, $"{commandName} must answer TPM_RC_SUCCESS.");
    }
}
