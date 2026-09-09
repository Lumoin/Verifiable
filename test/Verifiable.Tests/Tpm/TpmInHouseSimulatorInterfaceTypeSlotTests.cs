using System.Buffers;
using System.Threading.Tasks;
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
/// Proves that a command whose wire frame carries a value OUTSIDE the admitted set of the interface type its
/// slot is declared with (TPM 2.0 Library Part 2, clause 9's <c>TPMI_*</c> types) is answered with the
/// transition's own response code rather than an exception escaping the command path: the simulator's parsers
/// carry such a value as read and let the consuming transition name the refusal, which is what keeps a
/// malformed-but-well-framed command a response on the wire instead of a fault.
/// </summary>
/// <remarks>
/// Three representative slots are covered, one per interface-type family: an object handle
/// (<c>TPMI_DH_OBJECT</c>), an NV Index handle (<c>TPMI_RH_NV_INDEX</c>), and a hash-algorithm selector
/// (<c>TPMI_ALG_HASH</c>). Each drives a value the type's own admitted set excludes, and each asserts both that
/// a response code came back at all and that it is the code the command's own clause names.
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorInterfaceTypeSlotTests
{
    /// <summary>The caller nonce the quote here echoes; its content is irrelevant to the refusal under test.</summary>
    private static byte[] QualifyingData { get; } = "Interface-type slot refusal proof nonce."u8.ToArray();

    /// <summary>The PCRs the quote selects; a non-empty selection keeps the frame a well-formed command.</summary>
    private static int[] PcrIndices { get; } = [0, 7];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A <c>TPM2_Quote()</c> whose <c>signHandle</c> names the permanent handle <c>TPM_RH_OWNER</c> — a value
    /// <c>TPMI_DH_OBJECT</c> does not admit, since that type is constrained to transient and persistent object
    /// handles (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 2, clause 9.3, Table 49) — is answered with <c>TPM_RC_HANDLE</c>, the
    /// code Part 3, clause 18.4's handle resolution names, and never with an exception leaving the command
    /// path.
    /// </summary>
    [TestMethod]
    public async Task QuoteWithAPermanentHandleInTheObjectSlotAnswersHandleRatherThanFaulting()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-interface-slot-quote").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(TpmAlgIdConstants.TPM_ALG_SHA256, PcrIndices, trackingPool.Pool);
        using QuoteInput quoteInput = QuoteInput.ForEcdsa(
            TpmiDhObject.FromValue((uint)TpmRh.TPM_RH_OWNER), QualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, trackingPool.Pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);

        TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [signAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }

        Assert.IsTrue(result.IsTpmError, "A permanent handle in the signHandle slot must be refused with a response code.");
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "A signHandle that resolves to no loaded object designates signHandle, handle 1 of Table 101 (TPM 2.0 Library Part 3, clause 18.4).");
    }

    /// <summary>
    /// A <c>TPM2_NV_DefineSpace()</c> whose <c>publicInfo.nvIndex</c> carries a handle whose most-significant
    /// octet is not <c>TPM_HT_NV_INDEX</c> — a value <c>TPMI_RH_NV_INDEX</c> does not admit (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.25, Table 71, over the handle ranges of clause 7.2) — is answered
    /// with <c>TPM_RC_HANDLE</c> rather than an exception leaving the command path.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceWithANonNvIndexHandleAnswersHandleRatherThanFaulting()
    {
        const uint NonNvIndexHandle = 0x0200_0010;

        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-interface-slot-nvdefine").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using Tpm2bAuth indexAuth = Tpm2bAuth.Create("index-auth"u8, trackingPool.Pool);
        using Tpm2bDigest authPolicy = Tpm2bDigest.Create(default, trackingPool.Pool);
        using var publicInfo = new TpmsNvPublic(
            NonNvIndexHandle,
            TpmAlgIdConstants.TPM_ALG_SHA256,
            TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_OWNERREAD,
            authPolicy,
            dataSize: 8);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, indexAuth, publicInfo);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, defineInput, [ownerAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTpmError, "An nvIndex outside the NV Index range must be refused with a response code.");
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), result.ResponseCode,
            "publicInfo, parameter 2 of Table 245, carrying a handle whose most-significant octet is not TPM_HT_NV_INDEX is parameter-encoded TPM_RC_HANDLE (TPM 2.0 Library Part 2, clause 7.2).");
    }

    /// <summary>
    /// A <c>TPM2_StartAuthSession()</c> whose <c>authHash</c> names <c>TPM_ALG_RSA</c> — an asymmetric algorithm
    /// that <c>TPMI_ALG_HASH</c> does not admit, since that type is constrained to the hash algorithms the TPM
    /// implements (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 2, clause 9.31, Table 77) — is answered with <c>TPM_RC_HASH</c>, the
    /// code that table names, rather than an exception leaving the command path.
    /// </summary>
    [TestMethod]
    public async Task StartAuthSessionWithANonHashAuthHashAnswersHashRatherThanFaulting()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-interface-slot-startauthsession").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        var sessionInput = new StartAuthSessionInput
        {
            TpmKey = (uint)TpmRh.TPM_RH_NULL,
            Bind = (uint)TpmRh.TPM_RH_NULL,
            SessionType = TpmSeConstants.TPM_SE_HMAC,
            AuthHash = TpmAlgIdConstants.TPM_ALG_RSA
        };

        TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, sessionInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }

        Assert.IsTrue(result.IsTpmError, "A non-hash authHash must be refused with a response code.");
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 4), result.ResponseCode,
            "authHash, parameter 5 of Table 14, naming an algorithm outside TPMI_ALG_HASH's admitted set is parameter-encoded TPM_RC_HASH (TPM 2.0 Library Part 2, clause 9.31, Table 77).");
    }

    /// <summary>
    /// Creates a simulator with the signing backends wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tpmId">The simulator identity, unique per test so no trace or meter crosses tests.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, string tpmId)
    {
        var simulator = new TpmSimulator(
            tpmId,
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
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
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
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

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_Quote, TpmResponseCodec.Quote);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);

        return registry;
    }
}
