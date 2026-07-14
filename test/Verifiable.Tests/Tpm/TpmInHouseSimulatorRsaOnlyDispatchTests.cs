using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Verifies the six ECC-backend-only admission-gate fix (<c>TPM_CC_Certify</c>, <c>TPM_CC_CertifyCreation</c>,
/// <c>TPM_CC_GetTime</c>, <c>TPM_CC_NV_Certify</c>, <c>TPM_CC_VerifySignature</c>, <c>TPM_CC_Quote</c>): an
/// RSA-ONLY simulator configuration (an RSA signing backend supplied, no ECC backend) admits and completes
/// RSA-keyed <c>TPM2_Certify()</c> and <c>TPM2_Quote()</c> end to end through the production wire path, while
/// an ECC <c>TPM2_CreatePrimary()</c> template under that same configuration still fails
/// <c>TPM_RC_COMMAND_CODE</c> — proving the per-key dispatch (not backend presence at admission) is what
/// actually decides which signer a command can use.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorRsaOnlyDispatchTests
{
    /// <summary>The RSA modulus size in bits used by these tests.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The fixed caller nonce (qualifyingData) echoed into the attestations' extraData.</summary>
    private static IMemoryOwner<byte> Nonce { get; } = RentLiteral("RSA-only dispatch nonce for the in-house TPM."u8);

    /// <summary>The SHA-256 PCR bank quoted by the RSA-only Quote path.</summary>
    private const TpmAlgIdConstants PcrBank = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The PCR indices quoted by the RSA-only Quote path.</summary>
    private static int[] PcrIndices { get; } = [0, 7];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>Releases the pooled <see cref="Nonce"/> buffer shared across every test in this class.</summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        Nonce.Dispose();
    }

    /// <summary>
    /// Verifies that an RSA-only simulator configuration admits and completes both <c>TPM2_Certify()</c> and
    /// <c>TPM2_Quote()</c> over an RSA attestation key end to end, proving the six dispatch gates now answer
    /// "any asymmetric backend" rather than "the ECC backend specifically".
    /// </summary>
    [TestMethod]
    public async Task RsaOnlySimulatorCompletesCertifyAndQuoteEndToEnd()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateRsaOnlyOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput certifyInput = CertifyInput.ForRsaSsa(subject.ObjectHandle, ak.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyResponse> certifyResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(certifyResult.IsSuccess, $"An RSA-only simulator must complete TPM2_Certify() over an RSA signer: '{certifyResult.ResponseCode}'.");
        using CertifyResponse certify = certifyResult.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSASSA, certify.SignatureAlgorithm);

        using TpmPasswordSession quoteSignAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
        using QuoteInput quoteInput = QuoteInput.ForRsaSsa(ak.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

        TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [quoteSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(quoteResult.IsSuccess, $"An RSA-only simulator must complete TPM2_Quote() over an RSA signer: '{quoteResult.ResponseCode}'.");
        using QuoteResponse quote = quoteResult.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSASSA, quote.SignatureAlgorithm);
    }

    /// <summary>
    /// Verifies that an ECC <c>TPM2_CreatePrimary()</c> template still fails <c>TPM_RC_COMMAND_CODE</c> under
    /// the same RSA-only configuration: the six-gate fix widens admission for the RSA-keyed attest commands,
    /// but object creation still requires the actual backend the requested key type needs.
    /// </summary>
    [TestMethod]
    public async Task RsaOnlySimulatorStillRejectsEccCreatePrimaryWithCommandCode()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateRsaOnlyOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput eccInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, eccInput, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_COMMAND_CODE, result.ResponseCode);
    }

    /// <summary>
    /// Creates a primary RSA-2048 signing key under the given hierarchy and returns the response (the caller
    /// owns it).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(
            hierarchy, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Null, pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA 2048, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a simulator with ONLY the RSA (framework) signing backend wired — no ECC backend at all —
    /// powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational, RSA-only simulator.</returns>
    private async Task<TpmSimulator> CreateRsaOnlyOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-rsa-only-dispatch",
            signingBackend: null,
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());
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

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Certify, TpmResponseCodec.Certify);
        _ = registry.Register(TpmCcConstants.TPM_CC_Quote, TpmResponseCodec.Quote);

        return registry;
    }

    /// <summary>
    /// Rents a buffer from <see cref="BaseMemoryPool.Shared"/> sized to <paramref name="literal"/> and copies the
    /// literal's bytes into it, so a fixed test constant is pool-backed rather than a naked array.
    /// </summary>
    /// <param name="literal">The compile-time literal bytes to copy into pooled memory.</param>
    /// <returns>A pooled owner holding exactly <paramref name="literal"/>'s bytes.</returns>
    private static IMemoryOwner<byte> RentLiteral(ReadOnlySpan<byte> literal)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(literal.Length);
        literal.CopyTo(owner.Memory.Span);

        return owner;
    }
}
