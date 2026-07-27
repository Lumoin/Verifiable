using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Verifies the six ECC-backend-only admission-gate fix (<c>TPM_CC_Certify</c>, <c>TPM_CC_CertifyCreation</c>,
/// <c>TPM_CC_GetTime</c>, <c>TPM_CC_NV_Certify</c>, <c>TPM_CC_VerifySignature</c>, <c>TPM_CC_Quote</c>) and its
/// RSA-OAEP-wave sibling, the <c>TPM_CC_MakeCredential</c>/<c>TPM_CC_ActivateCredential</c> gate widening
/// (R-10): an RSA-ONLY simulator configuration (an RSA signing backend supplied, no ECC backend) admits and
/// completes RSA-keyed <c>TPM2_Certify()</c>, <c>TPM2_Quote()</c>, and the standard RSA endorsement key's
/// <c>TPM2_MakeCredential()</c>/<c>TPM2_ActivateCredential()</c> round trip end to end through the production
/// wire path, while an ECC <c>TPM2_CreatePrimary()</c> template under that same configuration still fails
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

    /// <summary>The policy session hash algorithm used by the standard RSA EK's PolicyA path.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The secret credential wrapped and recovered by the RSA MakeCredential/ActivateCredential test.</summary>
    private static IMemoryOwner<byte> CredentialSecret { get; } =
        RentLiteral([0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF]);

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>Releases the pooled buffers shared across every test in this class.</summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        Nonce.Dispose();
        CredentialSecret.Dispose();
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
    /// Verifies that an RSA-only simulator configuration completes the standard RSA endorsement key's
    /// <c>TPM2_MakeCredential()</c> / <c>TPM2_ActivateCredential()</c> round trip end to end (R-10: the two
    /// gates widen the same way the six attest-command gates did in wave 6), recovering exactly the credential
    /// that was wrapped, with no ECC backend supplied at all.
    /// </summary>
    [TestMethod]
    public async Task RsaOnlySimulatorCompletesMakeAndActivateCredentialEndToEnd()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateRsaOnlyOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateRsaEndorsementKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        using MakeCredentialInput makeInput = MakeCredentialInput.Create(ek.ObjectHandle, CredentialSecret.Memory.Span, ak.Name.Span, pool);
        TpmResult<MakeCredentialResponse> makeResult = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
            tpm, makeInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(makeResult.IsSuccess, $"An RSA-only simulator must complete TPM2_MakeCredential() over the RSA EK: '{makeResult.ResponseCode}'.");
        using MakeCredentialResponse made = makeResult.Value;

        //The standard EK clears userWithAuth, so keyHandle's USER role needs a policy session satisfied by
        //TPM2_PolicySecret() against the Endorsement Hierarchy (TCG EK Credential Profile, Annex B.3.2).
        TpmResult<StartAuthSessionResponse> policyStartResult = await tpm.StartPolicySessionAsync(
            SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");
        using StartAuthSessionResponse policyStart = policyStartResult.Value;
        uint policyHandle = policyStart.SessionHandle.Value;

        TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
            (uint)TpmRh.TPM_RH_ENDORSEMENT, policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret failed: '{secretResult.ResponseCode}'.");
        secretResult.Value.Dispose();

        using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
            ak.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
        using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPolicySession keySession = TpmPolicySession.ForSession(policyHandle, SessionAlg, pool);
        ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), ek.Name.Span.ToArray()];

        TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
            tpm, activateInput, [activateAuth, keySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(activateResult.IsSuccess, $"An RSA-only simulator must complete TPM2_ActivateCredential() over the RSA EK: '{activateResult.ResponseCode}'.");

        using ActivateCredentialResponse activated = activateResult.Value;
        Assert.IsTrue(
            activated.CertInfo.AsReadOnlySpan().SequenceEqual(CredentialSecret.Memory.Span),
            "The recovered credential must equal the secret wrapped by TPM2_MakeCredential over the RSA EK.");
    }

    /// <summary>
    /// Verifies that an RSA <em>signing</em> key (not a storage key) is rejected as the <c>keyHandle</c> of
    /// <c>TPM2_MakeCredential()</c> with <c>TPM_RC_TYPE</c>: the widened admission gate (R-10) does not admit
    /// any RSA key indiscriminately — the credential key must be a Storage Key by attribute
    /// (<c>restricted=1, decrypt=1</c>, TPM 2.0 Library Part 3, clause 12.6), the same attribute predicate the
    /// ECC arm applies, not an algorithm check. This proves the wave replaced the old <c>KeyType != ECC</c>
    /// reject with a storage-attribute predicate rather than merely widening it to admit every RSA key.
    /// </summary>
    [TestMethod]
    public async Task RsaOnlySimulatorRejectsRsaSigningKeyAsCredentialKeyWithType()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateRsaOnlyOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //An RSA SIGNING key (SIGN_ENCRYPT, not RESTRICTED|DECRYPT) stands in for the credential key — a valid
        //RSA key, but not a Storage Key, so it must be refused as a MakeCredential keyHandle.
        using CreatePrimaryResponse signingKey = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using MakeCredentialInput makeInput = MakeCredentialInput.Create(signingKey.ObjectHandle, CredentialSecret.Memory.Span, ak.Name.Span, pool);
        TpmResult<MakeCredentialResponse> makeResult = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
            tpm, makeInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(makeResult.IsSuccess, "A non-storage RSA key must not be usable as a MakeCredential credential key.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_TYPE,
            makeResult.ResponseCode,
            "A credential key that is not a Storage Key must be rejected with TPM_RC_TYPE (Part 3, clause 12.6).");
    }

    /// <summary>
    /// Creates the standard RSA 2048 endorsement key (TCG EK Credential Profile, Annex B.3.3, Template L-1)
    /// under the Endorsement Hierarchy, through <see cref="CreatePrimaryInput.ForRsaEndorsementKey"/>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateRsaEndorsementKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_ENDORSEMENT, pool);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (standard RSA EK) failed: '{result.ResponseCode}'.");

        return result.Value;
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
        _ = registry.Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_ActivateCredential, TpmResponseCodec.ActivateCredential);

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
