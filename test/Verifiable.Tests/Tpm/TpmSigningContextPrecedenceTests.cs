using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
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
/// Regression coverage for the per-call/constructor-default context precedence at
/// <see cref="PrivateKey.SignAsync"/>'s <c>context ?? defaultContext</c> choke point: a caller-supplied
/// per-call <c>context</c> must win over the key's constructor-time default, never the reverse.
/// </summary>
/// <remarks>
/// <para>
/// Uses the in-house behavioural <see cref="TpmSimulator"/> — never real hardware — as the vehicle,
/// because <see cref="TpmCryptographicFunctions"/> is this codebase's one production caller that
/// routes real, observable state (a <see cref="TpmDevice"/> handle, scheme, hash, and signature tag)
/// through the per-call <c>context</c> dictionary rather than a closure. Two independently operational
/// simulators stand in for two distinct devices: the signing key is created only on
/// <c>deviceWithKey</c>, so a context naming <c>deviceWithoutKey</c> is a "poisoned" default — routing
/// a Sign command to it fails with <see cref="TpmRcConstants.TPM_RC_HANDLE"/> because the handle does
/// not resolve there (TPM 2.0 Part 3, clause 20.2), the same failure
/// <c>TpmInHouseSimulatorSignTests.SignWithUnknownKeyHandleReturnsHandle</c> proves for a raw command.
/// </para>
/// <para>
/// The test binds the constructor default to the poisoned context, first proving the default really
/// is wired through (no explicit override fails identically), then supplies the correct per-call
/// context and asserts signing succeeds and the resulting signature verifies against the key's real,
/// exported public area — which is only possible if the per-call context, not the poisoned default,
/// reached <see cref="TpmCryptographicFunctions.SignAsync"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmSigningContextPrecedenceTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The fixed message signed through the per-call/default context precedence check.</summary>
    private static byte[] MessageBytes { get; } = "Verifiable per-call TPM signing-context precedence test."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A per-call <c>context</c> passed to <see cref="PrivateKey.SignAsync"/> overrides the key's
    /// constructor-time default context, rather than the reverse. Without the override, signing fails
    /// because the constructor default names a device the key was never created on; with the override
    /// naming the correct device, signing succeeds and the signature verifies against the key's real
    /// exported public area.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "The PrivateKey takes ownership of the handle memory and is disposed by its using declaration.")]
    public async Task PerCallContextOverridesTheConstructorDefaultContext()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();

        //The key lives only on this device.
        TpmSimulator simulatorWithKey = await CreateOperationalSimulatorAsync(pool, "tpm-context-precedence-with-key").ConfigureAwait(false);
        using TpmDevice deviceWithKey = TpmDevice.Create(simulatorWithKey.SubmitAsync);

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            deviceWithKey, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{primaryResult.ResponseCode}'.");
        using CreatePrimaryResponse primary = primaryResult.Value;

        //A distinct, independently operational simulator with no key created: the same handle value
        //does not resolve there.
        TpmSimulator simulatorWithoutKey = await CreateOperationalSimulatorAsync(pool, "tpm-context-precedence-without-key").ConfigureAwait(false);
        using TpmDevice deviceWithoutKey = TpmDevice.Create(simulatorWithoutKey.SubmitAsync);

        FrozenDictionary<string, object> poisonedDefaultContext = TpmCryptographicFunctions.CreateP256SigningContext(deviceWithoutKey);
        FrozenDictionary<string, object> correctContext = TpmCryptographicFunctions.CreateP256SigningContext(deviceWithKey);

        using var privateKey = new PrivateKey(
            TpmCryptographicFunctions.CreateHandleKeyMemory(primary.ObjectHandle.Value, CryptoTags.P256PrivateKey, pool),
            "tpm-context-precedence",
            TpmCryptographicFunctions.SignAsync,
            poisonedDefaultContext);

        //Baseline: with no per-call override, the constructor default is genuinely used, and it names
        //the wrong device, so signing fails. This proves the default is wired through at all, so the
        //override proven below is a meaningful precedence check rather than a vacuous one.
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
        {
            _ = await privateKey.SignAsync(MessageBytes, pool).ConfigureAwait(false);
        }).ConfigureAwait(false);

        //The mutation this test kills swaps `context ?? defaultContext` for `defaultContext ?? context`
        //at the PrivateKey.SignAsync choke point: under that mutation this call would ALSO route to
        //deviceWithoutKey and fail identically to the call above, rather than succeeding.
        var observer = new TestObserver<CryptoEvent>();
        Signature signature;
        using(CryptographicKeyEvents.Events.Subscribe(observer))
        {
            signature = await privateKey.SignAsync(MessageBytes, pool, context: correctContext).ConfigureAwait(false);
        }

        using(signature)
        {
            Assert.Contains(
                (SignatureProducedEvent e) => e.Backend == "Tpm" && e.Algorithm == CryptoAlgorithm.P256,
                observer.Received.OfType<SignatureProducedEvent>(),
                "The per-call context override must reach the TPM signing function and emit its SignatureProducedEvent.");

            //Firewalled verify: reconstruct the public key from deviceWithKey's exported public area only.
            byte[] compressedPublicKey = TpmEccWireFixtures.BuildCompressedPublicKey(primary.OutPublic.PublicArea.Unique.Ecc!, P256ComponentSize);
            VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(
                CryptoAlgorithm.P256, Purpose.Verification);
            (bool verified, CryptoEvent? _) = await verify(
                MessageBytes, signature.AsReadOnlyMemory(), compressedPublicKey, null, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(verified, "A signature produced via the per-call context override must verify against the key it actually named.");
        }
    }


    /// <summary>
    /// Creates a simulator with the ECC signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase — mirroring
    /// <c>TpmInHouseSimulatorSignTests.CreateOperationalAsync</c>, kept local to this file per the
    /// wave-8 file discipline (new test files only; shared test infrastructure stays untouched).
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tpmId">The simulator's identifier, also its default proof seed.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalSimulatorAsync(MemoryPool<byte> pool, string tpmId)
    {
        var simulator = new TpmSimulator(tpmId, signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }


    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor
    /// frames an unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
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


    /// <summary>Creates a response codec registry covering the commands this test issues.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);

        return registry;
    }
}
