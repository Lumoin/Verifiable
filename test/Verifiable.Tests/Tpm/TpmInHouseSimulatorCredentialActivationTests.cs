using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
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
/// Drives credential activation (<c>TPM2_MakeCredential()</c> + <c>TPM2_ActivateCredential()</c>) against the
/// in-house behavioural <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same
/// production command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="MakeCredentialInput"/> / <see cref="ActivateCredentialInput"/> and response codecs). Credential
/// activation is the challenge-response that proves an attestation key (AK) is bound to a specific credential /
/// endorsement key (EK) in the same TPM (TPM 2.0 Library Part 1, clause 24; Part 3, clauses 12.6 and 12.5).
/// </summary>
/// <remarks>
/// <para>
/// A challenger holding the EK public key wraps a secret bound to the AK's Name with <c>TPM2_MakeCredential()</c>;
/// the device recovers it with <c>TPM2_ActivateCredential()</c> only because it holds both the EK (to recover the
/// seed) and the AK (whose Name the credential's integrity is keyed to). Recovering the secret is the proof of
/// co-residence that lets an enrollment authority trust the AK. A restricted-decrypt ECC storage primary stands in
/// for the EK; the standard EK adds the well-known authorization policy (a policy session over the endorsement
/// hierarchy) but is otherwise the same mechanism.
/// </para>
/// <para>
/// The simulator runs both sides, so its credential-protection crypto is self-consistent by construction: the seed
/// is transported by a faithful ECDH exchange with the EK's public point fed to <c>KDFe</c> (Part 1, clause
/// 9.4.10.3), and the credential blob is the real AK-Name-bound outer wrap (<c>KDFa</c>-derived AES-CFB encryption
/// and an outer HMAC over the ciphertext and the AK's Name, Part 1, clause 24), all through the shipped
/// <see cref="Kdfa"/> / <see cref="Kdfe"/> and the registered digest/HMAC seams. The negative test confirms the
/// binding is to the AK's <i>Name</i>: a credential bound to one AK cannot be activated against a different object,
/// even with the same EK — the re-derivation keyed on the activate object's Name yields a different HMAC key, so the
/// integrity check fails.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorCredentialActivationTests
{
    /// <summary>The secret credential wrapped and recovered by the tests (16 bytes, within the EK nameAlg digest size).</summary>
    private static byte[] CredentialSecret { get; } =
        [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task MakeAndActivateCredentialRecoversTheSecret()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                //Challenger side: wrap the secret to the EK public key, bound to the AK's Name.
                using MakeCredentialResponse made = await MakeCredentialAsync(tpm, registry, pool, ek.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);
                Assert.IsFalse(made.CredentialBlob.IsEmpty, "The credential blob must not be empty.");
                Assert.IsFalse(made.Secret.IsEmpty, "The encrypted secret must not be empty.");

                //Device side: recover the secret. The AK is the activate object (ADMIN role), the EK recovers the
                //seed (USER role); both authorized with empty-auth password sessions in handle order.
                using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                    ak.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                    tpm, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(activateResult.IsSuccess, $"TPM2_ActivateCredential failed: '{activateResult.ResponseCode}'.");

                using ActivateCredentialResponse activated = activateResult.Value;
                Assert.IsTrue(
                    activated.CertInfo.AsReadOnlySpan().SequenceEqual(CredentialSecret),
                    "The recovered credential must equal the secret wrapped by TPM2_MakeCredential, proving AK and EK co-reside.");
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task ActivateWithWrongObjectIsRejected()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            using CreatePrimaryResponse otherAk = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
            try
            {
                //The credential is bound to the AK's Name.
                using MakeCredentialResponse made = await MakeCredentialAsync(tpm, registry, pool, ek.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);

                //Activating against a different object (otherAk) must fail: the credential's integrity is keyed to
                //the bound AK's Name, so a mismatched activate object cannot recover the secret.
                using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                    otherAk.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
                using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                    tpm, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(
                    activateResult.IsSuccess,
                    "A credential bound to one attestation key's Name must not be activatable against a different object.");
            }
            finally
            {
                await FlushAsync(tpm, registry, otherAk.ObjectHandle.Value, pool).ConfigureAwait(false);
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task ActivateCredentialRejectsUndersizedCredentialBlob()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                //A wire-legal but empty credentialBlob and secret (size-zero TPM2B fields) reach the effect executor
                //after the handles resolve; a too-small buffer must fail closed with TPM_RC_SIZE rather than throw an
                //out-of-range exception out of the executor, which the PDA runner does not catch (Part 3, clause 12.5).
                using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                    ak.ObjectHandle, ek.ObjectHandle, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                    tpm, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(activateResult.IsSuccess, "An undersized credentialBlob/secret must be rejected, not crash.");
                Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, activateResult.ResponseCode);
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Wraps <see cref="CredentialSecret"/> to the given key's public area, bound to <paramref name="objectName"/>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The credential key (EK) whose public area protects the seed.</param>
    /// <param name="objectName">The Name of the object the credential is bound to (the AK).</param>
    /// <returns>The MakeCredential response (the caller owns it).</returns>
    private async Task<MakeCredentialResponse> MakeCredentialAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmiDhObject keyHandle, byte[] objectName)
    {
        using MakeCredentialInput input = MakeCredentialInput.Create(keyHandle, CredentialSecret, objectName, pool);

        //TPM2_MakeCredential uses only the public area of the key, so it takes no authorization session.
        TpmResult<MakeCredentialResponse> result = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_MakeCredential failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a restricted-decrypt ECC storage primary (the EK stand-in) under the given hierarchy.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response (the caller owns it and flushes the handle).</returns>
    private async Task<CreatePrimaryResponse> CreateStoragePrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            hierarchy, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary storage key ({hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key (the AK) under the given hierarchy.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response (the caller owns it and flushes the handle).</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary signing key ({hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase. The ECC backend is required so the simulator services
    /// <c>TPM2_CreatePrimary()</c> for the EK and AK primaries and the ECDH secret exchange of credential activation.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-credactivation", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
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

    /// <summary>
    /// Creates a response codec registry covering the commands these tests issue.
    /// </summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_ActivateCredential, TpmResponseCodec.ActivateCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Flushes a transient object handle, ignoring the result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="handle">The handle to flush.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle, MemoryPool<byte> pool)
    {
        var flush = FlushContextInput.ForHandle(handle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }
}
