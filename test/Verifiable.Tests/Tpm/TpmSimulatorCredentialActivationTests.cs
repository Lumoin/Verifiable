using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.TestInfrastructure.TpmSimulator;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Acceptance tests for credential activation (TPM2_MakeCredential + TPM2_ActivateCredential) against the TCG
/// ms-tpm-20-ref software TPM simulator — the challenge-response that proves an attestation key (AK) is bound to
/// a specific credential/endorsement key (EK) in the same TPM.
/// </summary>
/// <remarks>
/// <para>
/// A challenger holding the EK public key wraps a secret bound to the AK's Name with <c>TPM2_MakeCredential</c>;
/// the device recovers it with <c>TPM2_ActivateCredential</c> only because it holds both the EK (to decrypt the
/// seed) and the AK (whose Name the credential is bound to). Recovering the secret is the proof of co-residence
/// that lets an enrollment authority trust the AK. Here a restricted-decrypt storage primary stands in for the
/// EK; the TCG-standard EK adds the well-known authorization policy (requiring a policy session over the
/// endorsement hierarchy) but is otherwise the same mechanism.
/// </para>
/// <para>
/// The negative test confirms the binding is to the AK's <i>Name</i>: a credential bound to one AK cannot be
/// activated against a different object, even with the same EK.
/// </para>
/// <para>
/// The tests are gated on a running simulator (start the container from
/// <c>test/Verifiable.Tests/TestInfrastructure/TpmSimulator/Dockerfile</c>, publishing ports 2321/2322); they
/// report <see cref="Assert.Inconclusive(string)"/> when none is reachable, so they are safe in any run.
/// </para>
/// </remarks>
[ConditionalTestClass]
[SkipIfNoTpmSimulator]
[DoNotParallelize]
[TestCategory("RequiresTpmSimulator")]
internal sealed class TpmSimulatorCredentialActivationTests
{
    /// <summary>The secret credential wrapped and recovered by the tests (16 bytes, within the EK nameAlg digest size).</summary>
    private static byte[] CredentialSecret { get; } =
        [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF];

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
    public async Task MakeAndActivateCredentialRecoversTheSecret()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
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

                //Device side: recover the secret. The AK is the activate object (ADMIN role), the EK decrypts the
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
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
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
