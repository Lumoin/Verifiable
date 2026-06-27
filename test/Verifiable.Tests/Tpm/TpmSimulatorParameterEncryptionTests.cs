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
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Acceptance tests for session-based parameter encryption against the TCG ms-tpm-20-ref software TPM simulator.
/// </summary>
/// <remarks>
/// <para>
/// These run the production executor / <see cref="TpmSession"/> / <see cref="TpmParameterEncryption"/> path
/// against a genuine TPM implementation over the simulator's TCP protocol (see
/// <see cref="MsTpmSimulatorConnection"/>). They complete what this development box's hardware TPM cannot: the
/// hardware TPM may not implement AES-CFB parameter encryption (it is platform specific), whereas the simulator
/// implements the full library, so the AES-CFB channel can be confirmed end-to-end against a real TPM.
/// </para>
/// <para>
/// The tests are gated on a running simulator (start the container from
/// <c>test/Verifiable.Tests/TestInfrastructure/TpmSimulator/Dockerfile</c>, publishing ports 2321/2322); they
/// report <see cref="Assert.Inconclusive(string)"/> when none is reachable, so they are safe in any run.
/// </para>
/// <para>
/// GetRandom's response bytes are random and so not directly comparable, but a verified response HMAC proves the
/// host derived the simulator's exact session key and nonces, and the same key drives the parameter-encryption
/// mask/keystream; byte-exact correctness of the XOR mask and AES-CFB transform is established independently by
/// the NIST/SP800-108 known-answer tests. These tests therefore confirm real-TPM interoperability of both
/// schemes — that the simulator accepts the negotiated symmetric definition and the encrypt attribute and
/// produces an encrypted response the host correctly verifies and decrypts.
/// </para>
/// </remarks>
[ConditionalTestClass]
[SkipIfNoTpmSimulator]
[DoNotParallelize]
[TestCategory("RequiresTpmSimulator")]
internal sealed class TpmSimulatorParameterEncryptionTests
{
    private static MsTpmSimulatorConnection? Connection { get; set; }

    private static TpmDevice? Tpm { get; set; }

    private static bool HasSimulator { get; set; }

    public TestContext TestContext { get; set; } = null!;

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

    [ClassCleanup]
    public static void ClassCleanup()
    {
        Tpm?.Dispose();
        Connection?.Dispose();
    }

    [TestInitialize]
    public void TestInit()
    {
        if(!HasSimulator)
        {
            Assert.Inconclusive("No TPM simulator is reachable on localhost:2321/2322. Start the container from TestInfrastructure/TpmSimulator/Dockerfile.");
        }
    }

    [TestMethod]
    public async Task XorEncryptedGetRandomRoundTripsAgainstSimulator()
    {
        await RunEncryptedGetRandomAsync(TpmtSymDef.Xor(TpmAlgIdConstants.TPM_ALG_SHA256)).ConfigureAwait(false);
    }

    [TestMethod]
    public async Task AesCfbEncryptedGetRandomRoundTripsAgainstSimulator()
    {
        //The headline of the simulator lane: AES-CFB parameter encryption confirmed against a genuine TPM, which
        //the hardware TPM cannot validate (CFB parameter encryption is platform specific).
        await RunEncryptedGetRandomAsync(TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a transient ECC bind object, starts a bound HMAC session that negotiates <paramref name="symmetric"/>,
    /// runs an encrypt-attributed GetRandom through it, and asserts the response verifies and decrypts to the
    /// requested length. The object and session are flushed before return.
    /// </summary>
    private async Task RunEncryptedGetRandomAsync(TpmtSymDef symmetric)
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        uint objectHandle = primary.ObjectHandle.Value;

        try
        {
            StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(objectHandle, SessionAlg, symmetric);

            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound) failed: '{startResult.ResponseCode}'.");

            //nonceTPM ownership transfers to the session below.
            StartAuthSessionResponse startResponse = startResult.Value;

            using Tpm2bAuth bindAuth = Tpm2bAuth.CreateEmpty(pool);
            using var session = await TpmSession.CreateBoundAsync(
                new TpmHandle(startResponse.SessionHandle.Value),
                bindAuth.AsReadOnlyMemory(),
                startInput.NonceCaller,
                startResponse.NonceTPM,
                SessionAlg,
                pool,
                symmetric: symmetric,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

            try
            {
                const int NumberOfRandomBytes = 32;

                //Run two encrypted GetRandoms and assert the decrypted buffers differ. GetRandom has no
                //known-answer plaintext (the RNG is non-deterministic), but two distinct decrypted results prove
                //the decrypt produced varying content — a degenerate decrypt returning a constant/zero buffer
                //would be caught here, which a length-only check would miss. Byte-exact transform correctness is
                //pinned separately by the NIST/SP800-108 known-answer tests.
                byte[] first = await GetDecryptedRandomAsync(NumberOfRandomBytes).ConfigureAwait(false);
                byte[] second = await GetDecryptedRandomAsync(NumberOfRandomBytes).ConfigureAwait(false);

                Assert.IsFalse(first.AsSpan().SequenceEqual(second),
                    "Two decrypted GetRandom results over the same session must differ; identical buffers indicate a broken parameter-decryption path.");

                async Task<byte[]> GetDecryptedRandomAsync(int count)
                {
                    var getRandomInput = new GetRandomInput((ushort)count);

                    TpmResult<GetRandomResponse> randomResult = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                        tpm, getRandomInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsTrue(randomResult.IsSuccess,
                        $"Encrypted GetRandom over a bound {symmetric.Algorithm} session failed: '{randomResult.ResponseCode}'. A failure means the host-derived session key, nonces, or parameter-encryption transform diverged from the simulator's.");

                    using GetRandomResponse randomResponse = randomResult.Value;
                    Assert.AreEqual(count, randomResponse.RandomBytes.Size,
                        "Parameter encryption must not change the parameter length.");

                    byte[] decrypted = new byte[count];
                    randomResponse.RandomBytes.AsReadOnlySpan().CopyTo(decrypted);

                    return decrypted;
                }
            }
            finally
            {
                var flushSession = FlushContextInput.ForHandle(startResponse.SessionHandle.Value);
                _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                    tpm, flushSession, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            var flushObject = FlushContextInput.ForHandle(objectHandle);
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, flushObject, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }
}
