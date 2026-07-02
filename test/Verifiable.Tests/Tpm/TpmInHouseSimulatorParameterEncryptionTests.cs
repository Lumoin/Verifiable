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
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives session-based parameter encryption against the in-house behavioural <see cref="TpmSimulator"/> — entirely
/// in-process, with no external assets — through the same production command path the production code uses
/// (<see cref="TpmCommandExecutor"/>, <see cref="TpmSession"/>, and <see cref="TpmParameterEncryption"/> over the
/// real command/response codecs). Each test creates a transient ECC bind object, starts a bound unsalted HMAC
/// session negotiating a symmetric definition (XOR obfuscation or AES-CFB), sets <c>CONTINUE_SESSION | ENCRYPT</c>,
/// and runs two <c>TPM2_GetRandom()</c> commands over the session, asserting each response verifies (the response
/// HMAC) and decrypts to the requested length and that the two decrypted buffers differ (TPM 2.0 Library Part 1,
/// clauses 17.6, 18.7, and 19).
/// </summary>
/// <remarks>
/// <para>
/// The simulator derives the session key with the SAME <c>KDFa</c> (Part 1, clause 17.6.10 equation 20) the host
/// <see cref="TpmSession.CreateBoundAsync"/> uses, keys the response HMAC and the parameter-encryption
/// mask/keystream on the SAME session value, and frames the response in the order the production executor expects
/// (the first response parameter is encrypted before rpHash is computed over the ciphertext, and the caller
/// decrypts only after the response HMAC verifies; Part 1, clauses 18.7 and 19.1). So the on-device derivation and
/// the host's verification cannot diverge by construction: these tests exercise the bound-session lifecycle, the
/// nonce rolling, and the encrypt-attribute command path, not the byte-exact transform, whose correctness is the
/// independent-oracle role of the transform's own known-answer tests.
/// </para>
/// <para>
/// The production <see cref="TpmSession"/> is the firewall: it verifies the response HMAC and decrypts the first
/// response parameter, so a session key, nonce, or keystream that the simulator derived off by a single byte would
/// make the executor reject the response. <c>TPM2_GetRandom()</c> has no known-answer plaintext (its RNG is
/// non-deterministic), but two distinct decrypted results prove the decrypt produced varying content — a
/// degenerate decrypt returning a constant buffer would be caught here, which a length-only check would miss.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorParameterEncryptionTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task XorEncryptedGetRandomRoundTripsThroughTheProductionPath()
    {
        await RunEncryptedGetRandomAsync(TpmtSymDef.Xor(TpmAlgIdConstants.TPM_ALG_SHA256)).ConfigureAwait(false);
    }

    [TestMethod]
    public async Task AesCfbEncryptedGetRandomRoundTripsThroughTheProductionPath()
    {
        //AES-CFB parameter encryption (Part 1, clause 19.3) is platform specific; this exercises the full
        //bound-session round trip over the AES-CFB channel through the production executor.
        await RunEncryptedGetRandomAsync(TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a transient ECC bind object, starts a bound HMAC session that negotiates <paramref name="symmetric"/>,
    /// runs two encrypt-attributed <c>TPM2_GetRandom()</c> commands through it, and asserts each response verifies
    /// and decrypts to the requested length and that the two decrypted buffers differ. The object and session are
    /// flushed before return.
    /// </summary>
    /// <param name="symmetric">The symmetric definition to negotiate for parameter encryption.</param>
    private async Task RunEncryptedGetRandomAsync(TpmtSymDef symmetric)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

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

                //Two encrypted GetRandoms over the same session must decrypt to distinct buffers: the nonces roll
                //per command and the RNG advances, so identical results would indicate a broken parameter-decryption
                //path that a length-only check would miss.
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
                        $"Encrypted GetRandom over a bound {symmetric.Algorithm} session failed: '{randomResult.ResponseCode}'. A failure means the simulator's session key, nonces, or parameter-encryption transform diverged from the host's.");

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

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired (for the bind object's
    /// <c>TPM2_CreatePrimary()</c>), powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the
    /// operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-paramenc", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
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
}
