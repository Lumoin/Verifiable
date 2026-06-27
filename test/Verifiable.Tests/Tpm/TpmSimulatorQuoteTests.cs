using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Core.EventLogs;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.EventLogs;
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
/// Acceptance test for TPM2_Quote (PCR attestation) against the TCG ms-tpm-20-ref software TPM simulator.
/// </summary>
/// <remarks>
/// <para>
/// The test creates a primary ECC P-256 signing key (used here as the attestation key, AK), quotes a selected
/// set of PCRs over a caller nonce through the production command path
/// (<see cref="QuoteInput"/> / <see cref="QuoteResponse"/> / <see cref="Tpm2bAttest"/>), then verifies the
/// result <b>off-TPM</b> from wire bytes only: the magic / type / nonce fields, the ECDSA signature over the raw
/// attestation bytes against a public key reconstructed from the TPM's exported public area, and the PCR binding
/// by re-reading the same PCRs and recomputing the composite digest. The verifier shares no in-memory state with
/// the signer beyond wire bytes, so a divergence between what a genuine TPM signs and what the host reconstructs
/// fails here rather than only against hardware.
/// </para>
/// <para>
/// A non-restricted signing key (the one created here) and a restricted attestation key both quote correctly —
/// <c>TPM2_Quote</c> always signs a TPM_GENERATED structure the TPM built itself, so the restriction that matters
/// for certifying external data does not change the quote path.
/// </para>
/// <para>
/// The test is gated on a running simulator (start the container from
/// <c>test/Verifiable.Tests/TestInfrastructure/TpmSimulator/Dockerfile</c>, publishing ports 2321/2322); it
/// reports <see cref="Assert.Inconclusive(string)"/> when none is reachable, so it is safe in any run.
/// </para>
/// </remarks>
[ConditionalTestClass]
[SkipIfNoTpmSimulator]
[DoNotParallelize]
[TestCategory("RequiresTpmSimulator")]
internal sealed class TpmSimulatorQuoteTests
{
    /// <summary>
    /// The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.
    /// </summary>
    private const int P256ComponentSize = 32;

    /// <summary>
    /// The PCR bank the quote selects from.
    /// </summary>
    private const TpmAlgIdConstants PcrBank = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// The PCRs the quote covers; two PCRs exercise the composite-digest concatenation order.
    /// </summary>
    private static int[] PcrIndices { get; } = [0, 7];

    /// <summary>
    /// The fixed caller nonce (qualifyingData) echoed into the attestation's extraData.
    /// </summary>
    private static byte[] Nonce { get; } =
    [
        0x51, 0x75, 0x6F, 0x74, 0x65, 0x20, 0x6E, 0x6F, 0x6E, 0x63, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x20,
        0x54, 0x50, 0x4D, 0x32, 0x5F, 0x51, 0x75, 0x6F, 0x74, 0x65, 0x20, 0x74, 0x65, 0x73, 0x74, 0x2E
    ];

    /// <summary>
    /// The connection to the simulator, established once for the class.
    /// </summary>
    private static MsTpmSimulatorConnection? Connection { get; set; }

    /// <summary>
    /// The TPM device created over the simulator connection.
    /// </summary>
    private static TpmDevice? Tpm { get; set; }

    /// <summary>
    /// Whether a simulator was reachable at class initialization.
    /// </summary>
    private static bool HasSimulator { get; set; }

    /// <summary>
    /// Gets or sets the per-test context (supplies the cancellation token).
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Connects to the simulator (if one is reachable) and brings up a TPM device for the class.
    /// </summary>
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

    /// <summary>
    /// Releases the TPM device and simulator connection.
    /// </summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        Tpm?.Dispose();
        Connection?.Dispose();
    }

    /// <summary>
    /// Skips the test when no simulator is reachable.
    /// </summary>
    [TestInitialize]
    public void TestInit()
    {
        if(!HasSimulator)
        {
            Assert.Inconclusive("No TPM simulator is reachable on localhost:2321/2322. Start the container from TestInfrastructure/TpmSimulator/Dockerfile.");
        }
    }

    [TestMethod]
    public async Task EcdsaP256QuoteVerifiesAgainstSimulator()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC P-256 AK) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        try
        {
            //Quote the selected PCRs over the nonce. The quote carries an empty-auth password session: a quote is
            //public, so it needs no HMAC/encrypt session.
            using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);

            //Redundant using local satisfies CA2000; ownership transfers to quoteInput and disposal is idempotent.
            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(
                primary.ObjectHandle,
                Nonce,
                TpmAlgIdConstants.TPM_ALG_SHA256,
                pcrSelection,
                pool);

            TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, quoteInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(quoteResult.IsSuccess, $"TPM2_Quote failed: '{quoteResult.ResponseCode}'.");

            using QuoteResponse quote = quoteResult.Value;
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, quote.SignatureAlgorithm);
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, quote.HashAlgorithm);

            //1. Attestation envelope: TPM-generated marker, quote type, and the nonce echoed verbatim.
            TpmsAttest attest = quote.Quoted.AttestationData;
            Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attest.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
            Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_QUOTE, attest.Type);
            Assert.IsTrue(attest.ExtraData.Span.SequenceEqual(Nonce), "extraData must echo the caller's qualifyingData nonce.");
            Assert.IsNotNull(attest.Attested.Quote);

            //2. Signature: over the RAW attestation bytes, against the AK public key reconstructed from the TPM's
            //exported public area only (firewalled — no shared in-memory state).
            byte[] attestDigest = SHA256.HashData(quote.Quoted.GetRawBytes());

            TpmsEccPoint point = primary.OutPublic.PublicArea.Unique.Ecc!;
            var ecParameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = ToFixed(point.X.AsReadOnlySpan(), P256ComponentSize),
                    Y = ToFixed(point.Y.AsReadOnlySpan(), P256ComponentSize)
                }
            };

            byte[] p1363Signature = new byte[2 * P256ComponentSize];
            ToFixed(quote.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
            ToFixed(quote.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

            using ECDsa ecdsa = ECDsa.Create(ecParameters);
            Assert.IsTrue(
                ecdsa.VerifyHash(attestDigest, p1363Signature),
                "The quote signature must verify over the raw attestation bytes against the AK's exported public key.");

            //3. PCR binding: re-read the same PCRs and recompute the composite digest the TPM signed.
            byte[] expectedPcrDigest = await ReadAndComputePcrCompositeAsync(tpm, registry, pool).ConfigureAwait(false);
            Assert.IsTrue(
                attest.Attested.Quote!.PcrDigest.AsReadOnlySpan().SequenceEqual(expectedPcrDigest),
                "The quote's pcrDigest must equal the hash of the concatenated selected PCR values.");
        }
        finally
        {
            await FlushAsync(tpm, registry, primary.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task QuoteVerifiesThroughTheCryptographyVerificationSeam()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC P-256 AK) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        try
        {
            using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(
                primary.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

            TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, quoteInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(quoteResult.IsSuccess, $"TPM2_Quote failed: '{quoteResult.ResponseCode}'.");

            using QuoteResponse quote = quoteResult.Value;

            //Project the TPM-specific signature and AK point into the neutral .Cryptography carriers, then verify
            //the attestation through the SAME verification delegate the library resolves for X.509/DID/mdoc — the
            //convergence seam. No TPM type crosses into the verification call.
            using Signature signature = quote.Signature.ToSignature(P256ComponentSize, CryptoTags.P256Signature, pool);
            using PublicKeyMemory akKey = primary.OutPublic.PublicArea.Unique.Ecc!.ToCompressedPublicKeyMemory(
                P256ComponentSize, CryptoTags.P256PublicKey, pool);

            VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(
                CryptoAlgorithm.P256, Purpose.Verification);
            using var publicKey = new PublicKey(akKey, "tpm-ak", verify);

            bool verified = await publicKey.VerifyAsync(quote.Quoted.GetRawBytes().ToArray(), signature).ConfigureAwait(false);
            Assert.IsTrue(
                verified,
                "A TPM quote must verify through the shared .Cryptography verification seam from the projected carriers.");
        }
        finally
        {
            await FlushAsync(tpm, registry, primary.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task QuoteReplaysAsACryptoProofLogEntry()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC P-256 AK) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        try
        {
            using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(
                primary.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

            TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, quoteInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(quoteResult.IsSuccess, $"TPM2_Quote failed: '{quoteResult.ResponseCode}'.");

            using QuoteResponse quote = quoteResult.Value;

            //Compose the quote into a generic crypto-proof log entry: the raw attestation is the canonical signed
            //payload, the projected signature and AK key are the neutral proof carriers. The replayer then verifies
            //and applies it through the same TPM-agnostic path a software-signed proof takes.
            byte[] canonical = quote.Quoted.GetRawBytes().ToArray();
            byte[] digest = SHA256.HashData(canonical);
            using Signature signature = quote.Signature.ToSignature(P256ComponentSize, CryptoTags.P256Signature, pool);
            using PublicKeyMemory akKey = primary.OutPublic.PublicArea.Unique.Ecc!.ToCompressedPublicKeyMemory(
                P256ComponentSize, CryptoTags.P256PublicKey, pool);

            var proof = new CryptoProof(signature, akKey, CryptoAlgorithm.P256);
            LogEntry<ReadOnlyMemory<byte>, CryptoProof> entry = new()
            {
                Index = 0,
                PreviousDigest = null,
                Digest = digest,
                CanonicalBytes = canonical,
                Operation = canonical,
                Proofs = [proof]
            };

            LogReplayResult<int, ReadOnlyMemory<byte>, CryptoProof> result =
                await CryptoProofLogReplayHarness.ReplayGenesisAsync(entry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsSuccess, $"A real TPM quote must replay as a crypto-proof log entry; error: '{result.Error}'.");
            Assert.IsInstanceOfType<ActiveLogState<int>>(result.State);
        }
        finally
        {
            await FlushAsync(tpm, registry, primary.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Reads the quoted PCRs and computes the composite digest the TPM signs into a quote: the SHA-256 hash of the
    /// concatenation of the selected PCR values in ascending PCR-index order (TPM 2.0 Library Part 4,
    /// <c>PCRComputeCurrentDigest</c>).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The expected composite PCR digest.</returns>
    private async Task<byte[]> ReadAndComputePcrCompositeAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool)
    {
        using PcrReadInput input = PcrReadInput.ForPcrs(PcrBank, PcrIndices, pool);
        TpmResult<PcrReadResponse> result = await TpmCommandExecutor.ExecuteAsync<PcrReadResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_PCR_Read failed: '{result.ResponseCode}'.");

        using PcrReadResponse response = result.Value;
        Assert.AreEqual(PcrIndices.Length, response.PcrValues.Count, "PCR_Read must return every selected PCR in one read.");

        using IncrementalHash composite = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        for(int i = 0; i < response.PcrValues.Count; i++)
        {
            composite.AppendData(response.PcrValues[i].AsReadOnlySpan());
        }

        return composite.GetHashAndReset();
    }

    /// <summary>
    /// Creates a response codec registry covering the commands this test issues.
    /// </summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Quote, TpmResponseCodec.Quote);
        _ = registry.Register(TpmCcConstants.TPM_CC_PCR_Read, TpmResponseCodec.PcrRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Flushes a transient object or session handle, ignoring the result.
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

    /// <summary>
    /// Left-pads a big-endian integer to a fixed width, as the IEEE P1363 / ECPoint encodings require. The TPM
    /// returns TPM2B integers that may omit leading zero bytes.
    /// </summary>
    /// <param name="value">The big-endian value.</param>
    /// <param name="length">The fixed width to pad to.</param>
    /// <returns>A new array of exactly <paramref name="length"/> bytes.</returns>
    private static byte[] ToFixed(ReadOnlySpan<byte> value, int length)
    {
        byte[] result = new byte[length];
        if(value.Length <= length)
        {
            value.CopyTo(result.AsSpan(length - value.Length));
        }
        else
        {
            //Defensive: drop any leading zero padding the TPM may have included.
            value[^length..].CopyTo(result);
        }

        return result;
    }
}
