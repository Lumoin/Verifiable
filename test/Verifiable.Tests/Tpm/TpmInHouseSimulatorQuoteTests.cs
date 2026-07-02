using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.EventLogs;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.EventLogs;
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
/// Drives <c>TPM2_Quote()</c> (PCR attestation) against the in-house behavioural <see cref="TpmSimulator"/> —
/// entirely in-process, with no external assets — through the same production command path the production code
/// uses (<see cref="TpmCommandExecutor"/> with the real <see cref="CreatePrimaryInput"/>, <see cref="QuoteInput"/>,
/// <see cref="PcrReadInput"/>, and response codecs): <c>TPM2_CreatePrimary()</c> mints a primary ECC P-256
/// signing key (used here as the attestation key, AK), then the AK quotes a selected set of PCRs in the SHA-256
/// bank over a caller nonce.
/// </summary>
/// <remarks>
/// <para>
/// The result is verified <b>off-TPM</b> from wire bytes only: the magic / type / nonce fields, the ECDSA
/// signature over the raw attestation bytes against the AK's exported public key reconstructed from
/// <c>outPublic</c> alone, and the PCR binding by re-reading the same PCRs (<c>TPM2_PCR_Read()</c>) and
/// recomputing the composite digest as the hash of the concatenated selected PCR values in ascending index order.
/// The verifier shares no in-memory state with the signer beyond the wire bytes, so a divergence between what the
/// simulator framed and what a genuine TPM would attest and sign fails here.
/// </para>
/// <para>
/// The same quote is verified three ways: directly against a reconstructed <see cref="ECDsa"/> key, through the
/// shared <c>.Cryptography</c> verification seam the library resolves for X.509/DID/mdoc (from the projected
/// neutral carriers), and by replaying it as a generic crypto-proof log entry. A quote is public by design, so it
/// carries an empty-auth password session; the signing backend is injected so the production <c>Verifiable.Tpm</c>
/// assembly stays provider-agnostic.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorQuoteTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The PCR bank the quote selects from.</summary>
    private const TpmAlgIdConstants PcrBank = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The PCRs the quote covers; two PCRs exercise the composite-digest concatenation order.</summary>
    private static int[] PcrIndices { get; } = [0, 7];

    /// <summary>The fixed caller nonce (qualifyingData) echoed into the attestation's extraData.</summary>
    private static byte[] Nonce { get; } = "Quote nonce for the in-house TPM."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task EcdsaP256QuoteVerifiesAgainstInHouseSimulator()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using QuoteResponse quote = await QuoteAsync(tpm, registry, pool, ak.ObjectHandle).ConfigureAwait(false);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, quote.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, quote.HashAlgorithm);

        //1. Attestation envelope: TPM-generated marker, quote type, and the nonce echoed verbatim.
        TpmsAttest attest = quote.Quoted.AttestationData;
        Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attest.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_QUOTE, attest.Type);
        Assert.IsTrue(attest.ExtraData.Span.SequenceEqual(Nonce), "extraData must echo the caller's qualifyingData nonce.");
        Assert.IsNotNull(attest.Attested.Quote);

        //2. Signature: over the RAW attestation bytes, against the AK public key reconstructed from the
        //simulator's exported public area only (firewalled — no shared in-memory state).
        byte[] attestDigest = await ComputeSha256Async(quote.Quoted.GetRawBytes().ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmsEccPoint point = ak.OutPublic.PublicArea.Unique.Ecc!;
        var ecParameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = ToFixed(point.X.AsReadOnlySpan(), P256ComponentSize),
                Y = ToFixed(point.Y.AsReadOnlySpan(), P256ComponentSize)
            }
        };

        //.NET's VerifyHash expects the raw IEEE P1363 r || s concatenation, each component fixed-width.
        byte[] p1363Signature = new byte[2 * P256ComponentSize];
        ToFixed(quote.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(quote.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        using ECDsa ecdsa = ECDsa.Create(ecParameters);
        Assert.IsTrue(
            ecdsa.VerifyHash(attestDigest, p1363Signature),
            "The quote signature must verify over the raw attestation bytes against the AK's exported public key.");

        //3. PCR binding: re-read the same PCRs and recompute the composite digest the simulator signed.
        byte[] expectedPcrDigest = await ReadAndComputePcrCompositeAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.IsTrue(
            attest.Attested.Quote!.PcrDigest.AsReadOnlySpan().SequenceEqual(expectedPcrDigest),
            "The quote's pcrDigest must equal the hash of the concatenated selected PCR values.");
    }

    [TestMethod]
    public async Task QuoteVerifiesThroughTheCryptographyVerificationSeam()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using QuoteResponse quote = await QuoteAsync(tpm, registry, pool, ak.ObjectHandle).ConfigureAwait(false);

        //Project the TPM-specific signature and AK point into the neutral .Cryptography carriers, then verify the
        //attestation through the SAME verification delegate the library resolves for X.509/DID/mdoc — the
        //convergence seam. No TPM type crosses into the verification call.
        using Signature signature = quote.Signature.ToSignature(P256ComponentSize, CryptoTags.P256Signature, pool);
        using PublicKeyMemory akKey = ak.OutPublic.PublicArea.Unique.Ecc!.ToCompressedPublicKeyMemory(
            P256ComponentSize, CryptoTags.P256PublicKey, pool);

        VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(
            CryptoAlgorithm.P256, Purpose.Verification);
        using var publicKey = new PublicKey(akKey, "tpm-ak", verify);

        bool verified = await publicKey.VerifyAsync(quote.Quoted.GetRawBytes().ToArray(), signature).ConfigureAwait(false);
        Assert.IsTrue(
            verified,
            "A TPM quote must verify through the shared .Cryptography verification seam from the projected carriers.");
    }

    [TestMethod]
    public async Task QuoteReplaysAsACryptoProofLogEntry()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using QuoteResponse quote = await QuoteAsync(tpm, registry, pool, ak.ObjectHandle).ConfigureAwait(false);

        //Compose the quote into a generic crypto-proof log entry: the raw attestation is the canonical signed
        //payload, the projected signature and AK key are the neutral proof carriers. The replayer then verifies
        //and applies it through the same TPM-agnostic path a software-signed proof takes.
        byte[] canonical = quote.Quoted.GetRawBytes().ToArray();
        byte[] digest = await ComputeSha256Async(canonical, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using Signature signature = quote.Signature.ToSignature(P256ComponentSize, CryptoTags.P256Signature, pool);
        using PublicKeyMemory akKey = ak.OutPublic.PublicArea.Unique.Ecc!.ToCompressedPublicKeyMemory(
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

        Assert.IsTrue(result.IsSuccess, $"An in-house TPM quote must replay as a crypto-proof log entry; error: '{result.Error}'.");
        Assert.IsInstanceOfType<ActiveLogState<int>>(result.State);
    }

    [TestMethod]
    public async Task QuoteWithUnknownSignKeyReturnsHandle()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //No signing key was created, so the transient signHandle does not resolve (TPM 2.0 Part 3, clause 18.4).
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
        using QuoteInput quoteInput = QuoteInput.ForEcdsa(
            TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase),
            Nonce,
            TpmAlgIdConstants.TPM_ALG_SHA256,
            pcrSelection,
            pool);

        TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, quoteResult.ResponseCode);
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the given hierarchy and returns the response (the caller
    /// owns it).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response.</returns>
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
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256 AK, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Quotes the selected PCRs over the fixed nonce with the given signing key and returns the response (the
    /// caller owns it). A quote is public, so it carries an empty-auth password session.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="signHandle">The signing (attestation) key handle.</param>
    /// <returns>The Quote response.</returns>
    private async Task<QuoteResponse> QuoteAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmiDhObject signHandle)
    {
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
        using QuoteInput quoteInput = QuoteInput.ForEcdsa(
            signHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

        TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(quoteResult.IsSuccess, $"TPM2_Quote failed: '{quoteResult.ResponseCode}'.");

        return quoteResult.Value;
    }

    /// <summary>
    /// Reads the quoted PCRs and computes the composite digest the simulator signs into a quote: the SHA-256 hash
    /// of the concatenation of the selected PCR values in ascending PCR-index order (TPM 2.0 Library Part 4,
    /// <c>PCRComputeCurrentDigest</c>), through the registered digest seam.
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

        int total = 0;
        for(int i = 0; i < response.PcrValues.Count; i++)
        {
            total += response.PcrValues[i].Size;
        }

        using IMemoryOwner<byte> composite = pool.Rent(Math.Max(total, 1));
        int offset = 0;
        for(int i = 0; i < response.PcrValues.Count; i++)
        {
            ReadOnlySpan<byte> value = response.PcrValues[i].AsReadOnlySpan();
            value.CopyTo(composite.Memory.Span[offset..]);
            offset += value.Length;
        }

        return await ComputeSha256Async(composite.Memory[..total], pool, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase. The ECC backend is required so the simulator services
    /// <c>TPM2_CreatePrimary()</c> and signs the attestation for <c>TPM2_Quote()</c>.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-quote", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
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
        _ = registry.Register(TpmCcConstants.TPM_CC_Quote, TpmResponseCodec.Quote);
        _ = registry.Register(TpmCcConstants.TPM_CC_PCR_Read, TpmResponseCodec.PcrRead);

        return registry;
    }

    /// <summary>
    /// Computes a SHA-256 digest through the registered digest seam (not a direct framework hash).
    /// </summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 32-byte digest.</returns>
    private static async Task<byte[]> ComputeSha256Async(ReadOnlyMemory<byte> message, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        Tag tag = new(new Dictionary<Type, object>
        {
            [typeof(HashAlgorithmName)] = HashAlgorithmName.SHA256,
            [typeof(Purpose)] = Purpose.Digest,
            [typeof(EncodingScheme)] = EncodingScheme.Raw,
            [typeof(MaterialSemantics)] = MaterialSemantics.Direct
        });

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(message),
            outputByteLength: P256ComponentSize,
            tag: tag,
            pool: pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Left-pads a big-endian integer to a fixed width, as the IEEE P1363 / ECPoint encodings require. The
    /// simulator returns TPM2B integers that may omit leading zero bytes.
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
            //Defensive: drop any leading zero padding the simulator may have included.
            value[^length..].CopyTo(result);
        }

        return result;
    }
}
