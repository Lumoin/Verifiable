using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.EventLogs;
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

    /// <summary>The RSA modulus size in bits used by the RSA quote tests.</summary>
    private const ushort Rsa2048KeyBits = 2048;

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

        //2. Qualified Name realism: qualifiedSigner must equal the AK's independent off-TPM recomputation
        //nameAlg || H(hierarchyHandle || Name) (TPM 2.0 Library Part 1, clause 16) — and must NOT equal the plain
        //Name (the regression a Name/QN collapse would otherwise pass).
        byte[] expectedSignerQn = await ComputeQualifiedNameAsync(
            (uint)TpmRh.TPM_RH_OWNER, ak.Name.Span.ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.QualifiedSigner.Span.SequenceEqual(expectedSignerQn),
            "qualifiedSigner must equal the AK's independently recomputed Qualified Name.");
        Assert.IsFalse(
            attest.QualifiedSigner.Span.SequenceEqual(ak.Name.Span),
            "qualifiedSigner must not collapse to the AK's plain Name.");

        //3. Signature: over the RAW attestation bytes, against the AK public key reconstructed from the
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

        //4. PCR binding: re-read the same PCRs and recompute the composite digest the simulator signed.
        byte[] expectedPcrDigest = await ReadAndComputePcrCompositeAsync(tpm, registry, pool, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
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
    /// Verifies an RSA-signed <c>TPM2_Quote()</c> (RSASSA and RSAPSS) end to end against the in-house simulator
    /// (TPM 2.0 Library Part 3, clause 18.4): the attestation envelope, the independently recomputed
    /// qualifiedSigner, the signature against the AK's exported modulus with the framework RSA verifier, and the
    /// independently recomputed PCR composite digest.
    /// </summary>
    [TestMethod]
    public async Task RsaQuoteVerifiesAgainstInHouseSimulator()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        var rsaParameters = new RSAParameters
        {
            Modulus = ak.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
            Exponent = [0x01, 0x00, 0x01]
        };

        await QuoteAndVerifyRsaAsync(tpm, registry, pool, ak, rsaParameters, TpmAlgIdConstants.TPM_ALG_SHA256, usePss: false).ConfigureAwait(false);
        await QuoteAndVerifyRsaAsync(tpm, registry, pool, ak, rsaParameters, TpmAlgIdConstants.TPM_ALG_SHA256, usePss: true).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that quoting with an ECC signer under an RSA scheme (RSASSA) is a genuine scheme/key-type
    /// mismatch, rejected with <c>TPM_RC_SCHEME</c> rather than coerced to the key's native scheme (TPM 2.0
    /// Library Part 3, clause 18.4).
    /// </summary>
    [TestMethod]
    public async Task QuoteWithSchemeMismatchedToSignerKeyTypeReturnsScheme()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
        using QuoteInput quoteInput = QuoteInput.ForRsaSsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

        TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, quoteResult.ResponseCode);
    }

    /// <summary>
    /// Verifies that a storage parent (RESTRICTED|DECRYPT, no SIGN_ENCRYPT) as the quote's signHandle is rejected
    /// with <c>TPM_RC_KEY</c>: "If the sign attribute is not SET in the key referenced by signHandle then the TPM
    /// shall return TPM_RC_KEY" (TPM 2.0 Library Part 3, clause 18.1).
    /// </summary>
    [TestMethod]
    public async Task QuoteWithNonSigningKeyReturnsKey()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
        using QuoteInput quoteInput = QuoteInput.ForEcdsa(parent.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

        TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, quoteResult.ResponseCode);
    }

    /// <summary>
    /// Verifies the TPM2B_DATA qualifyingData size bound (TPM 2.0 Library Part 2, clause 10.4.3: bounded by the
    /// size of a marshaled TPMT_HA, 66 octets for the largest supported digest): a 66-octet qualifyingData
    /// succeeds, and a 67-octet qualifyingData is rejected with <c>TPM_RC_SIZE</c>.
    /// </summary>
    [TestMethod]
    public async Task QuoteWithOversizedQualifyingDataReturnsSize()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        byte[] atBound = new byte[Tpm2bData.MaxSize];
        byte[] overBound = new byte[Tpm2bData.MaxSize + 1];

        using TpmPasswordSession atBoundAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmlPcrSelection atBoundSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
        using QuoteInput atBoundInput = QuoteInput.ForEcdsa(ak.ObjectHandle, atBound, TpmAlgIdConstants.TPM_ALG_SHA256, atBoundSelection, pool);
        TpmResult<QuoteResponse> atBoundResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, atBoundInput, [atBoundAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(atBoundResult.IsSuccess, $"A 66-octet qualifyingData is exactly at the TPM2B_DATA bound and must succeed: '{atBoundResult.ResponseCode}'.");
        atBoundResult.Value.Dispose();

        using TpmPasswordSession overBoundAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmlPcrSelection overBoundSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
        using QuoteInput overBoundInput = QuoteInput.ForEcdsa(ak.ObjectHandle, overBound, TpmAlgIdConstants.TPM_ALG_SHA256, overBoundSelection, pool);
        TpmResult<QuoteResponse> overBoundResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, overBoundInput, [overBoundAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, overBoundResult.ResponseCode);
    }

    /// <summary>
    /// Verifies that an RSA quote's attest digest and PCR composite digest are both computed under the requested
    /// SHA-384 scheme hash, not a hardcoded SHA-256 (TPM 2.0 Library Part 3, clause 18.4): the independent RSA
    /// oracle verifies with <see cref="HashAlgorithmName.SHA384"/> over a 48-byte digest, and the recomputed PCR
    /// composite is likewise hashed with SHA-384.
    /// </summary>
    [TestMethod]
    public async Task RsaQuoteWithSha384SchemeHashVerifies()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        var rsaParameters = new RSAParameters
        {
            Modulus = ak.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
            Exponent = [0x01, 0x00, 0x01]
        };

        await QuoteAndVerifyRsaAsync(tpm, registry, pool, ak, rsaParameters, TpmAlgIdConstants.TPM_ALG_SHA384, usePss: false).ConfigureAwait(false);
    }

    /// <summary>
    /// Quotes the fixed PCR selection with the RSA AK under the given scheme and scheme hash through the
    /// production command path, verifies the attestation off-TPM (magic/type/nonce/qualifiedSigner), verifies the
    /// signature against the AK's exported modulus with an independent RSA verifier, and verifies the PCR binding
    /// by independently recomputing the composite digest under the same scheme hash.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="ak">The RSA attestation key's CreatePrimary response.</param>
    /// <param name="rsaParameters">The public key reconstructed from the AK's exported modulus.</param>
    /// <param name="schemeHashAlg">The scheme hash algorithm to quote and verify under.</param>
    /// <param name="usePss">When <see langword="true"/>, quotes and verifies RSAPSS; otherwise RSASSA (PKCS#1 v1.5).</param>
    private async Task QuoteAndVerifyRsaAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, CreatePrimaryResponse ak, RSAParameters rsaParameters, TpmAlgIdConstants schemeHashAlg, bool usePss)
    {
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
        using QuoteInput quoteInput = usePss
            ? QuoteInput.ForRsaPss(ak.ObjectHandle, Nonce, schemeHashAlg, pcrSelection, pool)
            : QuoteInput.ForRsaSsa(ak.ObjectHandle, Nonce, schemeHashAlg, pcrSelection, pool);

        TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        string schemeName = usePss ? "RSAPSS" : "RSASSA";
        Assert.IsTrue(quoteResult.IsSuccess, $"TPM2_Quote ({schemeName}, {schemeHashAlg}) failed: '{quoteResult.ResponseCode}'.");

        using QuoteResponse quote = quoteResult.Value;
        Assert.AreEqual(usePss ? TpmAlgIdConstants.TPM_ALG_RSAPSS : TpmAlgIdConstants.TPM_ALG_RSASSA, quote.SignatureAlgorithm);
        Assert.AreEqual(schemeHashAlg, quote.HashAlgorithm);

        //1. Attestation envelope: TPM-generated marker, quote type, and the nonce echoed verbatim.
        TpmsAttest attest = quote.Quoted.AttestationData;
        Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attest.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_QUOTE, attest.Type);
        Assert.IsTrue(attest.ExtraData.Span.SequenceEqual(Nonce), "extraData must echo the caller's qualifyingData nonce.");
        Assert.IsNotNull(attest.Attested.Quote);

        //2. Qualified Name realism: qualifiedSigner must equal the AK's independent off-TPM recomputation and must
        //NOT collapse to the plain Name (the regression a Name/QN collapse would otherwise pass).
        byte[] expectedSignerQn = await ComputeQualifiedNameAsync(
            (uint)TpmRh.TPM_RH_ENDORSEMENT, ak.Name.Span.ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.QualifiedSigner.Span.SequenceEqual(expectedSignerQn),
            "qualifiedSigner must equal the RSA AK's independently recomputed Qualified Name.");
        Assert.IsFalse(
            attest.QualifiedSigner.Span.SequenceEqual(ak.Name.Span),
            "qualifiedSigner must not collapse to the RSA AK's plain Name.");

        //3. Signature: over the RAW attestation bytes, against the RSA AK public key reconstructed from the
        //simulator's exported modulus only.
        byte[] attestDigest = await ComputeDigestAsync(quote.Quoted.GetRawBytes().ToArray(), schemeHashAlg, pool, TestContext.CancellationToken).ConfigureAwait(false);
        RSASignaturePadding padding = usePss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        using RSA rsa = RSA.Create(rsaParameters);
        Assert.IsTrue(
            rsa.VerifyHash(attestDigest, quote.Signature.RsaSignature.Buffer.ToArray(), ToHashAlgorithmName(schemeHashAlg), padding),
            $"The {schemeName} quote signature must verify against the RSA AK's exported modulus.");

        //4. PCR binding: re-read the same PCRs and recompute the composite digest under the same scheme hash the
        //simulator signed (Part 3, clause 18.4: the PCR digest uses the hash of the signing scheme).
        byte[] expectedPcrDigest = await ReadAndComputePcrCompositeAsync(tpm, registry, pool, schemeHashAlg).ConfigureAwait(false);
        Assert.IsTrue(
            attest.Attested.Quote!.PcrDigest.AsReadOnlySpan().SequenceEqual(expectedPcrDigest),
            "The quote's pcrDigest must equal the hash of the concatenated selected PCR values under the scheme hash.");
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
    /// Creates a primary RSA-2048 signing key under the given hierarchy and returns the response (the caller owns
    /// it). A NULL scheme makes this an unrestricted signing key, so the scheme (RSASSA or RSAPSS) is chosen per
    /// <c>TPM2_Quote()</c>, as a real caller would.
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
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA 2048 AK, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates an ECC storage parent (RESTRICTED|DECRYPT, no SIGN_ENCRYPT) under the given hierarchy and returns
    /// the response (the caller owns it) — a key that cannot sign, for the negative sign-attribute test.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the parent.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            hierarchy, authPassword: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC storage parent, {hierarchy}) failed: '{result.ResponseCode}'.");

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
    /// Reads the quoted PCRs and computes the composite digest the simulator signs into a quote: the hash of the
    /// concatenation of the selected PCR values in ascending PCR-index order (TPM 2.0 Library Part 4,
    /// <c>PCRComputeCurrentDigest</c>), through the registered digest seam under the requested scheme hash (Part
    /// 3, clause 18.4: the PCR digest uses the hash of the signing scheme).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hashAlg">The scheme hash algorithm the quote was signed under.</param>
    /// <returns>The expected composite PCR digest.</returns>
    private async Task<byte[]> ReadAndComputePcrCompositeAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmAlgIdConstants hashAlg)
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

        return await ComputeDigestAsync(composite.Memory[..total], hashAlg, pool, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers it
    /// on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase. Both backends are required
    /// so the simulator services <c>TPM2_CreatePrimary()</c> for either key type and signs the attestation for
    /// <c>TPM2_Quote()</c> with either an ECC or an RSA attestation key.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-quote",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
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
        Tag tag = Tag.Create(HashAlgorithmName.SHA256)
            .With(Purpose.Digest)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(message),
            outputByteLength: P256ComponentSize,
            tag: tag,
            pool: pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Computes a digest through the registered digest seam (not a direct framework hash), sized and tagged for
    /// the requested hash algorithm — the scheme-hash-agile counterpart of <see cref="ComputeSha256Async"/> used
    /// to recompute expected digests for an RSA quote signed under a non-SHA-256 scheme hash.
    /// </summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="hashAlg">The hash algorithm (SHA-256, SHA-384, or SHA-512).</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The digest, sized for <paramref name="hashAlg"/>.</returns>
    private static async Task<byte[]> ComputeDigestAsync(ReadOnlyMemory<byte> message, TpmAlgIdConstants hashAlg, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        (int outputByteLength, HashAlgorithmName algorithmName) = hashAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_SHA256 => (32, HashAlgorithmName.SHA256),
            TpmAlgIdConstants.TPM_ALG_SHA384 => (48, HashAlgorithmName.SHA384),
            TpmAlgIdConstants.TPM_ALG_SHA512 => (64, HashAlgorithmName.SHA512),
            _ => throw new NotSupportedException($"This test computes only SHA-256/384/512 digests; '{hashAlg}' is not supported.")
        };

        Tag tag = Tag.Create(algorithmName)
            .With(Purpose.Digest)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(message),
            outputByteLength: outputByteLength,
            tag: tag,
            pool: pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Maps a TPM hash algorithm identifier to the framework's <see cref="HashAlgorithmName"/>, for the
    /// independent RSA verifier oracle (<see cref="RSA.VerifyHash(byte[], byte[], HashAlgorithmName, RSASignaturePadding)"/>).
    /// </summary>
    /// <param name="hashAlg">The hash algorithm.</param>
    /// <returns>The matching framework hash algorithm name.</returns>
    private static HashAlgorithmName ToHashAlgorithmName(TpmAlgIdConstants hashAlg) => hashAlg switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA256 => HashAlgorithmName.SHA256,
        TpmAlgIdConstants.TPM_ALG_SHA384 => HashAlgorithmName.SHA384,
        TpmAlgIdConstants.TPM_ALG_SHA512 => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"This test verifies only SHA-256/384/512 signatures; '{hashAlg}' is not supported.")
    };

    /// <summary>
    /// Recomputes an object's Qualified Name independently: <c>nameAlg || H(hierarchyHandle || Name)</c> (TPM 2.0
    /// Library Part 1, clause 16), through the registered digest seam. Every object this simulator quotes with is
    /// a primary created directly under a permanent hierarchy, so the hierarchy's own Qualified Name is its
    /// 4-octet big-endian handle value — this test never calls the production <c>TpmObjectName</c> helper,
    /// matching the file's firewalled, off-TPM oracle style.
    /// </summary>
    /// <param name="hierarchy">The permanent hierarchy handle the object was created under.</param>
    /// <param name="name">The object's own Name.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recomputed Qualified Name.</returns>
    private static async Task<byte[]> ComputeQualifiedNameAsync(uint hierarchy, ReadOnlyMemory<byte> name, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ushort nameAlg = BinaryPrimitives.ReadUInt16BigEndian(name.Span[..sizeof(ushort)]);
        Assert.AreEqual((ushort)TpmAlgIdConstants.TPM_ALG_SHA256, nameAlg, "This test assumes a SHA-256 nameAlg.");

        byte[] message = new byte[sizeof(uint) + name.Length];
        BinaryPrimitives.WriteUInt32BigEndian(message, hierarchy);
        name.Span.CopyTo(message.AsSpan(sizeof(uint)));

        byte[] digest = await ComputeSha256Async(message, pool, cancellationToken).ConfigureAwait(false);

        byte[] qualifiedName = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(qualifiedName, nameAlg);
        digest.CopyTo(qualifiedName.AsSpan(sizeof(ushort)));

        return qualifiedName;
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
