using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.EventLogs;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.EventLogs;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

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

    /// <summary>The non-empty authValue given to the DA-protected AK fixture used to prove the sign slot verifies the signing key's own retained password.</summary>
    private const string SignKeyPassword = "quote-signing-key-auth";

    /// <summary>The AK's authValue in wire form — the UTF-8 octets of <see cref="SignKeyPassword"/>, matching the password-to-authValue convention <see cref="Tpm2bSensitiveCreate.WithPassword"/> applies on the creation side.</summary>
    private static byte[] SignKeyPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(SignKeyPassword);

    /// <summary>A wrong guess at the AK's authValue, distinct from <see cref="SignKeyPasswordBytes"/>.</summary>
    private static byte[] WrongSignKeyPasswordBytes { get; } = [0x51, 0x52, 0x53, 0x54];

    /// <summary>The hash algorithm for every real HMAC-arm session the over-session tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA public exponent the framework RSA key generator uses, for the salted-session tpmKey.</summary>
    private const uint DefaultRsaExponent = 65537;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task EcdsaP256QuoteVerifiesAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
        //nameAlg || H(hierarchyHandle || Name) (TPM 2.0 Library Part 1, clause 13, Table 9) — and must NOT equal the plain
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
        //simulator's exported public area only (firewalled — no shared in-memory state). Independent-oracle
        //carve-out: framework ECDsa verifies the library-produced signature from wire bytes alone, so this
        //is deliberately not migrated to fixture key material.
        byte[] attestDigest = await ComputeSha256Async(quote.Quoted.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

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

    /// <summary>
    /// Verifies that <c>TPM2_Quote()</c> checks the signing key's own retained authValue at the sign slot
    /// rather than accepting any <c>TPM_RS_PW</c> password unchecked (TPM 2.0 Library Part 1, clause 16.6.4.3;
    /// Part 3, clause 18.1): a DA-protected AK created with a non-empty authValue quotes when the CORRECT
    /// password authorizes slot 0, leaving the dictionary-attack lockout counter unmoved, and is refused with
    /// the session-encoded <c>TPM_RC_AUTH_FAIL</c> at the same slot (Part 2, clause 6.6.2) — charging the
    /// lockout counter by exactly one (Part 1, clause 16.8.7) — when the supplied password is WRONG.
    /// </summary>
    [TestMethod]
    public async Task QuoteVerifiesTheSigningKeysAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess, $"GetDictionaryAttackParameters failed: '{before.ResponseCode}'.");

        TpmResult<QuoteResponse> correct = await QuoteWithAuthAsync(tpm, registry, pool, ak.ObjectHandle, SignKeyPasswordBytes).ConfigureAwait(false);
        Assert.IsTrue(correct.IsSuccess, $"A quote authorized with the AK's CORRECT authValue must succeed, but failed: '{correct.ResponseCode}'.");
        correct.Value.Dispose();

        TpmResult<TpmDictionaryAttackParameters> afterCorrect = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, afterCorrect.Value.LockoutCounter, "A correctly-authorized quote must move no counter.");

        TpmResult<QuoteResponse> wrong = await QuoteWithAuthAsync(tpm, registry, pool, ak.ObjectHandle, WrongSignKeyPasswordBytes).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_FAIL, wrong.BaseError,
            "A WRONG authValue against the DA-protected AK's sign slot must fail with TPM_RC_AUTH_FAIL.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), wrong.ResponseCode,
            "The mismatch names the sign slot (index 0), so the wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            afterCorrect.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
            "A wrong authValue against the DA-protected AK's sign slot must charge the lockout counter exactly once (TPM 2.0 Library Part 1, clause 16.8.7).");
    }

    /// <summary>
    /// Verifies that <c>TPM2_Quote()</c> refuses a <c>TPMA_OBJECT.userWithAuth</c>-CLEAR signing key's
    /// <c>TPM_RS_PW</c> password authorization with a <c>TPM_RC_POLICY_FAIL</c>, session-encoded to the same index even when the supplied
    /// password IS the key's own correct authValue: <c>userWithAuth</c> CLEAR means the USER role accepts
    /// only a policy session, so authValue-based authorization is never admissible for this slot, regardless
    /// of whether the value would have matched (TPM 2.0 Library Part 3, clause 5.6, check 7.1). Check 7.1
    /// precedes checks 9/10 in clause 5.6's mandatory order, so the password is never compared; a policy
    /// session remains the admissible shape for this key. The refusing response code is <c>TPM_RC_POLICY_FAIL</c>,
    /// not <c>TPM_RC_AUTH_FAIL</c>, so clause 5.6's closing rule ("shall not alter any TPM state") applies: the
    /// DA-protected key's <c>failedTries</c> is left exactly where it started.
    /// </summary>
    [TestMethod]
    public async Task QuoteWithUserWithAuthClearSignerRefusesCorrectPasswordWithoutComparingIt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateUserWithAuthClearSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess, $"GetDictionaryAttackParameters failed: '{before.ResponseCode}'.");

        TpmResult<QuoteResponse> quoteResult = await QuoteWithAuthAsync(tpm, registry, pool, ak.ObjectHandle, SignKeyPasswordBytes).ConfigureAwait(false);
        if(quoteResult.IsSuccess)
        {
            quoteResult.Value.Dispose();
        }

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), quoteResult.ResponseCode,
            $"A userWithAuth-CLEAR signer must reject even its OWN correct password at signHandle, session 1 of Table 101, " +
            $"(TPM 2.0 Library Part 3, clause 5.6, check 7.1), never authorize it (got '{quoteResult.ResponseCode}').");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "The check 7.1 refusal is uncharged: TPM_RC_POLICY_FAIL is not TPM_RC_AUTH_FAIL, so failedTries must " +
            "not move (TPM 2.0 Library Part 3, clause 5.6's closing rule).");
    }

    [TestMethod]
    public async Task QuoteVerifiesThroughTheCryptographyVerificationSeam()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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

        bool verified = await publicKey.VerifyAsync(quote.Quoted.GetRawMemory(), signature).ConfigureAwait(false);
        Assert.IsTrue(
            verified,
            "A TPM quote must verify through the shared .Cryptography verification seam from the projected carriers.");
    }

    [TestMethod]
    public async Task QuoteReplaysAsACryptoProofLogEntry()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using QuoteResponse quote = await QuoteAsync(tpm, registry, pool, ak.ObjectHandle).ConfigureAwait(false);

        //Compose the quote into a generic crypto-proof log entry: the raw attestation is the canonical signed
        //payload, the projected signature and AK key are the neutral proof carriers. The replayer then verifies
        //and applies it through the same TPM-agnostic path a software-signed proof takes.
        ReadOnlyMemory<byte> canonical = quote.Quoted.GetRawMemory();
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

    /// <summary>
    /// <c>TPM2_Quote()</c>'s <c>signHandle</c> is its sole handle (index 0); a transient-range value that
    /// resolves to no loaded object answers <c>TPM_RC_REFERENCE_H0</c> (TPM 2.0 Library Part 3, clause 5.4, step
    /// 2.1).
    /// </summary>
    [TestMethod]
    public async Task QuoteWithUnknownSignKeyAnswersReferenceH0()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

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

        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, quoteResult.ResponseCode, "An unloaded transient signHandle at index 0 answers TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1).");
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
        using QuoteInput quoteInput = QuoteInput.ForRsaSsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

        TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SCHEME, 1), quoteResult.ResponseCode, "Table 101: inScheme is TPM2_Quote()'s second parameter (parameter 2); a scheme mismatched to signHandle's key type is parameter-encoded TPM_RC_SCHEME at index 1.");
    }

    /// <summary>
    /// Verifies that a storage parent (RESTRICTED|DECRYPT, no SIGN_ENCRYPT) as the quote's signHandle is rejected
    /// with <c>TPM_RC_KEY</c>: "If the sign attribute is not SET in the key referenced by signHandle then the TPM
    /// shall return TPM_RC_KEY" (TPM 2.0 Library Part 3, clause 18.1).
    /// </summary>
    [TestMethod]
    public async Task QuoteWithNonSigningKeyReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
        using QuoteInput quoteInput = QuoteInput.ForEcdsa(parent.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

        TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), quoteResult.ResponseCode, "Table 101: signHandle is TPM2_Quote()'s sole handle (handle 1); a key without the sign attribute is handle-encoded TPM_RC_KEY at index 0.");
    }

    /// <summary>
    /// Verifies the TPM2B_DATA qualifyingData size bound (TPM 2.0 Library Part 2, clause 10.3.3: bounded by the
    /// size of a marshaled TPMT_HA, 66 octets for the largest supported digest): a 66-octet qualifyingData
    /// succeeds, and a 67-octet qualifyingData is rejected with <c>TPM_RC_SIZE</c>.
    /// </summary>
    [TestMethod]
    public async Task QuoteWithOversizedQualifyingDataReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), overBoundResult.ResponseCode, "A 67-octet qualifyingData past the TPM2B_DATA bound must be refused with TPM_RC_SIZE at qualifyingData, parameter 1 of the Quote command table.");
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse ak, RSAParameters rsaParameters, TpmAlgIdConstants schemeHashAlg, bool usePss)
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
        byte[] attestDigest = await ComputeDigestAsync(quote.Quoted.GetRawMemory(), schemeHashAlg, pool, TestContext.CancellationToken).ConfigureAwait(false);
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
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
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
    /// Creates a DA-protected primary ECC P-256 signing key under the given hierarchy with the non-empty
    /// <see cref="SignKeyPassword"/> authValue and returns the response (the caller owns it) — the fixture the
    /// sign-slot verification proof needs to exercise the AK's own retained password rather than the empty one
    /// every other AK fixture in this file carries.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateDaProtectedSigningPrimaryWithAuthAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy,
            password: SignKeyPassword,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: false);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (DA-protected ECC AK with authValue, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the given hierarchy with <c>TPMA_OBJECT.userWithAuth</c>
    /// CLEAR and the non-empty <see cref="SignKeyPassword"/> retained authValue, and returns the response (the
    /// caller owns it) — the fixture the check 7.1 proof needs. There is no factory for a userWithAuth-CLEAR
    /// signing key, so the public template is composed directly from the same pieces
    /// <see cref="CreatePrimaryInput.ForEccSigningKey"/> uses internally, with
    /// <see cref="TpmaObject.USER_WITH_AUTH"/> omitted from the object attributes. Creation itself is authorized
    /// by the hierarchy handle, which "operates as if userWithAuth is SET" regardless of the created object's own
    /// attributes (TPM 2.0 Library Part 3, clause 5.6), so creation succeeds even though the resulting key's own
    /// USER-role slot will not accept authValue-based authorization. The key is DA-protected (no
    /// <c>TPMA_OBJECT.noDA</c>) so a subsequent authorization attempt against it can be proven to leave
    /// <c>failedTries</c> unmoved.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the CreatePrimaryInput, whose Dispose releases them.")]
    private async Task<CreatePrimaryResponse> CreateUserWithAuthClearSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        var attributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.SIGN_ENCRYPT;

        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.WithPassword(SignKeyPassword, pool);
        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            attributes,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));

        using CreatePrimaryInput input = new(hierarchy, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (userWithAuth-CLEAR ECC AK, {hierarchy}) failed: '{result.ResponseCode}'.");

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
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
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
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
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
    private async Task<QuoteResponse> QuoteAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject signHandle)
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
    /// Quotes the selected PCRs over the fixed nonce with the given signing key, authorizing the sign slot with
    /// the supplied password rather than an empty-auth session, and returns the raw result (success or failure)
    /// for the caller to assert on — the counterpart to <see cref="QuoteAsync"/> for the sign-slot authValue
    /// verification proof, which must observe both the success and the refusal branch.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="signHandle">The signing (attestation) key handle.</param>
    /// <param name="keyAuthValue">The password to fold into the sign slot's <c>TPM_RS_PW</c> session.</param>
    /// <returns>The Quote result, not asserted for success.</returns>
    private async Task<TpmResult<QuoteResponse>> QuoteWithAuthAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject signHandle, ReadOnlyMemory<byte> keyAuthValue)
    {
        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(keyAuthValue.Span, pool);
        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
        using QuoteInput quoteInput = QuoteInput.ForEcdsa(
            signHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

        return await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
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
    private async Task<byte[]> ReadAndComputePcrCompositeAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmAlgIdConstants hashAlg)
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
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-quote",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
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
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
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
    private static async Task<byte[]> ComputeSha256Async(ReadOnlyMemory<byte> message, BaseMemoryPool pool, CancellationToken cancellationToken)
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
    private static async Task<byte[]> ComputeDigestAsync(ReadOnlyMemory<byte> message, TpmAlgIdConstants hashAlg, BaseMemoryPool pool, CancellationToken cancellationToken)
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
    /// Library Part 1, clause 13, Table 9), through the registered digest seam. Every object this simulator quotes with is
    /// a primary created directly under a permanent hierarchy, so the hierarchy's own Qualified Name is its
    /// 4-octet big-endian handle value — this test never calls the production <c>TpmObjectName</c> helper,
    /// matching the file's firewalled, off-TPM oracle style.
    /// </summary>
    /// <param name="hierarchy">The permanent hierarchy handle the object was created under.</param>
    /// <param name="name">The object's own Name.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recomputed Qualified Name.</returns>
    private static async Task<byte[]> ComputeQualifiedNameAsync(uint hierarchy, ReadOnlyMemory<byte> name, BaseMemoryPool pool, CancellationToken cancellationToken)
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
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)) — a local mirror of the production session-index encoding, transcribed
    /// independently here since the production helper is private.
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

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

    /// <summary>
    /// A real, unbound/unsalted HMAC session at <c>TPM2_Quote()</c>'s single authorization slot, carrying the
    /// AK's CORRECT retained authValue, attests — and a SECOND command over the SAME session likewise attests,
    /// each adopting a genuinely rolled <c>nonceTPM</c> from its own response entry: a session's nonceTPM
    /// changes on every use, command and response alike (TPM 2.0 Library Part 1, clause 16.6.3.1), and the HMAC
    /// that authenticates a response entry (clause 16.6.5, equation 17) verifies — and only then lets the
    /// session adopt the new value — solely when that entry is genuine (TPM 2.0 Library Part 3, clause 18.4).
    /// </summary>
    [TestMethod]
    public async Task QuoteOverUnboundHmacSessionWithCorrectAuthValueAttestsAndRollsNonceTpmOnASecondCommand()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse ak = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            session.SetAuthValue(SignKeyPasswordBytes, pool);

            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

            byte[] nonceTpmBeforeFirst = session.NonceTpm.ToArray();
            using TpmlPcrSelection firstSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
            using QuoteInput firstInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, firstSelection, pool);
            TpmResult<QuoteResponse> first = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, firstInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(first.IsSuccess, $"A quote authorized with the AK's CORRECT authValue must attest, but failed: '{first.ResponseCode}'.");
            first.Value.Dispose();

            Assert.IsFalse(
                session.NonceTpm.Span.SequenceEqual(nonceTpmBeforeFirst),
                "The session must adopt a genuinely rolled nonceTPM from its own response entry - it only does so once that entry's own response HMAC has verified.");

            byte[] nonceTpmBeforeSecond = session.NonceTpm.ToArray();
            using TpmlPcrSelection secondSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
            using QuoteInput secondInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, secondSelection, pool);
            TpmResult<QuoteResponse> second = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, secondInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(second.IsSuccess, $"A SECOND command over the SAME session must likewise attest, but failed: '{second.ResponseCode}'.");
            second.Value.Dispose();

            Assert.IsFalse(
                session.NonceTpm.Span.SequenceEqual(nonceTpmBeforeSecond),
                "The second command must again roll the session's nonceTPM from its own response entry.");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A real, unbound/unsalted HMAC session genuinely verifies the AK's OWN authValue (TPM 2.0 Library Part 1,
    /// clause 16.6.5, equation 17): a WRONG guess against a DA-protected AK fails the sign slot's command HMAC
    /// with the session-encoded <c>TPM_RC_AUTH_FAIL</c> and charges the lockout counter exactly once (clause
    /// 16.8.7), the session form of the same check <c>TPM2_Quote()</c>'s password arm already applies (TPM 2.0
    /// Library Part 3, clause 18.4).
    /// </summary>
    [TestMethod]
    public async Task QuoteOverUnboundHmacSessionWithWrongAuthValueOnDaProtectedSignerChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse ak = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess, $"GetDictionaryAttackParameters failed: '{before.ResponseCode}'.");

        TpmResult<QuoteResponse> result = await QuoteOverUnboundHmacSessionAsync(tpm, registry, pool, ak, WrongSignKeyPasswordBytes).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_FAIL, result.BaseError,
            "A WRONG authValue folded into a real sign session against a DA-protected AK must fail command-HMAC verification with TPM_RC_AUTH_FAIL.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
            "The mismatch names the sign slot (index 0), so the wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter + 1, after.Value.LockoutCounter,
            "A wrong authValue against the DA-protected AK's sign slot must charge the lockout counter exactly once (TPM 2.0 Library Part 1, clause 16.8.7).");
    }

    /// <summary>
    /// The NO_DA contrast to <see cref="QuoteOverUnboundHmacSessionWithWrongAuthValueOnDaProtectedSignerChargesFailedTries"/>:
    /// a WRONG guess folded into a real sign session against a <c>noDA</c> AK answers the uncharged
    /// <c>TPM_RC_BAD_AUTH</c> rather than the DA-counted <c>TPM_RC_AUTH_FAIL</c> (TPM 2.0 Library Part 1, clause
    /// 16.8.7), still session-encoded to the sign slot's index (Part 2, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task QuoteOverUnboundHmacSessionWithWrongAuthValueOnNoDaSignerReturnsBadAuthWithoutCharging()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse ak = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess, $"GetDictionaryAttackParameters failed: '{before.ResponseCode}'.");

        TpmResult<QuoteResponse> result = await QuoteOverUnboundHmacSessionAsync(tpm, registry, pool, ak, WrongSignKeyPasswordBytes).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError,
            "A WRONG authValue folded into a real sign session against a noDA AK must fail command-HMAC verification with the uncharged TPM_RC_BAD_AUTH.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
            "The mismatch names the sign slot (index 0), so the wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "A noDA signer's mismatch must move no counter (TPM 2.0 Library Part 1, clause 16.8.1).");
    }

    /// <summary>
    /// A sign session BOUND TO THE SIGNING KEY ITSELF attests with no per-command authValue: binding already
    /// incorporates the key's authValue into the session key (TPM 2.0 Library Part 1, clause 16.6.10, equation
    /// 20), so the command HMAC omits it (equations 21/22) — the bind-omission path for <c>TPM2_Quote()</c>'s
    /// single authorized slot (Part 3, clause 18.4).
    /// </summary>
    [TestMethod]
    public async Task QuoteOverSignSessionBoundToTheSigningKeyItselfAttestsWithoutAPerCommandAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse ak = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(ak.ObjectHandle.Value, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to the signing key) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = await TpmSession.CreateBoundAsync(
                new TpmHandle(sessionHandle), SignKeyPasswordBytes, startInput.NonceCaller, started.NonceTPM,
                HmacSessionAlg, TestEntropy.NewCounterStream(), pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

            TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, quoteInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                result.IsSuccess,
                $"A sign session bound to the signing key itself must attest with the authValue folded into the bind, but failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A SALTED and BOUND sign session — bound to the signing key itself — attests: the salt folds in after the
    /// bind authValue in the session-key KDFa (TPM 2.0 Library Part 1, clause 16.6.12, equation 25), so salting
    /// composes with the same bind-omission path <see cref="QuoteOverSignSessionBoundToTheSigningKeyItselfAttestsWithoutAPerCommandAuthValue"/>
    /// proves unsalted (TPM 2.0 Library Part 3, clause 18.4).
    /// </summary>
    [TestMethod]
    public async Task QuoteOverSaltedAndBoundSignSessionAttests()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse ak = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;
        uint akHandle = ak.ObjectHandle.Value;

        ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

        (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateBoundAndSaltedHmacSession(
            tpmKeyHandle, akHandle, modulus, DefaultRsaExponent, HmacSessionAlg, HmacSessionAlg, rsaBackend.EncryptOaep, TestEntropy.NewCounterStream(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        using(salt)
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (salted-and-bound) failed: '{startResult.ResponseCode}'.");

            StartAuthSessionResponse started = startResult.Value;
            uint sessionHandle = started.SessionHandle.Value;

            try
            {
                using TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), SignKeyPasswordBytes, startInput.NonceCaller, started.NonceTPM,
                    HmacSessionAlg, TestEntropy.NewCounterStream(), pool, symmetric: TpmtSymDef.Null, salt: salt.Memory[..saltLength],
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

                using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
                using QuoteInput quoteInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
                ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

                TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                    tpm, quoteInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(
                    result.IsSuccess,
                    $"A salted-and-bound sign session bound to the signing key itself must attest, but failed: '{result.ResponseCode}'.");
                using(QuoteResponse response = result.Value)
                {
                    Assert.IsNotNull(response.Quoted.AttestationData.Attested.Quote);
                }
            }
            finally
            {
                _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                    tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// A session claiming the <c>AUDIT</c> attribute at <c>TPM2_Quote()</c>'s sign slot is admitted (TPM 2.0
    /// Library Part 1, clause 17.1) and the command succeeds, extending the session's audit digest to
    /// <c>H(0…0 ‖ cpHash ‖ rpHash)</c> on its first use (equation 30) with the response echoing <c>audit</c> SET,
    /// <c>auditExclusive</c> SET and <c>auditReset</c> CLEAR (Part 2, clause 8.4, Table 38) — proved by chaining
    /// cpHash/rpHash from the octets this test itself sent and read, then reading the session's digest back
    /// through <c>TPM2_GetSessionAuditDigest()</c> with the NULL signer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1; Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    [TestMethod]
    public async Task QuoteOverSessionWithAuditAttributeSetSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        List<(TpmCcConstants Code, byte[] Command, byte[] Response)> wire = [];
        using TpmDevice tpm = CreateRecordingDevice(simulator, wire);
        TpmResponseRegistry registry = CreateHmacArmRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

            TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, quoteInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            using QuoteResponse? response = result.IsSuccess ? result.Value : null;

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SUCCESS, result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode,
                "An audit-claiming sign session succeeds (TPM 2.0 Library Part 1, clause 17.1).");

            (TpmCcConstants Code, byte[] Command, byte[] Response) audited = wire[^1];
            byte auditedAttributes = ReadResponseSessionAttributes(audited.Response, outHandleCount: 0, sessionIndex: 0);
            Assert.AreEqual(
                (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE), auditedAttributes,
                "The response echoes audit SET and auditExclusive SET (the session's first use as an audit session), with auditReset CLEAR (TPM 2.0 Library Part 2, clause 8.4, Table 38).");

            byte[] responseParameters = ReadResponseParameters(audited.Response, outHandleCount: 0);
            byte[] cpHash = await ComputeCpHashAsync(TpmCcConstants.TPM_CC_Quote, handleNames, SerializeCommandParameters(quoteInput, handleCount: 1), pool).ConfigureAwait(false);
            byte[] rpHash = await ComputeRpHashAsync(TpmCcConstants.TPM_CC_Quote, responseParameters, pool).ConfigureAwait(false);
            byte[] expectedDigest = await ExtendAuditDigestAsync(priorDigest: null, cpHash, rpHash, pool).ConfigureAwait(false);

            using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(sessionHandle), ReadOnlySpan<byte>.Empty, pool);
            using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                tpm, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            using GetSessionAuditDigestResponse? auditDigestResponse = digestResult.IsSuccess ? digestResult.Value : null;

            Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() over the freshly audited session must succeed: '{digestResult.ResponseCode}'.");
            Assert.IsTrue(auditDigestResponse!.SessionAudit.ExclusiveSession.IsYes, "The session became the exclusive audit session on its first use (TPM 2.0 Library Part 1, clause 17.2).");
            Assert.IsTrue(
                expectedDigest.AsSpan().SequenceEqual(auditDigestResponse.SessionAudit.SessionDigest.AsReadOnlySpan()),
                "The session's audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) chained from the quote exchange's own wire octets (TPM 2.0 Library Part 1, clause 17.1, equation 30).");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The USER-role gate (TPM 2.0 Library Part 3, clause 5.6, check 7.1) for a <c>userWithAuth</c>-CLEAR signer
    /// runs before any sign-slot command HMAC is queued for verification: a REAL, unbound/unsalted HMAC sign
    /// session carrying a WRONG guess at the signer's authValue still answers the BARE
    /// <c>TPM_RC_POLICY_FAIL</c>, never a session-encoded <c>TPM_RC_AUTH_FAIL</c>, and moves no counter — the
    /// gate precedes the command-HMAC verification that would otherwise fail and charge the dictionary-attack
    /// counter for a wrong guess against a DA-protected signer.
    /// </summary>
    [TestMethod]
    public async Task QuoteOverSessionWithUserWithAuthClearSignerAndWrongHmacGuessReturnsPolicyFailNotAuthFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse clearSigner = await CreateUserWithAuthClearSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess, $"GetDictionaryAttackParameters failed: '{before.ResponseCode}'.");

        TpmResult<QuoteResponse> result = await QuoteOverUnboundHmacSessionAsync(tpm, registry, pool, clearSigner, WrongSignKeyPasswordBytes).ConfigureAwait(false);
        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_FAIL, result.BaseError,
            "A userWithAuth-CLEAR signer's USER-role gate must refuse a real sign session carrying a WRONG guess with TPM_RC_POLICY_FAIL, never the session-encoded auth failure that guess would otherwise earn — BaseError strips the P/N designation, so it reads the field-independent code regardless.");
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), result.ResponseCode,
            "The refusal is session-associated to Quote's sole authorizing slot (index 0): the gate runs before any command-HMAC verification is ever queued.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "TPM_RC_POLICY_FAIL is not TPM_RC_AUTH_FAIL, so the userWithAuth gate must move no counter, even though the guess was wrong.");
    }

    /// <summary>
    /// The sign slot's own DA/Lockout gate (TPM 2.0 Library Part 3, clause 5.6, check 3) answers before EITHER
    /// sign-slot credential shape is evaluated: with the TPM in Lockout mode, a DA-protected AK answers the bare
    /// <c>TPM_RC_LOCKOUT</c> even though the sign session carries the CORRECT authValue — check 3 precedes
    /// checks 7.1 and 9/10 in clause 5.6's mandatory order, so no credential is ever compared.
    /// </summary>
    [TestMethod]
    public async Task QuoteOverUnboundHmacSessionWithDaProtectedSignerUnderLockoutReturnsLockout()
    {
        const uint SingleAttemptMaxTries = 1;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse ak = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, SingleAttemptMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        //A single wrong password over the all-password arm charges the DA-protected signer and, with maxTries at
        //one, enters Lockout mode as a side effect.
        TpmResult<QuoteResponse> seedingResult = await QuoteWithAuthAsync(tpm, registry, pool, ak.ObjectHandle, WrongSignKeyPasswordBytes).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), seedingResult.ResponseCode,
            "The seeding mismatch must be a charged sign-slot auth failure at session index 0.");

        TpmResult<QuoteResponse> result = await QuoteOverUnboundHmacSessionAsync(tpm, registry, pool, ak, SignKeyPasswordBytes).ConfigureAwait(false);
        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode,
            "A DA-protected signing key in Lockout mode must be refused before either sign-slot credential shape is evaluated, correct or not (TPM 2.0 Library Part 3, clause 5.6's check 3 precedes checks 7.1 and 9/10).");
    }

    /// <summary>
    /// A POLICY-session handle at <c>TPM2_Quote()</c>'s sign slot is a kind of authorization this simulator's
    /// session arm does not model, answered with the BARE <c>TPM_RC_AUTH_TYPE</c> — resolved before any
    /// command-HMAC verification is queued (TPM 2.0 Library Part 3, clause 5.6, step 2 of the entry ladder).
    /// </summary>
    [TestMethod]
    public async Task QuoteWithAPolicySessionHandleAtTheSignSlotReturnsAuthType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        TpmResult<StartAuthSessionResponse> policyStartResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStartResult.IsSuccess, $"StartPolicySession failed: '{policyStartResult.ResponseCode}'.");

        StartAuthSessionResponse policyStarted = policyStartResult.Value;
        uint policySessionHandle = policyStarted.SessionHandle.Value;

        try
        {
            using TpmSession policySlotSession = new(new TpmHandle(policySessionHandle), policyStarted.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);

            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

            TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, quoteInput, [policySlotSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode,
                "A policy-session handle at the sign slot is a kind of authorization this arm does not model, answered bare.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(policySessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A session handle that resolves to no loaded session at all — never a policy session either — is blamed
    /// on the offending slot index with the BARE <c>TPM_RC_REFERENCE_S0</c> (TPM 2.0 Library Part 2, clause
    /// 6.6.2's <c>TPM_RC_REFERENCE_S*</c> block), distinct from the <c>TPM_RC_AUTH_TYPE</c> a loaded policy
    /// session earns.
    /// </summary>
    [TestMethod]
    public async Task QuoteWithAnUnloadedSessionHandleAtTheSignSlotReturnsSessionReferenceMiss()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        //Flush the session BEFORE ever using it in a command, so the handle is genuinely unloaded when the Quote
        //below names it - distinct from a policy session or a TPM_RS_PW password slot.
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);

        using TpmSession unloadedSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
        using QuoteInput quoteInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
        ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

        TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [unloadedSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_REFERENCE_S0, result.ResponseCode,
            "A session handle that resolves to no loaded session at all is blamed on the offending slot index (TPM 2.0 Library Part 2, clause 6.6.2).");
    }

    /// <summary>
    /// A real HMAC session's carrier rentals (session key, authValue, nonce buffers) around <c>TPM2_Quote()</c>
    /// (TPM 2.0 Library Part 3, clause 18.4) are returned to the pool exactly, whether the round trip is REFUSED
    /// (a wrong authValue) or SUCCESSFUL (the correct one): real pool telemetry over a genuine
    /// <see cref="BaseMemoryPool"/>, no test hook in production code.
    /// </summary>
    [TestMethod]
    public async Task QuoteOverHmacSessionReturnsEveryRentedCarrierToPoolAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse ak = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        StartAuthSessionInput refusedStartInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), BaseMemoryPool.Shared);
        TpmResult<StartAuthSessionResponse> refusedStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, refusedStartInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(refusedStartResult.IsSuccess, $"StartAuthSession failed: '{refusedStartResult.ResponseCode}'.");

        StartAuthSessionResponse refusedStarted = refusedStartResult.Value;
        uint refusedSessionHandle = refusedStarted.SessionHandle.Value;

        try
        {
            using TpmSession refusedSession = new(new TpmHandle(refusedSessionHandle), refusedStarted.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), trackingPool.Pool);
            refusedSession.SetAuthValue(WrongSignKeyPasswordBytes, trackingPool.Pool);

            Assert.IsGreaterThan(
                baseline, trackingPool.OutstandingCount,
                "A session carrying a non-empty authValue must leave live carrier rentals, or the balance assertion below is vacuous.");

            using TpmlPcrSelection refusedPcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, trackingPool.Pool);
            using QuoteInput refusedQuoteInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, refusedPcrSelection, trackingPool.Pool);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

            TpmResult<QuoteResponse> refusedResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, refusedQuoteInput, [refusedSession], handleNames, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_FAIL, refusedResult.BaseError,
                "The refused area must be a genuine wrong-authValue command-HMAC failure, or its own carrier accounting proves nothing about a refusal.");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(refusedSessionHandle), [], null, trackingPool.Pool, registry, CancellationToken.None).ConfigureAwait(false);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refused area alone must return every rented carrier (the session key, the authValue, and the nonce buffers) to the pool.");

        StartAuthSessionInput okStartInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), BaseMemoryPool.Shared);
        TpmResult<StartAuthSessionResponse> okStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, okStartInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(okStartResult.IsSuccess, $"StartAuthSession failed: '{okStartResult.ResponseCode}'.");

        StartAuthSessionResponse okStarted = okStartResult.Value;
        uint okSessionHandle = okStarted.SessionHandle.Value;

        try
        {
            using TpmSession okSession = new(new TpmHandle(okSessionHandle), okStarted.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), trackingPool.Pool);
            okSession.SetAuthValue(SignKeyPasswordBytes, trackingPool.Pool);

            using TpmlPcrSelection okPcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, trackingPool.Pool);
            using QuoteInput okQuoteInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, okPcrSelection, trackingPool.Pool);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

            TpmResult<QuoteResponse> okResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, okQuoteInput, [okSession], handleNames, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(okResult.IsSuccess, $"The successful area must attest with the CORRECT authValue: '{okResult.ResponseCode}'.");
            okResult.Value.Dispose();
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(okSessionHandle), [], null, trackingPool.Pool, registry, CancellationToken.None).ConfigureAwait(false);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Both a refused and a successful Quote-over-session round trip must return every rented carrier to the pool.");
    }

    /// <summary>
    /// Verifies a full ECDSA P-256 <c>TPM2_Quote()</c> round trip composed over a REAL, unbound/unsalted HMAC
    /// session at the sign slot rather than a password (TPM 2.0 Library Part 3, clause 18.4): the same off-TPM
    /// checks <see cref="EcdsaP256QuoteVerifiesAgainstInHouseSimulator"/> applies to the all-password
    /// composition — envelope, qualifiedSigner, signature, and PCR binding — must hold identically when the sign
    /// slot's authorization rides a genuine session instead.
    /// </summary>
    [TestMethod]
    public async Task EcdsaP256QuoteOverUnboundHmacSessionVerifiesAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

            TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, quoteInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(quoteResult.IsSuccess, $"TPM2_Quote (over an unbound HMAC session) failed: '{quoteResult.ResponseCode}'.");

            using QuoteResponse quote = quoteResult.Value;
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, quote.SignatureAlgorithm);
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, quote.HashAlgorithm);

            TpmsAttest attest = quote.Quoted.AttestationData;
            Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attest.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
            Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_QUOTE, attest.Type);
            Assert.IsTrue(attest.ExtraData.Span.SequenceEqual(Nonce), "extraData must echo the caller's qualifyingData nonce.");
            Assert.IsNotNull(attest.Attested.Quote);

            byte[] expectedSignerQn = await ComputeQualifiedNameAsync(
                (uint)TpmRh.TPM_RH_OWNER, ak.Name.Span.ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                attest.QualifiedSigner.Span.SequenceEqual(expectedSignerQn),
                "qualifiedSigner must equal the AK's independently recomputed Qualified Name, even when the sign slot rode a real HMAC session.");

            byte[] attestDigest = await ComputeSha256Async(quote.Quoted.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

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

            byte[] p1363Signature = new byte[2 * P256ComponentSize];
            ToFixed(quote.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
            ToFixed(quote.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

            using ECDsa ecdsa = ECDsa.Create(ecParameters);
            Assert.IsTrue(
                ecdsa.VerifyHash(attestDigest, p1363Signature),
                "The quote signature must verify over the raw attestation bytes against the AK's exported public key, even when the sign slot was authorized over a real HMAC session.");

            byte[] expectedPcrDigest = await ReadAndComputePcrCompositeAsync(tpm, registry, pool, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            Assert.IsTrue(
                attest.Attested.Quote!.PcrDigest.AsReadOnlySpan().SequenceEqual(expectedPcrDigest),
                "The quote's pcrDigest must equal the hash of the concatenated selected PCR values.");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies an RSA-signed <c>TPM2_Quote()</c> (RSASSA and RSAPSS) round trip composed over a REAL,
    /// unbound/unsalted HMAC session at the sign slot rather than a password (TPM 2.0 Library Part 3, clause
    /// 18.4): the same off-TPM checks <see cref="RsaQuoteVerifiesAgainstInHouseSimulator"/> applies to the
    /// all-password composition must hold identically when the sign slot's authorization rides a genuine
    /// session instead.
    /// </summary>
    [TestMethod]
    public async Task RsaQuoteOverUnboundHmacSessionVerifiesAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        var rsaParameters = new RSAParameters
        {
            Modulus = ak.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
            Exponent = [0x01, 0x00, 0x01]
        };

        await QuoteOverUnboundHmacSessionAndVerifyRsaAsync(tpm, registry, pool, ak, rsaParameters, usePss: false).ConfigureAwait(false);
        await QuoteOverUnboundHmacSessionAndVerifyRsaAsync(tpm, registry, pool, ak, rsaParameters, usePss: true).ConfigureAwait(false);
    }

    /// <summary>
    /// Quotes the fixed PCR selection with the RSA AK under the given scheme over a fresh, real, unbound HMAC
    /// sign session, verifies the attestation off-TPM (magic/type/nonce/qualifiedSigner), verifies the signature
    /// against the AK's exported modulus with an independent RSA verifier, and verifies the PCR binding by
    /// independently recomputing the composite digest.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="ak">The RSA attestation key's CreatePrimary response.</param>
    /// <param name="rsaParameters">The public key reconstructed from the AK's exported modulus.</param>
    /// <param name="usePss">When <see langword="true"/>, quotes and verifies RSAPSS; otherwise RSASSA (PKCS#1 v1.5).</param>
    private async Task QuoteOverUnboundHmacSessionAndVerifyRsaAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse ak, RSAParameters rsaParameters, bool usePss)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
            using QuoteInput quoteInput = usePss
                ? QuoteInput.ForRsaPss(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool)
                : QuoteInput.ForRsaSsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

            TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, quoteInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            string schemeName = usePss ? "RSAPSS" : "RSASSA";
            Assert.IsTrue(quoteResult.IsSuccess, $"TPM2_Quote ({schemeName}, over an unbound HMAC session) failed: '{quoteResult.ResponseCode}'.");

            using QuoteResponse quote = quoteResult.Value;
            Assert.AreEqual(usePss ? TpmAlgIdConstants.TPM_ALG_RSAPSS : TpmAlgIdConstants.TPM_ALG_RSASSA, quote.SignatureAlgorithm);
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, quote.HashAlgorithm);

            TpmsAttest attest = quote.Quoted.AttestationData;
            Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attest.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
            Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_QUOTE, attest.Type);
            Assert.IsTrue(attest.ExtraData.Span.SequenceEqual(Nonce), "extraData must echo the caller's qualifyingData nonce.");
            Assert.IsNotNull(attest.Attested.Quote);

            byte[] expectedSignerQn = await ComputeQualifiedNameAsync(
                (uint)TpmRh.TPM_RH_ENDORSEMENT, ak.Name.Span.ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                attest.QualifiedSigner.Span.SequenceEqual(expectedSignerQn),
                "qualifiedSigner must equal the RSA AK's independently recomputed Qualified Name.");

            byte[] attestDigest = await ComputeSha256Async(quote.Quoted.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
            RSASignaturePadding padding = usePss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
            using RSA rsa = RSA.Create(rsaParameters);
            Assert.IsTrue(
                rsa.VerifyHash(attestDigest, quote.Signature.RsaSignature.Buffer.ToArray(), HashAlgorithmName.SHA256, padding),
                $"The {schemeName} quote signature must verify against the RSA AK's exported modulus, even when the sign slot was authorized over a real HMAC session.");

            byte[] expectedPcrDigest = await ReadAndComputePcrCompositeAsync(tpm, registry, pool, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
            Assert.IsTrue(
                attest.Attested.Quote!.PcrDigest.AsReadOnlySpan().SequenceEqual(expectedPcrDigest),
                "The quote's pcrDigest must equal the hash of the concatenated selected PCR values.");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Quotes the fixed PCR selection with <paramref name="ak"/> over a fresh, real, unbound/unsalted HMAC sign
    /// session carrying <paramref name="sessionAuthValue"/>, flushing the session on the way out — the
    /// single-slot mirror of the multi-slot HMAC-arm helpers the NV-certify suite composes, sized for
    /// <c>TPM2_Quote()</c>'s ONE authorized handle (TPM 2.0 Library Part 3, clause 18.4, Table 101).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <param name="sessionAuthValue">The authValue term folded into the sign session; empty leaves the session at its default empty authValue.</param>
    /// <returns>The Quote result, not asserted for success.</returns>
    private async Task<TpmResult<QuoteResponse>> QuoteOverUnboundHmacSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse ak, ReadOnlyMemory<byte> sessionAuthValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            if(!sessionAuthValue.IsEmpty)
            {
                session.SetAuthValue(sessionAuthValue.Span, pool);
            }

            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

            return await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, quoteInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the given hierarchy with the noDA attribute SET (dictionary
    /// attack exempt) and the non-empty <see cref="SignKeyPassword"/> retained authValue, and returns the
    /// response (the caller owns it) — the noDA contrast fixture the wrong-authValue proofs need, distinct from
    /// <see cref="CreateDaProtectedSigningPrimaryWithAuthAsync"/>'s DA-protected sibling.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateNoDaSigningPrimaryWithAuthAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy,
            password: SignKeyPassword,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (noDA ECC AK with authValue, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates the standard RSA endorsement-key-shaped decrypt key (RESTRICTED+DECRYPT, SHA-256 nameAlg) used as
    /// a salted session's RSA tpmKey — distinct from the RSA signing AK the RSA happy-path tests create.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaDecryptKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_OWNER, pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA decrypt key for salting) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Extends <see cref="CreateRegistry"/> with the StartAuthSession/FlushContext codecs the over-session tests need.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateHmacArmRegistry()
    {
        TpmResponseRegistry registry = CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>The digest width, in octets, of <see cref="HmacSessionAlg"/> (SHA-256) — the Zero Digest width an audit session's first extend starts from (TPM 2.0 Library Part 1, clause 17.1, equation 30).</summary>
    private const int AuditDigestSize = 32;

    /// <summary>
    /// Wraps a device whose transport records every submitted command's raw octets alongside the raw response
    /// octets the simulator returned, in submission order — the wire archaeology an audit digest's independent
    /// chain needs, firewalled to the wire with no back-channel into <see cref="TpmSession"/> or simulator
    /// internals.
    /// </summary>
    /// <param name="simulator">The simulator the recording transport forwards to.</param>
    /// <param name="pairs">The list each observed triple is appended to, in submission order.</param>
    /// <returns>A device the caller disposes; its transport records as a side effect of forwarding.</returns>
    private static TpmDevice CreateRecordingDevice(TpmSimulator simulator, List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs)
    {
        async ValueTask<TpmResult<TpmResponse>> RecordAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            byte[] commandBytes = command.ToArray();
            TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
            byte[] responseBytes = result.IsSuccess ? result.Value.AsReadOnlySpan().ToArray() : [];
            var commandReader = new TpmReader(commandBytes);
            TpmHeader commandHeader = TpmHeader.Parse(ref commandReader);
            pairs.Add(((TpmCcConstants)commandHeader.Code, commandBytes, responseBytes));

            return result;
        }

        return TpmDevice.Create(RecordAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
    }

    /// <summary>
    /// Serializes an input's parameter area alone — the octets a command sends after its handle area — by
    /// invoking the same <see cref="ITpmCommandInput.WriteParameters"/> the executor calls, a second time, over a
    /// freshly rented buffer: a pure marshal of the input's own immutable fields, not a read of any computed or
    /// cached wire state.
    /// </summary>
    /// <param name="input">The command input.</param>
    /// <param name="handleCount">The command's handle count, so the parameter area can be sized apart from the handle area.</param>
    /// <returns>The parameter octets, in the order <see cref="ITpmCommandInput.WriteParameters"/> writes them.</returns>
    private static byte[] SerializeCommandParameters(QuoteInput input, int handleCount)
    {
        int parametersSize = input.GetSerializedSize() - (handleCount * sizeof(uint));
        byte[] buffer = new byte[parametersSize];
        var writer = new TpmWriter(buffer);
        input.WriteParameters(ref writer);

        return buffer;
    }

    /// <summary>
    /// Reads the response parameter area out of a captured raw response's octets — the bytes rpHash (TPM 2.0
    /// Library Part 1, clause 15.8, equation 16) is computed over, as actually returned on the wire, independent
    /// of whatever the codec parsed them into.
    /// </summary>
    /// <param name="responseBytes">The raw response octets, tagged <c>TPM_ST_SESSIONS</c>.</param>
    /// <param name="outHandleCount">The number of output handles the response carries before its parameter area.</param>
    /// <returns>The response parameter octets.</returns>
    private static byte[] ReadResponseParameters(byte[] responseBytes, int outHandleCount)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < outHandleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint parameterSize = reader.ReadUInt32();

        return reader.ReadBytes((int)parameterSize).ToArray();
    }

    /// <summary>
    /// Reads one entry's <c>sessionAttributes</c> octet out of a captured raw response's authorization area — the
    /// octet Table 38's <c>audit</c>/<c>auditExclusive</c>/<c>auditReset</c> echo lands in and the response HMAC
    /// is computed over, walked directly off the wire rather than through any parsed session state.
    /// </summary>
    /// <param name="responseBytes">The raw response octets.</param>
    /// <param name="outHandleCount">The number of output handles preceding the parameter area.</param>
    /// <param name="sessionIndex">The zero-based position, in request order, of the session entry to read.</param>
    /// <returns>The entry's raw <c>sessionAttributes</c> octet.</returns>
    private static byte ReadResponseSessionAttributes(byte[] responseBytes, int outHandleCount, int sessionIndex)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < outHandleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint parameterSize = reader.ReadUInt32();
        _ = reader.ReadBytes((int)parameterSize);

        byte attributes = 0;
        for(int i = 0; i <= sessionIndex; i++)
        {
            ushort nonceLength = reader.ReadUInt16();
            _ = reader.ReadBytes(nonceLength);
            attributes = reader.ReadByte();
            ushort hmacLength = reader.ReadUInt16();
            _ = reader.ReadBytes(hmacLength);
        }

        return attributes;
    }

    /// <summary>
    /// Computes <c>cpHash = H_sessionAlg(commandCode ‖ Name1 ‖ Name2 ‖ … ‖ parameters)</c> (TPM 2.0 Library Part
    /// 1, clause 15.7, equation 15) over octets this test assembled itself from the command it sent.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="handleNames">The handle Names, in handle order.</param>
    /// <param name="parameters">The parameter area as sent.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The cpHash octets.</returns>
    private async Task<byte[]> ComputeCpHashAsync(TpmCcConstants commandCode, ReadOnlyMemory<byte>[] handleNames, ReadOnlyMemory<byte> parameters, BaseMemoryPool pool)
    {
        int namesLength = 0;
        foreach(ReadOnlyMemory<byte> name in handleNames)
        {
            namesLength += name.Length;
        }

        byte[] input = new byte[sizeof(uint) + namesLength + parameters.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, (uint)commandCode);
        int offset = sizeof(uint);
        foreach(ReadOnlyMemory<byte> name in handleNames)
        {
            name.Span.CopyTo(input.AsSpan(offset));
            offset += name.Length;
        }
        parameters.Span.CopyTo(input.AsSpan(offset));

        return await HashSha256Async(input, pool).ConfigureAwait(false);
    }

    /// <summary>
    /// Computes <c>rpHash = H_sessionAlg(TPM_RC_SUCCESS ‖ commandCode ‖ parameters)</c> (TPM 2.0 Library Part 1,
    /// clause 15.8, equation 16) over the response parameter octets as actually read off the wire.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="responseParameters">The response parameter area as read.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The rpHash octets.</returns>
    private async Task<byte[]> ComputeRpHashAsync(TpmCcConstants commandCode, ReadOnlyMemory<byte> responseParameters, BaseMemoryPool pool)
    {
        byte[] input = new byte[sizeof(uint) + sizeof(uint) + responseParameters.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, (uint)TpmRcConstants.TPM_RC_SUCCESS);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(sizeof(uint)), (uint)commandCode);
        responseParameters.Span.CopyTo(input.AsSpan(2 * sizeof(uint)));

        return await HashSha256Async(input, pool).ConfigureAwait(false);
    }

    /// <summary>
    /// Extends an audit session digest by one round: <c>H(old ‖ cpHash ‖ rpHash)</c>, with the Zero Digest of the
    /// session's hash width standing in for <paramref name="priorDigest"/> on the session's first use as an audit
    /// session (TPM 2.0 Library Part 1, clause 17.1, equation 30).
    /// </summary>
    /// <param name="priorDigest">The digest before this extend, or <see langword="null"/> on first use.</param>
    /// <param name="cpHash">The audited command's cpHash.</param>
    /// <param name="rpHash">The audited command's rpHash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The extended digest.</returns>
    private async Task<byte[]> ExtendAuditDigestAsync(byte[]? priorDigest, byte[] cpHash, byte[] rpHash, BaseMemoryPool pool)
    {
        byte[] old = priorDigest ?? new byte[AuditDigestSize];
        byte[] input = new byte[old.Length + cpHash.Length + rpHash.Length];
        old.CopyTo(input, 0);
        cpHash.CopyTo(input, old.Length);
        rpHash.CopyTo(input, old.Length + cpHash.Length);

        return await HashSha256Async(input, pool).ConfigureAwait(false);
    }

    /// <summary>Computes a raw SHA-256 digest over <paramref name="input"/> through the project's own digest primitive.</summary>
    /// <param name="input">The octets to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The digest octets.</returns>
    private async Task<byte[]> HashSha256Async(ReadOnlyMemory<byte> input, BaseMemoryPool pool)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input, AuditDigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }
}
