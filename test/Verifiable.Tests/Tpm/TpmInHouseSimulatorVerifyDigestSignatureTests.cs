using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_CreatePrimary()</c>, <c>TPM2_Sign()</c>, then <c>TPM2_VerifyDigestSignature()</c> against the
/// in-house behavioural <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the
/// same production command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="CreatePrimaryInput"/>, <see cref="SignInput"/>, <see cref="VerifyDigestSignatureInput"/>, and
/// response codecs).
/// </summary>
/// <remarks>
/// <para>
/// <c>TPM2_VerifyDigestSignature()</c> (TPM 2.0 Library Part 3, clause 20.4, Tables 120/121) is the digest-only
/// counterpart of <c>TPM2_VerifySignature()</c>: a public-key operation needing no authorization on
/// <c>keyHandle</c>, so every test here issues it with no sessions at all — the executor frames
/// <c>TPM_ST_NO_SESSIONS</c>, one of the two tags Table 120 admits for this command. Two rules distinguish it from
/// <c>TPM2_VerifySignature()</c>: the signing scheme (including the hash algorithm) in <c>signature</c> must match
/// the EXACT scheme of <c>keyHandle</c> (clause 20.4.1), not merely a compatible family, and a successful
/// verification returns a <c>TPMT_TK_VERIFIED</c> tagged <c>TPM_ST_DIGEST_VERIFIED</c> whose
/// <see cref="TpmtTkVerified.Metadata"/> carries the verified scheme's hash algorithm (TPM 2.0 Library Part 2,
/// clause 10.6.5, Table 111's <c>digestVerified</c> arm).
/// </para>
/// <para>
/// The happy-path test injects a fixed proof seed and independently reproduces the full Equation (5) ticket HMAC
/// — including the 2-octet metadata — from it, the same technique
/// <c>TpmInHouseSimulatorVerifySignatureTests.EcdsaVerifySignatureProducesAVerifiableTicket</c> uses for the
/// metadata-less <c>TPM_ST_VERIFIED</c> ticket.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorVerifyDigestSignatureTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate, an ECDSA r/s component, or a SHA-256 digest.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus size in bits used to size an RSA-shaped placeholder signature.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>A transient-range handle value for frames refused before handle resolution ever runs.</summary>
    private const uint ArbitraryKeyHandle = 0x8000_0001;

    /// <summary>The fixed message whose SHA-256 digest is signed and then verified.</summary>
    private static byte[] MessageBytes { get; } = "Verifiable in-house TPM VerifyDigestSignature acceptance test."u8.ToArray();

    /// <summary>A digest-shaped buffer of the wrong length for a SHA-256 scheme (16, not 32, octets).</summary>
    private static byte[] WrongSizedDigestBytes { get; } = new byte[16];

    /// <summary>A placeholder ECDSA signature (r ‖ s, both zero) for gates that reject before the verify delegate ever runs.</summary>
    private static byte[] PlaceholderEcdsaSignature { get; } = new byte[2 * P256ComponentSize];

    /// <summary>A placeholder RSA signature buffer sized to a 2048-bit modulus, for the same before-verify gates.</summary>
    private static byte[] PlaceholderRsaSignature { get; } = new byte[Rsa2048KeyBits / 8];

    /// <summary>A fixed seed standing in for the hierarchy's persistent random proof secret, injected to make the verified ticket reproducible.</summary>
    private static byte[] TicketSeed { get; } = Convert.FromHexString("A0B0C0D0E0F0102030405060708090A0B0C0D0E0F0102030405060708090A0");

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The happy path with the two-sided proof: a real ECDSA signature (produced by <c>TPM2_Sign()</c>) verifies,
    /// the returned ticket is tagged <c>TPM_ST_DIGEST_VERIFIED</c> with metadata SHA-256, and the ticket HMAC is
    /// independently reproduced from the injected proof seed — Equation (5),
    /// <c>HMAC_contextAlg(proof, tag ‖ digest ‖ keyName ‖ metadata)</c>, WITH the 2-octet metadata included
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.5) — proving the ticket is a genuine, verifiable HMAC
    /// bound to the seed and not an opaque value.
    /// </summary>
    [TestMethod]
    public async Task VerifyDigestSignatureHappyPathReproducesEquationFiveWithMetadataFromTheInjectedSeed()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateSeededOperationalAsync(TicketSeed, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] digest = SHA256.HashData(MessageBytes);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (ECDSA) failed: '{signResult.ResponseCode}'.");

        using SignResponse signature = signResult.Value;
        byte[] p1363Signature = ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan());

        using VerifyDigestSignatureInput verifyInput = VerifyDigestSignatureInput.ForEcdsa(
            primary.ObjectHandle, digest, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifyDigestSignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifyDigestSignature (ECDSA) failed: '{verifyResult.ResponseCode}'.");

        using VerifyDigestSignatureResponse verified = verifyResult.Value;
        Assert.AreEqual(TpmStConstants.TPM_ST_DIGEST_VERIFIED, verified.Validation.Tag, "The ticket tag must be TPM_ST_DIGEST_VERIFIED.");
        Assert.AreEqual(TpmiRhHierarchy.Owner, verified.Validation.Hierarchy, "The ticket hierarchy must be the verifying key's own hierarchy.");
        Assert.IsFalse(verified.Validation.IsNull, "A successful verification must return a real ticket, not a NULL ticket.");
        Assert.HasCount(P256ComponentSize, verified.Validation.Hmac, "The verified ticket HMAC is a SHA-256 HMAC.");
        Assert.IsTrue(verified.Validation.Metadata.HasValue, "A TPM_ST_DIGEST_VERIFIED ticket must carry metadata (Table 111's digestVerified arm).");
        Assert.AreEqual(
            TpmAlgIdConstants.TPM_ALG_SHA256, verified.Validation.Metadata!.Value.Value,
            "The ticket metadata must be the verified scheme's hash algorithm.");

        //Recompute the ticket exactly as TPM2_VerifyDigestSignature would: proof = H(seed || hierarchy), and the
        //ticket HMAC is HMAC(proof, TPM_ST_DIGEST_VERIFIED || digest || keyName || metadata) — Equation (5),
        //metadata INCLUDED, the two-sided proof.
        byte[] proof = SHA256.HashData(BuildProofInput(TicketSeed, (uint)TpmRh.TPM_RH_OWNER));
        byte[] ticketMessage = BuildDigestVerifiedTicketMessage(digest, primary.Name.Span, TpmAlgIdConstants.TPM_ALG_SHA256);
        byte[] expectedTicket = HMACSHA256.HashData(proof, ticketMessage);

        Assert.IsTrue(
            expectedTicket.AsSpan().SequenceEqual(verified.Validation.Hmac),
            "The verified ticket must be HMAC(H(seed || hierarchy), TPM_ST_DIGEST_VERIFIED || digest || keyName || metadata), verifiable against the injected seed.");
    }

    /// <summary>
    /// "The TPM will verify that the signing scheme (including the hash or XOF algorithm) in signature matches
    /// the signing scheme of keyHandle (TPM_RC_SCHEME)"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.4.1): a signature declaring SHA-384 against an ECC key
    /// whose RETAINED template scheme hash is SHA-256 is refused with <c>TPM_RC_SCHEME</c> — this exact-hash rule
    /// is stricter than <c>TPM2_VerifySignature()</c>'s own family match, which does not compare the hash at all.
    /// </summary>
    [TestMethod]
    public async Task VerifyDigestSignatureWithMismatchedHashAlgorithmReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] digest = SHA256.HashData(MessageBytes);

        using VerifyDigestSignatureInput verifyInput = VerifyDigestSignatureInput.ForEcdsa(
            primary.ObjectHandle, digest, PlaceholderEcdsaSignature, TpmAlgIdConstants.TPM_ALG_SHA384, pool);
        TpmResult<VerifyDigestSignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, verifyResult.ResponseCode, "A signature declaring SHA-384 against a SHA-256-schemed key must be refused with TPM_RC_SCHEME.");
    }

    /// <summary>
    /// The scheme-family counterpart of <see cref="VerifyDigestSignatureWithMismatchedHashAlgorithmReturnsScheme"/>:
    /// an RSASSA-shaped signature against an ECC key is refused with <c>TPM_RC_SCHEME</c> before the resolved
    /// scheme's hash is even compared
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.4.1).
    /// </summary>
    [TestMethod]
    public async Task VerifyDigestSignatureWithSchemeIncompatibleWithKeyTypeReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] digest = SHA256.HashData(MessageBytes);

        using VerifyDigestSignatureInput verifyInput = VerifyDigestSignatureInput.ForRsaSsa(
            primary.ObjectHandle, digest, PlaceholderRsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifyDigestSignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, verifyResult.ResponseCode, "An RSASSA-shaped signature against an ECC key must be refused with TPM_RC_SCHEME.");
    }

    /// <summary>
    /// The failure counterpart of the happy path: "Otherwise, the TPM shall return TPM_RC_SIGNATURE"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3, carried into clause 20.4 via the "is like
    /// TPM2_VerifySequenceComplete()" relation). A single flipped octet fails verification and produces no ticket
    /// at all.
    /// </summary>
    [TestMethod]
    public async Task VerifyDigestSignatureWithCorruptedSignatureReturnsSignature()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] digest = SHA256.HashData(MessageBytes);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (ECDSA) failed: '{signResult.ResponseCode}'.");

        using SignResponse signature = signResult.Value;
        byte[] p1363Signature = ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan());
        p1363Signature[^1] ^= 0xFF;

        using VerifyDigestSignatureInput verifyInput = VerifyDigestSignatureInput.ForEcdsa(
            primary.ObjectHandle, digest, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifyDigestSignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(verifyResult.IsSuccess, "A corrupted signature must not verify.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIGNATURE, verifyResult.ResponseCode);
    }

    /// <summary>
    /// "If the key is in the NULL hierarchy, then hmac in the ticket will be the Empty Buffer"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3, carried via the "is like" relation into clause 20.4;
    /// independently confirmed by clause 17's external-object rule). The NULL tuple still carries the verified
    /// scheme's hash algorithm as metadata [owner-flaggable — Table 111's <c>digestVerified</c> arm names a plain
    /// <c>TPMI_ALG_HASH</c> with no NULL admission, so the wire must carry a real hash id].
    /// </summary>
    [TestMethod]
    public async Task VerifyDigestSignatureAgainstANullHierarchyKeyReturnsTheNullTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_NULL).ConfigureAwait(false);
        byte[] digest = SHA256.HashData(MessageBytes);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (ECDSA, NULL hierarchy) failed: '{signResult.ResponseCode}'.");

        using SignResponse signature = signResult.Value;
        byte[] p1363Signature = ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan());

        using VerifyDigestSignatureInput verifyInput = VerifyDigestSignatureInput.ForEcdsa(
            primary.ObjectHandle, digest, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifyDigestSignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifyDigestSignature (NULL hierarchy key) failed: '{verifyResult.ResponseCode}'.");

        using VerifyDigestSignatureResponse verified = verifyResult.Value;
        Assert.AreEqual(TpmStConstants.TPM_ST_DIGEST_VERIFIED, verified.Validation.Tag, "The ticket tag must still be TPM_ST_DIGEST_VERIFIED.");
        Assert.IsTrue(verified.Validation.IsNull, "A NULL-hierarchy key's ticket must be the NULL tuple.");
        Assert.IsTrue(verified.Validation.Hierarchy.IsNull, "The ticket hierarchy must be TPM_RH_NULL.");
        Assert.IsTrue(verified.Validation.Hmac.IsEmpty, "The NULL ticket's hmac must be the Empty Buffer.");
        Assert.IsTrue(verified.Validation.Metadata.HasValue, "The NULL ticket must still carry metadata (Table 111's digestVerified arm admits no NULL selector).");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, verified.Validation.Metadata!.Value.Value, "The NULL ticket's metadata must be the verified scheme's hash algorithm.");
    }

    /// <summary>
    /// The digest-size sentence in clause 20.4 is textually identical to clause 20.7's: a digest shorter than the
    /// resolved scheme's hash width is refused with <c>TPM_RC_SIZE</c> [owner-flaggable basis: no RC named in
    /// clause 20.4 itself; Part 2 clause 4.16 / Part 3 clause 5.8's general size-parameter fallback]
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.4).
    /// </summary>
    [TestMethod]
    public async Task VerifyDigestSignatureWithMismatchedDigestSizeReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        using VerifyDigestSignatureInput verifyInput = VerifyDigestSignatureInput.ForEcdsa(
            primary.ObjectHandle, WrongSizedDigestBytes, PlaceholderEcdsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifyDigestSignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, verifyResult.ResponseCode, "A digest whose size mismatches the resolved scheme's hash width must be refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// The RSA counterpart of <see cref="VerifyDigestSignatureHappyPathReproducesEquationFiveWithMetadataFromTheInjectedSeed"/>,
    /// exercising <c>VerifyDigestSignatureRsaAsync</c> (no other test in this file drives an RSA key through this
    /// command): an RSA signing key created with an EXPLICIT RSASSA/SHA-256 template scheme signs via
    /// <c>TPM2_Sign()</c>, the resulting RSASSA signature verifies, the returned ticket is tagged
    /// <c>TPM_ST_DIGEST_VERIFIED</c> with metadata SHA-256, and the ticket HMAC is independently reproduced from
    /// the injected proof seed — Equation (5), WITH the 2-octet metadata included
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.5) — the same two-sided proof the ECC happy path
    /// gives.
    /// </summary>
    [TestMethod]
    public async Task VerifyDigestSignatureRsaHappyPathReproducesEquationFiveWithMetadataFromTheInjectedSeed()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateSeededOperationalAsync(TicketSeed, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (RSA 2048, RSASSA) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] digest = SHA256.HashData(MessageBytes);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForRsaSsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (RSASSA) failed: '{signResult.ResponseCode}'.");

        using SignResponse signature = signResult.Value;
        byte[] rsaSignature = signature.Signature.RsaSignature.Buffer.ToArray();

        using VerifyDigestSignatureInput verifyInput = VerifyDigestSignatureInput.ForRsaSsa(
            primary.ObjectHandle, digest, rsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifyDigestSignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifyDigestSignature (RSASSA) failed: '{verifyResult.ResponseCode}'.");

        using VerifyDigestSignatureResponse verified = verifyResult.Value;
        Assert.AreEqual(TpmStConstants.TPM_ST_DIGEST_VERIFIED, verified.Validation.Tag, "The ticket tag must be TPM_ST_DIGEST_VERIFIED.");
        Assert.AreEqual(TpmiRhHierarchy.Owner, verified.Validation.Hierarchy, "The ticket hierarchy must be the verifying key's own hierarchy.");
        Assert.IsFalse(verified.Validation.IsNull, "A successful verification must return a real ticket, not a NULL ticket.");
        Assert.HasCount(P256ComponentSize, verified.Validation.Hmac, "The verified ticket HMAC is a SHA-256 HMAC.");
        Assert.IsTrue(verified.Validation.Metadata.HasValue, "A TPM_ST_DIGEST_VERIFIED ticket must carry metadata (Table 111's digestVerified arm).");
        Assert.AreEqual(
            TpmAlgIdConstants.TPM_ALG_SHA256, verified.Validation.Metadata!.Value.Value,
            "The ticket metadata must be the verified scheme's hash algorithm.");

        //Recompute the ticket exactly as TPM2_VerifyDigestSignature would: proof = H(seed || hierarchy), and the
        //ticket HMAC is HMAC(proof, TPM_ST_DIGEST_VERIFIED || digest || keyName || metadata) — Equation (5),
        //metadata INCLUDED, the two-sided proof.
        byte[] proof = SHA256.HashData(BuildProofInput(TicketSeed, (uint)TpmRh.TPM_RH_OWNER));
        byte[] ticketMessage = BuildDigestVerifiedTicketMessage(digest, primary.Name.Span, TpmAlgIdConstants.TPM_ALG_SHA256);
        byte[] expectedTicket = HMACSHA256.HashData(proof, ticketMessage);

        Assert.IsTrue(
            expectedTicket.AsSpan().SequenceEqual(verified.Validation.Hmac),
            "The verified ticket must be HMAC(H(seed || hierarchy), TPM_ST_DIGEST_VERIFIED || digest || keyName || metadata), verifiable against the injected seed.");
    }

    /// <summary>
    /// "The scheme of keyHandle must be a signing scheme that supports signing a digest" — a storage parent's
    /// template scheme is <c>TPM_ALG_NULL</c> (its <c>sign</c> attribute is CLEAR too, but clause 20.4.1 states
    /// only the scheme rule; verification is a public-key operation, so the sign attribute is never consulted),
    /// so it retains no signing scheme to match against and is refused <c>TPM_RC_SCHEME</c> — clause 20.4.1's
    /// "nothing to match against" case
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.4.1).
    /// </summary>
    [TestMethod]
    public async Task VerifyDigestSignatureAgainstAnEccStorageParentHandleReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");

        using CreatePrimaryResponse parent = parentResult.Value;
        byte[] digest = SHA256.HashData(MessageBytes);

        using VerifyDigestSignatureInput verifyInput = VerifyDigestSignatureInput.ForEcdsa(
            parent.ObjectHandle, digest, PlaceholderEcdsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifyDigestSignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SCHEME, verifyResult.ResponseCode,
            "A storage parent's NULL template scheme retains none, so TPM2_VerifyDigestSignature() has nothing to match the signature's scheme against.");
    }

    /// <summary>
    /// A non-empty <c>context</c> is refused with <c>TPM_RC_SIZE</c>: Table 220's <c>empty[0]</c> arm is the only
    /// conformant value for either scheme this simulator resolves
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.7/11.3.8, Tables 220/221).
    /// <see cref="VerifyDigestSignatureInput"/> always frames an empty context, so this hand-frames the command —
    /// and reaches the check with a real resolved <c>keyHandle</c>, since handle resolution precedes the context
    /// check in the transition. The digest is CORRECTLY sized for the key's SHA-256 scheme (unlike
    /// <see cref="WrongSizedDigestBytes"/>) so this discriminates the context gate from the digest-size gate: were
    /// the context check removed, a correctly-sized digest would proceed past it to the placeholder signature's
    /// verification failure (<c>TPM_RC_SIGNATURE</c>), not <c>TPM_RC_SIZE</c>.
    /// </summary>
    [TestMethod]
    public async Task VerifyDigestSignatureWithNonEmptyContextReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] digest = SHA256.HashData(MessageBytes);

        byte[] nonEmptyContext = [0x01, 0x02, 0x03, 0x04];
        byte[] signatureBody = BuildEcdsaSignatureBody(TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, PlaceholderEcdsaSignature);

        TpmRcConstants code = await SubmitVerifyDigestSignatureCommandAsync(
            simulator, pool, primary.ObjectHandle.Value, nonEmptyContext, digest, signatureBody).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "A non-empty context must be refused with TPM_RC_SIZE (Table 220's empty[0] arm), ahead of the digest-size check.");
    }

    /// <summary>
    /// A <c>TPM_ST_SESSIONS</c>-tagged frame is refused with <c>TPM_RC_BAD_TAG</c> before any other read. Table
    /// 120 admits that tag on a TPM carrying an audit or decrypt session
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.4.2, Table 120), but this simulator models no audit or
    /// decrypt sessions for this command, so it fails closed on the tag — a deterministic refusal of the whole
    /// frame instead of misreading the authorization area's <c>authorizationSize</c> octets as the head of the
    /// <c>context</c> parameter.
    /// </summary>
    [TestMethod]
    public async Task VerifyDigestSignatureWithASessionsTagIsRefusedBadTag()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] digest = SHA256.HashData(MessageBytes);
        byte[] signatureBody = BuildEcdsaSignatureBody(TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, PlaceholderEcdsaSignature);

        TpmRcConstants code = await SubmitVerifyDigestSignatureCommandAsync(
            simulator, pool, ArbitraryKeyHandle, [], digest, signatureBody, (ushort)TpmStConstants.TPM_ST_SESSIONS).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_TAG, code, "A TPM_ST_SESSIONS frame must be refused with TPM_RC_BAD_TAG at the tag gate, before any handle or parameter read.");
    }

    /// <summary>
    /// The <c>TPM2_VerifyDigestSignature()</c> arm of the shared ECDSA rebuild: a <c>signatureR</c> carried with an
    /// extra leading zero octet encodes the same integer and verifies (TPM 2.0 Library Part 3, clause 20.4; Part
    /// 2, clause 11.3.2, Table 214; clause 11.2.5.1, Table 197).
    /// </summary>
    [TestMethod]
    public async Task VerifyDigestSignatureAcceptsASignatureRWithALeadingZeroOctetAsTheSameInteger()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] digest = SHA256.HashData(MessageBytes);
        (byte[] r, byte[] s) = await SignEcdsaComponentsAsync(tpm, registry, pool, primary.ObjectHandle, digest).ConfigureAwait(false);

        byte[] zeroPaddedR = [0x00, .. ToFixed(r, P256ComponentSize)];
        byte[] body = BuildEcdsaSignatureBodyFromComponents(TpmAlgIdConstants.TPM_ALG_SHA256, zeroPaddedR, ToFixed(s, P256ComponentSize));

        TpmRcConstants code = await SubmitVerifyDigestSignatureCommandAsync(simulator, pool, primary.ObjectHandle.Value, [], digest, body).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "A signatureR with an insignificant leading zero octet encodes the same integer and must verify (Table 214/197).");
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the given hierarchy, with an empty authValue, and returns
    /// the response (the caller owns it).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Concatenates the ECDSA r and s components into the IEEE P1363 <c>r ‖ s</c> form
    /// <see cref="VerifyDigestSignatureInput.ForEcdsa"/> takes, left-padding each to the P-256 field width.
    /// </summary>
    /// <param name="r">The signature's r component.</param>
    /// <param name="s">The signature's s component.</param>
    /// <returns>The concatenated, fixed-width P1363 signature.</returns>
    private static byte[] ConcatenateP1363(ReadOnlySpan<byte> r, ReadOnlySpan<byte> s)
    {
        byte[] result = new byte[2 * P256ComponentSize];
        ToFixed(r, P256ComponentSize).CopyTo(result.AsSpan(0));
        ToFixed(s, P256ComponentSize).CopyTo(result.AsSpan(P256ComponentSize));

        return result;
    }

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers it
    /// on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-verify-digest-signature",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Creates a simulator wired with a caller-injected hierarchy proof seed (making its tickets independently
    /// reproducible) and BOTH signing backends, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c>
    /// into the operational phase.
    /// </summary>
    /// <param name="seed">The proof seed to inject.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateSeededOperationalAsync(byte[] seed, BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-verify-digest-signature-seed",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(),
            seed: seed);
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
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifyDigestSignature, TpmResponseCodec.VerifyDigestSignature);

        return registry;
    }

    /// <summary>Builds the ticket proof-derivation input: the seed followed by the hierarchy handle.</summary>
    /// <param name="seed">The TPM seed.</param>
    /// <param name="hierarchy">The hierarchy handle.</param>
    /// <returns>The proof-derivation input bytes.</returns>
    private static byte[] BuildProofInput(byte[] seed, uint hierarchy)
    {
        byte[] input = new byte[seed.Length + sizeof(uint)];
        var writer = new TpmWriter(input);
        writer.WriteBytes(seed);
        writer.WriteUInt32(hierarchy);

        return input;
    }

    /// <summary>
    /// Builds the <c>TPM_ST_DIGEST_VERIFIED</c> ticket HMAC message: tag (UINT16) followed by the digest, the
    /// verifying key's Name, and the 2-octet metadata hash algorithm — Equation (5), TPM 2.0 Library Part 2,
    /// clause 10.6.5, WITH metadata (unlike the metadata-less <c>TPM_ST_VERIFIED</c> message).
    /// </summary>
    /// <param name="digest">The digest the signature was claimed to be over.</param>
    /// <param name="keyName">The verifying key's Name.</param>
    /// <param name="metadataHashAlg">The verified scheme's hash algorithm.</param>
    /// <returns>The ticket message bytes.</returns>
    private static byte[] BuildDigestVerifiedTicketMessage(ReadOnlySpan<byte> digest, ReadOnlySpan<byte> keyName, TpmAlgIdConstants metadataHashAlg)
    {
        byte[] message = new byte[sizeof(ushort) + digest.Length + keyName.Length + sizeof(ushort)];
        var writer = new TpmWriter(message);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_DIGEST_VERIFIED);
        writer.WriteBytes(digest);
        writer.WriteBytes(keyName);
        writer.WriteUInt16((ushort)metadataHashAlg);

        return message;
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_VerifyDigestSignature()</c> command whose header tag and <c>context</c> body are
    /// supplied verbatim, bypassing <see cref="VerifyDigestSignatureInput"/> (which always frames an empty
    /// context under <c>TPM_ST_NO_SESSIONS</c>). This command authorizes no entity (TPM 2.0 Library Part 3,
    /// clause 20.4); no handle area authorization — <c>keyHandle</c> alone.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The header tag octets, written verbatim.</param>
    /// <param name="keyHandle">The <c>keyHandle</c> handle value.</param>
    /// <param name="context">The <c>context</c> parameter's octets, written verbatim as a TPM2B.</param>
    /// <param name="digest">The <c>digest</c> parameter's octets.</param>
    /// <param name="signatureBody">The already-marshaled <c>TPMT_SIGNATURE</c> body, verbatim.</param>
    /// <param name="length">The framed command's total length.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameVerifyDigestSignatureCommand(
        BaseMemoryPool pool, ushort tag, uint keyHandle, ReadOnlySpan<byte> context, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signatureBody, out int length)
    {
        length =
            TpmHeader.HeaderSize
            + sizeof(uint)                     //Handle area: keyHandle (no authorization area).
            + sizeof(ushort) + context.Length  //TPM2B_SIGNATURE_CTX.
            + sizeof(ushort) + digest.Length   //TPM2B_DIGEST.
            + signatureBody.Length;            //TPMT_SIGNATURE.

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader(tag, (uint)length, (uint)TpmCcConstants.TPM_CC_VerifyDigestSignature);
            header.WriteTo(ref writer);
            writer.WriteUInt32(keyHandle);
            writer.WriteTpm2b(context);
            writer.WriteTpm2b(digest);
            writer.WriteBytes(signatureBody);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_VerifyDigestSignature()</c> built by
    /// <see cref="FrameVerifyDigestSignatureCommand"/> straight to the simulator (bypassing
    /// <see cref="TpmCommandExecutor"/>) and yields the response code.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The <c>keyHandle</c> handle value.</param>
    /// <param name="context">The <c>context</c> parameter's octets.</param>
    /// <param name="digest">The <c>digest</c> parameter's octets.</param>
    /// <param name="signatureBody">The already-marshaled <c>TPMT_SIGNATURE</c> body, verbatim.</param>
    /// <param name="tag">The header tag octets; <c>TPM_ST_NO_SESSIONS</c> when omitted, the form the typed input frames.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitVerifyDigestSignatureCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint keyHandle, byte[] context, byte[] digest, byte[] signatureBody, ushort tag = (ushort)TpmStConstants.TPM_ST_NO_SESSIONS)
    {
        using IMemoryOwner<byte> commandOwner = FrameVerifyDigestSignatureCommand(pool, tag, keyHandle, context, digest, signatureBody, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// Builds an ECDSA <c>TPMT_SIGNATURE</c> body: sigAlg, hashAlg, then signatureR and signatureS as equal-width
    /// halves of <paramref name="p1363Signature"/>, each an independent TPM2B.
    /// </summary>
    /// <param name="sigAlg">The signature algorithm selector.</param>
    /// <param name="hashAlg">The hash algorithm carried inside the member.</param>
    /// <param name="p1363Signature">The IEEE P1363 r ‖ s signature octets.</param>
    /// <returns>The marshaled body.</returns>
    private static byte[] BuildEcdsaSignatureBody(TpmAlgIdConstants sigAlg, TpmAlgIdConstants hashAlg, ReadOnlySpan<byte> p1363Signature)
    {
        int fieldWidth = p1363Signature.Length / 2;
        byte[] body = new byte[2 * sizeof(ushort) + sizeof(ushort) + fieldWidth + sizeof(ushort) + fieldWidth];
        var writer = new TpmWriter(body);
        writer.WriteUInt16((ushort)sigAlg);
        writer.WriteUInt16((ushort)hashAlg);
        writer.WriteTpm2b(p1363Signature[..fieldWidth]);
        writer.WriteTpm2b(p1363Signature[fieldWidth..]);

        return body;
    }

    /// <summary>
    /// Left-pads a big-endian integer to a fixed width, as the IEEE P1363 encoding requires. The simulator
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
            value[^length..].CopyTo(result);
        }

        return result;
    }

    /// <summary>
    /// Signs <paramref name="digest"/> through <c>TPM2_Sign()</c> over an empty-password session and returns the
    /// ECDSA components exactly as the TPM answered them, unpadded.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The ECDSA signing key handle.</param>
    /// <param name="digest">The digest to sign.</param>
    /// <returns>The <c>signatureR</c> and <c>signatureS</c> octets.</returns>
    private async Task<(byte[] R, byte[] S)> SignEcdsaComponentsAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] digest)
    {
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(keyHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (ECDSA) failed: '{signResult.ResponseCode}'.");

        using SignResponse signature = signResult.Value;

        return (signature.Signature.SignatureR!.AsReadOnlySpan().ToArray(), signature.Signature.SignatureS!.AsReadOnlySpan().ToArray());
    }

    /// <summary>
    /// Builds an ECDSA <c>TPMT_SIGNATURE</c> body — sigAlg, hashAlg, then <c>signatureR</c> and <c>signatureS</c>
    /// each as its own TPM2B — from two independently sized components, exactly as Table 214 frames them.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm carried inside the member.</param>
    /// <param name="signatureR">The <c>signatureR</c> octets, written verbatim.</param>
    /// <param name="signatureS">The <c>signatureS</c> octets, written verbatim.</param>
    /// <returns>The marshaled body.</returns>
    private static byte[] BuildEcdsaSignatureBodyFromComponents(TpmAlgIdConstants hashAlg, ReadOnlySpan<byte> signatureR, ReadOnlySpan<byte> signatureS)
    {
        byte[] body = new byte[2 * sizeof(ushort) + sizeof(ushort) + signatureR.Length + sizeof(ushort) + signatureS.Length];
        var writer = new TpmWriter(body);
        writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_ECDSA);
        writer.WriteUInt16((ushort)hashAlg);
        writer.WriteTpm2b(signatureR);
        writer.WriteTpm2b(signatureS);

        return body;
    }
}
