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
/// Drives <c>TPM2_CreatePrimary()</c>, <c>TPM2_Sign()</c>, then <c>TPM2_VerifySignature()</c> against the
/// in-house behavioural <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the
/// same production command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="CreatePrimaryInput"/>, <see cref="SignInput"/>, <see cref="VerifySignatureInput"/>, and response
/// codecs).
/// </summary>
/// <remarks>
/// <para>
/// <c>TPM2_VerifySignature()</c> is a public-key operation (TPM 2.0 Library Part 3, clause 20.2): unlike every
/// other command this simulator signs with, the key referenced by <c>keyHandle</c> needs no authorization and
/// the effect never consults its <c>sign</c> attribute. A successful verification returns a
/// <c>TPMT_TK_VERIFIED</c> whose HMAC folds <c>TPM_ST_VERIFIED || digest || keyName</c> under the verifying key's
/// hierarchy proof — the field-order mirror of the creation ticket's <c>name || creationHash</c>.
/// </para>
/// <para>
/// The ECC positive test injects a fixed proof seed and independently reproduces the ticket HMAC from it, proving
/// the ticket is a genuine, verifiable HMAC bound to the injected seed rather than an opaque or stubbed value —
/// the same technique <c>TpmInHouseSimulatorSignTests.CreationTicketIsAVerifiableHmacOfTheInjectedSeed</c> uses
/// for the creation ticket.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorVerifySignatureTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate, an ECDSA r/s component, or a SHA-256 digest.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus size in bits used by the RSA verify-signature tests.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>
    /// A transient handle value naming no loaded object in a freshly-brought-operational simulator — stands in
    /// for <c>@keyHandle</c> in tests whose refusal fires at the parse (or is otherwise independent of the
    /// handle actually resolving).
    /// </summary>
    private const uint ArbitraryKeyHandle = 0x8000_0001;

    /// <summary>
    /// The bound on signatures drawn while looking for one whose <c>signatureS</c> starts with a zero octet: the
    /// chance is one in 256 per signature, so the bound is missed with probability under e^-16.
    /// </summary>
    private const int MaxSigningAttemptsForALeadingZero = 4096;

    /// <summary>The fixed message whose SHA-256 digest is signed and then verified.</summary>
    private static byte[] MessageBytes { get; } = "Verifiable in-house TPM VerifySignature acceptance test."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies a full ECDSA P-256 round trip through <c>TPM2_Sign()</c> then <c>TPM2_VerifySignature()</c>, and
    /// independently reproduces the returned <c>TPMT_TK_VERIFIED</c> HMAC from the injected proof seed — proving
    /// it is a real HMAC over <c>TPM_ST_VERIFIED || digest || keyName</c> bound to that seed (TPM 2.0 Library
    /// Part 3, clause 20.2; Part 2, clause 10.6.5), not a placeholder.
    /// </summary>
    [TestMethod]
    public async Task EcdsaVerifySignatureProducesAVerifiableTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //A fixed seed stands in for the hierarchy's persistent random proof secret; injecting it makes the
        //verified ticket reproducible and lets this test recompute it.
        byte[] seed = Convert.FromHexString("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");

        using var simulator = new TpmSimulator("tpm-in-house-verify-signature-seed", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), seed: seed);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);
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

        //VerifySignature carries no authorization at all: keyHandle needs none (a public-key operation), so the
        //executor is given no sessions and frames TPM_ST_NO_SESSIONS.
        using VerifySignatureInput verifyInput = VerifySignatureInput.ForEcdsa(primary.ObjectHandle, digest, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifySignature (ECDSA) failed: '{verifyResult.ResponseCode}'.");

        using VerifySignatureResponse verified = verifyResult.Value;
        Assert.AreEqual(TpmStConstants.TPM_ST_VERIFIED, verified.Validation.Tag, "The ticket tag must be TPM_ST_VERIFIED.");
        Assert.AreEqual(TpmiRhHierarchy.Owner, verified.Validation.Hierarchy, "The ticket hierarchy must be the signing key's own hierarchy.");
        Assert.IsFalse(verified.Validation.IsNull, "A successful verification must return a real ticket, not a NULL ticket.");
        Assert.HasCount(P256ComponentSize, verified.Validation.Hmac, "The verified ticket digest is a SHA-256 HMAC.");

        //Recompute the ticket exactly as TPM2_VerifySignature would: the proof is H(seed || hierarchy), and the
        //ticket digest is HMAC(proof, TPM_ST_VERIFIED || digest || keyName) — the mirror image of the creation
        //ticket's TPM_ST_CREATION || name || creationHash order. A match proves the ticket is a real, verifiable
        //HMAC bound to the injected seed, not an opaque or stubbed value.
        byte[] proof = SHA256.HashData(BuildProofInput(seed, (uint)TpmRh.TPM_RH_OWNER));
        byte[] ticketMessage = BuildVerifiedTicketMessage(digest, primary.Name.Span);
        byte[] expectedTicket = HMACSHA256.HashData(proof, ticketMessage);

        Assert.IsTrue(
            expectedTicket.AsSpan().SequenceEqual(verified.Validation.Hmac),
            "The verified ticket must be HMAC(H(seed || hierarchy), TPM_ST_VERIFIED || digest || keyName), verifiable against the injected seed.");
    }

    /// <summary>
    /// Verifies RSA signatures under both RSASSA and RSAPSS through <c>TPM2_Sign()</c> then
    /// <c>TPM2_VerifySignature()</c>, asserting the returned ticket is structurally sound (TPM 2.0 Library Part 3,
    /// clause 20.2).
    /// </summary>
    [TestMethod]
    public async Task RsaVerifySignatureAcceptsRsaSsaAndRsaPssSignatures()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //A NULL scheme makes this an unrestricted signing key, so the scheme (RSASSA or RSAPSS) is chosen per
        //TPM2_Sign() / TPM2_VerifySignature() — both are exercised against one (expensive) RSA key generation.
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Null, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (RSA 2048) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] digest = SHA256.HashData(MessageBytes);

        await SignAndVerifyRsaAsync(tpm, registry, pool, primary.ObjectHandle, digest, usePss: false).ConfigureAwait(false);
        await SignAndVerifyRsaAsync(tpm, registry, pool, primary.ObjectHandle, digest, usePss: true).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that a signature with one flipped octet fails verification: "Otherwise, the TPM shall return
    /// TPM_RC_SIGNATURE" (TPM 2.0 Library Part 3, clause 20.2).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithCorruptedSignatureReturnsSignature()
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

        //Flip one octet of the signature (part of the s component) so it no longer verifies against the digest.
        p1363Signature[^1] ^= 0xFF;

        using VerifySignatureInput verifyInput = VerifySignatureInput.ForEcdsa(primary.ObjectHandle, digest, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIGNATURE, verifyResult.ResponseCode);
    }

    /// <summary>
    /// "If the key is in the NULL hierarchy, then hmac in the ticket will be the Empty Buffer"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.2.1) — the ECC-VerifySignature counterpart of
    /// <c>TpmInHouseSimulatorVerifyDigestSignatureTests.VerifyDigestSignatureAgainstANullHierarchyKeyReturnsTheNullTicket</c>:
    /// a primary created under <c>TPM_RH_NULL</c> signs, and <c>TPM2_VerifySignature()</c> succeeds with the
    /// NULL <c>TPM_ST_VERIFIED</c> ticket (empty hmac, hierarchy <c>TPM_RH_NULL</c>) rather than minting a real
    /// HMAC over an unvetted key.
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureAgainstANullHierarchyKeyReturnsTheNullTicket()
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

        using VerifySignatureInput verifyInput = VerifySignatureInput.ForEcdsa(primary.ObjectHandle, digest, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifySignature (NULL hierarchy key) failed: '{verifyResult.ResponseCode}'.");

        using VerifySignatureResponse verified = verifyResult.Value;
        Assert.AreEqual(TpmStConstants.TPM_ST_VERIFIED, verified.Validation.Tag, "The ticket tag must still be TPM_ST_VERIFIED.");
        Assert.IsTrue(verified.Validation.IsNull, "A NULL-hierarchy key's ticket must be the NULL tuple.");
        Assert.IsTrue(verified.Validation.Hierarchy.IsNull, "The ticket hierarchy must be TPM_RH_NULL.");
        Assert.IsTrue(verified.Validation.Hmac.IsEmpty, "The NULL ticket's hmac must be the Empty Buffer.");
        Assert.IsFalse(verified.Validation.Metadata.HasValue, "TPM_ST_VERIFIED selects Table 111's TPMS_EMPTY arm; the ticket carries no metadata.");
    }

    /// <summary>
    /// Verifies that an RSA-shaped signature against an ECC key is rejected: the signature algorithm must be
    /// compatible with the resolved key's type (TPM_RC_SCHEME on mismatch, mirroring TPM2_Certify()'s dispatch).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithSchemeIncompatibleWithKeyTypeReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] digest = SHA256.HashData(MessageBytes);

        //An RSASSA-shaped signature against an ECC key: rejected before the verify delegate is ever consulted, so
        //the placeholder signature bytes need not be genuine.
        byte[] placeholderSignature = new byte[Rsa2048KeyBits / 8];
        using VerifySignatureInput verifyInput = VerifySignatureInput.ForRsaSsa(primary.ObjectHandle, digest, placeholderSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, verifyResult.ResponseCode);
    }

    /// <summary>
    /// Verifies that an unknown <c>keyHandle</c> is rejected: no transient object resolves to it (TPM 2.0 Library
    /// Part 3, clause 20.2).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithUnknownKeyHandleReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //No key was created, so the transient handle does not resolve.
        byte[] digest = SHA256.HashData(MessageBytes);
        byte[] placeholderSignature = new byte[2 * P256ComponentSize];
        using VerifySignatureInput verifyInput = VerifySignatureInput.ForEcdsa(
            TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase), digest, placeholderSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, verifyResult.ResponseCode);
    }

    /// <summary>
    /// A <c>signature.sigAlg</c> of <c>TPM_ALG_NULL</c> is refused with <c>TPM_RC_SCHEME</c> at the wire, before
    /// any handle resolves. <c>TPMT_SIGNATURE.sigAlg</c> is itself marked <c>+TPMI_ALG_SIG_SCHEME</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.6, Table 219), so the general structure admits a
    /// NULL selector — but Table 219's own note requires <c>[sigAlg]signature</c> to be "the actual signature
    /// information", and a NULL selector picks no <c>TPMU_SIGNATURE</c> member at all, so there is none to
    /// verify: <c>TPM2_VerifySignature()</c>'s <c>signature</c> parameter needs a genuine signature, unlike
    /// <c>TPM2_Sign()</c>'s <c>inScheme</c> (a <c>TPMT_SIG_SCHEME</c>, Table 183 — a request for a scheme, not
    /// itself a signature value), where NULL legitimately asks for the key's default.
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithNullSigAlgReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] digest = new byte[P256ComponentSize];
        byte[] body = BuildSigAlgOnlyBody(TpmAlgIdConstants.TPM_ALG_NULL);

        TpmRcConstants code = await SubmitVerifySignatureCommandAsync(simulator, pool, ArbitraryKeyHandle, digest, body).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, code, "A NULL signature.sigAlg must be refused at the wire (Table 219).");
    }

    /// <summary>
    /// A <c>signature.sigAlg</c> naming an algorithm that is not a signing scheme at all (a hash algorithm ID)
    /// is refused with <c>TPM_RC_SCHEME</c>, the same as an unadmitted selector value
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.6, Table 219).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithUnsupportedSigAlgReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] digest = new byte[P256ComponentSize];
        byte[] body = BuildSigAlgOnlyBody(TpmAlgIdConstants.TPM_ALG_SHA256);

        TpmRcConstants code = await SubmitVerifySignatureCommandAsync(simulator, pool, ArbitraryKeyHandle, digest, body).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, code, "A sigAlg naming no signing scheme at all must be refused (Table 219).");
    }

    /// <summary>
    /// An ECDSA <c>signatureR</c> declaring more than <see cref="Tpm2bEccParameter.MaxSize"/> is refused with
    /// <c>TPM_RC_SIZE</c> (TPM 2.0 Library Part 2, clause 11.3.2, Table 214's <c>signatureR</c>, itself a
    /// <c>TPM2B_ECC_PARAMETER</c>, clause 11.2.5.1, Table 197) — even though the parse never resolves
    /// <c>keyHandle</c>.
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithSignatureROverBoundReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] digest = new byte[P256ComponentSize];
        byte[] body = BuildEcdsaSignatureBody(
            TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256,
            declaredRSize: (ushort)(Tpm2bEccParameter.MaxSize + 1), actualRBytesProvided: Tpm2bEccParameter.MaxSize + 1,
            declaredSSize: P256ComponentSize, actualSBytesProvided: P256ComponentSize);

        TpmRcConstants code = await SubmitVerifySignatureCommandAsync(simulator, pool, ArbitraryKeyHandle, digest, body).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "signatureR over Tpm2bEccParameter.MaxSize must be TPM_RC_SIZE (Table 214/197).");
    }

    /// <summary>The <c>signatureS</c> counterpart of <see cref="VerifySignatureWithSignatureROverBoundReturnsSize"/>.</summary>
    [TestMethod]
    public async Task VerifySignatureWithSignatureSOverBoundReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] digest = new byte[P256ComponentSize];
        byte[] body = BuildEcdsaSignatureBody(
            TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256,
            declaredRSize: P256ComponentSize, actualRBytesProvided: P256ComponentSize,
            declaredSSize: (ushort)(Tpm2bEccParameter.MaxSize + 1), actualSBytesProvided: Tpm2bEccParameter.MaxSize + 1);

        TpmRcConstants code = await SubmitVerifySignatureCommandAsync(simulator, pool, ArbitraryKeyHandle, digest, body).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "signatureS over Tpm2bEccParameter.MaxSize must be TPM_RC_SIZE (Table 214/197).");
    }

    /// <summary>
    /// An RSA <c>rsaSignature</c> declaring more than <see cref="Tpm2bPublicKeyRsa.MaxRsaKeyBytes"/> is refused
    /// with <c>TPM_RC_SIZE</c> (TPM 2.0 Library Part 2, clause 11.3.1, Table 212's <c>sig</c>, itself a
    /// <c>TPM2B_PUBLIC_KEY_RSA</c>, clause 11.2.4.5, Table 194).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithRsaSignatureOverBoundReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] digest = new byte[P256ComponentSize];
        byte[] body = BuildRsaSignatureBody(
            TpmAlgIdConstants.TPM_ALG_RSASSA, TpmAlgIdConstants.TPM_ALG_SHA256,
            declaredSigSize: (ushort)(Tpm2bPublicKeyRsa.MaxRsaKeyBytes + 1), actualSigBytesProvided: Tpm2bPublicKeyRsa.MaxRsaKeyBytes + 1);

        TpmRcConstants code = await SubmitVerifySignatureCommandAsync(simulator, pool, ArbitraryKeyHandle, digest, body).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "rsaSignature over Tpm2bPublicKeyRsa.MaxRsaKeyBytes must be TPM_RC_SIZE (Table 212/194).");
    }

    /// <summary>
    /// A <c>signatureR</c> that is BOTH over <see cref="Tpm2bEccParameter.MaxSize"/> AND truncated (the frame
    /// carries fewer octets than declared) is refused with <c>TPM_RC_SIZE</c>, not <c>TPM_RC_INSUFFICIENT</c>:
    /// the declared size is checked against the bound before the remaining-octets probe (bound-before-truncation,
    /// the same bound-before-truncation order extended here to the signature fields).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithOverBoundAndTruncatedSignatureRReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] digest = new byte[P256ComponentSize];
        byte[] body = BuildEcdsaSignatureBody(
            TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256,
            declaredRSize: Tpm2bEccParameter.MaxSize + 68, actualRBytesProvided: 10,
            declaredSSize: 0, actualSBytesProvided: 0);

        TpmRcConstants code = await SubmitVerifySignatureCommandAsync(simulator, pool, ArbitraryKeyHandle, digest, body).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "An over-bound signatureR is TPM_RC_SIZE even when the frame is also too short to supply it.");
    }

    /// <summary>
    /// The within-bound complement of <see cref="VerifySignatureWithOverBoundAndTruncatedSignatureRReturnsSize"/>:
    /// a <c>signatureR</c> declared WITHIN <see cref="Tpm2bEccParameter.MaxSize"/> but whose frame carries fewer
    /// octets than declared is refused with <c>TPM_RC_INSUFFICIENT</c>, not <c>TPM_RC_SIZE</c> — pinning the
    /// truncation leg of bound-before-truncation, not just its bound-wins-when-both-fire compound case.
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithWithinBoundTruncatedSignatureRReturnsInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] digest = new byte[P256ComponentSize];
        byte[] body = BuildEcdsaSignatureBody(
            TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256,
            declaredRSize: P256ComponentSize, actualRBytesProvided: 10,
            declaredSSize: 0, actualSBytesProvided: 0);

        TpmRcConstants code = await SubmitVerifySignatureCommandAsync(simulator, pool, ArbitraryKeyHandle, digest, body).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_INSUFFICIENT, code,
            "A within-bound signatureR whose frame is too short to supply it is TPM_RC_INSUFFICIENT, not TPM_RC_SIZE.");
    }

    /// <summary>
    /// An ECDSA <c>signatureR</c>/<c>signatureS</c> pair whose independently-bounded, independently-supplied
    /// lengths combine to an ODD total is accepted at the wire, not refused with <c>TPM_RC_SIZE</c>: Table 214
    /// relates neither field's size to the other (each is independently leading-zero-stripped) — the simulator's
    /// own remarks note "TPM2B integers that may omit leading zero bytes" — so a wire-valid pair like this must
    /// parse cleanly through to the next check (here <c>TPM_RC_HANDLE</c>, from the unresolved key).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithOddCombinedSignatureRAndSLengthDoesNotReturnSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] digest = new byte[P256ComponentSize];
        byte[] body = BuildEcdsaSignatureBody(
            TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256,
            declaredRSize: P256ComponentSize, actualRBytesProvided: P256ComponentSize,
            declaredSSize: P256ComponentSize - 1, actualSBytesProvided: P256ComponentSize - 1);

        TpmRcConstants code = await SubmitVerifySignatureCommandAsync(simulator, pool, ArbitraryKeyHandle, digest, body).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_HANDLE, code,
            "An ECDSA signature whose r and s independently-supplied lengths combine to an odd total must parse cleanly, reaching the unresolved-handle check rather than being refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// Proves the pooled-carrier ownership of <c>TPM2_VerifySignature()</c>'s signature against an ABSOLUTE
    /// metered-pool baseline: an over-bound <c>signatureR</c> rents nothing (the shared body parser refuses on
    /// the declared size alone, before <see cref="TpmtSignature.Create"/> is ever reached), and a refusal AFTER a
    /// genuinely non-empty, in-bound signature has been fully rented (unknown <c>keyHandle</c>) releases it
    /// through <see cref="TpmVerifySignatureRequested.Dispose"/>.
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureOverBoundSignatureRRefusalBalancesThePool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        byte[] digest = new byte[P256ComponentSize];
        byte[] body = BuildEcdsaSignatureBody(
            TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256,
            declaredRSize: (ushort)(Tpm2bEccParameter.MaxSize + 1), actualRBytesProvided: Tpm2bEccParameter.MaxSize + 1,
            declaredSSize: 0, actualSBytesProvided: 0);

        TpmRcConstants code = await SubmitVerifySignatureCommandAsync(simulator, trackingPool.Pool, ArbitraryKeyHandle, digest, body).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "An over-bound signatureR must still answer TPM_RC_SIZE under the metered pool.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The parser must rent nothing for a signatureR it refuses on its declared size alone.");
    }

    /// <summary>
    /// A genuinely non-empty, in-bound signature parses cleanly (both the digest and the <c>TpmtSignature</c> are
    /// rented as the parse's last acts), then <c>OnVerifySignature</c> refuses the unresolved <c>keyHandle</c>
    /// with <c>TPM_RC_HANDLE</c> and releases both carriers through <see cref="TpmVerifySignatureRequested.Dispose"/>
    /// — including the signature, not merely the digest.
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithUnknownKeyHandleReleasesTheParsedSignature()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        byte[] digest = new byte[P256ComponentSize];
        byte[] body = BuildEcdsaSignatureBody(
            TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256,
            declaredRSize: P256ComponentSize, actualRBytesProvided: P256ComponentSize,
            declaredSSize: P256ComponentSize, actualSBytesProvided: P256ComponentSize);

        TpmRcConstants code = await SubmitVerifySignatureCommandAsync(simulator, trackingPool.Pool, ArbitraryKeyHandle, digest, body).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, code, "An unknown keyHandle must be refused after a clean parse.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The TPM_RC_HANDLE refusal must release the parsed digest and signature carriers alike.");
    }

    /// <summary>
    /// An ECDSA <c>signatureR</c> carried with an extra leading zero octet (33 octets for P-256) verifies exactly
    /// as its 32-octet form does: each of <c>signatureR</c>/<c>signatureS</c> is a <c>TPM2B_ECC_PARAMETER</c>
    /// integer whose leading zero octets are insignificant, and Table 214 relates neither field's size to the
    /// other, so the pair is the same signature (TPM 2.0 Library Part 2, clause 11.3.2, Table 214; clause
    /// 11.2.5.1, Table 197).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureAcceptsASignatureRWithALeadingZeroOctetAsTheSameInteger()
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

        TpmRcConstants code = await SubmitVerifySignatureCommandAsync(simulator, pool, primary.ObjectHandle.Value, digest, body).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "A signatureR with an insignificant leading zero octet encodes the same integer and must verify (Table 214/197).");
    }

    /// <summary>
    /// An ECDSA <c>signatureS</c> whose own leading zero octets are omitted (fewer than 32 octets for P-256)
    /// verifies exactly as its fixed-width form does — a <c>TPM2B_ECC_PARAMETER</c> is an integer, not a
    /// fixed-width field, and a genuine signer may well emit it that way (TPM 2.0 Library Part 2, clause 11.3.2,
    /// Table 214; clause 11.2.5.1, Table 197). Signatures are drawn until one has a leading zero to omit.
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureAcceptsASignatureSStrippedOfItsLeadingZeroOctetsAsTheSameInteger()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] digest = SHA256.HashData(MessageBytes);

        byte[]? body = null;
        for(int attempt = 0; attempt < MaxSigningAttemptsForALeadingZero && body is null; attempt++)
        {
            (byte[] r, byte[] s) = await SignEcdsaComponentsAsync(tpm, registry, pool, primary.ObjectHandle, digest).ConfigureAwait(false);
            byte[] fixedS = ToFixed(s, P256ComponentSize);
            if(fixedS[0] == 0x00)
            {
                body = BuildEcdsaSignatureBodyFromComponents(TpmAlgIdConstants.TPM_ALG_SHA256, ToFixed(r, P256ComponentSize), fixedS.AsSpan().TrimStart((byte)0x00));
            }
        }

        Assert.IsNotNull(body, "A signatureS with a leading zero octet appears in roughly one signature of 256; none appeared within the bound.");

        TpmRcConstants code = await SubmitVerifySignatureCommandAsync(simulator, pool, primary.ObjectHandle.Value, digest, body).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "A signatureS shorter than the field width encodes the same integer and must verify (Table 214/197).");
    }

    /// <summary>
    /// An ECDSA <c>signatureR</c> whose significant octets exceed the curve field width (a non-zero 33rd octet
    /// for P-256) is no element of the curve's scalar field — it is at least 2^256, above the order — so the
    /// verification fails with <c>TPM_RC_SIGNATURE</c>, exactly as a mathematically invalid pair does; the
    /// parse admits it (Table 197's bound is <c>MAX_ECC_KEY_BYTES</c>, not the key's own width), the verification
    /// refuses it (TPM 2.0 Library Part 3, clause 20.2.1; Part 2, clause 11.2.5.1, Table 197).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureRefusesASignatureRWiderThanTheCurveFieldWithSignature()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] digest = SHA256.HashData(MessageBytes);
        (byte[] r, byte[] s) = await SignEcdsaComponentsAsync(tpm, registry, pool, primary.ObjectHandle, digest).ConfigureAwait(false);

        //s carries an insignificant leading zero of its own so the pair's combined length is even: the refusal
        //must come from r's width, never from an odd-length concatenation.
        byte[] overWidthR = [0x01, .. ToFixed(r, P256ComponentSize)];
        byte[] zeroPaddedS = [0x00, .. ToFixed(s, P256ComponentSize)];
        byte[] body = BuildEcdsaSignatureBodyFromComponents(TpmAlgIdConstants.TPM_ALG_SHA256, overWidthR, zeroPaddedS);

        TpmRcConstants code = await SubmitVerifySignatureCommandAsync(simulator, pool, primary.ObjectHandle.Value, digest, body).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIGNATURE, code, "A signatureR above the field width is no curve element and must fail verification, not parsing.");
    }

    /// <summary>
    /// The shared rebuild every ECDSA-verifying effect uses left-pads a short component to the field width and
    /// drops a component's leading zero octets — the integer semantics of <c>TPM2B_ECC_PARAMETER</c> (TPM 2.0
    /// Library Part 2, clause 11.2.5.1, Table 197) rendered as the fixed-width IEEE P1363 <c>r ‖ s</c> the verify
    /// delegate takes.
    /// </summary>
    [TestMethod]
    public void NormalizedEcdsaSignatureLeftPadsAShortComponentAndDropsLeadingZeroOctets()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] shortR = [0x01, 0x02, 0x03];
        byte[] zeroLedS = [0x00, 0x00, 0xAB, 0xCD, 0xEF];
        using TpmuSignature signature = TpmuSignature.CreateEcdsaFromComponents(TpmAlgIdConstants.TPM_ALG_SHA256, shortR, zeroLedS, pool);
        byte[] destination = new byte[8];

        bool isWritten = TpmLifecycleTransitions.TryWriteNormalizedEcdsaSignature(signature, componentWidth: 4, destination);

        Assert.IsTrue(isWritten, "Both components fit a four-octet field.");
        byte[] expected = [0x00, 0x01, 0x02, 0x03, 0x00, 0xAB, 0xCD, 0xEF];
        Assert.IsTrue(expected.AsSpan().SequenceEqual(destination), "r is left-padded to the width; s keeps exactly one leading zero because its three significant octets leave one octet of padding in a four-octet field.");
    }

    /// <summary>
    /// The shared rebuild refuses a component whose significant octets exceed the field width — the value is at
    /// least 2^(8·width), above any curve order — so the verifying effect answers <c>TPM_RC_SIGNATURE</c>
    /// (TPM 2.0 Library Part 3, clause 20.2.1); leading zero octets beyond the width are not significant and
    /// do not trip the refusal.
    /// </summary>
    [TestMethod]
    public void NormalizedEcdsaSignatureRefusesAComponentWhoseSignificantOctetsExceedTheWidth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] overWidthR = [0x01, 0x00, 0x00, 0x00, 0x00];
        byte[] zeroPaddedS = [0x00, 0x01, 0x02, 0x03, 0x04];
        using TpmuSignature overWidth = TpmuSignature.CreateEcdsaFromComponents(TpmAlgIdConstants.TPM_ALG_SHA256, overWidthR, zeroPaddedS, pool);
        using TpmuSignature zeroPadded = TpmuSignature.CreateEcdsaFromComponents(TpmAlgIdConstants.TPM_ALG_SHA256, zeroPaddedS, zeroPaddedS, pool);
        byte[] destination = new byte[8];

        Assert.IsFalse(TpmLifecycleTransitions.TryWriteNormalizedEcdsaSignature(overWidth, componentWidth: 4, destination), "Five significant octets do not fit a four-octet field.");
        Assert.IsTrue(TpmLifecycleTransitions.TryWriteNormalizedEcdsaSignature(zeroPadded, componentWidth: 4, destination), "A leading zero octet beyond the width is insignificant.");
        byte[] expected = [0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04];
        Assert.IsTrue(expected.AsSpan().SequenceEqual(destination), "Each five-octet component with a leading zero is the four-octet integer it encodes.");
    }

    /// <summary>
    /// The field width every ECDSA-verifying effect normalizes to derives from the verifying key's own SEC1
    /// uncompressed point (<c>0x04 ‖ X ‖ Y</c>): 65 octets for P-256, 97 for P-384, 133 for P-521 — no curve
    /// table, the point's length settles it.
    /// </summary>
    [TestMethod]
    public void EccComponentWidthDerivesFromTheSec1PointLength()
    {
        Assert.AreEqual(32, TpmLifecycleTransitions.EccComponentWidth(new byte[65]), "P-256: (65 - 1) / 2.");
        Assert.AreEqual(48, TpmLifecycleTransitions.EccComponentWidth(new byte[97]), "P-384: (97 - 1) / 2.");
        Assert.AreEqual(66, TpmLifecycleTransitions.EccComponentWidth(new byte[133]), "P-521: (133 - 1) / 2.");
    }

    /// <summary>
    /// Signs the digest with the given RSA scheme through <c>TPM2_Sign()</c>, then verifies it through
    /// <c>TPM2_VerifySignature()</c>, asserting success and a structurally sound returned ticket.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The handle of the loaded RSA signing key.</param>
    /// <param name="digest">The pre-computed SHA-256 digest to sign and verify.</param>
    /// <param name="usePss">When <see langword="true"/>, signs and verifies RSAPSS; otherwise RSASSA (PKCS#1 v1.5).</param>
    private async Task SignAndVerifyRsaAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] digest, bool usePss)
    {
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = usePss
            ? SignInput.ForRsaPss(keyHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool)
            : SignInput.ForRsaSsa(keyHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        string schemeName = usePss ? "RSAPSS" : "RSASSA";
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign ({schemeName}) failed: '{signResult.ResponseCode}'.");

        using SignResponse signature = signResult.Value;
        byte[] rsaSignature = signature.Signature.RsaSignature.Buffer.ToArray();

        using VerifySignatureInput verifyInput = usePss
            ? VerifySignatureInput.ForRsaPss(keyHandle, digest, rsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool)
            : VerifySignatureInput.ForRsaSsa(keyHandle, digest, rsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifySignature ({schemeName}) failed: '{verifyResult.ResponseCode}'.");

        using VerifySignatureResponse verified = verifyResult.Value;
        Assert.AreEqual(TpmStConstants.TPM_ST_VERIFIED, verified.Validation.Tag, "The ticket tag must be TPM_ST_VERIFIED.");
        Assert.AreEqual(TpmiRhHierarchy.Owner, verified.Validation.Hierarchy, "The ticket hierarchy must be the signing key's own hierarchy.");
        Assert.IsFalse(verified.Validation.IsNull, "A successful verification must return a real ticket, not a NULL ticket.");
        Assert.HasCount(P256ComponentSize, verified.Validation.Hmac, "The verified ticket digest is a SHA-256 HMAC.");
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
    /// Concatenates the ECDSA r and s components into the IEEE P1363 <c>r ‖ s</c> form the verify delegate and
    /// <see cref="VerifySignatureInput.ForEcdsa"/> take, left-padding each to the P-256 field width.
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
            "tpm-in-house-verify-signature",
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

    /// <summary>
    /// "The object to validate the signature must be a signing key" — the reference's first input validation
    /// refuses a <c>keyHandle</c> whose <c>sign</c> attribute is CLEAR with <c>TPM_RC_ATTRIBUTES</c> for every
    /// key type, ahead of the signature verification itself: an ECC storage parent (restricted decryption key)
    /// presented with a well-formed ECDSA signature shape is refused before any verification runs
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.2 (Part 4 <c>VerifySignature.c</c>, Detailed Actions);
    /// Part 2: Structures, clause 8.3.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureOverANonSigningAsymmetricKeyIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");
        using CreatePrimaryResponse parent = parentResult.Value;

        byte[] digest = new byte[32];
        byte[] signature = new byte[64];
        using VerifySignatureInput input = VerifySignatureInput.ForEcdsa(
            parent.ObjectHandle, digest, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySignatureResponse> result = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "A non-signing asymmetric key at TPM2_VerifySignature() must be refused with TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// The <c>sign</c> gate precedes the hash bound: the same non-signing ECC storage parent presented with a
    /// SHA-1 signature hash answers <c>TPM_RC_ATTRIBUTES</c>, where a signing key with that hash draws
    /// <c>TPM_RC_HASH</c> — the reference's first input validation runs ahead of every other rule
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.2 (Part 4 <c>VerifySignature.c</c>, Detailed Actions)).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureOverANonSigningAsymmetricKeyIsRefusedWithAttributesBeforeTheHashRule()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");
        using CreatePrimaryResponse parent = parentResult.Value;

        byte[] digest = new byte[20];
        byte[] signature = new byte[64];
        using VerifySignatureInput input = VerifySignatureInput.ForEcdsa(
            parent.ObjectHandle, digest, signature, TpmAlgIdConstants.TPM_ALG_SHA1, pool);
        TpmResult<VerifySignatureResponse> result = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "The sign gate must answer before the hash bound: a non-signing key with a SHA-1 signature hash is TPM_RC_ATTRIBUTES, not TPM_RC_HASH.");
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySignature, TpmResponseCodec.VerifySignature);

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
    /// Builds the verified-ticket HMAC message: TPM_ST_VERIFIED (UINT16) followed by the digest and the
    /// verifying key's Name — the mirror image of the creation ticket's TPM_ST_CREATION || name || creationHash
    /// order.
    /// </summary>
    /// <param name="digest">The digest the signature was claimed to be over.</param>
    /// <param name="keyName">The verifying key's Name.</param>
    /// <returns>The ticket message bytes.</returns>
    private static byte[] BuildVerifiedTicketMessage(ReadOnlySpan<byte> digest, ReadOnlySpan<byte> keyName)
    {
        byte[] message = new byte[sizeof(ushort) + digest.Length + keyName.Length];
        var writer = new TpmWriter(message);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_VERIFIED);
        writer.WriteBytes(digest);
        writer.WriteBytes(keyName);

        return message;
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_VerifySignature()</c> command whose <c>signature</c> body is supplied verbatim —
    /// letting a caller express a declared/actual TPM2B size mismatch or an over-bound declared size that
    /// <see cref="VerifySignatureInput"/>'s typed factories cannot (they refuse those shapes client-side before a
    /// command is ever framed). No sessions: <c>TPM2_VerifySignature()</c> authorizes no entity (TPM 2.0 Library
    /// Part 3, clause 20.2).
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle value.</param>
    /// <param name="digest">The <c>digest</c> parameter's octets.</param>
    /// <param name="signatureBody">The already-marshaled <c>TPMT_SIGNATURE</c> body (sigAlg, and whatever follows it), verbatim.</param>
    /// <param name="length">The framed command's total length.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameVerifySignatureCommand(
        BaseMemoryPool pool, uint keyHandle, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signatureBody, out int length)
    {
        length = TpmHeader.HeaderSize + sizeof(uint) + sizeof(ushort) + digest.Length + signatureBody.Length;
        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_VerifySignature);
            header.WriteTo(ref writer);
            writer.WriteUInt32(keyHandle);
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
    /// Submits a hand-framed <c>TPM2_VerifySignature()</c> built by <see cref="FrameVerifySignatureCommand"/>
    /// straight to the simulator (bypassing <see cref="TpmCommandExecutor"/>) and yields the response code.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle value.</param>
    /// <param name="digest">The <c>digest</c> parameter's octets.</param>
    /// <param name="signatureBody">The already-marshaled <c>TPMT_SIGNATURE</c> body, verbatim.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitVerifySignatureCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint keyHandle, byte[] digest, byte[] signatureBody)
    {
        using IMemoryOwner<byte> commandOwner = FrameVerifySignatureCommand(pool, keyHandle, digest, signatureBody, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>Builds a <c>TPMT_SIGNATURE</c> body carrying only the <c>sigAlg</c> selector — enough to probe the wire-level scheme gate, which refuses before reading anything past it.</summary>
    /// <param name="sigAlg">The selector value to write.</param>
    /// <returns>The two-octet body.</returns>
    private static byte[] BuildSigAlgOnlyBody(TpmAlgIdConstants sigAlg)
    {
        byte[] body = new byte[sizeof(ushort)];
        var writer = new TpmWriter(body);
        writer.WriteUInt16((ushort)sigAlg);

        return body;
    }

    /// <summary>
    /// Builds an ECDSA <c>TPMT_SIGNATURE</c> body: sigAlg, hashAlg, then signatureR and signatureS each as an
    /// independently declared/actual TPM2B pair, letting a caller express an over-bound declared size, a
    /// truncated frame, or both at once, per component.
    /// </summary>
    /// <param name="sigAlg">The signature algorithm selector.</param>
    /// <param name="hashAlg">The hash algorithm carried inside the member.</param>
    /// <param name="declaredRSize">signatureR's declared TPM2B size.</param>
    /// <param name="actualRBytesProvided">The octets the frame actually carries for signatureR.</param>
    /// <param name="declaredSSize">signatureS's declared TPM2B size.</param>
    /// <param name="actualSBytesProvided">The octets the frame actually carries for signatureS.</param>
    /// <returns>The marshaled body.</returns>
    private static byte[] BuildEcdsaSignatureBody(
        TpmAlgIdConstants sigAlg, TpmAlgIdConstants hashAlg,
        int declaredRSize, int actualRBytesProvided, int declaredSSize, int actualSBytesProvided)
    {
        byte[] body = new byte[2 * sizeof(ushort) + sizeof(ushort) + actualRBytesProvided + sizeof(ushort) + actualSBytesProvided];
        var writer = new TpmWriter(body);
        writer.WriteUInt16((ushort)sigAlg);
        writer.WriteUInt16((ushort)hashAlg);
        writer.WriteUInt16((ushort)declaredRSize);
        if(actualRBytesProvided > 0)
        {
            writer.WriteBytes(new byte[actualRBytesProvided]);
        }

        writer.WriteUInt16((ushort)declaredSSize);
        if(actualSBytesProvided > 0)
        {
            writer.WriteBytes(new byte[actualSBytesProvided]);
        }

        return body;
    }

    /// <summary>
    /// The RSA counterpart of <see cref="BuildEcdsaSignatureBody"/>: sigAlg, hashAlg, then the single
    /// <c>rsaSignature</c> TPM2B with an independently declared/actual size.
    /// </summary>
    /// <param name="sigAlg">The signature algorithm selector (RSASSA or RSAPSS).</param>
    /// <param name="hashAlg">The hash algorithm carried inside the member.</param>
    /// <param name="declaredSigSize">rsaSignature's declared TPM2B size.</param>
    /// <param name="actualSigBytesProvided">The octets the frame actually carries for rsaSignature.</param>
    /// <returns>The marshaled body.</returns>
    private static byte[] BuildRsaSignatureBody(TpmAlgIdConstants sigAlg, TpmAlgIdConstants hashAlg, int declaredSigSize, int actualSigBytesProvided)
    {
        byte[] body = new byte[2 * sizeof(ushort) + sizeof(ushort) + actualSigBytesProvided];
        var writer = new TpmWriter(body);
        writer.WriteUInt16((ushort)sigAlg);
        writer.WriteUInt16((ushort)hashAlg);
        writer.WriteUInt16((ushort)declaredSigSize);
        if(actualSigBytesProvided > 0)
        {
            writer.WriteBytes(new byte[actualSigBytesProvided]);
        }

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
