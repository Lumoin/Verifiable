using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
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

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_CertifyCreation()</c> (creation attestation) against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production
/// command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="CertifyCreationInput"/> and response codecs): <c>TPM2_CreatePrimary()</c> mints a subject signing
/// key under the owner hierarchy and a separate attestation key (AK) under the endorsement hierarchy, then the AK
/// certifies that the subject was created by the TPM, re-verifying the creation ticket <c>TPM2_CreatePrimary()</c>
/// returned.
/// </summary>
/// <remarks>
/// <para>
/// The result is verified <b>off-TPM</b> from wire bytes only: the magic / type / nonce fields, that the attested
/// objectName equals the subject's Name recomputed independently from its exported public area, that the attested
/// creationHash equals the creation hash <c>TPM2_CreatePrimary()</c> reported, and the ECDSA/RSA signature over the
/// raw attestation bytes against the AK's exported public key reconstructed from <c>outPublic</c> alone.
/// </para>
/// <para>
/// Only the signing key (<c>@signHandle</c>) requires authorization (TPM 2.0 Library Part 3, clause 18.3, Table
/// 88); the certified object (<c>objectHandle</c>) carries no authorization at all, so the executor is given a
/// single empty-auth password session.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorCertifyCreationTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus size in bits used by the RSA certify-creation tests.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The signing key's authValue for the sign-slot password-verification test.</summary>
    private const string SignerKeyPassword = "certify-creation-signer-auth";

    /// <summary>The fixed caller nonce (qualifyingData) echoed into the attestation's extraData.</summary>
    private static byte[] Nonce { get; } = "CertifyCreation nonce for the in-house TPM."u8.ToArray();

    /// <summary>
    /// The signing key's authValue in wire form — the UTF-8 octets <see cref="SignerKeyPassword"/> derives (TPM
    /// 2.0 Library authValue-from-password is UTF-8, trailing zeros trimmed per Part 1, clause 17.6.4.3).
    /// </summary>
    private static byte[] SignerKeyAuth { get; } = System.Text.Encoding.UTF8.GetBytes(SignerKeyPassword);

    /// <summary>A wrong guess at the signing key's authValue, distinct from <see cref="SignerKeyAuth"/>.</summary>
    private static byte[] WrongSignerKeyAuth { get; } = [0xDE, 0xAD, 0xBE, 0xEF];

    /// <summary>The hash algorithm for every real (HMAC or policy) session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The correct authValue for the userWithAuth-CLEAR signing key used by the userWithAuth gate test.</summary>
    private const string UserWithAuthClearSignerPassword = "certify-creation-clear-signer";

    /// <summary>
    /// <see cref="UserWithAuthClearSignerPassword"/> in wire form — the UTF-8 octets the TPM 2.0 Library
    /// authValue-from-password derivation uses (Part 1, clause 17.6.4.3).
    /// </summary>
    private static byte[] UserWithAuthClearSignerAuth { get; } = System.Text.Encoding.UTF8.GetBytes(UserWithAuthClearSignerPassword);

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies a full ECDSA P-256 certify-creation round trip: the attested objectName matches the subject's
    /// independently recomputed Name, the attested creationHash matches CreatePrimary's own reported creation
    /// hash, qualifiedSigner is the AK's real (non-collapsed) Qualified Name, and the signature verifies against
    /// the AK's exported public key (TPM 2.0 Library Part 3, clause 18.3).
    /// </summary>
    [TestMethod]
    public async Task EcdsaP256CertifyCreationVerifiesAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
            ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, certifyCreationInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_CertifyCreation failed: '{result.ResponseCode}'.");

        using CertifyCreationResponse certifyCreation = result.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, certifyCreation.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, certifyCreation.HashAlgorithm);

        await AssertCreationAttestationAsync(certifyCreation, subject, ak, pool).ConfigureAwait(false);

        byte[] attestDigest = await ComputeSha256Async(certifyCreation.CertifyInfo.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmsEccPoint akPoint = ak.OutPublic.PublicArea.Unique.Ecc!;
        var ecParameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = ToFixed(akPoint.X.AsReadOnlySpan(), P256ComponentSize),
                Y = ToFixed(akPoint.Y.AsReadOnlySpan(), P256ComponentSize)
            }
        };

        byte[] p1363Signature = new byte[2 * P256ComponentSize];
        ToFixed(certifyCreation.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(certifyCreation.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        using ECDsa ecdsa = ECDsa.Create(ecParameters);
        Assert.IsTrue(
            ecdsa.VerifyHash(attestDigest, p1363Signature),
            "The certify-creation signature must verify over the raw attestation bytes against the AK's exported public key.");
    }

    /// <summary>
    /// Verifies certify-creation with an RSA AK under both RSASSA and RSAPSS, mirroring the ECDSA assertions
    /// (TPM 2.0 Library Part 3, clause 18.3).
    /// </summary>
    [TestMethod]
    public async Task RsaCertifyCreationVerifiesAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        var rsaParameters = new RSAParameters
        {
            Modulus = ak.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
            Exponent = [0x01, 0x00, 0x01]
        };

        await CertifyCreationAndVerifyRsaAsync(tpm, registry, pool, subject, ak, rsaParameters, usePss: false).ConfigureAwait(false);
        await CertifyCreationAndVerifyRsaAsync(tpm, registry, pool, subject, ak, rsaParameters, usePss: true).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that a creation ticket with one flipped octet fails the stateless re-verification: "This ticket
    /// is then compared to creationTicket. If the tickets are not the same, the TPM shall return TPM_RC_TICKET"
    /// (TPM 2.0 Library Part 3, clause 18.3).
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationWithTamperedTicketReturnsTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmtTkCreation tamperedTicket = FlipTicketOctet(subject.CreationTicket, pool);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
            ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), tamperedTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, certifyCreationInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_TICKET, result.ResponseCode);
    }

    /// <summary>
    /// Verifies that a storage parent (RESTRICTED|DECRYPT, no SIGN_ENCRYPT) as the certify-creation's signHandle
    /// is rejected with <c>TPM_RC_KEY</c>: "If the sign attribute is not SET in the key referenced by signHandle
    /// then the TPM shall return TPM_RC_KEY" (TPM 2.0 Library Part 3, clause 18.1, shared by clause 18.3).
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationWithNonSigningKeyReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
            parent.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, certifyCreationInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, result.ResponseCode);
    }

    /// <summary>
    /// TPM2_CertifyCreation()'s signing-key slot (Auth Index 1, Auth Role USER; TPM 2.0 Library Part 3, clause
    /// 18.3, Table 88) is verified against the signing key's retained authValue over a plain <c>TPM_RS_PW</c>
    /// session: a DA-protected AK created with a real password attests with the CORRECT password and moves no
    /// dictionary-attack counter, while a WRONG password is refused with the session-index-encoded
    /// <c>TPM_RC_AUTH_FAIL</c> (Part 2, clause 6.6.2) and charges <c>failedTries</c> exactly once (Part 1, clause
    /// 17.8.7). The certified object carries no authorization at all (Table 91/99), so only the signing key's
    /// slot is ever exercised.
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationVerifiesTheSigningKeysAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession correctSignAuth = TpmPasswordSession.Create(SignerKeyAuth, pool);
        using CertifyCreationInput correctCertifyCreationInput = CertifyCreationInput.ForEcdsa(
            ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, correctCertifyCreationInput, [correctSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(correctResult.IsSuccess, $"TPM2_CertifyCreation with the signing key's correct password must succeed, but failed: '{correctResult.ResponseCode}'.");
        correctResult.Value.Dispose();

        TpmResult<TpmDictionaryAttackParameters> afterCorrect = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, afterCorrect.Value.LockoutCounter,
            "A correctly-authorized TPM2_CertifyCreation must move no dictionary-attack counter.");

        using TpmPasswordSession wrongSignAuth = TpmPasswordSession.Create(WrongSignerKeyAuth, pool);
        using CertifyCreationInput wrongCertifyCreationInput = CertifyCreationInput.ForEcdsa(
            ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, wrongCertifyCreationInput, [wrongSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), wrongResult.ResponseCode,
            "A wrong signing-key password over a plain TPM_RS_PW session names the sign slot (index 0), session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            afterCorrect.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
            "A wrong signing-key password against a DA-protected AK must charge failedTries exactly once (TPM 2.0 Library Part 1, clause 17.8.7).");
    }

    /// <summary>
    /// TPM2_CertifyCreation()'s signing-key slot (Auth Index 1, Auth Role USER) refuses a userWithAuth-CLEAR
    /// signer's <c>TPM_RS_PW</c> authorization with a bare <c>TPM_RC_POLICY_FAIL</c> even when the CORRECT
    /// password is supplied, and never charges the dictionary-attack counter for it: check 7.1 of the mandatory
    /// authorization-check order (TPM 2.0 Library Part 3, clause 5.6) precedes the credential comparison
    /// (checks 9/10), so the password is never inspected — a policy session, not <c>TPM_RS_PW</c>, is the
    /// admissible authorization shape for such a key. The closing rule of clause 5.6 holds that a non-
    /// <c>TPM_RC_AUTH_FAIL</c> error "shall not alter any TPM state", so <c>failedTries</c> is left untouched.
    /// The certified object (<c>objectHandle</c>) carries no authorization at all (Table 91), so only the sign
    /// slot is exercised. Creating the signer itself succeeds because a hierarchy is exempt from this gate ("a
    /// hierarchy operates as if userWithAuth is SET").
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationWithUserWithAuthClearSignerIsRefusedWithoutComparingThePassword()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateUserWithAuthClearSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.Create(UserWithAuthClearSignerAuth, pool);
        using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
            ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, certifyCreationInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode,
            $"A userWithAuth-CLEAR signing key must refuse a TPM_RS_PW authorization — even with its correct " +
            $"password — with a bare TPM_RC_POLICY_FAIL (TPM 2.0 Library Part 3, clause 5.6, check 7.1), never " +
            $"a session-encoded code and never TPM_RC_AUTH_FAIL (got '{result.ResponseCode}').");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "A userWithAuth-CLEAR refusal must be uncharged: TPM_RC_POLICY_FAIL is not TPM_RC_AUTH_FAIL, and a " +
            "non-AUTH_FAIL error must not alter any TPM state (TPM 2.0 Library Part 3, clause 5.6, closing rule).");
    }

    /// <summary>
    /// Certifies the subject's creation with the RSA AK under the given scheme through the production command
    /// path, verifies the attestation off-TPM, and verifies the signature against the AK's exported modulus with
    /// an independent RSA verifier.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="subject">The certified object's CreatePrimary response.</param>
    /// <param name="ak">The RSA attestation key's CreatePrimary response.</param>
    /// <param name="rsaParameters">The public key reconstructed from the AK's exported modulus.</param>
    /// <param name="usePss">When <see langword="true"/>, certifies and verifies RSAPSS; otherwise RSASSA (PKCS#1 v1.5).</param>
    private async Task CertifyCreationAndVerifyRsaAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse subject, CreatePrimaryResponse ak, RSAParameters rsaParameters, bool usePss)
    {
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyCreationInput certifyCreationInput = usePss
            ? CertifyCreationInput.ForRsaPss(ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool)
            : CertifyCreationInput.ForRsaSsa(ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, certifyCreationInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        string schemeName = usePss ? "RSAPSS" : "RSASSA";
        Assert.IsTrue(result.IsSuccess, $"TPM2_CertifyCreation ({schemeName}) failed: '{result.ResponseCode}'.");

        using CertifyCreationResponse certifyCreation = result.Value;
        Assert.AreEqual(usePss ? TpmAlgIdConstants.TPM_ALG_RSAPSS : TpmAlgIdConstants.TPM_ALG_RSASSA, certifyCreation.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, certifyCreation.HashAlgorithm);

        await AssertCreationAttestationAsync(certifyCreation, subject, ak, pool).ConfigureAwait(false);

        byte[] attestDigest = await ComputeSha256Async(certifyCreation.CertifyInfo.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        RSASignaturePadding padding = usePss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        using RSA rsa = RSA.Create(rsaParameters);
        Assert.IsTrue(
            rsa.VerifyHash(attestDigest, certifyCreation.Signature.RsaSignature.Buffer.ToArray(), HashAlgorithmName.SHA256, padding),
            $"The {schemeName} certify-creation signature must verify against the RSA AK's exported modulus.");
    }

    /// <summary>
    /// Asserts the envelope (magic/type/nonce), the attested objectName against an independent Name
    /// recomputation, the attested creationHash against CreatePrimary's own reported creation hash, and
    /// qualifiedSigner against an independent (non-collapsed) Qualified Name recomputation.
    /// </summary>
    /// <param name="certifyCreation">The parsed certify-creation response.</param>
    /// <param name="subject">The certified object's CreatePrimary response.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task AssertCreationAttestationAsync(CertifyCreationResponse certifyCreation, CreatePrimaryResponse subject, CreatePrimaryResponse ak, BaseMemoryPool pool)
    {
        TpmsAttest attest = certifyCreation.CertifyInfo.AttestationData;
        Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attest.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_CREATION, attest.Type);
        Assert.IsTrue(attest.ExtraData.Span.SequenceEqual(Nonce), "extraData must echo the caller's qualifyingData nonce.");
        Assert.IsNotNull(attest.Attested.Creation);

        byte[] expectedName = await ComputeObjectNameAsync(subject.OutPublic, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.Attested.Creation!.ObjectName.Span.SequenceEqual(expectedName),
            "The attested objectName must equal the subject's Name recomputed from its exported public area.");

        Assert.IsTrue(
            attest.Attested.Creation!.CreationHash.AsReadOnlySpan().SequenceEqual(subject.CreationHash.AsReadOnlySpan()),
            "The attested creationHash must equal the creation hash TPM2_CreatePrimary() reported for the subject.");

        byte[] expectedSignerQn = await ComputeQualifiedNameAsync(
            (uint)TpmRh.TPM_RH_ENDORSEMENT, ak.Name.Span.ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.QualifiedSigner.Span.SequenceEqual(expectedSignerQn),
            "qualifiedSigner must equal the AK's independently recomputed Qualified Name.");
        Assert.IsFalse(
            attest.QualifiedSigner.Span.SequenceEqual(ak.Name.Span),
            "qualifiedSigner must not collapse to the AK's plain Name.");
    }

    /// <summary>
    /// Round-trips a creation ticket through the wire form with the last octet (part of the HMAC digest) flipped,
    /// producing a ticket that fails the stateless re-verification without depending on any non-public
    /// construction API.
    /// </summary>
    /// <param name="ticket">The genuine creation ticket to tamper with.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>A tampered creation ticket the caller owns and must dispose.</returns>
    private static TpmtTkCreation FlipTicketOctet(TpmtTkCreation ticket, BaseMemoryPool pool)
    {
        int size = ticket.SerializedSize;
        byte[] wireBytes = new byte[size];
        var writer = new TpmWriter(wireBytes);
        ticket.WriteTo(ref writer);

        wireBytes[^1] ^= 0xFF;

        var reader = new TpmReader(wireBytes);
        return TpmtTkCreation.Parse(ref reader, pool);
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
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a DA-protected primary ECC P-256 signing key under the endorsement hierarchy with a NON-EMPTY
    /// authValue (<see cref="SignerKeyPassword"/>) — the fixture the sign-slot password-verification test needs
    /// to exercise the attestation key's own retained authValue, unlike every other AK fixture in this file, which
    /// carries an empty one.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateDaProtectedSigningPrimaryWithAuthAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_ENDORSEMENT,
            password: SignerKeyPassword,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: false);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (DA-protected ECC signer with authValue) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the endorsement hierarchy with TPMA_OBJECT.userWithAuth
    /// CLEAR and a non-empty authValue (<see cref="UserWithAuthClearSignerPassword"/>), composing the public
    /// template the same way <see cref="CreatePrimaryInput.ForEccSigningKey"/> does internally but omitting
    /// <see cref="TpmaObject.USER_WITH_AUTH"/> from the object attributes. Creation itself succeeds because the
    /// endorsement hierarchy handle authorizes it and a hierarchy is exempt from the userWithAuth gate ("a
    /// hierarchy operates as if userWithAuth is SET", TPM 2.0 Library Part 3, clause 5.6). The key is left
    /// DA-protected (no TPMA_OBJECT.noDA) so a refusal that wrongly compared and rejected the password would
    /// still surface as a moved dictionary-attack counter.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the CreatePrimaryInput, whose Dispose releases them.")]
    private async Task<CreatePrimaryResponse> CreateUserWithAuthClearSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        var attributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.SIGN_ENCRYPT;

        var inSensitive = Tpm2bSensitiveCreate.WithPassword(UserWithAuthClearSignerPassword, pool);
        var inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256, attributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));
        using CreatePrimaryInput input = new(TpmRh.TPM_RH_ENDORSEMENT, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (userWithAuth-CLEAR ECC signer) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a primary RSA-2048 signing key under the given hierarchy and returns the response (the caller owns
    /// it).
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
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA 2048, {hierarchy}) failed: '{result.ResponseCode}'.");

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
    /// Recomputes a loaded object's Name from its exported public area: <c>nameAlg || H_nameAlg(TPMT_PUBLIC)</c>
    /// (TPM 2.0 Library Part 1, clause 14, Table 6), through the registered digest seam. The test keys use a SHA-256 nameAlg.
    /// </summary>
    /// <param name="outPublic">The object's exported public area.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recomputed Name (2-byte nameAlg prefix + digest).</returns>
    private static async Task<byte[]> ComputeObjectNameAsync(Tpm2bPublic outPublic, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        TpmAlgIdConstants nameAlg = outPublic.PublicArea.NameAlg;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, nameAlg, "This test assumes a SHA-256 nameAlg.");

        byte[] marshaledPublic = MarshalPublicArea(outPublic, pool);
        byte[] digest = await ComputeSha256Async(marshaledPublic, pool, cancellationToken).ConfigureAwait(false);

        byte[] name = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)nameAlg);
        digest.CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>
    /// Recomputes an object's Qualified Name independently: <c>nameAlg || H(hierarchyHandle || Name)</c> (TPM 2.0
    /// Library Part 1, clause 14, Table 6), through the registered digest seam. Every object this simulator certifies is a
    /// primary created directly under a permanent hierarchy, so the hierarchy's own Qualified Name is its 4-octet
    /// big-endian handle value — this test never calls the production <c>TpmObjectName</c> helper, matching the
    /// file's firewalled, off-TPM oracle style.
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
    /// Marshals the exported public area into its canonical TPMT_PUBLIC wire form (no TPM2B size prefix) — the
    /// hash input the object Name is computed over.
    /// </summary>
    /// <param name="outPublic">The exported public area.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The marshaled TPMT_PUBLIC bytes.</returns>
    private static byte[] MarshalPublicArea(Tpm2bPublic outPublic, BaseMemoryPool pool)
    {
        int size = outPublic.PublicArea.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        outPublic.PublicArea.WriteTo(ref writer);

        return owner.Memory.Span[..size].ToArray();
    }

    /// <summary>
    /// Applies the session-index response-code modifier a TPM adds when a failure is attributed to a specific
    /// authorization session: <c>rc = baseRc + TPM_RC_S + 0x100 * (sessionIndex + 1)</c> (TPM 2.0 Library Part 2,
    /// clause 6.6.2).
    /// </summary>
    /// <param name="baseRc">The unmodified format-1 response code.</param>
    /// <param name="sessionIndex">The zero-based index of the session the failure names.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers it
    /// on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-certify-creation",
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

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_CertifyCreation, TpmResponseCodec.CertifyCreation);

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
    /// A real, unbound/unsalted HMAC session at TPM2_CertifyCreation()'s sole signing-key slot, folding the
    /// signing key's own CORRECT authValue, verifies and attests: the command HMAC compares against the
    /// retained authValue exactly as TPM 2.0 Library Part 1, clause 17.6.5 (equation 17) requires. A SECOND
    /// certify over the SAME session likewise succeeds and adopts a genuinely rolled nonceTPM from its own
    /// response entry — a session's nonceTPM changes on every use (Part 1, clause 17.6.3.1), and only a
    /// response whose HMAC verifies (clause 17.6.5) lets the session adopt it — proving this session
    /// authorizes over the real, spec-shaped session mechanics rather than a stub (TPM 2.0 Library Part 3,
    /// clause 18.3).
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationOverUnboundHmacSessionWithCorrectAuthAttestsAndRollsNonceOnASecondUse()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            signSession.SetAuthValue(SignerKeyAuth, pool);

            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), subject.Name.Span.ToArray()];

            using(CertifyCreationInput firstInput = CertifyCreationInput.ForEcdsa(
                ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool))
            {
                TpmResult<CertifyCreationResponse> firstResult = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                    tpm, firstInput, [signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(firstResult.IsSuccess, $"The first certify over the real session must attest: '{firstResult.ResponseCode}'.");
                firstResult.Value.Dispose();
            }

            byte[] nonceTpmBeforeSecond = signSession.NonceTpm.ToArray();

            using(CertifyCreationInput secondInput = CertifyCreationInput.ForEcdsa(
                ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool))
            {
                TpmResult<CertifyCreationResponse> secondResult = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                    tpm, secondInput, [signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(secondResult.IsSuccess, $"A second certify over the SAME session must also attest: '{secondResult.ResponseCode}'.");
                secondResult.Value.Dispose();
            }

            Assert.IsFalse(
                signSession.NonceTpm.Span.SequenceEqual(nonceTpmBeforeSecond),
                "The session must adopt a genuinely rolled nonceTPM from its own response entry on the second use — proof the response HMAC was actually verified.");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A real, unbound/unsalted HMAC session at the sole signing-key slot folding a WRONG guess at a
    /// dictionary-attack-protected signing key's authValue fails command-HMAC verification and is charged to
    /// failedTries — the throttle that closes the dictionary-attack oracle (TPM 2.0 Library Part 1, clause
    /// 17.8.1; clause 17.6.5, equation 17). The mismatch names the sole slot (index 0), so the wire code
    /// carries the session-index modifier (Part 2, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationOverHmacSessionWithWrongAuthOnDaProtectedSignerChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<CertifyCreationResponse> result = await CertifyCreationOverRealSignSessionAsync(
            tpm, registry, pool, ak, subject, signSlotAuthValue: WrongSignerKeyAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_FAIL, result.BaseError,
            "A wrong guess against a DA-protected signing key must fail the sole slot's command HMAC with TPM_RC_AUTH_FAIL.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
            "The mismatch names the sole slot (index 0), so the wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter + 1, after.Value.LockoutCounter,
            "A wrong guess against a DA-protected signing key must charge failedTries exactly once.");
    }

    /// <summary>
    /// The NO_DA-half contrast to
    /// <see cref="CertifyCreationOverHmacSessionWithWrongAuthOnDaProtectedSignerChargesFailedTries"/> (TPM 2.0
    /// Library Part 2, Table 233, bit 25): a real HMAC session folding a WRONG guess at a
    /// dictionary-attack-EXEMPT signing key's authValue is refused with the plain <c>TPM_RC_BAD_AUTH</c> rather
    /// than the DA-counted <c>TPM_RC_AUTH_FAIL</c>, and moves no counter. The wire code still carries the
    /// session-index modifier for the sole slot (TPM 2.0 Library Part 2, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationOverHmacSessionWithWrongAuthOnNoDaSignerReturnsBadAuthWithoutCharging()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<CertifyCreationResponse> result = await CertifyCreationOverRealSignSessionAsync(
            tpm, registry, pool, ak, subject, signSlotAuthValue: WrongSignerKeyAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError,
            "A wrong guess against a NO_DA signing key must fail the sole slot's command HMAC with the plain TPM_RC_BAD_AUTH, never the DA-counted TPM_RC_AUTH_FAIL.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
            "The mismatch still names the sole slot (index 0), so the wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "A NO_DA signing key's failed comparison must move no dictionary-attack counter.");
    }

    /// <summary>
    /// A sign session BOUND TO THE SIGNING KEY ITSELF attests with no authValue folded into its command HMAC:
    /// binding already incorporated the key's authValue into the session key (TPM 2.0 Library Part 1, clause
    /// 17.6.10, equation 20), so the command HMAC omits it (equations 21/22) — the sole slot's bind-omission
    /// path for TPM2_CertifyCreation() (Part 3, clause 18.3).
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationOverSignSessionBoundToTheSigningKeyItselfAttestsWithNoPerCommandAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(ak.ObjectHandle.Value, HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to the signing key) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession signSession = await TpmSession.CreateBoundAsync(
                new TpmHandle(sessionHandle), SignerKeyAuth, startInput.NonceCaller, started.NonceTPM,
                HmacSessionAlg, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            signSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;

            using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
                ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), subject.Name.Span.ToArray()];

            TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                tpm, certifyCreationInput, [signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
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
    /// A SALTED-and-BOUND HMAC session at the sole signing-key slot attests: the session key folds the bind
    /// entity's authValue then the ECDH-derived salt (TPM 2.0 Library Part 1, clause 17.6.12, equation 25), and
    /// bound to the signing key itself with its real (empty) authValue the per-command HMAC omits it via the
    /// same bind-omission an unsalted bound session uses (clause 17.6.10). Proves the salted-session
    /// channel-protection path composes at TPM2_CertifyCreation()'s sole slot (Part 3, clause 18.3).
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationOverSaltedAndBoundSignSessionAttests()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        using CreatePrimaryResponse saltKey = await CreateStorageParentAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        TpmsEccPoint saltKeyPoint = saltKey.OutPublic.PublicArea.Unique.Ecc!;
        ReadOnlyMemory<byte> saltKeyPublicPoint = EllipticCurveUtilities.CombineToUncompressedPoint(
            saltKeyPoint.X.AsReadOnlySpan(), saltKeyPoint.Y.AsReadOnlySpan());

        TpmEccSigningBackend eccBackend = BouncyCastleTpmEccSigningBackend.Create();
        (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateBoundAndSaltedHmacSession(
            saltKey.ObjectHandle.Value, ak.ObjectHandle.Value, saltKeyPublicPoint, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmAlgIdConstants.TPM_ALG_SHA256, HmacSessionAlg, eccBackend.GenerateKey, eccBackend.ComputeSharedSecret, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using(salt)
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (salted and bound) failed: '{startResult.ResponseCode}'.");
            StartAuthSessionResponse started = startResult.Value;
            uint sessionHandle = started.SessionHandle.Value;

            try
            {
                using TpmSession signSession = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), ReadOnlyMemory<byte>.Empty, startInput.NonceCaller, started.NonceTPM,
                    HmacSessionAlg, pool, symmetric: TpmtSymDef.Null, salt: salt.Memory[..saltLength],
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                signSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;

                using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
                    ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), subject.Name.Span.ToArray()];

                TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                    tpm, certifyCreationInput, [signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"A salted-and-bound sign session must attest: '{result.ResponseCode}'.");
                result.Value.Dispose();
            }
            finally
            {
                _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                    tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// An <c>audit</c> attribute set on the sole signing-key session is refused: this arm models no command audit
    /// (<c>ValidateSessionArea(auditIsSupported: false)</c>), so a session claiming <c>audit</c> is refused with
    /// the session-encoded <c>TPM_RC_ATTRIBUTES</c> (TPM 2.0 Library Part 2, clause 8.4, Table 40; Part 3, clause
    /// 5.6) before the command HMAC is ever evaluated. Audit is the attribute this gate refuses categorically,
    /// which is what makes it the one this test pins: the decrypt and encrypt attributes name the command's
    /// parameter-encryption gates and are admitted on their own terms.
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationOverSignSessionWithAuditAttributeReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            signSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

            using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
                ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), subject.Name.Span.ToArray()];

            TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                tpm, certifyCreationInput, [signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_ATTRIBUTES, result.BaseError,
                "An audit attribute on a session authorizing a command this arm does not audit must be refused with TPM_RC_ATTRIBUTES.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), result.ResponseCode,
                "The refusal names the sole slot (index 0), so the wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// TPM2_CertifyCreation()'s sole signing-key slot (Auth Index 1, Auth Role USER) refuses a
    /// userWithAuth-CLEAR signer's real HMAC session with the bare <c>TPM_RC_POLICY_FAIL</c> even when the
    /// session folds a WRONG guess at the signer's authValue: check 7.1 of the mandatory authorization-check
    /// order (TPM 2.0 Library Part 3, clause 5.6) precedes the queued command-HMAC verification (checks 9/10),
    /// so the wrong guess is never compared — the gate fires before any HMAC is even queued — and the refusal
    /// is uncharged (clause 5.6's closing rule: a non-<c>TPM_RC_AUTH_FAIL</c> error "shall not alter any TPM
    /// state").
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationOverHmacSessionWithUserWithAuthClearSignerAndWrongGuessReturnsPolicyFailNotAuthFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse clearSigner = await CreateUserWithAuthClearSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<CertifyCreationResponse> result = await CertifyCreationOverRealSignSessionAsync(
            tpm, registry, pool, clearSigner, subject, signSlotAuthValue: WrongSignerKeyAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_FAIL, result.BaseError,
            "A userWithAuth-CLEAR signer must refuse a real HMAC session with TPM_RC_POLICY_FAIL, even with a wrong guess.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode,
            "The refusal is the BARE constant, not the session-encoded form a genuine command-HMAC mismatch would carry — the gate runs before that verification is ever queued.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "TPM_RC_POLICY_FAIL is not TPM_RC_AUTH_FAIL, so the userWithAuth gate must move no counter, even though the guess was wrong.");
    }

    /// <summary>
    /// The sole signing-key slot carries the signing key's own DA/Lockout gate (TPM 2.0 Library Part 3, clause
    /// 5.6, check 3): with the TPM in Lockout mode, a DA-protected signing key answers the bare
    /// <c>TPM_RC_LOCKOUT</c> even though the real HMAC session folds the CORRECT authValue — check 3 precedes
    /// the queued command-HMAC verification (checks 7.1 and 9/10), so no credential is ever evaluated.
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationOverHmacSessionWithDaProtectedSignerUnderLockoutReturnsLockout()
    {
        const uint SingleAttemptMaxTries = 1;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse signer = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, SingleAttemptMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        //A single wrong sign password over the all-password arm charges the DA-protected signer and, with
        //maxTries at one, enters Lockout mode as a side effect.
        using(TpmPasswordSession wrongSignAuth = TpmPasswordSession.Create(WrongSignerKeyAuth, pool))
        using(CertifyCreationInput seedingInput = CertifyCreationInput.ForEcdsa(
            signer.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool))
        {
            TpmResult<CertifyCreationResponse> seedingResult = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                tpm, seedingInput, [wrongSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), seedingResult.ResponseCode,
                "The seeding mismatch must be a charged sign-slot auth failure at session index 0.");
        }

        TpmResult<CertifyCreationResponse> result = await CertifyCreationOverRealSignSessionAsync(
            tpm, registry, pool, signer, subject, signSlotAuthValue: SignerKeyAuth).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode,
            "A DA-protected signing key in Lockout mode must be refused before its credential is evaluated, correct or not (clause 5.6's check 3 precedes checks 7.1 and 9/10).");
    }

    /// <summary>
    /// TPM2_CertifyCreation()'s sole slot resolves its session handle against the simulator's own session
    /// tables before any credential is evaluated (TPM 2.0 Library Part 3, clause 5.6, step 2 of the entry
    /// ladder): a genuine POLICY session's handle is a kind of authorization this command's session-authorized
    /// arm does not model, answered with the bare <c>TPM_RC_AUTH_TYPE</c>; a handle that names neither a real
    /// HMAC session nor a policy session — here, one already flushed — is blamed on the offending slot index
    /// with <c>TPM_RC_REFERENCE_S0</c> (TPM 2.0 Library Part 2, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationOverUnresolvableSignSlotHandlesReturnsAuthTypeOrReferenceMiss()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), subject.Name.Span.ToArray()];

        //A real POLICY session's handle at the sole slot.
        TpmResult<StartAuthSessionResponse> policyStartResult = await tpm.StartPolicySessionAsync(HmacSessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");
        using StartAuthSessionResponse policyStarted = policyStartResult.Value;
        uint policySessionHandle = policyStarted.SessionHandle.Value;

        try
        {
            using TpmPolicySession policySlot = TpmPolicySession.ForSession(policySessionHandle, HmacSessionAlg, pool);
            using CertifyCreationInput policyInput = CertifyCreationInput.ForEcdsa(
                ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

            TpmResult<CertifyCreationResponse> policyResult = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                tpm, policyInput, [policySlot], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_TYPE, policyResult.ResponseCode,
                "A genuine POLICY session's handle at the sole slot must be refused with the bare TPM_RC_AUTH_TYPE — a kind of authorization this arm does not model.");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(policySessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }

        //A once-real HMAC session, flushed before use — a handle that is no longer loaded.
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");
        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        using TpmSession unloadedSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext failed: '{flushResult.ResponseCode}'.");

        using CertifyCreationInput unloadedInput = CertifyCreationInput.ForEcdsa(
            ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> unloadedResult = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, unloadedInput, [unloadedSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_REFERENCE_S0, unloadedResult.ResponseCode,
            "A session handle that names neither a real HMAC session nor a policy session must be blamed on the offending slot index (TPM 2.0 Library Part 2, clause 6.6.2).");
    }

    /// <summary>
    /// A creation ticket with one flipped octet still fails the stateless re-verification when the sole
    /// signing-key slot is proven over a REAL HMAC session carrying the signer's CORRECT (empty) authValue: the
    /// command HMAC verifies — the session's own arm never queues a HMAC failure — so the rejection comes
    /// entirely from the effect's ticket comparison, which answers the bare <c>TPM_RC_TICKET</c> with no
    /// attestation and therefore no response session area (TPM 2.0 Library Part 3, clause 18.3). Proven
    /// off-wire: the session adopts NO rolled nonceTPM from this response, because there is no response session
    /// entry for it to verify and roll from.
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationOverHmacSessionWithTamperedTicketReturnsTicketWithNoSessionArea()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmtTkCreation tamperedTicket = FlipTicketOctet(subject.CreationTicket, pool);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            byte[] nonceTpmBeforeCommand = signSession.NonceTpm.ToArray();

            using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
                ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), tamperedTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), subject.Name.Span.ToArray()];

            TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                tpm, certifyCreationInput, [signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_TICKET, result.ResponseCode,
                "A tampered creation ticket over a genuinely-authorized real session must still answer the bare TPM_RC_TICKET — the ticket compare runs inside the effect, after the session's own command HMAC has verified.");
            Assert.IsTrue(
                signSession.NonceTpm.Span.SequenceEqual(nonceTpmBeforeCommand),
                "A TPM_RC_TICKET rejection carries no attestation and therefore no response session area, so the session must adopt no rolled nonceTPM from it.");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Pool balance across TPM2_CertifyCreation()'s session-authorized arm: a REFUSED attempt (a wrong,
    /// non-empty sign password over a real HMAC session) and a SUCCESSFUL one (the correct, non-empty sign
    /// password over a fresh real HMAC session) each return every carrier they rented — the session and the
    /// queued request alike — to the pool, proven with real pool telemetry (<see cref="MeteredHousePool"/>),
    /// never an internal hook. A mid-scenario liveness check in each area proves the rentals were genuinely
    /// live before the balance is asserted.
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationOverHmacSessionReturnsEveryRentedCarrierToPoolAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        StartAuthSessionInput refusedStartInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> refusedStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, refusedStartInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(refusedStartResult.IsSuccess, $"StartAuthSession (refused area) failed: '{refusedStartResult.ResponseCode}'.");
        StartAuthSessionResponse refusedStarted = refusedStartResult.Value;
        uint refusedSessionHandle = refusedStarted.SessionHandle.Value;

        try
        {
            using TpmSession refusedSession = new(new TpmHandle(refusedSessionHandle), refusedStarted.NonceTPM, HmacSessionAlg, trackingPool.Pool);
            refusedSession.SetAuthValue(WrongSignerKeyAuth, trackingPool.Pool);

            using CertifyCreationInput refusedInput = CertifyCreationInput.ForEcdsa(
                ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), subject.Name.Span.ToArray()];

            Assert.IsGreaterThan(
                baseline, trackingPool.OutstandingCount,
                "The wrong-password session and the queued request must hold live carrier rentals, or the refused-area balance assertion below is vacuous.");

            TpmResult<CertifyCreationResponse> refusedResult = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                tpm, refusedInput, [refusedSession], handleNames, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), refusedResult.ResponseCode,
                "The refused attempt must be a charged sign-slot auth failure at session index 0.");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(refusedSessionHandle), [], null, trackingPool.Pool, registry, CancellationToken.None).ConfigureAwait(false);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refused area must return every rented carrier to the pool.");

        StartAuthSessionInput successStartInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> successStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, successStartInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(successStartResult.IsSuccess, $"StartAuthSession (successful area) failed: '{successStartResult.ResponseCode}'.");
        StartAuthSessionResponse successStarted = successStartResult.Value;
        uint successSessionHandle = successStarted.SessionHandle.Value;

        try
        {
            using TpmSession successSession = new(new TpmHandle(successSessionHandle), successStarted.NonceTPM, HmacSessionAlg, trackingPool.Pool);
            successSession.SetAuthValue(SignerKeyAuth, trackingPool.Pool);

            using CertifyCreationInput successInput = CertifyCreationInput.ForEcdsa(
                ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), subject.Name.Span.ToArray()];

            Assert.IsGreaterThan(
                baseline, trackingPool.OutstandingCount,
                "The correct-password session and the queued request must hold live carrier rentals, or the successful-area balance assertion below is vacuous.");

            TpmResult<CertifyCreationResponse> successResult = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                tpm, successInput, [successSession], handleNames, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(successResult.IsSuccess, $"The correctly-authorized attempt must attest: '{successResult.ResponseCode}'.");
            successResult.Value.Dispose();
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(successSessionHandle), [], null, trackingPool.Pool, registry, CancellationToken.None).ConfigureAwait(false);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The successful area must likewise return every rented carrier to the pool.");
    }

    /// <summary>
    /// Certifies <paramref name="subject"/>'s creation with <paramref name="ak"/>, authorizing the sole
    /// signing-key slot with a fresh, real, unbound/unsalted HMAC session (TPM 2.0 Library Part 1, clause
    /// 17.6.9, equation 19) carrying <paramref name="signSlotAuthValue"/>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <param name="subject">The certified object's CreatePrimary response.</param>
    /// <param name="signSlotAuthValue">The authValue term folded into the sign session; empty for the honest shape.</param>
    /// <returns>The certify-creation result.</returns>
    private async Task<TpmResult<CertifyCreationResponse>> CertifyCreationOverRealSignSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse ak, CreatePrimaryResponse subject, ReadOnlyMemory<byte> signSlotAuthValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (sign slot) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            if(!signSlotAuthValue.IsEmpty)
            {
                signSession.SetAuthValue(signSlotAuthValue.Span, pool);
            }

            using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
                ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), subject.Name.Span.ToArray()];

            return await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                tpm, certifyCreationInput, [signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Creates a DA-EXEMPT primary ECC P-256 signing key under the endorsement hierarchy with a NON-EMPTY
    /// authValue (<see cref="SignerKeyPassword"/>) — the NO_DA contrast fixture to
    /// <see cref="CreateDaProtectedSigningPrimaryWithAuthAsync"/>, used to prove a failed sign-slot compare
    /// answers the plain <c>TPM_RC_BAD_AUTH</c> rather than the DA-counted <c>TPM_RC_AUTH_FAIL</c>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateNoDaSigningPrimaryWithAuthAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_ENDORSEMENT,
            password: SignerKeyPassword,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (NO_DA ECC signer with authValue) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Extends <see cref="CreateRegistry"/> with the StartAuthSession/FlushContext codecs the real-session tests need.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateHmacArmRegistry()
    {
        TpmResponseRegistry registry = CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }
}
