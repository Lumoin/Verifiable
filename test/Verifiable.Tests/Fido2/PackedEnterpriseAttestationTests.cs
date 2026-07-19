using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for WP-Enterprise — <see href="https://www.w3.org/TR/webauthn-3/#sctn-enterprise-packed-attestation-cert-requirements">WebAuthn
/// L3 section 8.2.2, Certificate Requirements for Enterprise Packed Attestation Statements</see>
/// (OID <c>1.3.6.1.4.1.45724.1.1.2</c>, <c>id-fido-gen-ce-sernum</c>): <see cref="PackedAttestation"/>'s
/// enterprise attestation serial-number extension handling on the certified (<c>x5c</c>-present)
/// branch — presence gated on <see cref="AttestationVerificationRequest.AcceptsEnterpriseAttestation"/>,
/// non-criticality enforced as documented defense-in-depth alongside the section 8.2.1 AAGUID
/// extension's identical shape (<c>PackedAttestation.cs</c> lines 228-250).
/// </summary>
/// <remarks>
/// Every fixture mints its certificate chain and attestation signature with an independent oracle —
/// raw <see cref="ECDsa"/> and <see cref="CertificateRequest"/>, never the library's own signing or
/// chain-building seams — so <see cref="PackedAttestation"/> is exercised against genuinely external
/// wire material reconstructed solely from the <see cref="AttestationVerificationRequest"/>'s
/// wire-shaped members.
/// </remarks>
[TestClass]
internal sealed class PackedEnterpriseAttestationTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>
    /// The dotted OID of the <c>id-fido-gen-ce-sernum</c> extension, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-enterprise-packed-attestation-cert-requirements">section 8.2.2</see>.
    /// </summary>
    private const string SernumExtensionOid = "1.3.6.1.4.1.45724.1.1.2";


    /// <summary>
    /// A leaf carrying a present, non-critical sernum extension is rejected with
    /// <see cref="Fido2AttestationErrors.SerialNumberExtensionNotPermitted"/> when the request did
    /// not accept enterprise attestation — section 8.2.2's "This extension MUST NOT be present in
    /// non-enterprise attestations" — exercised through a permissive injected chain validator so the
    /// in-layer presence check, not chain validation, is what rejects.
    /// </summary>
    [TestMethod]
    public async Task SernumExtensionPresentWithoutAcceptingEnterpriseIsRejectedWithSerialNumberExtensionNotPermitted()
    {
        Fido2AttestationError? error = await VerifySernumChainAsync(
            serialNumber: [1, 2, 3, 4], sernumCritical: false, acceptsEnterpriseAttestation: false, useRealChainValidator: false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.SerialNumberExtensionNotPermitted.Code, error.Code);
    }


    /// <summary>
    /// A leaf carrying a present, non-critical sernum extension verifies successfully when the
    /// request accepted enterprise attestation — the positive enterprise path.
    /// </summary>
    [TestMethod]
    public async Task SernumExtensionPresentWithAcceptingEnterpriseVerifiesAsCertifiedResult()
    {
        AttestationResult result = await VerifySernumChainRawAsync(
            serialNumber: [1, 2, 3, 4], sernumCritical: false, acceptsEnterpriseAttestation: true, useRealChainValidator: false);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>
    /// A leaf with no sernum extension verifies successfully with the default (unaccepted)
    /// enterprise-attestation request through the real registered chain validator — the regression
    /// control proving the new section 8.2.2 code path does not disturb the existing non-enterprise
    /// certified verification.
    /// </summary>
    [TestMethod]
    public async Task NoSernumExtensionWithDefaultRequestVerifiesAsCertifiedResult()
    {
        AttestationResult result = await VerifySernumChainRawAsync(
            serialNumber: null, sernumCritical: false, acceptsEnterpriseAttestation: false, useRealChainValidator: true);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>
    /// A leaf whose sernum extension is marked critical is rejected with
    /// <see cref="Fido2AttestationErrors.ChainValidationFailed"/> through the real registered chain
    /// validator: RFC 5280 section 4.2 requires rejecting a certificate carrying an unrecognised
    /// critical extension, and both registered chain validators enforce that during chain building —
    /// before <see cref="PackedAttestation"/>'s own section 8.2.2 non-criticality check ever runs,
    /// mirroring the AAGUID/firmware-version critical-extension precedents
    /// (<c>PackedCertificateProfileTests.AaguidExtensionMarkedCriticalIsRejectedWithChainValidationFailed</c>
    /// and <c>...LeafWithCriticalFirmwareVersionExtensionIsRejectedWithChainValidationFailed</c>).
    /// </summary>
    [TestMethod]
    public async Task SernumExtensionCriticalIsRejectedWithChainValidationFailed()
    {
        Fido2AttestationError? error = await VerifySernumChainAsync(
            serialNumber: [1, 2, 3, 4], sernumCritical: true, acceptsEnterpriseAttestation: true, useRealChainValidator: true);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, error.Code);
    }


    /// <summary>
    /// A leaf whose sernum extension is marked critical is rejected with
    /// <see cref="Fido2AttestationErrors.CertificateProfileViolation"/> through a permissive
    /// injected chain validator that does not itself enforce RFC 5280 section 4.2 — proving
    /// <see cref="PackedAttestation"/>'s own in-layer defense-in-depth check exists independent of
    /// the chain validator's enforcement, the wave-8 lesson.
    /// </summary>
    [TestMethod]
    public async Task SernumExtensionCriticalThroughPermissiveValidatorIsRejectedWithCertificateProfileViolation()
    {
        Fido2AttestationError? error = await VerifySernumChainAsync(
            serialNumber: [1, 2, 3, 4], sernumCritical: true, acceptsEnterpriseAttestation: true, useRealChainValidator: false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>
    /// <see cref="CtapWaveEpFixtures.EncodeSernumExtensionValue"/> emits a single DER OCTET STRING — not
    /// the AAGUID extension's double-OCTET-STRING wrap (<see cref="Fido2AttestationTestVectors.EncodeAaguidExtensionValue"/>) —
    /// decoded back with an independent <see cref="AsnReader"/> and compared against a hand-built value.
    /// </summary>
    [TestMethod]
    public void EncodeSernumExtensionValueProducesSingleOctetStringWrap()
    {
        byte[] serialNumber = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] encoded = CtapWaveEpFixtures.EncodeSernumExtensionValue(serialNumber);

        var reader = new AsnReader(encoded, AsnEncodingRules.DER);
        byte[] decoded = reader.ReadOctetString();

        Assert.IsFalse(reader.HasData);
        Assert.AreSequenceEqual(serialNumber, decoded);

        var handWritten = new AsnWriter(AsnEncodingRules.DER);
        handWritten.WriteOctetString(serialNumber);
        Assert.AreSequenceEqual(handWritten.Encode(), encoded);
    }


    /// <summary>
    /// Mints a section 8.2.1-conformant certified packed attestation chain, optionally carrying the
    /// sernum extension, verifies it, and returns the rejection error, if any.
    /// </summary>
    /// <param name="serialNumber">The sernum extension's octet-string value, or <see langword="null"/> to omit the extension.</param>
    /// <param name="sernumCritical">The sernum extension's criticality, when present.</param>
    /// <param name="acceptsEnterpriseAttestation">The <see cref="AttestationVerificationRequest.AcceptsEnterpriseAttestation"/> value.</param>
    /// <param name="useRealChainValidator">Whether chain validation runs through the real registered Microsoft backend; see <see cref="VerifySernumChainRawAsync"/>.</param>
    /// <returns>The <see cref="Fido2AttestationError"/> of a <see cref="RejectedAttestationResult"/>, or <see langword="null"/>.</returns>
    private async Task<Fido2AttestationError?> VerifySernumChainAsync(
        byte[]? serialNumber, bool sernumCritical, bool acceptsEnterpriseAttestation, bool useRealChainValidator)
    {
        AttestationResult result = await VerifySernumChainRawAsync(serialNumber, sernumCritical, acceptsEnterpriseAttestation, useRealChainValidator);

        return result is RejectedAttestationResult rejected ? rejected.Error : null;
    }


    /// <summary>
    /// Mints a section 8.2.1-conformant certified packed attestation chain, optionally carrying the
    /// sernum extension, and returns the raw <see cref="AttestationResult"/>.
    /// </summary>
    /// <param name="serialNumber">The sernum extension's octet-string value, or <see langword="null"/> to omit the extension.</param>
    /// <param name="sernumCritical">The sernum extension's criticality, when present.</param>
    /// <param name="acceptsEnterpriseAttestation">The <see cref="AttestationVerificationRequest.AcceptsEnterpriseAttestation"/> value.</param>
    /// <param name="useRealChainValidator">
    /// When <see langword="true"/>, chain validation runs through the real registered Microsoft
    /// backend (<see cref="MicrosoftX509Functions.ValidateChainAsync"/>). When <see langword="false"/>,
    /// a permissive stub validator is injected (<see cref="CreatePermissiveChainValidator"/>) that
    /// returns the leaf's own public key without enforcing RFC 5280 section 4.2's critical-extension
    /// rejection, so <see cref="PackedAttestation"/>'s own in-layer checks are what is exercised.
    /// </param>
    /// <returns>The raw verification result.</returns>
    private async Task<AttestationResult> VerifySernumChainRawAsync(
        byte[]? serialNumber, bool sernumCritical, bool acceptsEnterpriseAttestation, bool useRealChainValidator)
    {
        //Cert-factory carve-out: feeds CreateSelfSignedCa below, which mints the root CA via CertificateRequest —
        //an API that requires a genuine framework ECDsa signing key, not opaque key-material memory.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //Independent-oracle carve-out: this same key backs the leaf certificate (CertificateRequest, cert-factory
        //carve-out) and signs the attestation statement via SignWithEcdsaP256 below, so PackedAttestation verifies
        //wire material against a framework ECDsa implementation genuinely independent of the library's own signing seam.
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        IReadOnlyList<X509Extension>? additionalExtensions = serialNumber is null
            ? null
            : [new X509Extension(SernumExtensionOid, CtapWaveEpFixtures.EncodeSernumExtensionValue(serialNumber), critical: sernumCritical)];

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit,
            aaguidExtensionValue: null, additionalExtensions: additionalExtensions);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: [leafPki, rootPki]);
        ValidateCertificateChainAsyncDelegate validateChain = useRealChainValidator
            ? MicrosoftX509Functions.ValidateChainAsync
            : CreatePermissiveChainValidator(credentialPublicKey);

        AttestationVerifyDelegate verify = PackedAttestation.Build(
            Fido2AttestationTestVectors.CreateStatementParser(statement),
            validateChain,
            MicrosoftX509Functions.ReadCertificateProfile,
            MicrosoftX509Functions.ReadCertificateExtensionValue);

        var request = new AttestationVerificationRequest(
            authenticatorDataBytes: authDataBytes,
            authenticatorData: authenticatorData,
            clientDataHash: clientDataHash,
            attestationStatement: ReadOnlyMemory<byte>.Empty,
            trustAnchors: [rootPki],
            validationTime: TestClock.CanonicalEpoch,
            pool: BaseMemoryPool.Shared)
        {
            AcceptsEnterpriseAttestation = acceptsEnterpriseAttestation
        };

        return await verify(request, TestContext.CancellationToken);
    }


    /// <summary>
    /// Builds a permissive <see cref="ValidateCertificateChainAsyncDelegate"/> stub that returns
    /// <paramref name="leafCredentialKey"/>'s own public key without validating the chain at all —
    /// no trust-anchor check, no RFC 5280 section 4.2 critical-extension rejection — so a test can
    /// reach <see cref="PackedAttestation"/>'s own in-layer checks regardless of how the injected
    /// validator would otherwise have rejected the certificate first.
    /// </summary>
    /// <param name="leafCredentialKey">The credential's own public key, returned as the "leaf key" on every call.</param>
    /// <returns>The permissive stub delegate.</returns>
    private static ValidateCertificateChainAsyncDelegate CreatePermissiveChainValidator(CoseKey leafCredentialKey) =>
        (chain, trustAnchors, validationTime, pool, cancellationToken, checkRevocation) =>
            ValueTask.FromResult(leafCredentialKey.ToPublicKeyMemory(pool));
}
