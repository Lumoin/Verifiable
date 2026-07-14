using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for the certified (<c>x5c</c>-present) branch of <see cref="PackedAttestation"/> exercising the two
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web Authentication Level 3,
/// section 7.1</see> clauses the chain-validation seam alone cannot satisfy: that the Relying Party MUST have
/// access to certificate status information for the INTERMEDIATE CA certificates (not only the leaf), and that
/// the Relying Party MUST be able to build the attestation certificate chain when the client's <c>x5c</c> omits
/// intermediates. Every fixture mints a real three-certificate chain (root CA → intermediate CA → leaf) with an
/// independent oracle, firewalled through the real <see cref="PackedAttestation.Build"/> composition.
/// </summary>
[TestClass]
internal sealed class PackedRevocationAndChainCompletionTests
{
    /// <summary>The fixed instant every minted certificate and CRL in this file is validated at.</summary>
    private static DateTimeOffset ValidationTime { get; } = new(2027, 6, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The CRL validity window's start, relative to <see cref="ValidationTime"/>.</summary>
    private static DateTimeOffset CrlThisUpdate { get; } = ValidationTime.AddDays(-1);

    /// <summary>The CRL validity window's end, relative to <see cref="ValidationTime"/>.</summary>
    private static DateTimeOffset CrlNextUpdate { get; } = ValidationTime.AddDays(30);


    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A leaf revoked by a CRL issued by its immediate issuer (the intermediate CA) is rejected, even though the
    /// intermediate itself is never reached because the leaf check fails first.
    /// </summary>
    [TestMethod]
    public async Task RevokedLeafCrlFromIntermediateIsRejectedWithChainValidationFailed()
    {
        using ChainFixture fixture = CreateChainFixture();
        using PkiCertificateMemory revokingLeafCrl = SyntheticPassportFactory.MintCrl(
            fixture.IntermediateCertificate, fixture.LeafCertificate, CrlThisUpdate, CrlNextUpdate, crlNumber: 1);

        var checker = new CrlRevocationChecker([revokingLeafCrl]);
        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(
            fixture, x5c: [fixture.LeafPki, fixture.IntermediatePki], checkRevocation: checker.CheckAsync, completeChain: null);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, error.Code);
    }


    /// <summary>
    /// The clause 6112 test: a leaf with a clean revocation status but an INTERMEDIATE CA certificate revoked by a
    /// CRL issued by the root is rejected — satisfiable only because the chain-validation seam consults revocation
    /// for every non-anchor certificate in the chain, not the leaf alone.
    /// </summary>
    [TestMethod]
    public async Task RevokedIntermediateCrlFromRootIsRejectedWithChainValidationFailed()
    {
        using ChainFixture fixture = CreateChainFixture();
        using PkiCertificateMemory cleanLeafCrl = SyntheticPassportFactory.MintCrl(
            fixture.IntermediateCertificate, revokedCertificate: null, CrlThisUpdate, CrlNextUpdate, crlNumber: 1);
        using PkiCertificateMemory revokingIntermediateCrl = SyntheticPassportFactory.MintCrl(
            fixture.RootCertificate, fixture.IntermediateCertificate, CrlThisUpdate, CrlNextUpdate, crlNumber: 2);

        var checker = new CrlRevocationChecker([cleanLeafCrl, revokingIntermediateCrl]);
        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(
            fixture, x5c: [fixture.LeafPki, fixture.IntermediatePki], checkRevocation: checker.CheckAsync, completeChain: null);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, error.Code);
    }


    /// <summary>A clean CRL covering both the leaf and the intermediate lets the certified attestation verify.</summary>
    [TestMethod]
    public async Task AllGoodCrlsAcrossLeafAndIntermediateReturnsCertifiedResult()
    {
        using ChainFixture fixture = CreateChainFixture();
        using PkiCertificateMemory cleanLeafCrl = SyntheticPassportFactory.MintCrl(
            fixture.IntermediateCertificate, revokedCertificate: null, CrlThisUpdate, CrlNextUpdate, crlNumber: 1);
        using PkiCertificateMemory cleanIntermediateCrl = SyntheticPassportFactory.MintCrl(
            fixture.RootCertificate, revokedCertificate: null, CrlThisUpdate, CrlNextUpdate, crlNumber: 2);

        var checker = new CrlRevocationChecker([cleanLeafCrl, cleanIntermediateCrl]);
        AttestationResult result = await VerifyAsync(
            fixture, x5c: [fixture.LeafPki, fixture.IntermediatePki], checkRevocation: checker.CheckAsync, completeChain: null);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>
    /// A revocation checker is wired but no supplied CRL covers the chain: the status is
    /// <see cref="CertificateRevocationStatus.Unknown"/> for the leaf, and the fail-closed policy rejects exactly
    /// as it would a confirmed revocation.
    /// </summary>
    [TestMethod]
    public async Task NoAuthoritativeCrlForTheChainIsRejectedWithChainValidationFailed()
    {
        using ChainFixture fixture = CreateChainFixture();
        var checker = new CrlRevocationChecker([]);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(
            fixture, x5c: [fixture.LeafPki, fixture.IntermediatePki], checkRevocation: checker.CheckAsync, completeChain: null);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, error.Code);
    }


    /// <summary>Positive control: with no revocation checker configured, behavior is unchanged and no CRL is needed.</summary>
    [TestMethod]
    public async Task NoRevocationCheckerConfiguredIsUnchangedAndReturnsCertifiedResult()
    {
        using ChainFixture fixture = CreateChainFixture();

        AttestationResult result = await VerifyAsync(
            fixture, x5c: [fixture.LeafPki, fixture.IntermediatePki], checkRevocation: null, completeChain: null);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>
    /// The clause 6113 test: the wire <c>x5c</c> carries the leaf only, but a <see cref="CertificateChainCompleter"/>
    /// configured with the intermediate lets the chain complete to the root trust anchor and verify successfully.
    /// </summary>
    [TestMethod]
    public async Task LeafOnlyX5cWithChainCompleterHoldingIntermediateSucceeds()
    {
        using ChainFixture fixture = CreateChainFixture();
        var completer = new CertificateChainCompleter([fixture.IntermediatePki]);

        AttestationResult result = await VerifyAsync(
            fixture, x5c: [fixture.LeafPki], checkRevocation: null, completeChain: completer.CompleteAsync);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>A leaf-only <c>x5c</c> with a completer whose store holds nothing cannot be completed and is rejected.</summary>
    [TestMethod]
    public async Task LeafOnlyX5cWithEmptyCompleterStoreIsRejectedWithChainValidationFailed()
    {
        using ChainFixture fixture = CreateChainFixture();
        var completer = new CertificateChainCompleter([]);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(
            fixture, x5c: [fixture.LeafPki], checkRevocation: null, completeChain: completer.CompleteAsync);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, error.Code);
    }


    /// <summary>Unchanged-behavior control: a leaf-only <c>x5c</c> with no completer configured cannot chain to the root and is rejected.</summary>
    [TestMethod]
    public async Task LeafOnlyX5cWithNoCompleterIsRejectedWithChainValidationFailed()
    {
        using ChainFixture fixture = CreateChainFixture();

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(
            fixture, x5c: [fixture.LeafPki], checkRevocation: null, completeChain: null);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, error.Code);
    }


    /// <summary>
    /// Chain completion and revocation compose: the leaf-only <c>x5c</c> completes through the intermediate, whose
    /// revocation status is then checked against the completed (not merely the wire-supplied) chain and found
    /// revoked.
    /// </summary>
    [TestMethod]
    public async Task CompletedChainWithRevokedIntermediateIsRejectedWithChainValidationFailed()
    {
        using ChainFixture fixture = CreateChainFixture();
        using PkiCertificateMemory cleanLeafCrl = SyntheticPassportFactory.MintCrl(
            fixture.IntermediateCertificate, revokedCertificate: null, CrlThisUpdate, CrlNextUpdate, crlNumber: 1);
        using PkiCertificateMemory revokingIntermediateCrl = SyntheticPassportFactory.MintCrl(
            fixture.RootCertificate, fixture.IntermediateCertificate, CrlThisUpdate, CrlNextUpdate, crlNumber: 2);

        var checker = new CrlRevocationChecker([cleanLeafCrl, revokingIntermediateCrl]);
        var completer = new CertificateChainCompleter([fixture.IntermediatePki]);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(
            fixture, x5c: [fixture.LeafPki], checkRevocation: checker.CheckAsync, completeChain: completer.CompleteAsync);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, error.Code);
    }


    /// <summary>Mints the shared root CA → intermediate CA → leaf fixture every test method verifies against.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the root, intermediate, and leaf certificates transfers to the returned ChainFixture, which the caller disposes.")]
    private static ChainFixture CreateChainFixture()
    {
        //X.509 certificate factory carve-out: CertificateRequest signs the self-signed root CA with this key.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //X.509 certificate factory carve-out: CertificateRequest signs the intermediate CA with this key.
        using ECDsa intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //X.509 certificate factory carve-out: CertificateRequest signs the leaf certificate with this key. It is
        //also an independent-oracle carve-out: this same key signs the attestation transcript below, which
        //PackedAttestation's own signature verification (leafPublicKey.VerifyAsync) must independently confirm
        //against the certificate's public key, firewalled from how that signature was produced.
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Chain Root", rootKey);
        X509Certificate2 intermediateCert;
        X509Certificate2 leafCert;
        try
        {
            intermediateCert = Fido2AttestationTestVectors.CreateIntermediateCaCertificate(rootCert, intermediateKey);
        }
        catch
        {
            rootCert.Dispose();
            throw;
        }

        try
        {
            X509Extension leafAuthorityKeyIdentifier = Fido2AttestationTestVectors.CreateLeafAuthorityKeyIdentifierExtension(intermediateCert);
            leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
                intermediateCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit,
                aaguidExtensionValue: null, additionalExtensions: [leafAuthorityKeyIdentifier]);
        }
        catch
        {
            intermediateCert.Dispose();
            rootCert.Dispose();
            throw;
        }

        PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        PkiCertificateMemory intermediatePki = Fido2AttestationTestVectors.ToPkiCertificateMemory(intermediateCert.RawData);
        PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);

        DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256);
        AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        return new ChainFixture(rootCert, intermediateCert, leafCert, rootPki, intermediatePki, leafPki, clientDataHash, authenticatorData, authDataBytes, signature);
    }


    /// <summary>Builds and runs the <see cref="PackedAttestation"/> verifier for a chosen <c>x5c</c> and Build-time seams.</summary>
    /// <param name="fixture">The chain fixture supplying the request's fixed members.</param>
    /// <param name="x5c">The certificates to present as the statement's <c>x5c</c>.</param>
    /// <param name="checkRevocation">The revocation seam to wire, or <see langword="null"/> for none.</param>
    /// <param name="completeChain">The chain-completion seam to wire, or <see langword="null"/> for none.</param>
    /// <returns>The verification result.</returns>
    private async Task<AttestationResult> VerifyAsync(
        ChainFixture fixture,
        IReadOnlyList<PkiCertificateMemory> x5c,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
        CompleteCertificateChainAsyncDelegate? completeChain)
    {
        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: fixture.Signature, X5c: x5c);
        AttestationVerifyDelegate verify = PackedAttestation.Build(
            Fido2AttestationTestVectors.CreateStatementParser(statement),
            MicrosoftX509Functions.ValidateChainAsync,
            MicrosoftX509Functions.ReadCertificateProfile,
            MicrosoftX509Functions.ReadCertificateExtensionValue,
            checkRevocation,
            completeChain);

        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            fixture.AuthDataBytes, fixture.AuthenticatorData, fixture.ClientDataHash,
            attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [fixture.RootPki], validationTime: ValidationTime);

        return await verify(request, TestContext.CancellationToken);
    }


    /// <summary>Runs <see cref="VerifyAsync"/> and returns the rejection error, if any.</summary>
    /// <param name="fixture">The chain fixture supplying the request's fixed members.</param>
    /// <param name="x5c">The certificates to present as the statement's <c>x5c</c>.</param>
    /// <param name="checkRevocation">The revocation seam to wire, or <see langword="null"/> for none.</param>
    /// <param name="completeChain">The chain-completion seam to wire, or <see langword="null"/> for none.</param>
    /// <returns>The <see cref="Fido2AttestationError"/> of a <see cref="RejectedAttestationResult"/>, or <see langword="null"/>.</returns>
    private async Task<Fido2AttestationError?> VerifyAndGetRejectionErrorAsync(
        ChainFixture fixture,
        IReadOnlyList<PkiCertificateMemory> x5c,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
        CompleteCertificateChainAsyncDelegate? completeChain)
    {
        AttestationResult result = await VerifyAsync(fixture, x5c, checkRevocation, completeChain);

        return result is RejectedAttestationResult rejected ? rejected.Error : null;
    }
}


/// <summary>
/// A firewalled root CA → intermediate CA → leaf attestation certificate chain, plus the signed
/// <c>authenticatorData || clientDataHash</c> transcript every test method in
/// <see cref="PackedRevocationAndChainCompletionTests"/> verifies against. Owns and disposes every certificate and
/// carrier.
/// </summary>
internal sealed class ChainFixture: IDisposable
{
    /// <summary>Initialises a new <see cref="ChainFixture"/>, taking ownership of every certificate and carrier.</summary>
    public ChainFixture(
        X509Certificate2 rootCertificate,
        X509Certificate2 intermediateCertificate,
        X509Certificate2 leafCertificate,
        PkiCertificateMemory rootPki,
        PkiCertificateMemory intermediatePki,
        PkiCertificateMemory leafPki,
        DigestValue clientDataHash,
        AuthenticatorData authenticatorData,
        byte[] authDataBytes,
        byte[] signature)
    {
        RootCertificate = rootCertificate;
        IntermediateCertificate = intermediateCertificate;
        LeafCertificate = leafCertificate;
        RootPki = rootPki;
        IntermediatePki = intermediatePki;
        LeafPki = leafPki;
        ClientDataHash = clientDataHash;
        AuthenticatorData = authenticatorData;
        AuthDataBytes = authDataBytes;
        Signature = signature;
    }


    /// <summary>Gets the root CA certificate (private key attached), the trust anchor.</summary>
    public X509Certificate2 RootCertificate { get; }

    /// <summary>Gets the intermediate CA certificate (private key attached), issued by <see cref="RootCertificate"/>.</summary>
    public X509Certificate2 IntermediateCertificate { get; }

    /// <summary>Gets the leaf attestation certificate (private key attached), issued by <see cref="IntermediateCertificate"/>.</summary>
    public X509Certificate2 LeafCertificate { get; }

    /// <summary>Gets the pooled certificate carrier for <see cref="RootCertificate"/>.</summary>
    public PkiCertificateMemory RootPki { get; }

    /// <summary>Gets the pooled certificate carrier for <see cref="IntermediateCertificate"/>.</summary>
    public PkiCertificateMemory IntermediatePki { get; }

    /// <summary>Gets the pooled certificate carrier for <see cref="LeafCertificate"/>.</summary>
    public PkiCertificateMemory LeafPki { get; }

    /// <summary>Gets the <c>clientDataHash</c> digest the attestation signature covers.</summary>
    public DigestValue ClientDataHash { get; }

    /// <summary>Gets the parsed <c>authData</c> view aliasing <see cref="AuthDataBytes"/>.</summary>
    public AuthenticatorData AuthenticatorData { get; }

    /// <summary>Gets the raw <c>authData</c> bytes the attestation signature covers.</summary>
    public byte[] AuthDataBytes { get; }

    /// <summary>Gets the leaf-signed attestation statement signature over <c>authData || clientDataHash</c>.</summary>
    public byte[] Signature { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        RootCertificate.Dispose();
        IntermediateCertificate.Dispose();
        LeafCertificate.Dispose();
        RootPki.Dispose();
        IntermediatePki.Dispose();
        LeafPki.Dispose();
        ClientDataHash.Dispose();
        AuthenticatorData.Dispose();
    }
}
