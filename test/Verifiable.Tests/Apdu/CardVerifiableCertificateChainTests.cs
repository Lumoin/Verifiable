using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Apdu.Eac;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates card-verifiable certificate chain verification (BSI TR-03110-3 §2.5): each certificate's
/// signature is checked against the issuer's public key, the holder/authority references link the chain,
/// the role narrows CVCA -> Document Verifier -> terminal, and validity is enforced against a reference
/// date. The chain is minted with the framework's own ECDSA (an independent signer) and verified through
/// the library's registered verification function, so the verifier only ever sees the wire bytes.
/// </summary>
[TestClass]
internal sealed class CardVerifiableCertificateChainTests
{
    private static readonly DateOnly Effective = new(2024, 1, 1);
    private static readonly DateOnly Expiration = new(2026, 1, 1);
    private static readonly DateOnly WithinValidity = new(2025, 1, 1);


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task VerifiesWellFormedCvcaToDocumentVerifierToTerminalChain()
    {
        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentVerifierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using CardVerifiableCertificate cvca = MintCvca(cvcaKey, "UTCVCA00001");
        Tag curve = cvca.PublicKey.EllipticCurvePoint!.Tag;
        using CardVerifiableCertificate documentVerifier = MintDocumentVerifier(cvcaKey, documentVerifierKey, "UTCVCA00001", "UTDVDE00001", curve);
        using CardVerifiableCertificate terminal = MintTerminal(documentVerifierKey, terminalKey, "UTDVDE00001", "UTISDE00001", curve);

        CvcChainVerificationResult result = await CardVerifiableCertificateChain.VerifyAsync(
            cvca, [documentVerifier, terminal], WithinValidity, TestContext.CancellationToken);

        Assert.AreEqual(CvcChainVerificationResult.Valid, result, "A correctly signed, linked, role-narrowing, in-validity chain verifies.");
    }


    [TestMethod]
    public async Task RejectsChainWithAForgedSignature()
    {
        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentVerifierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using CardVerifiableCertificate cvca = MintCvca(cvcaKey, "UTCVCA00001");
        Tag curve = cvca.PublicKey.EllipticCurvePoint!.Tag;
        using CardVerifiableCertificate documentVerifier = MintDocumentVerifier(cvcaKey, documentVerifierKey, "UTCVCA00001", "UTDVDE00001", curve);
        //The terminal certificate is signed by its own key, not the Document Verifier's, so the signature
        //does not verify against the Document Verifier public key.
        using CardVerifiableCertificate terminal = MintTerminal(terminalKey, terminalKey, "UTDVDE00001", "UTISDE00001", curve);

        CvcChainVerificationResult result = await CardVerifiableCertificateChain.VerifyAsync(
            cvca, [documentVerifier, terminal], WithinValidity, TestContext.CancellationToken);

        Assert.AreEqual(CvcChainVerificationResult.InvalidSignature, result, "A certificate not signed by its issuer is rejected.");
    }


    [TestMethod]
    public async Task RejectsChainWithABrokenReference()
    {
        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentVerifierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using CardVerifiableCertificate cvca = MintCvca(cvcaKey, "UTCVCA00001");
        Tag curve = cvca.PublicKey.EllipticCurvePoint!.Tag;
        //The Document Verifier names a different authority than the CVCA holder reference.
        using CardVerifiableCertificate documentVerifier = MintDocumentVerifier(cvcaKey, documentVerifierKey, "UTCVCA99999", "UTDVDE00001", curve);

        CvcChainVerificationResult result = await CardVerifiableCertificateChain.VerifyAsync(
            cvca, [documentVerifier], WithinValidity, TestContext.CancellationToken);

        Assert.AreEqual(CvcChainVerificationResult.BrokenChain, result, "A Certification Authority Reference that does not match the issuer is rejected.");
    }


    [TestMethod]
    public async Task RejectsCvcaIssuingATerminalDirectly()
    {
        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using CardVerifiableCertificate cvca = MintCvca(cvcaKey, "UTCVCA00001");
        Tag curve = cvca.PublicKey.EllipticCurvePoint!.Tag;
        //Linked and validly signed by the CVCA, but a terminal role: a CVCA may only issue Document Verifiers.
        using CardVerifiableCertificate terminal = MintTerminal(cvcaKey, terminalKey, "UTCVCA00001", "UTISDE00001", curve);

        CvcChainVerificationResult result = await CardVerifiableCertificateChain.VerifyAsync(
            cvca, [terminal], WithinValidity, TestContext.CancellationToken);

        Assert.AreEqual(CvcChainVerificationResult.InvalidRole, result, "A CVCA may not issue a terminal certificate directly.");
    }


    [TestMethod]
    public async Task VerifiesAFullRsaCvcaToDocumentVerifierToTerminalChain()
    {
        using RSA cvcaKey = RSA.Create(2048);
        using RSA documentVerifierKey = RSA.Create(2048);
        using RSA terminalKey = RSA.Create(2048);

        //Every certificate is RSA-signed by its RSA issuer (id-TA-RSA-v1-5-SHA-256); an RSA certificate carries
        //no domain parameters, so the chain needs no inherited curve.
        using CardVerifiableCertificate cvca = CardVerifiableCertificateMinter.Mint(
            cvcaKey, cvcaKey, "UTCVCA00001", "UTCVCA00001", CardVerifiableCertificateMinter.CvcaRole, Effective, Expiration, BaseMemoryPool.Shared);
        using CardVerifiableCertificate documentVerifier = CardVerifiableCertificateMinter.Mint(
            cvcaKey, documentVerifierKey, "UTCVCA00001", "UTDVDE00001", CardVerifiableCertificateMinter.DocumentVerifierRole, Effective, Expiration, BaseMemoryPool.Shared);
        using CardVerifiableCertificate terminal = CardVerifiableCertificateMinter.Mint(
            documentVerifierKey, terminalKey, "UTDVDE00001", "UTISDE00001", CardVerifiableCertificateMinter.TerminalRole, Effective, Expiration, BaseMemoryPool.Shared);

        CvcChainVerificationResult result = await CardVerifiableCertificateChain.VerifyAsync(
            cvca, [documentVerifier, terminal], WithinValidity, TestContext.CancellationToken);

        Assert.AreEqual(CvcChainVerificationResult.Valid, result, "A full RSA chain whose every certificate is RSA-signed by its issuer verifies through the RSA issuer path.");
    }


    [TestMethod]
    public async Task RejectsRsaChainWithAForgedSignature()
    {
        using RSA cvcaKey = RSA.Create(2048);
        using RSA documentVerifierKey = RSA.Create(2048);

        using CardVerifiableCertificate cvca = CardVerifiableCertificateMinter.Mint(
            cvcaKey, cvcaKey, "UTCVCA00001", "UTCVCA00001", CardVerifiableCertificateMinter.CvcaRole, Effective, Expiration, BaseMemoryPool.Shared);
        //The Document Verifier's RSA signature is corrupted, so it does not verify against the RSA CVCA key.
        using CardVerifiableCertificate documentVerifier = CardVerifiableCertificateMinter.MintWithTamperedSignature(
            cvcaKey, documentVerifierKey, "UTCVCA00001", "UTDVDE00001", CardVerifiableCertificateMinter.DocumentVerifierRole, Effective, Expiration, BaseMemoryPool.Shared);

        CvcChainVerificationResult result = await CardVerifiableCertificateChain.VerifyAsync(
            cvca, [documentVerifier], WithinValidity, TestContext.CancellationToken);

        Assert.AreEqual(CvcChainVerificationResult.InvalidSignature, result, "An RSA certificate whose signature does not verify against its RSA issuer is rejected.");
    }


    [TestMethod]
    public async Task RejectsExpiredCertificate()
    {
        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentVerifierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using CardVerifiableCertificate cvca = MintCvca(cvcaKey, "UTCVCA00001");
        Tag curve = cvca.PublicKey.EllipticCurvePoint!.Tag;
        using CardVerifiableCertificate documentVerifier = MintDocumentVerifier(cvcaKey, documentVerifierKey, "UTCVCA00001", "UTDVDE00001", curve);

        CvcChainVerificationResult result = await CardVerifiableCertificateChain.VerifyAsync(
            cvca, [documentVerifier], new DateOnly(2027, 6, 1), TestContext.CancellationToken);

        Assert.AreEqual(CvcChainVerificationResult.Expired, result, "A certificate whose expiration date precedes the reference date is rejected.");
    }


    /// <summary>Mints a self-signed CVCA certificate (full domain parameters).</summary>
    private static CardVerifiableCertificate MintCvca(ECDsa cvcaKey, string reference) =>
        CardVerifiableCertificateMinter.Mint(cvcaKey, cvcaKey, reference, reference, CardVerifiableCertificateMinter.CvcaRole, includeDomainParameters: true, Effective, Expiration, inheritedCurve: null, BaseMemoryPool.Shared);

    /// <summary>Mints a Document Verifier certificate under the CVCA (inherited curve).</summary>
    private static CardVerifiableCertificate MintDocumentVerifier(ECDsa issuerKey, ECDsa documentVerifierKey, string authorityReference, string holderReference, Tag curve) =>
        CardVerifiableCertificateMinter.Mint(issuerKey, documentVerifierKey, authorityReference, holderReference, CardVerifiableCertificateMinter.DocumentVerifierRole, includeDomainParameters: false, Effective, Expiration, curve, BaseMemoryPool.Shared);

    /// <summary>Mints a terminal certificate under its issuer (inherited curve).</summary>
    private static CardVerifiableCertificate MintTerminal(ECDsa issuerKey, ECDsa terminalKey, string authorityReference, string holderReference, Tag curve) =>
        CardVerifiableCertificateMinter.Mint(issuerKey, terminalKey, authorityReference, holderReference, CardVerifiableCertificateMinter.TerminalRole, includeDomainParameters: false, Effective, Expiration, curve, BaseMemoryPool.Shared);
}
