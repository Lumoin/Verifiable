using Microsoft.Extensions.Time.Testing;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Verifiable.Apdu;
using Verifiable.Apdu.Automata;
using Verifiable.Apdu.Bac;
using Verifiable.Apdu.Eac;
using Verifiable.Apdu.Lds;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Drives the real Terminal Authentication certificate-chain presentation
/// (<see cref="TerminalAuthentication.PresentCertificateChainAsync"/>) against the stateful
/// <see cref="CardSimulator"/> over an established Basic Access Control session. The chip holds the trusted
/// Country Verifying Certification Authority certificate as personalisation and, on each MSE:Set DST and
/// PSO:Verify Certificate, verifies the presented certificate against the key it already trusts and imports
/// it. The chain is minted with the framework's own ECDSA (an independent signer); both sides are production
/// code that agree only on the wire bytes.
/// </summary>
[TestClass]
internal sealed class CardSimulatorTerminalAuthenticationTests
{
    private const string Td2MachineReadableZone =
        "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
        "L898902C<3UTO6908061F9406236<<<<<<<8";

    private const string DocumentNumber = "L898902C<";
    private const string DateOfBirth = "690806";
    private const string DateOfExpiry = "940623";

    private const string CvcaReference = "UTCVCA00001";
    private const string DocumentVerifierReference = "UTDVDE00001";
    private const string TerminalReference = "UTISDE00001";

    /// <summary>The effective date every minted certificate carries unless a row names its own.</summary>
    private static DateOnly Effective { get; } = new(2024, 1, 1);
    /// <summary>The expiration date every minted certificate carries unless a row names its own.</summary>
    private static DateOnly Expiration { get; } = new(2026, 1, 1);


    /// <summary>The test framework's context, supplying cancellation for the minting and the verification.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The chip accepts a correctly signed, linked, role-narrowing Document Verifier and terminal chain presented under the Country Verifying Certification Authority it trusts.</summary>
    /// <returns>A task completing once the chip's answer is judged.</returns>
    [TestMethod]
    public async Task VerifiesAPresentedDocumentVerifierAndTerminalChain()
    {
        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentVerifierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var trustAnchor = await MintCvcaAsync(cvcaKey, CvcaReference, TestContext.CancellationToken).ConfigureAwait(false);
        Tag curve = trustAnchor.PublicKey.EllipticCurvePoint!.Tag;
        using var documentVerifier = await MintDocumentVerifierAsync(cvcaKey, documentVerifierKey, CvcaReference, curve, TestContext.CancellationToken).ConfigureAwait(false);
        using var terminal = await MintTerminalAsync(documentVerifierKey, terminalKey, DocumentVerifierReference, curve, TestContext.CancellationToken).ConfigureAwait(false);

        bool accepted = await PresentChainOverBacAsync(trustAnchor, [documentVerifier, terminal]);

        Assert.IsTrue(accepted, "The chip must accept a correctly signed, linked, role-narrowing chain presented under the trusted CVCA.");
    }


    /// <summary>The chip rejects a chain whose terminal certificate's signature does not verify under the Document Verifier's key.</summary>
    /// <returns>A task completing once the chip's answer is judged.</returns>
    [TestMethod]
    public async Task RejectsAPresentedChainWithATamperedTerminalCertificate()
    {
        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentVerifierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var trustAnchor = await MintCvcaAsync(cvcaKey, CvcaReference, TestContext.CancellationToken).ConfigureAwait(false);
        Tag curve = trustAnchor.PublicKey.EllipticCurvePoint!.Tag;
        using var documentVerifier = await MintDocumentVerifierAsync(cvcaKey, documentVerifierKey, CvcaReference, curve, TestContext.CancellationToken).ConfigureAwait(false);
        //The terminal certificate's signature is corrupted, so it does not verify against the Document Verifier key.
        using var terminal = await CardVerifiableCertificateMinter.MintWithTamperedSignatureAsync(
            documentVerifierKey, terminalKey, DocumentVerifierReference, TerminalReference, CardVerifiableCertificateMinter.TerminalRole, includeDomainParameters: false, Effective, Expiration, curve, BaseMemoryPool.Shared, TerminalType.AuthenticationTerminal, TestContext.CancellationToken).ConfigureAwait(false);

        bool accepted = await PresentChainOverBacAsync(trustAnchor, [documentVerifier, terminal]);

        Assert.IsFalse(accepted, "The chip must reject a chain whose terminal certificate signature does not verify.");
    }


    /// <summary>The chip rejects MSE:Set DST naming a certification authority it does not hold: the presented chain chains to another CVCA than the one it trusts.</summary>
    /// <returns>A task completing once the chip's answer is judged.</returns>
    [TestMethod]
    public async Task RejectsAChainNotRootedInTheChipsTrustAnchor()
    {
        using ECDsa presentedCvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa chipCvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentVerifierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //The chip trusts a different CVCA than the one the presented chain chains to.
        using var trustAnchor = await MintCvcaAsync(chipCvcaKey, "UTCVCA88888", TestContext.CancellationToken).ConfigureAwait(false);
        Tag curve = trustAnchor.PublicKey.EllipticCurvePoint!.Tag;
        using var documentVerifier = await MintDocumentVerifierAsync(presentedCvcaKey, documentVerifierKey, CvcaReference, curve, TestContext.CancellationToken).ConfigureAwait(false);

        bool accepted = await PresentChainOverBacAsync(trustAnchor, [documentVerifier]);

        Assert.IsFalse(accepted, "The chip must reject MSE:Set DST naming a certification authority it does not hold.");
    }


    /// <summary>The chip rejects a terminal certificate the CVCA issued directly, though linked and validly signed: a CVCA issues Document Verifiers alone.</summary>
    /// <returns>A task completing once the chip's answer is judged.</returns>
    [TestMethod]
    public async Task RejectsACvcaIssuingATerminalDirectly()
    {
        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var trustAnchor = await MintCvcaAsync(cvcaKey, CvcaReference, TestContext.CancellationToken).ConfigureAwait(false);
        Tag curve = trustAnchor.PublicKey.EllipticCurvePoint!.Tag;
        //Linked to and validly signed by the CVCA, but a terminal role: a CVCA may issue only Document Verifiers.
        using var terminal = await CardVerifiableCertificateMinter.MintAsync(
            cvcaKey, terminalKey, CvcaReference, TerminalReference, CardVerifiableCertificateMinter.TerminalRole, includeDomainParameters: false, Effective, Expiration, curve, BaseMemoryPool.Shared, TerminalType.AuthenticationTerminal, TestContext.CancellationToken).ConfigureAwait(false);

        bool accepted = await PresentChainOverBacAsync(trustAnchor, [terminal]);

        Assert.IsFalse(accepted, "The chip must reject a terminal certificate issued directly by the CVCA.");
    }


    /// <summary>The chip accepts a chain whose certificates were issued in sequence, each after its parent: under the default date it advances from the trust anchor's effective date rather than rejecting later certificates as not yet valid.</summary>
    /// <returns>A task completing once the chip's answer is judged.</returns>
    [TestMethod]
    public async Task VerifiesAChainWithStaggeredValidityDatesUnderTheDefaultDate()
    {
        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentVerifierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //A realistic chain: each certificate is issued after its parent, so the children's effective dates are
        //later than the trust anchor's. The chip starts from the trust anchor's effective date and advances.
        DateOnly expiration = new(2030, 1, 1);
        using var trustAnchor = await CardVerifiableCertificateMinter.MintAsync(
            cvcaKey, cvcaKey, CvcaReference, CvcaReference, CardVerifiableCertificateMinter.CvcaRole, includeDomainParameters: true, new DateOnly(2023, 1, 1), expiration, inheritedCurve: null, BaseMemoryPool.Shared, TerminalType.AuthenticationTerminal, TestContext.CancellationToken).ConfigureAwait(false);
        Tag curve = trustAnchor.PublicKey.EllipticCurvePoint!.Tag;
        using var documentVerifier = await CardVerifiableCertificateMinter.MintAsync(
            cvcaKey, documentVerifierKey, CvcaReference, DocumentVerifierReference, CardVerifiableCertificateMinter.DocumentVerifierRole, includeDomainParameters: false, new DateOnly(2024, 6, 1), expiration, curve, BaseMemoryPool.Shared, TerminalType.AuthenticationTerminal, TestContext.CancellationToken).ConfigureAwait(false);
        using var terminal = await CardVerifiableCertificateMinter.MintAsync(
            documentVerifierKey, terminalKey, DocumentVerifierReference, TerminalReference, CardVerifiableCertificateMinter.TerminalRole, includeDomainParameters: false, new DateOnly(2025, 6, 1), expiration, curve, BaseMemoryPool.Shared, TerminalType.AuthenticationTerminal, TestContext.CancellationToken).ConfigureAwait(false);

        bool accepted = await PresentChainOverBacAsync(trustAnchor, [documentVerifier, terminal], cardDate: null);

        Assert.IsTrue(accepted, "A chain whose certificates are issued in sequence must be accepted; the chip advances its date rather than rejecting later certificates as not yet valid.");
    }


    /// <summary>The chip rejects a terminal certificate that expired before the date verifying the Document Verifier advanced it to.</summary>
    /// <returns>A task completing once the chip's answer is judged.</returns>
    [TestMethod]
    public async Task RejectsACertificateExpiredRelativeToTheAdvancingDate()
    {
        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentVerifierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //Verifying the Document Verifier advances the chip's date to 2026; the terminal certificate expired in
        //2024, before that date, so the chip rejects it as expired.
        using var trustAnchor = await CardVerifiableCertificateMinter.MintAsync(
            cvcaKey, cvcaKey, CvcaReference, CvcaReference, CardVerifiableCertificateMinter.CvcaRole, includeDomainParameters: true, new DateOnly(2023, 1, 1), new DateOnly(2030, 1, 1), inheritedCurve: null, BaseMemoryPool.Shared, TerminalType.AuthenticationTerminal, TestContext.CancellationToken).ConfigureAwait(false);
        Tag curve = trustAnchor.PublicKey.EllipticCurvePoint!.Tag;
        using var documentVerifier = await CardVerifiableCertificateMinter.MintAsync(
            cvcaKey, documentVerifierKey, CvcaReference, DocumentVerifierReference, CardVerifiableCertificateMinter.DocumentVerifierRole, includeDomainParameters: false, new DateOnly(2026, 1, 1), new DateOnly(2030, 1, 1), curve, BaseMemoryPool.Shared, TerminalType.AuthenticationTerminal, TestContext.CancellationToken).ConfigureAwait(false);
        using var terminal = await CardVerifiableCertificateMinter.MintAsync(
            documentVerifierKey, terminalKey, DocumentVerifierReference, TerminalReference, CardVerifiableCertificateMinter.TerminalRole, includeDomainParameters: false, new DateOnly(2024, 1, 1), new DateOnly(2024, 6, 1), curve, BaseMemoryPool.Shared, TerminalType.AuthenticationTerminal, TestContext.CancellationToken).ConfigureAwait(false);

        bool accepted = await PresentChainOverBacAsync(trustAnchor, [documentVerifier, terminal], cardDate: null);

        Assert.IsFalse(accepted, "A terminal certificate expired relative to the chip's advancing current date must be rejected.");
    }


    /// <summary>
    /// Personalises a chip holding the trust anchor, establishes Basic Access Control against it, and presents
    /// the chain over the session, returning whether the chip accepted it. A <see langword="null"/> card date
    /// exercises the default (the trust anchor's effective date, advancing as certificates are verified).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The Basic Access Control session and its access keys are disposed in the using blocks.")]
    private async Task<bool> PresentChainOverBacAsync(CardVerifiableCertificate trustAnchor, CardVerifiableCertificate[] chain, DateOnly? cardDate = null)
    {
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x6E], BaseMemoryPool.Shared);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);

        using var card = new CardSimulator(
            "passport-terminal-auth", [efCom, dataGroup1], terminalAuthenticationTrustAnchor: trustAnchor, terminalAuthenticationDate: cardDate, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        (SecureMessagingSession bacSession, SymmetricKeyMemory accessEncryptionKey, SymmetricKeyMemory accessMacKey) =
            await EstablishBacAsync(device);
        using(accessEncryptionKey)
        using(accessMacKey)
        using(bacSession)
        {
            return await TerminalAuthentication.PresentCertificateChainAsync(
                device, bacSession, chain, BaseMemoryPool.Shared, TestContext.CancellationToken);
        }
    }


    /// <summary>
    /// Runs the real terminal Basic Access Control against the card and returns the established session plus
    /// the borrowed access keys (the caller disposes all three).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the session and the access keys transfers to the caller, which disposes all three.")]
    private async Task<(SecureMessagingSession Session, SymmetricKeyMemory EncryptionKey, SymmetricKeyMemory MacKey)> EstablishBacAsync(ApduDevice device)
    {
        string mrzInformation = BasicAccessControl.BuildMrzInformation(DocumentNumber, DateOfBirth, DateOfExpiry);
        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await BasicAccessControl.DeriveAccessKeysAsync(
            mrzInformation, BaseMemoryPool.Shared, TestContext.CancellationToken);

        byte[] terminalNonce = Convert.FromHexString("1122334455667788");
        byte[] terminalKeyingMaterial = Convert.FromHexString("112233445566778899AABBCCDDEEFF00");

        SecureMessagingSession session = await BasicAccessControl.EstablishSessionAsync(
            device, encryptionKey, macKey, terminalNonce, terminalKeyingMaterial, BaseMemoryPool.Shared, TestContext.CancellationToken);

        return (session, encryptionKey, macKey);
    }


    /// <summary>Mints the self-signed Country Verifying Certification Authority certificate (full domain parameters).</summary>
    /// <param name="cvcaKey">The CVCA's key, which signs its own certificate.</param>
    /// <param name="reference">The CVCA's reference, both its holder and its authority reference.</param>
    /// <param name="cancellationToken">Cancels the signing.</param>
    /// <returns>The certificate.</returns>
    private static ValueTask<CardVerifiableCertificate> MintCvcaAsync(ECDsa cvcaKey, string reference, CancellationToken cancellationToken) =>
        CardVerifiableCertificateMinter.MintAsync(cvcaKey, cvcaKey, reference, reference, CardVerifiableCertificateMinter.CvcaRole, includeDomainParameters: true, Effective, Expiration, inheritedCurve: null, BaseMemoryPool.Shared, TerminalType.AuthenticationTerminal, cancellationToken);


    /// <summary>Mints a Document Verifier certificate under its issuer (inherited curve).</summary>
    /// <param name="issuerKey">The issuer's key, which signs the certificate.</param>
    /// <param name="documentVerifierKey">The Document Verifier's key, which the certificate carries.</param>
    /// <param name="authorityReference">The issuer's reference.</param>
    /// <param name="curve">The curve the certificate inherits from its issuer.</param>
    /// <param name="cancellationToken">Cancels the signing.</param>
    /// <returns>The certificate.</returns>
    private static ValueTask<CardVerifiableCertificate> MintDocumentVerifierAsync(ECDsa issuerKey, ECDsa documentVerifierKey, string authorityReference, Tag curve, CancellationToken cancellationToken) =>
        CardVerifiableCertificateMinter.MintAsync(issuerKey, documentVerifierKey, authorityReference, DocumentVerifierReference, CardVerifiableCertificateMinter.DocumentVerifierRole, includeDomainParameters: false, Effective, Expiration, curve, BaseMemoryPool.Shared, TerminalType.AuthenticationTerminal, cancellationToken);


    /// <summary>Mints a terminal certificate under its issuer (inherited curve).</summary>
    /// <param name="issuerKey">The issuer's key, which signs the certificate.</param>
    /// <param name="terminalKey">The terminal's key, which the certificate carries.</param>
    /// <param name="authorityReference">The issuer's reference.</param>
    /// <param name="curve">The curve the certificate inherits from its issuer.</param>
    /// <param name="cancellationToken">Cancels the signing.</param>
    /// <returns>The certificate.</returns>
    private static ValueTask<CardVerifiableCertificate> MintTerminalAsync(ECDsa issuerKey, ECDsa terminalKey, string authorityReference, Tag curve, CancellationToken cancellationToken) =>
        CardVerifiableCertificateMinter.MintAsync(issuerKey, terminalKey, authorityReference, TerminalReference, CardVerifiableCertificateMinter.TerminalRole, includeDomainParameters: false, Effective, Expiration, curve, BaseMemoryPool.Shared, TerminalType.AuthenticationTerminal, cancellationToken);
}
