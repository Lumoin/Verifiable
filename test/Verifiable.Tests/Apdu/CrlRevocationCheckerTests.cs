using System;
using System.Security;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the offline <see cref="CrlRevocationChecker"/> against a minted CRL scenario: a Document Signer and its
/// CSCA plus a clean, a revoking, a stale, and a forged CRL. The checker answers purely from the supplied CRLs (no
/// network), fails closed to <see cref="CertificateRevocationStatus.Unknown"/> when no authoritative CRL is available,
/// and plugs into the X.509 chain-validation seam as a revocation source.
/// </summary>
[TestClass]
internal sealed class CrlRevocationCheckerTests
{
    private static readonly DateTimeOffset ValidationTime = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task ReportsGoodForACleanCrl()
    {
        using RevocationScenario scenario = SyntheticPassportFactory.MintRevocationScenario(ValidationTime);
        var checker = new CrlRevocationChecker([scenario.CleanCrl]);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.DocumentSigner, [scenario.CscaAnchor], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Good, status, "A valid CRL that covers the issuer and does not list the signer reports Good.");
    }


    [TestMethod]
    public async Task ReportsRevokedForARevokingCrl()
    {
        using RevocationScenario scenario = SyntheticPassportFactory.MintRevocationScenario(ValidationTime);
        var checker = new CrlRevocationChecker([scenario.RevokingCrl]);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.DocumentSigner, [scenario.CscaAnchor], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Revoked, status, "A CRL listing the Document Signer's serial reports Revoked.");
    }


    [TestMethod]
    public async Task ReportsUnknownWhenNoCrlIsAvailable()
    {
        using RevocationScenario scenario = SyntheticPassportFactory.MintRevocationScenario(ValidationTime);
        var checker = new CrlRevocationChecker([]);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.DocumentSigner, [scenario.CscaAnchor], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Unknown, status, "With no CRL the status cannot be determined; the fail-closed value is Unknown.");
    }


    [TestMethod]
    public async Task ReportsUnknownForAStaleCrl()
    {
        using RevocationScenario scenario = SyntheticPassportFactory.MintRevocationScenario(ValidationTime);
        var checker = new CrlRevocationChecker([scenario.StaleCrl]);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.DocumentSigner, [scenario.CscaAnchor], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Unknown, status, "An expired CRL is not authoritative, so the status is Unknown rather than Good.");
    }


    [TestMethod]
    public async Task ReportsUnknownForACrlItCannotVerify()
    {
        using RevocationScenario scenario = SyntheticPassportFactory.MintRevocationScenario(ValidationTime);

        //The forged CRL claims the CSCA's issuer name and lists the Document Signer's serial, but is signed by a
        //different key — it must not authenticate, so it cannot mark the signer revoked and the status stays Unknown.
        var checker = new CrlRevocationChecker([scenario.ForgedRevokingCrl]);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.DocumentSigner, [scenario.CscaAnchor], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Unknown, status, "A CRL that does not verify under a trusted issuer key is not authoritative, so a forged revocation is ignored.");
    }


    [TestMethod]
    public async Task RevocationWinsWhenACleanAndARevokingCrlAreBothPresent()
    {
        using RevocationScenario scenario = SyntheticPassportFactory.MintRevocationScenario(ValidationTime);
        var checker = new CrlRevocationChecker([scenario.CleanCrl, scenario.RevokingCrl]);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.DocumentSigner, [scenario.CscaAnchor], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Revoked, status, "A revocation in any authoritative CRL is decisive, even alongside a clean one.");
    }


    [TestMethod]
    public async Task ReportsUnknownForANotYetValidCrl()
    {
        using RevocationScenario scenario = SyntheticPassportFactory.MintRevocationScenario(ValidationTime);
        var checker = new CrlRevocationChecker([scenario.NotYetValidCrl]);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.DocumentSigner, [scenario.CscaAnchor], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Unknown, status, "A CRL whose thisUpdate is in the future is not yet valid, so the status is Unknown.");
    }


    [TestMethod]
    public async Task ReportsUnknownForAnUntrustedCleanCrl()
    {
        using RevocationScenario scenario = SyntheticPassportFactory.MintRevocationScenario(ValidationTime);

        //A clean CRL signed by an untrusted key must not be accepted as authoritative; otherwise a forged clean CRL
        //could vouch for a revoked signer. This pins the fail-open direction of the signature gate.
        var checker = new CrlRevocationChecker([scenario.ForgedCleanCrl]);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.DocumentSigner, [scenario.CscaAnchor], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Unknown, status, "An unverifiable clean CRL is not authoritative, so it cannot vouch for the signer.");
    }


    [TestMethod]
    public async Task ReportsUnknownWhenTheAuthorisingCandidateLacksCrlSign()
    {
        using RevocationScenario scenario = SyntheticPassportFactory.MintRevocationScenario(ValidationTime);

        //The revoking CRL verifies under the candidate's key (it shares the CSCA's key), but the candidate's Key Usage
        //lacks cRLSign (RFC 5280 §6.3.3(f)), so it is not authorised to attest revocation and the CRL is not honoured.
        var checker = new CrlRevocationChecker([scenario.RevokingCrl]);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.DocumentSigner, [scenario.NonCrlSignerAnchor], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Unknown, status, "A candidate not authorised to sign CRLs cannot make a CRL authoritative, even when its key verifies the signature.");
    }


    [TestMethod]
    public async Task ReportsUnknownForACrlWithoutNextUpdateByDefault()
    {
        using RevocationScenario scenario = SyntheticPassportFactory.MintRevocationScenario(ValidationTime);

        //A CRL with no nextUpdate has no freshness bound; the secure default treats it as non-authoritative.
        var checker = new CrlRevocationChecker([scenario.NoNextUpdateCrl]);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.DocumentSigner, [scenario.CscaAnchor], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Unknown, status, "By default a CRL without nextUpdate is non-authoritative, so the status is Unknown.");
    }


    [TestMethod]
    public async Task AcceptsACrlWithoutNextUpdateWhenTheFlagAllowsIt()
    {
        using RevocationScenario scenario = SyntheticPassportFactory.MintRevocationScenario(ValidationTime);

        //Opting in, a no-nextUpdate CRL is treated as authoritative, so the clean no-nextUpdate CRL reports Good.
        var checker = new CrlRevocationChecker([scenario.NoNextUpdateCrl], allowCrlsWithoutNextUpdate: true);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.DocumentSigner, [scenario.CscaAnchor], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Good, status, "With the opt-in flag a no-nextUpdate CRL is authoritative and its clean listing reports Good.");
    }


    [TestMethod]
    public async Task SkipsAMalformedCrlAndStillConsultsAValidOne()
    {
        using RevocationScenario scenario = SyntheticPassportFactory.MintRevocationScenario(ValidationTime);

        //A malformed CRL in the set must be skipped, not abort the scan; the valid revoking CRL behind it still applies.
        var checker = new CrlRevocationChecker([scenario.MalformedCrl, scenario.RevokingCrl]);

        CertificateRevocationStatus status = await checker.CheckAsync(
            scenario.DocumentSigner, [scenario.CscaAnchor], ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Revoked, status, "A malformed CRL is skipped, so a valid revoking CRL later in the set is still honoured.");
    }


    [TestMethod]
    public async Task ChainValidationRejectsALeafRevokedByTheCrlChecker()
    {
        using RevocationScenario scenario = SyntheticPassportFactory.MintRevocationScenario(ValidationTime);
        var checker = new CrlRevocationChecker([scenario.RevokingCrl]);
        PkiCertificateMemory[] chain = [scenario.DocumentSigner];
        PkiCertificateMemory[] anchors = [scenario.CscaAnchor];

        //The CRL checker plugs into the chain-validation seam as the revocation source, so a revoked leaf is rejected.
        bool threw = false;
        try
        {
            using PublicKeyMemory leafKey = await MicrosoftX509Functions.ValidateChainAsync(
                chain, anchors, ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken, checker.CheckAsync).ConfigureAwait(false);
        }
        catch(SecurityException)
        {
            threw = true;
        }

        Assert.IsTrue(threw, "A Document Signer revoked by the supplied CRL must be rejected by chain validation.");
    }


    [TestMethod]
    public async Task ChainValidationAcceptsALeafClearedByTheCrlChecker()
    {
        using RevocationScenario scenario = SyntheticPassportFactory.MintRevocationScenario(ValidationTime);
        var checker = new CrlRevocationChecker([scenario.CleanCrl]);
        PkiCertificateMemory[] chain = [scenario.DocumentSigner];
        PkiCertificateMemory[] anchors = [scenario.CscaAnchor];

        using PublicKeyMemory leafKey = await MicrosoftX509Functions.ValidateChainAsync(
            chain, anchors, ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken, checker.CheckAsync).ConfigureAwait(false);

        Assert.IsNotNull(leafKey, "A clean CRL lets chain validation complete and return the leaf key.");
    }
}
