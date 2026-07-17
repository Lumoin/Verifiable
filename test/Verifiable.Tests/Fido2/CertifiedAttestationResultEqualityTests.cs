using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CertifiedAttestationResult"/>'s overridden record equality: two results
/// carrying the same attestation type and byte-identical trust paths, but built from independently
/// minted <see cref="PkiCertificateMemory"/> instances over the same certificate bytes, must compare
/// equal and report the same hash code — content equality, not the reference equality the
/// compiler-synthesized record comparison of an <see cref="IReadOnlyList{T}"/> member would give two
/// independently constructed lists.
/// </summary>
/// <remarks>
/// Every fixture's <see cref="ECDsa"/> key exists only to satisfy <see cref="Fido2AttestationTestVectors"/>'s
/// <see cref="CertificateRequest"/>-based certificate factories (<c>CreateSelfSignedCa</c>,
/// <c>CreateLeafAttestationCertificate</c>) — the test-side X.509 certificate factory carve-out. No
/// cryptographic operation is exercised or verified here; only the record equality of the resulting
/// certificate bytes, wrapped as independently minted <see cref="PkiCertificateMemory"/> instances.
/// </remarks>
[TestClass]
internal sealed class CertifiedAttestationResultEqualityTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Two <see cref="CertifiedAttestationResult"/> instances whose trust paths were independently
    /// minted from the same certificate bytes — never the same <see cref="PkiCertificateMemory"/>
    /// instances — compare equal and report the same hash code.
    /// </summary>
    [TestMethod]
    public void EqualTrustPathsFromIndependentlyMintedCertificatesAreEqual()
    {
        //Cert-factory carve-out: this key only feeds CreateSelfSignedCa's CertificateRequest signing;
        //the assertions below exercise PkiCertificateMemory equality, no operation over the key itself.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Root", rootKey);

        using PkiCertificateMemory rootPkiA = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory rootPkiB = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        Assert.AreNotSame(rootPkiA, rootPkiB);

        var resultA = new CertifiedAttestationResult(AttestationType.Basic, [rootPkiA]);
        var resultB = new CertifiedAttestationResult(AttestationType.Basic, [rootPkiB]);

        Assert.AreEqual(resultA, resultB);
        Assert.AreEqual(resultA.GetHashCode(), resultB.GetHashCode());
    }


    /// <summary>
    /// Two independently minted, byte-identical two-certificate (leaf, root) trust paths compare
    /// equal element-wise and in order.
    /// </summary>
    [TestMethod]
    public void EqualMultiCertificateTrustPathsAreEqual()
    {
        //Cert-factory carve-out: these keys only feed CreateSelfSignedCa/CreateLeafAttestationCertificate's
        //CertificateRequest signing; the assertions below exercise PkiCertificateMemory equality only.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        using PkiCertificateMemory leafPkiA = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPkiA = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory leafPkiB = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPkiB = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var resultA = new CertifiedAttestationResult(AttestationType.Unknown, [leafPkiA, rootPkiA]);
        var resultB = new CertifiedAttestationResult(AttestationType.Unknown, [leafPkiB, rootPkiB]);

        Assert.AreEqual(resultA, resultB);
        Assert.AreEqual(resultA.GetHashCode(), resultB.GetHashCode());
    }


    /// <summary>A differing <see cref="AttestationType"/> breaks equality even when the trust path is identical.</summary>
    [TestMethod]
    public void DifferingAttestationTypeBreaksEquality()
    {
        //Cert-factory carve-out: this key only feeds CreateSelfSignedCa's CertificateRequest signing;
        //the assertion below exercises CertifiedAttestationResult equality, not this key.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Root", rootKey);
        using PkiCertificateMemory rootPkiA = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory rootPkiB = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var basicResult = new CertifiedAttestationResult(AttestationType.Basic, [rootPkiA]);
        var attestationCaResult = new CertifiedAttestationResult(AttestationType.AttestationCa, [rootPkiB]);

        Assert.AreNotEqual(basicResult, attestationCaResult);
    }


    /// <summary>A trust path with a different certificate breaks equality even when the type matches.</summary>
    [TestMethod]
    public void DifferingTrustPathCertificateBreaksEquality()
    {
        //Cert-factory carve-out: these keys only feed CreateSelfSignedCa's CertificateRequest signing
        //for two independent roots; the assertion below exercises trust-path equality, not the keys.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa otherRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Root", rootKey);
        using X509Certificate2 otherRootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Other Root", otherRootKey);

        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory otherRootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(otherRootCert.RawData);

        var resultA = new CertifiedAttestationResult(AttestationType.Basic, [rootPki]);
        var resultB = new CertifiedAttestationResult(AttestationType.Basic, [otherRootPki]);

        Assert.AreNotEqual(resultA, resultB);
    }


    /// <summary>A trust path differing only in certificate order breaks equality — order is significant.</summary>
    [TestMethod]
    public void DifferingTrustPathOrderBreaksEquality()
    {
        //Cert-factory carve-out: these keys only feed CreateSelfSignedCa/CreateLeafAttestationCertificate's
        //CertificateRequest signing; the assertion below exercises trust-path order, not the keys.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var leafFirst = new CertifiedAttestationResult(AttestationType.Unknown, [leafPki, rootPki]);
        var rootFirst = new CertifiedAttestationResult(AttestationType.Unknown, [rootPki, leafPki]);

        Assert.AreNotEqual(leafFirst, rootFirst);
    }
}
