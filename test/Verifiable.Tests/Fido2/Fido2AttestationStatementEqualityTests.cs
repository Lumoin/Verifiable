using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for the content equality added to <see cref="PackedAttestationStatement"/>,
/// <see cref="AndroidKeyAttestationStatement"/>, and <see cref="FidoU2fAttestationStatement"/>: two
/// independently built instances carrying byte-identical <c>Signature</c> and element-wise-identical
/// <c>X5c</c> content must compare equal and report the same hash code — content equality, not the
/// reference equality the compiler-synthesized record comparison would give the
/// <see cref="ReadOnlyMemory{T}"/> and <see cref="IReadOnlyList{T}"/> members.
/// </summary>
[TestClass]
internal sealed class Fido2AttestationStatementEqualityTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    // ---------------------------------------------------------------------------------------
    // PackedAttestationStatement
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Two <see cref="PackedAttestationStatement"/> instances built from independently-minted
    /// <see cref="PkiCertificateMemory"/> instances over the same certificate bytes, and independently
    /// cloned signature bytes, compare equal and report the same hash code.
    /// </summary>
    [TestMethod]
    public void EqualPackedStatementsFromIndependentInstancesAreEqual()
    {
        //X.509 CA-signing key for CreateSelfSignedCa's CertificateRequest mint — the cert-factory carve-out; not TestKeyMaterialProvider fixture material.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Root", rootKey);
        byte[] signature = [0x01, 0x02, 0x03, 0x04];

        using PkiCertificateMemory rootPkiA = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory rootPkiB = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        Assert.AreNotSame(rootPkiA, rootPkiB);

        var statementA = new PackedAttestationStatement(-7, (byte[])signature.Clone(), [rootPkiA]);
        var statementB = new PackedAttestationStatement(-7, (byte[])signature.Clone(), [rootPkiB]);

        Assert.AreEqual(statementA, statementB);
        Assert.AreEqual(statementA.GetHashCode(), statementB.GetHashCode());
    }


    /// <summary>
    /// Two <see cref="PackedAttestationStatement"/> instances that both carry a <see langword="null"/>
    /// <c>X5c</c> (self attestation) compare equal.
    /// </summary>
    [TestMethod]
    public void EqualPackedStatementsWithNullX5cAreEqual()
    {
        byte[] signature = [0x0A, 0x0B];

        var statementA = new PackedAttestationStatement(-7, (byte[])signature.Clone(), X5c: null);
        var statementB = new PackedAttestationStatement(-7, (byte[])signature.Clone(), X5c: null);

        Assert.AreEqual(statementA, statementB);
        Assert.AreEqual(statementA.GetHashCode(), statementB.GetHashCode());
    }


    /// <summary>A <see langword="null"/> <c>X5c</c> (self attestation) never equals an empty <c>X5c</c> list.</summary>
    [TestMethod]
    public void PackedStatementWithNullX5cIsNotEqualToEmptyX5c()
    {
        byte[] signature = [0x0A, 0x0B];

        var statementWithNullX5c = new PackedAttestationStatement(-7, (byte[])signature.Clone(), X5c: null);
        var statementWithEmptyX5c = new PackedAttestationStatement(-7, (byte[])signature.Clone(), X5c: []);

        Assert.AreNotEqual(statementWithNullX5c, statementWithEmptyX5c);
    }


    /// <summary>A differing <see cref="PackedAttestationStatement.Alg"/> breaks equality.</summary>
    [TestMethod]
    public void DifferingAlgBreaksPackedStatementEquality()
    {
        byte[] signature = [0x01, 0x02];

        var statementA = new PackedAttestationStatement(-7, (byte[])signature.Clone(), X5c: null);
        var statementB = new PackedAttestationStatement(-257, (byte[])signature.Clone(), X5c: null);

        Assert.AreNotEqual(statementA, statementB);
    }


    /// <summary>A differing <see cref="PackedAttestationStatement.Signature"/> breaks equality.</summary>
    [TestMethod]
    public void DifferingSignatureBreaksPackedStatementEquality()
    {
        var statementA = new PackedAttestationStatement(-7, new byte[] { 0x01, 0x02 }, X5c: null);
        var statementB = new PackedAttestationStatement(-7, new byte[] { 0x01, 0x03 }, X5c: null);

        Assert.AreNotEqual(statementA, statementB);
    }


    /// <summary>A differing <see cref="PackedAttestationStatement.X5c"/> certificate breaks equality.</summary>
    [TestMethod]
    public void DifferingX5cCertificateBreaksPackedStatementEquality()
    {
        //X.509 CA-signing keys for CreateSelfSignedCa's CertificateRequest mints (two independent CAs) — the cert-factory carve-out; not TestKeyMaterialProvider fixture material.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa otherRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Root", rootKey);
        using X509Certificate2 otherRootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Other Root", otherRootKey);
        byte[] signature = [0x01, 0x02];

        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory otherRootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(otherRootCert.RawData);

        var statementA = new PackedAttestationStatement(-7, (byte[])signature.Clone(), [rootPki]);
        var statementB = new PackedAttestationStatement(-7, (byte[])signature.Clone(), [otherRootPki]);

        Assert.AreNotEqual(statementA, statementB);
    }


    // ---------------------------------------------------------------------------------------
    // AndroidKeyAttestationStatement
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Two <see cref="AndroidKeyAttestationStatement"/> instances built from independently-minted
    /// <see cref="PkiCertificateMemory"/> instances over the same certificate bytes, and independently
    /// cloned signature bytes, compare equal and report the same hash code.
    /// </summary>
    [TestMethod]
    public void EqualAndroidKeyStatementsFromIndependentInstancesAreEqual()
    {
        //X.509 CA-signing key for CreateSelfSignedCa's CertificateRequest mint — the cert-factory carve-out; not TestKeyMaterialProvider fixture material.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Root", rootKey);
        byte[] signature = [0x05, 0x06, 0x07];

        using PkiCertificateMemory rootPkiA = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory rootPkiB = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statementA = new AndroidKeyAttestationStatement(-7, (byte[])signature.Clone(), [rootPkiA]);
        var statementB = new AndroidKeyAttestationStatement(-7, (byte[])signature.Clone(), [rootPkiB]);

        Assert.AreEqual(statementA, statementB);
        Assert.AreEqual(statementA.GetHashCode(), statementB.GetHashCode());
    }


    /// <summary>A differing <see cref="AndroidKeyAttestationStatement.Alg"/> breaks equality.</summary>
    [TestMethod]
    public void DifferingAlgBreaksAndroidKeyStatementEquality()
    {
        //X.509 CA-signing key for CreateSelfSignedCa's CertificateRequest mint — the cert-factory carve-out; not TestKeyMaterialProvider fixture material.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Root", rootKey);
        byte[] signature = [0x05, 0x06];

        using PkiCertificateMemory rootPkiA = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory rootPkiB = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statementA = new AndroidKeyAttestationStatement(-7, (byte[])signature.Clone(), [rootPkiA]);
        var statementB = new AndroidKeyAttestationStatement(-257, (byte[])signature.Clone(), [rootPkiB]);

        Assert.AreNotEqual(statementA, statementB);
    }


    /// <summary>A differing <see cref="AndroidKeyAttestationStatement.Signature"/> breaks equality.</summary>
    [TestMethod]
    public void DifferingSignatureBreaksAndroidKeyStatementEquality()
    {
        //X.509 CA-signing key for CreateSelfSignedCa's CertificateRequest mint — the cert-factory carve-out; not TestKeyMaterialProvider fixture material.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Root", rootKey);

        using PkiCertificateMemory rootPkiA = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory rootPkiB = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statementA = new AndroidKeyAttestationStatement(-7, new byte[] { 0x05, 0x06 }, [rootPkiA]);
        var statementB = new AndroidKeyAttestationStatement(-7, new byte[] { 0x05, 0x07 }, [rootPkiB]);

        Assert.AreNotEqual(statementA, statementB);
    }


    /// <summary>A differing <see cref="AndroidKeyAttestationStatement.X5c"/> certificate breaks equality.</summary>
    [TestMethod]
    public void DifferingX5cCertificateBreaksAndroidKeyStatementEquality()
    {
        //X.509 CA-signing keys for CreateSelfSignedCa's CertificateRequest mints (two independent CAs) — the cert-factory carve-out; not TestKeyMaterialProvider fixture material.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa otherRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Root", rootKey);
        using X509Certificate2 otherRootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Other Root", otherRootKey);
        byte[] signature = [0x05, 0x06];

        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory otherRootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(otherRootCert.RawData);

        var statementA = new AndroidKeyAttestationStatement(-7, (byte[])signature.Clone(), [rootPki]);
        var statementB = new AndroidKeyAttestationStatement(-7, (byte[])signature.Clone(), [otherRootPki]);

        Assert.AreNotEqual(statementA, statementB);
    }


    // ---------------------------------------------------------------------------------------
    // FidoU2fAttestationStatement
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Two <see cref="FidoU2fAttestationStatement"/> instances built from independently-minted
    /// <see cref="PkiCertificateMemory"/> instances over the same certificate bytes, and independently
    /// cloned signature bytes, compare equal and report the same hash code.
    /// </summary>
    [TestMethod]
    public void EqualFidoU2fStatementsFromIndependentInstancesAreEqual()
    {
        //X.509 CA-signing key for CreateSelfSignedCa's CertificateRequest mint — the cert-factory carve-out; not TestKeyMaterialProvider fixture material.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Root", rootKey);
        byte[] signature = [0x08, 0x09];

        using PkiCertificateMemory rootPkiA = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory rootPkiB = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statementA = new FidoU2fAttestationStatement((byte[])signature.Clone(), [rootPkiA]);
        var statementB = new FidoU2fAttestationStatement((byte[])signature.Clone(), [rootPkiB]);

        Assert.AreEqual(statementA, statementB);
        Assert.AreEqual(statementA.GetHashCode(), statementB.GetHashCode());
    }


    /// <summary>A differing <see cref="FidoU2fAttestationStatement.Signature"/> breaks equality.</summary>
    [TestMethod]
    public void DifferingSignatureBreaksFidoU2fStatementEquality()
    {
        //X.509 CA-signing key for CreateSelfSignedCa's CertificateRequest mint — the cert-factory carve-out; not TestKeyMaterialProvider fixture material.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Root", rootKey);

        using PkiCertificateMemory rootPkiA = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory rootPkiB = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statementA = new FidoU2fAttestationStatement(new byte[] { 0x08, 0x09 }, [rootPkiA]);
        var statementB = new FidoU2fAttestationStatement(new byte[] { 0x08, 0x0A }, [rootPkiB]);

        Assert.AreNotEqual(statementA, statementB);
    }


    /// <summary>A differing <see cref="FidoU2fAttestationStatement.X5c"/> certificate breaks equality.</summary>
    [TestMethod]
    public void DifferingX5cCertificateBreaksFidoU2fStatementEquality()
    {
        //X.509 CA-signing keys for CreateSelfSignedCa's CertificateRequest mints (two independent CAs) — the cert-factory carve-out; not TestKeyMaterialProvider fixture material.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa otherRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Root", rootKey);
        using X509Certificate2 otherRootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Equality Other Root", otherRootKey);
        byte[] signature = [0x08, 0x09];

        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory otherRootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(otherRootCert.RawData);

        var statementA = new FidoU2fAttestationStatement((byte[])signature.Clone(), [rootPki]);
        var statementB = new FidoU2fAttestationStatement((byte[])signature.Clone(), [otherRootPki]);

        Assert.AreNotEqual(statementA, statementB);
    }
}
