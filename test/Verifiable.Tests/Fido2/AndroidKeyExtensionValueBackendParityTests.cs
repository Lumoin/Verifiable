using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Additive backend-parity tests for <see cref="ReadCertificateExtensionValueDelegate"/>: proves
/// <see cref="BouncyCastleX509Functions.ReadCertificateExtensionValue"/> — the implementation this
/// package adds to close the gap <c>scout-seams.md</c> found (only the Microsoft backend implemented
/// the delegate before this wave) — agrees byte-for-byte with
/// <see cref="MicrosoftX509Functions.ReadCertificateExtensionValue"/> on the same minted certificate,
/// for both the android key attestation certificate extension and its absence/criticality axes.
/// </summary>
/// <remarks>
/// Every fixture certificate is minted with a raw <see cref="ECDsa"/> key handed to this suite's
/// shared X.509 certificate-minting helpers (<see cref="Fido2AttestationTestVectors.CreateSelfSignedCa"/>,
/// <see cref="AndroidKeyAttestationTestVectors.CreateEcCredCert"/>,
/// <see cref="Fido2AttestationTestVectors.CreateLeafAttestationCertificate"/>), which require a native
/// <see cref="ECDsa"/> key object rather than this package's own key-material types. The key itself is
/// never compared or interop-tested here — only the resulting certificate's extension bytes are.
/// </remarks>
[TestClass]
internal sealed class AndroidKeyExtensionValueBackendParityTests
{
    /// <summary>
    /// Both backends read the same android key attestation certificate extension value and
    /// criticality from the same minted certificate.
    /// </summary>
    [TestMethod]
    public void BothBackendsAgreeOnAPresentNonCriticalExtension()
    {
        // Cert-factory carve-out: CreateSelfSignedCa and CreateEcCredCert require live ECDsa instances for CertificateRequest.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);

        byte[] keyDescriptionBytes = AndroidKeyAttestationTestVectors.EncodeKeyDescriptionExtensionValue(
            [1, 2, 3, 4], AndroidKeyAttestationTestVectors.EmptyAuthorizationList, AndroidKeyAttestationTestVectors.ConformantAuthorizationList);
        using X509Certificate2 credCert = AndroidKeyAttestationTestVectors.CreateEcCredCert(rootCert, credentialKey, keyDescriptionBytes);
        using PkiCertificateMemory credCertPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(credCert.RawData);

        X509ExtensionValue? microsoftValue = MicrosoftX509Functions.ReadCertificateExtensionValue(credCertPki, AndroidKeyAttestationTestVectors.KeyDescriptionExtensionOid);
        X509ExtensionValue? bouncyCastleValue = BouncyCastleX509Functions.ReadCertificateExtensionValue(credCertPki, AndroidKeyAttestationTestVectors.KeyDescriptionExtensionOid);

        Assert.IsNotNull(microsoftValue);
        Assert.IsNotNull(bouncyCastleValue);
        Assert.IsFalse(microsoftValue.IsCritical);
        Assert.IsFalse(bouncyCastleValue.IsCritical);
        Assert.IsTrue(microsoftValue.Value.Span.SequenceEqual(bouncyCastleValue.Value.Span));
        Assert.IsTrue(microsoftValue.Value.Span.SequenceEqual(keyDescriptionBytes));
    }


    /// <summary>Both backends report <see langword="null"/> for an OID the certificate does not carry.</summary>
    [TestMethod]
    public void BothBackendsAgreeOnAnAbsentExtension()
    {
        // Cert-factory carve-out: CreateSelfSignedCa and CreateLeafAttestationCertificate require live ECDsa instances for CertificateRequest.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 credCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, credentialKey, isCertificateAuthority: false, organizationalUnit: null, aaguidExtensionValue: null);
        using PkiCertificateMemory credCertPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(credCert.RawData);

        Assert.IsNull(MicrosoftX509Functions.ReadCertificateExtensionValue(credCertPki, AndroidKeyAttestationTestVectors.KeyDescriptionExtensionOid));
        Assert.IsNull(BouncyCastleX509Functions.ReadCertificateExtensionValue(credCertPki, AndroidKeyAttestationTestVectors.KeyDescriptionExtensionOid));
    }


    /// <summary>Both backends report an extension's criticality flag identically when it is marked critical.</summary>
    [TestMethod]
    public void BothBackendsAgreeOnACriticalExtension()
    {
        // Cert-factory carve-out: CreateSelfSignedCa and CreateLeafAttestationCertificate require live ECDsa instances for CertificateRequest.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);

        byte[] keyDescriptionBytes = AndroidKeyAttestationTestVectors.EncodeKeyDescriptionExtensionValue(
            [5, 6, 7, 8], AndroidKeyAttestationTestVectors.EmptyAuthorizationList, AndroidKeyAttestationTestVectors.ConformantAuthorizationList);
        using X509Certificate2 credCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, credentialKey, isCertificateAuthority: false, organizationalUnit: null, aaguidExtensionValue: null,
            additionalExtensions: [new X509Extension(AndroidKeyAttestationTestVectors.KeyDescriptionExtensionOid, keyDescriptionBytes, critical: true)]);
        using PkiCertificateMemory credCertPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(credCert.RawData);

        X509ExtensionValue? microsoftValue = MicrosoftX509Functions.ReadCertificateExtensionValue(credCertPki, AndroidKeyAttestationTestVectors.KeyDescriptionExtensionOid);
        X509ExtensionValue? bouncyCastleValue = BouncyCastleX509Functions.ReadCertificateExtensionValue(credCertPki, AndroidKeyAttestationTestVectors.KeyDescriptionExtensionOid);

        Assert.IsNotNull(microsoftValue);
        Assert.IsNotNull(bouncyCastleValue);
        Assert.IsTrue(microsoftValue.IsCritical);
        Assert.IsTrue(bouncyCastleValue.IsCritical);
    }
}
