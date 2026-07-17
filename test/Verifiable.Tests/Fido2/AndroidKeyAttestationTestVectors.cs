using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Shared test-vector builders for the <c>android-key</c> attestation-verification tests: mints the
/// key description extension (OID <c>1.3.6.1.4.1.11129.2.1.17</c>) with BouncyCastle's ASN.1 writer —
/// an independent oracle from the System.Formats.Asn1-based <see cref="AndroidKeyDescription.Read"/>
/// this package ships — and the credCert carrying it, reusing
/// <see cref="Fido2AttestationTestVectors"/>'s chain-minting helpers for everything section 8.4 does
/// not itself define.
/// </summary>
internal static class AndroidKeyAttestationTestVectors
{
    /// <summary>
    /// The dotted OID of the android key attestation certificate extension, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-key-attstn-cert-requirements">W3C Web
    /// Authentication Level 3, section 8.4.1</see>. Duplicated from <see cref="AndroidKeyAttestation"/>'s
    /// own private constant, mirroring <see cref="Fido2AttestationTestVectors.AaguidExtensionOid"/>'s
    /// own duplication of <c>PackedAttestation</c>'s constant.
    /// </summary>
    internal const string KeyDescriptionExtensionOid = "1.3.6.1.4.1.11129.2.1.17";

    /// <summary>The <c>KM_PURPOSE_SIGN</c> value section 8.4's verification procedure requires.</summary>
    internal const int KmPurposeSign = 2;

    /// <summary>The <c>KM_ORIGIN_GENERATED</c> value section 8.4's verification procedure requires.</summary>
    internal const int KmOriginGenerated = 0;

    /// <summary>The Subject distinguished name a minted RSA credCert carries.</summary>
    private const string RsaCredCertSubjectName = "CN=Test Android Key Credential, O=Test Authenticator Vendor, C=US";

    /// <summary>Gets the default <c>notBefore</c> instant a minted RSA credCert carries.</summary>
    private static DateTimeOffset DefaultNotBefore { get; } = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>Gets the default <c>notAfter</c> instant a minted RSA credCert carries.</summary>
    private static DateTimeOffset DefaultNotAfter { get; } = new(2029, 1, 1, 0, 0, 0, TimeSpan.Zero);


    /// <summary>
    /// Gets an <see cref="AndroidKeyAuthorizationList"/> satisfying section 8.4's origin/purpose
    /// checks: <c>purpose</c> contains <see cref="KmPurposeSign"/>, <c>origin</c> is
    /// <see cref="KmOriginGenerated"/>, and <c>allApplications</c> is absent.
    /// </summary>
    internal static AndroidKeyAuthorizationList ConformantAuthorizationList { get; } =
        new(new HashSet<int> { KmPurposeSign }, KmOriginGenerated, HasAllApplications: false);

    /// <summary>
    /// Gets an <see cref="AndroidKeyAuthorizationList"/> with every field absent — the "this
    /// authorization list carries none of the key description fields" fixture (the shape a
    /// hardware-backed key's <c>softwareEnforced</c> list, or a software-only key's
    /// <c>teeEnforced</c> list, typically has).
    /// </summary>
    internal static AndroidKeyAuthorizationList EmptyAuthorizationList { get; } =
        new(new HashSet<int>(), null, HasAllApplications: false);


    /// <summary>
    /// DER-encodes a <c>KeyDescription</c> SEQUENCE — <c>attestationVersion</c>,
    /// <c>attestationSecurityLevel</c>, <c>keymasterVersion</c>, <c>keymasterSecurityLevel</c>, and
    /// <c>uniqueId</c> carry fixed, unchecked placeholder values, since section 8.4's verification
    /// procedure never inspects them — using BouncyCastle's ASN.1 writer, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-key-attstn-cert-requirements">section
    /// 8.4.1</see>'s delegated schema and confirmed byte-for-byte against
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-android-key-es256">section
    /// 16.14</see>'s own key description bytes (<see cref="AndroidKeyDescriptionReaderTests"/>).
    /// </summary>
    /// <param name="attestationChallenge">The <c>attestationChallenge</c> OCTET STRING content.</param>
    /// <param name="softwareEnforced">The <c>softwareEnforced</c> authorization list.</param>
    /// <param name="teeEnforced">The <c>teeEnforced</c> authorization list.</param>
    /// <returns>The DER-encoded <c>KeyDescription</c> SEQUENCE — the extension's <c>extnValue</c> content, not further OCTET-STRING-wrapped.</returns>
    internal static byte[] EncodeKeyDescriptionExtensionValue(byte[] attestationChallenge, AndroidKeyAuthorizationList softwareEnforced, AndroidKeyAuthorizationList teeEnforced)
    {
        var keyDescription = new DerSequence(
            new DerInteger(300),
            new DerEnumerated(0),
            new DerInteger(0),
            new DerEnumerated(0),
            new DerOctetString(attestationChallenge),
            new DerOctetString([]),
            EncodeAuthorizationList(softwareEnforced),
            EncodeAuthorizationList(teeEnforced));

        return keyDescription.GetEncoded();

        //Encodes one AuthorizationList SEQUENCE's tagged, OPTIONAL elements, in ascending tag order,
        //via BouncyCastle's explicit-tagging DerTaggedObject — confirmed to reproduce section
        //16.14's own purpose/origin bytes exactly (AndroidKeyDescriptionReaderTests).
        static Asn1Sequence EncodeAuthorizationList(AndroidKeyAuthorizationList authorizationList)
        {
            var elements = new List<Asn1Encodable>();
            if(authorizationList.Purposes.Count > 0)
            {
                Asn1Encodable[] purposeIntegers = [.. authorizationList.Purposes.Select(static purpose => (Asn1Encodable)new DerInteger(purpose))];
                elements.Add(new DerTaggedObject(1, new DerSet(purposeIntegers)));
            }

            if(authorizationList.HasAllApplications)
            {
                elements.Add(new DerTaggedObject(600, DerNull.Instance));
            }

            if(authorizationList.Origin is int origin)
            {
                elements.Add(new DerTaggedObject(702, new DerInteger(origin)));
            }

            return new DerSequence(elements.ToArray());
        }
    }


    /// <summary>
    /// Mints an EC credCert whose key IS <paramref name="credentialKey"/> and which carries
    /// <paramref name="keyDescriptionExtensionValue"/> under <see cref="KeyDescriptionExtensionOid"/>,
    /// reusing <see cref="Fido2AttestationTestVectors.CreateLeafAttestationCertificate"/> for
    /// everything section 8.4 does not itself define (section 8.4.1 imposes no certificate profile,
    /// so the reused helper's profile-shaped fields are cosmetic here).
    /// </summary>
    /// <param name="issuerCertificate">The issuing CA certificate (private key attached).</param>
    /// <param name="credentialKey">The credential's own P-256/P-384/P-521 key pair.</param>
    /// <param name="keyDescriptionExtensionValue">The DER-encoded <c>KeyDescription</c> SEQUENCE.</param>
    /// <returns>The credCert, private key attached.</returns>
    internal static X509Certificate2 CreateEcCredCert(X509Certificate2 issuerCertificate, ECDsa credentialKey, byte[] keyDescriptionExtensionValue)
    {
        return Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            issuerCertificate,
            credentialKey,
            isCertificateAuthority: false,
            organizationalUnit: null,
            aaguidExtensionValue: null,
            additionalExtensions: [new X509Extension(KeyDescriptionExtensionOid, keyDescriptionExtensionValue, critical: false)]);
    }


    /// <summary>
    /// Mints an RSA credCert whose key IS <paramref name="credentialKey"/> and which carries
    /// <paramref name="keyDescriptionExtensionValue"/> under <see cref="KeyDescriptionExtensionOid"/>
    /// — the RS256 algorithm-matrix fixture. Built locally rather than through
    /// <see cref="Fido2AttestationTestVectors.CreateLeafAttestationCertificateWithRsaKey"/>, which
    /// exposes no <c>additionalExtensions</c> parameter.
    /// </summary>
    /// <param name="issuerCertificate">The issuing EC CA certificate (private key attached).</param>
    /// <param name="credentialKey">The credential's own RSA key pair.</param>
    /// <param name="keyDescriptionExtensionValue">The DER-encoded <c>KeyDescription</c> SEQUENCE.</param>
    /// <returns>The credCert, private key attached.</returns>
    internal static X509Certificate2 CreateRsaCredCert(X509Certificate2 issuerCertificate, RSA credentialKey, byte[] keyDescriptionExtensionValue)
    {
        ArgumentNullException.ThrowIfNull(issuerCertificate);
        ArgumentNullException.ThrowIfNull(credentialKey);
        ArgumentNullException.ThrowIfNull(keyDescriptionExtensionValue);

        var request = new CertificateRequest(RsaCredCertSubjectName, credentialKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        request.CertificateExtensions.Add(new X509Extension(KeyDescriptionExtensionOid, keyDescriptionExtensionValue, critical: false));

        //CertificateRequest.Create(X509Certificate2, ...) requires the issuer's key algorithm to
        //match the request's own; an RSA credCert signed by the EC test root needs the explicit
        //X509SignatureGenerator overload instead, mirroring Fido2AttestationTestVectors's own RSA
        //leaf-minting helper.
        using ECDsa issuerKey = issuerCertificate.GetECDsaPrivateKey()
            ?? throw new ArgumentException("Issuer certificate must carry an ECDsa private key.", nameof(issuerCertificate));
        X509SignatureGenerator issuerSignatureGenerator = X509SignatureGenerator.CreateForECDsa(issuerKey);

        byte[] serialNumber = RandomNumberGenerator.GetBytes(16);
        return request.Create(
            issuerCertificate.SubjectName,
            issuerSignatureGenerator,
            DefaultNotBefore,
            DefaultNotAfter,
            serialNumber).CopyWithPrivateKey(credentialKey);
    }


    /// <summary>
    /// Encodes a valid <c>android-key</c> <c>attStmt</c> CBOR map (<c>alg</c>/<c>sig</c>/<c>x5c</c>) in
    /// the CTAP2 canonical CBOR encoding form, as a real authenticator would. Kept for
    /// <see cref="Verifiable.Tests.ToolTests.Fido2CliCompositionRootGapTests"/>'s own fixture, which
    /// mints a registration fixture from raw certificate DER bytes rather than pooled
    /// <see cref="Verifiable.Cryptography.Pki.PkiCertificateMemory"/> carriers;
    /// <see cref="AndroidKeyAttestationTests"/> itself uses the shipped
    /// <see cref="Verifiable.Cbor.Fido2.AndroidKeyAttestationStatementCborWriter"/> instead.
    /// </summary>
    /// <param name="alg">The COSE algorithm identifier.</param>
    /// <param name="sig">The attestation signature bytes.</param>
    /// <param name="x5c">The certificate chain's DER bytes, credCert first.</param>
    /// <returns>The encoded <c>attStmt</c> bytes.</returns>
    internal static byte[] EncodeAndroidKeyAttStmt(int alg, byte[] sig, IReadOnlyList<byte[]> x5c)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteTextString("alg");
        writer.WriteInt32(alg);
        writer.WriteTextString("sig");
        writer.WriteByteString(sig);
        writer.WriteTextString("x5c");
        writer.WriteStartArray(x5c.Count);
        foreach(byte[] certificate in x5c)
        {
            writer.WriteByteString(certificate);
        }

        writer.WriteEndArray();
        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>
    /// A <see cref="ParseAndroidKeyAttestationStatementDelegate"/> stub that ignores the raw CBOR
    /// input and returns a pre-built <see cref="AndroidKeyAttestationStatement"/>, mirroring
    /// <see cref="Fido2AttestationTestVectors.CreateStatementParser"/>'s idiom for the
    /// direct-verifier tests that thread an already-parsed statement through rather than real CBOR.
    /// </summary>
    /// <param name="statement">The statement to return regardless of the supplied bytes.</param>
    /// <returns>A delegate that always returns <paramref name="statement"/>.</returns>
    internal static ParseAndroidKeyAttestationStatementDelegate CreateStatementParser(AndroidKeyAttestationStatement statement) =>
        (_, _) => statement;
}
