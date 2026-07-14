using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.BouncyCastle;
using Verifiable.Cbor.Mdoc;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Shared test-vector builders for the WebAuthn L3 attestation-verification tests: mints an
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements">section 8.2.1</see>
/// conformant attestation certificate chain, assembles <see cref="AttestationVerificationRequest"/> instances
/// from parsed-view members, and signs the <c>authenticatorData || clientDataHash</c> transcript with an
/// independent oracle (raw <see cref="ECDsa"/>, never the library's own signing seam) so the verifier under
/// test is exercised against genuinely external wire material.
/// </summary>
internal static class Fido2AttestationTestVectors
{
    /// <summary>
    /// The <c>id-fido-gen-ce-aaguid</c> extension object identifier per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements">section 8.2.1</see>.
    /// </summary>
    internal const string AaguidExtensionOid = "1.3.6.1.4.1.45724.1.1.4";

    /// <summary>
    /// The literal Subject Organizational Unit value the packed-attestation certificate profile requires, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements">section 8.2.1</see>.
    /// </summary>
    internal const string RequiredOrganizationalUnit = "Authenticator Attestation";

    /// <summary>
    /// The <c>id-fido-gen-ce-fw-version</c> extension object identifier per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements">section 8.2.1</see>.
    /// </summary>
    internal const string FirmwareVersionExtensionOid = "1.3.6.1.4.1.45724.1.1.5";

    /// <summary>The conformant default Subject-C (ISO 3166-1 alpha-2 country code) minted leaf certificates carry.</summary>
    private const string DefaultLeafCountry = "US";

    /// <summary>The conformant default Subject-O minted leaf certificates carry.</summary>
    private const string DefaultLeafOrganization = "Test Authenticator Vendor";

    /// <summary>The conformant default Subject-CN minted leaf certificates carry.</summary>
    private const string DefaultLeafCommonName = "Test Authenticator";

    /// <summary>Gets the default <c>notBefore</c> instant minted leaf certificates carry.</summary>
    private static DateTimeOffset DefaultLeafNotBefore { get; } = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>Gets the default <c>notAfter</c> instant minted leaf certificates carry.</summary>
    private static DateTimeOffset DefaultLeafNotAfter { get; } = new(2029, 1, 1, 0, 0, 0, TimeSpan.Zero);


    /// <summary>
    /// Creates a self-signed CA certificate, mirroring the cert-minting idiom used for mdoc IACA trust tests:
    /// a P-256 key, Basic Constraints <c>cA=true</c>, and <c>keyCertSign</c>/<c>cRLSign</c> Key Usage.
    /// </summary>
    /// <param name="subjectName">The RFC 4514 subject distinguished name string.</param>
    /// <param name="key">The CA's P-256 key pair; the private half signs both the root and any leaf it issues.</param>
    /// <returns>The self-signed root certificate, private key attached.</returns>
    internal static X509Certificate2 CreateSelfSignedCa(string subjectName, ECDsa key)
    {
        //Test-side certificate factory (owner carve-out): CertificateRequest mints the CA
        //certificate directly, there being no library seam for issuing X.509 certificates.
        var request = new CertificateRequest(subjectName, key, HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 1, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        return request.CreateSelfSigned(
            notBefore: new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            notAfter: new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero));
    }


    /// <summary>
    /// Mints an intermediate CA certificate issued by <paramref name="issuerCertificate"/> — the middle tier of a
    /// three-certificate chain (root CA → intermediate CA → leaf) used by the chain-completion and
    /// intermediate-revocation tests. Carries Basic Constraints <c>cA=true</c> with no further path length budget,
    /// <c>keyCertSign</c>/<c>cRLSign</c> Key Usage, a Subject Key Identifier, and an Authority Key Identifier
    /// referencing the issuer — the ambiguous-issuer-safe minting convention every CA/intermediate/leaf certificate
    /// in this suite follows (RFC 5280 section 4.2.1.1/4.2.1.2), so a real path builder can disambiguate same-named
    /// issuer candidates by key rather than name alone.
    /// </summary>
    /// <param name="issuerCertificate">The issuing root CA certificate (private key attached, e.g. from <see cref="CreateSelfSignedCa"/>).</param>
    /// <param name="intermediateKey">The intermediate's own P-256 key pair; the private half signs the leaf certificates it issues.</param>
    /// <param name="subjectName">The RFC 4514 subject distinguished name string. Defaults to a fixed test value.</param>
    /// <returns>The intermediate CA certificate, private key attached.</returns>
    internal static X509Certificate2 CreateIntermediateCaCertificate(
        X509Certificate2 issuerCertificate,
        ECDsa intermediateKey,
        string subjectName = "CN=Test Attestation Intermediate")
    {
        ArgumentNullException.ThrowIfNull(issuerCertificate);
        ArgumentNullException.ThrowIfNull(intermediateKey);

        //Test-side certificate factory (owner carve-out): CertificateRequest mints the
        //intermediate certificate directly, there being no library seam for issuing X.509 certificates.
        var request = new CertificateRequest(subjectName, intermediateKey, HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuerCertificate, includeKeyIdentifier: true, includeIssuerAndSerial: false));

        byte[] serialNumber = RandomNumberGenerator.GetBytes(16);
        return request.Create(
            issuerCertificate,
            notBefore: DefaultLeafNotBefore,
            notAfter: DefaultLeafNotAfter,
            serialNumber).CopyWithPrivateKey(intermediateKey);
    }


    /// <summary>
    /// Builds the Authority Key Identifier extension for a leaf certificate issued by
    /// <paramref name="issuerCertificate"/>, for use with <see cref="CreateLeafAttestationCertificate"/>'s
    /// <c>additionalExtensions</c> parameter — the ambiguous-issuer-safe minting convention (RFC 5280 section
    /// 4.2.1.1) applied to a leaf issued by an intermediate CA rather than a self-signed root.
    /// </summary>
    /// <param name="issuerCertificate">The issuing certificate (the intermediate CA, e.g. from <see cref="CreateIntermediateCaCertificate"/>).</param>
    /// <returns>The Authority Key Identifier extension referencing <paramref name="issuerCertificate"/>.</returns>
    internal static X509Extension CreateLeafAuthorityKeyIdentifierExtension(X509Certificate2 issuerCertificate)
    {
        ArgumentNullException.ThrowIfNull(issuerCertificate);

        //Test-side certificate factory (owner carve-out): the BCL's own Authority Key
        //Identifier builder is the natural counterpart to CertificateRequest-minted certificates.
        return X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuerCertificate, includeKeyIdentifier: true, includeIssuerAndSerial: false);
    }


    /// <summary>
    /// Mints a leaf attestation certificate whose profile-relevant fields are individually controllable, so a
    /// single helper produces both the section 8.2.1-conformant happy-path certificate and every certificate-shaped
    /// negative fixture (missing OU, CA-flagged leaf, mismatching AAGUID extension).
    /// </summary>
    /// <param name="issuerCertificate">The issuing CA certificate (private key attached, e.g. from <see cref="CreateSelfSignedCa"/>).</param>
    /// <param name="leafKey">The leaf's own P-256 key pair; the private half is the attestation signing key under test.</param>
    /// <param name="isCertificateAuthority">The Basic Constraints <c>cA</c> value to assert on the leaf.</param>
    /// <param name="organizationalUnit">
    /// The Subject-OU value to assert, or <see langword="null"/> to omit the OU attribute entirely — the
    /// "leaf without the required OU" fixture.
    /// </param>
    /// <param name="aaguidExtensionValue">
    /// The AAGUID to embed in the <see cref="AaguidExtensionOid"/> extension, or <see langword="null"/> to omit
    /// the extension — per section 8.2.1 the extension is present only when the root is shared across models.
    /// </param>
    /// <param name="country">
    /// The Subject-C value to assert, or <see langword="null"/> to omit the Country attribute entirely — the
    /// "leaf without the required Subject-C" fixture. Defaults to the conformant <c>US</c>.
    /// </param>
    /// <param name="organization">
    /// The Subject-O value to assert, or <see langword="null"/> to omit the Organization attribute entirely —
    /// the "leaf without the required Subject-O" fixture. Defaults to a conformant vendor name.
    /// </param>
    /// <param name="commonName">
    /// The Subject-CN value to assert, or <see langword="null"/> to omit the Common Name attribute entirely —
    /// the "leaf without the required Subject-CN" fixture. Defaults to a conformant vendor-chosen name.
    /// </param>
    /// <param name="aaguidExtensionIsCritical">
    /// The criticality of the <see cref="AaguidExtensionOid"/> extension when <paramref name="aaguidExtensionValue"/>
    /// is not <see langword="null"/>. Defaults to <see langword="false"/>, the section 8.2.1-conformant value; a
    /// caller passing <see langword="true"/> builds the "AAGUID extension marked critical" negative fixture.
    /// </param>
    /// <param name="notBefore">The certificate's <c>notBefore</c> instant. Defaults to a fixed conformant value.</param>
    /// <param name="notAfter">The certificate's <c>notAfter</c> instant. Defaults to a fixed conformant value.</param>
    /// <param name="additionalExtensions">
    /// Extra certificate extensions to add beyond the standard section 8.2.1 profile set, or
    /// <see langword="null"/> for none — the "leaf carries an extra extension" negative fixtures
    /// (e.g. a critical <c>id-fido-gen-ce-fw-version</c>).
    /// </param>
    /// <returns>The leaf certificate, private key attached.</returns>
    internal static X509Certificate2 CreateLeafAttestationCertificate(
        X509Certificate2 issuerCertificate,
        ECDsa leafKey,
        bool isCertificateAuthority,
        string? organizationalUnit,
        Guid? aaguidExtensionValue,
        string? country = DefaultLeafCountry,
        string? organization = DefaultLeafOrganization,
        string? commonName = DefaultLeafCommonName,
        bool aaguidExtensionIsCritical = false,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        IReadOnlyList<X509Extension>? additionalExtensions = null)
    {
        ArgumentNullException.ThrowIfNull(issuerCertificate);
        ArgumentNullException.ThrowIfNull(leafKey);

        string subjectName = BuildAttestationSubjectName(country, organization, organizationalUnit, commonName);

        //Test-side certificate factory (owner carve-out): CertificateRequest mints the leaf
        //certificate directly, there being no library seam for issuing X.509 certificates.
        var request = new CertificateRequest(subjectName, leafKey, HashAlgorithmName.SHA256);
        AddLeafAttestationExtensions(request, isCertificateAuthority, aaguidExtensionValue, aaguidExtensionIsCritical);

        if(additionalExtensions is not null)
        {
            foreach(X509Extension extension in additionalExtensions)
            {
                request.CertificateExtensions.Add(extension);
            }
        }

        byte[] serialNumber = RandomNumberGenerator.GetBytes(16);
        return request.Create(
            issuerCertificate,
            notBefore: notBefore ?? DefaultLeafNotBefore,
            notAfter: notAfter ?? DefaultLeafNotAfter,
            serialNumber).CopyWithPrivateKey(leafKey);
    }


    /// <summary>
    /// Mints a leaf attestation certificate hand-rewritten to encode as X.509 version 1 — the
    /// section 8.2.1 "MUST be version 3" negative fixture (tally clause 6419). <c>CertificateRequest</c>
    /// always emits version-3 TBSCertificates, so no public API mints version 1 directly: this
    /// starts from an otherwise section 8.2.1-conformant leaf, then removes the TBSCertificate's
    /// <c>[0]</c> version and <c>[3]</c> extensions fields — the only two fields whose presence
    /// distinguishes version 3 from version 1 per
    /// <see href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.1">RFC 5280 section
    /// 4.1.2.1</see> — and re-signs the rewritten TBSCertificate with the issuer's own key, since the
    /// original signature no longer covers it.
    /// </summary>
    /// <param name="issuerCertificate">The issuing CA certificate (private key attached, e.g. from <see cref="CreateSelfSignedCa"/>).</param>
    /// <param name="leafKey">The leaf's own P-256 key pair; the private half is the attestation signing key under test.</param>
    /// <returns>The version-1 leaf certificate, private key attached.</returns>
    internal static X509Certificate2 CreateVersion1LeafAttestationCertificate(X509Certificate2 issuerCertificate, ECDsa leafKey)
    {
        ArgumentNullException.ThrowIfNull(issuerCertificate);
        ArgumentNullException.ThrowIfNull(leafKey);

        using X509Certificate2 version3Certificate = CreateLeafAttestationCertificate(
            issuerCertificate, leafKey, isCertificateAuthority: false, RequiredOrganizationalUnit, aaguidExtensionValue: null);

        AsnReader certificateReader = new AsnReader(version3Certificate.RawData, AsnEncodingRules.DER).ReadSequence();
        ReadOnlyMemory<byte> tbsCertificate = certificateReader.ReadEncodedValue();
        ReadOnlyMemory<byte> signatureAlgorithm = certificateReader.ReadEncodedValue();

        AsnReader tbsReader = new AsnReader(tbsCertificate, AsnEncodingRules.DER).ReadSequence();
        var tbsWriter = new AsnWriter(AsnEncodingRules.DER);
        using(tbsWriter.PushSequence())
        {
            while(tbsReader.HasData)
            {
                Asn1Tag tag = tbsReader.PeekTag();
                if(tag.TagClass == TagClass.ContextSpecific && (tag.TagValue == 0 || tag.TagValue == 3))
                {
                    //Drop the [0] version and [3] extensions fields: their absence is exactly what
                    //makes the rewritten TBSCertificate encode as X.509 version 1.
                    tbsReader.ReadEncodedValue();
                }
                else
                {
                    tbsWriter.WriteEncodedValue(tbsReader.ReadEncodedValue().Span);
                }
            }
        }

        byte[] version1TbsCertificate = tbsWriter.Encode();

        //Test-side certificate factory (owner carve-out): re-signs the hand-rewritten
        //TBSCertificate with the issuer's own key, completing the version-1 certificate mint.
        using ECDsa issuerKey = issuerCertificate.GetECDsaPrivateKey()
            ?? throw new ArgumentException("Issuer certificate must carry an ECDsa private key.", nameof(issuerCertificate));
        byte[] signatureValue = issuerKey.SignData(version1TbsCertificate, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var certificateWriter = new AsnWriter(AsnEncodingRules.DER);
        using(certificateWriter.PushSequence())
        {
            certificateWriter.WriteEncodedValue(version1TbsCertificate);
            certificateWriter.WriteEncodedValue(signatureAlgorithm.Span);
            certificateWriter.WriteBitString(signatureValue);
        }

        byte[] certificateBytes = certificateWriter.Encode();
        using X509Certificate2 certificateOnly = X509CertificateLoader.LoadCertificate(certificateBytes);

        return certificateOnly.CopyWithPrivateKey(leafKey);
    }


    /// <summary>
    /// DER-encodes a non-negative firmware version as the INTEGER value the
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements">section 8.2.1</see>
    /// <c>id-fido-gen-ce-fw-version</c> extension carries.
    /// </summary>
    /// <param name="firmwareVersion">The non-negative firmware version to encode.</param>
    /// <returns>The DER bytes of an INTEGER carrying <paramref name="firmwareVersion"/>.</returns>
    internal static byte[] EncodeFirmwareVersionExtensionValue(int firmwareVersion)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteInteger(firmwareVersion);

        return writer.Encode();
    }


    /// <summary>
    /// Reverses the certificate order of a minted <c>x5c</c>-shaped chain — the "x5c array carries
    /// the chain out of order (leaf not first)" negative fixture for
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">section 8.2</see>, whose
    /// CDDL and verification procedure both assume the attestation certificate is the first element.
    /// </summary>
    /// <param name="chain">The leaf-first chain to permute.</param>
    /// <returns>The same certificates with their order reversed (root-first).</returns>
    internal static PkiCertificateMemory[] ReverseChainOrder(IReadOnlyList<PkiCertificateMemory> chain)
    {
        ArgumentNullException.ThrowIfNull(chain);

        var reversed = new PkiCertificateMemory[chain.Count];
        for(int i = 0; i < chain.Count; i++)
        {
            reversed[i] = chain[chain.Count - 1 - i];
        }

        return reversed;
    }


    /// <summary>
    /// Mints an RSA-keyed leaf attestation certificate — the certified RS256 packed-attestation matrix
    /// fixture, where the leaf key family must match the statement's <c>alg</c>. Mirrors
    /// <see cref="CreateLeafAttestationCertificate(X509Certificate2, ECDsa, bool, string?, Guid?, string?, string?, string?, bool, DateTimeOffset?, DateTimeOffset?)"/>
    /// exactly, save for the RSA key and PKCS#1 v1.5/SHA-256 signature algorithm.
    /// </summary>
    /// <param name="issuerCertificate">The issuing CA certificate (private key attached, e.g. from <see cref="CreateSelfSignedCa"/>).</param>
    /// <param name="leafKey">The leaf's own RSA-2048 key pair; the private half is the attestation signing key under test.</param>
    /// <param name="isCertificateAuthority">The Basic Constraints <c>cA</c> value to assert on the leaf.</param>
    /// <param name="organizationalUnit">The Subject-OU value to assert, or <see langword="null"/> to omit it.</param>
    /// <param name="aaguidExtensionValue">The AAGUID to embed, or <see langword="null"/> to omit the extension.</param>
    /// <param name="country">The Subject-C value to assert, or <see langword="null"/> to omit it. Defaults to <c>US</c>.</param>
    /// <param name="organization">The Subject-O value to assert, or <see langword="null"/> to omit it.</param>
    /// <param name="commonName">The Subject-CN value to assert, or <see langword="null"/> to omit it.</param>
    /// <param name="aaguidExtensionIsCritical">The criticality of the AAGUID extension. Defaults to <see langword="false"/>.</param>
    /// <param name="notBefore">The certificate's <c>notBefore</c> instant. Defaults to a fixed conformant value.</param>
    /// <param name="notAfter">The certificate's <c>notAfter</c> instant. Defaults to a fixed conformant value.</param>
    /// <returns>The leaf certificate, private key attached.</returns>
    internal static X509Certificate2 CreateLeafAttestationCertificateWithRsaKey(
        X509Certificate2 issuerCertificate,
        RSA leafKey,
        bool isCertificateAuthority,
        string? organizationalUnit,
        Guid? aaguidExtensionValue,
        string? country = DefaultLeafCountry,
        string? organization = DefaultLeafOrganization,
        string? commonName = DefaultLeafCommonName,
        bool aaguidExtensionIsCritical = false,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        ArgumentNullException.ThrowIfNull(issuerCertificate);
        ArgumentNullException.ThrowIfNull(leafKey);

        string subjectName = BuildAttestationSubjectName(country, organization, organizationalUnit, commonName);

        //Test-side certificate factory (owner carve-out): CertificateRequest mints the RSA
        //leaf certificate directly, there being no library seam for issuing X.509 certificates.
        var request = new CertificateRequest(subjectName, leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        AddLeafAttestationExtensions(request, isCertificateAuthority, aaguidExtensionValue, aaguidExtensionIsCritical);

        //CertificateRequest.Create(X509Certificate2, ...) — the convenience overload
        //CreateLeafAttestationCertificate (the EC-leaf sibling) uses — requires the issuer's key
        //algorithm to match the request's own; an RSA leaf signed by the EC test root
        //(CreateSelfSignedCa) needs the explicit X509SignatureGenerator overload instead.
        using ECDsa issuerKey = issuerCertificate.GetECDsaPrivateKey()
            ?? throw new ArgumentException("Issuer certificate must carry an ECDsa private key.", nameof(issuerCertificate));
        X509SignatureGenerator issuerSignatureGenerator = X509SignatureGenerator.CreateForECDsa(issuerKey);

        byte[] serialNumber = RandomNumberGenerator.GetBytes(16);
        return request.Create(
            issuerCertificate.SubjectName,
            issuerSignatureGenerator,
            notBefore ?? DefaultLeafNotBefore,
            notAfter ?? DefaultLeafNotAfter,
            serialNumber).CopyWithPrivateKey(leafKey);
    }


    /// <summary>
    /// Builds the RFC 4514 Subject distinguished name string for a minted attestation leaf certificate,
    /// in Subject-field order <c>C, O, OU, CN</c>, omitting any attribute whose value is <see langword="null"/> —
    /// the "missing required Subject attribute" negative fixtures.
    /// </summary>
    /// <param name="country">The Subject-C value, or <see langword="null"/> to omit it.</param>
    /// <param name="organization">The Subject-O value, or <see langword="null"/> to omit it.</param>
    /// <param name="organizationalUnit">The Subject-OU value, or <see langword="null"/> to omit it.</param>
    /// <param name="commonName">The Subject-CN value, or <see langword="null"/> to omit it.</param>
    /// <returns>The RFC 4514 subject name string.</returns>
    private static string BuildAttestationSubjectName(string? country, string? organization, string? organizationalUnit, string? commonName)
    {
        var attributes = new List<string>(4);
        if(country is not null)
        {
            attributes.Add($"C={country}");
        }

        if(organization is not null)
        {
            attributes.Add($"O={organization}");
        }

        if(organizationalUnit is not null)
        {
            attributes.Add($"OU={organizationalUnit}");
        }

        if(commonName is not null)
        {
            attributes.Add($"CN={commonName}");
        }

        return string.Join(", ", attributes);
    }


    /// <summary>
    /// Adds the section 8.2.1 profile extensions (Basic Constraints, Key Usage, Subject Key Identifier, and
    /// the optional AAGUID extension) common to both the EC and RSA leaf-minting overloads.
    /// </summary>
    /// <param name="request">The certificate request to add extensions to.</param>
    /// <param name="isCertificateAuthority">The Basic Constraints <c>cA</c> value to assert.</param>
    /// <param name="aaguidExtensionValue">The AAGUID to embed, or <see langword="null"/> to omit the extension.</param>
    /// <param name="aaguidExtensionIsCritical">The criticality of the AAGUID extension.</param>
    private static void AddLeafAttestationExtensions(CertificateRequest request, bool isCertificateAuthority, Guid? aaguidExtensionValue, bool aaguidExtensionIsCritical)
    {
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: isCertificateAuthority, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        if(aaguidExtensionValue is Guid aaguid)
        {
            //Section 8.2.1: "The extension MUST NOT be marked as critical." aaguidExtensionIsCritical
            //defaults to false (conformant); a caller passing true builds the negative fixture.
            request.CertificateExtensions.Add(new X509Extension(AaguidExtensionOid, EncodeAaguidExtensionValue(aaguid), critical: aaguidExtensionIsCritical));
        }
    }


    /// <summary>
    /// DER-encodes the 16-byte big-endian AAGUID as the OCTET STRING value the
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements">section 8.2.1</see>
    /// <c>id-fido-gen-ce-aaguid</c> extension carries — the content <see cref="X509Extension"/> wraps in the
    /// outer extnValue OCTET STRING at certificate-encoding time, matching the spec's "wrapped in two OCTET
    /// STRINGS" illustration.
    /// </summary>
    /// <param name="aaguid">The AAGUID to encode.</param>
    /// <returns>The DER bytes of an OCTET STRING containing the 16 big-endian AAGUID bytes.</returns>
    internal static byte[] EncodeAaguidExtensionValue(Guid aaguid)
    {
        Span<byte> aaguidBytes = stackalloc byte[16];
        aaguid.TryWriteBytes(aaguidBytes, bigEndian: true, out _);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(aaguidBytes);

        return writer.Encode();
    }


    /// <summary>
    /// Copies a DER-encoded certificate into a pooled <see cref="PkiCertificateMemory"/> carrier, the wire-shaped
    /// form <see cref="AttestationVerificationRequest.TrustAnchors"/> and a packed <c>x5c</c> carry.
    /// </summary>
    /// <param name="derBytes">The DER-encoded certificate bytes (e.g. <see cref="X509Certificate2.RawData"/>).</param>
    /// <returns>A pooled certificate carrier; the caller owns and disposes it.</returns>
    internal static PkiCertificateMemory ToPkiCertificateMemory(byte[] derBytes)
    {
        ArgumentNullException.ThrowIfNull(derBytes);

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>
    /// Builds a P-256 COSE_Key view directly from an <see cref="ECDsa"/> key pair's public parameters — the
    /// <c>credentialPublicKey</c> the packed self-attestation verification procedure reads <c>alg</c> from.
    /// </summary>
    /// <param name="key">The P-256 key pair whose public point becomes the COSE_Key coordinates.</param>
    /// <param name="alg">The optional COSE <c>alg</c> label (e.g. <c>-7</c> for ES256), or <see langword="null"/>.</param>
    /// <returns>The parsed-view <see cref="CoseKey"/>.</returns>
    internal static CoseKey CreateP256CoseKey(ECDsa key, int? alg)
    {
        ArgumentNullException.ThrowIfNull(key);

        ECParameters parameters = key.ExportParameters(includePrivateParameters: false);
        return new CoseKey(kty: CoseKeyTypes.Ec2, alg: alg, curve: CoseKeyCurves.P256, x: parameters.Q.X, y: parameters.Q.Y);
    }


    /// <summary>
    /// Builds a P-384 COSE_Key view directly from an <see cref="ECDsa"/> key pair's public parameters —
    /// the ES384 packed-attestation algorithm-matrix fixture.
    /// </summary>
    /// <param name="key">The P-384 key pair whose public point becomes the COSE_Key coordinates.</param>
    /// <param name="alg">The optional COSE <c>alg</c> label (e.g. <c>-35</c> for ES384), or <see langword="null"/>.</param>
    /// <returns>The parsed-view <see cref="CoseKey"/>.</returns>
    internal static CoseKey CreateP384CoseKey(ECDsa key, int? alg)
    {
        ArgumentNullException.ThrowIfNull(key);

        ECParameters parameters = key.ExportParameters(includePrivateParameters: false);
        return new CoseKey(kty: CoseKeyTypes.Ec2, alg: alg, curve: CoseKeyCurves.P384, x: parameters.Q.X, y: parameters.Q.Y);
    }


    /// <summary>
    /// Builds a P-521 COSE_Key view directly from an <see cref="ECDsa"/> key pair's public parameters —
    /// the ES512 packed-attestation algorithm-matrix fixture.
    /// </summary>
    /// <param name="key">The P-521 key pair whose public point becomes the COSE_Key coordinates.</param>
    /// <param name="alg">The optional COSE <c>alg</c> label (e.g. <c>-36</c> for ES512), or <see langword="null"/>.</param>
    /// <returns>The parsed-view <see cref="CoseKey"/>.</returns>
    internal static CoseKey CreateP521CoseKey(ECDsa key, int? alg)
    {
        ArgumentNullException.ThrowIfNull(key);

        ECParameters parameters = key.ExportParameters(includePrivateParameters: false);
        return new CoseKey(kty: CoseKeyTypes.Ec2, alg: alg, curve: CoseKeyCurves.P521, x: parameters.Q.X, y: parameters.Q.Y);
    }


    /// <summary>
    /// Builds an RSA COSE_Key view directly from an <see cref="RSA"/> key pair's public parameters
    /// (<c>n</c>/<c>e</c> per RFC 8230 §4) — the RS256 packed-attestation algorithm-matrix fixture.
    /// </summary>
    /// <param name="key">The RSA key pair whose modulus and exponent become the COSE_Key <c>n</c>/<c>e</c>.</param>
    /// <param name="alg">The optional COSE <c>alg</c> label (e.g. <c>-257</c> for RS256), or <see langword="null"/>.</param>
    /// <returns>The parsed-view <see cref="CoseKey"/>.</returns>
    internal static CoseKey CreateRsaCoseKey(RSA key, int? alg)
    {
        ArgumentNullException.ThrowIfNull(key);

        RSAParameters parameters = key.ExportParameters(includePrivateParameters: false);
        return new CoseKey(kty: CoseKeyTypes.Rsa, alg: alg, n: parameters.Modulus, e: parameters.Exponent);
    }


    /// <summary>
    /// Builds an OKP (Ed25519) COSE_Key view from an Ed25519 public key's raw bytes — the EdDSA packed
    /// self-attestation algorithm-matrix fixture. No independent .NET BCL Ed25519 primitive exists, so
    /// this credential is minted through <see cref="TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial"/>
    /// and signed via <see cref="BouncyCastleCryptographicFunctions.SignEd25519Async"/> — the firewall
    /// independence is that no key object crosses the issuer/verifier boundary, only wire bytes.
    /// </summary>
    /// <param name="publicKey">The Ed25519 public key's raw bytes.</param>
    /// <param name="alg">The optional COSE <c>alg</c> label (e.g. <c>-8</c> for EdDSA), or <see langword="null"/>.</param>
    /// <returns>The parsed-view <see cref="CoseKey"/>.</returns>
    internal static CoseKey CreateEd25519CoseKey(PublicKeyMemory publicKey, int? alg)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        return new CoseKey(kty: CoseKeyTypes.Okp, alg: alg, curve: CoseKeyCurves.Ed25519, x: publicKey.AsReadOnlyMemory());
    }


    /// <summary>
    /// Assembles both the raw <c>authData</c> wire bytes (what the attestation signature covers) and the parsed
    /// <see cref="AuthenticatorData"/> view a verifier reads its attested-credential fields from, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">section 6.1</see>.
    /// </summary>
    /// <param name="aaguid">The AAGUID to embed in the attested credential data. Ignored when <paramref name="credentialPublicKey"/> is <see langword="null"/>.</param>
    /// <param name="credentialPublicKey">
    /// The credential public key to embed, or <see langword="null"/> to build <c>authData</c> with the <c>AT</c>
    /// flag clear — the "no attested credential data" fixture.
    /// </param>
    /// <param name="rawBytes">The raw <c>authData</c> bytes, an independent buffer with the same content as what the returned view was built from.</param>
    /// <returns>
    /// The parsed view. Its <see cref="Fido2.AuthenticatorData.RpIdHash"/> and, when present, attested
    /// credential data are owned pooled carriers; the caller owns and disposes the returned instance.
    /// </returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the DigestValue/CredentialId carriers transfers to the returned AuthenticatorData, which the caller disposes via a using declaration.")]
    internal static AuthenticatorData BuildAuthenticatorData(Guid aaguid, CoseKey? credentialPublicKey, out byte[] rawBytes)
    {
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        if(credentialPublicKey is null)
        {
            rawBytes = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags: AuthenticatorDataFlags.None, signCount: 0);

            return new AuthenticatorData(Fido2TestVectors.WrapRpIdHash(rpIdHash, BaseMemoryPool.Shared), new AuthenticatorDataFlags(AuthenticatorDataFlags.None), 0, null, ReadOnlyMemory<byte>.Empty);
        }

        byte[] credentialId = [0x01, 0x02, 0x03, 0x04];
        byte[] credentialPublicKeyCbor = MdocCborCoseKeyWriter.Write(credentialPublicKey).ToArray();
        byte[] attestedCredentialDataBytes = Fido2TestVectors.BuildAttestedCredentialData(aaguid, credentialId, credentialPublicKeyCbor);

        rawBytes = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, AuthenticatorDataFlags.AttestedCredentialDataIncludedBit, 0, attestedCredentialDataBytes);
        var attestedCredentialData = new AttestedCredentialData(aaguid, CredentialId.Create(credentialId, BaseMemoryPool.Shared), credentialPublicKey);

        return new AuthenticatorData(Fido2TestVectors.WrapRpIdHash(rpIdHash, BaseMemoryPool.Shared), new AuthenticatorDataFlags(AuthenticatorDataFlags.AttestedCredentialDataIncludedBit), 0, attestedCredentialData, ReadOnlyMemory<byte>.Empty);
    }


    /// <summary>
    /// Computes the <c>clientDataHash</c> synchronously through the registered SHA-256
    /// <see cref="HashFunctionDelegate"/> — a public-data digest with no hardware-async backend, per the
    /// codebase's sync-by-nature hash seam.
    /// </summary>
    /// <param name="clientDataBytes">The serialized <c>collectedClientData</c> bytes to hash.</param>
    /// <param name="pool">The pool the digest carrier rents from.</param>
    /// <returns>The 32-byte SHA-256 <see cref="DigestValue"/>; the caller disposes it.</returns>
    internal static DigestValue ComputeClientDataHash(byte[] clientDataBytes, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(clientDataBytes);

        return CryptographicKeyEvents.ComputeDigest(clientDataBytes, 32, CryptoTags.Sha256Digest, pool);
    }


    /// <summary>
    /// Builds the <c>authenticatorData || clientDataHash</c> transcript that every packed attestation signature
    /// (Basic/AttCA and Self alike) covers, per the
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">section 8.2</see> signing procedure.
    /// </summary>
    /// <param name="authenticatorDataBytes">The raw <c>authData</c> bytes.</param>
    /// <param name="clientDataHash">The <c>clientDataHash</c> digest.</param>
    /// <returns>The concatenated bytes to sign or verify.</returns>
    internal static byte[] BuildToBeSigned(ReadOnlyMemory<byte> authenticatorDataBytes, DigestValue clientDataHash)
    {
        ArgumentNullException.ThrowIfNull(clientDataHash);

        return Fido2TestVectors.Concat(authenticatorDataBytes.Span.ToArray(), clientDataHash.AsReadOnlySpan().ToArray());
    }


    /// <summary>
    /// Signs <paramref name="toBeSigned"/> with a raw <see cref="ECDsa"/> P-256 key — the independent oracle that
    /// mints attestation statements without going through the library's own signing seam, so the verifier under
    /// test is exercised against genuinely external wire material. Uses the ASN.1 DER <c>Ecdsa-Sig-Value</c>
    /// encoding
    /// (<see href="https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3">RFC 3279 section 2.2.3</see>),
    /// the wire format
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types">WebAuthn L3 section
    /// 6.5.5</see> requires for an ECDSA <c>sig</c> value, so the minted vector exercises
    /// <see cref="PackedAttestation"/>'s DER-to-P1363 conversion rather than agreeing with it by construction.
    /// </summary>
    /// <param name="key">The P-256 private key to sign with.</param>
    /// <param name="toBeSigned">The bytes to sign.</param>
    /// <returns>The ASN.1 DER-encoded <c>Ecdsa-Sig-Value</c> ECDSA/SHA-256 signature bytes.</returns>
    internal static byte[] SignWithEcdsaP256(ECDsa key, byte[] toBeSigned)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(toBeSigned);

        return key.SignData(toBeSigned, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }


    /// <summary>
    /// Signs <paramref name="toBeSigned"/> with a raw <see cref="ECDsa"/> P-384 key — mirrors
    /// <see cref="SignWithEcdsaP256"/> for the ES384 algorithm-matrix fixture.
    /// </summary>
    /// <param name="key">The P-384 private key to sign with.</param>
    /// <param name="toBeSigned">The bytes to sign.</param>
    /// <returns>The ASN.1 DER-encoded <c>Ecdsa-Sig-Value</c> ECDSA/SHA-384 signature bytes.</returns>
    internal static byte[] SignWithEcdsaP384(ECDsa key, byte[] toBeSigned)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(toBeSigned);

        return key.SignData(toBeSigned, HashAlgorithmName.SHA384, DSASignatureFormat.Rfc3279DerSequence);
    }


    /// <summary>
    /// Signs <paramref name="toBeSigned"/> with a raw <see cref="ECDsa"/> P-521 key — mirrors
    /// <see cref="SignWithEcdsaP256"/> for the ES512 algorithm-matrix fixture.
    /// </summary>
    /// <param name="key">The P-521 private key to sign with.</param>
    /// <param name="toBeSigned">The bytes to sign.</param>
    /// <returns>The ASN.1 DER-encoded <c>Ecdsa-Sig-Value</c> ECDSA/SHA-512 signature bytes.</returns>
    internal static byte[] SignWithEcdsaP521(ECDsa key, byte[] toBeSigned)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(toBeSigned);

        return key.SignData(toBeSigned, HashAlgorithmName.SHA512, DSASignatureFormat.Rfc3279DerSequence);
    }


    /// <summary>
    /// Signs <paramref name="toBeSigned"/> with a raw <see cref="RSA"/> key using PKCS#1 v1.5/SHA-256 —
    /// the independent oracle for the RS256 packed-attestation algorithm-matrix fixture. Section
    /// 6.5.5 leaves RSA signatures "not ASN.1 wrapped", so the raw signature is returned unchanged.
    /// </summary>
    /// <param name="key">The RSA private key to sign with.</param>
    /// <param name="toBeSigned">The bytes to sign.</param>
    /// <returns>The raw RSASSA-PKCS1-v1_5/SHA-256 signature bytes.</returns>
    internal static byte[] SignWithRsaPkcs1Sha256(RSA key, byte[] toBeSigned)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(toBeSigned);

        return key.SignData(toBeSigned, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }


    /// <summary>
    /// Signs <paramref name="toBeSigned"/> with an Ed25519 private key via the BouncyCastle primitive —
    /// the independent oracle for the EdDSA packed self-attestation algorithm-matrix fixture. Section
    /// 6.5.5 leaves EdDSA signatures "not ASN.1 wrapped", so the raw signature is returned unchanged.
    /// </summary>
    /// <param name="privateKey">The Ed25519 private key to sign with.</param>
    /// <param name="toBeSigned">The bytes to sign.</param>
    /// <returns>The raw Ed25519 signature bytes.</returns>
    internal static async ValueTask<byte[]> SignWithEd25519Async(PrivateKeyMemory privateKey, byte[] toBeSigned)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(toBeSigned);

        using Signature signature = await privateKey.SignAsync(toBeSigned, BouncyCastleCryptographicFunctions.SignEd25519Async, BaseMemoryPool.Shared).ConfigureAwait(false);

        return signature.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// Signs <paramref name="privateKey"/>'s secp256k1 key over <paramref name="toBeSigned"/> via the
    /// BouncyCastle primitive — the independent oracle for the ES256K packed self-attestation
    /// algorithm-matrix fixture. No framework <see cref="ECDsa"/> named curve covers secp256k1
    /// (RFC 8812 §3.2), so the credential is minted through
    /// <see cref="TestKeyMaterialProvider.CreateFreshSecp256k1KeyMaterial"/> rather than <see cref="ECDsa.Create()"/>.
    /// The BouncyCastle primitive returns the fixed-width IEEE P1363 encoding; section 6.5.5
    /// requires an ECDSA <c>sig</c> value to be ASN.1 DER-encoded, so the result is re-encoded before
    /// return, mirroring <see cref="Fido2AssertionOracle"/>'s EC re-encoding.
    /// </summary>
    /// <param name="privateKey">The secp256k1 private key to sign with.</param>
    /// <param name="toBeSigned">The bytes to sign.</param>
    /// <returns>The ASN.1 DER-encoded ECDSA/secp256k1 signature bytes.</returns>
    internal static async ValueTask<byte[]> SignWithSecp256k1Async(PrivateKeyMemory privateKey, byte[] toBeSigned)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(toBeSigned);

        using Signature p1363Signature = await privateKey.SignAsync(toBeSigned, BouncyCastleCryptographicFunctions.SignSecp256k1Async, BaseMemoryPool.Shared).ConfigureAwait(false);
        using IMemoryOwner<byte> derOwner = EcdsaSignatureEncoding.ConvertP1363ToDer(p1363Signature.AsReadOnlySpan(), BaseMemoryPool.Shared, out int derLength);

        return derOwner.Memory.Span[..derLength].ToArray();
    }


    /// <summary>
    /// Signs <paramref name="key"/>'s RSA key over <paramref name="toBeSigned"/> using RSASSA-PSS/SHA-256
    /// via the BouncyCastle primitive — the independent oracle for the PS256 packed self-attestation
    /// algorithm-matrix fixture (the registered PS256 verify path is Microsoft-backed, per
    /// <c>CryptoProviderStartup</c>'s RSA-family registrations).
    /// </summary>
    /// <param name="key">The RSA private key to sign with.</param>
    /// <param name="toBeSigned">The bytes to sign.</param>
    /// <returns>The RSASSA-PSS/SHA-256 signature bytes.</returns>
    internal static async ValueTask<byte[]> SignWithRsaPssSha256Async(RSA key, byte[] toBeSigned)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(toBeSigned);

        byte[] privateKeyDer = key.ExportRSAPrivateKey();
        (Signature signature, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.SignRsaSha256PssAsync(privateKeyDer, toBeSigned, BaseMemoryPool.Shared).ConfigureAwait(false);
        using var disposableSignature = signature;

        return signature.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// Builds an <see cref="AttestationVerificationRequest"/> from its wire-shaped members. A thin, named-argument
    /// wrapper so call sites read as a list of the fields under test rather than a positional constructor call.
    /// </summary>
    /// <param name="authenticatorDataBytes">The raw <c>authData</c> bytes the attestation signature covers.</param>
    /// <param name="authenticatorData">The parsed view aliasing <paramref name="authenticatorDataBytes"/>.</param>
    /// <param name="clientDataHash">The <c>clientDataHash</c> digest.</param>
    /// <param name="attestationStatement">The raw, opaque <c>attStmt</c> CBOR bytes (ignored by the stub parse delegates the tests supply).</param>
    /// <param name="trustAnchors">The trust anchor certificates, possibly empty.</param>
    /// <param name="validationTime">The UTC instant chain validation is evaluated at.</param>
    /// <returns>The assembled request.</returns>
    internal static AttestationVerificationRequest CreateRequest(
        ReadOnlyMemory<byte> authenticatorDataBytes,
        AuthenticatorData authenticatorData,
        DigestValue clientDataHash,
        ReadOnlyMemory<byte> attestationStatement,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset validationTime)
    {
        return new AttestationVerificationRequest(
            authenticatorDataBytes: authenticatorDataBytes,
            authenticatorData: authenticatorData,
            clientDataHash: clientDataHash,
            attestationStatement: attestationStatement,
            trustAnchors: trustAnchors,
            validationTime: validationTime,
            pool: BaseMemoryPool.Shared);
    }


    /// <summary>
    /// A <see cref="ParsePackedAttestationStatementDelegate"/> stub that ignores the raw CBOR input and returns a
    /// pre-built <see cref="PackedAttestationStatement"/> — the CBOR codec is edge-wired separately; these tests
    /// exercise the verification procedure against a directly constructed statement.
    /// </summary>
    /// <param name="statement">The statement to return regardless of the supplied bytes.</param>
    /// <returns>A delegate that always returns <paramref name="statement"/>.</returns>
    internal static ParsePackedAttestationStatementDelegate CreateStatementParser(PackedAttestationStatement statement) =>
        (_, _) => statement;


    /// <summary>
    /// A <see cref="ParsePackedAttestationStatementDelegate"/> stub that always throws
    /// <see cref="Fido2FormatException"/> — simulates a malformed <c>attStmt</c> CBOR payload so the caller's
    /// <c>catch</c>-and-map-to-<c>MalformedStatement</c> behavior can be exercised without a real codec.
    /// </summary>
    /// <param name="message">The exception message.</param>
    /// <returns>A delegate that always throws.</returns>
    internal static ParsePackedAttestationStatementDelegate CreateThrowingParser(string message) =>
        (_, _) => throw new Fido2FormatException(message);


    /// <summary>
    /// Encodes a valid <c>attestationObject</c> CBOR map (<c>fmt</c>/<c>attStmt</c>/<c>authData</c>)
    /// in the CTAP2 canonical CBOR encoding form, as a real authenticator would.
    /// </summary>
    /// <param name="format">The <c>fmt</c> value.</param>
    /// <param name="attStmtCbor">The already-encoded <c>attStmt</c> CBOR bytes, embedded verbatim.</param>
    /// <param name="authData">The raw <c>authData</c> bytes, embedded as a CBOR byte string.</param>
    /// <returns>The encoded <c>attestationObject</c> bytes.</returns>
    internal static byte[] EncodeAttestationObject(string format, byte[] attStmtCbor, byte[] authData)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteTextString("fmt");
        writer.WriteTextString(format);
        writer.WriteTextString("attStmt");
        writer.WriteEncodedValue(attStmtCbor);
        writer.WriteTextString("authData");
        writer.WriteByteString(authData);
        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>
    /// Encodes a valid <c>packed</c> <c>attStmt</c> CBOR map (<c>alg</c>/<c>sig</c>, optionally
    /// <c>x5c</c>) in the CTAP2 canonical CBOR encoding form.
    /// </summary>
    /// <param name="alg">The COSE algorithm identifier.</param>
    /// <param name="sig">The attestation signature bytes.</param>
    /// <param name="x5c">The certificate chain's DER bytes, leaf first, or <see langword="null"/> for self attestation.</param>
    /// <returns>The encoded <c>attStmt</c> bytes.</returns>
    internal static byte[] EncodePackedAttStmt(int alg, byte[] sig, IReadOnlyList<byte[]>? x5c)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(x5c is null ? 2 : 3);
        writer.WriteTextString("alg");
        writer.WriteInt32(alg);
        writer.WriteTextString("sig");
        writer.WriteByteString(sig);
        if(x5c is not null)
        {
            writer.WriteTextString("x5c");
            writer.WriteStartArray(x5c.Count);
            foreach(byte[] certificate in x5c)
            {
                writer.WriteByteString(certificate);
            }

            writer.WriteEndArray();
        }

        writer.WriteEndMap();

        return writer.Encode();
    }
}
