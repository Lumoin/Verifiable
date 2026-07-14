using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Shared test-vector builders for the FIDO Metadata Service BLOB verification tests: mints an
/// independent, self-contained MDS root/signer PKI and hand-assembles compact-JWS BLOB bytes from
/// JSON fragments, so every vector is minted fresh at test time with an independent oracle (raw
/// <see cref="ECDsa"/>/<see cref="RSA"/>, never the library's own signing seam), per
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob">FIDO
/// Metadata Service v3.1, section 3.1.7: Metadata BLOB</see>.
/// </summary>
internal static class MetadataBlobTestVectors
{
    /// <summary>Gets the fixed <c>notBefore</c> instant every minted certificate in this file carries.</summary>
    private static DateTimeOffset DefaultNotBefore { get; } = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>Gets the fixed <c>notAfter</c> instant every minted certificate in this file carries.</summary>
    private static DateTimeOffset DefaultNotAfter { get; } = new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);


    /// <summary>
    /// Mints a self-signed MDS root CA certificate (P-256), mirroring
    /// <see cref="Fido2AttestationTestVectors.CreateSelfSignedCa"/>'s shape under a name distinct
    /// from the packed-attestation fixtures.
    /// </summary>
    /// <param name="subjectName">The RFC 4514 subject distinguished name string.</param>
    /// <param name="key">The root's own P-256 key pair.</param>
    /// <returns>The self-signed root certificate, private key attached.</returns>
    internal static X509Certificate2 CreateMdsRootCa(string subjectName, ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);

        //Test-side certificate factory (owner carve-out): CertificateRequest mints the root CA
        //certificate directly, there being no library seam for issuing X.509 certificates.
        var request = new CertificateRequest(subjectName, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        return request.CreateSelfSigned(DefaultNotBefore, DefaultNotAfter);
    }


    /// <summary>
    /// Mints an MDS BLOB-signing leaf certificate (P-256), issued by <paramref name="issuer"/>, with
    /// an Authority Key Identifier referencing the issuer and a <c>digitalSignature</c> Key Usage —
    /// the ambiguous-issuer-safe minting convention every certificate in this suite follows.
    /// </summary>
    /// <param name="issuer">The issuing MDS root CA certificate (private key attached).</param>
    /// <param name="signingKey">The signer's own P-256 key pair.</param>
    /// <param name="subjectName">The RFC 4514 subject distinguished name string.</param>
    /// <param name="notBefore">
    /// The certificate's <c>notBefore</c> instant. Defaults to <see cref="DefaultNotBefore"/>; a
    /// caller issuing through an intermediate CA whose own validity window is narrower (for example
    /// <see cref="Fido2AttestationTestVectors.CreateIntermediateCaCertificate"/>'s) supplies a value
    /// that fits within it.
    /// </param>
    /// <param name="notAfter">The certificate's <c>notAfter</c> instant. Defaults to <see cref="DefaultNotAfter"/>; see <paramref name="notBefore"/>.</param>
    /// <returns>The signing leaf certificate, private key attached.</returns>
    internal static X509Certificate2 CreateMdsSigningCertificate(
        X509Certificate2 issuer, ECDsa signingKey, string subjectName = "CN=Test MDS BLOB Signer", DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(signingKey);

        //Test-side certificate factory (owner carve-out): CertificateRequest mints the signing
        //leaf certificate directly, there being no library seam for issuing X.509 certificates.
        var request = new CertificateRequest(subjectName, signingKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(Fido2AttestationTestVectors.CreateLeafAuthorityKeyIdentifierExtension(issuer));

        byte[] serialNumber = RandomNumberGenerator.GetBytes(16);

        return request.Create(issuer, notBefore ?? DefaultNotBefore, notAfter ?? DefaultNotAfter, serialNumber).CopyWithPrivateKey(signingKey);
    }


    /// <summary>
    /// Mints an RSA-keyed MDS BLOB-signing leaf certificate, issued by the EC <paramref name="issuer"/> —
    /// the RS256 algorithm-matrix fixture, mirroring
    /// <see cref="Fido2AttestationTestVectors.CreateLeafAttestationCertificateWithRsaKey"/>'s
    /// cross-algorithm issuance shape.
    /// </summary>
    /// <param name="issuer">The issuing MDS root CA certificate (private key attached, EC).</param>
    /// <param name="signingKey">The signer's own RSA key pair.</param>
    /// <param name="subjectName">The RFC 4514 subject distinguished name string.</param>
    /// <returns>The signing leaf certificate, private key attached.</returns>
    internal static X509Certificate2 CreateMdsSigningCertificateRsa(X509Certificate2 issuer, RSA signingKey, string subjectName = "CN=Test MDS BLOB Signer RSA")
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(signingKey);

        //Test-side certificate factory (owner carve-out): CertificateRequest mints the RSA
        //signing leaf certificate directly, there being no library seam for issuing X.509 certificates.
        var request = new CertificateRequest(subjectName, signingKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(Fido2AttestationTestVectors.CreateLeafAuthorityKeyIdentifierExtension(issuer));

        //Test-side certificate factory (owner carve-out): CertificateRequest.Create(X509Certificate2, ...)'s
        //convenience overload requires the issuer's key algorithm to match the request's own; an RSA leaf
        //signed by the EC test root needs this explicit X509SignatureGenerator overload instead.
        using ECDsa issuerKey = issuer.GetECDsaPrivateKey()
            ?? throw new ArgumentException("Issuer certificate must carry an ECDsa private key.", nameof(issuer));
        X509SignatureGenerator issuerSignatureGenerator = X509SignatureGenerator.CreateForECDsa(issuerKey);
        byte[] serialNumber = RandomNumberGenerator.GetBytes(16);

        return request.Create(issuer.SubjectName, issuerSignatureGenerator, DefaultNotBefore, DefaultNotAfter, serialNumber).CopyWithPrivateKey(signingKey);
    }


    /// <summary>Copies a DER-encoded certificate into a pooled <see cref="PkiCertificateMemory"/> carrier.</summary>
    /// <param name="derBytes">The DER-encoded certificate bytes.</param>
    /// <returns>A pooled certificate carrier; the caller owns and disposes it.</returns>
    internal static PkiCertificateMemory ToPkiCertificateMemory(byte[] derBytes) =>
        Fido2AttestationTestVectors.ToPkiCertificateMemory(derBytes);


    /// <summary>
    /// Builds the JWT Header JSON: <c>alg</c>/<c>typ</c>/<c>x5c</c>, optionally with an <c>x5u</c>
    /// member (the unsupported-branch negative fixture).
    /// </summary>
    /// <param name="alg">The <c>alg</c> value.</param>
    /// <param name="x5cCertificates">The certificate chain's DER bytes, leaf first.</param>
    /// <param name="includeX5u">Whether to add an <c>x5u</c> member — the out-of-scope rejection fixture.</param>
    /// <returns>The header JSON text.</returns>
    internal static string BuildHeaderJson(string alg, IReadOnlyList<byte[]> x5cCertificates, bool includeX5u = false)
    {
        ArgumentNullException.ThrowIfNull(x5cCertificates);

        string x5cJson = string.Join(",", x5cCertificates.Select(certificate => $"\"{Convert.ToBase64String(certificate)}\""));
        string x5uPart = includeX5u ? ",\"x5u\":\"https://mds.example.invalid/signer-chain.pem\"" : string.Empty;

        return $$"""{"alg":"{{alg}}","typ":"JWT","x5c":[{{x5cJson}}]{{x5uPart}}}""";
    }


    /// <summary>
    /// Builds a <c>metadataStatement</c> JSON object carrying an optional
    /// <c>attestationRootCertificates</c> array.
    /// </summary>
    /// <param name="attestationRootCertificates">The attestation root certificates' DER bytes, or <see langword="null"/> to omit the member.</param>
    /// <param name="description">A filler <c>description</c> value, exercising the "unknown member skipped" path.</param>
    /// <returns>The metadata statement JSON text.</returns>
    internal static string BuildMetadataStatementJson(IReadOnlyList<byte[]>? attestationRootCertificates = null, string description = "Test Authenticator")
    {
        string rootsPart = attestationRootCertificates is null
            ? string.Empty
            : $",\"attestationRootCertificates\":[{string.Join(",", attestationRootCertificates.Select(certificate => $"\"{Convert.ToBase64String(certificate)}\""))}]";

        return $$"""{"description":"{{description}}"{{rootsPart}}}""";
    }


    /// <summary>Builds a <c>StatusReport</c> JSON object.</summary>
    /// <param name="status">The <c>status</c> value.</param>
    /// <param name="effectiveDate">The optional <c>effectiveDate</c> ISO-8601 date string.</param>
    /// <param name="certificate">The optional base64 (standard) DER <c>certificate</c> string.</param>
    /// <returns>The status report JSON text.</returns>
    internal static string BuildStatusReportJson(string status, string? effectiveDate = null, string? certificate = null)
    {
        string effectiveDatePart = effectiveDate is null ? string.Empty : $",\"effectiveDate\":\"{effectiveDate}\"";
        string certificatePart = certificate is null ? string.Empty : $",\"certificate\":\"{certificate}\"";

        return $$"""{"status":"{{status}}"{{effectiveDatePart}}{{certificatePart}}}""";
    }


    /// <summary>Builds a <c>MetadataBLOBPayloadEntry</c> JSON object.</summary>
    /// <param name="aaguid">The optional <c>aaguid</c> — the FIDO2 lookup key.</param>
    /// <param name="aaid">The optional <c>aaid</c> — the UAF lookup key.</param>
    /// <param name="attestationCertificateKeyIdentifiers">The optional <c>attestationCertificateKeyIdentifiers</c> — the U2F lookup key.</param>
    /// <param name="metadataStatementJson">The <c>metadataStatement</c> JSON text. Defaults to a minimal statement with no attestation roots.</param>
    /// <param name="statusReportJsons">The <c>statusReports</c> JSON texts. Defaults to a single <c>FIDO_CERTIFIED</c> report.</param>
    /// <param name="timeOfLastStatusChange">The optional <c>timeOfLastStatusChange</c> ISO-8601 date string.</param>
    /// <returns>The entry JSON text.</returns>
    internal static string BuildEntryJson(
        Guid? aaguid = null,
        string? aaid = null,
        IReadOnlyList<string>? attestationCertificateKeyIdentifiers = null,
        string? metadataStatementJson = null,
        IReadOnlyList<string>? statusReportJsons = null,
        string? timeOfLastStatusChange = "2020-01-01")
    {
        var members = new List<string>();
        if(aaguid is { } aaguidValue)
        {
            members.Add($"\"aaguid\":\"{aaguidValue:D}\"");
        }

        if(aaid is not null)
        {
            members.Add($"\"aaid\":\"{aaid}\"");
        }

        if(attestationCertificateKeyIdentifiers is not null)
        {
            string ackiJson = string.Join(",", attestationCertificateKeyIdentifiers.Select(identifier => $"\"{identifier}\""));
            members.Add($"\"attestationCertificateKeyIdentifiers\":[{ackiJson}]");
        }

        members.Add($"\"metadataStatement\":{metadataStatementJson ?? BuildMetadataStatementJson()}");

        IReadOnlyList<string> reports = statusReportJsons ?? [BuildStatusReportJson(WellKnownAuthenticatorStatuses.FidoCertified, "2020-01-01")];
        members.Add($"\"statusReports\":[{string.Join(",", reports)}]");

        if(timeOfLastStatusChange is not null)
        {
            members.Add($"\"timeOfLastStatusChange\":\"{timeOfLastStatusChange}\"");
        }

        return "{" + string.Join(",", members) + "}";
    }


    /// <summary>Builds the <c>MetadataBLOBPayload</c> JSON object.</summary>
    /// <param name="no">The <c>no</c> serial number.</param>
    /// <param name="nextUpdate">The <c>nextUpdate</c> ISO-8601 date string.</param>
    /// <param name="entryJsons">The <c>entries</c> JSON texts.</param>
    /// <param name="legalHeader">The optional <c>legalHeader</c> value.</param>
    /// <returns>The payload JSON text.</returns>
    internal static string BuildPayloadJson(long no, string nextUpdate, IReadOnlyList<string> entryJsons, string? legalHeader = "Test legal header")
    {
        ArgumentNullException.ThrowIfNull(entryJsons);

        string legalHeaderPart = legalHeader is null ? string.Empty : $"\"legalHeader\":\"{legalHeader}\",";

        return $$"""{{{legalHeaderPart}}"no":{{no}},"nextUpdate":"{{nextUpdate}}","entries":[{{string.Join(",", entryJsons)}}]}""";
    }


    /// <summary>
    /// Assembles a compact-JWS Metadata BLOB from already-built header/payload JSON, signing the
    /// <c>tbsPayload</c> with <paramref name="sign"/> — an independent oracle, never the library's
    /// own signing seam.
    /// </summary>
    /// <param name="headerJson">The JWT Header JSON text.</param>
    /// <param name="payloadJson">The Metadata BLOB Payload JSON text.</param>
    /// <param name="sign">Signs the UTF-8 <c>tbsPayload</c> bytes and returns the raw (not DER-wrapped) signature bytes.</param>
    /// <returns>The compact-JWS BLOB bytes.</returns>
    internal static byte[] BuildBlobBytes(string headerJson, string payloadJson, Func<byte[], byte[]> sign)
    {
        ArgumentNullException.ThrowIfNull(sign);

        string headerSegment = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(headerJson));
        string payloadSegment = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(payloadJson));
        string signingInput = $"{headerSegment}.{payloadSegment}";
        byte[] signature = sign(Encoding.UTF8.GetBytes(signingInput));
        string signatureSegment = Base64Url.EncodeToString(signature);

        return Encoding.UTF8.GetBytes($"{signingInput}.{signatureSegment}");
    }


    /// <summary>
    /// Signs with a raw <see cref="ECDsa"/> key, producing the fixed-width IEEE P1363 encoding RFC
    /// 7518 §3.4 requires for a JWS ES256 signature — <see cref="ECDsa.SignData(byte[], HashAlgorithmName)"/>'s
    /// default <see cref="DSASignatureFormat.IeeeP1363"/>, deliberately NOT the ASN.1 DER encoding
    /// the WebAuthn attestation/assertion signature wire format uses.
    /// </summary>
    /// <param name="key">The P-256 private key to sign with.</param>
    /// <param name="data">The bytes to sign.</param>
    /// <returns>The raw P1363 ECDSA/SHA-256 signature bytes.</returns>
    internal static byte[] SignEs256(ECDsa key, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(data);

        return key.SignData(data, HashAlgorithmName.SHA256);
    }


    /// <summary>
    /// Signs with a raw <see cref="RSA"/> key using PKCS#1 v1.5/SHA-256 — the RS256 JWS signing
    /// algorithm, an independent oracle.
    /// </summary>
    /// <param name="key">The RSA private key to sign with.</param>
    /// <param name="data">The bytes to sign.</param>
    /// <returns>The raw RSASSA-PKCS1-v1_5/SHA-256 signature bytes.</returns>
    internal static byte[] SignRs256(RSA key, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(data);

        return key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }


    /// <summary>
    /// Flips the second-to-last byte of the BLOB's signature segment — a MITM'd-in-transit tamper —
    /// while leaving the header and payload segments byte-identical, so the BLOB still parses
    /// successfully (proving the ensuing rejection comes from signature verification, not from a
    /// parse failure) but no longer verifies. Tampering the signature segment specifically, rather
    /// than the payload segment, avoids the base64url-vs-JSON-structural-byte coupling a
    /// payload-segment tamper would risk (a single flipped base64url character can corrupt JSON
    /// syntax, turning this into a <see cref="Fido2MetadataErrors.MalformedBlob"/> case instead of
    /// the intended <see cref="Fido2MetadataErrors.InvalidBlobSignature"/> one) — the signature bytes
    /// carry no structure of their own, so any single-character change there safely stays within the
    /// intended failure axis.
    /// </summary>
    /// <remarks>
    /// Deliberately the SECOND-to-last character, not the last: for a fixed-width P-256 P1363
    /// signature (64 bytes, 64 mod 3 = 1 leftover byte), base64url's final two-character group
    /// canonically constrains its terminal character to one of only 16 values (index a multiple of
    /// 4) — the low bits of a partial final group must be zero. A naive "flip the very last
    /// character" tamper intermittently lands on a non-canonical replacement (rejected as
    /// <see cref="Fido2MetadataErrors.MalformedBlob"/> rather than the intended
    /// <see cref="Fido2MetadataErrors.InvalidBlobSignature"/>) whenever the random signature's last
    /// byte happens to already produce the canonical terminal character this method would flip to —
    /// a genuine, reproducible defect this rewrite fixes, not flakiness to shrug off. The
    /// second-to-last character carries no such constraint (it is never the terminal character of a
    /// base64 group for this fixed signature length), so any single-character change there is always
    /// syntactically valid base64url.
    /// </remarks>
    /// <param name="blobBytes">The well-formed compact-JWS BLOB bytes to tamper.</param>
    /// <returns>The tampered BLOB bytes.</returns>
    internal static byte[] TamperSignatureSegment(byte[] blobBytes)
    {
        ArgumentNullException.ThrowIfNull(blobBytes);

        byte[] tampered = (byte[])blobBytes.Clone();
        int tamperIndex = tampered.Length - 2;
        tampered[tamperIndex] = tampered[tamperIndex] == (byte)'A' ? (byte)'B' : (byte)'A';

        return tampered;
    }


    /// <summary>
    /// A minted MDS root CA plus BLOB-signing leaf certificate chain (P-256), the fixture every
    /// Metadata BLOB verification test signs its vectors under. Owns and disposes every certificate.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the root and signing key/certificate transfers to the returned MdsPkiFixture, which the caller disposes.")]
    internal static MdsPkiFixture CreateMdsPkiFixture()
    {
        //Cert-factory carve-out: this key is signing input to CreateMdsRootCa's CertificateRequest, which requires a framework ECDsa instance.
        ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 rootCertificate = CreateMdsRootCa("CN=Test MDS Root", rootKey);
        //Cert-factory carve-out: this key is signing input to CreateMdsSigningCertificate's CertificateRequest, and it is
        //also the independent oracle exposed via MdsPkiFixture.SigningKey, which callers hand to SignEs256 to produce
        //the raw JWS signature the library's own verifier is proven against.
        ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 signingCertificate = CreateMdsSigningCertificate(rootCertificate, signingKey);

        return new MdsPkiFixture(rootKey, rootCertificate, signingKey, signingCertificate);
    }
}


/// <summary>
/// A minted MDS root CA plus BLOB-signing leaf certificate (P-256), owning every certificate and
/// key it carries.
/// </summary>
internal sealed class MdsPkiFixture: IDisposable
{
    /// <summary>Initializes a new <see cref="MdsPkiFixture"/>, taking ownership of every certificate and key.</summary>
    public MdsPkiFixture(ECDsa rootKey, X509Certificate2 rootCertificate, ECDsa signingKey, X509Certificate2 signingCertificate)
    {
        RootKey = rootKey;
        RootCertificate = rootCertificate;
        SigningKey = signingKey;
        SigningCertificate = signingCertificate;
    }


    /// <summary>Gets the MDS root CA's private key.</summary>
    public ECDsa RootKey { get; }

    /// <summary>Gets the MDS root CA certificate (private key attached), the trust anchor.</summary>
    public X509Certificate2 RootCertificate { get; }

    /// <summary>Gets the BLOB signing leaf's private key.</summary>
    public ECDsa SigningKey { get; }

    /// <summary>Gets the BLOB signing leaf certificate (private key attached), issued by <see cref="RootCertificate"/>.</summary>
    public X509Certificate2 SigningCertificate { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        RootKey.Dispose();
        RootCertificate.Dispose();
        SigningKey.Dispose();
        SigningCertificate.Dispose();
    }
}
