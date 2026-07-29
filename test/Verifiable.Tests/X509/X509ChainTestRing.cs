using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography;

namespace Verifiable.Tests.X509;

/// <summary>
/// Generates real .NET X.509 certificate chains for tests — self-signed
/// roots, signed intermediates, end-entity leaves. Parallel to
/// <see cref="Tests.Federation.FederationTestRing"/> on the Federation
/// side: composable per-node builders plus a couple of convenience
/// methods for the common chain shapes.
/// </summary>
/// <remarks>
/// <para>
/// Composable building blocks let tests construct any chain topology:
/// </para>
/// <code>
/// using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider);
/// using X509ChainTestRingNode intermediate = X509ChainTestRing.CreateIntermediate(root, timeProvider);
/// using X509ChainTestRingNode leaf = X509ChainTestRing.CreateLeaf(intermediate, "verifier.example.com", timeProvider);
/// </code>
/// <para>
/// Or use a convenience method for the canonical three-level chain:
/// </para>
/// <code>
/// using X509ChainTestRingChain three = X509ChainTestRing.BuildThreeLevelChain(
///     dnsName: "verifier.example.com",
///     timeProvider: timeProvider);
/// </code>
/// <para>
/// Test-project resident per the project's "promote when stable" rhythm.
/// Eventual EU regulatory work (eIDAS QTSP chains, federation entity
/// attestations) may want a library-grade equivalent; the API surface
/// here is the staging ground.
/// </para>
/// </remarks>
internal static class X509ChainTestRing
{
    private static readonly HashAlgorithmName SignatureHashAlg = HashAlgorithmName.SHA256;

    /// <summary>
    /// The number of CSPRNG bytes drawn for a certificate serial number.
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2">RFC 5280 §4.1.2.2</see> caps the
    /// serial at 20 octets; issuance profiles require at least 64 bits of CSPRNG output in it, because a
    /// predictable serial hands an attacker control of to-be-signed bytes — the lever chosen-prefix
    /// collision forgeries against the signature hash need.
    /// </summary>
    internal const int SerialNumberByteLength = 8;


    /// <summary>
    /// Draws a fresh certificate serial number through the registered entropy seam, so the draw carries
    /// CBOM provenance and entropy-tracking events instead of an untracked direct framework CSPRNG call.
    /// </summary>
    /// <param name="byteLength">
    /// The number of CSPRNG bytes to draw. Defaults to <see cref="SerialNumberByteLength"/>; callers may
    /// draw wider serials, up to the 20-octet cap
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2">RFC 5280 §4.1.2.2</see> places
    /// on a certificate serial number.
    /// </param>
    /// <returns>The serial number; the caller disposes it after certificate creation.</returns>
    internal static Salt CreateSerialNumber(int byteLength = SerialNumberByteLength)
    {
        return CryptographicKeyEvents.GenerateSalt(byteLength, CryptoTags.X509CertificateSerialNumber, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// The <c>id-kp-timeStamping</c> extended key usage purpose. A Time-Stamping Authority's certificate
    /// <see href="https://www.rfc-editor.org/rfc/rfc3161#section-2.3">RFC 3161 §2.3</see> requires to carry
    /// exactly this purpose, in a critical Extended Key Usage extension.
    /// </summary>
    internal const string TimeStampingKeyPurposeOid = "1.3.6.1.5.5.7.3.8";

    /// <summary>
    /// The <c>ecdsa-with-SHA256</c> signature algorithm object identifier
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5758#section-3.2">RFC 5758 §3.2</see>) every certificate,
    /// revocation list and time-stamp token this ring mints is signed with. Named here because a fixture that
    /// states cryptographic constraints over minted material has to name the algorithm the material actually
    /// uses.
    /// </summary>
    internal static string EcdsaWithSha256SignatureOid { get; } = "1.2.840.10045.4.3.2";

    /// <summary>
    /// The same algorithm under the mechanism name the independent BouncyCastle signature factory takes, for the
    /// revocation lists and time-stamp tokens minted through that oracle.
    /// </summary>
    internal static string EcdsaWithSha256SignatureName { get; } = "SHA256withECDSA";

    /// <summary>
    /// The key size in bits of every signing key this ring mints (the NIST P-256 curve's field size), for a
    /// fixture stating a minimum key size in its cryptographic constraints.
    /// </summary>
    internal const int SigningKeySizeBits = 256;


    /// <summary>
    /// Creates a self-signed Root CA. The returned node's certificate
    /// carries <c>BasicConstraints CA=true, pathLenConstraint=1</c> by
    /// default, so it can sign one level of intermediate beneath it.
    /// </summary>
    /// <param name="timeProvider">The clock the default validity window is derived from; never read when both instants are supplied.</param>
    /// <param name="subjectCn">The common name of the certificate's subject.</param>
    /// <param name="pathLengthConstraint">The Basic Constraints path length budget.</param>
    /// <param name="notBefore">An explicit validity start, for a fixture that places issuance at a named instant of a timeline; defaults to one day before the clock's now.</param>
    /// <param name="notAfter">An explicit validity end, for a fixture that places expiry at a named instant of a timeline; defaults to ten years after the clock's now.</param>
    /// <returns>The node, which the caller disposes.</returns>
    public static X509ChainTestRingNode CreateRootCa(
        TimeProvider timeProvider,
        string subjectCn = "Verifiable Test Root CA",
        int pathLengthConstraint = 1,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);

        DateTimeOffset now = timeProvider.GetUtcNow();
        DateTimeOffset validFrom = notBefore ?? now.AddDays(-1);
        DateTimeOffset validTo = notAfter ?? now.AddYears(10);

        //X.509 cert-factory carve-out: CertificateRequest.CreateSelfSigned needs a live framework signing key.
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        CertificateRequest request = new(
            $"CN={subjectCn}, O=Verifiable Test Infrastructure",
            key,
            SignatureHashAlg);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: true,
                hasPathLengthConstraint: true,
                pathLengthConstraint: pathLengthConstraint,
                critical: true));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                critical: true));

        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(
                request.PublicKey,
                X509SubjectKeyIdentifierHashAlgorithm.Sha256,
                critical: false));

        using X509Certificate2 selfSignedWithKey = request.CreateSelfSigned(
            notBefore: validFrom.UtcDateTime,
            notAfter: validTo.UtcDateTime);

        //Strip the auto-attached private key so the stored cert is public-only;
        //the SigningKey property holds the ECDsa separately. Uniform shape across
        //all roles makes CopyWithPrivateKey-when-issuing safe everywhere.
        X509Certificate2 publicOnly = X509CertificateLoader.LoadCertificate(selfSignedWithKey.RawData);

        return new X509ChainTestRingNode(X509ChainNodeRole.Root, publicOnly, key);
    }


    /// <summary>
    /// Creates an Intermediate CA signed by <paramref name="issuer"/>.
    /// Issuer must be a Root or another Intermediate (CA=true) with
    /// remaining path-length budget.
    /// </summary>
    /// <param name="issuer">The issuing node.</param>
    /// <param name="timeProvider">The clock the default validity window is derived from; never read when both instants are supplied.</param>
    /// <param name="subjectCn">The common name of the certificate's subject.</param>
    /// <param name="pathLengthConstraint">The Basic Constraints path length budget.</param>
    /// <param name="notBefore">An explicit validity start, for a fixture that places issuance at a named instant of a timeline; defaults to one day before the clock's now.</param>
    /// <param name="notAfter">An explicit validity end, for a fixture that places expiry at a named instant of a timeline; defaults to five years after the clock's now.</param>
    /// <returns>The node, which the caller disposes.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "leafCert with private key transferred to caller-owned X509ChainTestRingNode.")]
    public static X509ChainTestRingNode CreateIntermediate(
        X509ChainTestRingNode issuer,
        TimeProvider timeProvider,
        string subjectCn = "Verifiable Test Intermediate CA",
        int pathLengthConstraint = 0,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(timeProvider);

        if(issuer.Role == X509ChainNodeRole.Leaf)
        {
            throw new InvalidOperationException(
                "Cannot issue an Intermediate from a Leaf; issuer must be a Root or Intermediate.");
        }

        DateTimeOffset now = timeProvider.GetUtcNow();
        DateTimeOffset validFrom = notBefore ?? now.AddDays(-1);
        DateTimeOffset validTo = notAfter ?? now.AddYears(5);

        //X.509 cert-factory carve-out: CertificateRequest.Create needs a live framework signing key.
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        try
        {
            CertificateRequest request = new(
                $"CN={subjectCn}, O=Verifiable Test Infrastructure",
                key,
                SignatureHashAlg);

            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(
                    certificateAuthority: true,
                    hasPathLengthConstraint: true,
                    pathLengthConstraint: pathLengthConstraint,
                    critical: true));

            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                    critical: true));

            X509SubjectKeyIdentifierExtension subjectKeyId =
                new(request.PublicKey, X509SubjectKeyIdentifierHashAlgorithm.Sha256, critical: false);
            request.CertificateExtensions.Add(subjectKeyId);

            X509SubjectKeyIdentifierExtension? issuerSubjectKeyId =
                FindSubjectKeyIdentifier(issuer.Certificate);
            if(issuerSubjectKeyId is not null)
            {
                request.CertificateExtensions.Add(
                    X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(issuerSubjectKeyId));
            }

            using Salt serial = CreateSerialNumber();

            //CertificateRequest.Create(issuer, ...) requires the issuer cert
            //to carry its private key. CreateSelfSigned (used for the root)
            //attaches it; Create(issuer,...) (used for non-root nodes) does
            //not, so we materialise a working copy with the key attached for
            //the duration of the call. The copy is disposed at scope exit;
            //the node's underlying certificate is unaffected.
            using X509Certificate2 issuerWithKey =
                issuer.Certificate.CopyWithPrivateKey(issuer.SigningKey);

            using X509Certificate2 publicOnly = request.Create(
                issuerWithKey,
                notBefore: validFrom.UtcDateTime,
                notAfter: validTo.UtcDateTime,
                serialNumber: serial.AsReadOnlySpan());

            //Stored cert is public-only; SigningKey holds the ECDsa.
            X509Certificate2 cert = X509CertificateLoader.LoadCertificate(publicOnly.RawData);

            return new X509ChainTestRingNode(X509ChainNodeRole.Intermediate, cert, key);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Creates an end-entity Leaf certificate signed by
    /// <paramref name="issuer"/>. The leaf carries the supplied DNS name
    /// as a Subject Alternative Name, suitable for OID4VP
    /// <c>x509_san_dns:</c> client_id matching.
    /// </summary>
    /// <param name="issuer">The issuing node.</param>
    /// <param name="dnsName">The DNS name carried as the subject common name and Subject Alternative Name.</param>
    /// <param name="timeProvider">The clock the default validity window is derived from; never read when both instants are supplied.</param>
    /// <param name="notBefore">An explicit validity start, for a fixture that places issuance at a named instant of a timeline; defaults to one day before the clock's now.</param>
    /// <param name="notAfter">An explicit validity end, for a fixture that places expiry at a named instant of a timeline; defaults to one year after the clock's now.</param>
    /// <returns>The node, which the caller disposes.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "leafCert with private key transferred to caller-owned X509ChainTestRingNode.")]
    public static X509ChainTestRingNode CreateLeaf(
        X509ChainTestRingNode issuer,
        string dnsName,
        TimeProvider timeProvider,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(dnsName);
        ArgumentNullException.ThrowIfNull(timeProvider);

        if(issuer.Role == X509ChainNodeRole.Leaf)
        {
            throw new InvalidOperationException(
                "Cannot issue a Leaf from another Leaf; issuer must be a Root or Intermediate.");
        }

        DateTimeOffset now = timeProvider.GetUtcNow();
        DateTimeOffset validFrom = notBefore ?? now.AddDays(-1);
        DateTimeOffset validTo = notAfter ?? now.AddYears(1);

        //X.509 cert-factory carve-out: CertificateRequest.Create needs a live framework signing key.
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        try
        {
            CertificateRequest request = new(
                $"CN={dnsName}, O=Verifiable Test Infrastructure",
                key,
                SignatureHashAlg);

            SubjectAlternativeNameBuilder sanBuilder = new();
            sanBuilder.AddDnsName(dnsName);
            request.CertificateExtensions.Add(sanBuilder.Build(critical: false));

            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(
                    certificateAuthority: false,
                    hasPathLengthConstraint: false,
                    pathLengthConstraint: 0,
                    critical: false));

            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature,
                    critical: true));

            X509SubjectKeyIdentifierExtension subjectKeyId =
                new(request.PublicKey, X509SubjectKeyIdentifierHashAlgorithm.Sha256, critical: false);
            request.CertificateExtensions.Add(subjectKeyId);

            X509SubjectKeyIdentifierExtension? issuerSubjectKeyId =
                FindSubjectKeyIdentifier(issuer.Certificate);
            if(issuerSubjectKeyId is not null)
            {
                request.CertificateExtensions.Add(
                    X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(issuerSubjectKeyId));
            }

            using Salt serial = CreateSerialNumber();

            using X509Certificate2 issuerWithKey =
                issuer.Certificate.HasPrivateKey
                    ? issuer.Certificate
                    : issuer.Certificate.CopyWithPrivateKey(issuer.SigningKey);

            using X509Certificate2 publicOnly = request.Create(
                issuerWithKey,
                notBefore: validFrom.UtcDateTime,
                notAfter: validTo.UtcDateTime,
                serialNumber: serial.AsReadOnlySpan());

            X509Certificate2 cert = X509CertificateLoader.LoadCertificate(publicOnly.RawData);

            return new X509ChainTestRingNode(X509ChainNodeRole.Leaf, cert, key);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Creates an end-entity certificate for a Time-Stamping Authority, signed by <paramref name="issuer"/>.
    /// The certificate carries the critical Extended Key Usage extension asserting <c>id-kp-timeStamping</c>
    /// and nothing else, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc3161#section-2.3">RFC 3161 §2.3</see> requires of the
    /// certificate a time-stamp token's signature is verified with, plus an Authority Key Identifier chained to
    /// the issuer's Subject Key Identifier so that chain building never faces an ambiguous same-subject issuer.
    /// </summary>
    /// <param name="issuer">The issuing node — a Root or an Intermediate.</param>
    /// <param name="timeProvider">The clock the default validity window is derived from; never read when both instants are supplied.</param>
    /// <param name="subjectCn">The common name of the authority; a Time-Stamping Authority is identified by its name rather than by a DNS Subject Alternative Name, so no such name is added.</param>
    /// <param name="notBefore">An explicit validity start, for a fixture that places issuance at a named instant of a timeline; defaults to one day before the clock's now.</param>
    /// <param name="notAfter">An explicit validity end, for a fixture whose timeline has the authority's certificate expire at a named instant; defaults to one year after the clock's now.</param>
    /// <returns>The node, which the caller disposes.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the issuer is itself an end-entity node.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The certificate's signing key transfers to the caller-owned X509ChainTestRingNode.")]
    public static X509ChainTestRingNode CreateTimeStampingAuthority(
        X509ChainTestRingNode issuer,
        TimeProvider timeProvider,
        string subjectCn = "Verifiable Test Time-Stamping Authority",
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectCn);

        if(issuer.Role == X509ChainNodeRole.Leaf)
        {
            throw new InvalidOperationException(
                "Cannot issue a Time-Stamping Authority certificate from a Leaf; issuer must be a Root or Intermediate.");
        }

        DateTimeOffset now = timeProvider.GetUtcNow();
        DateTimeOffset validFrom = notBefore ?? now.AddDays(-1);
        DateTimeOffset validTo = notAfter ?? now.AddYears(1);

        //X.509 cert-factory carve-out: CertificateRequest.Create needs a live framework signing key.
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        try
        {
            CertificateRequest request = new(
                $"CN={subjectCn}, O=Verifiable Test Infrastructure",
                key,
                SignatureHashAlg);

            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(
                    certificateAuthority: false,
                    hasPathLengthConstraint: false,
                    pathLengthConstraint: 0,
                    critical: true));

            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
                    critical: true));

            OidCollection timeStampingOnly = [new Oid(TimeStampingKeyPurposeOid)];
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(timeStampingOnly, critical: true));

            X509SubjectKeyIdentifierExtension subjectKeyId =
                new(request.PublicKey, X509SubjectKeyIdentifierHashAlgorithm.Sha256, critical: false);
            request.CertificateExtensions.Add(subjectKeyId);

            X509SubjectKeyIdentifierExtension? issuerSubjectKeyId =
                FindSubjectKeyIdentifier(issuer.Certificate);
            if(issuerSubjectKeyId is not null)
            {
                request.CertificateExtensions.Add(
                    X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(issuerSubjectKeyId));
            }

            using Salt serial = CreateSerialNumber();

            //The stored issuer certificate is public-only, so a working copy carrying the key is materialised
            //for the duration of the call and disposed at scope exit, exactly as CreateIntermediate does.
            using X509Certificate2 issuerWithKey = issuer.Certificate.CopyWithPrivateKey(issuer.SigningKey);

            using X509Certificate2 publicOnly = request.Create(
                issuerWithKey,
                notBefore: validFrom.UtcDateTime,
                notAfter: validTo.UtcDateTime,
                serialNumber: serial.AsReadOnlySpan());

            X509Certificate2 cert = X509CertificateLoader.LoadCertificate(publicOnly.RawData);

            return new X509ChainTestRingNode(X509ChainNodeRole.Leaf, cert, key);
        }
        catch
        {
            key.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Builds the canonical three-level chain: Root CA → Intermediate CA →
    /// Leaf. Convenience for tests that don't need topology variation.
    /// </summary>
    public static X509ChainTestRingChain BuildThreeLevelChain(string dnsName, TimeProvider timeProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dnsName);
        ArgumentNullException.ThrowIfNull(timeProvider);

        X509ChainTestRingNode root = CreateRootCa(timeProvider, pathLengthConstraint: 1);
        X509ChainTestRingNode intermediate;
        try
        {
            intermediate = CreateIntermediate(root, timeProvider);
        }
        catch
        {
            root.Dispose();
            throw;
        }

        X509ChainTestRingNode leaf;
        try
        {
            leaf = CreateLeaf(intermediate, dnsName, timeProvider);
        }
        catch
        {
            intermediate.Dispose();
            root.Dispose();
            throw;
        }

        return new X509ChainTestRingChain(root, intermediate, leaf);
    }


    /// <summary>
    /// Finds a certificate's own Subject Key Identifier extension, if present. Shared by the intermediate/leaf
    /// builders here and by test-only certificate minting elsewhere in this assembly that needs to chain an
    /// Authority Key Identifier to an issuer's Subject Key Identifier (for example an in-house TPM simulator's
    /// EK/AK certificate profile).
    /// </summary>
    /// <param name="cert">The certificate to search.</param>
    /// <returns>The Subject Key Identifier extension, or <see langword="null"/> when absent.</returns>
    internal static X509SubjectKeyIdentifierExtension? FindSubjectKeyIdentifier(X509Certificate2 cert)
    {
        foreach(X509Extension ext in cert.Extensions)
        {
            if(ext is X509SubjectKeyIdentifierExtension ski)
            {
                return ski;
            }
        }
        return null;
    }
}


/// <summary>
/// Output of <see cref="X509ChainTestRing.BuildThreeLevelChain"/>: the
/// three constituent nodes plus a convenience <c>X5cValues</c> property
/// returning the JOSE-shaped base64-DER chain (leaf first per RFC 7515 §4.1.6).
/// Disposing this disposes all three nodes.
/// </summary>
internal sealed class X509ChainTestRingChain: IDisposable
{
    public X509ChainTestRingNode Root { get; }

    public X509ChainTestRingNode Intermediate { get; }

    public X509ChainTestRingNode Leaf { get; }


    internal X509ChainTestRingChain(
        X509ChainTestRingNode root,
        X509ChainTestRingNode intermediate,
        X509ChainTestRingNode leaf)
    {
        Root = root;
        Intermediate = intermediate;
        Leaf = leaf;
    }


    /// <summary>
    /// The base64-encoded DER chain as it would appear in the JAR's
    /// <c>x5c</c> JOSE header — leaf first, then intermediate, then root.
    /// (The root is typically not included on the wire in production; for
    /// tests it's useful to have it so chain validators that need it can
    /// pick it up.)
    /// </summary>
    public IReadOnlyList<string> X5cValues =>
    [
        Convert.ToBase64String(Leaf.Certificate.RawData),
        Convert.ToBase64String(Intermediate.Certificate.RawData),
        Convert.ToBase64String(Root.Certificate.RawData),
    ];


    /// <summary>Returns just the root cert as a single-entry x5c — the trust anchor.</summary>
    public IReadOnlyList<string> RootX5c =>
    [
        Convert.ToBase64String(Root.Certificate.RawData),
    ];


    public void Dispose()
    {
        Leaf.Dispose();
        Intermediate.Dispose();
        Root.Dispose();
    }
}
