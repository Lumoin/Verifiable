using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

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
    /// Creates a self-signed Root CA. The returned node's certificate
    /// carries <c>BasicConstraints CA=true, pathLenConstraint=1</c> by
    /// default, so it can sign one level of intermediate beneath it.
    /// </summary>
    public static X509ChainTestRingNode CreateRootCa(
        TimeProvider timeProvider,
        string subjectCn = "Verifiable Test Root CA",
        int pathLengthConstraint = 1)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);

        DateTimeOffset now = timeProvider.GetUtcNow();
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
            notBefore: now.AddDays(-1).UtcDateTime,
            notAfter: now.AddYears(10).UtcDateTime);

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
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "leafCert with private key transferred to caller-owned X509ChainTestRingNode.")]
    public static X509ChainTestRingNode CreateIntermediate(
        X509ChainTestRingNode issuer,
        TimeProvider timeProvider,
        string subjectCn = "Verifiable Test Intermediate CA",
        int pathLengthConstraint = 0)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(timeProvider);

        if(issuer.Role == X509ChainNodeRole.Leaf)
        {
            throw new InvalidOperationException(
                "Cannot issue an Intermediate from a Leaf; issuer must be a Root or Intermediate.");
        }

        DateTimeOffset now = timeProvider.GetUtcNow();
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

            byte[] serial = RandomNumberGenerator.GetBytes(8);

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
                notBefore: now.AddDays(-1).UtcDateTime,
                notAfter: now.AddYears(5).UtcDateTime,
                serialNumber: serial);

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
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "leafCert with private key transferred to caller-owned X509ChainTestRingNode.")]
    public static X509ChainTestRingNode CreateLeaf(
        X509ChainTestRingNode issuer,
        string dnsName,
        TimeProvider timeProvider)
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

            byte[] serial = RandomNumberGenerator.GetBytes(8);

            using X509Certificate2 issuerWithKey =
                issuer.Certificate.HasPrivateKey
                    ? issuer.Certificate
                    : issuer.Certificate.CopyWithPrivateKey(issuer.SigningKey);

            using X509Certificate2 publicOnly = request.Create(
                issuerWithKey,
                notBefore: now.AddDays(-1).UtcDateTime,
                notAfter: now.AddYears(1).UtcDateTime,
                serialNumber: serial);

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
