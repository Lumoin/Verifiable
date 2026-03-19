using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using BouncyCastleX509 = Org.BouncyCastle.X509.X509Certificate;

namespace Verifiable.BouncyCastle;

/// <summary>
/// BouncyCastle-backed implementations of the X.509 certificate chain validation
/// delegates defined in <c>Verifiable.Cryptography.Pki</c>.
/// </summary>
/// <remarks>
/// <para>
/// Uses <c>Org.BouncyCastle.X509.X509CertificateParser</c> for DER parsing,
/// <c>Org.BouncyCastle.Pkix.PkixCertPathBuilder</c> for PKIX chain validation per
/// RFC 5280, and <c>Org.BouncyCastle.Asn1.X509.GeneralNames</c> for Subject
/// Alternative Name extension parsing. No OS library dependency — fully
/// WASM-compatible.
/// </para>
/// <para>
/// Typical wiring alongside <see cref="MicrosoftX509Functions"/> for cross-checking:
/// </para>
/// <code>
/// ResolveKeyFromX509SanDnsDelegate bouncyCastleResolver =
///     (x5c, expectedDns, trustAnchors, time, pool, ct) =>
///         X509SanDnsKeyResolver.ResolveAsync(
///             x5c, expectedDns, trustAnchors, time,
///             BouncyCastleX509Functions.ParseX5c,
///             BouncyCastleX509Functions.ValidateChain,
///             BouncyCastleX509Functions.VerifyDnsSan,
///             pool, ct);
/// </code>
/// </remarks>
public static class BouncyCastleX509Functions
{
    private static readonly X509CertificateParser CertificateParser = new();


    /// <summary>
    /// Implements <see cref="ParseX5cDelegate"/>. Parses base64-encoded DER certificate
    /// strings into <see cref="PkiCertificateMemory"/> instances using BouncyCastle.
    /// The DER structure is validated immediately; malformed input throws before any
    /// pooled memory is allocated.
    /// </summary>
    public static IReadOnlyList<PkiCertificateMemory> ParseX5c(
        IReadOnlyList<string> x5cValues,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(x5cValues);
        ArgumentNullException.ThrowIfNull(pool);

        if(x5cValues.Count == 0)
        {
            throw new FormatException(
                "The x5c JOSE header parameter must contain at least one certificate.");
        }

        var result = new List<PkiCertificateMemory>(x5cValues.Count);
        try
        {
            foreach(string base64Der in x5cValues)
            {
                if(string.IsNullOrWhiteSpace(base64Der))
                {
                    throw new FormatException(
                        "The x5c JOSE header contains an empty certificate entry.");
                }

                byte[] derBytes = Convert.FromBase64String(base64Der);

                //Parse via BouncyCastle to validate DER structure before allocating.
                _ = CertificateParser.ReadCertificate(derBytes);

                IMemoryOwner<byte> owner = pool.Rent(derBytes.Length);
                derBytes.CopyTo(owner.Memory);
                result.Add(new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate));
            }

            return result;
        }
        catch
        {
            foreach(PkiCertificateMemory cert in result)
            {
                cert.Dispose();
            }

            throw;
        }
    }


    /// <summary>
    /// Implements <see cref="ValidateCertificateChainDelegate"/>. Validates the chain
    /// using <see cref="PkixCertPathBuilder"/> per RFC 5280 and returns the leaf
    /// certificate's public key as a <see cref="PublicKeyMemory"/>.
    /// </summary>
    public static PublicKeyMemory ValidateChain(
        IReadOnlyList<PkiCertificateMemory> chain,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset validationTime,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(trustAnchors);
        ArgumentNullException.ThrowIfNull(pool);

        if(chain.Count == 0)
        {
            throw new ArgumentException(
                "Certificate chain must contain at least one certificate.", nameof(chain));
        }

        BouncyCastleX509 leafCert = CertificateParser.ReadCertificate(
            chain[0].AsReadOnlyMemory().ToArray());

        var trustAnchorSet = new HashSet<TrustAnchor>();
        foreach(PkiCertificateMemory anchor in trustAnchors)
        {
            BouncyCastleX509 anchorCert = CertificateParser.ReadCertificate(
                anchor.AsReadOnlyMemory().ToArray());
            trustAnchorSet.Add(new TrustAnchor(anchorCert, null));
        }

        var intermediateCerts = new List<BouncyCastleX509>();
        for(int i = 1; i < chain.Count; i++)
        {
            intermediateCerts.Add(CertificateParser.ReadCertificate(
                chain[i].AsReadOnlyMemory().ToArray()));
        }

        X509CertStoreSelector selector = new() { Certificate = leafCert };

        PkixBuilderParameters pkixParams = new(trustAnchorSet, selector)
        {
            IsRevocationEnabled = false,
            Date = validationTime.UtcDateTime
        };

        //The builder searches stores to find the cert matching the selector — the leaf
        //must be in a store alongside any intermediates, not just set as the selector target.
        var allCerts = new List<BouncyCastleX509>(chain.Count) { leafCert };
        allCerts.AddRange(intermediateCerts);
        pkixParams.AddStoreCert(CollectionUtilities.CreateStore<BouncyCastleX509>(allCerts));

        PkixCertPathBuilder builder = new();
        PkixCertPathBuilderResult result;

        try
        {
            result = builder.Build(pkixParams);
        }
        catch(PkixCertPathBuilderException ex)
        {
            throw new System.Security.SecurityException(
                $"X.509 certificate chain validation failed: {ex.Message}", ex);
        }

        BouncyCastleX509 validatedLeaf =
            (BouncyCastleX509)result.CertPath.Certificates[0];

        return ExtractPublicKey(validatedLeaf, pool);
    }


    /// <summary>
    /// Implements <see cref="VerifyDnsSanDelegate"/>. Verifies that the leaf
    /// certificate's Subject Alternative Name contains a <c>dNSName</c> entry
    /// matching <paramref name="expectedDnsName"/> using BouncyCastle ASN.1 parsing.
    /// </summary>
    public static void VerifyDnsSan(
        PkiCertificateMemory leafCertificate,
        string expectedDnsName)
    {
        ArgumentNullException.ThrowIfNull(leafCertificate);
        ArgumentNullException.ThrowIfNull(expectedDnsName);

        BouncyCastleX509 cert = CertificateParser.ReadCertificate(
            leafCertificate.AsReadOnlyMemory().ToArray());

        Asn1OctetString? sanExtension =
            cert.GetExtensionValue(X509Extensions.SubjectAlternativeName);

        if(sanExtension is null)
        {
            throw new System.Security.SecurityException(
                $"Leaf certificate has no Subject Alternative Name extension. " +
                $"The x509_san_dns: prefix requires a dNSName SAN matching " +
                $"'{expectedDnsName}'.");
        }

        //Decode the OCTET STRING wrapper to get the GeneralNames sequence.
        Asn1Object sanObj = X509ExtensionUtilities.FromExtensionValue(sanExtension);
        GeneralNames generalNames = GeneralNames.GetInstance(sanObj);

        bool found = generalNames.GetNames()
            .Where(static gn => gn.TagNo == GeneralName.DnsName)
            .Any(gn => string.Equals(
                gn.Name.ToString(),
                expectedDnsName,
                StringComparison.OrdinalIgnoreCase));

        if(!found)
        {
            throw new System.Security.SecurityException(
                $"Leaf certificate SAN does not contain a dNSName entry matching " +
                $"'{expectedDnsName}' per OID4VP 1.0 §5.9.3.");
        }
    }


    private static PublicKeyMemory ExtractPublicKey(
        BouncyCastleX509 certificate,
        MemoryPool<byte> pool)
    {
        var publicKey = certificate.GetPublicKey();

        if(publicKey is Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters ecKey)
        {
            return ExtractEcPublicKey(ecKey, pool);
        }

        throw new NotSupportedException(
            $"Leaf certificate public key type '{publicKey.GetType().Name}' is not " +
            $"supported. Only EC keys are currently supported in the BouncyCastle driver.");
    }


    private static PublicKeyMemory ExtractEcPublicKey(
        Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters ecKey,
        MemoryPool<byte> pool)
    {
        //Encode as compressed point: 0x02 (even Y) or 0x03 (odd Y) || X.
        //BouncyCastle ECPoint.GetEncoded(compressed: true) produces this format directly.
        //MicrosoftCryptographicFunctions.VerifyECDsa calls EllipticCurveUtilities.IsCompressed
        //and returns false for uncompressed points, so compressed encoding is required.
        byte[] compressed = ecKey.Q.Normalize().GetEncoded(compressed: true);

        string? oid = ecKey.PublicKeyParamSet?.Id;
        Tag tag = oid switch
        {
            WellKnownOids.EcP256 => CryptoTags.P256PublicKey,
            WellKnownOids.EcP384 => CryptoTags.P384PublicKey,
            WellKnownOids.EcP521 => CryptoTags.P521PublicKey,
            _ => throw new NotSupportedException(
                $"EC curve OID '{oid}' is not supported. " +
                $"Supported curves are P-256 ({WellKnownOids.EcP256}), " +
                $"P-384 ({WellKnownOids.EcP384}), and " +
                $"P-521 ({WellKnownOids.EcP521}).")
        };

        IMemoryOwner<byte> owner = pool.Rent(compressed.Length);
        compressed.CopyTo(owner.Memory);

        return new PublicKeyMemory(owner, tag);
    }
}
