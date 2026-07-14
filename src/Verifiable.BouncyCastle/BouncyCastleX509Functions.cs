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
using System.Formats.Asn1;
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
///             BouncyCastleX509Functions.ValidateChainAsync,
///             BouncyCastleX509Functions.VerifyDnsSan,
///             pool, ct);
/// </code>
/// </remarks>
public static class BouncyCastleX509Functions
{
    private static X509CertificateParser CertificateParser { get; } = new();


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
    /// Implements <see cref="ValidateCertificateChainAsyncDelegate"/>. Validates the chain
    /// using <see cref="PkixCertPathBuilder"/> per RFC 5280 and returns the leaf
    /// certificate's public key as a <see cref="PublicKeyMemory"/>.
    /// </summary>
    /// <param name="checkRevocation">
    /// An optional revocation-status checker. When supplied, every certificate in <paramref name="chain"/> that is
    /// not byte-equal to a supplied trust anchor — the leaf and every intermediate CA certificate the chain
    /// carries — is additionally checked, and the result is fail-closed (a revoked or indeterminate status
    /// throws); when <see langword="null"/> only chain building is performed. The PKIX builder's own revocation is
    /// left off (<c>IsRevocationEnabled = false</c>) so revocation flows through this supplied seam.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <remarks>
    /// Chain building is in-memory; the async signature carries the optionally-supplied <paramref name="checkRevocation"/>
    /// seam (an OCSP/CRL round-trip) and reserves the seam for remote-anchor resolution. With no checker the method
    /// completes without awaiting.
    /// </remarks>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the returned PublicKeyMemory transfers to the caller via the ValueTask; the caller disposes it.")]
    public static async ValueTask<PublicKeyMemory> ValidateChainAsync(
        IReadOnlyList<PkiCertificateMemory> chain,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset validationTime,
        MemoryPool<byte> pool,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(trustAnchors);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

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

        //Revocation is part of path validation: when a revocation source is configured, every certificate in the
        //chain that is not itself a supplied trust anchor must additionally be checked and the result is
        //fail-closed — anything but an affirmative Good (a revoked certificate or an indeterminate status) rejects
        //the chain. This covers the leaf AND every intermediate CA certificate the chain carries, per WebAuthn
        //Level 3 section 7.1's "certificate status information for the intermediate CA certificates".
        if(checkRevocation is not null)
        {
            for(int certificateIndex = 0; certificateIndex < chain.Count; certificateIndex++)
            {
                PkiCertificateMemory candidate = chain[certificateIndex];
                if(trustAnchors.Contains(candidate))
                {
                    //A chain entry that is itself a supplied trust anchor (some callers include the root in the
                    //wire-supplied chain) needs no revocation source — it is trusted by configuration, not path.
                    continue;
                }

                //The issuer candidates for this certificate are every OTHER chain entry plus the trust anchors, so
                //a checker can locate the leaf's intermediate issuer as well as an intermediate's root issuer — the
                //single-certificate-chain case (issuerCandidates == trustAnchors) is unchanged.
                var issuerCandidates = new List<PkiCertificateMemory>(chain.Count - 1 + trustAnchors.Count);
                for(int otherIndex = 0; otherIndex < chain.Count; otherIndex++)
                {
                    if(otherIndex != certificateIndex)
                    {
                        issuerCandidates.Add(chain[otherIndex]);
                    }
                }

                issuerCandidates.AddRange(trustAnchors);

                CertificateRevocationStatus revocationStatus = await checkRevocation(
                    candidate, issuerCandidates, validationTime, pool, cancellationToken).ConfigureAwait(false);
                if(revocationStatus != CertificateRevocationStatus.Good)
                {
                    throw new System.Security.SecurityException(
                        $"X.509 certificate revocation check failed: the certificate at chain index {certificateIndex} has revocation status '{revocationStatus}'.");
                }
            }
        }

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


    /// <summary>
    /// Implements <see cref="IsSelfSignedCertificateDelegate"/>. Reports whether the
    /// certificate's Issuer distinguished name is equivalent to its Subject
    /// distinguished name.
    /// </summary>
    public static bool IsSelfSigned(PkiCertificateMemory certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        BouncyCastleX509 cert = CertificateParser.ReadCertificate(
            certificate.AsReadOnlyMemory().ToArray());

        return cert.IssuerDN.Equivalent(cert.SubjectDN);
    }


    /// <summary>
    /// Implements <see cref="ExtractAuthorityKeyIdentifierDelegate"/>. Reads the <c>KeyIdentifier</c> of
    /// the certificate's AuthorityKeyIdentifier extension (RFC 5280 §4.2.1.1) and returns it
    /// base64url-encoded — the value a DCQL <c>trusted_authorities</c> entry of type <c>aki</c> matches
    /// against per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.1">OID4VP 1.0 §6.1.1.1</see>.
    /// Returns <see langword="null"/> when the certificate carries no AuthorityKeyIdentifier extension or
    /// that extension omits the KeyIdentifier (e.g. it identifies the issuer by name + serial instead).
    /// </summary>
    /// <param name="certificate">The certificate to read — typically the leaf of an mdoc IssuerAuth x5chain.</param>
    /// <param name="base64UrlEncoder">Encoder producing the base64url string form (the AKI is public metadata, not key material).</param>
    /// <returns>The base64url-encoded AuthorityKeyIdentifier KeyIdentifier, or <see langword="null"/>.</returns>
    public static string? GetAuthorityKeyIdentifier(
        PkiCertificateMemory certificate,
        EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        BouncyCastleX509 cert = CertificateParser.ReadCertificate(
            certificate.AsReadOnlyMemory().ToArray());

        Asn1OctetString? extensionValue = cert.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
        if(extensionValue is null)
        {
            return null;
        }

        byte[]? keyIdentifier = AuthorityKeyIdentifier.GetInstance(
            X509ExtensionUtilities.FromExtensionValue(extensionValue)).GetKeyIdentifier();
        if(keyIdentifier is null)
        {
            return null;
        }

        return base64UrlEncoder(keyIdentifier);
    }


    /// <summary>
    /// Implements <see cref="ReadCertificateProfileDelegate"/>. Reads the certificate's Key Usage and
    /// Basic Constraints, its version, and its Subject Organizational Unit, Country, Organization, and
    /// Common Name values via BouncyCastle, and reports the profile-relevant constraints as
    /// backend-neutral booleans.
    /// </summary>
    /// <param name="certificate">The certificate to inspect.</param>
    /// <returns>The certificate's <see cref="X509CertificateProfile"/>.</returns>
    public static X509CertificateProfile ReadCertificateProfile(PkiCertificateMemory certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        BouncyCastleX509 cert;
        try
        {
            cert = CertificateParser.ReadCertificate(certificate.AsReadOnlyMemory().ToArray());
        }
        catch(Org.BouncyCastle.Security.Certificates.CertificateException exception)
        {
            //The parser rejects a malformed certificate — including the RFC 5280 §4.2 duplicate-extension shape
            //(a certificate MUST NOT include more than one instance of an extension) that the Microsoft backend's
            //explicit guard also rejects. Surface it as the same CryptographicException, so the seam has one
            //exception contract regardless of which backend is registered.
            throw new System.Security.Cryptography.CryptographicException(
                "The certificate could not be read as a valid X.509 certificate (for example it includes a duplicate extension that RFC 5280 §4.2 forbids).", exception);
        }

        //GetKeyUsage returns the RFC 5280 §4.2.1.3 bits (index 0 digitalSignature, index 5 keyCertSign),
        //or null when the Key Usage extension is absent; trailing zero bits may be omitted, so the length
        //is guarded before indexing. GetBasicConstraints returns -1 when the certificate is not a CA (the
        //extension is absent or sets cA=FALSE) and the path-length value otherwise (RFC 5280 §4.2.1.9).
        bool[]? keyUsage = cert.GetKeyUsage();

        //X509Name.GetValueList(X509Name.OU/.C/.O/.CN) returns the Subject's Organizational Unit
        //(RFC 5280 §4.1.2.4, OID 2.5.4.11), Country (OID 2.5.4.6), Organization (OID 2.5.4.10), and
        //Common Name (OID 2.5.4.3) values in the order the RDNs were parsed from the encoded Subject
        //field, matching the Microsoft backend's declared (non-reversed) enumeration order.
        IList<string> organizationalUnits = cert.SubjectDN.GetValueList(X509Name.OU);
        IList<string> countries = cert.SubjectDN.GetValueList(X509Name.C);
        IList<string> organizations = cert.SubjectDN.GetValueList(X509Name.O);
        IList<string> commonNames = cert.SubjectDN.GetValueList(X509Name.CN);

        return new X509CertificateProfile
        {
            AssertsDigitalSignature = keyUsage is { Length: > 0 } && keyUsage[0],
            AssertsKeyCertSign = keyUsage is { Length: > 5 } && keyUsage[5],
            IsCertificateAuthority = cert.GetBasicConstraints() != -1,
            Version = cert.Version,
            HasEmptySubject = cert.SubjectDN.GetOidList().Count == 0,
            SubjectOrganizationalUnits = [.. organizationalUnits],
            SubjectCountries = [.. countries],
            SubjectOrganizations = [.. organizations],
            SubjectCommonNames = [.. commonNames]
        };
    }


    /// <summary>
    /// Implements <see cref="ReadCertificateExtensionValueDelegate"/>. Reads a single named
    /// extension of the certificate and returns its raw DER contents and criticality flag, using
    /// BouncyCastle — matching <see cref="MicrosoftX509Functions.ReadCertificateExtensionValue"/>'s
    /// contract byte-for-byte.
    /// </summary>
    /// <param name="certificate">The certificate to inspect.</param>
    /// <param name="oid">The dotted-decimal object identifier of the extension to read.</param>
    /// <returns>
    /// The <see cref="X509ExtensionValue"/> for <paramref name="oid"/>, or <see langword="null"/>
    /// when the certificate carries no extension with that identifier.
    /// </returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// Thrown when the certificate could not be parsed as a valid X.509 certificate — for example
    /// it includes more than one instance of a single extension (of any OID), which RFC 5280 §4.2
    /// forbids and which the BouncyCastle certificate parser itself rejects during parsing,
    /// matching the Microsoft backend's explicit duplicate-extension guard.
    /// </exception>
    public static X509ExtensionValue? ReadCertificateExtensionValue(PkiCertificateMemory certificate, string oid)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(oid);

        BouncyCastleX509 cert;
        try
        {
            cert = CertificateParser.ReadCertificate(certificate.AsReadOnlyMemory().ToArray());
        }
        catch(Org.BouncyCastle.Security.Certificates.CertificateException exception)
        {
            //Mirrors ReadCertificateProfile's own catch: the parser rejects a malformed certificate
            //— including the RFC 5280 §4.2 duplicate-extension shape the Microsoft backend's
            //explicit guard also rejects — as the same CryptographicException, so the seam has one
            //exception contract regardless of which backend is registered.
            throw new System.Security.Cryptography.CryptographicException(
                "The certificate could not be read as a valid X.509 certificate (for example it includes a duplicate extension that RFC 5280 §4.2 forbids).", exception);
        }

        X509Extension? extension = cert.GetExtension(new DerObjectIdentifier(oid));
        if(extension is null)
        {
            return null;
        }

        return new X509ExtensionValue(extension.Value.GetOctets(), extension.IsCritical);
    }


    /// <summary>
    /// Extracts the leaf certificate's public key as a <see cref="PublicKeyMemory"/>, in the same
    /// internal key-material shapes the Microsoft backend's own leaf-key extraction produces for the
    /// same certificate: compressed SEC1 point for EC, bare PKCS#1 <c>RSAPublicKey</c> DER for RSA.
    /// </summary>
    /// <param name="certificate">The validated leaf certificate to extract the public key from.</param>
    /// <param name="pool">Memory pool for the returned key's carrier allocation.</param>
    /// <returns>The tagged public key. The caller owns and disposes it.</returns>
    /// <exception cref="NotSupportedException">
    /// Thrown when the certificate's public key is neither EC nor RSA, or names an EC curve or RSA key
    /// size neither backend supports.
    /// </exception>
    private static PublicKeyMemory ExtractPublicKey(
        BouncyCastleX509 certificate,
        MemoryPool<byte> pool)
    {
        var publicKey = certificate.GetPublicKey();

        if(publicKey is Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters ecKey)
        {
            return ExtractEcPublicKey(ecKey, pool);
        }

        if(publicKey is Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters rsaKey)
        {
            return ExtractRsaPublicKey(rsaKey, pool);
        }

        throw new NotSupportedException(
            $"Leaf certificate public key type '{publicKey.GetType().Name}' is not " +
            $"supported. Only EC and RSA keys are currently supported in the BouncyCastle driver.");
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


    /// <summary>
    /// Encodes an RSA public key as a bare PKCS#1 <c>RSAPublicKey</c> DER SEQUENCE — not the full X.509
    /// SubjectPublicKeyInfo — matching the shape <c>BouncyCastleCryptographicFunctions.ParseRsaPublicKey</c>
    /// reads and the shape the Microsoft backend produces via <c>RSA.ExportRSAPublicKey()</c> for the
    /// same certificate, so the two backends' RSA leaf-key extraction is byte-identical.
    /// </summary>
    /// <param name="rsaKey">The RSA public key parameters read from the certificate.</param>
    /// <param name="pool">Memory pool for the returned key's carrier allocation.</param>
    /// <returns>The tagged public key. The caller owns and disposes it.</returns>
    /// <exception cref="NotSupportedException">Thrown when the key's size names an RSA key size neither backend supports.</exception>
    private static PublicKeyMemory ExtractRsaPublicKey(
        Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters rsaKey,
        MemoryPool<byte> pool)
    {
        //WriteIntegerUnsigned interprets its argument as an unsigned big-endian magnitude and
        //itself prepends the 0x00 sign-guard byte a DER INTEGER needs when the magnitude's most
        //significant bit is set — ToByteArrayUnsigned already strips any such guard byte BigInteger
        //may carry internally, so the two compose into the same minimal DER encoding
        //BouncyCastleCryptographicFunctions.ParseRsaPublicKey reads back with AsnReader.ReadInteger().
        AsnWriter writer = new(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteIntegerUnsigned(rsaKey.Modulus.ToByteArrayUnsigned());
            writer.WriteIntegerUnsigned(rsaKey.Exponent.ToByteArrayUnsigned());
        }

        byte[] rsaPublicKey = writer.Encode();
        IMemoryOwner<byte> owner = pool.Rent(rsaPublicKey.Length);
        rsaPublicKey.CopyTo(owner.Memory);

        return new PublicKeyMemory(owner, X509RsaPublicKeyTags.ResolvePublicKeyTag(rsaKey.Modulus.BitLength));
    }
}