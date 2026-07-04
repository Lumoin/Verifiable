using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Microsoft;

/// <summary>
/// BCL-backed implementations of the X.509 certificate chain validation delegates
/// defined in <c>Verifiable.OAuth.Oid4Vp</c>.
/// </summary>
/// <remarks>
/// <para>
/// Wire these static methods as the <see cref="ParseX5cDelegate"/>,
/// <see cref="ValidateCertificateChainAsyncDelegate"/>, and
/// <see cref="VerifyDnsSanDelegate"/> in application setup:
/// </para>
/// <code>
/// ResolveKeyFromX509SanDnsDelegate resolver =
///     (x5c, expectedDns, trustAnchors, time, pool, ct) =>
///         X509SanDnsKeyResolver.ResolveAsync(
///             x5c, expectedDns, trustAnchors, time,
///             MicrosoftX509Functions.ParseX5c,
///             MicrosoftX509Functions.ValidateChainAsync,
///             MicrosoftX509Functions.VerifyDnsSan,
///             pool, ct);
/// </code>
/// </remarks>
public static class MicrosoftX509Functions
{
    /// <summary>
    /// Implements <see cref="ParseX5cDelegate"/>. Decodes the base64-encoded DER
    /// certificate strings from a JOSE <c>x5c</c> header into
    /// <see cref="PkiCertificateMemory"/> instances.
    /// </summary>
    /// <param name="x5cValues">
    /// Base64-encoded DER strings. First entry is the leaf per RFC 7515 §4.1.6.
    /// </param>
    /// <param name="pool">
    /// Memory pool for DER byte allocations. Must be
    /// <see cref="BaseMemoryPool.Shared"/> to guarantee exact-size allocations.
    /// </param>
    /// <returns>Certificate chain in order, leaf first. Caller must dispose all.</returns>
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
    /// using <see cref="X509Chain"/> with <see cref="X509ChainTrustMode.CustomRootTrust"/>
    /// and returns the leaf certificate's public key.
    /// </summary>
    /// <param name="chain">Certificate chain, leaf first.</param>
    /// <param name="trustAnchors">
    /// Trust anchor certificates. Pass ecosystem CA certificates obtained from the
    /// EUDI Trust List or equivalent trust framework for production use.
    /// </param>
    /// <param name="validationTime">UTC time for certificate validity evaluation.</param>
    /// <param name="pool">Memory pool for key material allocation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="checkRevocation">
    /// An optional revocation-status checker. When supplied, the leaf certificate that chained is additionally
    /// checked and the result is fail-closed (a revoked or indeterminate status throws); when <see langword="null"/>
    /// only chain building is performed. The built-in <see cref="X509Chain"/> revocation is left off
    /// (<see cref="X509RevocationMode.NoCheck"/>) so revocation flows through this supplied seam rather than the OS.
    /// </param>
    /// <returns>Leaf public key. Caller must dispose.</returns>
    /// <remarks>
    /// Chain building is in-memory; the async signature carries the optionally-supplied
    /// <paramref name="checkRevocation"/> seam (an OCSP/CRL round-trip) and reserves the seam for remote-anchor
    /// resolution. With no checker the method completes without awaiting.
    /// </remarks>
    /// <exception cref="System.Security.SecurityException">
    /// Thrown when chain validation fails, including when <paramref name="checkRevocation"/> reports the leaf as
    /// revoked or of indeterminate status.
    /// </exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the returned PublicKeyMemory transfers to the caller via the ValueTask; the caller disposes it.")]
    public static async ValueTask<PublicKeyMemory> ValidateChainAsync(
        IReadOnlyList<PkiCertificateMemory> chain,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset validationTime,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation = null)
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

        using X509Certificate2 leafCert = X509CertificateLoader.LoadCertificate(chain[0].AsReadOnlyMemory().Span);
        using X509Chain x509Chain = new();

        x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        x509Chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        x509Chain.ChainPolicy.VerificationTime = validationTime.UtcDateTime;

        //Certs added to CustomTrustStore and ExtraStore must remain alive until
        //after Build completes — do not use 'using' inside the loops.
        var anchorCerts = new List<X509Certificate2>(trustAnchors.Count);
        var intermediateCerts = new List<X509Certificate2>(Math.Max(0, chain.Count - 1));
        try
        {
            foreach(PkiCertificateMemory anchor in trustAnchors)
            {
                X509Certificate2 anchorCert =
                    X509CertificateLoader.LoadCertificate(anchor.AsReadOnlyMemory().Span);
                anchorCerts.Add(anchorCert);
                x509Chain.ChainPolicy.CustomTrustStore.Add(anchorCert);
            }

            for(int i = 1; i < chain.Count; i++)
            {
                X509Certificate2 intermediate =
                    X509CertificateLoader.LoadCertificate(chain[i].AsReadOnlyMemory().Span);
                intermediateCerts.Add(intermediate);
                x509Chain.ChainPolicy.ExtraStore.Add(intermediate);
            }

            bool valid = x509Chain.Build(leafCert);
            if(!valid)
            {
                string errors = string.Join(", ", x509Chain.ChainStatus
                    .Select(static s => s.StatusInformation.Trim()));

                throw new System.Security.SecurityException(
                    $"X.509 certificate chain validation failed: {errors}");
            }

            //Revocation is part of path validation: when a revocation source is configured, the leaf that just
            //chained must additionally be checked and the result is fail-closed — anything but an affirmative Good
            //(a revoked leaf or an indeterminate status) rejects the chain.
            if(checkRevocation is not null)
            {
                CertificateRevocationStatus revocationStatus = await checkRevocation(
                    chain[0], trustAnchors, validationTime, pool, cancellationToken).ConfigureAwait(false);
                if(revocationStatus != CertificateRevocationStatus.Good)
                {
                    throw new System.Security.SecurityException(
                        $"X.509 certificate revocation check failed: the leaf certificate's revocation status is '{revocationStatus}'.");
                }
            }

            return ExtractPublicKey(leafCert, pool);
        }
        finally
        {
            foreach(X509Certificate2 cert in anchorCerts)
            {
                cert.Dispose();
            }

            foreach(X509Certificate2 cert in intermediateCerts)
            {
                cert.Dispose();
            }
        }
    }


    /// <summary>
    /// Implements <see cref="VerifyDnsSanDelegate"/>. Verifies that the leaf
    /// certificate's Subject Alternative Name contains a <c>dNSName</c> entry
    /// matching <paramref name="expectedDnsName"/>.
    /// </summary>
    /// <param name="leafCertificate">The leaf certificate from the validated chain.</param>
    /// <param name="expectedDnsName">
    /// The DNS name that must appear in the SAN. For <c>x509_san_dns:</c> this is the
    /// <c>client_id</c> with the prefix stripped per OID4VP 1.0 §5.9.3.
    /// </param>
    /// <exception cref="System.Security.SecurityException">
    /// Thrown when no SAN extension is present or no DNS SAN entry matches.
    /// </exception>
    public static void VerifyDnsSan(
        PkiCertificateMemory leafCertificate,
        string expectedDnsName)
    {
        ArgumentNullException.ThrowIfNull(leafCertificate);
        ArgumentNullException.ThrowIfNull(expectedDnsName);

        using X509Certificate2 cert = X509CertificateLoader.LoadCertificate(leafCertificate.AsReadOnlyMemory().Span);

        X509Extension? sanExtension = cert.Extensions["2.5.29.17"];

        if(sanExtension is null)
        {
            throw new System.Security.SecurityException(
                $"Leaf certificate has no Subject Alternative Name extension. " +
                $"The x509_san_dns: prefix requires a dNSName SAN matching '{expectedDnsName}'.");
        }

        //Parse the SAN extension directly from RawData using AsnReader — locale-independent.
        //X509Extension.Format uses OS-localised strings ("DNS-nimi=" on Finnish Windows),
        //making it unusable for programmatic matching. RawData is always DER.
        //GeneralName dNSName is context-specific primitive tag [2] containing an IA5String.
        var dnsNames = new List<string>();
        AsnReader outer = new(sanExtension.RawData, AsnEncodingRules.DER);
        AsnReader sequence = outer.ReadSequence();

        while(sequence.HasData)
        {
            Asn1Tag tag = sequence.PeekTag();
            if(tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 2)
            {
                dnsNames.Add(sequence.ReadCharacterString(
                    UniversalTagNumber.IA5String,
                    new Asn1Tag(TagClass.ContextSpecific, 2)));
            }
            else
            {
                sequence.ReadEncodedValue();
            }
        }

        bool found = dnsNames.Any(name =>
            name.Equals(expectedDnsName, StringComparison.OrdinalIgnoreCase));

        if(!found)
        {
            string actual = string.Join(", ", dnsNames.Select(n => $"'{n}'"));
            throw new System.Security.SecurityException(
                $"Expected dNSName '{expectedDnsName}' not found in SAN. " +
                $"dNSName entries found: [{actual}]");
        }
    }


    /// <summary>
    /// Implements <see cref="IsSelfSignedCertificateDelegate"/>. Reports whether the
    /// certificate's Issuer distinguished name equals its Subject distinguished name.
    /// </summary>
    /// <param name="certificate">The certificate to inspect.</param>
    /// <returns><see langword="true"/> when the certificate is self-signed.</returns>
    public static bool IsSelfSigned(PkiCertificateMemory certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        using X509Certificate2 cert = X509CertificateLoader.LoadCertificate(certificate.AsReadOnlyMemory().Span);

        //Compare the raw DER of the Issuer and Subject names rather than their string
        //forms — string rendering is encoding- and locale-sensitive, the DER is canonical.
        return cert.IssuerName.RawData.AsSpan().SequenceEqual(cert.SubjectName.RawData);
    }


    /// <summary>
    /// Reads the <c>KeyIdentifier</c> of the certificate's AuthorityKeyIdentifier extension
    /// (RFC 5280 §4.2.1.1) and returns it base64url-encoded — the value a DCQL
    /// <c>trusted_authorities</c> entry of type <c>aki</c> matches against per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.1">OID4VP 1.0 §6.1.1.1</see>.
    /// Returns <see langword="null"/> when the certificate carries no AuthorityKeyIdentifier
    /// extension or that extension omits the KeyIdentifier (e.g. it identifies the issuer by
    /// name + serial instead).
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

        using X509Certificate2 cert = X509CertificateLoader.LoadCertificate(certificate.AsReadOnlyMemory().Span);

        if(cert.Extensions["2.5.29.35"] is not X509AuthorityKeyIdentifierExtension authorityKeyIdentifier
            || authorityKeyIdentifier.KeyIdentifier is not { } keyIdentifier)
        {
            return null;
        }

        return base64UrlEncoder(keyIdentifier.Span);
    }


    /// <summary>
    /// Implements <see cref="ReadCertificateProfileDelegate"/>. Reads the certificate's Key Usage
    /// (<c>2.5.29.15</c>) and Basic Constraints (<c>2.5.29.19</c>) extensions and reports the
    /// profile-relevant constraints as backend-neutral booleans.
    /// </summary>
    /// <param name="certificate">The certificate to inspect.</param>
    /// <returns>The certificate's <see cref="X509CertificateProfile"/>.</returns>
    public static X509CertificateProfile ReadCertificateProfile(PkiCertificateMemory certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        using X509Certificate2 cert = X509CertificateLoader.LoadCertificate(certificate.AsReadOnlyMemory().Span);

        //RFC 5280 §4.2: a certificate MUST NOT include more than one instance of a particular extension. The
        //base class library loader tolerates a duplicate, so reading a single instance with
        //OfType<>().FirstOrDefault() below would derive the profile from whichever instance the DER happens to
        //encode first — letting a malformed certificate hide a second KeyUsage asserting keyCertSign behind a
        //conformant one. Reject the certificate instead, so the profile is never taken from an arbitrarily chosen
        //instance (the BouncyCastle backend's parser refuses a duplicate extension OID outright, so both backends
        //fail closed on the same bytes).
        string? duplicateExtensionOid = cert.Extensions
            .GroupBy(extension => extension.Oid?.Value)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .FirstOrDefault();
        if(duplicateExtensionOid is not null)
        {
            throw new CryptographicException(
                $"The certificate includes more than one instance of the extension '{duplicateExtensionOid}', which RFC 5280 §4.2 forbids.");
        }

        X509KeyUsageExtension? keyUsage = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        X509BasicConstraintsExtension? basicConstraints = cert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();

        return new X509CertificateProfile
        {
            AssertsDigitalSignature = keyUsage is not null && keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature),
            AssertsKeyCertSign = keyUsage is not null && keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign),
            IsCertificateAuthority = basicConstraints is not null && basicConstraints.CertificateAuthority
        };
    }


    private static PublicKeyMemory ExtractPublicKey(
        X509Certificate2 certificate,
        MemoryPool<byte> pool)
    {
        ECDsa? ecdsa = certificate.PublicKey.GetECDsaPublicKey();
        if(ecdsa is not null)
        {
            using(ecdsa)
            {
                return ExtractEcPublicKey(ecdsa, pool);
            }
        }

        RSA? rsa = certificate.PublicKey.GetRSAPublicKey();
        if(rsa is not null)
        {
            using(rsa)
            {
                byte[] spki = rsa.ExportSubjectPublicKeyInfo();
                IMemoryOwner<byte> owner = pool.Rent(spki.Length);
                spki.CopyTo(owner.Memory);

                Tag tag = rsa.KeySize switch
                {
                    2048 => CryptoTags.Rsa2048PublicKey,
                    4096 => CryptoTags.Rsa4096PublicKey,
                    _ => throw new NotSupportedException(
                        $"RSA key size {rsa.KeySize} bits is not supported. " +
                        $"Supported sizes are 2048 and 4096.")
                };

                return new PublicKeyMemory(owner, tag);
            }
        }

        throw new NotSupportedException(
            $"Leaf certificate public key algorithm " +
            $"'{certificate.PublicKey.Oid.FriendlyName}' is not supported. " +
            $"Only EC and RSA keys are currently supported.");
    }


    private static PublicKeyMemory ExtractEcPublicKey(ECDsa ecdsa, MemoryPool<byte> pool)
    {
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);

        byte[] x = parameters.Q.X!;
        byte[] y = parameters.Q.Y!;
        int coordinateLength = x.Length;

        //Encode as compressed point: 0x02 (even Y) or 0x03 (odd Y) || X.
        //MicrosoftCryptographicFunctions.VerifyECDsa calls EllipticCurveUtilities.IsCompressed
        //and returns false for uncompressed points, so compressed encoding is required.
        int totalLength = 1 + coordinateLength;
        IMemoryOwner<byte> owner = pool.Rent(totalLength);

        owner.Memory.Span[0] = (y[^1] & 1) == 0
            ? EllipticCurveUtilities.EvenYCoordinate
            : EllipticCurveUtilities.OddYCoordinate;
        x.CopyTo(owner.Memory.Span[1..]);

        Tag tag = parameters.Curve.Oid?.Value switch
        {
            WellKnownOids.EcP256 => CryptoTags.P256PublicKey,
            WellKnownOids.EcP384 => CryptoTags.P384PublicKey,
            WellKnownOids.EcP521 => CryptoTags.P521PublicKey,
            _ => throw new NotSupportedException(
                $"EC curve '{parameters.Curve.Oid?.FriendlyName}' is not supported. " +
                $"Supported curves are P-256, P-384, and P-521.")
        };

        return new PublicKeyMemory(owner, tag);
    }
}
