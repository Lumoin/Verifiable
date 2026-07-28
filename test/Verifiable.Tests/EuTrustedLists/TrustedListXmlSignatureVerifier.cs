using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Cryptography.Pki.Xml;

/// <summary>
/// A worked <see cref="VerifyTrustedListSignatureDelegate"/> implementation for the TLv6 XAdES-BASELINE-B
/// profile: <see cref="System.Security.Cryptography.Xml.SignedXml"/> (BCL, already pinned in this
/// repository's central package versions but referenced by no shipped project) covers the XMLDSIG
/// cryptographic core, and this type adds the two checks XAdES layers on top — the
/// <c>xades:SigningCertificate</c> binding and trust-anchor membership — structurally the XML analogue of
/// the ESS <c>signing-certificate-v2</c> binding <see cref="CAdESVerification"/> already performs for CMS.
/// </summary>
/// <remarks>
/// <para>
/// Staged, promotable worked example (contract R-4): production namespace (<c>Verifiable.Cryptography.Pki.Xml</c>,
/// matching <see cref="TrustedListXmlParser"/>), no test-framework type, no dependency on
/// <c>TestInfrastructure</c>. Only <see cref="System.Security.Cryptography.Xml"/> is test-project-only —
/// its <c>PackageReference</c> is on the test project, never on <c>Verifiable.Cryptography</c>.
/// </para>
/// <para>
/// <strong>Scope, per the profile the ETSI TS 119 612 V2.4.1 TLv6 signature actually is</strong> (never
/// XAdES-LT — no timestamp, no revocation data, no signature policy): one enveloped signature, exactly two
/// <c>ds:Reference</c> elements (the whole document via the enveloped-signature transform, and the
/// <c>xades:SignedProperties</c>), the <c>SigningCertificate</c> binding, and trust-anchor membership. A
/// document whose <c>ds:SignedInfo</c> does not carry exactly two references is rejected as malformed
/// rather than accepted under a looser reading of the profile.
/// </para>
/// <para>
/// <strong>Fail-closed hash algorithm handling.</strong> The certificate-digest hash inside the
/// <c>SigningCertificate</c> binding is computed through <see cref="CryptographicKeyEvents.ComputeDigestAsync(ReadOnlyMemory{byte},int,Tag,MemoryPool{byte},System.Collections.Frozen.FrozenDictionary{string,object}?,string?,CancellationToken)"/> —
/// the registered digest seam, never a direct <c>System.Security.Cryptography.SHA256</c> call — exactly as
/// <see cref="CAdESVerification"/>'s own <c>signing-certificate-v2</c> check does; an algorithm this seam does
/// not recognise fails closed as <see cref="TrustedListSignatureStatus.UnsupportedHashAlgorithm"/> rather than
/// silently falling back to a default.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1515:Consider making public types internal", Justification = "Staged composition-edge code (layering-split-ledger.md): public by design so the boundary is already the future package's API boundary, per the promotability rules.")]
public static class TrustedListXmlSignatureVerifier
{
    /// <summary>The XAdES 1.3.2 namespace of <c>QualifyingProperties</c>/<c>SigningCertificateV2</c>/<c>SigningTime</c>.</summary>
    private const string XadesNamespace = "http://uri.etsi.org/01903/v1.3.2#";

    /// <summary>The XMLDSIG core namespace.</summary>
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    /// <summary>The <c>xmlenc#sha256</c> digest algorithm URI.</summary>
    private const string DigestSha256Uri = "http://www.w3.org/2001/04/xmlenc#sha256";

    /// <summary>The <c>xmldsig-more#sha384</c> digest algorithm URI.</summary>
    private const string DigestSha384Uri = "http://www.w3.org/2001/04/xmldsig-more#sha384";

    /// <summary>The <c>xmlenc#sha512</c> digest algorithm URI.</summary>
    private const string DigestSha512Uri = "http://www.w3.org/2001/04/xmlenc#sha512";


    /// <summary>
    /// Verifies <paramref name="document"/>'s XMLDSIG/XAdES-BASELINE-B signature against
    /// <paramref name="trustAnchors"/>. Has the <see cref="VerifyTrustedListSignatureDelegate"/> shape.
    /// </summary>
    /// <param name="document">The raw, signed document bytes. The caller retains ownership.</param>
    /// <param name="trustAnchors">The certificates the signer must be one of.</param>
    /// <param name="pool">The memory pool the certificate-digest computation rents scratch buffers from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The verification result.</returns>
    public static async ValueTask<TrustedListSignatureVerificationResult> VerifyAsync(
        PooledMemory document,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(trustAnchors);
        ArgumentNullException.ThrowIfNull(pool);

        //PreserveWhitespace MUST be true: XmlDocument otherwise normalizes insignificant whitespace on load,
        //which changes the canonicalized bytes of the whole-document Reference (URI="") and makes even a
        //genuine signature fail CheckSignature.
        XmlDocument xmlDocument = new() { XmlResolver = null, PreserveWhitespace = true };
        try
        {
            //Attacker-reachable input: DTD processing is prohibited before this document's own signature has
            //even been located, the same discipline TrustedListXmlParser applies.
            var readerSettings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            using var stream = new MemoryStream(document.AsReadOnlySpan().ToArray(), writable: false);
            using XmlReader reader = XmlReader.Create(stream, readerSettings);
            xmlDocument.Load(reader);
        }
        catch(XmlException ex)
        {
            return TrustedListSignatureVerificationResult.Failed(TrustedListSignatureStatus.Malformed, $"The document is not well-formed XML: {ex.Message}");
        }

        XmlNodeList signatureNodes = xmlDocument.GetElementsByTagName("Signature", DsNamespace);
        if(signatureNodes.Count == 0 || signatureNodes[0] is not XmlElement signatureElement)
        {
            return TrustedListSignatureVerificationResult.Failed(TrustedListSignatureStatus.MissingSignature, "The document carries no ds:Signature element.");
        }

        var signedXml = new SignedXml(xmlDocument);
        try
        {
            signedXml.LoadXml(signatureElement);
        }
        catch(Exception ex) when(ex is CryptographicException or FormatException)
        {
            return TrustedListSignatureVerificationResult.Failed(TrustedListSignatureStatus.Malformed, $"The ds:Signature element did not parse: {ex.Message}");
        }

        //The TLv6 profile per ETSI TS 119 612 V2.4.1 is exactly two references: the whole document (enveloped
        //signature transform) and the xades:SignedProperties. Anything else is not this profile.
        if(signedXml.SignedInfo?.References.Count != 2)
        {
            return TrustedListSignatureVerificationResult.Failed(TrustedListSignatureStatus.Malformed, "The TLv6 profile requires exactly two ds:Reference elements.");
        }

        X509Certificate2? signerCertificate = ExtractSignerCertificate(signedXml);
        if(signerCertificate is null)
        {
            return TrustedListSignatureVerificationResult.Failed(TrustedListSignatureStatus.MissingSigningCertificateBinding, "The signature's ds:KeyInfo carries no X.509 certificate.");
        }

        using(signerCertificate)
        {
            bool cryptographicallyValid;
            try
            {
                //verifySignatureOnly: trust is decided below against the caller's own trust anchors, not by
                //building a PKIX chain for signerCertificate — the TLv6 signer is bootstrap-trusted, never
                //chain-built to a public root (see the delegate's own remarks).
                cryptographicallyValid = signedXml.CheckSignature(signerCertificate, verifySignatureOnly: true);
            }
            catch(CryptographicException)
            {
                cryptographicallyValid = false;
            }

            if(!cryptographicallyValid)
            {
                return TrustedListSignatureVerificationResult.Failed(TrustedListSignatureStatus.InvalidSignature, "The XMLDSIG signature did not verify.");
            }

            (TrustedListSignatureStatus bindingStatus, string? bindingFailureReason, DateTimeOffset? signingTime) =
                await VerifySigningCertificateBindingAsync(signatureElement, signerCertificate, pool, cancellationToken).ConfigureAwait(false);

            if(bindingStatus != TrustedListSignatureStatus.Valid)
            {
                return TrustedListSignatureVerificationResult.Failed(bindingStatus, bindingFailureReason ?? "The XAdES SigningCertificate binding failed.");
            }

            if(!IsAmongTrustAnchors(signerCertificate.RawData, trustAnchors))
            {
                return TrustedListSignatureVerificationResult.Failed(TrustedListSignatureStatus.UntrustedSigner, "The signer certificate is not among the supplied trust anchors.");
            }

            return TrustedListSignatureVerificationResult.Valid(signingTime);
        }
    }


    /// <summary>Returns <see langword="true"/> when <paramref name="signerDerBytes"/> byte-equals one of <paramref name="trustAnchors"/>.</summary>
    private static bool IsAmongTrustAnchors(byte[] signerDerBytes, IReadOnlyList<PkiCertificateMemory> trustAnchors)
    {
        foreach(PkiCertificateMemory anchor in trustAnchors)
        {
            if(anchor.AsReadOnlySpan().SequenceEqual(signerDerBytes))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>Reads the first X.509 certificate out of the signature's <c>ds:KeyInfo/ds:X509Data</c>, or <see langword="null"/> when none is present.</summary>
    private static X509Certificate2? ExtractSignerCertificate(SignedXml signedXml)
    {
        foreach(KeyInfoClause clause in signedXml.KeyInfo)
        {
            if(clause is KeyInfoX509Data x509Data && x509Data.Certificates is not null)
            {
                foreach(X509Certificate2 candidate in x509Data.Certificates.Cast<X509Certificate2>())
                {
                    return candidate;
                }
            }
        }

        return null;
    }


    /// <summary>
    /// Verifies the XAdES <c>SigningCertificate</c> binding: the <c>xades:SigningCertificateV2/Cert/CertDigest</c>
    /// hash must match <paramref name="signerCertificate"/> under the hash algorithm the binding declares — the
    /// XML analogue of the ESS <c>signing-certificate-v2</c> check <see cref="CAdESVerification"/> performs for
    /// CMS. Also reads the optional <c>xades:SigningTime</c>.
    /// </summary>
    private static async ValueTask<(TrustedListSignatureStatus Status, string? Reason, DateTimeOffset? SigningTime)> VerifySigningCertificateBindingAsync(
        XmlElement signatureElement, X509Certificate2 signerCertificate, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        XmlNamespaceManager namespaceManager = new(signatureElement.OwnerDocument!.NameTable);
        namespaceManager.AddNamespace("xades", XadesNamespace);
        namespaceManager.AddNamespace("ds", DsNamespace);

        XmlNode? certDigestNode = signatureElement.SelectSingleNode(
            ".//ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties" +
            "/xades:SigningCertificateV2/xades:Cert/xades:CertDigest", namespaceManager);

        if(certDigestNode is null)
        {
            return (TrustedListSignatureStatus.MissingSigningCertificateBinding, "No xades:SigningCertificateV2/Cert/CertDigest was found.", null);
        }

        string? digestAlgorithmUri = certDigestNode.SelectSingleNode("ds:DigestMethod/@Algorithm", namespaceManager)?.Value;
        string? digestValueBase64 = certDigestNode.SelectSingleNode("ds:DigestValue", namespaceManager)?.InnerText;

        if(digestAlgorithmUri is null || digestValueBase64 is null)
        {
            return (TrustedListSignatureStatus.MissingSigningCertificateBinding, "The CertDigest element is missing its DigestMethod or DigestValue.", null);
        }

        (Tag tag, int length) = DigestForUri(digestAlgorithmUri);
        if(tag is null)
        {
            return (TrustedListSignatureStatus.UnsupportedHashAlgorithm, $"Unsupported CertDigest hash algorithm '{digestAlgorithmUri}'.", null);
        }

        using DigestValue computed = await CryptographicKeyEvents.ComputeDigestAsync(
            signerCertificate.RawData, length, tag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        byte[] expectedDigest = Convert.FromBase64String(digestValueBase64.Trim());
        if(!computed.AsReadOnlySpan().SequenceEqual(expectedDigest))
        {
            return (TrustedListSignatureStatus.SigningCertificateBindingMismatch, "The CertDigest does not match the signer certificate.", null);
        }

        XmlNode? signingTimeNode = signatureElement.SelectSingleNode(
            ".//ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime", namespaceManager);

        DateTimeOffset? signingTime = signingTimeNode is not null
            && DateTimeOffset.TryParse(signingTimeNode.InnerText.Trim(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset parsed)
                ? parsed
                : null;

        return (TrustedListSignatureStatus.Valid, null, signingTime);
    }


    /// <summary>Maps an XMLDSIG/xmlenc digest algorithm URI to its digest <see cref="Tag"/> and output length, or a <see langword="null"/> tag for an unsupported algorithm.</summary>
    private static (Tag Tag, int Length) DigestForUri(string uri) => uri switch
    {
        DigestSha256Uri => (CryptoTags.Sha256Digest, 32),
        DigestSha384Uri => (CryptoTags.Sha384Digest, 48),
        DigestSha512Uri => (CryptoTags.Sha512Digest, 64),
        _ => (null!, 0)
    };
}
