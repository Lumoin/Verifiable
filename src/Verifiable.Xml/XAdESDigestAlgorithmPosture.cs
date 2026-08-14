using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// Clause 6.2.1's MD5 digest-algorithm ban surfaced at the XAdES layer — XA-6.2.1-02: "In addition, MD5
/// algorithm shall not be used as digest algorithm," per
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>. The leaf compares the raw <c>ds:DigestMethod Algorithm</c> URI octets
/// exact-character against the one MD5 identifier <see href="https://www.rfc-editor.org/rfc/rfc6931#section-2.1">
/// IETF RFC 6931 clause 2.1</see> registers (<c>http://www.w3.org/2001/04/xmldsig-more#md5</c>) — the same
/// identifier <c>Verifiable.Cryptography.Pki.XmlSignatureWellKnown.Md5DigestUri</c> already recognizes one
/// layer up. This crypto-free leaf's boundary keeps it from referencing that Pki type
/// directly, so the literal is restated here rather than shared; a bijection test pins the two literals to the
/// same value, the same posture applied for a URI that exists on both sides of the layering boundary
/// (there, the Encoding enum). No algorithm RESOLUTION happens here — this is recognition only, exactly like
/// <c>XmlSignatureWellKnown.IsRefusedDigestUri</c>'s own MD5 half.
/// </summary>
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "This is a registered algorithm identifier compared as a string or as UTF-8 octets, never dereferenced; nothing here fetches a URI. XML Signature clause 6.1 identifies an algorithm by the URI string as written, and System.Uri normalizes case, escaping and default ports, which would make two identifiers that name different algorithms compare equal — the same justification XmlSignatureIdentifiers and Verifiable.Cryptography.Pki.XmlSignatureWellKnown already carry for the identical shape.")]
public static class XAdESDigestAlgorithmPosture
{
    /// <summary>The MD5 digest algorithm URI, <c>http://www.w3.org/2001/04/xmldsig-more#md5</c>.</summary>
    public static string Md5DigestUri { get; } = "http://www.w3.org/2001/04/xmldsig-more#md5";

    /// <summary><see cref="Md5DigestUri"/> as UTF-8 octets, for exact-character comparison against an already-read <c>Algorithm</c> attribute span.</summary>
    public static ReadOnlySpan<byte> Md5DigestUriUtf8 => "http://www.w3.org/2001/04/xmldsig-more#md5"u8;


    /// <summary>
    /// Tells whether a <c>ds:DigestMethod Algorithm</c> URI names MD5 — XA-6.2.1-02's ban, checkable at every
    /// digest-algorithm position the XAdES surface carries:
    /// <see cref="XAdESDigestAlgAndValue.DigestMethodAlgorithm"/> (<c>CertDigest</c>, <c>SigPolicyHash</c>, the
    /// Annex A CRL/OCSP reference <c>DigestAlgAndValue</c> sites — one shared reader),
    /// <see cref="XAdESReferenceInfo.Digest"/>'s own field (<c>OtherTimeStampType</c>'s
    /// <c>ReferenceInfo</c> list — the "timestamp imprint digest method" position), and
    /// <see cref="XAdESRenewedDigestsV2.DigestMethodAlgorithm"/> (clause 5.5.3's own, non-shared
    /// <c>ds:DigestMethod</c>).
    /// </summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute's raw octets, exact-character.</param>
    /// <returns><see langword="true"/> when <paramref name="algorithmUri"/> is <see cref="Md5DigestUriUtf8"/>.</returns>
    public static bool IsMd5DigestUri(ReadOnlySpan<byte> algorithmUri)
    {
        return algorithmUri.SequenceEqual(Md5DigestUriUtf8);
    }
}
