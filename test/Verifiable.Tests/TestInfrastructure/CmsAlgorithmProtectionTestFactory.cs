using System;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Mints a plain CMS SignedData carrying the <c>id-aa-CMSAlgorithmProtection</c> signed or unsigned
/// attribute (<see href="https://www.rfc-editor.org/rfc/rfc6211#section-2">RFC 6211 §2</see>), with the
/// attribute's own <c>digestAlgorithm</c>/<c>signatureAlgorithm</c> values under the caller's control — a
/// genuine agreeing pair, a deliberately disagreeing one, or a duplicated <c>AttributeValue</c> — signed
/// over with the framework's own signer, mirroring <see cref="CmsSignedDataTestFactory"/>'s
/// <c>System.Security.Cryptography.Pkcs</c>-backed minting shape (a fixture-minting concern, not the
/// project's own CMS surface under test). Because the attribute is added to <see cref="CmsSigner.SignedAttributes"/>
/// before <see cref="SignedCms.ComputeSignature(CmsSigner)"/> runs, the signature is computed over
/// whatever value — correct or deliberately wrong — the attribute carries, so a mismatch fixture's
/// signature still verifies and only the algorithm-protection compare can reject it.
/// </summary>
internal static class CmsAlgorithmProtectionTestFactory
{
    /// <summary>The <c>id-aa-CMSAlgorithmProtection</c> signed attribute object identifier (RFC 6211 §2).</summary>
    public const string CmsAlgorithmProtectionOid = "1.2.840.113549.1.9.52";


    /// <summary>
    /// Signs the payload as a plain CMS SignedData carrying a <c>CMSAlgorithmProtection</c> attribute value
    /// naming <paramref name="digestAlgorithmOid"/> and <paramref name="signatureAlgorithmOid"/>, placed as
    /// a signed attribute (the only placement RFC 6211 §2 admits: "it MUST NOT be an unsigned attribute") or
    /// as an unsigned one, for the negative that proves an unsigned instance is never consulted.
    /// </summary>
    /// <param name="payload">The content to sign.</param>
    /// <param name="signerCertificate">The signer certificate (the test holds its key).</param>
    /// <param name="digestAlgorithmOid">The <c>digestAlgorithm</c> object identifier the attribute value carries.</param>
    /// <param name="signatureAlgorithmOid">The <c>signatureAlgorithm [1]</c> object identifier the attribute value carries.</param>
    /// <param name="asSignedAttribute">
    /// When <see langword="true"/> (the default), the attribute is added to <see cref="CmsSigner.SignedAttributes"/>
    /// before the signature is computed, so it is covered by the signature. When <see langword="false"/>, it
    /// is added as an unsigned attribute after computing the signature instead, exactly as
    /// <see cref="CmsSignedDataTestFactory.SignAsCAdEST"/> attaches its own unsigned timestamp attribute.
    /// </param>
    /// <param name="duplicateAttributeValue">
    /// When <see langword="true"/>, the same attribute value is added twice under the one attribute type —
    /// <see cref="CryptographicAttributeObjectCollection.Add(System.Security.Cryptography.AsnEncodedData)"/>
    /// merges same-OID adds into the one attribute's <c>Values</c> collection rather than creating a second
    /// attribute — producing the two-<c>AttributeValue</c> shape RFC 6211 §2 forbids ("There MUST NOT be zero
    /// or multiple instances of AttributeValue present").
    /// </param>
    /// <param name="rawAttributeValue">
    /// When non-<see langword="null"/>, carried verbatim as the attribute value in place of the §2 encoding
    /// the algorithm identifier parameters would otherwise produce — for negatives that need a malformed or
    /// over-long value signed over, so the signature mathematics verify and only the attribute's own parse or
    /// compare can reject.
    /// </param>
    /// <returns>The wire carrier. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the carrier transfers to the caller, which disposes it.")]
    public static CmsSignedData SignWithCmsAlgorithmProtection(
        ReadOnlySpan<byte> payload,
        X509Certificate2 signerCertificate,
        string digestAlgorithmOid,
        string signatureAlgorithmOid,
        bool asSignedAttribute = true,
        bool duplicateAttributeValue = false,
        byte[]? rawAttributeValue = null)
    {
        ArgumentNullException.ThrowIfNull(signerCertificate);
        ArgumentNullException.ThrowIfNull(digestAlgorithmOid);
        ArgumentNullException.ThrowIfNull(signatureAlgorithmOid);

        var content = new ContentInfo(payload.ToArray());
        var signedCms = new SignedCms(content, detached: false);
        var signer = new CmsSigner(signerCertificate) { IncludeOption = X509IncludeOption.EndCertOnly };

        //A signing-time attribute keeps signer.SignedAttributes non-empty even when the algorithm-protection
        //attribute itself is placed only in unsignedAttrs: an empty SignedAttributes collection makes .NET's
        //CmsSigner omit signedAttrs entirely (a bare signature over the content, RFC 5652 §5.4's "field is
        //absent" branch), which would leave no message-digest attribute for ManagedCmsVerification to read —
        //an artifact of this fixture-minting shape, not of the attribute under test.
        signer.SignedAttributes.Add(new Pkcs9SigningTime());

        byte[] attributeValue = rawAttributeValue ?? BuildCmsAlgorithmProtectionValue(digestAlgorithmOid, signatureAlgorithmOid);
        if(asSignedAttribute)
        {
            signer.SignedAttributes.Add(new AsnEncodedData(new Oid(CmsAlgorithmProtectionOid), attributeValue));
            if(duplicateAttributeValue)
            {
                signer.SignedAttributes.Add(new AsnEncodedData(new Oid(CmsAlgorithmProtectionOid), attributeValue));
            }
        }

        signedCms.ComputeSignature(signer);

        if(!asSignedAttribute)
        {
            signedCms.SignerInfos[0].AddUnsignedAttribute(new AsnEncodedData(new Oid(CmsAlgorithmProtectionOid), attributeValue));
        }

        return CmsSignedData.FromBytes(signedCms.Encode(), BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Encodes a <c>CMSAlgorithmProtection</c> value (RFC 6211 §2) naming <paramref name="digestAlgorithmOid"/>
    /// as <c>digestAlgorithm</c> and <paramref name="signatureAlgorithmOid"/> as the present
    /// <c>signatureAlgorithm [1]</c>, with <c>macAlgorithm [2]</c> absent — the signed-data WITH COMPONENTS
    /// alternative ("signatureAlgorithm PRESENT, macAlgorithm ABSENT").
    /// </summary>
    private static byte[] BuildCmsAlgorithmProtectionValue(string digestAlgorithmOid, string signatureAlgorithmOid)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            using(writer.PushSequence())                                              //digestAlgorithm AlgorithmIdentifier.
            {
                writer.WriteObjectIdentifier(digestAlgorithmOid);
            }

            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))       //signatureAlgorithm [1].
            {
                writer.WriteObjectIdentifier(signatureAlgorithmOid);
            }
        }

        return writer.Encode();
    }
}
