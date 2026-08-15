using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using BcAttribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using BcCmsSignedData = Org.BouncyCastle.Cms.CmsSignedData;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Verifiable.BouncyCastle;

/// <summary>
/// A BouncyCastle-backed implementation of <see cref="VerifyCmsSignedDataDelegate"/> and of its detached
/// counterpart <see cref="VerifyDetachedCmsSignedDataDelegate"/> — independent of
/// Microsoft's <c>System.Security.Cryptography.Pkcs.SignedCms</c>. Verifies the signature on a CMS SignedData
/// (RFC 5652) and returns its encapsulated content with the embedded certificates and the signer's signed
/// attributes, the shared core of eMRTD Passive Authentication and the CAdES family of EU advanced signatures.
/// </summary>
/// <remarks>
/// <para>
/// Register at application startup, optionally under a qualifier so it can coexist with another backend:
/// </para>
/// <code>
/// CryptographicKeyFactory.RegisterFunction(
///     typeof(VerifyCmsSignedDataDelegate),
///     (VerifyCmsSignedDataDelegate)BouncyCastleCmsFunctions.VerifyCmsSignedDataAsync);
/// </code>
/// <para>
/// No OS library dependency — fully WASM-compatible. Like the Microsoft backend, it verifies the signature
/// only (over the signed attributes, including the message-digest binding of the content) and throws on
/// failure; the returned <see cref="CmsVerifiedContent.Certificates"/> (signer first) feed
/// <see cref="ValidateCertificateChainAsyncDelegate"/> for the separate trust step. Both backends produce the
/// same <see cref="CmsVerifiedContent"/>, so CAdES and Passive Authentication work over either unchanged.
/// </para>
/// </remarks>
public static class BouncyCastleCmsFunctions
{
    /// <summary>
    /// Implements <see cref="VerifyCmsSignedDataDelegate"/> with BouncyCastle. Decodes the CMS SignedData,
    /// verifies the signer's signature over the encapsulated content, and returns the content with the
    /// embedded certificates and the signer's signed attributes.
    /// </summary>
    /// <param name="signedData">The CMS SignedData carrier with encapsulated content.</param>
    /// <param name="pool">The memory pool for the content, certificate, and signed-attribute allocations.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The verified content and embedded certificates. The caller disposes it.</returns>
    /// <exception cref="CryptographicException">Thrown when the signature is invalid or the signer certificate is absent.</exception>
    public static ValueTask<CmsVerifiedContent> VerifyCmsSignedDataAsync(
        Verifiable.Cryptography.Pki.CmsSignedData signedData,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        var cms = new BcCmsSignedData(signedData.AsReadOnlySpan().ToArray());

        return Verify(cms, pool);
    }


    /// <summary>
    /// Implements <see cref="VerifyDetachedCmsSignedDataDelegate"/> with BouncyCastle. Decodes a CMS SignedData
    /// that encapsulates no content of its own, verifies the signer's signature against content the caller
    /// carries beside it, and returns that content with the embedded certificates and signed attributes.
    /// </summary>
    /// <param name="signedData">The CMS SignedData carrier, encapsulating no content of its own.</param>
    /// <param name="detachedContent">The octets the signature is detached over — the Signer's Document.</param>
    /// <param name="pool">The memory pool for the content, certificate, and signed-attribute allocations.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The verified content and embedded certificates. The caller disposes it.</returns>
    /// <exception cref="CryptographicException">Thrown when the structure encapsulates content of its own, the signature is invalid, or the signer certificate is absent.</exception>
    /// <remarks>
    /// The decoder takes the detached content as the processable it is constructed with, so everything after
    /// the decode is the encapsulated case verbatim. A structure that does carry its own content is refused
    /// before that, because verifying one of two contents is the shape a substitution attack takes — the same
    /// rule the library's managed backend applies.
    /// </remarks>
    public static ValueTask<CmsVerifiedContent> VerifyDetachedCmsSignedDataAsync(
        Verifiable.Cryptography.Pki.CmsSignedData signedData,
        SignedContentMemory detachedContent,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(detachedContent);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        byte[] encoded = signedData.AsReadOnlySpan().ToArray();
        if(new BcCmsSignedData(encoded).SignedContent is not null)
        {
            throw new CryptographicException("The CMS SignedData encapsulates content of its own, so it is not a detached signature.");
        }

        var cms = new BcCmsSignedData(new CmsProcessableByteArray(detachedContent.AsReadOnlySpan().ToArray()), encoded);

        return Verify(cms, pool);
    }


    /// <summary>
    /// Verifies a decoded CMS SignedData and projects it into the seam's verified content — the body both the
    /// encapsulated and the detached member share, which differ only in where the content came from.
    /// </summary>
    /// <param name="cms">The decoded structure, carrying the content to verify against.</param>
    /// <param name="pool">The memory pool for the content, certificate, and signed-attribute allocations.</param>
    /// <returns>The verified content and embedded certificates. The caller disposes it.</returns>
    /// <exception cref="CryptographicException">Thrown when the signature is invalid or the signer certificate is absent.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the content buffer, certificate memories, and signed-attribute carriers transfers to the returned CmsVerifiedContent, which the caller disposes; the catch disposes them on a partial failure.")]
    private static ValueTask<CmsVerifiedContent> Verify(BcCmsSignedData cms, BaseMemoryPool pool)
    {
        SignerInformation signer = cms.GetSignerInfos().GetSigners().FirstOrDefault()
            ?? throw new CryptographicException("The CMS SignedData carries no signer information.");

        List<BcX509Certificate> embeddedCertificates = ParseCertificates(cms.SignedData.Certificates);
        BcX509Certificate? signerCertificate = null;
        foreach(BcX509Certificate candidate in embeddedCertificates)
        {
            if(signer.SignerID.Match(candidate))
            {
                signerCertificate = candidate;
                break;
            }
        }

        if(signerCertificate is null)
        {
            throw new CryptographicException("The CMS SignedData does not embed the signer certificate.");
        }

        bool verified;
        try
        {
            //Verifies the signature over the signed attributes, including the message-digest binding of the content.
            verified = signer.Verify(signerCertificate);
        }
        catch(CmsException exception)
        {
            throw new CryptographicException("The CMS signature did not verify.", exception);
        }

        if(!verified)
        {
            throw new CryptographicException("The CMS signature did not verify.");
        }

        CmsProcessable signedContent = cms.SignedContent
            ?? throw new CryptographicException("The CMS SignedData carries no encapsulated content.");
        using var contentStream = new MemoryStream();
        signedContent.Write(contentStream);
        byte[] content = contentStream.ToArray();

        string contentType = cms.SignedContentType.Id;
        byte[] signerDer = signerCertificate.GetEncoded();

        var certificates = new List<PkiCertificateMemory>();
        var signedAttributes = new List<CmsSignedAttribute>();
        IMemoryOwner<byte>? contentOwner = null;
        try
        {
            //The signer's certificate first, then the remaining embedded, intact certificates.
            certificates.Add(ToPkiCertificate(signerDer, pool));
            foreach(BcX509Certificate certificate in embeddedCertificates)
            {
                byte[] der = certificate.GetEncoded();
                if(!der.AsSpan().SequenceEqual(signerDer))
                {
                    certificates.Add(ToPkiCertificate(der, pool));
                }
            }

            //The signer's signed attributes, which the signature covers; the format layer (CAdES) validates them.
            if(signer.SignedAttributes is not null)
            {
                Asn1EncodableVector attributes = signer.SignedAttributes.ToAsn1EncodableVector();
                for(int i = 0; i < attributes.Count; i++)
                {
                    BcAttribute attribute = BcAttribute.GetInstance(attributes[i]);
                    if(attribute.AttrValues.Count > 0)
                    {
                        byte[] der = attribute.AttrValues[0].GetEncoded(Asn1Encodable.Der);
                        signedAttributes.Add(ToSignedAttribute(attribute.AttrType.Id, der, pool));
                    }
                }
            }

            contentOwner = pool.Rent(content.Length);
            content.CopyTo(contentOwner.Memory.Span);

            CmsVerifiedContent result = new(contentType, contentOwner, content.Length, certificates, signerIndex: 0, signedAttributes);

            return ValueTask.FromResult(result);
        }
        catch
        {
            contentOwner?.Dispose();
            foreach(PkiCertificateMemory certificate in certificates)
            {
                certificate.Dispose();
            }

            foreach(CmsSignedAttribute attribute in signedAttributes)
            {
                attribute.Dispose();
            }

            throw;
        }
    }


    /// <summary>
    /// Parses a CMS SignedData <c>certificates</c> field member-wise, tolerant of a member that fails RFC 5280
    /// certificate parsing.
    /// </summary>
    /// <param name="certificates">The decoded <c>certificates [0] IMPLICIT CertificateSet OPTIONAL</c> field, or <see langword="null"/> when the field is absent.</param>
    /// <returns>The members that parsed as a <c>Certificate</c>, in the field's own order; empty when <paramref name="certificates"/> is <see langword="null"/> or no member parses.</returns>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-10.2.3">RFC 5652 §10.2.3</see>'s
    /// <c>CertificateSet ::= SET OF CertificateChoices</c> lets a member be any of
    /// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-10.2.2">§10.2.2</see>'s tagged
    /// <c>CertificateChoices</c> alternatives — <see cref="X509CertificateStructure.GetOptional(Asn1Encodable)"/>
    /// already discriminates those, returning <see langword="null"/> without surfacing them as a certificate. An
    /// untagged <c>Certificate</c> alternative that fails RFC 5280 parsing throws instead of returning
    /// <see langword="null"/>, so that failure is caught and the member is skipped rather than failing the whole
    /// walk. What licenses the skip is that the field is not itself covered by the signature (§5.4's message
    /// digest calculation runs over the content or signed attributes, and §5.6 verifies against that digest), so
    /// a broken non-signer member is a verification-denial lever, never evidence against the signature;
    /// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">§5.1</see> and §10.2.3 additionally make
    /// the set's contents a convenience without a completeness promise ("more certificates than necessary,…
    /// fewer certificates than necessary"), so no verifier may rely on every member being usable. Which members
    /// parse is this backend's own certificate parser's judgment, so for a hostile member the surviving list can
    /// differ from the managed backend's — the signer-resolution contract is identical, the tolerance boundary
    /// is per-parser.
    /// </remarks>
    private static List<BcX509Certificate> ParseCertificates(Asn1Set? certificates)
    {
        var result = new List<BcX509Certificate>();
        if(certificates is null)
        {
            return result;
        }

        foreach(Asn1Encodable member in certificates)
        {
            try
            {
                X509CertificateStructure? structure = X509CertificateStructure.GetOptional(member);
                if(structure is not null)
                {
                    result.Add(new BcX509Certificate(structure));
                }
            }
            catch(Exception exception) when (exception is not OutOfMemoryException)
            {
                //Not signature-covered (§5.4/§5.6), so a member that fails RFC 5280 parsing is skipped rather
                //than denying verification of the signer and the remaining, intact members. The guard spans both
                //the structure decode and the certificate construction and admits every exception type, because
                //BouncyCastle's parse surface raises an open set across shapes and versions (ArgumentException,
                //InvalidOperationException, CertificateParsingException among those observed) and a member's
                //parseability must never depend on that taxonomy.
                continue;
            }
        }

        return result;
    }


    /// <summary>
    /// Copies DER certificate bytes into a pooled <see cref="PkiCertificateMemory"/>.
    /// </summary>
    private static PkiCertificateMemory ToPkiCertificate(byte[] der, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(der.Length);
        der.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>
    /// Copies a signed attribute's DER value into a pooled <see cref="CmsSignedAttribute"/>.
    /// </summary>
    private static CmsSignedAttribute ToSignedAttribute(string oid, byte[] der, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(der.Length);
        der.CopyTo(owner.Memory.Span);

        return new CmsSignedAttribute(oid, owner);
    }
}
