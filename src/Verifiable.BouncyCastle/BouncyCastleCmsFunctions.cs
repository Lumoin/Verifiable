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
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Utilities.Collections;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using BcAttribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using BcCmsSignedData = Org.BouncyCastle.Cms.CmsSignedData;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Verifiable.BouncyCastle;

/// <summary>
/// A BouncyCastle-backed implementation of <see cref="VerifyCmsSignedDataDelegate"/> — independent of
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
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the content buffer, certificate memories, and signed-attribute carriers transfers to the returned CmsVerifiedContent, which the caller disposes; the catch disposes them on a partial failure.")]
    public static ValueTask<CmsVerifiedContent> VerifyCmsSignedDataAsync(
        Verifiable.Cryptography.Pki.CmsSignedData signedData,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        var cms = new BcCmsSignedData(signedData.AsReadOnlySpan().ToArray());

        SignerInformation signer = cms.GetSignerInfos().GetSigners().FirstOrDefault()
            ?? throw new CryptographicException("The CMS SignedData carries no signer information.");

        IStore<BcX509Certificate> certificateStore = cms.GetCertificates();
        BcX509Certificate signerCertificate = certificateStore.EnumerateMatches(signer.SignerID).FirstOrDefault()
            ?? throw new CryptographicException("The CMS SignedData does not embed the signer certificate.");

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
            //The signer's certificate first, then the remaining embedded certificates.
            certificates.Add(ToPkiCertificate(signerDer, pool));
            foreach(BcX509Certificate certificate in certificateStore.EnumerateMatches(null))
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
    /// Copies DER certificate bytes into a pooled <see cref="PkiCertificateMemory"/>.
    /// </summary>
    private static PkiCertificateMemory ToPkiCertificate(byte[] der, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(der.Length);
        der.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>
    /// Copies a signed attribute's DER value into a pooled <see cref="CmsSignedAttribute"/>.
    /// </summary>
    private static CmsSignedAttribute ToSignedAttribute(string oid, byte[] der, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(der.Length);
        der.CopyTo(owner.Memory.Span);

        return new CmsSignedAttribute(oid, owner);
    }
}
