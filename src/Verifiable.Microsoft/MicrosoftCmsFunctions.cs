using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Microsoft;

/// <summary>
/// A BCL-backed implementation of <see cref="VerifyCmsSignedDataDelegate"/> using
/// <see cref="SignedCms"/>.
/// </summary>
/// <remarks>
/// <para>
/// Register at application startup:
/// </para>
/// <code>
/// CryptographicKeyFactory.RegisterFunction(
///     typeof(VerifyCmsSignedDataDelegate),
///     (VerifyCmsSignedDataDelegate)MicrosoftCmsFunctions.VerifyCmsSignedDataAsync);
/// </code>
/// <para>
/// This verifies the CMS signature only — it does not build or trust a certificate chain. The
/// returned <see cref="CmsVerifiedContent.Certificates"/> (signer first) feed
/// <see cref="ValidateCertificateChainAsyncDelegate"/> for the separate trust step, keeping the two
/// concerns composable: eMRTD Passive Authentication chains the signer to a CSCA; CAdES validates
/// its signed attributes; both reuse this same verified-content core.
/// </para>
/// </remarks>
public static class MicrosoftCmsFunctions
{
    /// <summary>
    /// Implements <see cref="VerifyCmsSignedDataDelegate"/>. Decodes the CMS SignedData, verifies the
    /// signer's signature over the encapsulated content, and returns the content with the embedded
    /// certificates.
    /// </summary>
    /// <param name="signedData">The CMS SignedData carrier with encapsulated content.</param>
    /// <param name="pool">Memory pool; must be <see cref="BaseMemoryPool.Shared"/> for exact-size allocations.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The verified content and embedded certificates. The caller disposes it.</returns>
    /// <exception cref="CryptographicException">Thrown when the signature is invalid or the signer certificate is absent.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the content buffer and certificate memories transfers to the returned CmsVerifiedContent, which the caller disposes; the catch disposes them on a partial failure.")]
    public static ValueTask<CmsVerifiedContent> VerifyCmsSignedDataAsync(
        CmsSignedData signedData,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        SignedCms cms = new();
        cms.Decode(signedData.AsReadOnlySpan());

        //Verify the signature over the encapsulated content, but not the certificate chain — trust is
        //established separately through the certificate-chain seam against the appropriate anchors.
        cms.CheckSignature(verifySignatureOnly: true);

        if(cms.SignerInfos.Count == 0)
        {
            throw new CryptographicException("The CMS SignedData carries no signer information.");
        }

        SignerInfo signer = cms.SignerInfos[0];
        X509Certificate2 signerCertificate = signer.Certificate
            ?? throw new CryptographicException("The CMS SignedData does not embed the signer certificate.");

        string contentType = cms.ContentInfo.ContentType.Value ?? string.Empty;
        byte[] content = cms.ContentInfo.Content;
        byte[] signerDer = signerCertificate.RawData;

        var certificates = new List<PkiCertificateMemory>(cms.Certificates.Count + 1);
        var signedAttributes = new List<CmsSignedAttribute>(signer.SignedAttributes.Count);
        IMemoryOwner<byte>? contentOwner = null;
        try
        {
            //The signer's certificate first, then the remaining embedded certificates (intermediates).
            certificates.Add(ToPkiCertificate(signerDer, pool));
            foreach(X509Certificate2 certificate in cms.Certificates)
            {
                byte[] der = certificate.RawData;
                if(!der.AsSpan().SequenceEqual(signerDer))
                {
                    certificates.Add(ToPkiCertificate(der, pool));
                }
            }

            //The signer's signed attributes, which the signature covers; a format layer (CAdES) validates them.
            foreach(CryptographicAttributeObject attribute in signer.SignedAttributes)
            {
                if(attribute.Oid.Value is string oid && attribute.Values.Count > 0)
                {
                    signedAttributes.Add(ToSignedAttribute(oid, attribute.Values[0].RawData, pool));
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
    /// Copies a signed attribute's DER value into a pooled <see cref="CmsSignedAttribute"/>.
    /// </summary>
    private static CmsSignedAttribute ToSignedAttribute(string oid, byte[] der, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(der.Length);
        der.CopyTo(owner.Memory.Span);

        return new CmsSignedAttribute(oid, owner);
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
}
