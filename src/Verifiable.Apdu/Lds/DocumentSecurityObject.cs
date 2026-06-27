using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The ICAO Doc 9303 eMRTD Document Security Object (EF.SOD): the file the chip stores at file
/// identifier <c>0x011D</c> that wraps the CMS SignedData over the LDS Security Object.
/// </summary>
/// <remarks>
/// <para>
/// On the wire EF.SOD is a single BER-TLV object with application tag <c>0x77</c> whose content is
/// the CMS <c>ContentInfo</c> (RFC 5652) carrying the SignedData. This type strips the <c>0x77</c>
/// wrapper to yield the CMS bytes that the signature-verification seam decodes.
/// </para>
/// </remarks>
public static class DocumentSecurityObject
{
    /// <summary>The eMRTD elementary file identifier of EF.SOD.</summary>
    public const ushort FileIdentifier = 0x011D;

    /// <summary>The BER-TLV application tag wrapping the EF.SOD CMS content.</summary>
    private const byte DocumentSecurityObjectTag = 0x77;


    /// <summary>
    /// Extracts the CMS SignedData from an EF.SOD file by removing the <c>0x77</c> wrapper, into a
    /// <see cref="CmsSignedData"/> carrier.
    /// </summary>
    /// <param name="efSod">The EF.SOD elementary file.</param>
    /// <param name="pool">The memory pool for the carrier.</param>
    /// <returns>The CMS SignedData. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the file is not a well-formed EF.SOD.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the CmsSignedData carrier transfers to the caller, which disposes it.")]
    public static CmsSignedData ExtractSignedData(ElementaryFile efSod, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(efSod);
        ArgumentNullException.ThrowIfNull(pool);

        var reader = new ApduReader(efSod.Content);
        if(reader.ReadByte() != DocumentSecurityObjectTag)
        {
            throw new InvalidOperationException($"The data is not an EF.SOD file (expected BER-TLV tag 0x{DocumentSecurityObjectTag:X2}).");
        }

        int length = reader.ReadTlvLength();

        return CmsSignedData.FromBytes(efSod.Content.Slice(reader.Consumed, length), pool);
    }


    /// <summary>
    /// Writes an EF.SOD file by wrapping CMS SignedData in the <c>0x77</c> application tag — the inverse
    /// of <see cref="ExtractSignedData"/>. The CMS is produced and signed by the caller (an issuer's
    /// Document Signer in production, an independent oracle in firewalled tests); this only frames it.
    /// </summary>
    /// <param name="signedData">The CMS SignedData over the LDS Security Object.</param>
    /// <param name="pool">The memory pool for the file carrier.</param>
    /// <returns>The EF.SOD <see cref="ElementaryFile"/>. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ElementaryFile, which the caller disposes; the catch disposes it on failure.")]
    public static ElementaryFile Write(CmsSignedData signedData, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(pool);

        ReadOnlySpan<byte> cms = signedData.AsReadOnlySpan();
        int total = BerTlvWriter.ElementSize(DocumentSecurityObjectTag, cms.Length);

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new BerTlvWriter(owner.Memory.Span[..total]);
            writer.WriteElement(DocumentSecurityObjectTag, cms);

            return new ElementaryFile(owner, FileIdentifier);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }
}
