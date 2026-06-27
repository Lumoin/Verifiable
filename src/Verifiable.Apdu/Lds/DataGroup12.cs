using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The parsed EF.DG12 (Data Group 12) of an ICAO Doc 9303 eMRTD: additional document details — the issuing
/// authority, date of issue, endorsements, and the personalization metadata the issuing state optionally
/// records (Doc 9303 Part 10).
/// </summary>
/// <remarks>
/// <para>
/// EF.DG12 (file identifier <c>0x010C</c>, BER-TLV template tag <c>0x6C</c>) is a template of optional data
/// objects. This type extracts the commonly used character-string fields; a leading tag list (<c>0x5C</c>),
/// an other-persons template, and the optional document images are skipped, since every modelled field is
/// self-describing by its own tag. The text is read as ASCII, the encoding the writer produces; fields the
/// file omits are <see langword="null"/>.
/// </para>
/// </remarks>
public sealed class DataGroup12
{
    /// <summary>The eMRTD elementary file identifier of EF.DG12.</summary>
    public const ushort FileIdentifier = 0x010C;

    private const int DataGroupTemplateTag = 0x6C;
    private const int IssuingAuthorityTag = 0x5F19;
    private const int DateOfIssueTag = 0x5F26;
    private const int EndorsementsTag = 0x5F1B;
    private const int TaxExitRequirementsTag = 0x5F1C;
    private const int PersonalizationDateTimeTag = 0x5F55;
    private const int PersonalizationSystemSerialNumberTag = 0x5F56;


    private DataGroup12(
        string? issuingAuthority, string? dateOfIssue, string? endorsements,
        string? taxExitRequirements, string? personalizationDateTime, string? personalizationSystemSerialNumber)
    {
        IssuingAuthority = issuingAuthority;
        DateOfIssue = dateOfIssue;
        Endorsements = endorsements;
        TaxExitRequirements = taxExitRequirements;
        PersonalizationDateTime = personalizationDateTime;
        PersonalizationSystemSerialNumber = personalizationSystemSerialNumber;
    }


    /// <summary>Gets the issuing authority (<c>5F19</c>), or <see langword="null"/> when absent.</summary>
    public string? IssuingAuthority { get; }

    /// <summary>Gets the date of issue (<c>5F26</c>, <c>YYYYMMDD</c>), or <see langword="null"/> when absent.</summary>
    public string? DateOfIssue { get; }

    /// <summary>Gets the endorsements or observations (<c>5F1B</c>), or <see langword="null"/> when absent.</summary>
    public string? Endorsements { get; }

    /// <summary>Gets the tax or exit requirements (<c>5F1C</c>), or <see langword="null"/> when absent.</summary>
    public string? TaxExitRequirements { get; }

    /// <summary>Gets the date and time of personalization (<c>5F55</c>, <c>YYYYMMDDHHMMSS</c>), or <see langword="null"/> when absent.</summary>
    public string? PersonalizationDateTime { get; }

    /// <summary>Gets the serial number of the personalization system (<c>5F56</c>), or <see langword="null"/> when absent.</summary>
    public string? PersonalizationSystemSerialNumber { get; }


    /// <summary>
    /// Parses an EF.DG12 file, extracting the commonly used character-string fields.
    /// </summary>
    /// <param name="dataGroup12">The DG12 file bytes (the BER-TLV structure beginning with tag <c>0x6C</c>).</param>
    /// <returns>The parsed <see cref="DataGroup12"/>.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the structure is not a well-formed DG12 template.</exception>
    public static DataGroup12 Parse(ReadOnlySpan<byte> dataGroup12)
    {
        var reader = new ApduReader(dataGroup12);
        if(LdsTlv.ReadTag(ref reader) != DataGroupTemplateTag)
        {
            throw new InvalidOperationException("The data is not an EF.DG12 file (expected BER-TLV tag 0x6C).");
        }

        var content = new ApduReader(reader.ReadBytes(reader.ReadTlvLength()));

        string? issuingAuthority = null, dateOfIssue = null, endorsements = null;
        string? taxExitRequirements = null, personalizationDateTime = null, personalizationSystemSerialNumber = null;

        while(!content.IsEmpty)
        {
            int tag = LdsTlv.ReadTag(ref content);
            ReadOnlySpan<byte> value = content.ReadBytes(content.ReadTlvLength());

            switch(tag)
            {
                case IssuingAuthorityTag: issuingAuthority = Encoding.ASCII.GetString(value); break;
                case DateOfIssueTag: dateOfIssue = Encoding.ASCII.GetString(value); break;
                case EndorsementsTag: endorsements = Encoding.ASCII.GetString(value); break;
                case TaxExitRequirementsTag: taxExitRequirements = Encoding.ASCII.GetString(value); break;
                case PersonalizationDateTimeTag: personalizationDateTime = Encoding.ASCII.GetString(value); break;
                case PersonalizationSystemSerialNumberTag: personalizationSystemSerialNumber = Encoding.ASCII.GetString(value); break;
                default:
                    //The tag list (5C), the other-persons template, the document images, and fields a newer
                    //minor version adds are not modelled here; they are skipped so the template still parses.
                    break;
            }
        }

        return new DataGroup12(issuingAuthority, dateOfIssue, endorsements, taxExitRequirements, personalizationDateTime, personalizationSystemSerialNumber);
    }


    /// <summary>
    /// Writes an EF.DG12 file from its optional character-string fields — the inverse of <see cref="Parse"/>.
    /// Only the fields supplied (non-<see langword="null"/>) are written, each as an ASCII character string.
    /// </summary>
    /// <param name="issuingAuthority">The issuing authority (<c>5F19</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="dateOfIssue">The date of issue (<c>5F26</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="endorsements">The endorsements or observations (<c>5F1B</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="taxExitRequirements">The tax or exit requirements (<c>5F1C</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="personalizationDateTime">The date and time of personalization (<c>5F55</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="personalizationSystemSerialNumber">The serial number of the personalization system (<c>5F56</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="pool">The memory pool for the file carrier.</param>
    /// <returns>The EF.DG12 <see cref="ElementaryFile"/>. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ElementaryFile, which the caller disposes; the catch disposes it on failure.")]
    public static ElementaryFile Write(
        string? issuingAuthority, string? dateOfIssue, string? endorsements,
        string? taxExitRequirements, string? personalizationDateTime, string? personalizationSystemSerialNumber,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int contentLength =
            LdsTlv.OptionalElementSize(IssuingAuthorityTag, issuingAuthority)
            + LdsTlv.OptionalElementSize(DateOfIssueTag, dateOfIssue)
            + LdsTlv.OptionalElementSize(EndorsementsTag, endorsements)
            + LdsTlv.OptionalElementSize(TaxExitRequirementsTag, taxExitRequirements)
            + LdsTlv.OptionalElementSize(PersonalizationDateTimeTag, personalizationDateTime)
            + LdsTlv.OptionalElementSize(PersonalizationSystemSerialNumberTag, personalizationSystemSerialNumber);
        int total = BerTlvWriter.ElementSize(DataGroupTemplateTag, contentLength);

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new BerTlvWriter(owner.Memory.Span[..total]);
            writer.WriteHeader(DataGroupTemplateTag, contentLength);
            LdsTlv.WriteOptionalAscii(ref writer, IssuingAuthorityTag, issuingAuthority);
            LdsTlv.WriteOptionalAscii(ref writer, DateOfIssueTag, dateOfIssue);
            LdsTlv.WriteOptionalAscii(ref writer, EndorsementsTag, endorsements);
            LdsTlv.WriteOptionalAscii(ref writer, TaxExitRequirementsTag, taxExitRequirements);
            LdsTlv.WriteOptionalAscii(ref writer, PersonalizationDateTimeTag, personalizationDateTime);
            LdsTlv.WriteOptionalAscii(ref writer, PersonalizationSystemSerialNumberTag, personalizationSystemSerialNumber);

            return new ElementaryFile(owner, FileIdentifier);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }
}
