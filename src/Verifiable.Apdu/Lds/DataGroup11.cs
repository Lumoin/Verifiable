using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The parsed EF.DG11 (Data Group 11) of an ICAO Doc 9303 eMRTD: additional personal details of the holder
/// beyond the MRZ — the full (unabbreviated) name, personal number, place of birth, permanent address, and
/// similar fields the issuing state optionally records (Doc 9303 Part 10).
/// </summary>
/// <remarks>
/// <para>
/// EF.DG11 (file identifier <c>0x010B</c>, BER-TLV template tag <c>0x6B</c>) is a template of optional
/// data objects, each present only when the issuing state populated it. This type extracts the commonly
/// used character-string fields; a leading tag list (<c>0x5C</c>) and an other-names count (<c>0x02</c>),
/// when present, are informational and are skipped, since every field is self-describing by its own tag.
/// The text is read as ASCII, the encoding the writer produces; fields the file omits are
/// <see langword="null"/>.
/// </para>
/// </remarks>
public sealed class DataGroup11
{
    /// <summary>The eMRTD elementary file identifier of EF.DG11.</summary>
    public const ushort FileIdentifier = 0x010B;

    private const int DataGroupTemplateTag = 0x6B;
    private const int FullNameTag = 0x5F0E;
    private const int PersonalNumberTag = 0x5F10;
    private const int PlaceOfBirthTag = 0x5F11;
    private const int PermanentAddressTag = 0x5F42;
    private const int TelephoneTag = 0x5F12;
    private const int ProfessionTag = 0x5F13;
    private const int TitleTag = 0x5F14;
    private const int PersonalSummaryTag = 0x5F15;


    private DataGroup11(
        string? fullName, string? personalNumber, string? placeOfBirth, string? permanentAddress,
        string? telephone, string? profession, string? title, string? personalSummary)
    {
        FullName = fullName;
        PersonalNumber = personalNumber;
        PlaceOfBirth = placeOfBirth;
        PermanentAddress = permanentAddress;
        Telephone = telephone;
        Profession = profession;
        Title = title;
        PersonalSummary = personalSummary;
    }


    /// <summary>Gets the holder's full (unabbreviated) name (<c>5F0E</c>), or <see langword="null"/> when absent.</summary>
    public string? FullName { get; }

    /// <summary>Gets the holder's personal number (<c>5F10</c>), or <see langword="null"/> when absent.</summary>
    public string? PersonalNumber { get; }

    /// <summary>Gets the holder's place of birth (<c>5F11</c>), or <see langword="null"/> when absent.</summary>
    public string? PlaceOfBirth { get; }

    /// <summary>Gets the holder's permanent address (<c>5F42</c>), or <see langword="null"/> when absent.</summary>
    public string? PermanentAddress { get; }

    /// <summary>Gets the holder's telephone number (<c>5F12</c>), or <see langword="null"/> when absent.</summary>
    public string? Telephone { get; }

    /// <summary>Gets the holder's profession (<c>5F13</c>), or <see langword="null"/> when absent.</summary>
    public string? Profession { get; }

    /// <summary>Gets the holder's title (<c>5F14</c>), or <see langword="null"/> when absent.</summary>
    public string? Title { get; }

    /// <summary>Gets the holder's personal summary (<c>5F15</c>), or <see langword="null"/> when absent.</summary>
    public string? PersonalSummary { get; }


    /// <summary>
    /// Parses an EF.DG11 file, extracting the commonly used character-string fields.
    /// </summary>
    /// <param name="dataGroup11">The DG11 file bytes (the BER-TLV structure beginning with tag <c>0x6B</c>).</param>
    /// <returns>The parsed <see cref="DataGroup11"/>.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the structure is not a well-formed DG11 template.</exception>
    public static DataGroup11 Parse(ReadOnlySpan<byte> dataGroup11)
    {
        var reader = new ApduReader(dataGroup11);
        if(LdsTlv.ReadTag(ref reader) != DataGroupTemplateTag)
        {
            throw new InvalidOperationException("The data is not an EF.DG11 file (expected BER-TLV tag 0x6B).");
        }

        var content = new ApduReader(reader.ReadBytes(reader.ReadTlvLength()));

        string? fullName = null, personalNumber = null, placeOfBirth = null, permanentAddress = null;
        string? telephone = null, profession = null, title = null, personalSummary = null;

        while(!content.IsEmpty)
        {
            int tag = LdsTlv.ReadTag(ref content);
            ReadOnlySpan<byte> value = content.ReadBytes(content.ReadTlvLength());

            switch(tag)
            {
                case FullNameTag: fullName = Encoding.ASCII.GetString(value); break;
                case PersonalNumberTag: personalNumber = Encoding.ASCII.GetString(value); break;
                case PlaceOfBirthTag: placeOfBirth = Encoding.ASCII.GetString(value); break;
                case PermanentAddressTag: permanentAddress = Encoding.ASCII.GetString(value); break;
                case TelephoneTag: telephone = Encoding.ASCII.GetString(value); break;
                case ProfessionTag: profession = Encoding.ASCII.GetString(value); break;
                case TitleTag: title = Encoding.ASCII.GetString(value); break;
                case PersonalSummaryTag: personalSummary = Encoding.ASCII.GetString(value); break;
                default:
                    //The tag list (5C), the other-names count (02), images, and fields a newer minor version
                    //adds are not modelled here; they are skipped so the template still parses.
                    break;
            }
        }

        return new DataGroup11(fullName, personalNumber, placeOfBirth, permanentAddress, telephone, profession, title, personalSummary);
    }


    /// <summary>
    /// Writes an EF.DG11 file from its optional character-string fields — the inverse of <see cref="Parse"/>.
    /// Only the fields supplied (non-<see langword="null"/>) are written, each as an ASCII character string.
    /// </summary>
    /// <param name="fullName">The holder's full name (<c>5F0E</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="personalNumber">The holder's personal number (<c>5F10</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="placeOfBirth">The holder's place of birth (<c>5F11</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="permanentAddress">The holder's permanent address (<c>5F42</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="telephone">The holder's telephone number (<c>5F12</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="profession">The holder's profession (<c>5F13</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="title">The holder's title (<c>5F14</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="personalSummary">The holder's personal summary (<c>5F15</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="pool">The memory pool for the file carrier.</param>
    /// <returns>The EF.DG11 <see cref="ElementaryFile"/>. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ElementaryFile, which the caller disposes; the catch disposes it on failure.")]
    public static ElementaryFile Write(
        string? fullName, string? personalNumber, string? placeOfBirth, string? permanentAddress,
        string? telephone, string? profession, string? title, string? personalSummary,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int contentLength =
            LdsTlv.OptionalElementSize(FullNameTag, fullName)
            + LdsTlv.OptionalElementSize(PersonalNumberTag, personalNumber)
            + LdsTlv.OptionalElementSize(PlaceOfBirthTag, placeOfBirth)
            + LdsTlv.OptionalElementSize(PermanentAddressTag, permanentAddress)
            + LdsTlv.OptionalElementSize(TelephoneTag, telephone)
            + LdsTlv.OptionalElementSize(ProfessionTag, profession)
            + LdsTlv.OptionalElementSize(TitleTag, title)
            + LdsTlv.OptionalElementSize(PersonalSummaryTag, personalSummary);
        int total = BerTlvWriter.ElementSize(DataGroupTemplateTag, contentLength);

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new BerTlvWriter(owner.Memory.Span[..total]);
            writer.WriteHeader(DataGroupTemplateTag, contentLength);
            LdsTlv.WriteOptionalAscii(ref writer, FullNameTag, fullName);
            LdsTlv.WriteOptionalAscii(ref writer, PersonalNumberTag, personalNumber);
            LdsTlv.WriteOptionalAscii(ref writer, PlaceOfBirthTag, placeOfBirth);
            LdsTlv.WriteOptionalAscii(ref writer, PermanentAddressTag, permanentAddress);
            LdsTlv.WriteOptionalAscii(ref writer, TelephoneTag, telephone);
            LdsTlv.WriteOptionalAscii(ref writer, ProfessionTag, profession);
            LdsTlv.WriteOptionalAscii(ref writer, TitleTag, title);
            LdsTlv.WriteOptionalAscii(ref writer, PersonalSummaryTag, personalSummary);

            return new ElementaryFile(owner, FileIdentifier);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }
}
