using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// A person the holder asks to be notified in an emergency, recorded in EF.DG16 (Doc 9303 Part 10): a date
/// of record and the person's name, telephone, and address, each optional.
/// </summary>
/// <param name="DateOfRecord">The date the record was made (<c>5F50</c>, <c>YYYYMMDD</c>), or <see langword="null"/> when absent.</param>
/// <param name="Name">The person's name (<c>5F51</c>), or <see langword="null"/> when absent.</param>
/// <param name="Telephone">The person's telephone number (<c>5F52</c>), or <see langword="null"/> when absent.</param>
/// <param name="Address">The person's address (<c>5F53</c>), or <see langword="null"/> when absent.</param>
public sealed record PersonToNotify(string? DateOfRecord, string? Name, string? Telephone, string? Address);


/// <summary>
/// The parsed EF.DG16 (Data Group 16) of an ICAO Doc 9303 eMRTD: the persons to notify in an emergency — a
/// count followed by one template per person (Doc 9303 Part 10).
/// </summary>
/// <remarks>
/// <para>
/// EF.DG16 (file identifier <c>0x0110</c>, BER-TLV template tag <c>0x70</c>) carries a count object
/// (<c>0x02</c>) and one person template (<c>0xA1</c>) each, holding the date of record and the person's
/// name, telephone, and address as ASCII character strings. The count is recomputed from the templates on
/// parse, so it need not be relied on.
/// </para>
/// </remarks>
public sealed class DataGroup16
{
    /// <summary>The eMRTD elementary file identifier of EF.DG16.</summary>
    public const ushort FileIdentifier = 0x0110;

    private const int DataGroupTemplateTag = 0x70;
    private const int CountTag = 0x02;
    private const int PersonTemplateTag = 0xA1;
    private const int DateOfRecordTag = 0x5F50;
    private const int NameTag = 0x5F51;
    private const int TelephoneTag = 0x5F52;
    private const int AddressTag = 0x5F53;


    private DataGroup16(IReadOnlyList<PersonToNotify> personsToNotify)
    {
        PersonsToNotify = personsToNotify;
    }


    /// <summary>Gets the persons to notify, in the order EF.DG16 lists them.</summary>
    public IReadOnlyList<PersonToNotify> PersonsToNotify { get; }


    /// <summary>
    /// Parses an EF.DG16 file into its list of persons to notify.
    /// </summary>
    /// <param name="dataGroup16">The DG16 file bytes (the BER-TLV structure beginning with tag <c>0x70</c>).</param>
    /// <returns>The parsed <see cref="DataGroup16"/>.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the structure is not a well-formed DG16 template.</exception>
    public static DataGroup16 Parse(ReadOnlySpan<byte> dataGroup16)
    {
        var reader = new ApduReader(dataGroup16);
        if(LdsTlv.ReadTag(ref reader) != DataGroupTemplateTag)
        {
            throw new InvalidOperationException("The data is not an EF.DG16 file (expected BER-TLV tag 0x70).");
        }

        var content = new ApduReader(reader.ReadBytes(reader.ReadTlvLength()));
        var persons = new List<PersonToNotify>();
        while(!content.IsEmpty)
        {
            int tag = LdsTlv.ReadTag(ref content);
            ReadOnlySpan<byte> value = content.ReadBytes(content.ReadTlvLength());
            if(tag == PersonTemplateTag)
            {
                persons.Add(ParsePerson(value));
            }

            //The count object (02) is recomputed from the templates, so it is skipped.
        }

        return new DataGroup16(persons);
    }


    /// <summary>
    /// Parses one person template (<c>0xA1</c>) into a <see cref="PersonToNotify"/>.
    /// </summary>
    private static PersonToNotify ParsePerson(ReadOnlySpan<byte> personTemplate)
    {
        var reader = new ApduReader(personTemplate);
        string? dateOfRecord = null, name = null, telephone = null, address = null;
        while(!reader.IsEmpty)
        {
            int tag = LdsTlv.ReadTag(ref reader);
            ReadOnlySpan<byte> value = reader.ReadBytes(reader.ReadTlvLength());
            switch(tag)
            {
                case DateOfRecordTag: dateOfRecord = Encoding.ASCII.GetString(value); break;
                case NameTag: name = Encoding.ASCII.GetString(value); break;
                case TelephoneTag: telephone = Encoding.ASCII.GetString(value); break;
                case AddressTag: address = Encoding.ASCII.GetString(value); break;
                default:
                    //Fields a newer minor version adds are skipped.
                    break;
            }
        }

        return new PersonToNotify(dateOfRecord, name, telephone, address);
    }


    /// <summary>
    /// Writes an EF.DG16 file from a list of persons to notify — the inverse of <see cref="Parse"/>. Only the
    /// supplied fields of each person are written, each as an ASCII character string.
    /// </summary>
    /// <param name="personsToNotify">The persons to notify (at most 255).</param>
    /// <param name="pool">The memory pool for the file carrier.</param>
    /// <returns>The EF.DG16 <see cref="ElementaryFile"/>. The caller disposes it.</returns>
    /// <exception cref="ArgumentException">Thrown when more than 255 persons are supplied (the single-octet count cannot encode them).</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ElementaryFile, which the caller disposes; the catch disposes it on failure.")]
    public static ElementaryFile Write(IReadOnlyList<PersonToNotify> personsToNotify, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(personsToNotify);
        ArgumentNullException.ThrowIfNull(pool);
        if(personsToNotify.Count > 0xFF)
        {
            throw new ArgumentException("EF.DG16 models at most 255 persons to notify.", nameof(personsToNotify));
        }

        int contentLength = BerTlvWriter.ElementSize(CountTag, 1);
        foreach(PersonToNotify person in personsToNotify)
        {
            contentLength += BerTlvWriter.ElementSize(PersonTemplateTag, PersonContentLength(person));
        }

        int total = BerTlvWriter.ElementSize(DataGroupTemplateTag, contentLength);

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new BerTlvWriter(owner.Memory.Span[..total]);
            writer.WriteHeader(DataGroupTemplateTag, contentLength);
            writer.WriteElement(CountTag, [(byte)personsToNotify.Count]);
            foreach(PersonToNotify person in personsToNotify)
            {
                writer.WriteHeader(PersonTemplateTag, PersonContentLength(person));
                LdsTlv.WriteOptionalAscii(ref writer, DateOfRecordTag, person.DateOfRecord);
                LdsTlv.WriteOptionalAscii(ref writer, NameTag, person.Name);
                LdsTlv.WriteOptionalAscii(ref writer, TelephoneTag, person.Telephone);
                LdsTlv.WriteOptionalAscii(ref writer, AddressTag, person.Address);
            }

            return new ElementaryFile(owner, FileIdentifier);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// The encoded content length of one person template — the sum of its present fields' element sizes.
    /// </summary>
    private static int PersonContentLength(PersonToNotify person) =>
        LdsTlv.OptionalElementSize(DateOfRecordTag, person.DateOfRecord)
        + LdsTlv.OptionalElementSize(NameTag, person.Name)
        + LdsTlv.OptionalElementSize(TelephoneTag, person.Telephone)
        + LdsTlv.OptionalElementSize(AddressTag, person.Address);
}
