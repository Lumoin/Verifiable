using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The Common Biometric Exchange Formats Framework (CBEFF) template ICAO Doc 9303 Part 10 wraps every
/// biometric data group in — EF.DG2 (face), EF.DG3 (finger), and EF.DG4 (iris). The wrappers are identical
/// across the three; only the data-group template tag and the inner biometric record differ. This helper
/// extracts the first biometric record from the wrappers and writes them around a record, so the data-group
/// types share one implementation of the framing.
/// </summary>
/// <remarks>
/// <para>
/// The nesting, per Doc 9303 Part 10: the data-group template (<c>0x75</c>/<c>0x63</c>/<c>0x76</c>) holds a
/// Biometric Information Group Template (<c>7F61</c>) carrying an instance count (<c>0x02</c>) and one or
/// more Biometric Information Templates (<c>7F60</c>); each holds a Biometric Header Template (<c>A1</c>)
/// and a biometric data block (<c>5F2E</c> or <c>7F2E</c>) — the ISO/IEC 19794 record. This helper reads the
/// first instance's record; multi-instance groups expose only their first record here.
/// </para>
/// </remarks>
internal static class CbeffBiometricTemplate
{
    /// <summary>Biometric Information Group Template tag (the outer CBEFF wrapper).</summary>
    private const int BiometricInformationGroupTemplateTag = 0x7F61;

    /// <summary>The number-of-instances element tag.</summary>
    private const int InstanceCountTag = 0x02;

    /// <summary>Biometric Information Template tag (one per stored biometric instance).</summary>
    private const int BiometricInformationTemplateTag = 0x7F60;

    /// <summary>Biometric Header Template tag.</summary>
    private const int BiometricHeaderTemplateTag = 0xA1;

    /// <summary>Biometric data block tag (primitive form).</summary>
    private const int BiometricDataTag = 0x5F2E;

    /// <summary>Biometric data block tag (constructed form).</summary>
    private const int BiometricDataConstructedTag = 0x7F2E;

    /// <summary>A minimal Biometric Header Template; Passive Authentication skips it, so the writer emits a placeholder.</summary>
    private static readonly byte[] BiometricHeaderPlaceholder = [0x80, 0x01, 0x00];


    /// <summary>
    /// Extracts the first biometric data record (the ISO/IEC 19794 record) from a CBEFF-wrapped data group.
    /// </summary>
    /// <param name="dataGroup">The data-group file bytes (beginning with <paramref name="dataGroupTemplateTag"/>).</param>
    /// <param name="dataGroupTemplateTag">The data-group template tag (<c>0x75</c> DG2, <c>0x63</c> DG3, <c>0x76</c> DG4).</param>
    /// <param name="dataGroupName">A short name for the data group, used in error messages.</param>
    /// <returns>The biometric record bytes (a view into <paramref name="dataGroup"/>).</returns>
    /// <exception cref="InvalidOperationException">Thrown when the structure is not a well-formed CBEFF template.</exception>
    public static ReadOnlySpan<byte> ExtractFirstBiometricData(ReadOnlySpan<byte> dataGroup, int dataGroupTemplateTag, string dataGroupName)
    {
        //A single reader over the whole data group is used so its Consumed count is the absolute offset of
        //the record within dataGroup; the record is then returned as a slice of dataGroup (escape-safe), not
        //as a slice of a nested ref-struct reader. Each level is the first child of its parent, so descending
        //is just "read this tag, read its length, continue"; the instance count and header template are
        //siblings that precede the record and are skipped.
        var reader = new ApduReader(dataGroup);
        DescendInto(ref reader, dataGroupTemplateTag, $"{dataGroupName} template");
        DescendInto(ref reader, BiometricInformationGroupTemplateTag, "biometric information group template");
        SkipElement(ref reader, InstanceCountTag, "instance count");
        DescendInto(ref reader, BiometricInformationTemplateTag, "biometric information template");
        SkipElement(ref reader, BiometricHeaderTemplateTag, "biometric header template");

        int dataTag = ReadTag(ref reader);
        if(dataTag != BiometricDataTag && dataTag != BiometricDataConstructedTag)
        {
            throw new InvalidOperationException($"{dataGroupName} has no biometric data block (expected tag 0x5F2E or 0x7F2E, found 0x{dataTag:X}).");
        }

        int recordLength = reader.ReadTlvLength();
        int recordOffset = reader.Consumed;

        //Compare by subtraction, never `recordOffset + recordLength` (which can overflow int to a negative value
        //that slips past the guard). recordOffset is a position within dataGroup, so the right side is non-negative.
        if(recordLength > dataGroup.Length - recordOffset)
        {
            throw new InvalidOperationException($"{dataGroupName} biometric data block length {recordLength} exceeds the data group.");
        }

        return dataGroup.Slice(recordOffset, recordLength);
    }


    /// <summary>
    /// Writes a single-instance CBEFF data group wrapping <paramref name="biometricRecord"/> — the inverse of
    /// <see cref="ExtractFirstBiometricData"/>, with a placeholder Biometric Header Template.
    /// </summary>
    /// <param name="dataGroupTemplateTag">The data-group template tag (<c>0x75</c> DG2, <c>0x63</c> DG3, <c>0x76</c> DG4).</param>
    /// <param name="biometricRecord">The ISO/IEC 19794 biometric record to wrap.</param>
    /// <param name="fileIdentifier">The elementary file identifier of the data group.</param>
    /// <param name="pool">The memory pool for the file carrier.</param>
    /// <returns>The data-group <see cref="ElementaryFile"/>. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ElementaryFile, which the caller disposes; the catch disposes it on failure.")]
    public static ElementaryFile Write(int dataGroupTemplateTag, ReadOnlySpan<byte> biometricRecord, ushort fileIdentifier, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int biometricTemplateContent =
            BerTlvWriter.ElementSize(BiometricHeaderTemplateTag, BiometricHeaderPlaceholder.Length)
            + BerTlvWriter.ElementSize(BiometricDataTag, biometricRecord.Length);
        int groupTemplateContent =
            BerTlvWriter.ElementSize(InstanceCountTag, 1)
            + BerTlvWriter.ElementSize(BiometricInformationTemplateTag, biometricTemplateContent);
        int dataGroupContent = BerTlvWriter.ElementSize(BiometricInformationGroupTemplateTag, groupTemplateContent);
        int total = BerTlvWriter.ElementSize(dataGroupTemplateTag, dataGroupContent);

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new BerTlvWriter(owner.Memory.Span[..total]);
            writer.WriteHeader(dataGroupTemplateTag, dataGroupContent);
            writer.WriteHeader(BiometricInformationGroupTemplateTag, groupTemplateContent);
            writer.WriteElement(InstanceCountTag, [0x01]);
            writer.WriteHeader(BiometricInformationTemplateTag, biometricTemplateContent);
            writer.WriteElement(BiometricHeaderTemplateTag, BiometricHeaderPlaceholder);
            writer.WriteElement(BiometricDataTag, biometricRecord);

            return new ElementaryFile(owner, fileIdentifier);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Descends into a constructed element of the expected tag: reads and checks the tag and reads its
    /// length, leaving the reader positioned at the element's content (its first child).
    /// </summary>
    private static void DescendInto(ref ApduReader reader, int expectedTag, string elementName)
    {
        if(ReadTag(ref reader) != expectedTag)
        {
            throw new InvalidOperationException($"Expected a {elementName} element (tag 0x{expectedTag:X}).");
        }

        _ = reader.ReadTlvLength();
    }


    /// <summary>
    /// Skips an element of the expected tag.
    /// </summary>
    private static void SkipElement(ref ApduReader reader, int expectedTag, string elementName)
    {
        if(ReadTag(ref reader) != expectedTag)
        {
            throw new InvalidOperationException($"Expected a {elementName} element (tag 0x{expectedTag:X}).");
        }

        reader.Skip(reader.ReadTlvLength());
    }


    /// <summary>
    /// Reads a BER-TLV tag, which is two bytes when the low five bits of the first byte are all set.
    /// </summary>
    private static int ReadTag(ref ApduReader reader)
    {
        int tag = reader.ReadByte();
        if((tag & 0x1F) == 0x1F)
        {
            tag = (tag << 8) | reader.ReadByte();
        }

        return tag;
    }
}
