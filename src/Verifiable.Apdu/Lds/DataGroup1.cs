using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Apdu.Mrz;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The parsed EF.DG1 (Data Group 1) of an ICAO Doc 9303 eMRTD: the Machine Readable Zone, the same
/// data printed on the document's data page, stored on the chip and authenticated by EF.SOD.
/// </summary>
/// <remarks>
/// <para>
/// DG1 (file identifier <c>0x0101</c>, BER-TLV template tag <c>0x61</c>) wraps a single data element,
/// <c>0x5F1F</c>, holding the raw MRZ characters (TD1, TD2, or TD3). This type strips the wrappers and
/// parses the characters through <see cref="MachineReadableZone"/>, so the document number, dates, and
/// other fields — and thus the BAC / PACE access-key check — come straight from the chip's own copy.
/// </para>
/// </remarks>
public sealed class DataGroup1
{
    /// <summary>The eMRTD elementary file identifier of EF.DG1.</summary>
    public const ushort FileIdentifier = 0x0101;

    /// <summary>BER-TLV template tag for DG1.</summary>
    private const int DataGroupTemplateTag = 0x61;

    /// <summary>BER-TLV tag for the MRZ data element within DG1.</summary>
    private const int MachineReadableZoneTag = 0x5F1F;


    private DataGroup1(MachineReadableZone machineReadableZone)
    {
        MachineReadableZone = machineReadableZone;
    }


    /// <summary>Gets the Machine Readable Zone parsed from the data group.</summary>
    public MachineReadableZone MachineReadableZone { get; }


    /// <summary>
    /// Parses an EF.DG1 file.
    /// </summary>
    /// <param name="dataGroup1">The DG1 file bytes (the BER-TLV structure beginning with tag <c>0x61</c>).</param>
    /// <returns>The parsed <see cref="DataGroup1"/>.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the structure is not a well-formed DG1.</exception>
    public static DataGroup1 Parse(ReadOnlySpan<byte> dataGroup1)
    {
        var reader = new ApduReader(dataGroup1);
        if(ReadTag(ref reader) != DataGroupTemplateTag)
        {
            throw new InvalidOperationException("The data is not an EF.DG1 file (expected BER-TLV tag 0x61).");
        }

        int templateLength = reader.ReadTlvLength();
        var content = new ApduReader(reader.ReadBytes(templateLength));

        if(ReadTag(ref content) != MachineReadableZoneTag)
        {
            throw new InvalidOperationException("EF.DG1 does not carry an MRZ data element (expected BER-TLV tag 0x5F1F).");
        }

        int mrzLength = content.ReadTlvLength();
        ReadOnlySpan<byte> mrz = content.ReadBytes(mrzLength);

        return new DataGroup1(MachineReadableZone.Parse(Encoding.ASCII.GetString(mrz)));
    }


    /// <summary>
    /// Writes an EF.DG1 file wrapping an MRZ — the inverse of <see cref="Parse"/>.
    /// </summary>
    /// <param name="machineReadableZone">The MRZ characters (TD1 90, TD2 72, or TD3 88 characters).</param>
    /// <param name="pool">The memory pool for the file carrier.</param>
    /// <returns>The EF.DG1 <see cref="ElementaryFile"/>. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ElementaryFile, which the caller disposes; the catch disposes it on failure.")]
    public static ElementaryFile Write(string machineReadableZone, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(machineReadableZone);
        ArgumentNullException.ThrowIfNull(pool);

        int contentLength = BerTlvWriter.ElementSize(MachineReadableZoneTag, machineReadableZone.Length);
        int total = BerTlvWriter.ElementSize(DataGroupTemplateTag, contentLength);

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new BerTlvWriter(owner.Memory.Span[..total]);
            writer.WriteHeader(DataGroupTemplateTag, contentLength);
            writer.WriteHeader(MachineReadableZoneTag, machineReadableZone.Length);
            writer.WriteAscii(machineReadableZone);

            return new ElementaryFile(owner, FileIdentifier);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
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
