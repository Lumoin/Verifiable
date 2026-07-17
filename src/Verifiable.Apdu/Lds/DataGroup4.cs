using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The parsed EF.DG4 (Data Group 4) of an ICAO Doc 9303 eMRTD: the holder's iris biometrics, stored in a
/// CBEFF-wrapped ISO/IEC 19794-6 iris image record and authenticated by EF.SOD. DG4 is sensitive and is
/// normally readable only after Extended Access Control (Terminal Authentication).
/// </summary>
/// <remarks>
/// <para>
/// DG4 (file identifier <c>0x0104</c>, BER-TLV template tag <c>0x76</c>) shares the CBEFF wrappers of EF.DG2
/// (Doc 9303 Part 10); only the data-group tag and the inner record differ. This type extracts the first
/// biometric record into a <see cref="BiometricDataBlock"/> and validates its ISO/IEC 19794-6 format
/// identifier (<c>"IIR\0"</c>); decoding the individual iris images within the record is a biometric-library
/// concern.
/// </para>
/// </remarks>
public sealed class DataGroup4: IDisposable
{
    /// <summary>The eMRTD elementary file identifier of EF.DG4.</summary>
    public const ushort FileIdentifier = 0x0104;

    private const int DataGroupTemplateTag = 0x76;

    //ISO/IEC 19794-6 iris image record format identifier: "IIR\0".
    private static byte[] IrisRecordFormatIdentifier { get; } = [0x49, 0x49, 0x52, 0x00];

    private bool disposed;


    private DataGroup4(BiometricDataBlock biometricData)
    {
        BiometricData = biometricData;
    }


    /// <summary>Gets the holder's iris biometric record. Owned by this data group.</summary>
    public BiometricDataBlock BiometricData { get; }


    /// <summary>
    /// Parses an EF.DG4 file, extracting the first ISO/IEC 19794-6 iris record into a
    /// <see cref="BiometricDataBlock"/>.
    /// </summary>
    /// <param name="dataGroup4">The DG4 file bytes (the BER-TLV structure beginning with tag <c>0x76</c>).</param>
    /// <param name="pool">The memory pool for the record carrier.</param>
    /// <returns>The parsed <see cref="DataGroup4"/>. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the structure is not a well-formed DG4.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the BiometricDataBlock carrier transfers to the returned DataGroup4, which the caller disposes.")]
    public static DataGroup4 Parse(ReadOnlySpan<byte> dataGroup4, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ReadOnlySpan<byte> record = CbeffBiometricTemplate.ExtractFirstBiometricData(dataGroup4, DataGroupTemplateTag, "DG4");
        if(record.Length < IrisRecordFormatIdentifier.Length || !record[..IrisRecordFormatIdentifier.Length].SequenceEqual(IrisRecordFormatIdentifier))
        {
            throw new InvalidOperationException("DG4 does not carry an ISO/IEC 19794-6 iris image record.");
        }

        return new DataGroup4(BiometricDataBlock.FromBytes(record, BiometricModality.Iris, pool));
    }


    /// <summary>
    /// Writes an EF.DG4 file wrapping an iris image record — the inverse of <see cref="Parse"/>. The record
    /// is placed in the CBEFF <c>76</c> / <c>7F61</c> / <c>7F60</c> / <c>A1</c> / <c>5F2E</c> wrappers.
    /// </summary>
    /// <param name="irisRecord">The ISO/IEC 19794-6 iris image record (beginning with <c>"IIR\0"</c>).</param>
    /// <param name="pool">The memory pool for the file carrier.</param>
    /// <returns>The EF.DG4 <see cref="ElementaryFile"/>. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the record lacks the ISO/IEC 19794-6 format identifier.</exception>
    public static ElementaryFile Write(ReadOnlySpan<byte> irisRecord, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(irisRecord.Length < IrisRecordFormatIdentifier.Length || !irisRecord[..IrisRecordFormatIdentifier.Length].SequenceEqual(IrisRecordFormatIdentifier))
        {
            throw new InvalidOperationException("A DG4 iris record must begin with the ISO/IEC 19794-6 format identifier \"IIR\\0\".");
        }

        return CbeffBiometricTemplate.Write(DataGroupTemplateTag, irisRecord, FileIdentifier, pool);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            BiometricData.Dispose();
            disposed = true;
        }
    }
}