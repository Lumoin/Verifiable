using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The parsed EF.DG3 (Data Group 3) of an ICAO Doc 9303 eMRTD: the holder's fingerprint biometrics, stored
/// in a CBEFF-wrapped ISO/IEC 19794-4 finger image record and authenticated by EF.SOD. DG3 is sensitive and
/// is normally readable only after Extended Access Control (Terminal Authentication).
/// </summary>
/// <remarks>
/// <para>
/// DG3 (file identifier <c>0x0103</c>, BER-TLV template tag <c>0x63</c>) shares the CBEFF wrappers of EF.DG2
/// (Doc 9303 Part 10); only the data-group tag and the inner record differ. This type extracts the first
/// biometric record into a <see cref="BiometricDataBlock"/> and validates its ISO/IEC 19794-4 format
/// identifier (<c>"FIR\0"</c>); decoding the individual finger images within the record is a biometric-library
/// concern.
/// </para>
/// </remarks>
public sealed class DataGroup3: IDisposable
{
    /// <summary>The eMRTD elementary file identifier of EF.DG3.</summary>
    public const ushort FileIdentifier = 0x0103;

    private const int DataGroupTemplateTag = 0x63;

    //ISO/IEC 19794-4 finger image record format identifier: "FIR\0".
    private static byte[] FingerRecordFormatIdentifier { get; } = [0x46, 0x49, 0x52, 0x00];

    private bool disposed;


    private DataGroup3(BiometricDataBlock biometricData)
    {
        BiometricData = biometricData;
    }


    /// <summary>Gets the holder's fingerprint biometric record. Owned by this data group.</summary>
    public BiometricDataBlock BiometricData { get; }


    /// <summary>
    /// Parses an EF.DG3 file, extracting the first ISO/IEC 19794-4 finger record into a
    /// <see cref="BiometricDataBlock"/>.
    /// </summary>
    /// <param name="dataGroup3">The DG3 file bytes (the BER-TLV structure beginning with tag <c>0x63</c>).</param>
    /// <param name="pool">The memory pool for the record carrier.</param>
    /// <returns>The parsed <see cref="DataGroup3"/>. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the structure is not a well-formed DG3.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the BiometricDataBlock carrier transfers to the returned DataGroup3, which the caller disposes.")]
    public static DataGroup3 Parse(ReadOnlySpan<byte> dataGroup3, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ReadOnlySpan<byte> record = CbeffBiometricTemplate.ExtractFirstBiometricData(dataGroup3, DataGroupTemplateTag, "DG3");
        if(record.Length < FingerRecordFormatIdentifier.Length || !record[..FingerRecordFormatIdentifier.Length].SequenceEqual(FingerRecordFormatIdentifier))
        {
            throw new InvalidOperationException("DG3 does not carry an ISO/IEC 19794-4 finger image record.");
        }

        return new DataGroup3(BiometricDataBlock.FromBytes(record, BiometricModality.Finger, pool));
    }


    /// <summary>
    /// Writes an EF.DG3 file wrapping a finger image record — the inverse of <see cref="Parse"/>. The record
    /// is placed in the CBEFF <c>63</c> / <c>7F61</c> / <c>7F60</c> / <c>A1</c> / <c>5F2E</c> wrappers.
    /// </summary>
    /// <param name="fingerRecord">The ISO/IEC 19794-4 finger image record (beginning with <c>"FIR\0"</c>).</param>
    /// <param name="pool">The memory pool for the file carrier.</param>
    /// <returns>The EF.DG3 <see cref="ElementaryFile"/>. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the record lacks the ISO/IEC 19794-4 format identifier.</exception>
    public static ElementaryFile Write(ReadOnlySpan<byte> fingerRecord, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(fingerRecord.Length < FingerRecordFormatIdentifier.Length || !fingerRecord[..FingerRecordFormatIdentifier.Length].SequenceEqual(FingerRecordFormatIdentifier))
        {
            throw new InvalidOperationException("A DG3 finger record must begin with the ISO/IEC 19794-4 format identifier \"FIR\\0\".");
        }

        return CbeffBiometricTemplate.Write(DataGroupTemplateTag, fingerRecord, FileIdentifier, pool);
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