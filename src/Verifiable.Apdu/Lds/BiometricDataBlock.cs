using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The biometric modality of a CBEFF-wrapped data record.
/// </summary>
public enum BiometricModality
{
    /// <summary>A finger image record (ISO/IEC 19794-4), carried in EF.DG3.</summary>
    Finger,

    /// <summary>An iris image record (ISO/IEC 19794-6), carried in EF.DG4.</summary>
    Iris
}


/// <summary>
/// The bytes of a CBEFF-wrapped biometric data record extracted from EF.DG3 (finger) or EF.DG4 (iris) —
/// the ISO/IEC 19794-4 / 19794-6 record the chip stores inside the Common Biometric Exchange Formats
/// Framework wrappers. A tracked carrier rather than a naked buffer: it owns its pooled memory, clears it
/// on disposal, and carries <see cref="ApduTags.BiometricRecord"/> for provenance.
/// </summary>
/// <remarks>
/// <para>
/// This carries the inner biometric record verbatim; decoding the finger or iris images it contains is a
/// biometric-library concern. The <see cref="Modality"/> records which biometric the record holds, and the
/// first four bytes are the ISO/IEC 19794 format identifier (<c>"FIR\0"</c> for finger, <c>"IIR\0"</c> for
/// iris), validated by <see cref="DataGroup3"/> / <see cref="DataGroup4"/> on parse.
/// </para>
/// </remarks>
[DebuggerDisplay("BiometricDataBlock({Modality}, {Length} bytes)")]
public sealed class BiometricDataBlock: SensitiveMemory
{
    /// <summary>
    /// Initialises a new <see cref="BiometricDataBlock"/> from owned record bytes.
    /// </summary>
    /// <param name="storage">The owned, exact-size buffer holding the biometric record. Ownership transfers to this instance.</param>
    /// <param name="modality">The biometric modality the record holds.</param>
    public BiometricDataBlock(IMemoryOwner<byte> storage, BiometricModality modality)
        : base(storage, ApduTags.BiometricRecord)
    {
        ArgumentNullException.ThrowIfNull(storage);
        Modality = modality;
    }


    /// <summary>Gets the biometric modality the record holds.</summary>
    public BiometricModality Modality { get; }

    /// <summary>Gets the length of the biometric record in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Copies <paramref name="bytes"/> into a pooled <see cref="BiometricDataBlock"/>.
    /// </summary>
    public static BiometricDataBlock FromBytes(ReadOnlySpan<byte> bytes, BiometricModality modality, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new BiometricDataBlock(owner, modality);
    }
}
