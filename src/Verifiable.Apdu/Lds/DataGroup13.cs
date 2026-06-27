using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The parsed EF.DG13 (Data Group 13) of an ICAO Doc 9303 eMRTD: optional details in a free, issuing-state
/// defined format (Doc 9303 Part 10). Because the content is country-specific, this type exposes it verbatim
/// as a tracked carrier rather than interpreting its structure.
/// </summary>
/// <remarks>
/// <para>
/// EF.DG13 (file identifier <c>0x010D</c>, BER-TLV template tag <c>0x6D</c>) wraps a free-format value the
/// issuing state defines. This type carries that inner content (the value of the <c>0x6D</c> template)
/// verbatim, tagged <see cref="ApduTags.OptionalDetails"/>; interpreting it is an issuing-state concern.
/// </para>
/// </remarks>
[DebuggerDisplay("DataGroup13(OptionalDetails, {Length} bytes)")]
public sealed class DataGroup13: SensitiveMemory
{
    /// <summary>The eMRTD elementary file identifier of EF.DG13.</summary>
    public const ushort FileIdentifier = 0x010D;

    private const int DataGroupTemplateTag = 0x6D;


    private DataGroup13(IMemoryOwner<byte> content)
        : base(content, ApduTags.OptionalDetails)
    {
    }


    /// <summary>Gets the length of the free-format content in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Parses an EF.DG13 file, exposing its free-format content verbatim.
    /// </summary>
    /// <param name="dataGroup13">The DG13 file bytes (the BER-TLV structure beginning with tag <c>0x6D</c>).</param>
    /// <param name="pool">The memory pool for the content carrier.</param>
    /// <returns>The parsed <see cref="DataGroup13"/>. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the structure is not a well-formed DG13 template.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented content buffer transfers to the returned DataGroup13, which the caller disposes; the catch disposes it on failure.")]
    public static DataGroup13 Parse(ReadOnlySpan<byte> dataGroup13, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var reader = new ApduReader(dataGroup13);
        if(LdsTlv.ReadTag(ref reader) != DataGroupTemplateTag)
        {
            throw new InvalidOperationException("The data is not an EF.DG13 file (expected BER-TLV tag 0x6D).");
        }

        ReadOnlySpan<byte> content = reader.ReadBytes(reader.ReadTlvLength());

        IMemoryOwner<byte> owner = pool.Rent(content.Length);
        try
        {
            content.CopyTo(owner.Memory.Span);

            return new DataGroup13(owner);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Writes an EF.DG13 file wrapping free-format content — the inverse of <see cref="Parse"/>.
    /// </summary>
    /// <param name="content">The free-format optional-details content the issuing state defines.</param>
    /// <param name="pool">The memory pool for the file carrier.</param>
    /// <returns>The EF.DG13 <see cref="ElementaryFile"/>. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ElementaryFile, which the caller disposes; the catch disposes it on failure.")]
    public static ElementaryFile Write(ReadOnlySpan<byte> content, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int total = BerTlvWriter.ElementSize(DataGroupTemplateTag, content.Length);

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new BerTlvWriter(owner.Memory.Span[..total]);
            writer.WriteElement(DataGroupTemplateTag, content);

            return new ElementaryFile(owner, FileIdentifier);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }
}
