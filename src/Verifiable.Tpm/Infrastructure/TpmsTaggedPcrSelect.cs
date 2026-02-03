using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Structures;

/// <summary>
/// Tagged PCR selection structure (TPMS_TAGGED_PCR_SELECT).
/// </summary>
/// <remarks>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM_PT_PCR tag;               // PCR property tag (4 bytes).
///     UINT8 sizeofSelect;           // Size of pcrSelect array (1 byte).
///     BYTE pcrSelect[sizeofSelect]; // Bitmap of PCRs with this property.
/// } TPMS_TAGGED_PCR_SELECT;
/// </code>
/// <para>
/// <b>Content:</b> Associates a PCR property (like "resettable" or "extendable")
/// with a bitmap of PCR indices that have that property.
/// </para>
/// </remarks>
/// <seealso cref="TpmPcrPropertiesData"/>
[DebuggerDisplay("{Tag}: {PcrSelect.Size * 8} PCRs")]
public readonly struct TpmsTaggedPcrSelect: IEquatable<TpmsTaggedPcrSelect>
{
    /// <summary>
    /// Gets the PCR property tag.
    /// </summary>
    public TpmPtPcrConstants Tag { get; }

    /// <summary>
    /// Gets the PCR selection bitmap.
    /// </summary>
    /// <remarks>
    /// Each bit represents one PCR. A set bit indicates the PCR has the property
    /// specified by <see cref="Tag"/>.
    /// </remarks>
    public ReadOnlyMemory<byte> PcrSelect { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="TpmsTaggedPcrSelect"/> struct.
    /// </summary>
    /// <param name="tag">The PCR property tag.</param>
    /// <param name="pcrSelect">The PCR selection bitmap.</param>
    public TpmsTaggedPcrSelect(TpmPtPcrConstants tag, ReadOnlyMemory<byte> pcrSelect)
    {
        Tag = tag;
        PcrSelect = pcrSelect;
    }

    /// <summary>
    /// Checks if a specific PCR index has this property.
    /// </summary>
    /// <param name="pcrIndex">The PCR index (0-based).</param>
    /// <returns><c>true</c> if the PCR has this property; otherwise, <c>false</c>.</returns>
    public bool HasProperty(int pcrIndex)
    {
        int byteIndex = pcrIndex / 8;
        int bitIndex = pcrIndex % 8;

        if(byteIndex >= PcrSelect.Length)
        {
            return false;
        }

        return (PcrSelect.Span[byteIndex] & (1 << bitIndex)) != 0;
    }

    /// <summary>
    /// Parses an instance from a byte buffer.
    /// </summary>
    /// <param name="source">The source bytes.</param>
    /// <returns>The parsed value and number of bytes consumed.</returns>
    public static TpmParseResult<TpmsTaggedPcrSelect> Parse(ReadOnlySpan<byte> source)
    {
        var reader = new TpmReader(source);
        uint tag = reader.ReadUInt32();
        byte sizeofSelect = reader.ReadByte();
        ReadOnlySpan<byte> pcrSelect = reader.ReadBytes(sizeofSelect);

        return new TpmParseResult<TpmsTaggedPcrSelect>(
            new TpmsTaggedPcrSelect((TpmPtPcrConstants)tag, pcrSelect.ToArray()),
            reader.Consumed);
    }

    /// <inheritdoc/>
    public bool Equals(TpmsTaggedPcrSelect other)
    {
        return Tag == other.Tag &&
               PcrSelect.Span.SequenceEqual(other.PcrSelect.Span);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is TpmsTaggedPcrSelect other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Tag);
        hash.AddBytes(PcrSelect.Span);
        return hash.ToHashCode();
    }

    /// <summary>
    /// Determines whether two instances are equal.
    /// </summary>
    public static bool operator ==(TpmsTaggedPcrSelect left, TpmsTaggedPcrSelect right) => left.Equals(right);

    /// <summary>
    /// Determines whether two instances are not equal.
    /// </summary>
    public static bool operator !=(TpmsTaggedPcrSelect left, TpmsTaggedPcrSelect right) => !left.Equals(right);
}