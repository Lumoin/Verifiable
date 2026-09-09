using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// TPM2B_ECC_POINT — a <see cref="TpmsEccPoint"/> framed as a single sized parameter.
/// </summary>
/// <remarks>
/// <para>
/// "This Table 199 structure is defined to allow a point to be a single sized parameter so that it may be
/// encrypted." (TPM 2.0 Library Part 2, clause 11.2.5.3, Table 199). "If the point is to be omitted, the X and Y
/// coordinates need to be individually set to Empty Buffers. The minimum value for size will be four. It is
/// checked indirectly by unmarshaling of the TPMS_ECC_POINT. If the type of point were BYTE, then size could have
/// been zero. However, this would complicate the process of marshaling the structure." (clause 11.2.5.3) — so a
/// <c>size</c> field of zero names a MISSING structure, never an omitted point (an omitted point is instead the
/// inner <see cref="TpmsEccPoint.Empty"/>, whose own two zero-length <c>TPM2B_ECC_PARAMETER</c> coordinates still
/// occupy four octets).
/// </para>
/// <para>
/// <b>Wire format (big-endian):</b>
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-1: <c>size</c> (UINT16) — "size of the remainder of this structure" (Table 199), the octet count of the <c>TPMS_ECC_POINT</c> that follows.</description></item>
///   <item><description>Bytes 2+: <c>point</c> (TPMS_ECC_POINT) — the coordinates, each an inner <c>TPM2B_ECC_PARAMETER</c> (clause 11.2.5.2, Table 198).</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 11.2.5.3, Table 199.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bEccPoint: IDisposable, ITpmWireType
{
    /// <summary>
    /// Shared empty instance wrapping <see cref="TpmsEccPoint.Empty"/> — the omitted-point shape (Table 199's
    /// remark), not a zero-size outer buffer, which <see cref="Parse"/> instead refuses (there is no wire
    /// encoding of a genuinely empty <c>TPM2B_ECC_POINT</c>: its minimum <c>size</c> is four).
    /// </summary>
    private static Tpm2bEccPoint EmptyInstance { get; } = new(TpmsEccPoint.Empty);

    /// <summary>Detects and prevents a redundant dispose of an already-released, non-<see cref="Empty"/> instance.</summary>
    private bool disposed;

    /// <summary>
    /// Initializes a new outer wrapper adopting <paramref name="point"/> — private so every construction path
    /// (<see cref="Parse"/>, <see cref="Create"/>, <see cref="FromPoint"/>) states its own ownership contract.
    /// </summary>
    /// <param name="point">The wrapped point, whose ownership transfers to this instance.</param>
    private Tpm2bEccPoint(TpmsEccPoint point)
    {
        Point = point;
    }

    /// <summary>Gets the omitted-point sentinel — <see cref="TpmsEccPoint.Empty"/> wrapped, dispose-immune.</summary>
    public static Tpm2bEccPoint Empty => EmptyInstance;

    /// <summary>Gets the wrapped <c>TPMS_ECC_POINT</c>.</summary>
    public TpmsEccPoint Point { get; }

    /// <summary>Gets whether the wrapped point is the omitted-point shape (both coordinates zero-length).</summary>
    public bool IsEmpty => Point.IsEmpty;

    /// <summary>
    /// Gets the serialized size: the 2-octet outer <c>size</c> field plus the wrapped point's own serialized
    /// size (never zero — even <see cref="TpmsEccPoint.Empty"/> contributes its two zero-length coordinates'
    /// 2-octet size prefixes, matching Table 199's "minimum value for size will be four").
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Point.GetSerializedSize();

    /// <summary>
    /// Writes this structure to a TPM writer: the outer <c>size</c> (the wrapped point's own serialized octet
    /// count), then the point itself.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt16((ushort)Point.GetSerializedSize());
        Point.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a <c>TPM2B_ECC_POINT</c> from a TPM reader: reads the outer <c>size</c>, refuses a zero size (Table
    /// 199's "if the type of point were BYTE, then size could have been zero" remark — for the actual
    /// <c>TPMS_ECC_POINT</c> type it cannot be, so zero names a missing structure, the Part 4 reference
    /// unmarshaler's own rule: "if size is zero, then the required structure is missing"), parses the inner
    /// <see cref="TpmsEccPoint"/>, then cross-checks the declared <c>size</c> against the octets the inner parse
    /// actually consumed. Table 199's own row states the rule directly: "#TPM_RC_SIZE error returned if the
    /// unmarshaled size of point is not exactly equal to size" (TPM 2.0 Library Part 2, clause 11.2.5.3, Table
    /// 199); Part 4's <c>TPM2B_ECC_POINT_Unmarshal</c> performs the identical check
    /// (<c>target-&gt;size != (startSize - *size)</c>), and every <c>TPM2B_ECC_POINT</c> consumer inherits it
    /// from this type.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating the inner point's coordinate storage.</param>
    /// <returns>The parsed structure; the caller owns it and its two coordinate rentals, and must dispose it.</returns>
    /// <exception cref="InvalidOperationException">The declared <c>size</c> is zero, or does not equal the octets the inner <c>TPMS_ECC_POINT</c> consumed.</exception>
    public static Tpm2bEccPoint Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ushort size = reader.ReadUInt16();
        if(size == 0)
        {
            throw new InvalidOperationException("TPM2B_ECC_POINT size is zero; the required TPMS_ECC_POINT structure is missing.");
        }

        int remainingBeforePoint = reader.Remaining;
        TpmsEccPoint point = TpmsEccPoint.Parse(ref reader, pool);
        int consumed = remainingBeforePoint - reader.Remaining;
        if(consumed != size)
        {
            point.Dispose();

            throw new InvalidOperationException($"TPM2B_ECC_POINT declared size {size} does not match the {consumed} octets the inner TPMS_ECC_POINT consumed.");
        }

        return new Tpm2bEccPoint(point);
    }

    /// <summary>
    /// Creates a <c>TPM2B_ECC_POINT</c> from the specified coordinates, renting fresh storage for each.
    /// </summary>
    /// <param name="x">The X coordinate bytes.</param>
    /// <param name="y">The Y coordinate bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created structure; the caller owns it and its two coordinate rentals, and must dispose it.</returns>
    public static Tpm2bEccPoint Create(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return new Tpm2bEccPoint(TpmsEccPoint.Create(x, y, pool));
    }

    /// <summary>
    /// Wraps an already-built <see cref="TpmsEccPoint"/>, taking ownership of it.
    /// </summary>
    /// <param name="point">The point to wrap; ownership transfers to the returned instance.</param>
    /// <returns>The wrapping structure.</returns>
    public static Tpm2bEccPoint FromPoint(TpmsEccPoint point)
    {
        ArgumentNullException.ThrowIfNull(point);

        return new Tpm2bEccPoint(point);
    }

    /// <summary>
    /// Releases the wrapped point's coordinate storage. <see cref="Empty"/> is dispose-immune (guarded here, and
    /// again by <see cref="TpmsEccPoint.Dispose"/> on the wrapped <see cref="TpmsEccPoint.Empty"/> singleton).
    /// </summary>
    public void Dispose()
    {
        if(!disposed && this != EmptyInstance)
        {
            Point.Dispose();
            disposed = true;
        }
    }

    /// <summary>The debugger's one-line rendering: the two coordinates' octet counts, never the octets themselves.</summary>
    private string DebuggerDisplay => IsEmpty
        ? "TPM2B_ECC_POINT(empty)"
        : $"TPM2B_ECC_POINT(x={Point.X.Length}, y={Point.Y.Length})";
}
