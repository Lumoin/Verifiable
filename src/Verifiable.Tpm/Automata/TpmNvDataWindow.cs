using System;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The <c>offset</c>/<c>size</c> window of a defined NV Index's data area that a read answers with, framed on
/// the wire as the <c>TPM2B_MAX_NV_BUFFER data</c> parameter of <c>TPM2_NV_Read()</c> (TPM 2.0 Library Part 3,
/// clause 31.13.2, Table 249; Part 2, clause 10.4.9, Table 99).
/// </summary>
/// <remarks>
/// <see cref="Data"/> is a BORROW of the carrier the durable Index state owns, never a rental of this record's:
/// the Index goes on living after the command and remains the carrier's single owner, so the framing step
/// copies the window's octets into the response buffer and releases nothing. Carrying the window as an offset
/// and a size over the borrowed area rather than as an extracted copy is what keeps the read free of a rental
/// the pure transition that answers it could not make.
/// </remarks>
/// <param name="Data">The Index's data area, borrowed from the Index that owns it.</param>
/// <param name="Offset">The octet offset of the window within <paramref name="Data"/>.</param>
/// <param name="Size">The number of octets in the window.</param>
public sealed record TpmNvDataWindow(TpmNvIndexData Data, ushort Offset, ushort Size)
{
    /// <summary>
    /// Gets the window's octets, read through the borrowed carrier.
    /// </summary>
    public ReadOnlySpan<byte> Span => Data.Span.Slice(Offset, Size);

    /// <summary>
    /// Gets the number of octets the window occupies once framed as a <c>TPM2B_MAX_NV_BUFFER</c>: the
    /// <c>UINT16</c> size prefix and the window itself.
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Size;
}
