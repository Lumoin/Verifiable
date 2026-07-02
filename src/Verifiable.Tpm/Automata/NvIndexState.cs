using System;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The simulator's model of a single defined NV Index: the persistent identity, authorization value,
/// attributes, size, and (once written) data area established by <c>TPM2_NV_DefineSpace()</c> and
/// <c>TPM2_NV_Write()</c>. This is the smallest NV-Index model the dictionary-attack/PIN flow and the
/// EK-certificate provisioning flow need — an NV Index is the lightest entity whose authValue can be made
/// dictionary-attack protected (TPM 2.0 Library Part 1, clause 17.8.1), which hierarchy authValues cannot,
/// and the persistent slot a manufacturer writes an EK certificate into (Part 3, clause 31.7).
/// </summary>
/// <remarks>
/// <para>
/// The authorization value and the data area are held as plain <see cref="ReadOnlyMemory{T}"/> rather than
/// pooled buffers: they are durable model state owned by the live automaton for the lifetime of the simulated
/// TPM, mirroring how <see cref="TpmExchange"/> holds recorded command/response octets. The hot
/// command/response wire path remains pool-backed; only the device's own persistent state lives here.
/// </para>
/// <para>
/// Written-ness is modelled as the <c>TPMA_NV_WRITTEN</c> bit within <see cref="Attributes"/>, set by the
/// first <c>TPM2_NV_Write()</c> (TPM 2.0 Library Part 2, clause 13.4). A freshly defined Index has the bit
/// clear and an empty <see cref="Data"/>, so a read of it answers <c>TPM_RC_NV_UNINITIALIZED</c>; a written
/// Index carries its stored octets in <see cref="Data"/> and answers a read from that buffer.
/// </para>
/// </remarks>
/// <param name="NvIndex">The NV Index handle (its most-significant octet is <c>TPM_HT_NV_INDEX</c>).</param>
/// <param name="AuthValue">The Index authorization value supplied at definition; compared against a caller's authorization on access.</param>
/// <param name="Attributes">The Index attributes (<c>TPMA_NV</c>) set at definition, with <c>TPMA_NV_WRITTEN</c> folded in once the Index has been written.</param>
/// <param name="DataSize">The size in octets of the Index data area declared at definition.</param>
/// <param name="Data">The octets stored by <c>TPM2_NV_Write()</c>, covering the written extent of the data area; empty until the first write.</param>
public sealed record NvIndexState(
    uint NvIndex,
    ReadOnlyMemory<byte> AuthValue,
    TpmaNv Attributes,
    ushort DataSize,
    ReadOnlyMemory<byte> Data)
{
    /// <summary>
    /// Gets a value indicating whether this Index is dictionary-attack protected: an authorization
    /// failure against it feeds the lockout counter and is blocked in lockout, unless
    /// <see cref="TpmaNv.TPMA_NV_NO_DA"/> is set (TPM 2.0 Library Part 2, clause 13.4; Part 1, clause 17.8).
    /// </summary>
    public bool IsDaProtected => (Attributes & TpmaNv.TPMA_NV_NO_DA) == 0;

    /// <summary>
    /// Gets a value indicating whether this Index may be read using its authorization value: only when
    /// <see cref="TpmaNv.TPMA_NV_AUTHREAD"/> is set (TPM 2.0 Library Part 2, clause 13.4). With the bit
    /// clear the Index authValue cannot authorize a read, even when the supplied value matches.
    /// </summary>
    public bool IsAuthReadAllowed => (Attributes & TpmaNv.TPMA_NV_AUTHREAD) != 0;

    /// <summary>
    /// Gets a value indicating whether this Index may be written using its authorization value: only when
    /// <see cref="TpmaNv.TPMA_NV_AUTHWRITE"/> is set (TPM 2.0 Library Part 2, clause 13.4). With the bit
    /// clear the Index authValue cannot authorize a write, even when the supplied value matches.
    /// </summary>
    public bool IsAuthWriteAllowed => (Attributes & TpmaNv.TPMA_NV_AUTHWRITE) != 0;

    /// <summary>
    /// Gets a value indicating whether this Index has been written (<c>TPMA_NV_WRITTEN</c> SET). An unwritten
    /// Index answers a read with <c>TPM_RC_NV_UNINITIALIZED</c> (TPM 2.0 Library Part 3, clause 31.13).
    /// </summary>
    public bool IsWritten => (Attributes & TpmaNv.TPMA_NV_WRITTEN) != 0;

    /// <summary>
    /// Returns a copy of this Index with <paramref name="data"/> stored at <paramref name="offset"/> and
    /// <c>TPMA_NV_WRITTEN</c> set, growing or patching the retained data area (TPM 2.0 Library Part 3,
    /// clause 31.7). The caller has already range-checked the write against <see cref="DataSize"/>.
    /// </summary>
    /// <param name="offset">The octet offset into the data area at which to write.</param>
    /// <param name="data">The octets to store.</param>
    /// <returns>The updated Index.</returns>
    public NvIndexState WriteData(int offset, ReadOnlySpan<byte> data)
    {
        int newLength = Math.Max(Data.Length, offset + data.Length);
        byte[] merged = new byte[newLength];
        Data.Span.CopyTo(merged);
        data.CopyTo(merged.AsSpan(offset));

        return this with { Data = merged, Attributes = Attributes | TpmaNv.TPMA_NV_WRITTEN };
    }
}
