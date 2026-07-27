using System;
using System.Buffers.Binary;
using Verifiable.Tpm.Spec.Attributes;

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
    /// The size in octets of <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> (pinCount + pinLimit, each a
    /// <c>UINT32</c>; TPM 2.0 Library Part 2, clause 13.3).
    /// </summary>
    private const int PinCounterParametersSize = 2 * sizeof(uint);

    /// <summary>
    /// The size in octets of a Counter Index's value (TPM 2.0 Library Part 2, clause 13.2: "Counter -
    /// contains an 8-octet value...").
    /// </summary>
    private const int CounterValueSize = sizeof(ulong);

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
    /// Gets a value indicating whether this Index may be written under Owner Authorization: only when
    /// <see cref="TpmaNv.TPMA_NV_OWNERWRITE"/> is set (TPM 2.0 Library Part 2, clause 13.4). With the bit
    /// clear owner authorization cannot write the Index, even when the owner authValue matches. This is the
    /// sole write path for a PIN Index, whose own authValue forbids <see cref="TpmaNv.TPMA_NV_AUTHWRITE"/>
    /// (Part 1, clause 37.2.6.1).
    /// </summary>
    public bool IsOwnerWriteAllowed => (Attributes & TpmaNv.TPMA_NV_OWNERWRITE) != 0;

    /// <summary>
    /// Gets a value indicating whether this Index may be read under Owner Authorization: only when
    /// <see cref="TpmaNv.TPMA_NV_OWNERREAD"/> is set (TPM 2.0 Library Part 3, clause 31.13: "Proper
    /// authorizations are required for this command as determined by TPMA_NV_PPREAD, TPMA_NV_OWNERREAD,
    /// TPMA_NV_AUTHREAD, and the authPolicy of the NV Index"). With the bit clear owner authorization cannot
    /// read the Index, even when the owner authValue matches - checked before the owner-auth compare, the
    /// same non-leaking order <see cref="IsOwnerWriteAllowed"/>'s gate uses at the owner-write arm.
    /// </summary>
    public bool IsOwnerReadAllowed => (Attributes & TpmaNv.TPMA_NV_OWNERREAD) != 0;

    /// <summary>
    /// Gets a value indicating whether this Index has been written (<c>TPMA_NV_WRITTEN</c> SET). An unwritten
    /// Index answers a read with <c>TPM_RC_NV_UNINITIALIZED</c> (TPM 2.0 Library Part 3, clause 31.13).
    /// </summary>
    public bool IsWritten => (Attributes & TpmaNv.TPMA_NV_WRITTEN) != 0;

    /// <summary>
    /// Gets the Index's type (the <c>TPM_NT</c> field within <see cref="Attributes"/>, bits 7:4; TPM 2.0
    /// Library Part 2, clause 13.2).
    /// </summary>
    public TpmNt IndexType => TpmaNvFields.GetTpmNt(Attributes);

    /// <summary>
    /// Gets a value indicating whether this Index is a PIN Fail Index (<see cref="TpmNt.TPM_NT_PIN_FAIL"/>):
    /// its own <see cref="PinCount"/> resets to zero on a successful authorization and increments on a failed
    /// one (TPM 2.0 Library Part 1, clause 37.2.6.6).
    /// </summary>
    public bool IsPinFail => IndexType == TpmNt.TPM_NT_PIN_FAIL;

    /// <summary>
    /// Gets a value indicating whether this Index is a PIN Pass Index (<see cref="TpmNt.TPM_NT_PIN_PASS"/>):
    /// its own <see cref="PinCount"/> increments on a successful authorization and is left unchanged on a
    /// failed one (TPM 2.0 Library Part 1, clause 37.2.6.6).
    /// </summary>
    public bool IsPinPass => IndexType == TpmNt.TPM_NT_PIN_PASS;

    /// <summary>
    /// Gets a value indicating whether this Index carries the localized PIN dictionary-attack defense
    /// (<see cref="IsPinFail"/> or <see cref="IsPinPass"/>; TPM 2.0 Library Part 1, clause 37.2.8.2), distinct
    /// from — and, for a PIN Pass Index without <see cref="TpmaNv.TPMA_NV_NO_DA"/>, additional to — the
    /// TPM-wide mechanism <see cref="IsDaProtected"/> gates.
    /// </summary>
    public bool IsPinIndex => IsPinFail || IsPinPass;

    /// <summary>
    /// Gets the current attempt count from the retained <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> data (the
    /// first four octets of <see cref="Data"/>; TPM 2.0 Library Part 2, clause 13.3). Zero for an unwritten
    /// Index, since no counter data has been stored yet — computed directly over <see cref="Data"/>, with no
    /// parallel counter state.
    /// </summary>
    public uint PinCount => Data.Length >= PinCounterParametersSize
        ? BinaryPrimitives.ReadUInt32BigEndian(Data.Span[..sizeof(uint)])
        : 0u;

    /// <summary>
    /// Gets the attempt threshold from the retained <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> data (the second
    /// four octets of <see cref="Data"/>; TPM 2.0 Library Part 2, clause 13.3). Zero for an unwritten Index.
    /// </summary>
    public uint PinLimit => Data.Length >= PinCounterParametersSize
        ? BinaryPrimitives.ReadUInt32BigEndian(Data.Span.Slice(sizeof(uint), sizeof(uint)))
        : 0u;

    /// <summary>
    /// Gets a value indicating whether this PIN Index's authValue is currently usable for authorization: the
    /// Index must already be written and <see cref="PinCount"/> must be strictly less than
    /// <see cref="PinLimit"/> (TPM 2.0 Library Part 1, clause 37.2.6.6). Meaningful only when
    /// <see cref="IsPinIndex"/> is <see langword="true"/>.
    /// </summary>
    public bool IsPinAuthAvailable => IsWritten && PinCount < PinLimit;

    /// <summary>
    /// Gets the current 8-octet counter value (TPM 2.0 Library Part 2, clause 13.2), stored big-endian across
    /// the whole <see cref="Data"/> area. Zero for an unwritten Index, since no counter data has been stored
    /// yet — meaningful only when <see cref="IndexType"/> is <see cref="TpmNt.TPM_NT_COUNTER"/>.
    /// </summary>
    public ulong CounterValue => Data.Length >= CounterValueSize
        ? BinaryPrimitives.ReadUInt64BigEndian(Data.Span[..CounterValueSize])
        : 0ul;

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

    /// <summary>
    /// Returns a copy of this PIN Index with <paramref name="pinCount"/> stored as the first four octets of
    /// the retained <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> data, leaving <see cref="PinLimit"/> (and any
    /// further stored octets) untouched (TPM 2.0 Library Part 2, clause 13.3). Composes over
    /// <see cref="WriteData"/>, so it also (harmlessly, for an already-written PIN Index) confirms
    /// <c>TPMA_NV_WRITTEN</c>.
    /// </summary>
    /// <param name="pinCount">The new pinCount value.</param>
    /// <returns>The updated Index.</returns>
    public NvIndexState WithPinCount(uint pinCount)
    {
        //Tiny, non-secret counter value (4 bytes) - never the authValue or key material this Index protects.
        Span<byte> pinCountBytes = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(pinCountBytes, pinCount);

        return WriteData(0, pinCountBytes);
    }

    /// <summary>
    /// Returns a copy of this Counter Index with <paramref name="counterValue"/> stored as the 8 big-endian
    /// octets spanning the whole retained data area (TPM 2.0 Library Part 2, clause 13.2). Composes over
    /// <see cref="WriteData"/> the way <see cref="WithPinCount"/> does, so it also sets
    /// <c>TPMA_NV_WRITTEN</c> (TPM 2.0 Library Part 1, clause 37.2.6.3: "the TPMA_NV_WRITTEN attribute will be
    /// SET" on the first increment).
    /// </summary>
    /// <param name="counterValue">The new counter value.</param>
    /// <returns>The updated Index.</returns>
    public NvIndexState WithCounterValue(ulong counterValue)
    {
        //Tiny, non-secret counter value (8 bytes) - never the authValue or key material this Index protects.
        Span<byte> counterValueBytes = stackalloc byte[CounterValueSize];
        BinaryPrimitives.WriteUInt64BigEndian(counterValueBytes, counterValue);

        return WriteData(0, counterValueBytes);
    }
}
