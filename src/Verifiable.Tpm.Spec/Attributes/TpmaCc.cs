using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Attributes;

/// <summary>
/// TPMA_CC - command code attributes from a context management perspective.
/// </summary>
/// <remarks>
/// <para>
/// The TPMA_CC bitfield indicates to a TPM Resource Manager (TRM) the number of resources required by a command and
/// how the command affects resources.
/// </para>
/// <para>
/// This structure is used in lists returned by the TPM in response to <c>TPM2_GetCapability(capability == TPM_CAP_COMMANDS)</c>.
/// </para>
/// <para>
/// Specification: TPM 2.0 Library Specification, Part 2: Structures, clause 8.9 (TPMA_CC).
/// </para>
/// <para>
/// Notes for this codebase:
/// TPMA_CC is also useful as a spec-defined, fixed mapping from command code to the number of input handles (C_HANDLES).
/// The executor can use <see cref="C_HANDLES"/> to split the request layout into:
/// Header | Handles | AuthArea | Parameters.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly struct TpmaCc: IEquatable<TpmaCc>
{
    /// <summary>Mask of <c>commandIndex</c>, bits 15:0 — "indicates the command being selected" (TPM 2.0 Library Part 2, clause 8.9.3.1).</summary>
    private const uint CommandIndexMask = 0x0000FFFFu;

    /// <summary>Position of <c>nv</c>, bit 22 — SET when the command may write to NV (Part 2, clause 8.9.3.2).</summary>
    private const int NvBit = 22;

    /// <summary>Position of <c>extensive</c>, bit 23 — SET when the command could flush any number of loaded contexts (Part 2, clause 8.9.3.3).</summary>
    private const int ExtensiveBit = 23;

    /// <summary>Position of <c>flushed</c>, bit 24 — SET when the contexts of the command's transient handles are flushed on completion (Part 2, clause 8.9.3.4).</summary>
    private const int FlushedBit = 24;

    /// <summary>Shift of <c>cHandles</c>, bits 27:25 — the number of handles in the command's handle area (Part 2, clause 8.9.3.5).</summary>
    private const int CHandlesShift = 25;

    /// <summary>Width mask of <c>cHandles</c> once shifted down: three bits, 0..7 (Part 2, clause 8.9.3.5).</summary>
    private const uint CHandlesMask = 0x07u;

    /// <summary>Position of <c>rHandle</c>, bit 28 — SET when the response carries a handle area (Part 2, clause 8.9.3.6).</summary>
    private const int RHandleBit = 28;

    /// <summary>Position of <c>V</c>, bit 29 — SET for a vendor-specific command (Part 2, clause 8.9.3.7); bits 31:30 are reserved.</summary>
    private const int VendorBit = 29;

    /// <summary>
    /// Raw 32-bit value containing the packed fields and flags.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes a new instance from the raw 32-bit value.
    /// </summary>
    /// <param name="value">The raw 32-bit TPMA_CC value.</param>
    public TpmaCc(uint value)
    {
#if DEBUG
        const uint reservedMask = 0b11u << 30;
        Debug.Assert((value & reservedMask) == 0, "Reserved bits 31:30 must be zero.");
#endif
        Value = value;
    }


    /// <summary>
    /// Creates a TPMA_CC value from a command index, the number of input handles (C_HANDLES), and the four
    /// context-management attribute bits.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A semantic constructor so call sites carry no magic numbers: COMMAND_INDEX lands in bits 15:0, C_HANDLES in
    /// bits 27:25, and each flag in its own bit. The flags are what a command's Part 3 header states: the
    /// <c>{NV}</c>, <c>{E}</c>, and <c>{F}</c> description modifiers (TPM 2.0 Library Part 3, clauses 4.2.6, 4.2.8,
    /// and 4.2.7) and whether the response carries a handle area (Part 2, clause 8.9.3.6).
    /// </para>
    /// <para>
    /// <c>{F}</c> "may be combined with the {NV} modifier but not with the {E} modifier" (Part 3, clause 4.2.7), so
    /// <paramref name="isFlushed"/> and <paramref name="isExtensive"/> together are refused.
    /// </para>
    /// </remarks>
    /// <param name="commandIndex">The command index (lower 16 bits of a command code).</param>
    /// <param name="cHandles">The number of handles in the handle area for this command (0..7).</param>
    /// <param name="isNv">Whether the command may write to NV memory (the <c>{NV}</c> modifier; bit 22).</param>
    /// <param name="isExtensive">Whether the command may flush any number of loaded contexts (the <c>{E}</c> modifier; bit 23).</param>
    /// <param name="isFlushed">Whether the command flushes the context of any transient handle it uses when it completes (the <c>{F}</c> modifier; bit 24).</param>
    /// <param name="hasResponseHandle">Whether the response carries a handle area (bit 28).</param>
    /// <returns>A TPMA_CC value with COMMAND_INDEX, C_HANDLES, and the requested flags populated.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="cHandles"/> is outside 0..7.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="isFlushed"/> and <paramref name="isExtensive"/> are both set.</exception>
    public static TpmaCc FromCommandIndex(ushort commandIndex, byte cHandles, bool isNv = false, bool isExtensive = false, bool isFlushed = false, bool hasResponseHandle = false)
    {
        if(cHandles > 7)
        {
            throw new ArgumentOutOfRangeException(nameof(cHandles), "C_HANDLES must be in the range 0..7.");
        }

        if(isFlushed && isExtensive)
        {
            throw new ArgumentException("FLUSHED and EXTENSIVE are mutually exclusive: {F} may be combined with {NV} but not with {E} (TPM 2.0 Library Part 3, clauses 4.2.7 and 4.2.8).", nameof(isExtensive));
        }

        uint value = ((uint)cHandles << CHandlesShift) | commandIndex;
        value |= isNv ? 1u << NvBit : 0u;
        value |= isExtensive ? 1u << ExtensiveBit : 0u;
        value |= isFlushed ? 1u << FlushedBit : 0u;
        value |= hasResponseHandle ? 1u << RHandleBit : 0u;

        return new TpmaCc(value);
    }

    /// <summary>
    /// Creates a TPMA_CC value from a raw command code, the number of input handles (C_HANDLES), and the four
    /// context-management attribute bits.
    /// </summary>
    /// <remarks>
    /// This overload accepts a 32-bit command code value (typically TPM_CC as uint). Only the lower 16 bits are used
    /// as COMMAND_INDEX (as per the spec definition of TPMA_CC); the flags are those of
    /// <see cref="FromCommandIndex(ushort, byte, bool, bool, bool, bool)"/>.
    /// </remarks>
    /// <param name="commandCode">The command code value. Only the low 16 bits are used.</param>
    /// <param name="cHandles">The number of handles in the handle area for this command (0..7).</param>
    /// <param name="isNv">Whether the command may write to NV memory (the <c>{NV}</c> modifier; bit 22).</param>
    /// <param name="isExtensive">Whether the command may flush any number of loaded contexts (the <c>{E}</c> modifier; bit 23).</param>
    /// <param name="isFlushed">Whether the command flushes the context of any transient handle it uses when it completes (the <c>{F}</c> modifier; bit 24).</param>
    /// <param name="hasResponseHandle">Whether the response carries a handle area (bit 28).</param>
    /// <returns>A TPMA_CC value with COMMAND_INDEX, C_HANDLES, and the requested flags populated.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="cHandles"/> is outside 0..7.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="isFlushed"/> and <paramref name="isExtensive"/> are both set.</exception>
    public static TpmaCc FromCommandCode(uint commandCode, byte cHandles, bool isNv = false, bool isExtensive = false, bool isFlushed = false, bool hasResponseHandle = false)
    {
        return FromCommandIndex((ushort)(commandCode & CommandIndexMask), cHandles, isNv, isExtensive, isFlushed, hasResponseHandle);
    }

    /// <summary>
    /// COMMAND_INDEX (bits 15:0): indicates the command being selected.
    /// </summary>
    public ushort COMMAND_INDEX => (ushort)(Value & CommandIndexMask);

    /// <summary>
    /// NV (bit 22): SET (1) indicates the command may write to NV; CLEAR (0) indicates it does not write to NV.
    /// </summary>
    public bool NV => (Value & (1u << NvBit)) != 0;

    /// <summary>
    /// EXTENSIVE (bit 23): SET (1) indicates the command could flush any number of loaded contexts; CLEAR (0) indicates
    /// no additional changes other than those indicated by FLUSHED.
    /// </summary>
    public bool EXTENSIVE => (Value & (1u << ExtensiveBit)) != 0;

    /// <summary>
    /// FLUSHED (bit 24): SET (1) indicates contexts associated with any transient handle in the command will be flushed
    /// when the command completes; CLEAR (0) indicates no context is flushed as a side effect.
    /// </summary>
    public bool FLUSHED => (Value & (1u << FlushedBit)) != 0;

    /// <summary>
    /// C_HANDLES (bits 27:25): indicates the number of handles in the handle area for this command.
    /// </summary>
    public byte C_HANDLES => (byte)((Value >> CHandlesShift) & CHandlesMask);

    /// <summary>
    /// R_HANDLE (bit 28): SET (1) indicates the presence of the handle area in the response.
    /// </summary>
    public bool R_HANDLE => (Value & (1u << RHandleBit)) != 0;

    /// <summary>
    /// V (bit 29): SET (1) indicates vendor-specific command; CLEAR (0) indicates defined in a version of this specification.
    /// </summary>
    public bool V => (Value & (1u << VendorBit)) != 0;

    /// <inheritdoc />
    public bool Equals(TpmaCc other) => Value == other.Value;

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is TpmaCc other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Value.GetHashCode();

    public static bool operator ==(TpmaCc left, TpmaCc right) => left.Equals(right);
    public static bool operator !=(TpmaCc left, TpmaCc right) => !left.Equals(right);

    /// <summary>The debugger rendering: the raw word, the command index, the handle count, and whichever attribute bits are set.</summary>
    private string DebuggerDisplay =>
        $"TPMA_CC(0x{Value:X8}, COMMAND_INDEX=0x{COMMAND_INDEX:X4}, C_HANDLES={C_HANDLES}{(NV ? ", NV" : "")}{(EXTENSIVE ? ", EXTENSIVE" : "")}{(FLUSHED ? ", FLUSHED" : "")}{(R_HANDLE ? ", R_HANDLE" : "")}{(V ? ", V" : "")})";
}
