using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Attributes;

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
/// Specification: TPM 2.0 Library Specification, Part 2: Structures, section 8.9 (TPMA_CC).
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
    //TPMA_CC bitfield layout
    //
    //Specification:
    //  TPM 2.0 Library Specification
    //  Part 2: Structures
    //  Section 8.9 - TPMA_CC
    //
    //Bit assignments (from the specification):
    //
    //  Bits 15:0   COMMAND_INDEX  - Identifies the command
    //  Bit  22     NV             - Command may write to NV memory
    //  Bit  23     EXTENSIVE      - Command may flush an unbounded number of contexts
    //  Bit  24     FLUSHED        - Command flushes associated transient objects
    //  Bits 27:25  C_HANDLES      - Number of handles in the command handle area
    //  Bit  28     R_HANDLE       - Response contains a handle area
    //  Bit  29     V              - Vendor-specific command
    //  Bits 31:30  Reserved
    //
    //These bit positions are fixed by the specification and are identical across
    //all compliant TPM 2.0 implementations.

    private const uint CommandIndexMask = 0x0000FFFFu;

    private const int NvBit = 22;
    private const int ExtensiveBit = 23;
    private const int FlushedBit = 24;

    private const int CHandlesShift = 25;
    private const uint CHandlesMask = 0x07u;

    private const int RHandleBit = 28;
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
    /// Creates a TPMA_CC value from a command index and the number of input handles (C_HANDLES).
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a semantic constructor to avoid magic numbers at call sites. It encodes:
    /// - COMMAND_INDEX in bits 15:0.
    /// - C_HANDLES in bits 27:25.
    /// </para>
    /// <para>
    /// Other TPMA_CC bits are left clear (0). If you need those bits set, use <see cref="TpmaCc(uint)"/> directly
    /// or OR additional flags at the call site in a controlled manner.
    /// </para>
    /// </remarks>
    /// <param name="commandIndex">The command index (lower 16 bits of a command code).</param>
    /// <param name="cHandles">The number of handles in the handle area for this command (0..7).</param>
    /// <returns>A TPMA_CC value with COMMAND_INDEX and C_HANDLES populated.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="cHandles"/> is outside 0..7.</exception>
    public static TpmaCc FromCommandIndex(ushort commandIndex, byte cHandles)
    {
        if(cHandles > 7)
        {
            throw new ArgumentOutOfRangeException(nameof(cHandles), "C_HANDLES must be in the range 0..7.");
        }

        uint value = ((uint)cHandles << CHandlesShift) | commandIndex;

        return new TpmaCc(value);
    }

    /// <summary>
    /// Creates a TPMA_CC value from a raw command code and the number of input handles (C_HANDLES).
    /// </summary>
    /// <remarks>
    /// <para>
    /// This overload accepts a 32-bit command code value (typically TPM_CC as uint). Only the lower 16 bits are used
    /// as COMMAND_INDEX (as per the spec definition of TPMA_CC).
    /// </para>
    /// </remarks>
    /// <param name="commandCode">The command code value. Only the low 16 bits are used.</param>
    /// <param name="cHandles">The number of handles in the handle area for this command (0..7).</param>
    /// <returns>A TPMA_CC value with COMMAND_INDEX and C_HANDLES populated.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="cHandles"/> is outside 0..7.</exception>
    public static TpmaCc FromCommandCode(uint commandCode, byte cHandles)
    {
        return FromCommandIndex((ushort)(commandCode & CommandIndexMask), cHandles);
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

    private string DebuggerDisplay => $"TPMA_CC(0x{Value:X8}, COMMAND_INDEX=0x{COMMAND_INDEX:X4}, C_HANDLES={C_HANDLES})";
}
