using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Groups the three header fields present at the start of every TPM command and response.
/// </summary>
/// <remarks>
/// <para>
/// This is an implementation convenience, not a TPM specification type. The TPM spec
/// defines that every command and response begins with these three fields, but does not
/// define a named structure for them.
/// </para>
/// <para>
/// <b>Command header layout</b> (TPM 2.0 Part 1, Section 16.9):
/// </para>
/// <list type="bullet">
///   <item><description>Offset 0-1: TPMI_ST_COMMAND_TAG (TPM_ST_SESSIONS or TPM_ST_NO_SESSIONS).</description></item>
///   <item><description>Offset 2-5: UINT32 commandSize (total size including header).</description></item>
///   <item><description>Offset 6-9: TPM_CC commandCode.</description></item>
/// </list>
/// <para>
/// <b>Response header layout</b> (TPM 2.0 Part 1, Section 16.10):
/// </para>
/// <list type="bullet">
///   <item><description>Offset 0-1: TPM_ST tag.</description></item>
///   <item><description>Offset 2-5: UINT32 responseSize (total size including header).</description></item>
///   <item><description>Offset 6-9: TPM_RC responseCode.</description></item>
/// </list>
/// <para>
/// See TPM 2.0 Part 3, Section 5.2 "Command Header Validation" for the TPM's
/// processing of command headers.
/// </para>
/// </remarks>
/// <param name="Tag">The structure tag (TPM_ST_SESSIONS or TPM_ST_NO_SESSIONS).</param>
/// <param name="Size">Total size in bytes including the header.</param>
/// <param name="Code">Command code (for requests) or response code (for responses).</param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmHeader(ushort Tag, uint Size, uint Code)
{
    /// <summary>
    /// The fixed size of the header in bytes.
    /// </summary>
    public const int HeaderSize = 10;

    /// <summary>
    /// Parses a header from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the header.</param>
    /// <returns>The parsed header.</returns>
    public static TpmHeader Parse(ref TpmReader reader)
    {
        ushort tag = reader.ReadUInt16();
        uint size = reader.ReadUInt32();
        uint code = reader.ReadUInt32();

        return new TpmHeader(tag, size, code);
    }

    /// <summary>
    /// Writes this header to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt16(Tag);
        writer.WriteUInt32(Size);
        writer.WriteUInt32(Code);
    }

    private string DebuggerDisplay => $"TpmHeader(Tag=0x{Tag:X4}, Size={Size}, Code=0x{Code:X8})";
}