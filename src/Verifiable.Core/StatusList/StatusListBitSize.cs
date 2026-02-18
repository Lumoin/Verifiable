using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.StatusList;

/// <summary>
/// Specifies the number of bits used per status entry in a Status List.
/// </summary>
/// <remarks>
/// <para>
/// The bit size determines the number of distinct status values representable:
/// </para>
/// <list type="bullet">
///   <item><description>1 bit allows 2 status values (0 through 1).</description></item>
///   <item><description>2 bits allow 4 status values (0 through 3).</description></item>
///   <item><description>4 bits allow 16 status values (0 through 15).</description></item>
///   <item><description>8 bits allow 256 status values (0 through 255).</description></item>
/// </list>
/// <para>
/// Per the specification, this limitation ensures that bit manipulation is
/// constrained to a single byte per operation.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1008:Enums should have zero value", Justification = "The specification (draft-ietf-oauth-status-list) defines allowed values as 1, 2, 4, and 8. A zero value is not valid per the RFC.")]
[SuppressMessage("Usage", "CA1027:Mark enums with FlagsAttribute", Justification = "Values represent bit widths per the specification, not combinable flags.")]
public enum StatusListBitSize
{
    /// <summary>
    /// One bit per status entry, supporting two possible values.
    /// </summary>
    OneBit = 1,

    /// <summary>
    /// Two bits per status entry, supporting four possible values.
    /// </summary>
    TwoBits = 2,

    /// <summary>
    /// Four bits per status entry, supporting sixteen possible values.
    /// </summary>
    FourBits = 4,

    /// <summary>
    /// Eight bits per status entry, supporting 256 possible values.
    /// </summary>
    EightBits = 8
}