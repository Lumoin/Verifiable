using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Apdu;

/// <summary>
/// ISO/IEC 7816-4 status word returned by a smart card after command execution.
/// </summary>
/// <remarks>
/// <para>
/// A status word is a two-byte value (SW1-SW2) appended to every APDU response.
/// Well-known ISO 7816-4 codes are provided as static properties.
/// Vendor-specific codes are registered via <see cref="Create"/>.
/// Values parsed from the wire are created via <see cref="FromValue"/>.
/// </para>
/// <para>
/// <strong>Bit-level classification:</strong> Properties such as <see cref="IsMoreDataAvailable"/>
/// and <see cref="IsRetryCounterWarning"/> work on any status word value, not only registered ones.
/// They decode the SW1 and SW2 fields according to the ISO 7816-4 encoding rules.
/// </para>
/// <para>
/// <strong>Vendor registration:</strong>
/// </para>
/// <code>
/// //At application startup.
/// public static class SafeNetStatusWords
/// {
///     public static StatusWord ApplicationNotAvailable { get; } =
///         StatusWord.Create(0x6999, "Application not available (vendor-specific).");
/// }
/// </code>
/// </remarks>
[DebuggerDisplay("{StatusWordNames.GetName(this),nq}")]
public readonly struct StatusWord : IEquatable<StatusWord>
{
    /// <summary>Gets the raw 16-bit status word value.</summary>
    public ushort Value { get; }

    /// <summary>Gets the first status byte (SW1).</summary>
    public byte Sw1 => (byte)(Value >> 8);

    /// <summary>Gets the second status byte (SW2).</summary>
    public byte Sw2 => (byte)(Value & 0xFF);

    private StatusWord(ushort value) { Value = value; }


    // ──────────────────────────────────────────────────────────────
    //  Well-known instances — ISO/IEC 7816-4.
    // ──────────────────────────────────────────────────────────────

    /// <summary>Success (0x9000). Command executed without error.</summary>
    public static StatusWord Success { get; } = new(0x9000);

    /// <summary>Wrong data (0x6A80). Incorrect parameters in the data field.</summary>
    public static StatusWord WrongData { get; } = new(0x6A80);

    /// <summary>File or application not found (0x6A82).</summary>
    public static StatusWord FileNotFound { get; } = new(0x6A82);

    /// <summary>Incorrect parameters P1-P2 (0x6A86).</summary>
    public static StatusWord IncorrectP1P2 { get; } = new(0x6A86);

    /// <summary>Referenced data not found (0x6A88).</summary>
    public static StatusWord ReferencedDataNotFound { get; } = new(0x6A88);

    /// <summary>Security status not satisfied (0x6982). Required authentication is missing.</summary>
    public static StatusWord SecurityNotSatisfied { get; } = new(0x6982);

    /// <summary>Authentication method blocked (0x6983). PIN is permanently blocked.</summary>
    public static StatusWord AuthenticationBlocked { get; } = new(0x6983);

    /// <summary>Instruction code not supported (0x6D00).</summary>
    public static StatusWord InstructionNotSupported { get; } = new(0x6D00);

    /// <summary>Class not supported (0x6E00).</summary>
    public static StatusWord ClassNotSupported { get; } = new(0x6E00);

    /// <summary>Logical channel not supported (0x6881).</summary>
    public static StatusWord LogicalChannelNotSupported { get; } = new(0x6881);

    /// <summary>Command not allowed — conditions of use not satisfied (0x6985).</summary>
    public static StatusWord ConditionsNotSatisfied { get; } = new(0x6985);


    private static readonly List<StatusWord> words =
    [
        Success, WrongData, FileNotFound, IncorrectP1P2, ReferencedDataNotFound,
        SecurityNotSatisfied, AuthenticationBlocked, InstructionNotSupported,
        ClassNotSupported, LogicalChannelNotSupported, ConditionsNotSatisfied
    ];

    /// <summary>Gets all registered status word values.</summary>
    public static IReadOnlyList<StatusWord> Words => words.AsReadOnly();


    /// <summary>
    /// Registers a vendor-specific status word with a description.
    /// Use values not already defined in ISO 7816-4 to avoid collisions.
    /// </summary>
    /// <param name="value">The 16-bit status word value.</param>
    /// <param name="description">The human-readable description for debugger display and forensics.</param>
    /// <returns>The registered status word.</returns>
    /// <exception cref="ArgumentException">Thrown if the value is already registered.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="description"/> is <see langword="null"/>.</exception>
    public static StatusWord Create(ushort value, string description)
    {
        ArgumentNullException.ThrowIfNull(description);

        for(int i = 0; i < words.Count; ++i)
        {
            if(words[i].Value == value)
            {
                throw new ArgumentException($"Status word 0x{value:X4} is already registered.", nameof(value));
            }
        }

        var newWord = new StatusWord(value);
        words.Add(newWord);
        StatusWordNames.Register(value, description);
        return newWord;
    }

    /// <summary>
    /// Creates a status word from a raw wire value without registration.
    /// Used when parsing response APDUs from card communication.
    /// </summary>
    /// <param name="value">The 16-bit status word value.</param>
    /// <returns>The status word.</returns>
    public static StatusWord FromValue(ushort value) => new(value);

    /// <summary>
    /// Creates a status word from individual SW1 and SW2 bytes.
    /// </summary>
    /// <param name="sw1">The first status byte.</param>
    /// <param name="sw2">The second status byte.</param>
    /// <returns>The status word.</returns>
    public static StatusWord FromBytes(byte sw1, byte sw2) => new((ushort)((sw1 << 8) | sw2));


    // ──────────────────────────────────────────────────────────────
    //  Bit-level classification — works on any value.
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Gets a value indicating whether the command completed successfully (<c>9000</c>).
    /// </summary>
    public bool IsSuccess => Value == 0x9000;

    /// <summary>
    /// Gets a value indicating whether more data is available (<c>61xx</c>).
    /// Issue GET RESPONSE with Le = SW2 to retrieve the next fragment.
    /// </summary>
    public bool IsMoreDataAvailable => Sw1 == 0x61;

    /// <summary>
    /// Gets the number of bytes available when <see cref="IsMoreDataAvailable"/> is <see langword="true"/>.
    /// A value of <c>0</c> means 256 bytes.
    /// </summary>
    public byte BytesAvailable => Sw2;

    /// <summary>
    /// Gets a value indicating that the Le field was incorrect and the card indicates
    /// the correct value in SW2 (<c>6Cxx</c>). Retry with Le = SW2.
    /// </summary>
    public bool IsWrongLeWithCorrection => Sw1 == 0x6C;

    /// <summary>
    /// Gets the correct Le value when <see cref="IsWrongLeWithCorrection"/> is <see langword="true"/>.
    /// </summary>
    public byte CorrectLe => Sw2;

    /// <summary>
    /// Gets a value indicating a retry counter warning (<c>63Cx</c>).
    /// The lower nibble of SW2 contains the remaining retry count.
    /// </summary>
    public bool IsRetryCounterWarning => Sw1 == 0x63 && (Sw2 & 0xF0) == 0xC0;

    /// <summary>
    /// Gets the remaining retry count when <see cref="IsRetryCounterWarning"/> is <see langword="true"/>.
    /// </summary>
    public int RetryCount => Sw2 & 0x0F;

    /// <summary>
    /// Gets a value indicating that the security status is not satisfied (<c>6982</c>).
    /// </summary>
    public bool IsSecurityStatusNotSatisfied => Value == 0x6982;

    /// <summary>
    /// Gets a value indicating that the authentication method is blocked (<c>6983</c>).
    /// </summary>
    public bool IsAuthenticationMethodBlocked => Value == 0x6983;

    /// <summary>
    /// Gets a value indicating that the file or application was not found (<c>6A82</c>).
    /// </summary>
    public bool IsFileOrAppNotFound => Value == 0x6A82;

    /// <summary>
    /// Gets a value indicating that the referenced data was not found (<c>6A88</c>).
    /// </summary>
    public bool IsReferencedDataNotFound => Value == 0x6A88;

    /// <summary>
    /// Gets a value indicating that the instruction code is not supported (<c>6D00</c>).
    /// </summary>
    public bool IsInstructionNotSupported => Value == 0x6D00;

    /// <summary>
    /// Gets a value indicating that the class byte is not supported (<c>6E00</c>).
    /// </summary>
    public bool IsClassNotSupported => Value == 0x6E00;

    /// <summary>
    /// Gets a value indicating incorrect parameters in the data field (<c>6A80</c>).
    /// </summary>
    public bool IsWrongData => Value == 0x6A80;

    /// <summary>
    /// Gets a value indicating incorrect parameters P1-P2 (<c>6A86</c>).
    /// </summary>
    public bool IsIncorrectP1P2 => Value == 0x6A86;

    /// <summary>
    /// Gets a value indicating that the logical channel is not supported (<c>6881</c>).
    /// </summary>
    public bool IsLogicalChannelNotSupported => Value == 0x6881;

    /// <summary>
    /// Gets a value indicating a warning status word (<c>62xx</c> or <c>63xx</c>).
    /// </summary>
    public bool IsWarning => Sw1 == 0x62 || Sw1 == 0x63;

    /// <summary>
    /// Gets a value indicating an error in the execution phase (<c>64xx</c> through <c>66xx</c>).
    /// </summary>
    public bool IsExecutionError => Sw1 >= 0x64 && Sw1 <= 0x66;

    /// <summary>
    /// Gets a value indicating a checking error (<c>67xx</c> through <c>6Fxx</c>).
    /// </summary>
    public bool IsCheckingError => Sw1 >= 0x67 && Sw1 <= 0x6F;


    /// <inheritdoc/>
    public override string ToString() => StatusWordNames.GetName(this);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(StatusWord other) => Value == other.Value;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is StatusWord other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Value;

    /// <inheritdoc/>
    public static bool operator ==(StatusWord left, StatusWord right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(StatusWord left, StatusWord right) => !left.Equals(right);
}


/// <summary>Provides human-readable names for <see cref="StatusWord"/> values.</summary>
public static class StatusWordNames
{
    private static readonly Dictionary<ushort, string> customNames = [];

    /// <summary>Gets the name for the specified status word.</summary>
    public static string GetName(StatusWord statusWord) => GetName(statusWord.Value);

    /// <summary>Gets the name for the specified status word value.</summary>
    public static string GetName(ushort value)
    {
        if(customNames.TryGetValue(value, out string? customName))
        {
            return $"{customName} (0x{value:X4})";
        }

        //Well-known ISO 7816-4 codes.
        string? isoName = value switch
        {
            var v when v == StatusWord.Success.Value => "Success",
            var v when v == StatusWord.WrongData.Value => "Wrong data",
            var v when v == StatusWord.FileNotFound.Value => "File or application not found",
            var v when v == StatusWord.IncorrectP1P2.Value => "Incorrect P1-P2",
            var v when v == StatusWord.ReferencedDataNotFound.Value => "Referenced data not found",
            var v when v == StatusWord.SecurityNotSatisfied.Value => "Security status not satisfied",
            var v when v == StatusWord.AuthenticationBlocked.Value => "Authentication method blocked",
            var v when v == StatusWord.InstructionNotSupported.Value => "Instruction not supported",
            var v when v == StatusWord.ClassNotSupported.Value => "Class not supported",
            var v when v == StatusWord.LogicalChannelNotSupported.Value => "Logical channel not supported",
            var v when v == StatusWord.ConditionsNotSatisfied.Value => "Conditions of use not satisfied",
            _ => null
        };

        if(isoName is not null)
        {
            return $"{isoName} (0x{value:X4})";
        }

        //Bit-pattern based descriptions for ranges.
        byte sw1 = (byte)(value >> 8);
        byte sw2 = (byte)(value & 0xFF);

        return (sw1, sw2) switch
        {
            (0x61, _) => $"More data available: {sw2} bytes (0x{value:X4})",
            (0x6C, _) => $"Wrong Le, correct is {sw2} (0x{value:X4})",
            (0x63, var s) when (s & 0xF0) == 0xC0 => $"Retry counter warning: {s & 0x0F} remaining (0x{value:X4})",
            (0x62, _) => $"Warning: non-volatile memory unchanged (0x{value:X4})",
            (0x63, _) => $"Warning: non-volatile memory changed (0x{value:X4})",
            (0x64, _) => $"Execution error: non-volatile memory unchanged (0x{value:X4})",
            (0x65, _) => $"Execution error: non-volatile memory changed (0x{value:X4})",
            (0x66, _) => $"Execution error: security related (0x{value:X4})",
            (0x67, 0x00) => $"Wrong length (0x{value:X4})",
            (0x68, _) => $"Functions in CLA not supported (0x{value:X4})",
            (0x69, _) => $"Command not allowed (0x{value:X4})",
            (0x6A, _) => $"Wrong parameters P1-P2 or data (0x{value:X4})",
            (0x6B, 0x00) => $"Wrong P1-P2 (0x{value:X4})",
            (0x6D, _) => $"Instruction not supported (0x{value:X4})",
            (0x6E, _) => $"Class not supported (0x{value:X4})",
            (0x6F, _) => $"No precise diagnosis (0x{value:X4})",
            _ => $"Unknown (0x{value:X4})"
        };
    }

    /// <summary>Registers a custom description for a vendor-specific status word.</summary>
    internal static void Register(ushort value, string description)
    {
        customNames[value] = description;
    }
}
