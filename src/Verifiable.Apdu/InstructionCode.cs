using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Apdu;

/// <summary>
/// Identifies an ISO/IEC 7816-4 instruction code.
/// </summary>
/// <remarks>
/// <para>
/// Well-known ISO 7816-4 instructions are provided as static properties.
/// Vendor-specific instructions are registered via <see cref="Create"/>.
/// Values parsed from the wire are created via <see cref="FromValue"/>.
/// </para>
/// <para>
/// <strong>Vendor registration:</strong>
/// </para>
/// <code>
/// //At application startup.
/// public static class VendorInstructions
/// {
///     public static InstructionCode GetVersion { get; } = InstructionCode.Create(0xFD, "GET VERSION");
///     public static InstructionCode SlotProbe { get; } = InstructionCode.Create(0xF7, "SLOT PROBE");
///     public static InstructionCode PivReset { get; } = InstructionCode.Create(0xFB, "PIV RESET");
/// }
/// </code>
/// </remarks>
[DebuggerDisplay("{InstructionCodeNames.GetName(this),nq}")]
public readonly struct InstructionCode : IEquatable<InstructionCode>
{
    /// <summary>Gets the raw byte value of this instruction code.</summary>
    public byte Code { get; }

    private InstructionCode(byte code) { Code = code; }


    /// <summary>SELECT (0xA4). Selects a file or application by name, identifier, or path.</summary>
    public static InstructionCode Select { get; } = new(0xA4);

    /// <summary>GET RESPONSE (0xC0). Retrieves response data after a <c>61xx</c> status word.</summary>
    public static InstructionCode GetResponse { get; } = new(0xC0);

    /// <summary>GET DATA with simple TLV (0xCA). Retrieves a data object identified by P1-P2.</summary>
    public static InstructionCode GetDataSimple { get; } = new(0xCA);

    /// <summary>GET DATA with BER-TLV (0xCB). Retrieves a data object identified by a tag in the data field.</summary>
    public static InstructionCode GetDataBerTlv { get; } = new(0xCB);

    /// <summary>PUT DATA (0xDB). Writes a data object to the card.</summary>
    public static InstructionCode PutData { get; } = new(0xDB);

    /// <summary>VERIFY (0x20). Verifies a PIN or password.</summary>
    public static InstructionCode Verify { get; } = new(0x20);

    /// <summary>CHANGE REFERENCE DATA (0x24). Changes a PIN by providing old and new values.</summary>
    public static InstructionCode ChangeReferenceData { get; } = new(0x24);

    /// <summary>RESET RETRY COUNTER (0x2C). Resets a PIN retry counter using a PUK or administrative key.</summary>
    public static InstructionCode ResetRetryCounter { get; } = new(0x2C);

    /// <summary>GENERAL AUTHENTICATE (0x87). Performs challenge-response or key agreement operations.</summary>
    public static InstructionCode GeneralAuthenticate { get; } = new(0x87);

    /// <summary>INTERNAL AUTHENTICATE (0x88). Card proves its identity to the terminal.</summary>
    public static InstructionCode InternalAuthenticate { get; } = new(0x88);

    /// <summary>EXTERNAL AUTHENTICATE (0x82). Terminal proves its identity to the card.</summary>
    public static InstructionCode ExternalAuthenticate { get; } = new(0x82);

    /// <summary>GET CHALLENGE (0x84). Requests random bytes from the card for use as a challenge.</summary>
    public static InstructionCode GetChallenge { get; } = new(0x84);

    /// <summary>READ BINARY (0xB0). Reads binary data from a transparent file.</summary>
    public static InstructionCode ReadBinary { get; } = new(0xB0);

    /// <summary>READ RECORD (0xB2). Reads a record from a record-oriented file.</summary>
    public static InstructionCode ReadRecord { get; } = new(0xB2);

    /// <summary>MANAGE SECURITY ENVIRONMENT (0x22). Sets up cryptographic context for subsequent operations.</summary>
    public static InstructionCode ManageSecurityEnvironment { get; } = new(0x22);

    /// <summary>PERFORM SECURITY OPERATION (0x2A). Runs a security operation such as verifying a card-verifiable certificate (ISO/IEC 7816-8).</summary>
    public static InstructionCode PerformSecurityOperation { get; } = new(0x2A);

    /// <summary>GENERATE ASYMMETRIC KEY PAIR (0x47). Generates a key pair on the card.</summary>
    public static InstructionCode GenerateAsymmetricKeyPair { get; } = new(0x47);


    private static List<InstructionCode> codes { get; } =
    [
        Select, GetResponse, GetDataSimple, GetDataBerTlv, PutData,
        Verify, ChangeReferenceData, ResetRetryCounter,
        GeneralAuthenticate, InternalAuthenticate, ExternalAuthenticate,
        GetChallenge, ReadBinary, ReadRecord, ManageSecurityEnvironment, PerformSecurityOperation, GenerateAsymmetricKeyPair
    ];

    /// <summary>Gets all registered instruction code values.</summary>
    public static IReadOnlyList<InstructionCode> Codes => codes.AsReadOnly();


    /// <summary>
    /// Registers a vendor-specific instruction code with a display name.
    /// Use codes in the proprietary range to avoid collisions with future standard additions.
    /// </summary>
    /// <param name="code">The instruction byte value.</param>
    /// <param name="name">The human-readable name for debugger display and forensics.</param>
    /// <returns>The registered instruction code.</returns>
    /// <exception cref="ArgumentException">Thrown if the code is already registered.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="name"/> is <see langword="null"/>.</exception>
    public static InstructionCode Create(byte code, string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        for(int i = 0; i < codes.Count; ++i)
        {
            if(codes[i].Code == code)
            {
                throw new ArgumentException($"Instruction code 0x{code:X2} is already registered.", nameof(code));
            }
        }

        var newCode = new InstructionCode(code);
        codes.Add(newCode);
        InstructionCodeNames.Register(code, name);
        return newCode;
    }

    /// <summary>
    /// Creates an instruction code from a raw wire value without registration.
    /// Used when parsing command APDUs from traces or card responses.
    /// </summary>
    /// <param name="code">The instruction byte value.</param>
    /// <returns>The instruction code.</returns>
    public static InstructionCode FromValue(byte code) => new(code);


    /// <inheritdoc/>
    public override string ToString() => InstructionCodeNames.GetName(this);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(InstructionCode other) => Code == other.Code;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is InstructionCode other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;

    /// <inheritdoc/>
    public static bool operator ==(InstructionCode left, InstructionCode right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(InstructionCode left, InstructionCode right) => !left.Equals(right);
}


/// <summary>Provides human-readable names for <see cref="InstructionCode"/> values.</summary>
public static class InstructionCodeNames
{
    private static Dictionary<byte, string> customNames { get; } = [];

    /// <summary>Gets the name for the specified instruction code.</summary>
    public static string GetName(InstructionCode instruction) => GetName(instruction.Code);

    /// <summary>Gets the name for the specified instruction byte value.</summary>
    public static string GetName(byte code)
    {
        if(customNames.TryGetValue(code, out string? customName))
        {
            return customName;
        }

        return code switch
        {
            var c when c == InstructionCode.Select.Code => nameof(InstructionCode.Select),
            var c when c == InstructionCode.GetResponse.Code => nameof(InstructionCode.GetResponse),
            var c when c == InstructionCode.GetDataSimple.Code => nameof(InstructionCode.GetDataSimple),
            var c when c == InstructionCode.GetDataBerTlv.Code => nameof(InstructionCode.GetDataBerTlv),
            var c when c == InstructionCode.PutData.Code => nameof(InstructionCode.PutData),
            var c when c == InstructionCode.Verify.Code => nameof(InstructionCode.Verify),
            var c when c == InstructionCode.ChangeReferenceData.Code => nameof(InstructionCode.ChangeReferenceData),
            var c when c == InstructionCode.ResetRetryCounter.Code => nameof(InstructionCode.ResetRetryCounter),
            var c when c == InstructionCode.GeneralAuthenticate.Code => nameof(InstructionCode.GeneralAuthenticate),
            var c when c == InstructionCode.InternalAuthenticate.Code => nameof(InstructionCode.InternalAuthenticate),
            var c when c == InstructionCode.ExternalAuthenticate.Code => nameof(InstructionCode.ExternalAuthenticate),
            var c when c == InstructionCode.GetChallenge.Code => nameof(InstructionCode.GetChallenge),
            var c when c == InstructionCode.ReadBinary.Code => nameof(InstructionCode.ReadBinary),
            var c when c == InstructionCode.ReadRecord.Code => nameof(InstructionCode.ReadRecord),
            var c when c == InstructionCode.ManageSecurityEnvironment.Code => nameof(InstructionCode.ManageSecurityEnvironment),
            var c when c == InstructionCode.PerformSecurityOperation.Code => nameof(InstructionCode.PerformSecurityOperation),
            var c when c == InstructionCode.GenerateAsymmetricKeyPair.Code => nameof(InstructionCode.GenerateAsymmetricKeyPair),
            _ => $"Unknown (0x{code:X2})"
        };
    }

    /// <summary>Registers a custom name for a vendor-specific instruction code.</summary>
    internal static void Register(byte code, string name)
    {
        customNames[code] = name;
    }
}