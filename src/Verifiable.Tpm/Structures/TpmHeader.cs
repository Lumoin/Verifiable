using System;
using Verifiable.Tpm.Infrastructure;

namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPM 2.0 command/response header structure (10 bytes).
/// </summary>
/// <remarks>
/// <para>
/// The header is present at the start of every TPM command and response:
/// </para>
/// <list type="bullet">
///   <item><description><see cref="Tag"/> - Indicates whether authorization sessions are present.</description></item>
///   <item><description><see cref="Size"/> - Total size of the command/response including header.</description></item>
///   <item><description><see cref="Code"/> - Command code (request) or response code (reply).</description></item>
/// </list>
/// <para>
/// See TPM 2.0 Library Specification, Part 1: Architecture, Section 18.
/// </para>
/// </remarks>
public readonly struct TpmHeader : ITpmParseable<TpmHeader>, IEquatable<TpmHeader>
{
    /// <summary>
    /// Size of the header in bytes.
    /// </summary>
    public const int HeaderSize = 10;

    /// <summary>
    /// Gets the structure tag indicating session usage.
    /// </summary>
    public ushort Tag { get; }

    /// <summary>
    /// Gets the total size of the command or response including header.
    /// </summary>
    public uint Size { get; }

    /// <summary>
    /// Gets the command code (for commands) or response code (for responses).
    /// </summary>
    public uint Code { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="TpmHeader"/> struct.
    /// </summary>
    /// <param name="tag">The structure tag.</param>
    /// <param name="size">The total size including header.</param>
    /// <param name="code">The command or response code.</param>
    public TpmHeader(ushort tag, uint size, uint code)
    {
        Tag = tag;
        Size = size;
        Code = code;
    }

    /// <summary>
    /// Creates a command header without authorization sessions.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="totalSize">The total command size including header.</param>
    /// <returns>A new command header.</returns>
    public static TpmHeader CreateCommand(Tpm2CcConstants commandCode, uint totalSize)
    {
        return new TpmHeader((ushort)Tpm2StConstants.TPM_ST_NO_SESSIONS, totalSize, (uint)commandCode);
    }

    /// <summary>
    /// Creates a command header with authorization sessions.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="totalSize">The total command size including header.</param>
    /// <returns>A new command header.</returns>
    public static TpmHeader CreateCommandWithSessions(Tpm2CcConstants commandCode, uint totalSize)
    {
        return new TpmHeader((ushort)Tpm2StConstants.TPM_ST_SESSIONS, totalSize, (uint)commandCode);
    }

    /// <summary>
    /// Creates a response header.
    /// </summary>
    /// <param name="responseCode">The response code.</param>
    /// <param name="totalSize">The total response size including header.</param>
    /// <returns>A new response header.</returns>
    public static TpmHeader CreateResponse(TpmRc responseCode, uint totalSize)
    {
        return new TpmHeader((ushort)Tpm2StConstants.TPM_ST_NO_SESSIONS, totalSize, (uint)responseCode);
    }

    /// <inheritdoc/>
    public int SerializedSize => HeaderSize;

    /// <inheritdoc/>
    public static TpmParseResult<TpmHeader> Parse(ReadOnlySpan<byte> source)
    {
        var reader = new TpmReader(source);
        ushort tag = reader.ReadUInt16();
        uint size = reader.ReadUInt32();
        uint code = reader.ReadUInt32();
        return new TpmParseResult<TpmHeader>(new TpmHeader(tag, size, code), reader.Consumed);
    }

    /// <inheritdoc/>
    public void WriteTo(Span<byte> destination)
    {
        var writer = new TpmWriter(destination);
        writer.WriteUInt16(Tag);
        writer.WriteUInt32(Size);
        writer.WriteUInt32(Code);
    }

    /// <summary>
    /// Gets the response code as a <see cref="TpmRc"/> enum value.
    /// </summary>
    public TpmRc ResponseCode => (TpmRc)Code;

    /// <summary>
    /// Gets the command code as a <see cref="Tpm2CcConstants"/> enum value.
    /// </summary>
    public Tpm2CcConstants CommandCode => (Tpm2CcConstants)Code;

    /// <summary>
    /// Gets a value indicating whether this is a success response.
    /// </summary>
    public bool IsSuccess => Code == 0;

    /// <summary>
    /// Gets a value indicating whether this header includes authorization sessions.
    /// </summary>
    public bool HasSessions => Tag == (ushort)Tpm2StConstants.TPM_ST_SESSIONS;

    /// <inheritdoc/>
    public bool Equals(TpmHeader other)
    {
        return Tag == other.Tag && Size == other.Size && Code == other.Code;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is TpmHeader other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Tag, Size, Code);

    /// <summary>
    /// Determines whether two instances are equal.
    /// </summary>
    public static bool operator ==(TpmHeader left, TpmHeader right) => left.Equals(right);

    /// <summary>
    /// Determines whether two instances are not equal.
    /// </summary>
    public static bool operator !=(TpmHeader left, TpmHeader right) => !left.Equals(right);
}
