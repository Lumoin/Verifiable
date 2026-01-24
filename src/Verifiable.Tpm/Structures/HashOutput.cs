using System;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Commands;

/// <summary>
/// Output for the TPM2_Hash command.
/// </summary>
/// <remarks>
/// <para>
/// Contains the resulting hash digest and a validation ticket.
/// </para>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 3: Commands, Section 15.4 - TPM2_Hash.
/// </para>
/// </remarks>
public readonly struct HashOutput: ITpmCommandOutput<HashOutput>, IEquatable<HashOutput>
{
    /// <summary>
    /// Gets the resulting hash digest.
    /// </summary>
    public ReadOnlyMemory<byte> Digest { get; }

    /// <summary>
    /// Gets the validation ticket tag.
    /// </summary>
    public ushort TicketTag { get; }

    /// <summary>
    /// Gets the hierarchy associated with the ticket.
    /// </summary>
    public uint TicketHierarchy { get; }

    /// <summary>
    /// Gets the ticket digest.
    /// </summary>
    public ReadOnlyMemory<byte> TicketDigest { get; }

    /// <inheritdoc/>
    public int SerializedSize => sizeof(ushort) + Digest.Length +
                                  sizeof(ushort) + sizeof(uint) +
                                  sizeof(ushort) + TicketDigest.Length;

    /// <summary>
    /// Initializes a new instance of the <see cref="HashOutput"/> struct.
    /// </summary>
    /// <param name="digest">The hash digest.</param>
    /// <param name="ticketTag">The ticket tag.</param>
    /// <param name="ticketHierarchy">The ticket hierarchy.</param>
    /// <param name="ticketDigest">The ticket digest.</param>
    public HashOutput(byte[] digest, ushort ticketTag = 0, uint ticketHierarchy = 0, byte[]? ticketDigest = null)
    {
        Digest = digest;
        TicketTag = ticketTag;
        TicketHierarchy = ticketHierarchy;
        TicketDigest = ticketDigest ?? [];
    }

    /// <inheritdoc/>
    public static TpmParseResult<HashOutput> Parse(ReadOnlySpan<byte> source)
    {
        var reader = new TpmReader(source);

        byte[] digest = reader.ReadTpm2b().ToArray();
        ushort ticketTag = reader.ReadUInt16();
        uint ticketHierarchy = reader.ReadUInt32();
        byte[] ticketDigest = reader.ReadTpm2b().ToArray();

        return new TpmParseResult<HashOutput>(
            new HashOutput(digest, ticketTag, ticketHierarchy, ticketDigest),
            reader.Consumed);
    }

    /// <inheritdoc/>
    public void WriteTo(Span<byte> destination)
    {
        var writer = new TpmWriter(destination);

        writer.WriteTpm2b(Digest.Span);
        writer.WriteUInt16(TicketTag);
        writer.WriteUInt32(TicketHierarchy);
        writer.WriteTpm2b(TicketDigest.Span);
    }

    /// <inheritdoc/>
    public bool Equals(HashOutput other)
    {
        return TicketTag == other.TicketTag &&
               TicketHierarchy == other.TicketHierarchy &&
               Digest.Span.SequenceEqual(other.Digest.Span) &&
               TicketDigest.Span.SequenceEqual(other.TicketDigest.Span);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is HashOutput other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(TicketTag);
        hash.Add(TicketHierarchy);
        hash.AddBytes(Digest.Span);
        hash.AddBytes(TicketDigest.Span);
        return hash.ToHashCode();
    }

    /// <summary>
    /// Determines whether two instances are equal.
    /// </summary>
    public static bool operator ==(HashOutput left, HashOutput right) => left.Equals(right);

    /// <summary>
    /// Determines whether two instances are not equal.
    /// </summary>
    public static bool operator !=(HashOutput left, HashOutput right) => !left.Equals(right);
}