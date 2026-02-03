using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// TPM2B_SENSITIVE_DATA - a sized buffer for sensitive data in object creation.
/// </summary>
/// <remarks>
/// <para>
/// This structure holds variable-length sensitive data for object creation,
/// prefixed with a 16-bit size field.
/// </para>
/// <para>
/// <b>Wire format (big-endian):</b>
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-1: Size (uint16) - number of octets in buffer.</description></item>
///   <item><description>Bytes 2+: Buffer - the sensitive data.</description></item>
/// </list>
/// <para>
/// <b>Usage:</b>
/// </para>
/// <list type="bullet">
///   <item><description>For symmetric keys: the key material.</description></item>
///   <item><description>For sealed data objects: the data to seal.</description></item>
///   <item><description>For asymmetric keys: typically empty (TPM generates the key).</description></item>
///   <item><description>For derived objects: label and context for derivation.</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.1.14, Table 167.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bSensitiveData: SensitiveMemory, ITpmWireType
{
    /// <summary>
    /// Shared empty instance backed by <see cref="EmptyMemoryOwner"/>.
    /// </summary>
    private static readonly Tpm2bSensitiveData EmptyInstance = new(EmptyMemoryOwner.Instance);

    /// <summary>
    /// Initializes new sensitive data with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the sensitive bytes.</param>
    public Tpm2bSensitiveData(IMemoryOwner<byte> storage) : base(storage, TpmTags.SensitiveData)
    {
    }

    /// <summary>
    /// Gets the length of the sensitive data in bytes.
    /// </summary>
    public int Length => MemoryOwner.Memory.Length;

    /// <summary>
    /// Gets a value indicating whether this sensitive data is empty.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Parses sensitive data from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the sensitive data.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed sensitive data.</returns>
    public static Tpm2bSensitiveData Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ushort length = reader.ReadUInt16();

        if(length == 0)
        {
            return EmptyInstance;
        }

        IMemoryOwner<byte> storage = pool.Rent(length);
        ReadOnlySpan<byte> sourceBytes = reader.ReadBytes(length);
        sourceBytes.CopyTo(storage.Memory.Span.Slice(0, length));

        return new Tpm2bSensitiveData(storage);
    }

    /// <summary>
    /// Writes this sensitive data to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteTpm2b(AsReadOnlySpan());
    }

    /// <summary>
    /// Gets the serialized size (2-byte length prefix + data).
    /// </summary>
    public int GetSerializedSize() => sizeof(ushort) + Length;

    /// <summary>
    /// Creates empty sensitive data.
    /// </summary>
    /// <returns>Empty sensitive data.</returns>
    public static Tpm2bSensitiveData CreateEmpty()
    {
        return EmptyInstance;
    }

    /// <summary>
    /// Creates sensitive data from the specified bytes.
    /// </summary>
    /// <param name="bytes">The sensitive bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created sensitive data.</returns>
    public static Tpm2bSensitiveData Create(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        if(bytes.IsEmpty)
        {
            return EmptyInstance;
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        bytes.CopyTo(storage.Memory.Span);
        return new Tpm2bSensitiveData(storage);
    }

    private string DebuggerDisplay => $"TPM2B_SENSITIVE_DATA({Length} bytes)";
}