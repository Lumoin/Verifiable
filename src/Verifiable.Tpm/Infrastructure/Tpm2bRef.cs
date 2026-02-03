using System;
using Verifiable.Cryptography;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// A read-only view into a TPM2B buffer for serialization.
/// </summary>
/// <typeparam name="T">The owned TPM2B type being viewed.</typeparam>
/// <remarks>
/// <para>
/// This ref struct provides a lightweight, type-safe view into owned TPM2B data
/// for writing to TPM command buffers. It does not transfer or affect ownership.
/// </para>
/// <para>
/// <strong>Wire format (big-endian):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-1: Size (uint16) - number of octets in buffer.</description></item>
///   <item><description>Bytes 2+: Buffer - the actual data.</description></item>
/// </list>
/// <para>
/// <strong>Type safety:</strong>
/// </para>
/// <para>
/// The generic parameter ensures type safety at compile time. For example,
/// <c>Tpm2bRef&lt;Tpm2bNonce&gt;</c> can only be created from a <see cref="Tpm2bNonce"/>,
/// preventing accidental misuse of auth values as nonces.
/// </para>
/// <para>
/// <strong>Usage:</strong>
/// </para>
/// <code>
/// // Session owns the nonce.
/// Tpm2bNonce nonceCaller = session.NonceCaller;
///
/// // Create a typed view for writing.
/// var nonceRef = new Tpm2bRef&lt;Tpm2bNonce&gt;(nonceCaller);
/// nonceRef.WriteTo(ref writer);
/// </code>
/// <para>
/// See TPM 2.0 Part 2, Section 10.4 for TPM2B structure definitions.
/// </para>
/// </remarks>
/// <seealso cref="BufferRef"/>
public readonly ref struct Tpm2bRef<T>(T source) where T : SensitiveMemory
{
    /// <summary>
    /// Gets a reference to the underlying buffer associated with the source.
    /// </summary>
    private BufferRef Buffer { get; } = new(source);

    /// <summary>
    /// Gets the underlying data as a read-only span.
    /// </summary>
    /// <returns>A read-only span over the buffer data.</returns>
    public ReadOnlySpan<byte> AsSpan() => Buffer.AsSpan();

    /// <summary>
    /// Gets the length of the buffer in bytes.
    /// </summary>
    public int Length => Buffer.Length;

    /// <summary>
    /// Gets a value indicating whether this buffer is empty.
    /// </summary>
    public bool IsEmpty => Buffer.IsEmpty;

    /// <summary>
    /// Gets the tag describing the buffer contents.
    /// </summary>
    public Tag Tag => Buffer.Tag;

    /// <summary>
    /// Writes this TPM2B structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    /// <remarks>
    /// Writes the standard TPM2B format: 2-byte size prefix followed by the data.
    /// </remarks>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteTpm2b(Buffer.AsSpan());
    }

    /// <summary>
    /// Gets the serialized size (2-byte length prefix + data).
    /// </summary>
    public int GetSerializedSize() => sizeof(ushort) + Buffer.Length;
}