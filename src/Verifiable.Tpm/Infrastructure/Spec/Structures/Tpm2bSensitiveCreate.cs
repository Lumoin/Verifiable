using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Sized buffer containing sensitive creation data (TPM2B_SENSITIVE_CREATE).
/// </summary>
/// <remarks>
/// <para>
/// This is a TPM2B wrapper around <see cref="TpmsSensitiveCreate"/>. The size
/// field indicates the total size of the contained TPMS_SENSITIVE_CREATE.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of sensitive in bytes.
///     TPMS_SENSITIVE_CREATE sensitive;         // The sensitive data.
/// } TPM2B_SENSITIVE_CREATE;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.1.16, Table 169.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bSensitiveCreate: IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the sensitive creation data.
    /// </summary>
    public TpmsSensitiveCreate Sensitive { get; }

    /// <summary>
    /// Initializes a new sized sensitive creation buffer.
    /// </summary>
    /// <param name="sensitive">The sensitive data.</param>
    public Tpm2bSensitiveCreate(TpmsSensitiveCreate sensitive)
    {
        Sensitive = sensitive;
    }

    /// <summary>
    /// Creates an empty sensitive creation buffer.
    /// </summary>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>Empty sensitive creation buffer.</returns>
    public static Tpm2bSensitiveCreate CreateEmpty(MemoryPool<byte> pool)
    {
        return new Tpm2bSensitiveCreate(TpmsSensitiveCreate.CreateEmpty(pool));
    }

    /// <summary>
    /// Creates a sensitive creation buffer with a password.
    /// </summary>
    /// <param name="password">The password string.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>Sensitive creation buffer with the specified auth.</returns>
    public static Tpm2bSensitiveCreate WithPassword(string password, MemoryPool<byte> pool)
    {
        return new Tpm2bSensitiveCreate(TpmsSensitiveCreate.WithPassword(password, pool));
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Sensitive.SerializedSize;
    

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        int innerSize = Sensitive.SerializedSize;
        writer.WriteUInt16((ushort)innerSize);
        Sensitive.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a sized sensitive creation buffer from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed sensitive creation buffer.</returns>
    public static Tpm2bSensitiveCreate Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return CreateEmpty(pool);
        }

        var sensitive = TpmsSensitiveCreate.Parse(ref reader, pool);
        return new Tpm2bSensitiveCreate(sensitive);
    }

    /// <summary>
    /// Releases resources owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Sensitive.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPM2B_SENSITIVE_CREATE({Sensitive})";
}