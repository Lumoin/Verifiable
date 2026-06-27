using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Certify-specific attestation information (TPMS_CERTIFY_INFO), the <c>certify</c> member of TPMU_ATTEST.
/// </summary>
/// <remarks>
/// <para>
/// Produced by <c>TPM2_Certify</c>: attests that an object with the given <see cref="Name"/> (and
/// <see cref="QualifiedName"/>) is loaded in the TPM. A verifier confirms the binding by recomputing the
/// certified object's Name (<c>nameAlg || H(TPMT_PUBLIC)</c>) from its exported public area and comparing it to
/// <see cref="Name"/>.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM2B_NAME name;                         // Name of the certified object.
///     TPM2B_NAME qualifiedName;                // Qualified Name of the certified object.
/// } TPMS_CERTIFY_INFO;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.12.3, Table 169.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmsCertifyInfo: ITpmWireType, IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the Name of the certified object.
    /// </summary>
    public Tpm2bName Name { get; }

    /// <summary>
    /// Gets the Qualified Name of the certified object.
    /// </summary>
    public Tpm2bName QualifiedName { get; }

    /// <summary>
    /// Initializes a new certify-info structure.
    /// </summary>
    /// <param name="name">The certified object's Name. Ownership is transferred.</param>
    /// <param name="qualifiedName">The certified object's Qualified Name. Ownership is transferred.</param>
    private TpmsCertifyInfo(Tpm2bName name, Tpm2bName qualifiedName)
    {
        Name = name;
        QualifiedName = qualifiedName;
    }

    /// <summary>
    /// Creates a certify-info structure from a name and qualified name (for tests and round-trips).
    /// </summary>
    /// <param name="name">The certified object's Name. Ownership is transferred.</param>
    /// <param name="qualifiedName">The certified object's Qualified Name. Ownership is transferred.</param>
    /// <returns>The created certify info.</returns>
    public static TpmsCertifyInfo Create(Tpm2bName name, Tpm2bName qualifiedName)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(qualifiedName);

        return new TpmsCertifyInfo(name, qualifiedName);
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            return Name.SerializedSize + QualifiedName.SerializedSize;
        }
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        Name.WriteTo(ref writer);
        QualifiedName.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a certify-info structure from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed certify info.</returns>
    public static TpmsCertifyInfo Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bName name = Tpm2bName.Parse(ref reader, pool);
        Tpm2bName qualifiedName = Tpm2bName.Parse(ref reader, pool);

        return new TpmsCertifyInfo(name, qualifiedName);
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Name.Dispose();
            QualifiedName.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPMS_CERTIFY_INFO(name={Name.Size} bytes, qualifiedName={QualifiedName.Size} bytes)";
}
