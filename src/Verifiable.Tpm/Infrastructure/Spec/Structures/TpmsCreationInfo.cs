using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Creation-specific attestation information (TPMS_CREATION_INFO), the <c>creation</c> member of TPMU_ATTEST.
/// </summary>
/// <remarks>
/// <para>
/// Produced by <c>TPM2_CertifyCreation()</c>: attests that the object with the given <see cref="ObjectName"/>
/// was created by the TPM with the given <see cref="CreationHash"/>. A verifier confirms the binding by
/// recomputing the certified object's Name (<c>nameAlg ‖ H(TPMT_PUBLIC)</c>) from its exported public area and
/// comparing it to <see cref="ObjectName"/>, and by comparing <see cref="CreationHash"/> to the creation hash
/// the object's own creation response reported.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM2B_NAME objectName;                   // Name of the object.
///     TPM2B_DIGEST creationHash;                // creationHash used in creating the object.
/// } TPMS_CREATION_INFO;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.12.7, Table 127.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmsCreationInfo: ITpmWireType, IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the Name of the created object.
    /// </summary>
    public Tpm2bName ObjectName { get; }

    /// <summary>
    /// Gets the creation hash used in creating the object.
    /// </summary>
    public Tpm2bDigest CreationHash { get; }

    /// <summary>
    /// Initializes a new creation-info structure.
    /// </summary>
    /// <param name="objectName">The created object's Name. Ownership is transferred.</param>
    /// <param name="creationHash">The creation hash. Ownership is transferred.</param>
    private TpmsCreationInfo(Tpm2bName objectName, Tpm2bDigest creationHash)
    {
        ObjectName = objectName;
        CreationHash = creationHash;
    }

    /// <summary>
    /// Creates a creation-info structure from an object Name and creation hash (for tests and round-trips).
    /// </summary>
    /// <param name="objectName">The created object's Name. Ownership is transferred.</param>
    /// <param name="creationHash">The creation hash. Ownership is transferred.</param>
    /// <returns>The created creation info.</returns>
    public static TpmsCreationInfo Create(Tpm2bName objectName, Tpm2bDigest creationHash)
    {
        ArgumentNullException.ThrowIfNull(objectName);
        ArgumentNullException.ThrowIfNull(creationHash);

        return new TpmsCreationInfo(objectName, creationHash);
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            return ObjectName.SerializedSize + CreationHash.SerializedSize;
        }
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        ObjectName.WriteTo(ref writer);
        CreationHash.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a creation-info structure from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed creation info.</returns>
    public static TpmsCreationInfo Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bName objectName = Tpm2bName.Parse(ref reader, pool);
        Tpm2bDigest creationHash = Tpm2bDigest.Parse(ref reader, pool);

        return new TpmsCreationInfo(objectName, creationHash);
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            ObjectName.Dispose();
            CreationHash.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPMS_CREATION_INFO(objectName={ObjectName.Size} bytes, creationHash={CreationHash.Size} bytes)";
}
