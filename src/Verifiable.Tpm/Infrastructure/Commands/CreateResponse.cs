using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_Create.
/// </summary>
/// <remarks>
/// <para>
/// TPM2_Create has no response handle (the created object is not loaded). Its parameters are
/// (Part 3, Section 12.1):
/// </para>
/// <list type="bullet">
///   <item><description>outPrivate (TPM2B_PRIVATE) - the parent-wrapped sensitive area; persist this and reload with TPM2_Load.</description></item>
///   <item><description>outPublic (TPM2B_PUBLIC) - the public area of the created object.</description></item>
///   <item><description>creationData (TPM2B_CREATION_DATA) - the creation data.</description></item>
///   <item><description>creationHash (TPM2B_DIGEST) - digest of creationData using nameAlg.</description></item>
///   <item><description>creationTicket (TPMT_TK_CREATION) - ticket used by TPM2_CertifyCreation.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class CreateResponse: ITpmWireType, IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the parent-wrapped private blob. Persist this (with <see cref="OutPublic"/>) and present it to
    /// TPM2_Load to bring the object back into a transient slot.
    /// </summary>
    public Tpm2bPrivate OutPrivate { get; }

    /// <summary>
    /// Gets the public area of the created object.
    /// </summary>
    public Tpm2bPublic OutPublic { get; }

    /// <summary>
    /// Gets the creation data for the object.
    /// </summary>
    public Tpm2bCreationData CreationData { get; }

    /// <summary>
    /// Gets the digest of the creation data.
    /// </summary>
    public Tpm2bDigest CreationHash { get; }

    /// <summary>
    /// Gets the creation ticket.
    /// </summary>
    public TpmtTkCreation CreationTicket { get; }

    private CreateResponse(
        Tpm2bPrivate outPrivate,
        Tpm2bPublic outPublic,
        Tpm2bCreationData creationData,
        Tpm2bDigest creationHash,
        TpmtTkCreation creationTicket)
    {
        OutPrivate = outPrivate;
        OutPublic = outPublic;
        CreationData = creationData;
        CreationHash = creationHash;
        CreationTicket = creationTicket;
    }

    /// <summary>
    /// Parses the response parameters from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for allocations.</param>
    /// <returns>The parsed response.</returns>
    public static CreateResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        Tpm2bPrivate outPrivate = Tpm2bPrivate.Parse(ref reader, pool);
        Tpm2bPublic outPublic = Tpm2bPublic.Parse(ref reader, pool);
        Tpm2bCreationData creationData = Tpm2bCreationData.Parse(ref reader, pool);
        Tpm2bDigest creationHash = Tpm2bDigest.Parse(ref reader, pool);
        TpmtTkCreation creationTicket = TpmtTkCreation.Parse(ref reader, pool);

        return new CreateResponse(outPrivate, outPublic, creationData, creationHash, creationTicket);
    }

    /// <summary>
    /// Releases resources owned by this response.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            OutPrivate.Dispose();
            OutPublic.Dispose();
            CreationData.Dispose();
            CreationHash.Dispose();
            CreationTicket.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"CreateResponse(private={OutPrivate.Length} bytes, {OutPublic.PublicArea.Type})";
}
