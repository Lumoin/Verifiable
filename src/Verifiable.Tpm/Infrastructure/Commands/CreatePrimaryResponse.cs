using System;
using Verifiable.Tpm.Spec.Structures;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_CreatePrimary.
/// </summary>
/// <remarks>
/// <para>
/// This type represents the complete response for the TPM2_CreatePrimary command,
/// including both the response handle and response parameters.
/// </para>
/// <para>
/// <b>Response handle (Part 3, clause 24.1):</b>
/// </para>
/// <list type="bullet">
///   <item><description>objectHandle (TPMI_DH_OBJECT) - handle for the created primary key.</description></item>
/// </list>
/// <para>
/// <b>Response parameters:</b>
/// </para>
/// <list type="bullet">
///   <item><description>outPublic (TPM2B_PUBLIC) - the public portion of the created object.</description></item>
///   <item><description>creationData (TPM2B_CREATION_DATA) - contains a TPMS_CREATION_DATA.</description></item>
///   <item><description>creationHash (TPM2B_DIGEST) - digest of creationData using nameAlg.</description></item>
///   <item><description>creationTicket (TPMT_TK_CREATION) - ticket used by TPM2_CertifyCreation.</description></item>
///   <item><description>name (TPM2B_NAME) - the name of the created object.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class CreatePrimaryResponse: ITpmWireType, IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the handle for the created primary object.
    /// </summary>
    /// <remarks>
    /// This handle references the newly created primary key in the TPM.
    /// It is a transient handle that must be flushed when no longer needed,
    /// or made persistent via TPM2_EvictControl.
    /// </remarks>
    public TpmiDhObject ObjectHandle { get; }

    /// <summary>
    /// Gets the public portion of the created object.
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

    /// <summary>
    /// Gets the name of the created object.
    /// </summary>
    public Tpm2bName Name { get; }

    private CreatePrimaryResponse(
        TpmiDhObject objectHandle,
        Tpm2bPublic outPublic,
        Tpm2bCreationData creationData,
        Tpm2bDigest creationHash,
        TpmtTkCreation creationTicket,
        Tpm2bName name)
    {
        ObjectHandle = objectHandle;
        OutPublic = outPublic;
        CreationData = creationData;
        CreationHash = creationHash;
        CreationTicket = creationTicket;
        Name = name;
    }

    /// <summary>
    /// Parses the response from handle and parameter data.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="objectHandle">The object handle from the response handle area.</param>
    /// <param name="pool">The memory pool for allocations.</param>
    /// <returns>The parsed response.</returns>
    public static CreatePrimaryResponse Parse(ref TpmReader reader, TpmiDhObject objectHandle, BaseMemoryPool pool)
    {
        //Each parameter rents before the next one is read, and every later read can refuse — the creation
        //ticket's own parse validates both its tag and its hierarchy. A device that answers a malformed
        //response would otherwise strand every carrier already rented for this response, one set per response,
        //so the earlier rentals are released here before the refusal leaves the parse.
        Tpm2bPublic? outPublic = null;
        Tpm2bCreationData? creationData = null;
        Tpm2bDigest? creationHash = null;
        TpmtTkCreation? creationTicket = null;
        try
        {
            outPublic = Tpm2bPublic.Parse(ref reader, pool);
            creationData = Tpm2bCreationData.Parse(ref reader, pool);
            creationHash = Tpm2bDigest.Parse(ref reader, pool);
            creationTicket = TpmtTkCreation.Parse(ref reader, pool);
            Tpm2bName name = Tpm2bName.Parse(ref reader, pool);

            return new CreatePrimaryResponse(objectHandle, outPublic, creationData, creationHash, creationTicket, name);
        }
        catch
        {
            creationTicket?.Dispose();
            creationHash?.Dispose();
            creationData?.Dispose();
            outPublic?.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Releases resources owned by this response.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            OutPublic.Dispose();
            CreationData.Dispose();
            CreationHash.Dispose();
            CreationTicket.Dispose();
            Name.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"CreatePrimaryResponse(Handle=0x{ObjectHandle.Value:X8}, Name={Name.Size} bytes)";
}
