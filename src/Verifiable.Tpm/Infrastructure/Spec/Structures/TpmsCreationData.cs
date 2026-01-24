using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Creation data providing environment information (TPMS_CREATION_DATA).
/// </summary>
/// <remarks>
/// <para>
/// This structure provides information about the environment in which an object
/// was created. It includes PCR state, locality, and parent information at the
/// time of creation.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPML_PCR_SELECTION pcrSelect;            // PCRs included in pcrDigest.
///     TPM2B_DIGEST pcrDigest;                  // Digest of selected PCRs.
///     TPMA_LOCALITY locality;                  // Locality at creation.
///     TPM_ALG_ID parentNameAlg;                // Parent's nameAlg.
///     TPM2B_NAME parentName;                   // Parent's Name at creation.
///     TPM2B_NAME parentQualifiedName;          // Parent's QN at creation.
///     TPM2B_DATA outsideInfo;                  // Additional creator info.
/// } TPMS_CREATION_DATA;
/// </code>
/// <para>
/// For primary keys under permanent handles (TPM_RH_OWNER, etc.), parentNameAlg
/// is TPM_ALG_NULL and parentName/parentQualifiedName are the 4-byte handle value.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 15.1, Table 246.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmsCreationData: IDisposable
{
    private readonly IMemoryOwner<byte>? pcrDigestStorage;
    private readonly int pcrDigestLength;
    private bool disposed;

    /// <summary>
    /// Gets the PCR selection indicating which PCRs are included in pcrDigest.
    /// </summary>
    public TpmlPcrSelection PcrSelect { get; }

    /// <summary>
    /// Gets the locality at which the object was created.
    /// </summary>
    public TpmaLocality Locality { get; }

    /// <summary>
    /// Gets the nameAlg of the parent.
    /// </summary>
    /// <remarks>
    /// TPM_ALG_NULL for primary keys under permanent handles.
    /// </remarks>
    public TpmAlgIdConstants ParentNameAlg { get; }

    /// <summary>
    /// Gets the Name of the parent at time of creation.
    /// </summary>
    /// <remarks>
    /// For permanent handles, this is the 4-byte handle value.
    /// </remarks>
    public Tpm2bName ParentName { get; }

    /// <summary>
    /// Gets the Qualified Name of the parent at time of creation.
    /// </summary>
    public Tpm2bName ParentQualifiedName { get; }

    /// <summary>
    /// Gets additional information added by the key creator.
    /// </summary>
    /// <remarks>
    /// Contents of the outsideInfo parameter from TPM2_Create() or TPM2_CreatePrimary().
    /// </remarks>
    public Tpm2bData OutsideInfo { get; }

    /// <summary>
    /// Initializes new creation data.
    /// </summary>
    private TpmsCreationData(
        TpmlPcrSelection pcrSelect,
        IMemoryOwner<byte>? pcrDigestStorage,
        int pcrDigestLength,
        TpmaLocality locality,
        TpmAlgIdConstants parentNameAlg,
        Tpm2bName parentName,
        Tpm2bName parentQualifiedName,
        Tpm2bData outsideInfo)
    {
        PcrSelect = pcrSelect;
        this.pcrDigestStorage = pcrDigestStorage;
        this.pcrDigestLength = pcrDigestLength;
        Locality = locality;
        ParentNameAlg = parentNameAlg;
        ParentName = parentName;
        ParentQualifiedName = parentQualifiedName;
        OutsideInfo = outsideInfo;
    }

    /// <summary>
    /// Gets the digest of selected PCRs using the object's nameAlg.
    /// </summary>
    /// <returns>The PCR digest, or empty if no PCRs selected.</returns>
    public ReadOnlySpan<byte> GetPcrDigest()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(pcrDigestStorage is null)
        {
            return ReadOnlySpan<byte>.Empty;
        }

        return pcrDigestStorage.Memory.Span.Slice(0, pcrDigestLength);
    }

    /// <summary>
    /// Parses creation data from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed creation data.</returns>
    public static TpmsCreationData Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        var pcrSelect = TpmlPcrSelection.Parse(ref reader, pool);

        ushort pcrDigestSize = reader.ReadUInt16();
        IMemoryOwner<byte>? pcrDigestStorage = null;

        if(pcrDigestSize > 0)
        {
            pcrDigestStorage = pool.Rent(pcrDigestSize);
            ReadOnlySpan<byte> source = reader.ReadBytes(pcrDigestSize);
            source.CopyTo(pcrDigestStorage.Memory.Span.Slice(0, pcrDigestSize));
        }

        var locality = (TpmaLocality)reader.ReadByte();
        var parentNameAlg = (TpmAlgIdConstants)reader.ReadUInt16();
        var parentName = Tpm2bName.Parse(ref reader, pool);
        var parentQualifiedName = Tpm2bName.Parse(ref reader, pool);
        var outsideInfo = Tpm2bData.Parse(ref reader, pool);

        return new TpmsCreationData(
            pcrSelect,
            pcrDigestStorage,
            pcrDigestSize,
            locality,
            parentNameAlg,
            parentName,
            parentQualifiedName,
            outsideInfo);
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            PcrSelect.Dispose();
            pcrDigestStorage?.Dispose();
            ParentName.Dispose();
            ParentQualifiedName.Dispose();
            OutsideInfo.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay =>
        $"TPMS_CREATION_DATA(locality={Locality}, parentAlg={ParentNameAlg})";
}