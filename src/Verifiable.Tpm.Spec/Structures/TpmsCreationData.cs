using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

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
/// Specification reference: TPM 2.0 Library Part 2, Section 15.1, Table 261.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmsCreationData: IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the PCR selection indicating which PCRs are included in pcrDigest.
    /// </summary>
    public TpmlPcrSelection PcrSelect { get; }

    /// <summary>
    /// Gets the digest of the selected PCR using the nameAlg of the object for which this structure is being
    /// created.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Table 261 states <c>pcrDigest.size shall be zero if the pcrSelect list is empty</c> (TPM 2.0 Library
    /// Part 2, clause 15.1, Table 261, printed page 206), so an empty selection is faithfully represented by
    /// <see cref="Tpm2bDigest.Empty"/>.
    /// </para>
    /// <para>
    /// Silicon built from the Reference Code's <c>FillInCreationData</c> instead runs its hash unconditionally
    /// for an empty selection, so it emits the full-width hash of zero concatenated values rather than a
    /// size-zero digest (TPM 2.0 Library Part 4, printed pages 722-723). <see cref="Parse"/> accepts both
    /// forms: it is size-driven, so a full-width digest parses exactly as a normal PCR digest of that width.
    /// </para>
    /// </remarks>
    public Tpm2bDigest PcrDigest { get; }

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
    /// <param name="pcrSelect">The PCR selection this creation data was formed over. Ownership is transferred.</param>
    /// <param name="pcrDigest">The digest of the selected PCR. Ownership is transferred.</param>
    /// <param name="locality">The locality at which the object was created.</param>
    /// <param name="parentNameAlg">The parent's nameAlg.</param>
    /// <param name="parentName">The parent's Name at time of creation. Ownership is transferred.</param>
    /// <param name="parentQualifiedName">The parent's Qualified Name at time of creation. Ownership is transferred.</param>
    /// <param name="outsideInfo">The creator-supplied outsideInfo. Ownership is transferred.</param>
    private TpmsCreationData(
        TpmlPcrSelection pcrSelect,
        Tpm2bDigest pcrDigest,
        TpmaLocality locality,
        TpmAlgIdConstants parentNameAlg,
        Tpm2bName parentName,
        Tpm2bName parentQualifiedName,
        Tpm2bData outsideInfo)
    {
        PcrSelect = pcrSelect;
        PcrDigest = pcrDigest;
        Locality = locality;
        ParentNameAlg = parentNameAlg;
        ParentName = parentName;
        ParentQualifiedName = parentQualifiedName;
        OutsideInfo = outsideInfo;
    }

    /// <summary>
    /// Parses creation data from a TPM reader.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Fields are parsed in wire order (Table 261). When a LATER field refuses the octets it was handed —
    /// whether an oversize declared length or a buffer truncated before that field's own declared size, every
    /// fixture in <c>TpmCreationDataCarrierTests</c> exercises both — every already-built carrier is disposed
    /// before the exception leaves this method: <see cref="PcrSelect"/>, <see cref="PcrDigest"/>,
    /// <see cref="ParentName"/> and <see cref="ParentQualifiedName"/> are each rented from <paramref name="pool"/>
    /// and would otherwise be orphaned, following the same nested try/catch/dispose/rethrow shape as
    /// <see cref="Tpm2bCreationData.FromMarshaled"/>.
    /// </para>
    /// <para>
    /// This holds for a truncated tail as well as an oversize field: <see cref="Tpm2bDigest.Parse"/>,
    /// <see cref="Tpm2bName.Parse"/> and <see cref="Tpm2bData.Parse"/> each check the declared size against the
    /// reader's remaining octets before renting, so a field that runs past the end of the wire buffer throws
    /// before it ever rents rather than after — leaving nothing for this method's own catch blocks to release on
    /// that field, and nothing for them to orphan on any later one either.
    /// </para>
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed creation data.</returns>
    /// <exception cref="InvalidOperationException"><c>pcrSelect</c> names more than <see cref="TpmlPcrSelection.MaxSelections"/> banks, or <c>pcrDigest</c>, <c>parentName</c>, <c>parentQualifiedName</c> or <c>outsideInfo</c> declares a size past its own structure's bound (<see cref="Tpm2bDigest.MaxSize"/>, <see cref="Tpm2bName.MaxSize"/>, <see cref="Tpm2bData.MaxSize"/>).</exception>
    /// <exception cref="ArgumentOutOfRangeException">A <c>pcrSelect</c> entry's <c>sizeofSelect</c> lies outside <see cref="TpmlPcrSelection.PcrSelectMin"/>..<see cref="TpmlPcrSelection.PcrSelectMax"/>, or a later field's declared size exceeds the octets remaining in <paramref name="reader"/>.</exception>
    public static TpmsCreationData Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        TpmlPcrSelection pcrSelect = TpmlPcrSelection.Parse(ref reader, pool);
        try
        {
            Tpm2bDigest pcrDigest = Tpm2bDigest.Parse(ref reader, pool);
            try
            {
                var locality = (TpmaLocality)reader.ReadByte();
                var parentNameAlg = (TpmAlgIdConstants)reader.ReadUInt16();
                Tpm2bName parentName = Tpm2bName.Parse(ref reader, pool);
                try
                {
                    Tpm2bName parentQualifiedName = Tpm2bName.Parse(ref reader, pool);
                    try
                    {
                        Tpm2bData outsideInfo = Tpm2bData.Parse(ref reader, pool);

                        return new TpmsCreationData(
                            pcrSelect,
                            pcrDigest,
                            locality,
                            parentNameAlg,
                            parentName,
                            parentQualifiedName,
                            outsideInfo);
                    }
                    catch
                    {
                        parentQualifiedName.Dispose();
                        throw;
                    }
                }
                catch
                {
                    parentName.Dispose();
                    throw;
                }
            }
            catch
            {
                pcrDigest.Dispose();
                throw;
            }
        }
        catch
        {
            pcrSelect.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            PcrSelect.Dispose();
            PcrDigest.Dispose();
            ParentName.Dispose();
            ParentQualifiedName.Dispose();
            OutsideInfo.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay =>
        $"TPMS_CREATION_DATA(locality={Locality}, parentAlg={ParentNameAlg}, pcrDigest={PcrDigest.Size} bytes)";
}
