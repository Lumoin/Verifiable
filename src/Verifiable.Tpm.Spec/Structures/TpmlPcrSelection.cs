using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// List of PCR selections (TPML_PCR_SELECTION).
/// </summary>
/// <remarks>
/// <para>
/// Used in commands like <c>TPM2_CreatePrimary()</c>, <c>TPM2_Create()</c>,
/// <c>TPM2_PCR_Read()</c>, and <c>TPM2_Quote()</c> to specify which PCRs
/// to include in an operation.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT32 count;                            // Number of selections (0 to HASH_COUNT).
///     TPMS_PCR_SELECTION pcrSelections[count]; // Array of selections.
/// } TPML_PCR_SELECTION;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 10.8.7, Table 128.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmlPcrSelection: ITpmWireType, IDisposable
{
    /// <summary>
    /// The greatest number of <see cref="TpmsPcrSelection"/> entries this list admits — the <c>HASH_COUNT</c>
    /// bound Table 128 places on <c>pcrSelections[count]</c>, whose violation the table names
    /// <c>#TPM_RC_SIZE</c> ("response code when count is greater than the possible number of banks", TPM 2.0
    /// Library Part 2, clause 10.8.7). This bounds the COUNT of banks a selection may name, never the octet
    /// width of any one bank's bitmap (that is <see cref="PcrSelectMax"/>). The value is a widened
    /// implementation bound: <c>HASH_COUNT</c> is the number of hash algorithms a TPM implements, so sixteen
    /// admits every bank allocation this library models and any a device is likely to report.
    /// </summary>
    public const int MaxSelections = 16;

    /// <summary>
    /// The least <c>sizeofSelect</c> a conformant <c>TPMS_PCR_SELECTION</c> may carry —
    /// <c>PCR_SELECT_MIN ≔ (PLATFORM_PCR + 7)/8</c> (TPM 2.0 Library Part 2, clause 10.5.1, equation 1), with
    /// <c>PLATFORM_PCR</c> the number of PCR the platform-specific specification requires. Every platform this
    /// library targets requires 24 PCR, so the bitmap is at least three octets wide. Table 107 states the bound
    /// as <c>sizeofSelect {PCR_SELECT_MIN:}</c> and names <c>#TPM_RC_VALUE</c> for a violation, which is what
    /// the reference unmarshaler answers for a width outside
    /// <see cref="PcrSelectMin"/>..<see cref="PcrSelectMax"/>.
    /// </summary>
    public const int PcrSelectMin = 3;

    /// <summary>
    /// The greatest <c>sizeofSelect</c> this list admits — <c>PCR_SELECT_MAX ≔ (IMPLEMENTATION_PCR + 7)/8</c>
    /// (TPM 2.0 Library Part 2, clause 10.5.1, equation 2), the octet width of a bitmap covering every PCR the
    /// TPM implements; Table 107 states it as <c>pcrSelect[sizeofSelect] {:PCR_SELECT_MAX}</c> with
    /// <c>#TPM_RC_VALUE</c>. <c>IMPLEMENTATION_PCR</c> is implementation-dependent, so this is a documented
    /// widening — 32 octets, 256 PCR — in the same spirit as <see cref="TpmHandleRanges.PCR_LAST"/> spanning
    /// the type's full index space rather than one implementation's live PCR count: a selection from any device
    /// this library talks to parses, while an octet count no TPM could mean is still refused. A bitmap wider
    /// than the PCR a bank actually implements is not an error — "if the TPM implements more PCR than there are
    /// bits in pcrSelect, the additional PCR are not selected" (clause 10.5.1), and the converse is settled by
    /// clearing the surplus bits where the selection is applied.
    /// </summary>
    public const int PcrSelectMax = 32;

    private static TpmlPcrSelection EmptyInstance { get; } = new([], []);
    private IMemoryOwner<byte>[] StorageOwners { get; }
    private bool disposed;

    /// <summary>
    /// Initializes a new PCR selection list.
    /// </summary>
    private TpmlPcrSelection(TpmsPcrSelection[] selections, IMemoryOwner<byte>[] storageOwners)
    {
        this.Selections = selections;
        this.StorageOwners = storageOwners;
    }

    /// <summary>
    /// Gets an empty PCR selection list.
    /// </summary>
    public static TpmlPcrSelection Empty => EmptyInstance;

    /// <summary>
    /// Gets the PCR selections.
    /// </summary>
    public TpmsPcrSelection[] Selections { get; }

    /// <summary>
    /// Gets the number of selections.
    /// </summary>
    public int Count => Selections.Length;

    /// <summary>
    /// Gets whether this list is empty.
    /// </summary>
    public bool IsEmpty => Selections.Length == 0;

    /// <summary>
    /// Gets the selection at the specified index.
    /// </summary>
    /// <param name="index">The index.</param>
    /// <returns>The selection.</returns>
    public TpmsPcrSelection this[int index] => Selections[index];

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        int size = sizeof(uint); //Count.
        foreach(var selection in Selections)
        {
            //Hash (2) + sizeofSelect (1) + pcrSelect (variable).
            size += sizeof(ushort) + sizeof(byte) + selection.PcrSelect.Length;
        }

        return size;
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt32((uint)Selections.Length);

        foreach(var selection in Selections)
        {
            writer.WriteUInt16((ushort)selection.HashAlgorithm);
            writer.WriteByte((byte)selection.PcrSelect.Length);
            writer.WriteBytes(selection.PcrSelect.Span);
        }
    }

    /// <summary>
    /// Parses a PCR selection list from a TPM reader.
    /// </summary>
    /// <remarks>
    /// Both wire bounds are checked BEFORE the octets they govern are rented, so a malformed list never leaves a
    /// pinned rental behind and never reaches the pool with a width the pool refuses. The two are distinguished
    /// by the exception they raise because Table 128 and Table 107 name different response codes for them: a
    /// <c>count</c> above <see cref="MaxSelections"/> is <c>#TPM_RC_SIZE</c> and raises
    /// <see cref="InvalidOperationException"/>, while a <c>sizeofSelect</c> outside
    /// <see cref="PcrSelectMin"/>..<see cref="PcrSelectMax"/> is <c>#TPM_RC_VALUE</c> and raises
    /// <see cref="ArgumentOutOfRangeException"/> — the same split the reference unmarshaler makes between
    /// <c>TPML_PCR_SELECTION_Unmarshal</c> and <c>TPMS_PCR_SELECTION_Unmarshal</c>.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed selection list.</returns>
    /// <exception cref="InvalidOperationException">The list names more than <see cref="MaxSelections"/> banks — <c>TPM_RC_SIZE</c>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">A selection's <c>sizeofSelect</c> lies outside <see cref="PcrSelectMin"/>..<see cref="PcrSelectMax"/> — <c>TPM_RC_VALUE</c>.</exception>
    public static TpmlPcrSelection Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        uint count = reader.ReadUInt32();

        if(count == 0)
        {
            return Empty;
        }

        if(count > MaxSelections)
        {
            throw new InvalidOperationException($"PCR selection count {count} exceeds maximum {MaxSelections}.");
        }

        var selections = new TpmsPcrSelection[(int)count];
        var storageOwners = new IMemoryOwner<byte>[(int)count];
        int filled = 0;
        try
        {
            for(int i = 0; i < count; i++)
            {
                var hashAlg = (TpmAlgIdConstants)reader.ReadUInt16();
                byte sizeofSelect = reader.ReadByte();

                //The width is settled before the rental it sizes: a zero sizeofSelect would otherwise reach the
                //pool as a zero-length rent, and a width no PCR bitmap can have is TPM_RC_VALUE by Table 107's
                //own bounds rather than an allocation failure.
                if(sizeofSelect < PcrSelectMin || sizeofSelect > PcrSelectMax)
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(reader),
                        sizeofSelect,
                        $"A TPMS_PCR_SELECTION sizeofSelect must lie between {PcrSelectMin} and {PcrSelectMax} octets.");
                }

                //Record the rental before the read that can throw, so a later selection whose sizeofSelect
                //overruns the buffer disposes this buffer and every earlier one rather than orphaning them.
                IMemoryOwner<byte> storage = pool.Rent(sizeofSelect);
                storageOwners[i] = storage;
                filled = i + 1;

                ReadOnlySpan<byte> source = reader.ReadBytes(sizeofSelect);
                source.CopyTo(storage.Memory.Span.Slice(0, sizeofSelect));

                selections[i] = new TpmsPcrSelection(hashAlg, storage.Memory.Slice(0, sizeofSelect));
            }
        }
        catch
        {
            for(int i = 0; i < filled; i++)
            {
                storageOwners[i]?.Dispose();
            }

            throw;
        }

        return new TpmlPcrSelection(selections, storageOwners);
    }

    /// <summary>
    /// Creates a PCR selection for a single bank with specified PCR indices.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm (bank).</param>
    /// <param name="pcrIndices">The PCR indices to select (0-23).</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The PCR selection list.</returns>
    public static TpmlPcrSelection Create(TpmAlgIdConstants hashAlg, ReadOnlySpan<int> pcrIndices, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(pcrIndices.IsEmpty)
        {
            return Empty;
        }

        //The narrowest conformant bitmap (PCR_SELECT_MIN octets), which covers the 24 PCR every targeted
        //platform-specific specification requires.
        const int SelectSize = PcrSelectMin;
        IMemoryOwner<byte> storage = pool.Rent(SelectSize);
        Span<byte> bitmap = storage.Memory.Span.Slice(0, SelectSize);
        bitmap.Clear();

        foreach(int index in pcrIndices)
        {
            if(index < 0 || index >= SelectSize * 8)
            {
                storage.Dispose();
                throw new ArgumentOutOfRangeException(nameof(pcrIndices), $"PCR index {index} is out of range (0-{(SelectSize * 8) - 1}).");
            }

            //Set the bit for this PCR.
            int byteIndex = index / 8;
            int bitIndex = index % 8;
            bitmap[byteIndex] |= (byte)(1 << bitIndex);
        }

        var selection = new TpmsPcrSelection(hashAlg, storage.Memory.Slice(0, SelectSize));
        var selections = new TpmsPcrSelection[] { selection };
        var storageOwners = new IMemoryOwner<byte>[] { storage };

        return new TpmlPcrSelection(selections, storageOwners);
    }

    /// <summary>
    /// Clears every selected bit that names a PCR the implementation does not hold, leaving the list naming
    /// exactly the registers an operation over it actually covers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// "If the TPM implements more PCR than there are bits in pcrSelect, the additional PCR are not selected"
    /// (TPM 2.0 Library Part 2, clause 10.5.1), and the converse — a bit naming a register the TPM does not have
    /// — is settled the same way: the bit is cleared rather than refused. The reference does this in
    /// <c>FilterPcr</c>, called from <c>PCRComputeCurrentDigest</c> and <c>PCRRead</c>, whose contract is stated
    /// as "as a side-effect, 'selection' is modified so that only the implemented PCR will have their bits still
    /// set"; a selection naming a bank the TPM has not allocated has all of its bits cleared, its entry
    /// retained. <c>TPM2_Quote()</c> then attests the FILTERED list ("Copy PCR select. 'PCRselect' is modified in
    /// PCRComputeCurrentDigest"), so a verifier reads which registers the digest actually covers rather than
    /// which ones the caller asked for.
    /// </para>
    /// <para>
    /// The mask is applied in place over the list's own rented storage, so the marshaled width is unchanged and
    /// no allocation is needed — which is what lets a caller holding no memory pool apply it.
    /// </para>
    /// </remarks>
    /// <param name="implementedBanks">The hash algorithms whose PCR banks the implementation has allocated; a selection naming any other bank keeps its entry with every bit cleared.</param>
    /// <param name="implementedPcrCount">The number of registers each allocated bank holds; a bit naming an index at or above it is cleared.</param>
    public void RetainImplementedPcrs(ReadOnlySpan<TpmAlgIdConstants> implementedBanks, int implementedPcrCount)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        foreach(TpmsPcrSelection selection in Selections)
        {
            bool isAllocated = false;
            foreach(TpmAlgIdConstants bank in implementedBanks)
            {
                if(bank == selection.HashAlgorithm)
                {
                    isAllocated = true;
                    break;
                }
            }

            //The carrier owns this buffer outright — it was rented by Parse or Create and is aliased nowhere
            //else — so the mask is written straight into it rather than through a fresh copy.
            Span<byte> bitmap = MemoryMarshal.AsMemory(selection.PcrSelect).Span;
            if(!isAllocated)
            {
                bitmap.Clear();

                continue;
            }

            for(int byteIndex = 0; byteIndex < bitmap.Length; byteIndex++)
            {
                for(int bitIndex = 0; bitIndex < 8; bitIndex++)
                {
                    if((byteIndex * 8) + bitIndex >= implementedPcrCount)
                    {
                        bitmap[byteIndex] &= (byte)~(1 << bitIndex);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed && this != EmptyInstance)
        {
            foreach(var owner in StorageOwners)
            {
                owner?.Dispose();
            }

            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPML_PCR_SELECTION({Selections.Length} selections)";
}
