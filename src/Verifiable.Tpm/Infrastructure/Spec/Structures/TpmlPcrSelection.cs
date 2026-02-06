using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

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
///     UINT32 count;                            // Number of selections (0 to PCR_SELECT_MAX).
///     TPMS_PCR_SELECTION pcrSelections[count]; // Array of selections.
/// } TPML_PCR_SELECTION;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.6.3.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmlPcrSelection: ITpmWireType, IDisposable
{
    /// <summary>
    /// Maximum number of PCR selections allowed.
    /// </summary>
    public const int MaxSelections = 16; // PCR_SELECT_MAX per spec.

    private static readonly TpmlPcrSelection EmptyInstance = new([], []);

    private readonly TpmsPcrSelection[] selections;
    private readonly IMemoryOwner<byte>[] storageOwners;
    private bool disposed;

    /// <summary>
    /// Initializes a new PCR selection list.
    /// </summary>
    private TpmlPcrSelection(TpmsPcrSelection[] selections, IMemoryOwner<byte>[] storageOwners)
    {
        this.selections = selections;
        this.storageOwners = storageOwners;
    }

    /// <summary>
    /// Gets an empty PCR selection list.
    /// </summary>
    public static TpmlPcrSelection Empty => EmptyInstance;

    /// <summary>
    /// Gets the PCR selections.
    /// </summary>
    public IReadOnlyList<TpmsPcrSelection> Selections => selections;

    /// <summary>
    /// Gets the number of selections.
    /// </summary>
    public int Count => selections.Length;

    /// <summary>
    /// Gets whether this list is empty.
    /// </summary>
    public bool IsEmpty => selections.Length == 0;

    /// <summary>
    /// Gets the selection at the specified index.
    /// </summary>
    /// <param name="index">The index.</param>
    /// <returns>The selection.</returns>
    public TpmsPcrSelection this[int index] => selections[index];

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        int size = sizeof(uint); //Count.
        foreach(var selection in selections)
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

        writer.WriteUInt32((uint)selections.Length);

        foreach(var selection in selections)
        {
            writer.WriteUInt16((ushort)selection.HashAlgorithm);
            writer.WriteByte((byte)selection.PcrSelect.Length);
            writer.WriteBytes(selection.PcrSelect.Span);
        }
    }

    /// <summary>
    /// Parses a PCR selection list from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed selection list.</returns>
    public static TpmlPcrSelection Parse(ref TpmReader reader, MemoryPool<byte> pool)
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

        for(int i = 0; i < count; i++)
        {
            var hashAlg = (TpmAlgIdConstants)reader.ReadUInt16();
            byte sizeofSelect = reader.ReadByte();

            IMemoryOwner<byte> storage = pool.Rent(sizeofSelect);
            ReadOnlySpan<byte> source = reader.ReadBytes(sizeofSelect);
            source.CopyTo(storage.Memory.Span.Slice(0, sizeofSelect));

            storageOwners[i] = storage;
            selections[i] = new TpmsPcrSelection(hashAlg, storage.Memory.Slice(0, sizeofSelect));
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
    public static TpmlPcrSelection Create(TpmAlgIdConstants hashAlg, ReadOnlySpan<int> pcrIndices, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(pcrIndices.IsEmpty)
        {
            return Empty;
        }

        //PCR selection bitmap: 3 bytes for PCRs 0-23.
        const int SelectSize = 3;
        IMemoryOwner<byte> storage = pool.Rent(SelectSize);
        Span<byte> bitmap = storage.Memory.Span.Slice(0, SelectSize);
        bitmap.Clear();

        foreach(int index in pcrIndices)
        {
            if(index < 0 || index > 23)
            {
                storage.Dispose();
                throw new ArgumentOutOfRangeException(nameof(pcrIndices), $"PCR index {index} is out of range (0-23).");
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
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed && this != EmptyInstance)
        {
            foreach(var owner in storageOwners)
            {
                owner?.Dispose();
            }

            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPML_PCR_SELECTION({selections.Length} selections)";
}