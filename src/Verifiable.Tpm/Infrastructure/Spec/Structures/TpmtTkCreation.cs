using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Creation ticket proving object creation (TPMT_TK_CREATION).
/// </summary>
/// <remarks>
/// <para>
/// This ticket is produced by <c>TPM2_Create()</c> or <c>TPM2_CreatePrimary()</c>.
/// It binds the creation data to the object and proves the object was created
/// by the TPM under a specific hierarchy.
/// </para>
/// <para>
/// <b>Ticket computation:</b>
/// </para>
/// <code>
/// HMACcontextAlg(proof, (TPM_ST_CREATION || name || HnameAlg(TPMS_CREATION_DATA)))
/// </code>
/// <para>
/// Where:
/// </para>
/// <list type="bullet">
///   <item><description><b>proof</b> - TPM secret value associated with the hierarchy.</description></item>
///   <item><description><b>name</b> - Name of the created object.</description></item>
///   <item><description><b>HnameAlg</b> - Hash using the object's nameAlg.</description></item>
/// </list>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM_ST tag;                              // TPM_ST_CREATION.
///     TPMI_RH_HIERARCHY hierarchy;             // Hierarchy containing the object.
///     TPM2B_DIGEST digest;                     // HMAC proof value.
/// } TPMT_TK_CREATION;
/// </code>
/// <para>
/// <b>NULL ticket:</b> A NULL Creation Ticket is the tuple
/// (TPM_ST_CREATION, TPM_RH_NULL, empty digest).
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.7.3, Table 109.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmtTkCreation: IDisposable, ITpmWireType
{
    private static readonly TpmtTkCreation NullInstance = new(
        TpmStConstants.TPM_ST_CREATION,
        TpmRh.TPM_RH_NULL,
        null,
        0);

    private readonly IMemoryOwner<byte>? storage;
    private readonly int digestLength;
    private bool disposed;

    /// <summary>
    /// Gets the ticket structure tag (must be TPM_ST_CREATION).
    /// </summary>
    public TpmStConstants Tag { get; }

    /// <summary>
    /// Gets the hierarchy containing the created object.
    /// </summary>
    /// <remarks>
    /// One of TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM, TPM_RH_NULL.
    /// </remarks>
    public TpmRh Hierarchy { get; }

    /// <summary>
    /// Initializes a new creation ticket.
    /// </summary>
    private TpmtTkCreation(TpmStConstants tag, TpmRh hierarchy, IMemoryOwner<byte>? storage, int digestLength)
    {
        Tag = tag;
        Hierarchy = hierarchy;
        this.storage = storage;
        this.digestLength = digestLength;
    }

    /// <summary>
    /// Gets a NULL creation ticket.
    /// </summary>
    public static TpmtTkCreation Null => NullInstance;

    /// <summary>
    /// Gets whether this is a NULL ticket.
    /// </summary>
    public bool IsNull => Hierarchy == TpmRh.TPM_RH_NULL && digestLength == 0;

    /// <summary>
    /// Gets the digest as a read-only span.
    /// </summary>
    public ReadOnlySpan<byte> Digest
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            if(storage is null)
            {
                return ReadOnlySpan<byte>.Empty;
            }

            return storage.Memory.Span.Slice(0, digestLength);
        }
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => sizeof(ushort) + sizeof(uint) + sizeof(ushort) + digestLength;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt16((ushort)Tag);
        writer.WriteUInt32((uint)Hierarchy);
        writer.WriteUInt16((ushort)digestLength);

        if(digestLength > 0)
        {
            writer.WriteBytes(Digest);
        }
    }

    /// <summary>
    /// Parses a creation ticket from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed creation ticket.</returns>
    public static TpmtTkCreation Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort tag = reader.ReadUInt16();

        if(tag != (ushort)TpmStConstants.TPM_ST_CREATION)
        {
            throw new InvalidOperationException($"Invalid creation ticket tag: 0x{tag:X4}. Expected TPM_ST_CREATION.");
        }

        var hierarchy = (TpmRh)reader.ReadUInt32();
        ushort digestSize = reader.ReadUInt16();

        if(digestSize == 0)
        {
            if(hierarchy == TpmRh.TPM_RH_NULL)
            {
                return Null;
            }

            return new TpmtTkCreation((TpmStConstants)tag, hierarchy, null, 0);
        }

        IMemoryOwner<byte> storage = pool.Rent(digestSize);
        ReadOnlySpan<byte> source = reader.ReadBytes(digestSize);
        source.CopyTo(storage.Memory.Span.Slice(0, digestSize));

        return new TpmtTkCreation((TpmStConstants)tag, hierarchy, storage, digestSize);
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            storage?.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay
    {
        get
        {
            if(IsNull)
            {
                return "TPMT_TK_CREATION(NULL)";
            }

            string hierarchyName = Hierarchy switch
            {
                TpmRh.TPM_RH_OWNER => "OWNER",
                TpmRh.TPM_RH_ENDORSEMENT => "ENDORSEMENT",
                TpmRh.TPM_RH_PLATFORM => "PLATFORM",
                TpmRh.TPM_RH_NULL => "NULL",
                _ => $"0x{(uint)Hierarchy:X8}"
            };

            return $"TPMT_TK_CREATION({hierarchyName}, {digestLength} bytes)";
        }
    }
}