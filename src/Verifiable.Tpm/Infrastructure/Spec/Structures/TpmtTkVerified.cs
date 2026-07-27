using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;


/// <summary>
/// A ticket produced by TPM2_VerifySignature() (TPMT_TK_VERIFIED).
/// </summary>
/// <remarks>
/// <para>
/// Provides evidence that the TPM has validated that a digest was signed by a key.
/// </para>
/// <para>
/// <b>Ticket computation:</b>
/// </para>
/// <code>
/// HMACcontextAlg(proof, (TPM_ST_VERIFIED || digest || keyName))
/// </code>
/// <para>
/// Where:
/// </para>
/// <list type="bullet">
///   <item><description><b>proof</b> - TPM secret value associated with the hierarchy containing keyName.</description></item>
///   <item><description><b>digest</b> - The digest the signature was claimed to be over.</description></item>
///   <item><description><b>keyName</b> - Name of the key that verified the signature.</description></item>
/// </list>
/// <para>
/// Note the field order — <c>digest || keyName</c> — is the mirror image of TPMT_TK_CREATION's
/// <c>name || creationHash</c> order.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM_ST tag;                  // Ticket structure tag (TPM_ST_VERIFIED).
///     TPMI_RH_HIERARCHY hierarchy; // The hierarchy containing keyName.
///     TPM2B_DIGEST digest;         // HMAC using proof value of hierarchy.
/// } TPMT_TK_VERIFIED;
/// </code>
/// <para>
/// <b>NULL ticket:</b> A NULL Verified Ticket is the tuple (TPM_ST_VERIFIED, TPM_RH_NULL, empty digest).
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, section 10.7.4, Table 110.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmtTkVerified: IDisposable, ITpmWireType
{
    /// <summary>
    /// The shared NULL Verified Ticket instance (TPM_ST_VERIFIED, TPM_RH_NULL, empty digest); it owns no pooled
    /// storage, so sharing one instance is safe and its disposal is a no-op.
    /// </summary>
    private static TpmtTkVerified NullInstance { get; } = new(
        TpmStConstants.TPM_ST_VERIFIED,
        TpmRh.TPM_RH_NULL,
        null,
        0);

    private readonly IMemoryOwner<byte>? storage;
    private readonly int digestLength;
    private bool disposed;

    /// <summary>
    /// Gets the ticket structure tag (must be TPM_ST_VERIFIED).
    /// </summary>
    public TpmStConstants Tag { get; }

    /// <summary>
    /// Gets the hierarchy containing the verifying key's Name.
    /// </summary>
    /// <remarks>
    /// One of TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM, TPM_RH_NULL.
    /// </remarks>
    public TpmRh Hierarchy { get; }

    /// <summary>
    /// Initializes a new verified ticket.
    /// </summary>
    private TpmtTkVerified(TpmStConstants tag, TpmRh hierarchy, IMemoryOwner<byte>? storage, int digestLength)
    {
        Tag = tag;
        Hierarchy = hierarchy;
        this.storage = storage;
        this.digestLength = digestLength;
    }

    /// <summary>
    /// Gets a NULL verified ticket.
    /// </summary>
    public static TpmtTkVerified Null => NullInstance;

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
    /// Parses a verified ticket from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed verified ticket.</returns>
    public static TpmtTkVerified Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort tag = reader.ReadUInt16();

        if(tag != (ushort)TpmStConstants.TPM_ST_VERIFIED)
        {
            throw new InvalidOperationException($"Invalid verified ticket tag: 0x{tag:X4}. Expected TPM_ST_VERIFIED.");
        }

        var hierarchy = (TpmRh)reader.ReadUInt32();
        ushort digestSize = reader.ReadUInt16();

        if(digestSize == 0)
        {
            if(hierarchy == TpmRh.TPM_RH_NULL)
            {
                return Null;
            }

            return new TpmtTkVerified((TpmStConstants)tag, hierarchy, null, 0);
        }

        IMemoryOwner<byte> storage = pool.Rent(digestSize);
        ReadOnlySpan<byte> source = reader.ReadBytes(digestSize);
        source.CopyTo(storage.Memory.Span.Slice(0, digestSize));

        return new TpmtTkVerified((TpmStConstants)tag, hierarchy, storage, digestSize);
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
                return "TPMT_TK_VERIFIED(NULL)";
            }

            string hierarchyName = Hierarchy switch
            {
                TpmRh.TPM_RH_OWNER => "OWNER",
                TpmRh.TPM_RH_ENDORSEMENT => "ENDORSEMENT",
                TpmRh.TPM_RH_PLATFORM => "PLATFORM",
                TpmRh.TPM_RH_NULL => "NULL",
                _ => $"0x{(uint)Hierarchy:X8}"
            };

            return $"TPMT_TK_VERIFIED({hierarchyName}, {digestLength} bytes)";
        }
    }
}
