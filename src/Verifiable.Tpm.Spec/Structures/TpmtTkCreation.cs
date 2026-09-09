using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Spec.Structures;

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
/// (TPM_ST_CREATION, TPM_RH_NULL, empty digest) — clause 10.6.2's construct for "a command requires a ticket
/// and no ticket is available".
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 10.6.3, Table 110.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmtTkCreation: IDisposable, ITpmWireType
{
    /// <summary>
    /// The shared NULL Creation Ticket instance (TPM_ST_CREATION, TPM_RH_NULL, empty digest); it owns no pooled
    /// storage, so sharing one instance is safe and its disposal is a no-op.
    /// </summary>
    private static TpmtTkCreation NullInstance { get; } = new(
        TpmStConstants.TPM_ST_CREATION,
        TpmiRhHierarchy.Null,
        null,
        0);

    private IMemoryOwner<byte>? Storage { get; }
    private int DigestLength { get; }
    private bool disposed;

    /// <summary>
    /// Gets the ticket structure tag (must be TPM_ST_CREATION).
    /// </summary>
    public TpmStConstants Tag { get; }

    /// <summary>
    /// Gets the hierarchy containing the created object, typed <c>TPMI_RH_HIERARCHY+</c> as Table 110 names it
    /// — the four hierarchy selectors of Part 2, clause 9.13, Table 59, the NULL hierarchy among them.
    /// </summary>
    public TpmiRhHierarchy Hierarchy { get; }

    /// <summary>
    /// Initializes a new creation ticket.
    /// </summary>
    private TpmtTkCreation(TpmStConstants tag, TpmiRhHierarchy hierarchy, IMemoryOwner<byte>? storage, int digestLength)
    {
        Tag = tag;
        Hierarchy = hierarchy;
        this.Storage = storage;
        this.DigestLength = digestLength;
    }

    /// <summary>
    /// Gets a NULL creation ticket.
    /// </summary>
    public static TpmtTkCreation Null => NullInstance;

    /// <summary>
    /// Gets whether this is a NULL ticket.
    /// </summary>
    public bool IsNull => Hierarchy.IsNull && DigestLength == 0;

    /// <summary>
    /// Gets the digest as a read-only span.
    /// </summary>
    public ReadOnlySpan<byte> Digest
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            if(Storage is null)
            {
                return ReadOnlySpan<byte>.Empty;
            }

            return Storage.Memory.Span.Slice(0, DigestLength);
        }
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => sizeof(ushort) + sizeof(uint) + sizeof(ushort) + DigestLength;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt16((ushort)Tag);
        Hierarchy.WriteTo(ref writer);
        writer.WriteUInt16((ushort)DigestLength);

        if(DigestLength > 0)
        {
            writer.WriteBytes(Digest);
        }
    }

    /// <summary>
    /// Parses a creation ticket from a TPM reader, validating both the structure tag and the hierarchy selector.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed creation ticket.</returns>
    /// <exception cref="InvalidOperationException">The tag is not <c>TPM_ST_CREATION</c> (<c>TPM_RC_TAG</c>, Table 110), or the hierarchy is not a <c>TPMI_RH_HIERARCHY</c> selector (<c>TPM_RC_VALUE</c>, Table 59).</exception>
    public static TpmtTkCreation Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort tag = reader.ReadUInt16();

        if(tag != (ushort)TpmStConstants.TPM_ST_CREATION)
        {
            throw new InvalidOperationException($"Invalid creation ticket tag: 0x{tag:X4}. Expected TPM_ST_CREATION.");
        }

        TpmiRhHierarchy hierarchy = TpmiRhHierarchy.Parse(ref reader);
        ushort digestSize = reader.ReadUInt16();

        if(digestSize == 0)
        {
            if(hierarchy.IsNull)
            {
                return Null;
            }

            return new TpmtTkCreation((TpmStConstants)tag, hierarchy, null, 0);
        }

        IMemoryOwner<byte> storage = pool.Rent(digestSize);
        try
        {
            ReadOnlySpan<byte> source = reader.ReadBytes(digestSize);
            source.CopyTo(storage.Memory.Span.Slice(0, digestSize));

            return new TpmtTkCreation((TpmStConstants)tag, hierarchy, storage, digestSize);
        }
        catch
        {
            //A truncated frame must not orphan the digest rental the declared size already asked for.
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Adopts an already-filled pooled buffer as this ticket's digest storage: ownership of
    /// <paramref name="digest"/> transfers to the returned instance, with no second rental and no copy — the
    /// production counterpart of <see cref="Parse"/> for the TPM side, which computes the ticket HMAC of
    /// equation 4 into a buffer it rented itself and then frames the whole <c>TPMT_TK_CREATION</c> from it.
    /// </summary>
    /// <remarks>
    /// The tag is always <c>TPM_ST_CREATION</c> (Table 110). A <paramref name="digestLength"/> of zero releases
    /// <paramref name="digest"/> here, since a ticket with no digest owns no storage: under <c>TPM_RH_NULL</c>
    /// that tuple IS the NULL Creation Ticket of clause 10.6.2, so the shared <see cref="Null"/> sentinel stands
    /// for it; under any other hierarchy the tuple is a distinct, storage-less ticket that keeps the hierarchy it
    /// was handed, exactly as <see cref="Parse"/> reconstructs the same octets off the wire. An argument that
    /// does not describe a valid ticket likewise releases <paramref name="digest"/> before the exception leaves,
    /// so a rejected adoption never orphans the rental.
    /// </remarks>
    /// <param name="hierarchy">The hierarchy containing the created object's Name, framed in the ticket's <c>hierarchy</c> field.</param>
    /// <param name="digest">The pooled buffer whose leading octets hold the ticket HMAC; ownership transfers to the returned instance or is released here.</param>
    /// <param name="digestLength">The number of valid octets at the head of <paramref name="digest"/>.</param>
    /// <returns>The adopted ticket.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="digest"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="digestLength"/> is negative, exceeds <paramref name="digest"/>'s length, or exceeds the 16-bit width of a <c>TPM2B</c> size field.</exception>
    public static TpmtTkCreation FromMarshaled(TpmiRhHierarchy hierarchy, IMemoryOwner<byte> digest, int digestLength)
    {
        ArgumentNullException.ThrowIfNull(digest);

        try
        {
            ArgumentOutOfRangeException.ThrowIfNegative(digestLength);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(digestLength, digest.Memory.Length);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(digestLength, ushort.MaxValue);
        }
        catch
        {
            digest.Dispose();
            throw;
        }

        if(digestLength == 0)
        {
            digest.Dispose();

            return hierarchy.IsNull
                ? Null
                : new TpmtTkCreation(TpmStConstants.TPM_ST_CREATION, hierarchy, null, 0);
        }

        return new TpmtTkCreation(TpmStConstants.TPM_ST_CREATION, hierarchy, digest, digestLength);
    }

    /// <summary>
    /// Releases the memory owned by this structure. The shared <see cref="Null"/> ticket is exempt: it owns no
    /// pooled storage and every consumer holds the same instance, so disposing one of them leaves it readable
    /// and framable for all the others.
    /// </summary>
    public void Dispose()
    {
        if(!disposed && this != NullInstance)
        {
            Storage?.Dispose();
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

            return $"TPMT_TK_CREATION({TpmValueConversions.GetHandleDescription(Hierarchy.Value)}, {DigestLength} bytes)";
        }
    }
}
