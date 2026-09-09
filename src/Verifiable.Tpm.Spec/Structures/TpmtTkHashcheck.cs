using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Spec.Structures;


/// <summary>
/// A ticket produced by TPM2_SequenceComplete() or TPM2_Hash() (TPMT_TK_HASHCHECK).
/// </summary>
/// <remarks>
/// <para>
/// Produced when the message that was digested did not start with TPM_GENERATED_VALUE. The ticket is
/// <c>HMAC_contextAlg(proof, (TPM_ST_HASHCHECK ‖ digest))</c> — equation 7.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM_ST tag;                  // Ticket structure tag (TPM_ST_HASHCHECK).
///     TPMI_RH_HIERARCHY hierarchy; // The hierarchy.
///     TPM2B_DIGEST digest;         // HMAC using proof value of hierarchy.
/// } TPMT_TK_HASHCHECK;
/// </code>
/// <para>
/// <b>NULL ticket:</b> the tuple (TPM_ST_HASHCHECK, TPM_RH_NULL, empty digest) — clause 10.6.2's construct for
/// "a command requires a ticket and no ticket is available", which is what <c>TPM2_Sign()</c> frames for a
/// digest the caller produced outside the TPM.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 10.6.7, Table 115.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmtTkHashcheck: IDisposable, ITpmWireType
{
    /// <summary>
    /// The shared NULL Hashcheck Ticket instance (TPM_ST_HASHCHECK, TPM_RH_NULL, empty digest); it owns no
    /// pooled storage, so sharing one instance is safe and its disposal is a no-op.
    /// </summary>
    private static TpmtTkHashcheck NullInstance { get; } = new(
        TpmStConstants.TPM_ST_HASHCHECK,
        TpmiRhHierarchy.Null,
        null,
        0);

    /// <summary>
    /// The pooled storage holding the ticket digest, or <see langword="null"/> for <see cref="Null"/>.
    /// </summary>
    private IMemoryOwner<byte>? Storage { get; }

    /// <summary>
    /// The number of valid digest octets at the head of <see cref="Storage"/>.
    /// </summary>
    private int DigestLength { get; }

    /// <summary>
    /// Gets or sets whether <see cref="Dispose"/> has already released <see cref="Storage"/>.
    /// </summary>
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the ticket structure tag (must be TPM_ST_HASHCHECK).
    /// </summary>
    public TpmStConstants Tag { get; }

    /// <summary>
    /// Gets the hierarchy whose proof keyed the ticket HMAC, typed <c>TPMI_RH_HIERARCHY+</c> as Table 115 names
    /// it — the four hierarchy selectors of Part 2, clause 9.13, Table 59, the NULL hierarchy among them.
    /// </summary>
    public TpmiRhHierarchy Hierarchy { get; }

    /// <summary>
    /// Initializes a new hash-check ticket.
    /// </summary>
    private TpmtTkHashcheck(TpmStConstants tag, TpmiRhHierarchy hierarchy, IMemoryOwner<byte>? storage, int digestLength)
    {
        Tag = tag;
        Hierarchy = hierarchy;
        this.Storage = storage;
        this.DigestLength = digestLength;
    }

    /// <summary>
    /// Gets the NULL Hashcheck Ticket.
    /// </summary>
    public static TpmtTkHashcheck Null => NullInstance;

    /// <summary>
    /// Gets whether this is a NULL ticket: the NULL hierarchy with an Empty Buffer digest (clause 10.6.2).
    /// </summary>
    public bool IsNull => Hierarchy.IsNull && DigestLength == 0;

    /// <summary>
    /// Gets the digest as a read-only span.
    /// </summary>
    public ReadOnlySpan<byte> Digest
    {
        get
        {
            ObjectDisposedException.ThrowIf(Disposed, this);

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
        ObjectDisposedException.ThrowIf(Disposed, this);

        writer.WriteUInt16((ushort)Tag);
        Hierarchy.WriteTo(ref writer);
        writer.WriteUInt16((ushort)DigestLength);

        if(DigestLength > 0)
        {
            writer.WriteBytes(Digest);
        }
    }

    /// <summary>
    /// Parses a hash-check ticket from a TPM reader, validating both the structure tag and the hierarchy
    /// selector.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed hash-check ticket.</returns>
    /// <exception cref="InvalidOperationException">The tag is not <c>TPM_ST_HASHCHECK</c> (<c>TPM_RC_TAG</c>, Table 115), or the hierarchy is not a <c>TPMI_RH_HIERARCHY</c> selector (<c>TPM_RC_VALUE</c>, Table 59).</exception>
    public static TpmtTkHashcheck Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort tag = reader.ReadUInt16();

        if(tag != (ushort)TpmStConstants.TPM_ST_HASHCHECK)
        {
            throw new InvalidOperationException($"Invalid hash-check ticket tag: 0x{tag:X4}. Expected TPM_ST_HASHCHECK.");
        }

        TpmiRhHierarchy hierarchy = TpmiRhHierarchy.Parse(ref reader);
        ushort digestSize = reader.ReadUInt16();

        if(digestSize == 0)
        {
            if(hierarchy.IsNull)
            {
                return Null;
            }

            return new TpmtTkHashcheck((TpmStConstants)tag, hierarchy, null, 0);
        }

        IMemoryOwner<byte> storage = pool.Rent(digestSize);
        try
        {
            ReadOnlySpan<byte> source = reader.ReadBytes(digestSize);
            source.CopyTo(storage.Memory.Span.Slice(0, digestSize));

            return new TpmtTkHashcheck((TpmStConstants)tag, hierarchy, storage, digestSize);
        }
        catch
        {
            //A truncated frame must not orphan the digest rental the declared size already asked for.
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Creates a hash-check ticket from the hierarchy and digest a caller holds — the host-side assembler that
    /// frames a ticket back onto the wire for a command that consumes one.
    /// </summary>
    /// <param name="hierarchy">The hierarchy whose proof keyed the ticket HMAC.</param>
    /// <param name="digest">The ticket HMAC octets; copied into pooled storage the returned instance owns.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created ticket; the caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static TpmtTkHashcheck Create(TpmiRhHierarchy hierarchy, ReadOnlySpan<byte> digest, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(digest.IsEmpty)
        {
            return hierarchy.IsNull
                ? Null
                : new TpmtTkHashcheck(TpmStConstants.TPM_ST_HASHCHECK, hierarchy, null, 0);
        }

        IMemoryOwner<byte> storage = pool.Rent(digest.Length);
        try
        {
            digest.CopyTo(storage.Memory.Span);

            return new TpmtTkHashcheck(TpmStConstants.TPM_ST_HASHCHECK, hierarchy, storage, digest.Length);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Releases the memory owned by this structure. The shared <see cref="Null"/> ticket is exempt: it owns no
    /// pooled storage and every consumer holds the same instance, so disposing one of them leaves it readable
    /// and framable for all the others.
    /// </summary>
    public void Dispose()
    {
        if(!Disposed && this != NullInstance)
        {
            Storage?.Dispose();
            Disposed = true;
        }
    }

    /// <summary>
    /// The debugger's one-line rendering: the tag, the hierarchy and the digest's octet count, never the
    /// digest octets themselves.
    /// </summary>
    private string DebuggerDisplay
    {
        get
        {
            if(IsNull)
            {
                return "TPMT_TK_HASHCHECK: (null)";
            }

            return $"TPMT_TK_HASHCHECK: {TpmValueConversions.GetHandleDescription(Hierarchy.Value)}, {DigestLength} bytes";
        }
    }
}
