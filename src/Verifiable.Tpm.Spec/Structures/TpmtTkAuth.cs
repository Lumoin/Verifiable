using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Spec.Structures;


/// <summary>
/// A ticket produced by TPM2_PolicySigned() and TPM2_PolicySecret() (TPMT_TK_AUTH).
/// </summary>
/// <remarks>
/// <para>
/// Produced when the authorization has an expiration time.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM_ST tag;                  // Ticket structure tag (TPM_ST_AUTH_SIGNED or TPM_ST_AUTH_SECRET).
///     TPMI_RH_HIERARCHY hierarchy; // The hierarchy of the object used to produce the ticket.
///     TPM2B_DIGEST digest;         // HMAC using proof value of hierarchy.
/// } TPMT_TK_AUTH;
/// </code>
/// <para>
/// <b>NULL ticket:</b> "A NULL Auth Ticket is the tuple &lt;TPM_ST_AUTH_SIGNED, TPM_RH_NULL, 0x0000&gt;"
/// (clause 10.7.5); clause 10.7.2 is the general construct.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, section 10.7.5, Table 111.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmtTkAuth: IDisposable, ITpmWireType
{
    /// <summary>
    /// The shared NULL Auth Ticket instance (TPM_ST_AUTH_SIGNED, TPM_RH_NULL, empty digest); it owns no pooled
    /// storage, so sharing one instance is safe and its disposal is a no-op.
    /// </summary>
    private static TpmtTkAuth NullInstance { get; } = new(
        TpmStConstants.TPM_ST_AUTH_SIGNED,
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
    /// Whether <see cref="Dispose"/> has already released <see cref="Storage"/>.
    /// </summary>
    private bool disposed;

    /// <summary>
    /// Gets the ticket structure tag (TPM_ST_AUTH_SIGNED or TPM_ST_AUTH_SECRET).
    /// </summary>
    public TpmStConstants Tag { get; }

    /// <summary>
    /// Gets the hierarchy of the object used to produce the ticket, typed <c>TPMI_RH_HIERARCHY+</c> as Table 111
    /// names it — the four hierarchy selectors of Part 2, clause 9.13, Table 60, the NULL hierarchy among them.
    /// </summary>
    public TpmiRhHierarchy Hierarchy { get; }

    /// <summary>
    /// Initializes a new authorization ticket.
    /// </summary>
    private TpmtTkAuth(TpmStConstants tag, TpmiRhHierarchy hierarchy, IMemoryOwner<byte>? storage, int digestLength)
    {
        Tag = tag;
        Hierarchy = hierarchy;
        this.Storage = storage;
        this.DigestLength = digestLength;
    }

    /// <summary>
    /// Gets the NULL Auth Ticket in the <c>TPM_ST_AUTH_SIGNED</c> form clause 10.7.5 names.
    /// </summary>
    public static TpmtTkAuth Null => NullInstance;

    /// <summary>
    /// Gets whether this is a NULL ticket: the NULL hierarchy with an Empty Buffer digest (clause 10.7.2).
    /// </summary>
    public bool IsNull => Hierarchy.IsNull && DigestLength == 0;

    /// <summary>
    /// Determines if this is from TPM2_PolicySigned().
    /// </summary>
    /// <returns><see langword="true"/> when the tag is <c>TPM_ST_AUTH_SIGNED</c>.</returns>
    public bool IsPolicySigned() => Tag == TpmStConstants.TPM_ST_AUTH_SIGNED;

    /// <summary>
    /// Determines if this is from TPM2_PolicySecret().
    /// </summary>
    /// <returns><see langword="true"/> when the tag is <c>TPM_ST_AUTH_SECRET</c>.</returns>
    public bool IsPolicySecret() => Tag == TpmStConstants.TPM_ST_AUTH_SECRET;

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
    /// Parses an authorization ticket from a TPM reader, validating both the structure tag and the hierarchy
    /// selector.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed authorization ticket.</returns>
    /// <exception cref="InvalidOperationException">The tag is neither <c>TPM_ST_AUTH_SIGNED</c> nor <c>TPM_ST_AUTH_SECRET</c> (<c>TPM_RC_TAG</c>, Table 111), or the hierarchy is not a <c>TPMI_RH_HIERARCHY</c> selector (<c>TPM_RC_VALUE</c>, Table 60).</exception>
    public static TpmtTkAuth Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort tag = reader.ReadUInt16();

        if(tag is not ((ushort)TpmStConstants.TPM_ST_AUTH_SIGNED or (ushort)TpmStConstants.TPM_ST_AUTH_SECRET))
        {
            throw new InvalidOperationException($"Invalid authorization ticket tag: 0x{tag:X4}. Expected TPM_ST_AUTH_SIGNED or TPM_ST_AUTH_SECRET.");
        }

        TpmiRhHierarchy hierarchy = TpmiRhHierarchy.Parse(ref reader);
        ushort digestSize = reader.ReadUInt16();

        if(digestSize == 0)
        {
            if(hierarchy.IsNull && tag == (ushort)TpmStConstants.TPM_ST_AUTH_SIGNED)
            {
                return Null;
            }

            return new TpmtTkAuth((TpmStConstants)tag, hierarchy, null, 0);
        }

        IMemoryOwner<byte> storage = pool.Rent(digestSize);
        try
        {
            ReadOnlySpan<byte> source = reader.ReadBytes(digestSize);
            source.CopyTo(storage.Memory.Span.Slice(0, digestSize));

            return new TpmtTkAuth((TpmStConstants)tag, hierarchy, storage, digestSize);
        }
        catch
        {
            //A truncated frame must not orphan the digest rental the declared size already asked for.
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Creates an authorization ticket from the tag, hierarchy, and digest a caller holds — the host-side
    /// assembler that frames a ticket back onto the wire for <c>TPM2_PolicyTicket()</c>.
    /// </summary>
    /// <remarks>
    /// The tag is framed exactly as handed over and is NOT checked against Table 111's set: a caller replaying a
    /// ticket is asserting what the TPM gave it, and the TPM is the party that answers <c>TPM_RC_TAG</c> for a
    /// tag it does not recognize (Part 3, clause 23.5). The hierarchy likewise rides through unvalidated for the
    /// same reason, so an out-of-set selector reaches the TPM and is answered there.
    /// </remarks>
    /// <param name="tag">The ticket structure tag to frame.</param>
    /// <param name="hierarchy">The hierarchy whose proof keyed the ticket HMAC.</param>
    /// <param name="digest">The ticket HMAC octets; copied into pooled storage the returned instance owns.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created ticket; the caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static TpmtTkAuth Create(TpmStConstants tag, TpmiRhHierarchy hierarchy, ReadOnlySpan<byte> digest, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(digest.IsEmpty)
        {
            return hierarchy.IsNull && tag == TpmStConstants.TPM_ST_AUTH_SIGNED
                ? Null
                : new TpmtTkAuth(tag, hierarchy, null, 0);
        }

        IMemoryOwner<byte> storage = pool.Rent(digest.Length);
        try
        {
            digest.CopyTo(storage.Memory.Span);

            return new TpmtTkAuth(tag, hierarchy, storage, digest.Length);
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
        if(!disposed && this != NullInstance)
        {
            Storage?.Dispose();
            disposed = true;
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
                return "TPMT_TK_AUTH: (null)";
            }

            return $"TPMT_TK_AUTH: ST_0x{(ushort)Tag:X4}, {TpmValueConversions.GetHandleDescription(Hierarchy.Value)}, {DigestLength} bytes";
        }
    }
}
