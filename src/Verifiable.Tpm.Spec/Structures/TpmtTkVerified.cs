using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Spec.Structures;


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
        TpmiRhHierarchy.Null,
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
    /// Gets the hierarchy containing the verifying key's Name, typed <c>TPMI_RH_HIERARCHY+</c> as Table 110
    /// names it — the four hierarchy selectors of Part 2, clause 9.13, Table 60, the NULL hierarchy among them.
    /// </summary>
    public TpmiRhHierarchy Hierarchy { get; }

    /// <summary>
    /// Initializes a new verified ticket.
    /// </summary>
    private TpmtTkVerified(TpmStConstants tag, TpmiRhHierarchy hierarchy, IMemoryOwner<byte>? storage, int digestLength)
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
    public bool IsNull => Hierarchy.IsNull && digestLength == 0;

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
        Hierarchy.WriteTo(ref writer);
        writer.WriteUInt16((ushort)digestLength);

        if(digestLength > 0)
        {
            writer.WriteBytes(Digest);
        }
    }

    /// <summary>
    /// Parses a verified ticket from a TPM reader, validating both the structure tag and the hierarchy selector.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed verified ticket.</returns>
    /// <exception cref="InvalidOperationException">The tag is not <c>TPM_ST_VERIFIED</c> (<c>TPM_RC_TAG</c>, Table 110), or the hierarchy is not a <c>TPMI_RH_HIERARCHY</c> selector (<c>TPM_RC_VALUE</c>, Table 60).</exception>
    public static TpmtTkVerified Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort tag = reader.ReadUInt16();

        if(tag != (ushort)TpmStConstants.TPM_ST_VERIFIED)
        {
            throw new InvalidOperationException($"Invalid verified ticket tag: 0x{tag:X4}. Expected TPM_ST_VERIFIED.");
        }

        TpmiRhHierarchy hierarchy = TpmiRhHierarchy.Parse(ref reader);
        ushort digestSize = reader.ReadUInt16();

        if(digestSize == 0)
        {
            if(hierarchy.IsNull)
            {
                return Null;
            }

            return new TpmtTkVerified((TpmStConstants)tag, hierarchy, null, 0);
        }

        IMemoryOwner<byte> storage = pool.Rent(digestSize);
        try
        {
            ReadOnlySpan<byte> source = reader.ReadBytes(digestSize);
            source.CopyTo(storage.Memory.Span.Slice(0, digestSize));

            return new TpmtTkVerified((TpmStConstants)tag, hierarchy, storage, digestSize);
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
    /// production counterpart of <see cref="Parse"/> for the TPM side, which computes the ticket HMAC into a
    /// buffer it rented itself and then frames the whole <c>TPMT_TK_VERIFIED</c> from it.
    /// </summary>
    /// <remarks>
    /// The tag is always <c>TPM_ST_VERIFIED</c> (TPM 2.0 Library Part 2, clause 10.7.4, Table 110). A
    /// <paramref name="digestLength"/> of zero releases <paramref name="digest"/> here, since a ticket with no
    /// digest owns no storage: under <c>TPM_RH_NULL</c> that tuple IS the NULL Verified Ticket of clause 10.7.2,
    /// so the shared <see cref="Null"/> sentinel stands for it; under any other hierarchy the tuple is a distinct,
    /// storage-less ticket that keeps the hierarchy it was handed, exactly as <see cref="Parse"/> reconstructs the
    /// same octets off the wire. An argument that does not describe a valid ticket likewise releases
    /// <paramref name="digest"/> before the exception leaves, so a rejected adoption never orphans the rental.
    /// </remarks>
    /// <param name="hierarchy">The hierarchy containing the verifying key's Name, framed in the ticket's <c>hierarchy</c> field.</param>
    /// <param name="digest">The pooled buffer whose leading octets hold the ticket HMAC; ownership transfers to the returned instance or is released here.</param>
    /// <param name="digestLength">The number of valid octets at the head of <paramref name="digest"/>.</param>
    /// <returns>The adopted ticket.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="digest"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="digestLength"/> is negative, exceeds <paramref name="digest"/>'s length, or exceeds the 16-bit width of a <c>TPM2B</c> size field.</exception>
    public static TpmtTkVerified FromMarshaled(TpmiRhHierarchy hierarchy, IMemoryOwner<byte> digest, int digestLength)
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
                : new TpmtTkVerified(TpmStConstants.TPM_ST_VERIFIED, hierarchy, null, 0);
        }

        return new TpmtTkVerified(TpmStConstants.TPM_ST_VERIFIED, hierarchy, digest, digestLength);
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

            return $"TPMT_TK_VERIFIED({TpmValueConversions.GetHandleDescription(Hierarchy.Value)}, {digestLength} bytes)";
        }
    }
}
