using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Spec.Structures;


/// <summary>
/// A ticket produced by TPM2_VerifySignature(), TPM2_VerifySequenceComplete(), or TPM2_VerifyDigestSignature()
/// (TPMT_TK_VERIFIED).
/// </summary>
/// <remarks>
/// <para>
/// Provides evidence that the TPM has validated that a message or digest was signed by a key with the Name
/// <c>keyName</c>. Used in <c>TPM2_PolicyAuthorize()</c>.
/// </para>
/// <para>
/// <b>Ticket computation (Equation 5):</b>
/// </para>
/// <code>
/// HMACcontextAlg(proof, (tag || digestOrMessage || keyName || metadata))
/// </code>
/// <para>
/// Where:
/// </para>
/// <list type="bullet">
///   <item><description><b>proof</b> - TPM secret value associated with the hierarchy containing keyName.</description></item>
///   <item><description><b>tag</b> - one of the three <see cref="TpmStConstants"/> values Table 112 lists for this ticket.</description></item>
///   <item><description><b>digestOrMessage</b> - the signed digest or message.</description></item>
///   <item><description><b>keyName</b> - Name of the key that signed <c>digestOrMessage</c>.</description></item>
///   <item><description><b>metadata</b> - the serialized <see cref="Metadata"/> contents, empty-length for the two <c>TPMS_EMPTY</c> arms.</description></item>
/// </list>
/// <para>
/// Note the field order — <c>digestOrMessage || keyName</c> — is the mirror image of TPMT_TK_CREATION's
/// <c>name || creationHash</c> order.
/// </para>
/// <para>
/// <b>Tag (Table 112):</b> <c>TPM_ST_VERIFIED</c> is produced by <c>TPM2_VerifySignature()</c>,
/// <c>TPM_ST_MESSAGE_VERIFIED</c> by <c>TPM2_VerifySequenceComplete()</c>, and <c>TPM_ST_DIGEST_VERIFIED</c> by
/// <c>TPM2_VerifyDigestSignature()</c>. A tag outside this set is <c>TPM_RC_TAG</c>.
/// </para>
/// <para>
/// <b>Metadata (Table 111, TPMU_TK_VERIFIED_META):</b> the <c>verified</c> and <c>messageVerified</c> arms are
/// <c>TPMS_EMPTY</c> — zero octets, selected by <c>TPM_ST_VERIFIED</c> and <c>TPM_ST_MESSAGE_VERIFIED</c>
/// respectively — so a <c>TPM_ST_VERIFIED</c> ticket is byte-identical to the pre-v185 wire format. The
/// <c>digestVerified</c> arm, selected by <c>TPM_ST_DIGEST_VERIFIED</c>, is a 2-octet <c>TPMI_ALG_HASH</c>: the
/// hash or XOF algorithm used to produce the verified digest. <see cref="Metadata"/> models this union — a
/// non-<see langword="null"/> value present exactly when <see cref="Tag"/> is <c>TPM_ST_DIGEST_VERIFIED</c>.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM_ST tag;                     // Ticket structure tag - one of Table 112's three values.
///     TPMI_RH_HIERARCHY hierarchy;    // The hierarchy containing keyName.
///     [tag]TPMU_TK_VERIFIED_META metadata; // Present only for TPM_ST_DIGEST_VERIFIED.
///     TPM2B_DIGEST hmac;              // HMAC using proof value of hierarchy.
/// } TPMT_TK_VERIFIED;
/// </code>
/// <para>
/// Earlier versions of the TPM 2.0 specification called the last field <c>digest</c>; version 185 renamed it to
/// <c>hmac</c> to disambiguate it from the other digests a <c>TPMT_TK_VERIFIED</c> carries — the signed
/// <c>digestOrMessage</c> and, for <c>TPM_ST_DIGEST_VERIFIED</c>, the <see cref="Metadata"/> hash algorithm.
/// <see cref="Hmac"/> models the renamed field.
/// </para>
/// <para>
/// <b>NULL ticket:</b> the tuple <c>&lt;tag, TPM_RH_NULL, 0x0000&gt;</c>, where <c>tag</c> is one of
/// <c>TPM_ST_VERIFIED</c>, <c>TPM_ST_MESSAGE_VERIFIED</c>, or <c>TPM_ST_DIGEST_VERIFIED</c>. Only the
/// <c>TPM_ST_VERIFIED</c> case is backed by the shared <see cref="Null"/> sentinel; a NULL ticket for either of
/// the other two tags is a distinct, storage-less instance that keeps its own tag (and, for
/// <c>TPM_ST_DIGEST_VERIFIED</c>, its own <see cref="Metadata"/> hash — the tuple is silent on metadata, but
/// Table 111's <c>digestVerified</c> arm names a plain <c>TPMI_ALG_HASH</c> with no NULL admission, so the wire
/// still carries a real hash algorithm).
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clauses 10.6.4 (Table 111) and 10.6.5 (Tables 112, 113).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmtTkVerified: IDisposable, ITpmWireType
{
    /// <summary>
    /// The shared NULL Verified Ticket instance (TPM_ST_VERIFIED, TPM_RH_NULL, no metadata, empty hmac); it owns
    /// no pooled storage, so sharing one instance is safe and its disposal is a no-op.
    /// </summary>
    private static TpmtTkVerified NullInstance { get; } = new(
        TpmStConstants.TPM_ST_VERIFIED,
        TpmiRhHierarchy.Null,
        null,
        null,
        0);

    private IMemoryOwner<byte>? Storage { get; }

    private int HmacLength { get; }

    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the ticket structure tag — one of the three values Table 112 admits (<c>TPM_RC_TAG</c> on any other
    /// value).
    /// </summary>
    public TpmStConstants Tag { get; }

    /// <summary>
    /// Gets the hierarchy containing the verifying key's Name, typed <c>TPMI_RH_HIERARCHY+</c> as Table 113
    /// names it — the four hierarchy selectors of Part 2, clause 9.13, Table 59, the NULL hierarchy among them.
    /// </summary>
    public TpmiRhHierarchy Hierarchy { get; }

    /// <summary>
    /// Gets the <c>TPMU_TK_VERIFIED_META</c> union member (Table 111): <see langword="null"/> for the
    /// <c>TPMS_EMPTY</c> arms selected by <c>TPM_ST_VERIFIED</c> and <c>TPM_ST_MESSAGE_VERIFIED</c>, or the
    /// <c>digestVerified</c> hash algorithm when <see cref="Tag"/> is <c>TPM_ST_DIGEST_VERIFIED</c>.
    /// </summary>
    public TpmiAlgHash? Metadata { get; }

    /// <summary>
    /// Initializes a new verified ticket.
    /// </summary>
    /// <param name="tag">The ticket structure tag.</param>
    /// <param name="hierarchy">The hierarchy containing the verifying key's Name.</param>
    /// <param name="metadata">The <c>TPMU_TK_VERIFIED_META</c> member, or <see langword="null"/> for an empty arm.</param>
    /// <param name="storage">The pooled buffer holding the HMAC octets, or <see langword="null"/> for an empty HMAC.</param>
    /// <param name="hmacLength">The number of valid HMAC octets at the head of <paramref name="storage"/>.</param>
    private TpmtTkVerified(TpmStConstants tag, TpmiRhHierarchy hierarchy, TpmiAlgHash? metadata, IMemoryOwner<byte>? storage, int hmacLength)
    {
        Tag = tag;
        Hierarchy = hierarchy;
        Metadata = metadata;
        Storage = storage;
        HmacLength = hmacLength;
    }

    /// <summary>
    /// Gets a NULL verified ticket tagged <c>TPM_ST_VERIFIED</c>.
    /// </summary>
    public static TpmtTkVerified Null => NullInstance;

    /// <summary>
    /// Gets whether this is a NULL ticket — the NULL hierarchy with an empty <see cref="Hmac"/>, regardless of
    /// <see cref="Tag"/> (Table 113's NULL tuple admits all three tags).
    /// </summary>
    public bool IsNull => Hierarchy.IsNull && HmacLength == 0;

    /// <summary>
    /// Gets the HMAC as a read-only span — the field Table 113 renamed from <c>digest</c> to <c>hmac</c> in
    /// version 185.
    /// </summary>
    public ReadOnlySpan<byte> Hmac
    {
        get
        {
            ObjectDisposedException.ThrowIf(Disposed, this);

            if(Storage is null)
            {
                return ReadOnlySpan<byte>.Empty;
            }

            return Storage.Memory.Span.Slice(0, HmacLength);
        }
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize =>
        sizeof(ushort) + sizeof(uint) + (Metadata.HasValue ? sizeof(ushort) : 0) + sizeof(ushort) + HmacLength;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        writer.WriteUInt16((ushort)Tag);
        Hierarchy.WriteTo(ref writer);

        if(Metadata is { } metadataHash)
        {
            metadataHash.WriteTo(ref writer);
        }

        writer.WriteUInt16((ushort)HmacLength);

        if(HmacLength > 0)
        {
            writer.WriteBytes(Hmac);
        }
    }

    /// <summary>
    /// Whether a raw tag value is one of the three <c>TPMT_TK_VERIFIED</c> ticket tags Table 112 admits.
    /// </summary>
    /// <param name="tag">The candidate tag.</param>
    /// <returns><see langword="true"/> when <paramref name="tag"/> is <c>TPM_ST_VERIFIED</c>, <c>TPM_ST_MESSAGE_VERIFIED</c>, or <c>TPM_ST_DIGEST_VERIFIED</c>.</returns>
    private static bool IsAdmittedTag(TpmStConstants tag) => tag switch
    {
        TpmStConstants.TPM_ST_VERIFIED or TpmStConstants.TPM_ST_MESSAGE_VERIFIED or TpmStConstants.TPM_ST_DIGEST_VERIFIED => true,
        _ => false
    };

    /// <summary>
    /// Parses a verified ticket from a TPM reader, validating the structure tag, the hierarchy selector, and —
    /// for <c>TPM_ST_DIGEST_VERIFIED</c> — the metadata hash algorithm.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed verified ticket.</returns>
    /// <exception cref="InvalidOperationException">The tag is not one of Table 112's three values (<c>TPM_RC_TAG</c>), the hierarchy is not a <c>TPMI_RH_HIERARCHY</c> selector (<c>TPM_RC_VALUE</c>, Table 59), or a <c>TPM_ST_DIGEST_VERIFIED</c> ticket's metadata is not a hash algorithm (<c>TPM_RC_HASH</c>).</exception>
    public static TpmtTkVerified Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort rawTag = reader.ReadUInt16();
        var tag = (TpmStConstants)rawTag;

        if(!IsAdmittedTag(tag))
        {
            throw new InvalidOperationException(
                $"Invalid verified ticket tag: 0x{rawTag:X4}. Expected TPM_ST_VERIFIED, TPM_ST_MESSAGE_VERIFIED, or TPM_ST_DIGEST_VERIFIED (TPM_RC_TAG, TPM 2.0 Library Part 2, clause 10.6.5, Table 112).");
        }

        TpmiRhHierarchy hierarchy = TpmiRhHierarchy.Parse(ref reader);
        TpmiAlgHash? metadata = tag == TpmStConstants.TPM_ST_DIGEST_VERIFIED
            ? TpmiAlgHash.Parse(ref reader)
            : null;

        ushort hmacSize = reader.ReadUInt16();

        if(hmacSize == 0)
        {
            if(hierarchy.IsNull && tag == TpmStConstants.TPM_ST_VERIFIED)
            {
                return Null;
            }

            return new TpmtTkVerified(tag, hierarchy, metadata, null, 0);
        }

        IMemoryOwner<byte> storage = pool.Rent(hmacSize);
        try
        {
            ReadOnlySpan<byte> source = reader.ReadBytes(hmacSize);
            source.CopyTo(storage.Memory.Span.Slice(0, hmacSize));

            return new TpmtTkVerified(tag, hierarchy, metadata, storage, hmacSize);
        }
        catch
        {
            //A truncated frame must not orphan the HMAC rental the declared size already asked for.
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Adopts an already-filled pooled buffer as this ticket's HMAC storage: ownership of <paramref name="hmac"/>
    /// transfers to the returned instance, with no second rental and no copy — the production counterpart of
    /// <see cref="Parse"/> for the TPM side, which computes the ticket HMAC into a buffer it rented itself and
    /// then frames the whole <c>TPMT_TK_VERIFIED</c> from it.
    /// </summary>
    /// <remarks>
    /// A <paramref name="hmacLength"/> of zero releases <paramref name="hmac"/> here, since a ticket with no HMAC
    /// owns no storage: under <c>TPM_RH_NULL</c> and <c>TPM_ST_VERIFIED</c> that tuple IS the NULL Verified
    /// Ticket the shared <see cref="Null"/> sentinel stands for; under any other tag or hierarchy the tuple is a
    /// distinct, storage-less ticket that keeps the tag, hierarchy, and metadata it was handed, exactly as
    /// <see cref="Parse"/> reconstructs the same octets off the wire. An argument that does not describe a valid
    /// ticket — an inadmissible tag, or a <paramref name="metadata"/> presence mismatched against
    /// <paramref name="tag"/> — likewise releases <paramref name="hmac"/> before the exception leaves, so a
    /// rejected adoption never orphans the rental.
    /// </remarks>
    /// <param name="tag">The ticket structure tag; must be one of Table 112's three values.</param>
    /// <param name="hierarchy">The hierarchy containing the verifying key's Name, framed in the ticket's <c>hierarchy</c> field.</param>
    /// <param name="metadata">The <c>TPMU_TK_VERIFIED_META</c> member; required exactly when <paramref name="tag"/> is <c>TPM_ST_DIGEST_VERIFIED</c>.</param>
    /// <param name="hmac">The pooled buffer whose leading octets hold the ticket HMAC; ownership transfers to the returned instance or is released here.</param>
    /// <param name="hmacLength">The number of valid octets at the head of <paramref name="hmac"/>.</param>
    /// <returns>The adopted ticket.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="hmac"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException"><paramref name="tag"/> is not one of Table 112's three values (<c>TPM_RC_TAG</c>), or <paramref name="metadata"/>'s presence does not match Table 111's arm for <paramref name="tag"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="hmacLength"/> is negative, exceeds <paramref name="hmac"/>'s length, or exceeds the 16-bit width of a <c>TPM2B</c> size field.</exception>
    public static TpmtTkVerified FromMarshaled(TpmStConstants tag, TpmiRhHierarchy hierarchy, TpmiAlgHash? metadata, IMemoryOwner<byte> hmac, int hmacLength)
    {
        ArgumentNullException.ThrowIfNull(hmac);

        try
        {
            if(!IsAdmittedTag(tag))
            {
                throw new InvalidOperationException(
                    $"Invalid verified ticket tag: {tag}. Expected TPM_ST_VERIFIED, TPM_ST_MESSAGE_VERIFIED, or TPM_ST_DIGEST_VERIFIED (TPM_RC_TAG, TPM 2.0 Library Part 2, clause 10.6.5, Table 112).");
            }

            bool isMetadataExpected = tag == TpmStConstants.TPM_ST_DIGEST_VERIFIED;
            if(metadata.HasValue != isMetadataExpected)
            {
                throw new InvalidOperationException(isMetadataExpected
                    ? "TPM_ST_DIGEST_VERIFIED requires a TPMU_TK_VERIFIED_META metadata value (Table 111's digestVerified arm)."
                    : $"{tag} carries no TPMU_TK_VERIFIED_META metadata (Table 111's TPMS_EMPTY arm); metadata must be null.");
            }

            ArgumentOutOfRangeException.ThrowIfNegative(hmacLength);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(hmacLength, hmac.Memory.Length);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(hmacLength, ushort.MaxValue);
        }
        catch
        {
            hmac.Dispose();
            throw;
        }

        if(hmacLength == 0)
        {
            hmac.Dispose();

            return hierarchy.IsNull && tag == TpmStConstants.TPM_ST_VERIFIED
                ? Null
                : new TpmtTkVerified(tag, hierarchy, metadata, null, 0);
        }

        return new TpmtTkVerified(tag, hierarchy, metadata, hmac, hmacLength);
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
    /// The debugger's one-line rendering: the tag, the hierarchy and the HMAC's octet count, never the HMAC
    /// octets themselves.
    /// </summary>
    private string DebuggerDisplay
    {
        get
        {
            if(IsNull)
            {
                return $"TPMT_TK_VERIFIED({Tag}, NULL)";
            }

            return $"TPMT_TK_VERIFIED({Tag}, {TpmValueConversions.GetHandleDescription(Hierarchy.Value)}, {HmacLength} bytes)";
        }
    }
}
