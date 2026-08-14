using System;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>sigPSt</c> unsigned header parameter (label <c>7</c> within <c>uHeaders</c>, Table 8) — a
/// signature-policy store carrying either the signature policy document itself or a local-store pointer to
/// it, for offline and long-term validation, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.3.2</see>.
/// </summary>
/// <remarks>
/// <para>
/// CDDL (clause 5.3.2, Table 9 keys):
/// </para>
/// <code>
/// sigPSt = {
///     1 =&gt; DocOrLocalURI,   ; docOrLocalUri
///     ? 2 =&gt; oId            ; spDSpec
/// }
/// DocOrLocalURI = {
///     1 =&gt; bstr //          ; sigPolDoc
///     2 =&gt; #6.32(tstr),     ; sigPolLocalURI
/// }
/// </code>
/// <para>
/// (CB-5.3.2-01) "The <c>sigPSt</c> CBOR map shall contain either: the signature policy document which is
/// referenced in the <c>sigPId</c> CBOR map ...; or a URI referencing a local store where the signature
/// policy document can be retrieved." <see cref="Content"/> models this exclusive two-case choice as
/// <see cref="CBAdESSignaturePolicyStoreContent"/>, mirroring
/// <see cref="AdESSignaturePolicyQualifier"/>'s closed-sum treatment of the sibling CDDL group choice in
/// clause 5.2.7.2.
/// </para>
/// <para>
/// (CB-5.3.2-04) <see cref="SpDSpec"/> — the <c>spDSpec</c> member, map key 2 — identifies the technical
/// specification that defines the syntax used for producing the signature policy document carried or
/// pointed to by <see cref="Content"/>; typed as <see cref="AdESObjectIdentifier"/> (clause 5.4.1), reused
/// verbatim.
/// </para>
/// <para>
/// <strong>Tamper detection despite being unsigned (clause 5.3.2, NOTE 3).</strong> "Being unsigned, the
/// <c>sigPSt</c> is not protected by the digital signature. If the <c>sigPId</c> signed attribute is
/// incorporated into the signature and contains the <c>digAlgVal</c> member with the digest value of the
/// signature policy document, any alteration of the signature policy document present within <c>sigPSt</c>
/// or within a local store, would be detected by the failure of the digests comparison." This model carries
/// no digest of its own — the tamper check compares <see cref="Content"/>'s bytes (or the bytes retrieved
/// through its local-store pointer) against <see cref="AdESSignaturePolicyIdentifier.Digest"/> on the
/// signed <c>sigPId</c> instance, a cross-component check owned by validation, not by this type. Clause 6's
/// Table 14 further conditions <c>sigPSt</c>'s very presence on that signed <c>sigPId</c>
/// digest already being incorporated (clause 6, requirement b) — likewise a signature-level creation rule,
/// not enforceable from this type alone.
/// </para>
/// <para>
/// <strong>Equality.</strong> A <c>sigPSt</c> is the pair it carries, so equality compares
/// <see cref="Content"/> and <see cref="SpDSpec"/> by value — both arms of <see cref="Content"/> compare by
/// their own content, and <see cref="AdESObjectIdentifier"/> is a value. Two stores decoded from the same wire
/// bytes therefore compare equal, which is what "the same signature policy store" has to mean when the digest
/// cross-check above compares stores rather than object references.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESSignaturePolicyStore: {Content}")]
public sealed class CBAdESSignaturePolicyStore: IEquatable<CBAdESSignaturePolicyStore>
{
    /// <summary>The <c>docOrLocalUri</c> member's map key, within <c>sigPSt</c> (Table 9, clause 5.3.2).</summary>
    public const int DocOrLocalUriKey = 1;

    /// <summary>The <c>spDSpec</c> member's map key, within <c>sigPSt</c> (Table 9, clause 5.3.2).</summary>
    public const int SpDSpecKey = 2;

    /// <summary>
    /// Initializes a new <see cref="CBAdESSignaturePolicyStore"/>.
    /// </summary>
    /// <param name="content">
    /// The <c>docOrLocalUri</c> member (map key 1): either the signature policy document itself or a
    /// local-store pointer to it (CB-5.3.2-01).
    /// </param>
    /// <param name="spDSpec">
    /// The <c>spDSpec</c> member (map key 2), or <see langword="null"/> to omit it (CB-5.3.2-04).
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="content"/> is <see langword="null"/>.</exception>
    public CBAdESSignaturePolicyStore(CBAdESSignaturePolicyStoreContent content, AdESObjectIdentifier? spDSpec = null)
    {
        ArgumentNullException.ThrowIfNull(content);

        Content = content;
        SpDSpec = spDSpec;
    }


    /// <summary>
    /// Gets the <c>docOrLocalUri</c> member (map key 1): either the signature policy document itself
    /// (<see cref="CBAdESSignaturePolicyStoreDocument"/>) or a local-store pointer to it
    /// (<see cref="CBAdESSignaturePolicyStoreLocalUri"/>) (CB-5.3.2-01).
    /// </summary>
    public CBAdESSignaturePolicyStoreContent Content { get; }

    /// <summary>
    /// Gets the <c>spDSpec</c> member (map key 2): the technical specification defining the syntax of the
    /// signature policy document (CB-5.3.2-04), or <see langword="null"/> when absent.
    /// </summary>
    public AdESObjectIdentifier? SpDSpec { get; }

    /// <inheritdoc/>
    public bool Equals(CBAdESSignaturePolicyStore? other)
    {
        return other is not null
            && Content.Equals(other.Content)
            && SpDSpec == other.SpDSpec;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as CBAdESSignaturePolicyStore);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Content, SpDSpec);
    }

    /// <summary>Reports whether two signature policy stores carry the same content and <c>spDSpec</c>.</summary>
    public static bool operator ==(CBAdESSignaturePolicyStore? left, CBAdESSignaturePolicyStore? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two signature policy stores carry different content or <c>spDSpec</c>.</summary>
    public static bool operator !=(CBAdESSignaturePolicyStore? left, CBAdESSignaturePolicyStore? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// The <c>DocOrLocalURI</c> CDDL group choice (clause 5.3.2) carried by
/// <see cref="CBAdESSignaturePolicyStore.Content"/>: a closed sum of the two ways the signature policy
/// document can be made available through <c>sigPSt</c>. A DU-ready closed sum: no external type may derive
/// from it.
/// </summary>
/// <remarks>
/// <para>
/// CDDL (clause 5.3.2): <c>DocOrLocalURI = { 1 =&gt; bstr // 2 =&gt; #6.32(tstr), }</c> — the source prints a
/// group-choice <c>//</c> after the first arm but a trailing map-member comma after the second (non-final)
/// arm, an internally inconsistent punctuation pairing (the same character of defect
/// <see cref="AdESPkiObject"/>'s clause notes for <c>X509OrOther</c>); the prose ("shall contain either
/// ... or ...") makes the intended reading an exclusive two-case choice, modelled here as the closed sum
/// below.
/// </para>
/// </remarks>
public abstract class CBAdESSignaturePolicyStoreContent
{
    /// <summary>The <c>sigPolDoc</c> choice arm's map key, within <c>DocOrLocalURI</c> (Table 9, clause 5.3.2).</summary>
    public const int SigPolDocKey = 1;

    /// <summary>The <c>sigPolLocalURI</c> choice arm's map key, within <c>DocOrLocalURI</c> (Table 9, clause 5.3.2).</summary>
    public const int SigPolLocalUriKey = 2;

    /// <summary>Restricts direct subtyping to the sibling types declared in this file.</summary>
    private protected CBAdESSignaturePolicyStoreContent()
    {
    }
}


/// <summary>
/// The <c>sigPolDoc</c> choice arm (clause 5.3.2, map key 1, Table 9): the signature policy document itself,
/// carried verbatim (CB-5.3.2-02).
/// </summary>
/// <remarks>
/// Equality compares <see cref="Document"/>'s bytes rather than buffer identity, so two instances carrying
/// byte-identical policy documents are equal even when backed by different buffers. <see cref="Document"/> is
/// a borrowed view, never disposed, so the comparison is always safe to perform.
/// </remarks>
[DebuggerDisplay("CBAdESSignaturePolicyStoreDocument({Document.Length} bytes)")]
public sealed class CBAdESSignaturePolicyStoreDocument : CBAdESSignaturePolicyStoreContent, IEquatable<CBAdESSignaturePolicyStoreDocument>
{
    /// <summary>Initializes a new <see cref="CBAdESSignaturePolicyStoreDocument"/>.</summary>
    /// <param name="document">
    /// The signature policy document's encoded octets, encapsulated within a CBOR byte string on the wire
    /// (CB-5.3.2-02). <strong>Borrowed</strong> view — the caller (creation path) or the wire-bytes source
    /// (parse path) owns the underlying memory, matching <see cref="AdESTimestampToken.Val"/>'s ownership
    /// convention.
    /// </param>
    public CBAdESSignaturePolicyStoreDocument(ReadOnlyMemory<byte> document)
    {
        Document = document;
    }

    /// <summary>
    /// The signature policy document's encoded octets, encapsulated within a CBOR byte string on the wire
    /// (CB-5.3.2-02). <strong>Borrowed</strong> view — the caller (creation path) or the wire-bytes source
    /// (parse path) owns the underlying memory, matching <see cref="AdESTimestampToken.Val"/>'s ownership
    /// convention.
    /// </summary>
    public ReadOnlyMemory<byte> Document { get; }

    /// <inheritdoc/>
    public bool Equals(CBAdESSignaturePolicyStoreDocument? other)
    {
        return other is not null && Document.Span.SequenceEqual(other.Document.Span);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as CBAdESSignaturePolicyStoreDocument);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(Document.Span);

        return hash.ToHashCode();
    }

    /// <summary>Reports whether two document arms hold the same policy document octets.</summary>
    public static bool operator ==(CBAdESSignaturePolicyStoreDocument? left, CBAdESSignaturePolicyStoreDocument? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two document arms hold different policy document octets.</summary>
    public static bool operator !=(CBAdESSignaturePolicyStoreDocument? left, CBAdESSignaturePolicyStoreDocument? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// The <c>sigPolLocalURI</c> choice arm (clause 5.3.2, map key 2, Table 9): a URI pointing to a
/// <em>local</em> store where the signature policy document can be retrieved (CB-5.3.2-03) — contrast with
/// <c>spURI</c> (<see cref="AdESSignaturePolicyUri"/>, clause 5.2.7.2), a remote/network pointer.
/// </summary>
/// <remarks>
/// This arm is the pointer it holds and nothing else, so equality is <see cref="Location"/>'s — the
/// component-wise comparison <see cref="Uri"/> defines, so that two arms addressing the same local store are
/// the same arm however each was constructed.
/// </remarks>
[DebuggerDisplay("CBAdESSignaturePolicyStoreLocalUri: {Location}")]
public sealed class CBAdESSignaturePolicyStoreLocalUri : CBAdESSignaturePolicyStoreContent, IEquatable<CBAdESSignaturePolicyStoreLocalUri>
{
    /// <summary>Initializes a new <see cref="CBAdESSignaturePolicyStoreLocalUri"/>.</summary>
    /// <param name="location">
    /// The local-store URI, carried as a
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.4.4.4">CBOR tag 32 (RFC 8949 §3.4.4.4)</see>
    /// URI string on the wire (<c>#6.32(tstr)</c>) — NOTE 1 of clause 5.3.2: "Contrary to the <c>spURI</c>, the
    /// <c>sigPolLocalURI</c> points to a local file."
    /// </param>
    public CBAdESSignaturePolicyStoreLocalUri(Uri location)
    {
        Location = location;
    }

    /// <summary>
    /// The local-store URI, carried as a
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.4.4.4">CBOR tag 32 (RFC 8949 §3.4.4.4)</see>
    /// URI string on the wire (<c>#6.32(tstr)</c>) — NOTE 1 of clause 5.3.2: "Contrary to the <c>spURI</c>, the
    /// <c>sigPolLocalURI</c> points to a local file."
    /// </summary>
    public Uri Location { get; }

    /// <inheritdoc/>
    public bool Equals(CBAdESSignaturePolicyStoreLocalUri? other)
    {
        return other is not null && Location == other.Location;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as CBAdESSignaturePolicyStoreLocalUri);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Location);
    }

    /// <summary>Reports whether two local-URI arms point at the same location.</summary>
    public static bool operator ==(CBAdESSignaturePolicyStoreLocalUri? left, CBAdESSignaturePolicyStoreLocalUri? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two local-URI arms point at different locations.</summary>
    public static bool operator !=(CBAdESSignaturePolicyStoreLocalUri? left, CBAdESSignaturePolicyStoreLocalUri? right)
    {
        return !(left == right);
    }
}
