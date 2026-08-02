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
/// <see cref="CBAdESSignaturePolicyQualifier"/>'s closed-sum treatment of the sibling CDDL group choice in
/// clause 5.2.7.2.
/// </para>
/// <para>
/// (CB-5.3.2-04) <see cref="SpDSpec"/> — the <c>spDSpec</c> member, map key 2 — identifies the technical
/// specification that defines the syntax used for producing the signature policy document carried or
/// pointed to by <see cref="Content"/>; typed as <see cref="CBAdESObjectIdentifier"/> (clause 5.4.1), reused
/// verbatim.
/// </para>
/// <para>
/// <strong>Tamper detection despite being unsigned (clause 5.3.2, NOTE 3).</strong> "Being unsigned, the
/// <c>sigPSt</c> is not protected by the digital signature. If the <c>sigPId</c> signed attribute is
/// incorporated into the signature and contains the <c>digAlgVal</c> member with the digest value of the
/// signature policy document, any alteration of the signature policy document present within <c>sigPSt</c>
/// or within a local store, would be detected by the failure of the digests comparison." This model carries
/// no digest of its own — the tamper check compares <see cref="Content"/>'s bytes (or the bytes retrieved
/// through its local-store pointer) against <see cref="CBAdESSignaturePolicyIdentifier.Digest"/> on the
/// signed <c>sigPId</c> instance, a cross-component check owned by validation, not by this type. Clause 6's
/// Table 14 (out of this stage) further conditions <c>sigPSt</c>'s very presence on that signed <c>sigPId</c>
/// digest already being incorporated (clause 6, requirement b) — likewise a signature-level creation rule,
/// not enforceable from this type alone.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESSignaturePolicyStore: {Content}")]
public sealed record CBAdESSignaturePolicyStore
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
    public CBAdESSignaturePolicyStore(CBAdESSignaturePolicyStoreContent content, CBAdESObjectIdentifier? spDSpec = null)
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
    public CBAdESObjectIdentifier? SpDSpec { get; }
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
/// <see cref="CBAdESPkiObject"/>'s clause notes for <c>X509OrOther</c>); the prose ("shall contain either
/// ... or ...") makes the intended reading an exclusive two-case choice, modelled here as the closed sum
/// below.
/// </para>
/// </remarks>
public abstract record CBAdESSignaturePolicyStoreContent
{
    /// <summary>The <c>sigPolDoc</c> choice arm's map key, within <c>DocOrLocalURI</c> (Table 9, clause 5.3.2).</summary>
    public const int SigPolDocKey = 1;

    /// <summary>The <c>sigPolLocalURI</c> choice arm's map key, within <c>DocOrLocalURI</c> (Table 9, clause 5.3.2).</summary>
    public const int SigPolLocalUriKey = 2;

    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESSignaturePolicyStoreContent()
    {
    }
}


/// <summary>
/// The <c>sigPolDoc</c> choice arm (clause 5.3.2, map key 1, Table 9): the signature policy document itself,
/// carried verbatim (CB-5.3.2-02).
/// </summary>
/// <param name="Document">
/// The signature policy document's encoded octets, encapsulated within a CBOR byte string on the wire
/// (CB-5.3.2-02). <strong>Borrowed</strong> view — the caller (creation path) or the wire-bytes source
/// (parse path) owns the underlying memory, matching <see cref="CBAdESTimestampToken.Val"/>'s ownership
/// convention.
/// </param>
[DebuggerDisplay("CBAdESSignaturePolicyStoreDocument({Document.Length} bytes)")]
public sealed record CBAdESSignaturePolicyStoreDocument(ReadOnlyMemory<byte> Document) : CBAdESSignaturePolicyStoreContent;


/// <summary>
/// The <c>sigPolLocalURI</c> choice arm (clause 5.3.2, map key 2, Table 9): a URI pointing to a
/// <em>local</em> store where the signature policy document can be retrieved (CB-5.3.2-03) — contrast with
/// <c>spURI</c> (<see cref="CBAdESSignaturePolicyUri"/>, clause 5.2.7.2), a remote/network pointer.
/// </summary>
/// <param name="Location">
/// The local-store URI, carried as a
/// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.4.4.4">CBOR tag 32 (RFC 8949 §3.4.4.4)</see>
/// URI string on the wire (<c>#6.32(tstr)</c>) — NOTE 1 of clause 5.3.2: "Contrary to the <c>spURI</c>, the
/// <c>sigPolLocalURI</c> points to a local file."
/// </param>
[DebuggerDisplay("CBAdESSignaturePolicyStoreLocalUri: {Location}")]
public sealed record CBAdESSignaturePolicyStoreLocalUri(Uri Location) : CBAdESSignaturePolicyStoreContent;
