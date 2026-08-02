using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>uHeaders</c> unsigned header parameter (label <c>268</c>, Table 8) — the single CBOR-array
/// unprotected-header container that holds every unsigned (post-signature) CB-AdES component, in strict
/// append-only incorporation order, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.3.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// CDDL (clause 5.3.1; reconstructed from two markdown fences split by a page-break artifact — content
/// unaltered, per the CB-AdES preflight leg 3 "Traps" note):
/// </para>
/// <code>
/// uHeaders = [+bstr .cbor UHeaderInstance] ;an array of CBOR byte strings each one encapsulating
///                                          ;one instance of UHeaderInstance
/// UHeaderInstance = {
///     sigTst_l =&gt; sigTst //     ;Signature time-stamp OR
///     valData_l =&gt; valData //   ;Validation data OR
///     arcTst_l =&gt; arcTst //     ;Archive-time-stamp OR
///     refs_l =&gt; refs //         ;References to certificates and revocation data OR
///     sigRTst_l =&gt; sigRTst //   ;Signature and references time-stamp OR
///     rfsTst_l =&gt; rfsTst //     ;References only time-stamp OR
///     sigPSt_l =&gt; sigPSt //     ;Signature Policy Store OR
///     11 =&gt; COSE_CounterSignature / [+COSE_CounterSignature] // ;full counter signature (IETF RFC 9338)
///     12 =&gt; COSE_CounterSignature0 //                           ;abbreviated counter signature (IETF RFC 9338)
///     33 =&gt; bstr / [2*certs:bstr] //                            ;x5chain for the signing certificate
///     *label =&gt; value          ;other additional unsigned attributes not specified in the present document
/// }
/// </code>
/// <para>
/// <strong>Array, not map (CB-5.3.1-01).</strong> "The <c>uHeaders</c> parameter, member of the unprotected
/// headers map, shall be a CBOR array whose elements contain CBOR values that are not signed by the CB-AdES
/// signature." NOTE 1 (clause 5.3.1) explains why: CBOR maps do not preserve order, but each successive
/// <c>arcTst</c>'s message imprint (clause 5.3.5.3) is built by concatenating, among other things, every
/// element already present in <c>uHeaders</c> in wire order — an ordered, append-only sequence is therefore
/// load-bearing, not incidental (CB-AdES preflight leg 3 synthesis fact). <see cref="CBAdESTimestampContainer"/>'s
/// own CB-5.4.3.3-09 remarks make the same point from the timestamp side: "the containers of time-stamp
/// tokens time-stamping components within the <c>uHeaders</c> unsigned header parameter, implicitly identify
/// what components are time-stamped ... No further information ... is required" — coverage is purely
/// positional, which is exactly why <see cref="ElementsBefore"/> exists.
/// </para>
/// <para>
/// <strong>Content scope (CB-5.3.1-02).</strong> "The <c>uHeaders</c> header parameter shall contain CBOR
/// values that qualify the CB-AdES signature itself, or the signer, or the COSE Payload."
/// </para>
/// <para>
/// <strong>Append-only (CB-5.3.1-03), enforced by API shape, not a runtime flag.</strong> "New unsigned
/// attributes shall always be added at the end of the <c>uHeaders</c> header parameter, which is a CBOR
/// array." <see cref="Append"/> is the only way to grow an instance: it returns a NEW
/// <see cref="CBAdESUnsignedHeaders"/> with the supplied element placed after every element this instance
/// already holds. There is no insert-at, reorder, or remove operation of any kind, so an illegal reordering
/// cannot be expressed through this type's surface.
/// </para>
/// <para>
/// <strong>bstr encapsulation is the CBOR layer's concern (CB-5.3.1-04).</strong> "The unsigned attributes
/// shall be encapsulated in CBOR byte strings before being placed within the <c>uHeaders</c> header
/// parameter." This model holds decoded <see cref="CBAdESUnsignedHeaderElement"/> values, not their
/// bstr-wrapped bytes; the codec (out of this stage's scope) owns both directions of that wrapping. The
/// <c>arcTst</c> message-imprint algorithm (clause 5.3.5.3) must walk the ENCODED bytes of each element, not
/// this decoded model, since the imprint is byte-exact over the wire encapsulation — the imprint builder is
/// therefore a CBOR-layer concern that reads this model only for its ordering and slicing, not for byte
/// production.
/// </para>
/// <para>
/// <strong>Exclusive incorporation point (CB-5.3.1-05).</strong> "All the CBOR objects listed above [
/// <c>sigPSt</c>, counter signature, <c>sigTst</c>, <c>valData</c>, <c>arcTst</c>, <c>refs</c>,
/// <c>sigRTst</c>, <c>rfsTst</c>] shall be placed within the <c>uHeaders</c> header parameter if they are
/// incorporated into the CB-AdES signature." <see cref="CBAdESUnsignedHeaderElement"/>'s closed sum
/// enumerates exactly these eight kinds, plus <c>x5chain</c> (label 33) and the open extension case, so no
/// other unsigned-component type exists outside this container.
/// </para>
/// <para>
/// <strong>Label/tag (CB-5.3.1-06), read per the S1 registry ruling.</strong> "The <c>uHeaders</c> CBOR array
/// shall be assigned an identifying tag. Additionally, each unsigned attribute shall be assigned a label"
/// (Table 8: <c>uHeaders</c> = <c>268</c>). The CDDL above shows NO <c>#6.268(...)</c> CBOR-tag wrapping
/// anywhere on the array production — "identifying tag" here reads as the IANA COSE header-parameter label
/// under which <c>uHeaders</c> appears as a member of the unprotected headers map (clause 3, IETF RFC 9052),
/// not a CBOR major-type-6 tag applied to the array value itself. That reading is already the one recorded
/// where the label lives on the wire side (the JCose serialization layer's header-parameter registry,
/// wavecb-contract.md ruling R-1(b)); this model carries no tag/label field of its own for the same reason
/// <see cref="CBAdESReferences"/> carries none — the label is wire-format placement, owned by the codec, not
/// by this decoded model.
/// </para>
/// <para>
/// <strong>Non-empty (CB-5.3.1-07), enforced at construction.</strong> "The <c>uHeaders</c> header parameter
/// shall be a non-empty array." An instance cannot exist with zero elements: <c>uHeaders</c> itself should
/// not exist at all until the first unsigned component is incorporated, rather than exist-but-empty.
/// </para>
/// <para>
/// <strong>Layer placement (CB-5.3.1-08/09), owned by the COSE substrate, not this model.</strong> "In
/// CB-AdES signatures supported by a <c>COSE_Sign</c> structure, this header parameter shall be placed at the
/// signer layer" (CB-5.3.1-08), and "The <c>uHeaders</c> header parameter shall be incorporated as member of
/// the unprotected header map of the CB-AdES signature" (CB-5.3.1-09, clause 3, IETF RFC 9052). Clause 4.4
/// additionally forbids <c>uHeaders</c> in the body layer of a <c>COSE_Sign</c> structure outright ("Shall
/// not contain the <c>uHeaders</c> unprotected header parameter in the body layer"). This type is
/// layer-agnostic by design: which COSE layer an instance is placed in is a property of the surrounding
/// signature structure, assembled by the (out-of-scope-here) COSE-composing orchestrator, not of this value
/// type.
/// </para>
/// <para>
/// <strong>Sole-member default (CB-5.3.1-10), a SHOULD, not a SHALL.</strong> "The <c>uHeaders</c> header
/// parameter should be the only header parameter incorporated to the unprotected headers map." Tolerating a
/// non-conformant signature with additional unprotected-header siblings is a validator policy choice for a
/// later stage; this type cannot see sibling unprotected-header members, so it cannot enforce or reject their
/// presence.
/// </para>
/// <para>
/// <strong>Extension escape hatch (CB-5.3.1-11), a SHOULD.</strong> "Any CBOR value that is not specified in
/// the present document should be incorporated as an element of the <c>uHeaders</c> header parameter" — the
/// CDDL's <c>*label =&gt; value</c> catch-all, modelled by <see cref="CBAdESUnsignedHeaderElementUnknown"/>.
/// </para>
/// <para>
/// <strong>Archive-timestamp protection hazard (clause 5.3.5.1, NOTE 2).</strong> "Any header parameter
/// different than <c>uHeaders</c> CBOR array present within the unprotected headers map is not protected by
/// the time-stamps encapsulated by this CBOR map [<c>arcTst</c>]." Combined with CB-5.3.1-10 being a SHOULD
/// rather than a SHALL, a tolerated extra unprotected-header sibling gets no archive-timestamp protection at
/// all — a caution for validators, not something this type can detect.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns every disposable element reachable through its indexer.
/// <see cref="Dispose"/> disposes every element that implements <see cref="IDisposable"/> and leaves the
/// others untouched — several element kinds (<see cref="CBAdESUnsignedHeaderElementValidationData"/>,
/// <see cref="CBAdESUnsignedHeaderElementSignaturePolicyStore"/>, and every opaque-bytes kind) own no
/// disposable resources of their own, matching each wrapped model's own ownership remarks.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESUnsignedHeaders({Count} elements)")]
public sealed record CBAdESUnsignedHeaders: IReadOnlyList<CBAdESUnsignedHeaderElement>, IDisposable
{
    /// <summary>
    /// The ordered backing storage of this instance's elements, in incorporation (wire) order. Never empty
    /// (enforced at construction, CB-5.3.1-07) and never mutated in place — <see cref="Append"/> always
    /// returns a new, independently-backed instance.
    /// </summary>
    private CBAdESUnsignedHeaderElement[] Elements { get; }


    /// <summary>
    /// Initializes a new <see cref="CBAdESUnsignedHeaders"/> from its full ordered element sequence. Takes a
    /// snapshot: subsequent mutation of <paramref name="elements"/> has no effect on this instance.
    /// </summary>
    /// <param name="elements">
    /// The unsigned header elements, in incorporation (wire) order (CB-5.3.1-01/03). Must contain at least
    /// one element (CB-5.3.1-07).
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="elements"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="elements"/> is empty.</exception>
    public CBAdESUnsignedHeaders(IReadOnlyList<CBAdESUnsignedHeaderElement> elements)
    {
        ArgumentNullException.ThrowIfNull(elements);

        if(elements.Count == 0)
        {
            throw new ArgumentException(
                "The 'uHeaders' header parameter shall be a non-empty array (ETSI TS 119 152-1 V1.1.1, clause 5.3.1, CB-5.3.1-07).",
                nameof(elements));
        }

        var snapshot = new CBAdESUnsignedHeaderElement[elements.Count];
        for(int i = 0; i < elements.Count; ++i)
        {
            snapshot[i] = elements[i];
        }

        Elements = snapshot;
    }


    /// <summary>
    /// Initializes a new <see cref="CBAdESUnsignedHeaders"/> directly from an already-owned backing array.
    /// Used internally by <see cref="Append"/>, which always produces a non-empty array, so the public
    /// constructor's guard would be redundant here.
    /// </summary>
    /// <param name="elements">The already-owned backing array, in incorporation order.</param>
    private CBAdESUnsignedHeaders(CBAdESUnsignedHeaderElement[] elements)
    {
        Elements = elements;
    }


    /// <summary>Gets the number of elements currently incorporated into this instance.</summary>
    public int Count => Elements.Length;


    /// <summary>Gets the element at the given zero-based position, in incorporation (wire) order.</summary>
    /// <param name="index">The zero-based position.</param>
    public CBAdESUnsignedHeaderElement this[int index] => Elements[index];


    /// <summary>
    /// Returns a NEW <see cref="CBAdESUnsignedHeaders"/> with <paramref name="element"/> incorporated after
    /// every element this instance already holds (CB-5.3.1-03: "New unsigned attributes shall always be added
    /// at the end"). This instance is left unchanged; there is no insert-at, reorder, or remove operation on
    /// this type.
    /// </summary>
    /// <param name="element">The element to append.</param>
    /// <returns>A new instance with <paramref name="element"/> as its last element.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="element"/> is <see langword="null"/>.</exception>
    public CBAdESUnsignedHeaders Append(CBAdESUnsignedHeaderElement element)
    {
        ArgumentNullException.ThrowIfNull(element);

        var next = new CBAdESUnsignedHeaderElement[Elements.Length + 1];
        for(int i = 0; i < Elements.Length; ++i)
        {
            next[i] = Elements[i];
        }

        next[Elements.Length] = element;

        return new CBAdESUnsignedHeaders(next);
    }


    /// <summary>
    /// Returns the elements strictly before the given position, in incorporation order — the prefix an
    /// <c>arcTst</c> element at that position covers under the clause 5.3.5.3 validation-time message-imprint
    /// variant ("take the elements in the <c>uHeaders</c> header parameter ... that precede (appear BEFORE)
    /// the <c>arcTst</c> CBOR map that contains the time-stamp token that is being validated"). Passing
    /// <see cref="Count"/> returns every element — the generation-time variant's full-sequence view.
    /// </summary>
    /// <param name="index">
    /// The exclusive upper bound: elements at positions <c>0</c> through <c>index - 1</c> are returned. Must
    /// be within <c>[0, Count]</c>.
    /// </param>
    /// <returns>A new, independent snapshot list of the elements before <paramref name="index"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="index"/> is negative or greater than <see cref="Count"/>.
    /// </exception>
    public IReadOnlyList<CBAdESUnsignedHeaderElement> ElementsBefore(int index)
    {
        if(index < 0 || index > Elements.Length)
        {
            throw new ArgumentOutOfRangeException(
                nameof(index),
                index,
                "The prefix boundary must be within [0, Count] (ETSI TS 119 152-1 V1.1.1, clause 5.3.5.3, validation-time message-imprint variant).");
        }

        var prefix = new CBAdESUnsignedHeaderElement[index];
        for(int i = 0; i < index; ++i)
        {
            prefix[i] = Elements[i];
        }

        return prefix;
    }


    /// <summary>Returns an enumerator over the elements, in incorporation order.</summary>
    public IEnumerator<CBAdESUnsignedHeaderElement> GetEnumerator()
    {
        return ((IEnumerable<CBAdESUnsignedHeaderElement>)Elements).GetEnumerator();
    }


    /// <summary>Returns a non-generic enumerator over the elements, in incorporation order.</summary>
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();


    /// <summary>
    /// Disposes every element reachable through this instance that implements <see cref="IDisposable"/>;
    /// element kinds that own no disposable resources (see the type remarks) are left untouched.
    /// </summary>
    public void Dispose()
    {
        for(int i = 0; i < Elements.Length; ++i)
        {
            if(Elements[i] is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }
}


/// <summary>
/// One element of the <c>UHeaderInstance</c> CDDL choice (clause 5.3.1) — the closed sum of every kind of
/// value <see cref="CBAdESUnsignedHeaders"/> may carry, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.3.1</see>, Table 8. A DU-ready closed sum: no external type may derive
/// from it.
/// </summary>
/// <remarks>
/// <para>
/// Eleven arms: the seven this document names by its own component clauses (<c>sigTst</c>, <c>valData</c>,
/// <c>arcTst</c>, <c>refs</c>, <c>sigRTst</c>, <c>rfsTst</c>, <c>sigPSt</c> — Table 8 labels <c>1</c>-<c>7</c>,
/// CB-5.3.1-05/06), the two <see href="https://www.rfc-editor.org/rfc/rfc9338">IETF RFC 9338</see>
/// counter-signature shapes (labels <c>11</c>/<c>12</c>), the
/// <see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">IETF RFC 9360</see> <c>x5chain</c> shape
/// (label <c>33</c>), and the open <c>*label =&gt; value</c> catch-all (CB-5.3.1-11) for anything else.
/// </para>
/// <para>
/// <see cref="Label"/> exposes each concrete sibling's Table-8-or-equivalent wire key polymorphically, so the
/// codec that walks a <see cref="CBAdESUnsignedHeaders"/> instance to encode it never needs its own
/// type-to-label switch that could drift out of sync as new sibling kinds are added.
/// </para>
/// </remarks>
public abstract record CBAdESUnsignedHeaderElement
{
    /// <summary>The <c>sigTst</c> arm's label (Table 8, clause 5.3.1).</summary>
    public const int SignatureTimestampLabel = 1;

    /// <summary>The <c>valData</c> arm's label (Table 8, clause 5.3.1).</summary>
    public const int ValidationDataLabel = 2;

    /// <summary>The <c>arcTst</c> arm's label (Table 8, clause 5.3.1).</summary>
    public const int ArchiveTimestampLabel = 3;

    /// <summary>The <c>refs</c> arm's label (Table 8, clause 5.3.1).</summary>
    public const int ReferencesLabel = 4;

    /// <summary>The <c>sigRTst</c> arm's label (Table 8, clause 5.3.1).</summary>
    public const int SignatureAndReferencesTimestampLabel = 5;

    /// <summary>The <c>rfsTst</c> arm's label (Table 8, clause 5.3.1).</summary>
    public const int ReferencesTimestampLabel = 6;

    /// <summary>The <c>sigPSt</c> arm's label (Table 8, clause 5.3.1).</summary>
    public const int SignaturePolicyStoreLabel = 7;

    /// <summary>
    /// The full-counter-signature arm's label (clause 5.3.1 CDDL;
    /// <see href="https://www.rfc-editor.org/rfc/rfc9338">IETF RFC 9338</see>).
    /// </summary>
    public const int FullCounterSignatureLabel = 11;

    /// <summary>
    /// The abbreviated-counter-signature arm's label (clause 5.3.1 CDDL;
    /// <see href="https://www.rfc-editor.org/rfc/rfc9338">IETF RFC 9338</see>).
    /// </summary>
    public const int AbbreviatedCounterSignatureLabel = 12;

    /// <summary>
    /// The <c>x5chain</c> arm's label (clause 5.3.1 CDDL;
    /// <see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">IETF RFC 9360 §2</see>).
    /// </summary>
    public const int CertificateChainLabel = 33;

    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESUnsignedHeaderElement()
    {
    }


    /// <summary>
    /// Gets this element's wire key: one of this type's own <c>int</c> label constants for the ten named
    /// arms, or the free-form <c>label</c> a <see cref="CBAdESUnsignedHeaderElementUnknown"/> catch-all entry
    /// carries.
    /// </summary>
    public abstract CBAdESUnsignedHeaderElementLabel Label { get; }
}


/// <summary>
/// The <c>label</c> CDDL rule (clause 5.2.5: <c>label = int / tstr</c>) as it applies to
/// <see cref="CBAdESUnsignedHeaderElement.Label"/> — a closed two-arm sum giving every element of
/// <see cref="CBAdESUnsignedHeaders"/> a uniform, switch-free way to expose its wire key, whether that key is
/// one of this document's own fixed integer labels (Table 8, or the RFC-9338/RFC-9360 labels <c>11</c>/
/// <c>12</c>/<c>33</c>) or the free-form <c>label</c> a <see cref="CBAdESUnsignedHeaderElementUnknown"/>
/// catch-all entry carries. A DU-ready closed sum: no external type may derive from it.
/// </summary>
/// <remarks>
/// An independent identity from <see cref="CBAdESSignaturePolicyQualifierLabel"/>'s occurrence of the same
/// CDDL rule — see the remarks on <see cref="CBAdESUnsignedHeaderElementUnknown"/> for why this document's own
/// convention is to give each occurrence of a reused CDDL shape its own type identity.
/// </remarks>
public abstract record CBAdESUnsignedHeaderElementLabel
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESUnsignedHeaderElementLabel()
    {
    }
}


/// <summary>
/// The <c>int</c> arm of the <c>label</c> CDDL rule (clause 5.2.5), as carried by
/// <see cref="CBAdESUnsignedHeaderElement.Label"/>.
/// </summary>
/// <param name="Value">The integer label.</param>
[DebuggerDisplay("CBAdESUnsignedHeaderElementIntegerLabel: {Value}")]
public sealed record CBAdESUnsignedHeaderElementIntegerLabel(int Value) : CBAdESUnsignedHeaderElementLabel;


/// <summary>
/// The <c>tstr</c> arm of the <c>label</c> CDDL rule (clause 5.2.5), as carried by
/// <see cref="CBAdESUnsignedHeaderElement.Label"/>.
/// </summary>
/// <param name="Value">The text label.</param>
[DebuggerDisplay("CBAdESUnsignedHeaderElementTextLabel: {Value}")]
public sealed record CBAdESUnsignedHeaderElementTextLabel(string Value) : CBAdESUnsignedHeaderElementLabel;


/// <summary>
/// The <c>sigTst</c> arm of <c>UHeaderInstance</c> (clause 5.3.1, Table 8, label <c>1</c>): one
/// <see cref="CBAdESSignatureTimestamp"/> incorporated as an element of <see cref="CBAdESUnsignedHeaders"/>.
/// </summary>
/// <param name="SignatureTimestamp">The wrapped signature time-stamp component.</param>
[DebuggerDisplay("CBAdESUnsignedHeaderElementSignatureTimestamp: {SignatureTimestamp}")]
public sealed record CBAdESUnsignedHeaderElementSignatureTimestamp(CBAdESSignatureTimestamp SignatureTimestamp)
    : CBAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>
    /// Gets the <c>sigTst</c> label (Table 8, clause 5.3.1) —
    /// <see cref="CBAdESUnsignedHeaderElement.SignatureTimestampLabel"/> (<c>1</c>).
    /// </summary>
    public override CBAdESUnsignedHeaderElementLabel Label => new CBAdESUnsignedHeaderElementIntegerLabel(SignatureTimestampLabel);


    /// <summary>Disposes <see cref="SignatureTimestamp"/>.</summary>
    public void Dispose() => SignatureTimestamp.Dispose();
}


/// <summary>
/// The <c>valData</c> arm of <c>UHeaderInstance</c> (clause 5.3.1, Table 8, label <c>2</c>): one
/// <see cref="CBAdESValidationData"/> incorporated as an element of <see cref="CBAdESUnsignedHeaders"/>.
/// </summary>
/// <param name="ValidationData">The wrapped certificate/revocation validation-data component.</param>
[DebuggerDisplay("CBAdESUnsignedHeaderElementValidationData: {ValidationData}")]
public sealed record CBAdESUnsignedHeaderElementValidationData(CBAdESValidationData ValidationData)
    : CBAdESUnsignedHeaderElement
{
    /// <summary>
    /// Gets the <c>valData</c> label (Table 8, clause 5.3.1) —
    /// <see cref="CBAdESUnsignedHeaderElement.ValidationDataLabel"/> (<c>2</c>).
    /// </summary>
    public override CBAdESUnsignedHeaderElementLabel Label => new CBAdESUnsignedHeaderElementIntegerLabel(ValidationDataLabel);
}


/// <summary>
/// The <c>arcTst</c> arm of <c>UHeaderInstance</c> (clause 5.3.1, Table 8, label <c>3</c>): one
/// <see cref="CBAdESArchiveTimestamp"/> incorporated as an element of <see cref="CBAdESUnsignedHeaders"/>.
/// </summary>
/// <param name="ArchiveTimestamp">The wrapped archive time-stamp component.</param>
[DebuggerDisplay("CBAdESUnsignedHeaderElementArchiveTimestamp: {ArchiveTimestamp}")]
public sealed record CBAdESUnsignedHeaderElementArchiveTimestamp(CBAdESArchiveTimestamp ArchiveTimestamp)
    : CBAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>
    /// Gets the <c>arcTst</c> label (Table 8, clause 5.3.1) —
    /// <see cref="CBAdESUnsignedHeaderElement.ArchiveTimestampLabel"/> (<c>3</c>).
    /// </summary>
    public override CBAdESUnsignedHeaderElementLabel Label => new CBAdESUnsignedHeaderElementIntegerLabel(ArchiveTimestampLabel);


    /// <summary>Disposes <see cref="ArchiveTimestamp"/>.</summary>
    public void Dispose() => ArchiveTimestamp.Dispose();
}


/// <summary>
/// The <c>refs</c> arm of <c>UHeaderInstance</c> (clause 5.3.1, Table 8, label <c>4</c>): one
/// <see cref="CBAdESReferences"/> incorporated as an element of <see cref="CBAdESUnsignedHeaders"/>.
/// </summary>
/// <param name="References">The wrapped certificate/revocation references component.</param>
[DebuggerDisplay("CBAdESUnsignedHeaderElementReferences: {References}")]
public sealed record CBAdESUnsignedHeaderElementReferences(CBAdESReferences References)
    : CBAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>
    /// Gets the <c>refs</c> label (Table 8, clause 5.3.1) —
    /// <see cref="CBAdESUnsignedHeaderElement.ReferencesLabel"/> (<c>4</c>).
    /// </summary>
    public override CBAdESUnsignedHeaderElementLabel Label => new CBAdESUnsignedHeaderElementIntegerLabel(ReferencesLabel);


    /// <summary>Disposes <see cref="References"/>.</summary>
    public void Dispose() => References.Dispose();
}


/// <summary>
/// The <c>sigRTst</c> arm of <c>UHeaderInstance</c> (clause 5.3.1, Table 8, label <c>5</c>): one
/// <see cref="CBAdESSignatureAndReferencesTimestamp"/> incorporated as an element of
/// <see cref="CBAdESUnsignedHeaders"/>.
/// </summary>
/// <param name="SignatureAndReferencesTimestamp">The wrapped signature-and-references time-stamp component.</param>
[DebuggerDisplay("CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp: {SignatureAndReferencesTimestamp}")]
public sealed record CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp(
    CBAdESSignatureAndReferencesTimestamp SignatureAndReferencesTimestamp)
    : CBAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>
    /// Gets the <c>sigRTst</c> label (Table 8, clause 5.3.1) —
    /// <see cref="CBAdESUnsignedHeaderElement.SignatureAndReferencesTimestampLabel"/> (<c>5</c>).
    /// </summary>
    public override CBAdESUnsignedHeaderElementLabel Label => new CBAdESUnsignedHeaderElementIntegerLabel(SignatureAndReferencesTimestampLabel);


    /// <summary>Disposes <see cref="SignatureAndReferencesTimestamp"/>.</summary>
    public void Dispose() => SignatureAndReferencesTimestamp.Dispose();
}


/// <summary>
/// The <c>rfsTst</c> arm of <c>UHeaderInstance</c> (clause 5.3.1, Table 8, label <c>6</c>): one
/// <see cref="CBAdESReferencesTimestamp"/> incorporated as an element of <see cref="CBAdESUnsignedHeaders"/>.
/// </summary>
/// <param name="ReferencesTimestamp">The wrapped references-only time-stamp component.</param>
[DebuggerDisplay("CBAdESUnsignedHeaderElementReferencesTimestamp: {ReferencesTimestamp}")]
public sealed record CBAdESUnsignedHeaderElementReferencesTimestamp(CBAdESReferencesTimestamp ReferencesTimestamp)
    : CBAdESUnsignedHeaderElement, IDisposable
{
    /// <summary>
    /// Gets the <c>rfsTst</c> label (Table 8, clause 5.3.1) —
    /// <see cref="CBAdESUnsignedHeaderElement.ReferencesTimestampLabel"/> (<c>6</c>).
    /// </summary>
    public override CBAdESUnsignedHeaderElementLabel Label => new CBAdESUnsignedHeaderElementIntegerLabel(ReferencesTimestampLabel);


    /// <summary>Disposes <see cref="ReferencesTimestamp"/>.</summary>
    public void Dispose() => ReferencesTimestamp.Dispose();
}


/// <summary>
/// The <c>sigPSt</c> arm of <c>UHeaderInstance</c> (clause 5.3.1, Table 8, label <c>7</c>): one
/// <see cref="CBAdESSignaturePolicyStore"/> incorporated as an element of <see cref="CBAdESUnsignedHeaders"/>.
/// </summary>
/// <param name="SignaturePolicyStore">The wrapped signature-policy-store component.</param>
[DebuggerDisplay("CBAdESUnsignedHeaderElementSignaturePolicyStore: {SignaturePolicyStore}")]
public sealed record CBAdESUnsignedHeaderElementSignaturePolicyStore(CBAdESSignaturePolicyStore SignaturePolicyStore)
    : CBAdESUnsignedHeaderElement
{
    /// <summary>
    /// Gets the <c>sigPSt</c> label (Table 8, clause 5.3.1) —
    /// <see cref="CBAdESUnsignedHeaderElement.SignaturePolicyStoreLabel"/> (<c>7</c>).
    /// </summary>
    public override CBAdESUnsignedHeaderElementLabel Label => new CBAdESUnsignedHeaderElementIntegerLabel(SignaturePolicyStoreLabel);
}


/// <summary>
/// The full-counter-signature arm of <c>UHeaderInstance</c> (clause 5.3.1, label <c>11</c>): a
/// <see href="https://www.rfc-editor.org/rfc/rfc9338">IETF RFC 9338</see> <c>COSE_CounterSignature</c> (or a
/// non-empty array of them, per the CDDL's <c>COSE_CounterSignature / [+COSE_CounterSignature]</c> choice)
/// incorporated as an element of <see cref="CBAdESUnsignedHeaders"/>.
/// </summary>
/// <remarks>
/// Carried OPAQUE at this stage: the RFC 9338 <c>COSE_CounterSignature</c> structure itself is substrate
/// capability built in the JCose/Cbor COSE layer (wavecb-contract.md stage S6), not modelled here.
/// <see cref="Value"/> is the raw, already-CBOR-encoded value bytes for this <c>UHeaderInstance</c> arm — a
/// single <c>COSE_CounterSignature</c> or the encoded array form, whichever the wire uses — to be decoded,
/// once S6 lands, by that substrate layer, not reinterpreted by this type.
/// </remarks>
/// <param name="Value">
/// The raw encoded value bytes for this arm. <strong>Borrowed</strong> view — the caller (creation path) or
/// the wire-bytes source (parse path) owns the underlying memory.
/// </param>
[DebuggerDisplay("CBAdESUnsignedHeaderElementFullCounterSignature: {Value.Length} bytes")]
public sealed record CBAdESUnsignedHeaderElementFullCounterSignature(ReadOnlyMemory<byte> Value)
    : CBAdESUnsignedHeaderElement
{
    /// <summary>
    /// Gets the full-counter-signature label (clause 5.3.1 CDDL) —
    /// <see cref="CBAdESUnsignedHeaderElement.FullCounterSignatureLabel"/> (<c>11</c>).
    /// </summary>
    public override CBAdESUnsignedHeaderElementLabel Label => new CBAdESUnsignedHeaderElementIntegerLabel(FullCounterSignatureLabel);
}


/// <summary>
/// The abbreviated-counter-signature arm of <c>UHeaderInstance</c> (clause 5.3.1, label <c>12</c>): a
/// <see href="https://www.rfc-editor.org/rfc/rfc9338">IETF RFC 9338</see> <c>COSE_CounterSignature0</c>
/// incorporated as an element of <see cref="CBAdESUnsignedHeaders"/>.
/// </summary>
/// <remarks>
/// Carried OPAQUE at this stage: the RFC 9338 <c>COSE_CounterSignature0</c> structure itself is substrate
/// capability built in the JCose/Cbor COSE layer (wavecb-contract.md stage S6), not modelled here.
/// <see cref="Value"/> is the raw, already-CBOR-encoded value bytes for this <c>UHeaderInstance</c> arm, to be
/// decoded, once S6 lands, by that substrate layer, not reinterpreted by this type.
/// </remarks>
/// <param name="Value">
/// The raw encoded value bytes for this arm. <strong>Borrowed</strong> view — the caller (creation path) or
/// the wire-bytes source (parse path) owns the underlying memory.
/// </param>
[DebuggerDisplay("CBAdESUnsignedHeaderElementAbbreviatedCounterSignature: {Value.Length} bytes")]
public sealed record CBAdESUnsignedHeaderElementAbbreviatedCounterSignature(ReadOnlyMemory<byte> Value)
    : CBAdESUnsignedHeaderElement
{
    /// <summary>
    /// Gets the abbreviated-counter-signature label (clause 5.3.1 CDDL) —
    /// <see cref="CBAdESUnsignedHeaderElement.AbbreviatedCounterSignatureLabel"/> (<c>12</c>).
    /// </summary>
    public override CBAdESUnsignedHeaderElementLabel Label => new CBAdESUnsignedHeaderElementIntegerLabel(AbbreviatedCounterSignatureLabel);
}


/// <summary>
/// The <c>x5chain</c> arm of <c>UHeaderInstance</c> (clause 5.3.1, label <c>33</c>): the signing certificate's
/// chain, carried unsigned, per
/// <see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">IETF RFC 9360 §2</see> — incorporated as an
/// element of <see cref="CBAdESUnsignedHeaders"/> when the certificate chain is not signed (clause 5.2.2: "If
/// <c>x5chain</c> has not to be signed, it shall be included within the <c>uHeaders</c> CBOR array").
/// </summary>
/// <remarks>
/// Carried OPAQUE at this stage: <see cref="Value"/> is the raw, already-CBOR-encoded <c>x5chain</c> value
/// bytes for this arm — a <c>bstr</c> (single certificate) or the CDDL's <c>[2*certs:bstr]</c> array form (a
/// chain of two or more), whichever the wire uses — to be decoded by the COSE/x5* substrate layer, not
/// reinterpreted by this type. Contrast with the signed <c>x5chain</c> occurrence (clause 5.1.8, out of this
/// type), which is a protected-header-map member rather than a <see cref="CBAdESUnsignedHeaders"/> element.
/// </remarks>
/// <param name="Value">
/// The raw encoded value bytes for this arm. <strong>Borrowed</strong> view — the caller (creation path) or
/// the wire-bytes source (parse path) owns the underlying memory.
/// </param>
[DebuggerDisplay("CBAdESUnsignedHeaderElementCertificateChain: {Value.Length} bytes")]
public sealed record CBAdESUnsignedHeaderElementCertificateChain(ReadOnlyMemory<byte> Value)
    : CBAdESUnsignedHeaderElement
{
    /// <summary>
    /// Gets the <c>x5chain</c> label (clause 5.3.1 CDDL) —
    /// <see cref="CBAdESUnsignedHeaderElement.CertificateChainLabel"/> (<c>33</c>).
    /// </summary>
    public override CBAdESUnsignedHeaderElementLabel Label => new CBAdESUnsignedHeaderElementIntegerLabel(CertificateChainLabel);
}


/// <summary>
/// The <c>*label =&gt; value</c> catch-all arm of <c>UHeaderInstance</c> (clause 5.3.1): an unsigned CB-AdES
/// component not specified in the present document (CB-5.3.1-11, a SHOULD-level extension escape hatch).
/// </summary>
/// <remarks>
/// <see cref="Label"/> models the CDDL's shared <c>label = int / tstr</c> rule (clause 5.2.5) through
/// <see cref="CBAdESUnsignedHeaderElementLabel"/> — an identity independent from
/// <see cref="CBAdESSignaturePolicyQualifierLabel"/>'s own occurrence of the same CDDL rule for
/// <c>otherQuals</c> (clause 5.2.7.2), matching this document's own convention of giving each occurrence of a
/// reused CDDL shape its own type identity (e.g. <see cref="CBAdESSignatureTimestamp"/> vs.
/// <see cref="CBAdESArchiveTimestamp"/>, both straight aliases of <see cref="CBAdESTimestampContainer"/>).
/// <see cref="Value"/> is the raw, already-CBOR-encoded value bytes for this arm, kept opaque — this library
/// makes no claim about the shape of a component it does not itself specify.
/// </remarks>
[DebuggerDisplay("CBAdESUnsignedHeaderElementUnknown: {Label}, {Value.Length} bytes")]
public sealed record CBAdESUnsignedHeaderElementUnknown : CBAdESUnsignedHeaderElement
{
    /// <summary>
    /// Initializes a new <see cref="CBAdESUnsignedHeaderElementUnknown"/>.
    /// </summary>
    /// <param name="label">The catch-all key identifying this element (the CDDL's <c>label</c> rule).</param>
    /// <param name="value">
    /// The element's raw encoded value bytes. <strong>Borrowed</strong> view — the caller (creation path) or
    /// the wire-bytes source (parse path) owns the underlying memory.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="label"/> is <see langword="null"/>.</exception>
    public CBAdESUnsignedHeaderElementUnknown(CBAdESUnsignedHeaderElementLabel label, ReadOnlyMemory<byte> value)
    {
        ArgumentNullException.ThrowIfNull(label);

        Label = label;
        Value = value;
    }


    /// <summary>Gets the catch-all key identifying this element (the CDDL's <c>label</c> rule, clause 5.2.5).</summary>
    public override CBAdESUnsignedHeaderElementLabel Label { get; }

    /// <summary>
    /// Gets the element's raw encoded value bytes. <strong>Borrowed</strong> view — the caller (creation path)
    /// or the wire-bytes source (parse path) owns the underlying memory.
    /// </summary>
    public ReadOnlyMemory<byte> Value { get; }
}
