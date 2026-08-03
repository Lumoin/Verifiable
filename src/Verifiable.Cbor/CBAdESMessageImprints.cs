using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Cbor;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Cbor;

/// <summary>
/// The signature-structure context selecting clause 5.3.5.3 step 2's context text string — one of the three
/// shapes a CB-AdES signature (or a component protected by an archive/references time-stamp) can be built
/// on, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.3.5.3, step 2</see>. A DU-ready closed sum: no external type may
/// derive from it.
/// </summary>
/// <remarks>
/// <para>
/// Step 2 (verbatim): "Add a context text string, whose value shall be either: 'Signature', if the CB-AdES
/// signature is built on the <c>COSE_Sign</c> structure defined in IETF RFC 9052; or 'Signature1', if the
/// CB-AdES signature is built on the <c>COSE_Sign1</c> structure defined in IETF RFC 9052; or the context
/// text string corresponding to the structure of the CB-AdES signature if it is a counter signature, as
/// specified in clause 3.3 of IETF RFC 9338." <see cref="CBAdESMessageImprints.GetContextText"/> is the
/// switch-expression mapping from an instance of this sum to that text string.
/// </para>
/// <para>
/// <strong>Shared vocabulary.</strong> This type (and its siblings) is <em>shared vocabulary</em> for the
/// CB-AdES message-imprint builders in this file — it has no independent CBOR wire encoding of its own (it
/// never appears as a CDDL production), so it lives beside the builders that consume it
/// (<c>Verifiable.Cbor</c>) rather than beside the COSE-free component models
/// (<c>Verifiable.Cryptography.Pki</c>, wavecb-contract.md ruling R-1(a)).
/// </para>
/// <para>
/// <strong>The countersignature case carries its context string as data, not as a fixed literal.</strong>
/// <see href="https://www.rfc-editor.org/rfc/rfc9338#section-3.3">IETF RFC 9338, clause 3.3</see> defines the
/// context strings for the <c>COSE_Countersignature</c>/<c>COSE_Countersignature0</c> shapes (version 1 and
/// version 2); this stage does not itself model the countersignature structures (wavecb-contract.md stage
/// S6 owns that substrate gap), so <see cref="CBAdESCountersignatureStructureContext"/> simply carries
/// whichever context string the RFC 9338-aware caller resolved, rather than re-deriving it here.
/// </para>
/// </remarks>
public abstract record CBAdESSignatureStructureContext
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESSignatureStructureContext()
    {
    }
}


/// <summary>
/// The <c>COSE_Sign</c> arm of <see cref="CBAdESSignatureStructureContext"/> — step 2's context text is the
/// fixed literal <c>"Signature"</c>. A stateless marker; use <see cref="Instance"/> rather than constructing
/// a new value.
/// </summary>
[DebuggerDisplay("CBAdESCoseSignStructureContext")]
public sealed record CBAdESCoseSignStructureContext: CBAdESSignatureStructureContext
{
    /// <summary>Prevents external construction; use <see cref="Instance"/>.</summary>
    private CBAdESCoseSignStructureContext()
    {
    }


    /// <summary>Gets the single shared instance of this marker.</summary>
    public static CBAdESCoseSignStructureContext Instance { get; } = new();
}


/// <summary>
/// The <c>COSE_Sign1</c> arm of <see cref="CBAdESSignatureStructureContext"/> — step 2's context text is the
/// fixed literal <c>"Signature1"</c>. A stateless marker; use <see cref="Instance"/> rather than constructing
/// a new value.
/// </summary>
/// <remarks>
/// <strong>Leg-3 step-4 trap.</strong> This arm additionally identifies the structure for which clause
/// 5.3.5.3's step 4 (signer-layer protected header) does not exist at all — <c>COSE_Sign1</c> has no signer
/// layer distinct from the body layer (see the <see cref="CBAdESArchiveTimestampImprintContext.SignerProtectedHeader"/>
/// remarks).
/// </remarks>
[DebuggerDisplay("CBAdESCoseSign1StructureContext")]
public sealed record CBAdESCoseSign1StructureContext: CBAdESSignatureStructureContext
{
    /// <summary>Prevents external construction; use <see cref="Instance"/>.</summary>
    private CBAdESCoseSign1StructureContext()
    {
    }


    /// <summary>Gets the single shared instance of this marker.</summary>
    public static CBAdESCoseSign1StructureContext Instance { get; } = new();
}


/// <summary>
/// The counter-signature arm of <see cref="CBAdESSignatureStructureContext"/> — step 2's context text is the
/// <see href="https://www.rfc-editor.org/rfc/rfc9338#section-3.3">IETF RFC 9338, clause 3.3</see> context
/// string for whichever countersignature shape (version 1 or version 2) the caller resolved, carried here as
/// data since this stage does not itself model the countersignature substrate (wavecb-contract.md stage S6).
/// </summary>
/// <param name="ContextText">The RFC 9338 clause 3.3 context text string. Must not be null or empty.</param>
[DebuggerDisplay("CBAdESCountersignatureStructureContext: {ContextText}")]
public sealed record CBAdESCountersignatureStructureContext: CBAdESSignatureStructureContext
{
    /// <summary>
    /// Initializes a new <see cref="CBAdESCountersignatureStructureContext"/>.
    /// </summary>
    /// <param name="contextText">
    /// The RFC 9338 clause 3.3 context text string corresponding to the counter signature's structure.
    /// </param>
    /// <exception cref="ArgumentException"><paramref name="contextText"/> is null or empty.</exception>
    public CBAdESCountersignatureStructureContext(string contextText)
    {
        ArgumentException.ThrowIfNullOrEmpty(contextText);

        ContextText = contextText;
    }


    /// <summary>Gets the RFC 9338 clause 3.3 context text string.</summary>
    public string ContextText { get; }
}


/// <summary>
/// The three-way source union for a CB-AdES message-imprint algorithm's payload contribution — shared
/// vocabulary between the <c>arcTst</c> builder (clause 5.3.5.3, steps 6/7) and the <c>adoTst</c> builder
/// (clause 5.2.6), since both branch identically on "payload attached", "payload detached and
/// unreferenced", or "<c>sigD</c> present with a defined mechanism". A DU-ready closed sum: no external type
/// may derive from it. See <see cref="CBAdESMessageImprints.BuildPayloadTimestampMessageImprintInput"/> and
/// the <c>arcTst</c> builder's remarks for why the two consumers encapsulate each arm differently despite the
/// identical source shape.
/// </summary>
public abstract record CBAdESPayloadImprintSource
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESPayloadImprintSource()
    {
    }
}


/// <summary>
/// The attached-payload arm of <see cref="CBAdESPayloadImprintSource"/>: the COSE Payload field is present,
/// and <see cref="PayloadBytes"/> is its content.
/// </summary>
/// <param name="PayloadBytes">
/// The COSE Payload field's content bytes. <strong>Borrowed</strong> view — the caller owns the underlying
/// memory.
/// </param>
[DebuggerDisplay("CBAdESAttachedPayloadImprintSource: {PayloadBytes.Length} bytes")]
public sealed record CBAdESAttachedPayloadImprintSource(ReadOnlyMemory<byte> PayloadBytes): CBAdESPayloadImprintSource;


/// <summary>
/// The detached-and-unreferenced arm of <see cref="CBAdESPayloadImprintSource"/>: the COSE Payload field is
/// absent, <c>sigD</c> does not reference it, and <see cref="PayloadBytes"/> is the out-of-band-retrieved
/// detached payload (retrieval mechanism out of this document's scope — clause 5.3.5.3 NOTE 1 / clause 5.2.6
/// closing paragraph).
/// </summary>
/// <param name="PayloadBytes">
/// The out-of-band-retrieved detached COSE Payload bytes. <strong>Borrowed</strong> view — the caller owns
/// the underlying memory.
/// </param>
[DebuggerDisplay("CBAdESDetachedPayloadImprintSource: {PayloadBytes.Length} bytes")]
public sealed record CBAdESDetachedPayloadImprintSource(ReadOnlyMemory<byte> PayloadBytes): CBAdESPayloadImprintSource;


/// <summary>
/// The <c>sigD</c>-present arm of <see cref="CBAdESPayloadImprintSource"/>: <see cref="ProcessedParBytes"/> is
/// the ordered sequence of byte views already produced by clause 5.2.8.2.2's <c>pars</c>-processing algorithm
/// (the S3 dereference seam — this type receives its output, it does not itself dereference anything).
/// </summary>
/// <remarks>
/// CB-5.2.8.2.2-05: "the stream of octets... [is] generated by... for each unvisited URI-reference in
/// <c>pars</c>, in order — dereference it..., then concatenate the resulting octets onto the stream." Order
/// is load-bearing (COSE-Payload byte order); <see cref="ProcessedParBytes"/> preserves it.
/// </remarks>
/// <param name="ProcessedParBytes">
/// The ordered, already-dereferenced byte sequences to concatenate. Must be non-empty (CB-5.2.8-06: <c>sigD</c>
/// shall reference one or more detached data objects). Each element is a <strong>borrowed</strong> view.
/// </param>
[DebuggerDisplay("CBAdESSigDProcessedPayloadImprintSource: {ProcessedParBytes.Count} segments")]
public sealed record CBAdESSigDProcessedPayloadImprintSource: CBAdESPayloadImprintSource
{
    /// <summary>
    /// Initializes a new <see cref="CBAdESSigDProcessedPayloadImprintSource"/>.
    /// </summary>
    /// <param name="processedParBytes">The ordered, already-dereferenced byte sequences to concatenate.</param>
    /// <exception cref="ArgumentNullException"><paramref name="processedParBytes"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="processedParBytes"/> is empty.</exception>
    public CBAdESSigDProcessedPayloadImprintSource(IReadOnlyList<ReadOnlyMemory<byte>> processedParBytes)
    {
        ArgumentNullException.ThrowIfNull(processedParBytes);
        if(processedParBytes.Count == 0)
        {
            throw new ArgumentException(
                "sigD shall reference one or more detached data objects, so the processed pars byte sequence " +
                "shall not be empty (ETSI TS 119 152-1 V1.1.1, clause 5.2.8.1, CB-5.2.8-06).",
                nameof(processedParBytes));
        }

        ProcessedParBytes = processedParBytes;
    }


    /// <summary>Gets the ordered, already-dereferenced byte sequences to concatenate.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> ProcessedParBytes { get; }
}


/// <summary>
/// The explicit, per-call parameter set for the <c>arcTst</c> message-imprint input builders (clause
/// 5.3.5.3) — grouped into one context because the algorithm's step count (twelve, plus the two-step
/// validation-time replacement) makes a long flat parameter list unwieldy. No closure capture: every input
/// the algorithm needs travels through this value, never through a captured outer variable.
/// </summary>
/// <remarks>
/// See
/// <see cref="CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput"/> and
/// <see cref="CBAdESMessageImprints.TryBuildArchiveTimestampValidationMessageImprintInput"/> for how each
/// field maps onto a step of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.3.5.3</see>.
/// </remarks>
[DebuggerDisplay("CBAdESArchiveTimestampImprintContext({StructureContext})")]
public readonly record struct CBAdESArchiveTimestampImprintContext
{
    /// <summary>Gets the signature-structure context selecting step 2's context text string.</summary>
    public required CBAdESSignatureStructureContext StructureContext { get; init; }

    /// <summary>
    /// Gets the body layer's protected-header bytes for step 3 — the serialized header map's own content
    /// (never itself bstr-wrapped by the caller; this builder performs that wrapping). An empty value
    /// produces the zero-length CBOR byte string step 3 calls for when "the body layer does not have the
    /// protected header."
    /// </summary>
    public required ReadOnlyMemory<byte> BodyProtectedHeader { get; init; }

    /// <summary>
    /// Gets the signer layer's protected-header bytes for step 4, or <see langword="null"/>.
    /// </summary>
    /// <remarks>
    /// <strong>Leg-3 step-4 trap (recorded reading).</strong> Step 4 begins "If the CB-AdES signature is
    /// built on the <c>COSE_Sign</c> structure, then: ..." with no paired "else if <c>COSE_Sign1</c>" clause
    /// anywhere in the spec text — the only sound reading (preflight leg 3) is that step 4 is skipped in its
    /// entirety for <c>COSE_Sign1</c>, which has no signer layer distinct from the body layer step 3 already
    /// covers. This field's nullability carries that distinction directly: <see langword="null"/> means "step
    /// 4 does not exist for this structure" (<c>COSE_Sign1</c> — contributes zero items to the accumulator
    /// array), while a non-null value — possibly <see cref="ReadOnlyMemory{T}.Empty"/> — means "step 4
    /// executes" (<c>COSE_Sign</c>, which always has a signer layer; an empty value produces the zero-length
    /// byte string step 4 calls for when the signer layer's protected header map is itself absent).
    /// <see cref="CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput"/> rejects a
    /// combination inconsistent with <see cref="StructureContext"/> for the two structures this stage knows
    /// (<c>COSE_Sign</c>/<c>COSE_Sign1</c>); a <see cref="CBAdESCountersignatureStructureContext"/> is not
    /// checked, since this stage does not model countersignature layering (stage S6).
    /// </remarks>
    public ReadOnlyMemory<byte>? SignerProtectedHeader { get; init; }

    /// <summary>
    /// Gets the externally supplied application data for step 5. An empty value produces the zero-length
    /// CBOR byte string step 5 calls for when "no data is externally supplied to the application."
    /// </summary>
    public required ReadOnlyMemory<byte> ExternallySuppliedData { get; init; }

    /// <summary>
    /// Gets the payload contribution for steps 6/7 — always contributes exactly one item to the accumulator
    /// array, whichever arm of <see cref="CBAdESPayloadImprintSource"/> applies.
    /// </summary>
    public required CBAdESPayloadImprintSource PayloadSource { get; init; }

    /// <summary>
    /// Gets the RFC 9338 <c>other_fields</c> CBOR array's already-encoded bytes for step 8, or
    /// <see langword="null"/> when the CB-AdES signature is not built on a version 2 counter signature (step
    /// 8 then contributes nothing at all — there is no placeholder for this step, unlike steps 3-6).
    /// </summary>
    /// <remarks>
    /// <strong>Recorded interpretation (flagged for review).</strong> Step 8's text — "add the
    /// <c>other_fields</c> CBOR array, as defined in clause 3.3 of IETF RFC 9338" — never says "encapsulated
    /// in a CBOR byte string" the way steps 3, 4, 5, 6, 7, and 9 each explicitly do. Read literally, this
    /// value is re-embedded into the accumulator array as the array value it already is (<c>WriteEncodedValue</c>),
    /// not wrapped in an additional byte string (<c>WriteByteString</c>) — a genuine asymmetry with every
    /// other step, not a spec defect, but one this implementation records rather than silently normalizes
    /// away.
    /// </remarks>
    public ReadOnlyMemory<byte>? CountersignatureOtherFields { get; init; }

    /// <summary>
    /// Gets the COSE signature value's raw content bytes for step 9 (the <c>signature</c> field's content,
    /// per <see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.1">IETF RFC 9052, clause 4.1</see> —
    /// never itself bstr-wrapped by the caller; this builder performs that wrapping, matching
    /// <see cref="CBAdESMessageImprints.BuildSignatureTimestampMessageImprintInput"/>'s reading of the same
    /// underlying bytes for <c>sigTst</c>, clause 5.3.3).
    /// </summary>
    public required ReadOnlyMemory<byte> SignatureValue { get; init; }

    /// <summary>
    /// Gets the encoded <c>uHeaders</c> CBOR array bytes for steps 10/11 — the whole
    /// <c>[+bstr .cbor UHeaderInstance]</c> wire array from the layer the caller has already selected
    /// (signer layer under <c>COSE_Sign</c>, body layer under <c>COSE_Sign1</c>, per steps 10/11's own
    /// branching — this builder does not re-derive that layer choice), or <see langword="null"/> when that
    /// layer does not have the <c>uHeaders</c> header parameter at all.
    /// </summary>
    /// <remarks>
    /// <strong>Recorded interpretation of the absent-vs-empty-slice asymmetry (flagged for review).</strong>
    /// Steps 10/11 add a zero-length CBOR byte string only "if [the layer] does not have the <c>uHeaders</c>
    /// header parameter" — i.e. when this field is <see langword="null"/>. When this field is non-null but
    /// the applicable slice (all elements for generation; elements strictly before the <c>arcTst</c> under
    /// validation) happens to be empty — the common case of validating the very first <c>arcTst</c> a
    /// signature ever incorporated — the literal reading contributes <em>zero</em> items to the accumulator
    /// array, not a placeholder, since the "not present" fallback condition genuinely does not hold (the
    /// parameter IS present; it simply yields nothing in this slice). This is a real, non-obvious asymmetry
    /// with steps 3-6 (which always contribute exactly one item, empty or not) and is implemented exactly as
    /// written rather than normalized.
    /// </remarks>
    public ReadOnlyMemory<byte>? UHeadersEncodedArray { get; init; }
}


/// <summary>
/// The four CB-AdES message-imprint-INPUT builders — pure byte-assembly functions that produce the bytes a
/// time-stamp-token request hashes, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see> clauses 5.2.6 (<c>adoTst</c>), 5.3.3 (<c>sigTst</c>), 5.3.5.3 (<c>arcTst</c>),
/// Annex A.1.2.1.2 (<c>sigRTst</c>), and Annex A.1.2.2.2 (<c>rfsTst</c>).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Scope.</strong> These builders assemble bytes; they never hash them (digest computation happens
/// at TSA-request time, in a later stage, via the registered digest delegates — wavecb-contract.md ruling
/// R-2) and they never perform I/O (dereferencing a <c>sigD</c> reference, or an unreferenced detached
/// payload, is an external seam whose output arrives here already as bytes — clause 5.2.8.2.1/5.2.8.2.2, out
/// of scope for this class).
/// </para>
/// <para>
/// <strong>Encode carrier.</strong> Every builder returns a <see cref="PooledMemory"/> rented from the
/// caller-supplied <see cref="BaseMemoryPool"/>, mirroring <see cref="CBAdESSerialization"/>'s own
/// <c>Encode*</c> convention. Outputs that are themselves well-formed CBOR (the <c>arcTst</c>/<c>sigRTst</c>/
/// <c>rfsTst</c> builders, and the <c>adoTst</c> builder's attached/detached arms) carry
/// <see cref="EncodedMessageImprintInputTag"/>; the two arms whose output is a raw, non-CBOR octet stream
/// (the <c>adoTst</c> builder's <c>sigD</c>-present arm, and the trivial <c>sigTst</c> helper) carry
/// <see cref="RawMessageImprintInputTag"/> instead, so CBOM/OTel provenance reflects which shape actually
/// left this class.
/// </para>
/// <para>
/// <strong>D1 (contract R-6): "step 12," not "step 11."</strong> Clause 5.3.5.3's closing sentence names
/// "the CBOR byte string resulting of step 11)" as the message-imprint input, but step 11 (the
/// <c>COSE_Sign1</c> branch of appending <c>uHeaders</c> elements) only appends to the still-open array;
/// step 12 — "Encode the generated CBOR array in a CBOR byte string" — is the only step that actually
/// produces one. Every builder below treats the fully-assembled array's own encoding as the imprint input.
/// </para>
/// <para>
/// <strong>Step-12 reading: no outer <c>bstr</c> item header (recorded interpretation).</strong> "Encode the
/// generated CBOR array in a CBOR byte string" is read as "the message-imprint input IS the encoded array's
/// bytes" — not those bytes prepended with an additional CBOR byte-string item header. Grounds: the bytes
/// are immediately the hash input (no consumer ever unwraps a further <c>bstr</c> layer before hashing), and
/// the COSE precedent is exact — <see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.4">IETF RFC
/// 9052's own <c>ToBeSigned</c></see> is the encoded <c>Sig_structure</c> array, never a <c>bstr</c>-wrapped
/// copy of it. The same reading applies to Annex A.1.2.1.2 step 5 and A.1.2.2.2 step 4, whose wording
/// ("Encode the generated CBOR array in a CBOR byte string") is identical in shape.
/// </para>
/// <para>
/// <strong>Leg-3 step-4 trap and leg-5 trap 4.</strong> See the
/// <see cref="CBAdESArchiveTimestampImprintContext.SignerProtectedHeader"/> remarks for step 4's
/// <c>COSE_Sign</c>-only existence, and
/// <see cref="TryBuildSignatureAndReferencesTimestampMessageImprintInput"/>'s remarks for Annex A.1.2.1.2
/// step 4 / A.1.2.2.2 step 3's stray "signer layer" wording under the <c>COSE_Sign1</c> branch (read as "body
/// layer").
/// </para>
/// <para>
/// <strong>Fail-closed, Try-style, over untrusted <c>uHeaders</c> bytes.</strong> The three builders that
/// walk an encoded <c>uHeaders</c> array (<c>arcTst</c> generation/validation, <c>sigRTst</c>/<c>rfsTst</c>)
/// use the <c>TryBuild*</c> shape and never throw for malformed input (contract R-5) — the walk is an
/// iterative loop over a definite-length CBOR array (no recursive descent), each element read as an opaque,
/// byte-exact <c>bstr</c> item via <see cref="CborReader.ReadEncodedValue"/> (<c>arcTst</c>, which copies
/// every qualifying element unmodified) or unwrapped one level via <see cref="CborReader.ReadByteString"/>
/// plus a nested <see cref="CborReader"/> peek at the inner one-entry map's key (<c>sigRTst</c>/<c>rfsTst</c>,
/// which filter by label before re-wrapping via <see cref="CborWriter.WriteByteString(ReadOnlySpan{byte})"/>)
/// — matching <see cref="CBAdESSerialization.ReadUnsignedHeaderElement"/>'s own established pattern for
/// exactly this "peek one level, dispatch, possibly discard" shape. The two builders that never parse CBOR
/// at all (<c>adoTst</c>, the trivial <c>sigTst</c> helper) have no failure mode to report and are plain,
/// non-<c>Try</c> methods.
/// </para>
/// </remarks>
public static class CBAdESMessageImprints
{
    /// <summary>
    /// Gets the <see cref="Tag"/> stamped on a message-imprint-input <see cref="PooledMemory"/> whose bytes
    /// are themselves well-formed CBOR (the <c>arcTst</c>/<c>sigRTst</c>/<c>rfsTst</c> builders' output, and
    /// the <c>adoTst</c> builder's attached/detached arms).
    /// </summary>
    private static Tag EncodedMessageImprintInputTag { get; } = Tag.Create(Purpose.Data).With(EncodingScheme.Cose);

    /// <summary>
    /// Gets the <see cref="Tag"/> stamped on a message-imprint-input <see cref="PooledMemory"/> whose bytes
    /// are a raw, non-CBOR octet stream (the <c>adoTst</c> builder's <c>sigD</c>-present arm, per CB-5.2.6-06's
    /// recorded reading, and the trivial <c>sigTst</c> helper's raw signature bytes).
    /// </summary>
    private static Tag RawMessageImprintInputTag { get; } = Tag.Create(Purpose.Data).With(EncodingScheme.Raw);


    /// <summary>
    /// Determines whether <paramref name="exception"/> represents malformed or non-conformant untrusted
    /// <c>uHeaders</c> bytes that every <c>TryBuild*</c> method in this class catches to fail closed, per
    /// contract R-5 (strict conformance; parsing never throws for malformed input) — mirroring
    /// <see cref="CBAdESSerialization"/>'s own classifier (duplicated here rather than shared, since that
    /// classifier is private to its class and this file's scope does not extend to editing it).
    /// </summary>
    /// <param name="exception">The exception to classify.</param>
    /// <returns><see langword="true"/> when the exception should be swallowed and reported as a build failure.</returns>
    private static bool IsFailClosedParseException(Exception exception) =>
        exception is CborContentException or InvalidOperationException or ArgumentException
            or IndexOutOfRangeException or OverflowException or FormatException;


    /// <summary>
    /// Maps a <see cref="CBAdESSignatureStructureContext"/> to clause 5.3.5.3 step 2's context text string.
    /// </summary>
    /// <param name="context">The signature-structure context.</param>
    /// <returns>The context text string.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
    /// <exception cref="NotSupportedException"><paramref name="context"/> is an unknown arm.</exception>
    public static string GetContextText(CBAdESSignatureStructureContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context switch
        {
            CBAdESCoseSignStructureContext => "Signature",
            CBAdESCoseSign1StructureContext => "Signature1",
            CBAdESCountersignatureStructureContext countersignature => countersignature.ContextText,
            _ => throw new NotSupportedException($"Unknown signature-structure context arm '{context.GetType()}'.")
        };
    }


    /// <summary>
    /// Builds the trivial <c>sigTst</c> message-imprint input (clause 5.3.3): the COSE signature value's raw
    /// content bytes, unwrapped and unconcatenated. Exposed as its own method so a later stage composes it
    /// rather than reaching into this class's internals.
    /// </summary>
    /// <remarks>
    /// CB-5.3.3-02 (recorded reading): "The input of the message imprint computation for the time-stamp
    /// tokens encapsulated by <c>sigTst</c> CBOR map shall be the COSE signature value present within the
    /// CB-AdES signature" — read literally as the <c>signature</c> field's content bytes themselves (IETF RFC
    /// 9052, clause 4.1), with no concatenation algorithm and no additional CBOR encoding of any kind, in
    /// contrast with <c>arcTst</c>'s 12-step concatenation (clause 5.3.5.3, this class's
    /// <see cref="TryBuildArchiveTimestampGenerationMessageImprintInput"/>/
    /// <see cref="TryBuildArchiveTimestampValidationMessageImprintInput"/>).
    /// </remarks>
    /// <param name="signatureValue">The COSE signature value's raw content bytes.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented carrier for the message-imprint input.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is null.</exception>
    public static PooledMemory BuildSignatureTimestampMessageImprintInput(ReadOnlyMemory<byte> signatureValue, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return PooledMemory.FromBytes(signatureValue.Span, pool, RawMessageImprintInputTag);
    }


    /// <summary>
    /// Builds the <c>arcTst</c> message-imprint input in generation mode (clause 5.3.5.3, all twelve steps,
    /// steps 10/11 over every element currently in <see cref="CBAdESArchiveTimestampImprintContext.UHeadersEncodedArray"/>).
    /// </summary>
    /// <param name="context">The algorithm's explicit inputs (steps 1-9).</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <param name="result">The message-imprint input on success; <see langword="null"/> on failure.</param>
    /// <returns>
    /// <see langword="true"/> on success; <see langword="false"/> when <see cref="CBAdESArchiveTimestampImprintContext.UHeadersEncodedArray"/>
    /// is present but malformed or non-conformant (never throws for that case — contract R-5).
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <see cref="CBAdESArchiveTimestampImprintContext.StructureContext"/>,
    /// <see cref="CBAdESArchiveTimestampImprintContext.PayloadSource"/>, or <paramref name="pool"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <see cref="CBAdESArchiveTimestampImprintContext.SignerProtectedHeader"/>'s presence is inconsistent
    /// with <see cref="CBAdESArchiveTimestampImprintContext.StructureContext"/> for the two structures this
    /// stage checks (<c>COSE_Sign</c>/<c>COSE_Sign1</c> — see the field's remarks).
    /// </exception>
    /// <remarks>
    /// See
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.3.5.3</see>, and this class's remarks for D1 and the step-12 reading.
    /// </remarks>
    public static bool TryBuildArchiveTimestampGenerationMessageImprintInput(
        CBAdESArchiveTimestampImprintContext context,
        BaseMemoryPool pool,
        out PooledMemory? result) =>
        TryBuildArchiveTimestampMessageImprintInputCore(context, uHeadersSliceBound: null, pool, out result);


    /// <summary>
    /// Builds the <c>arcTst</c> message-imprint input in validation mode (clause 5.3.5.3, steps 10/11 replaced:
    /// only the <c>uHeaders</c> elements strictly before the <c>arcTst</c> under validation contribute).
    /// </summary>
    /// <param name="context">The algorithm's explicit inputs (steps 1-9).</param>
    /// <param name="arcTstElementIndex">
    /// The zero-based position, within <see cref="CBAdESArchiveTimestampImprintContext.UHeadersEncodedArray"/>,
    /// of the <c>arcTst</c> element under validation. Elements at positions <c>0</c> through
    /// <c>arcTstElementIndex - 1</c> contribute; matches
    /// <see cref="CBAdESUnsignedHeaders.ElementsBefore(int)"/>'s own exclusive-upper-bound convention on the
    /// decoded model side.
    /// </param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <param name="result">The message-imprint input on success; <see langword="null"/> on failure.</param>
    /// <returns>
    /// <see langword="true"/> on success; <see langword="false"/> when <see cref="CBAdESArchiveTimestampImprintContext.UHeadersEncodedArray"/>
    /// is present but malformed or non-conformant (never throws for that case — contract R-5).
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <see cref="CBAdESArchiveTimestampImprintContext.StructureContext"/>,
    /// <see cref="CBAdESArchiveTimestampImprintContext.PayloadSource"/>, or <paramref name="pool"/> is null.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="arcTstElementIndex"/> is negative.</exception>
    /// <exception cref="ArgumentException">
    /// <see cref="CBAdESArchiveTimestampImprintContext.SignerProtectedHeader"/>'s presence is inconsistent
    /// with <see cref="CBAdESArchiveTimestampImprintContext.StructureContext"/> for the two structures this
    /// stage checks (<c>COSE_Sign</c>/<c>COSE_Sign1</c> — see the field's remarks).
    /// </exception>
    /// <remarks>
    /// See the <see cref="CBAdESArchiveTimestampImprintContext.UHeadersEncodedArray"/> remarks for the
    /// recorded absent-vs-empty-slice reading this validation variant exercises whenever
    /// <paramref name="arcTstElementIndex"/> is <c>0</c>.
    /// </remarks>
    public static bool TryBuildArchiveTimestampValidationMessageImprintInput(
        CBAdESArchiveTimestampImprintContext context,
        int arcTstElementIndex,
        BaseMemoryPool pool,
        out PooledMemory? result)
    {
        if(arcTstElementIndex < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(arcTstElementIndex),
                arcTstElementIndex,
                "The arcTst element index shall not be negative (ETSI TS 119 152-1 V1.1.1, clause 5.3.5.3, validation-time variant).");
        }

        return TryBuildArchiveTimestampMessageImprintInputCore(context, arcTstElementIndex, pool, out result);
    }


    /// <summary>
    /// The shared core behind <see cref="TryBuildArchiveTimestampGenerationMessageImprintInput"/> and
    /// <see cref="TryBuildArchiveTimestampValidationMessageImprintInput"/> — the twelve-step clause 5.3.5.3
    /// algorithm, with the <c>uHeaders</c> slice boundary (steps 10/11) as an explicit parameter distinguishing
    /// the two call modes (leg-3 implication).
    /// </summary>
    /// <param name="context">The algorithm's explicit inputs (steps 1-9).</param>
    /// <param name="uHeadersSliceBound">
    /// <see langword="null"/> for the generation-time variant (all elements); otherwise the exclusive upper
    /// bound (element count to take from the start of the array) for the validation-time variant.
    /// </param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <param name="result">The message-imprint input on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; <see langword="false"/> on malformed <c>uHeaders</c> bytes.</returns>
    /// <remarks>
    /// Fails closed (returns <see langword="false"/>) when
    /// <see cref="CBAdESArchiveTimestampImprintContext.UHeadersEncodedArray"/> is present but either the array
    /// itself is empty (a present <c>uHeaders</c> shall be non-empty, CB-5.3.1-07) or any element is not itself
    /// a CBOR byte string (every element shall be <c>[+bstr .cbor UHeaderInstance]</c>, CB-5.3.1-04).
    /// </remarks>
    private static bool TryBuildArchiveTimestampMessageImprintInputCore(
        CBAdESArchiveTimestampImprintContext context,
        int? uHeadersSliceBound,
        BaseMemoryPool pool,
        out PooledMemory? result)
    {
        ArgumentNullException.ThrowIfNull(context.StructureContext);
        ArgumentNullException.ThrowIfNull(context.PayloadSource);
        ArgumentNullException.ThrowIfNull(pool);

        if(context.StructureContext is CBAdESCoseSign1StructureContext && context.SignerProtectedHeader.HasValue)
        {
            throw new ArgumentException(
                "COSE_Sign1 has no signer layer; step 4 of clause 5.3.5.3 does not exist for this structure " +
                "(preflight leg 3 step-4 trap), so SignerProtectedHeader shall be null.",
                nameof(context));
        }

        if(context.StructureContext is CBAdESCoseSignStructureContext && !context.SignerProtectedHeader.HasValue)
        {
            throw new ArgumentException(
                "COSE_Sign always has a signer layer; step 4 of clause 5.3.5.3 always executes for this " +
                "structure (adding the header, or a zero-length byte string when absent), so " +
                "SignerProtectedHeader shall not be null.",
                nameof(context));
        }

        try
        {
            List<ReadOnlyMemory<byte>>? uHeadersItems = null;
            if(context.UHeadersEncodedArray.HasValue)
            {
                var uHeadersReader = new CborReader(context.UHeadersEncodedArray.Value, CborConformanceMode.Canonical);
                int elementCount = uHeadersReader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
                int itemsToTake = uHeadersSliceBound.HasValue ? Math.Min(uHeadersSliceBound.Value, elementCount) : elementCount;

                var items = new List<ReadOnlyMemory<byte>>(Math.Min(itemsToTake, 64));
                for(int i = 0; i < elementCount; ++i)
                {
                    //Every uHeaders array element shall be a bstr-wrapped UHeaderInstance ([+bstr .cbor
                    //UHeaderInstance], CB-5.3.1-04); reject anything else fail-closed rather than letting a
                    //non-bstr element pass through the take or skip path unchecked.
                    if(uHeadersReader.PeekState() != CborReaderState.ByteString)
                    {
                        throw new CborContentException(
                            "A uHeaders array element shall be a CBOR byte string wrapping a UHeaderInstance " +
                            "(ETSI TS 119 152-1 V1.1.1, clause 5.3.1, CB-5.3.1-04).");
                    }

                    if(i < itemsToTake)
                    {
                        items.Add(uHeadersReader.ReadEncodedValue());
                    }
                    else
                    {
                        uHeadersReader.SkipValue();
                    }
                }

                uHeadersReader.ReadEndArray();
                if(uHeadersReader.BytesRemaining != 0)
                {
                    result = null;
                    return false;
                }

                uHeadersItems = items;
            }

            int uHeadersContribution = uHeadersItems is not null ? uHeadersItems.Count : 1;
            int totalCount = 1                                          //step 2: context text.
                + 1                                                     //step 3: body-layer protected header.
                + (context.SignerProtectedHeader.HasValue ? 1 : 0)      //step 4: signer-layer protected header (COSE_Sign only).
                + 1                                                     //step 5: externally supplied data.
                + 1                                                     //steps 6/7: payload branch, exactly one item.
                + (context.CountersignatureOtherFields.HasValue ? 1 : 0) //step 8: RFC 9338 other_fields (v2 countersignature only).
                + 1                                                     //step 9: signature value.
                + uHeadersContribution;                                  //steps 10/11: uHeaders elements (or the absent-parameter placeholder).

            var writer = new CborWriter(CborConformanceMode.Canonical);
            writer.WriteStartArray(totalCount);

            writer.WriteTextString(GetContextText(context.StructureContext));
            writer.WriteByteString(context.BodyProtectedHeader.Span);

            if(context.SignerProtectedHeader.HasValue)
            {
                writer.WriteByteString(context.SignerProtectedHeader.Value.Span);
            }

            writer.WriteByteString(context.ExternallySuppliedData.Span);

            WritePayloadContribution(writer, context.PayloadSource);

            if(context.CountersignatureOtherFields.HasValue)
            {
                writer.WriteEncodedValue(context.CountersignatureOtherFields.Value.Span);
            }

            writer.WriteByteString(context.SignatureValue.Span);

            if(uHeadersItems is not null)
            {
                foreach(ReadOnlyMemory<byte> item in uHeadersItems)
                {
                    writer.WriteEncodedValue(item.Span);
                }
            }
            else
            {
                writer.WriteByteString(ReadOnlySpan<byte>.Empty);
            }

            writer.WriteEndArray();

            result = PooledMemory.FromBytes(writer.Encode(), pool, EncodedMessageImprintInputTag);
            return true;
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            result = null;
            return false;
        }

        static void WritePayloadContribution(CborWriter writer, CBAdESPayloadImprintSource source)
        {
            _ = source switch
            {
                CBAdESAttachedPayloadImprintSource attached => WriteWrapped(writer, attached.PayloadBytes),
                CBAdESDetachedPayloadImprintSource detached => WriteWrapped(writer, detached.PayloadBytes),
                CBAdESSigDProcessedPayloadImprintSource sigD => WriteWrapped(writer, ConcatenateSegments(sigD.ProcessedParBytes)),
                _ => throw new NotSupportedException($"Unknown payload-source arm '{source.GetType()}'.")
            };

            static bool WriteWrapped(CborWriter writer, ReadOnlyMemory<byte> bytes)
            {
                writer.WriteByteString(bytes.Span);
                return true;
            }
        }
    }


    /// <summary>
    /// Builds the <c>adoTst</c> message-imprint input (clause 5.2.6): an octet stream, not necessarily itself
    /// a single CBOR value — see the arm-by-arm remarks below for the CB-5.2.6-06 reading.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Clause 5.2.6: "The message imprint computation input for the time-stamp token shall be an octet
    /// stream built as indicated below." Unlike the <c>arcTst</c>/<c>sigRTst</c>/<c>rfsTst</c> builders, this
    /// octet stream is never itself embedded as one element of a larger accumulator array, so each arm's
    /// encapsulation is exactly what clause 5.2.6 says for that arm, with no further wrapping:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <see cref="CBAdESAttachedPayloadImprintSource"/>/<see cref="CBAdESDetachedPayloadImprintSource"/>
    /// (CB-5.2.6-05): "The CBOR byte string of the <c>payload</c> field, if present" / "the bytes of the
    /// detached COSE Payload, encapsulated in a CBOR byte string" — both wrapped in one CBOR byte string; the
    /// wrapped item's own encoded bytes ARE the octet stream.
    /// </description></item>
    /// <item><description>
    /// <see cref="CBAdESSigDProcessedPayloadImprintSource"/> (CB-5.2.6-06, recorded reading): "concatenate the
    /// bytes resulting from processing the contents of its <c>pars</c> member..." — this sentence, unlike the
    /// branch above, never says "encapsulate... in a CBOR byte string." Read literally: the octet stream is
    /// the raw concatenation, with NO CBOR byte-string wrapping at all — in contrast with <c>arcTst</c>'s own
    /// step 7, which explicitly wraps the identical concatenation ("concatenate them, encapsulate them in a
    /// CBOR byte string, and add this CBOR byte string"). This is a genuine, deliberate-reading asymmetry
    /// between the two algorithms over the same underlying <c>sigD</c> mechanism, recorded here rather than
    /// silently harmonized. The accompanying NOTE explains the rationale independent of the encapsulation
    /// question: <c>ObjectIdByURIHash</c> still time-stamps the retrieved objects, not their digests, "to
    /// protect against future weaknesses of the digest algorithms used in <c>sigD</c>."
    /// </description></item>
    /// </list>
    /// <para>
    /// Third-party <c>sigD.mId</c> mechanisms (CB-5.2.6-07) are out of scope: this method's source union takes
    /// already-processed bytes regardless of which mechanism produced them, keeping that dispatch seam open
    /// for a later stage.
    /// </para>
    /// </remarks>
    /// <param name="source">The three-way payload contribution source.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <returns>The pool-rented carrier for the message-imprint input.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="source"/> or <paramref name="pool"/> is null.</exception>
    /// <exception cref="NotSupportedException"><paramref name="source"/> is an unknown arm.</exception>
    public static PooledMemory BuildPayloadTimestampMessageImprintInput(CBAdESPayloadImprintSource source, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(pool);

        return source switch
        {
            CBAdESAttachedPayloadImprintSource attached => EncodeWrappedByteString(attached.PayloadBytes, pool),
            CBAdESDetachedPayloadImprintSource detached => EncodeWrappedByteString(detached.PayloadBytes, pool),
            CBAdESSigDProcessedPayloadImprintSource sigD =>
                PooledMemory.FromBytes(ConcatenateSegments(sigD.ProcessedParBytes).Span, pool, RawMessageImprintInputTag),
            _ => throw new NotSupportedException($"Unknown payload-source arm '{source.GetType()}'.")
        };

        static PooledMemory EncodeWrappedByteString(ReadOnlyMemory<byte> bytes, BaseMemoryPool pool)
        {
            var writer = new CborWriter(CborConformanceMode.Canonical);
            writer.WriteByteString(bytes.Span);

            return PooledMemory.FromBytes(writer.Encode(), pool, EncodedMessageImprintInputTag);
        }
    }


    /// <summary>
    /// Builds the <c>sigRTst</c> message-imprint input (Annex A.1.2.1.2): the COSE signature value, followed
    /// by the <c>sigTst</c>/<c>refs</c> elements from <paramref name="uHeadersEncodedArray"/>, in wire order.
    /// </summary>
    /// <param name="signatureValue">The COSE signature value's raw content bytes (step 2).</param>
    /// <param name="uHeadersEncodedArray">
    /// The encoded <c>uHeaders</c> CBOR array bytes from the layer the caller has already selected (signer
    /// layer under <c>COSE_Sign</c>, body layer under <c>COSE_Sign1</c> — see this method's remarks for the
    /// leg-5 trap 4 reading), or <see langword="null"/> when that layer does not have the <c>uHeaders</c>
    /// header parameter (steps 3/4).
    /// </param>
    /// <param name="uHeadersSliceBound">
    /// <see langword="null"/> for the generation-time call (every element that precedes this <c>sigRTst</c>
    /// instance in wire order — which, at generation time, is EVERY element already present, since the new
    /// instance is about to be appended after them); otherwise the exclusive upper bound (element count to
    /// take from the start of <paramref name="uHeadersEncodedArray"/>) for the validation-time call, mirroring
    /// <see cref="TryBuildArchiveTimestampMessageImprintInputCore"/>'s <c>uHeadersSliceBound</c>
    /// precedent exactly. See the class remarks' D15 citation below for why this parameter exists.
    /// </param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <param name="result">The message-imprint input on success; <see langword="null"/> on failure.</param>
    /// <returns>
    /// <see langword="true"/> on success; <see langword="false"/> when <paramref name="uHeadersEncodedArray"/>
    /// is present but malformed or non-conformant, or <paramref name="uHeadersSliceBound"/> is negative (never
    /// throws for either case — contract R-5).
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is null.</exception>
    /// <remarks>
    /// <para>
    /// See
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, Annex A.1.2.1.2</see>. CB-A.1.2.1-03: this method does not itself gate on
    /// <c>refs</c> being present before generation — that precondition ("if the component <c>refs</c> is not
    /// present, the <c>sigRTst</c> CBOR map shall not be generated") is owned by the creation-path orchestrator
    /// that decides whether to call this method at all, not by the byte-assembly step itself.
    /// </para>
    /// <para>
    /// <strong>D15 (wavecb-contract.md R-6, added at S4 review, RULED).</strong> Annex A.1.2.1.2 lacks the
    /// explicit validation-time prefix replacement clause 5.3.5.3 gives <c>arcTst</c> (its steps 10/11
    /// "elements that precede..."). A repeated <c>sigTst</c> instance appended AFTER a <c>sigRTst</c> is legal
    /// (Table 14 note 7); reading this step over the FULL final <c>uHeaders</c> array at validation time would
    /// then make validation compute a different imprint than the one the Time-Stamping Authority actually
    /// attested at generation — a false <c>ImprintMismatch</c> on a conformant signature. RULED by analogy with
    /// 5.3.5.3's own validation variant: the message-imprint input for a SPECIFIC <c>sigRTst</c> instance — at
    /// generation and validation alike — is built from only the <c>uHeaders</c> elements that precede that
    /// instance's own position. <paramref name="uHeadersSliceBound"/> is this reading's mechanism.
    /// </para>
    /// <para>
    /// <strong>Leg-5 trap 4 (recorded reading).</strong> Step 4's text says "take those elements in the
    /// <c>uHeaders</c> header parameter from the body layer... If the <em>signer</em> layer does not have any
    /// of those <c>uHeaders</c> header parameters, add a zero-length CBOR byte string" — the "signer layer"
    /// in that second sentence is almost certainly a copy-paste leftover from the preceding <c>COSE_Sign</c>
    /// step (step 3), since <c>COSE_Sign1</c> has no signer layer at all. Read as "body layer" throughout.
    /// </para>
    /// <para>
    /// <strong>Filter reading.</strong> "Take those elements in the <c>uHeaders</c> header parameter... in
    /// the order that they appear within <c>uHeaders</c>, and add them to the CBOR array: <c>sigTst</c> if it
    /// is present; <c>refs</c> if it is present" is read as a filter over <c>uHeaders</c>'s wire order (keep
    /// only the elements whose inner one-entry <c>UHeaderInstance</c> map key is the <c>sigTst</c> label
    /// (<see cref="CBAdESUnsignedHeaderElement.SignatureTimestampLabel"/>, <c>1</c>) or the <c>refs</c> label
    /// (<see cref="CBAdESUnsignedHeaderElement.ReferencesLabel"/>, <c>4</c>), preserving whichever of the two
    /// happens to appear first) — not a fixed "<c>sigTst</c> always precedes <c>refs</c>" rule, applied over
    /// only the prefix <paramref name="uHeadersSliceBound"/> selects (D15). When the
    /// filtered result is empty (whether because <paramref name="uHeadersEncodedArray"/> is
    /// <see langword="null"/>, or present but contains neither label within the selected prefix — both read as
    /// "the layer does not have any of those <c>uHeaders</c> header parameters"), exactly one zero-length CBOR
    /// byte string is added — unlike the <c>arcTst</c> builder's own absent-vs-empty-slice asymmetry (see
    /// <see cref="CBAdESArchiveTimestampImprintContext.UHeadersEncodedArray"/>), these two conditions collapse
    /// to the same outcome here.
    /// </para>
    /// </remarks>
    public static bool TryBuildSignatureAndReferencesTimestampMessageImprintInput(
        ReadOnlyMemory<byte> signatureValue,
        ReadOnlyMemory<byte>? uHeadersEncodedArray,
        int? uHeadersSliceBound,
        BaseMemoryPool pool,
        out PooledMemory? result) =>
        TryBuildReferencesFamilyMessageImprintInputCore(includeSignatureValue: true, signatureValue, uHeadersEncodedArray, uHeadersSliceBound, pool, out result);


    /// <summary>
    /// Builds the <c>rfsTst</c> message-imprint input (Annex A.1.2.2.2): identical to
    /// <see cref="TryBuildSignatureAndReferencesTimestampMessageImprintInput"/> minus the leading signature
    /// value.
    /// </summary>
    /// <param name="uHeadersEncodedArray">
    /// The encoded <c>uHeaders</c> CBOR array bytes from the layer the caller has already selected, or
    /// <see langword="null"/> when that layer does not have the <c>uHeaders</c> header parameter. See
    /// <see cref="TryBuildSignatureAndReferencesTimestampMessageImprintInput"/>'s remarks for the leg-5 trap
    /// 4 and filter readings, both identical here.
    /// </param>
    /// <param name="uHeadersSliceBound">
    /// <see langword="null"/> for the generation-time call; otherwise the exclusive upper bound (element count
    /// to take from the start of <paramref name="uHeadersEncodedArray"/>) for the validation-time call. See
    /// <see cref="TryBuildSignatureAndReferencesTimestampMessageImprintInput"/>'s D15 remarks, identical here
    /// for Annex A.1.2.2.2.
    /// </param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <param name="result">The message-imprint input on success; <see langword="null"/> on failure.</param>
    /// <returns>
    /// <see langword="true"/> on success; <see langword="false"/> when <paramref name="uHeadersEncodedArray"/>
    /// is present but malformed or non-conformant, or <paramref name="uHeadersSliceBound"/> is negative (never
    /// throws for either case — contract R-5).
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is null.</exception>
    /// <remarks>
    /// See
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, Annex A.1.2.2.2</see>. CB-A.1.2.2-03: same generation-gate deferral as
    /// <see cref="TryBuildSignatureAndReferencesTimestampMessageImprintInput"/>'s CB-A.1.2.1-03 remark. D15
    /// (wavecb-contract.md R-6): same validation-time prefix-replacement ruling, identical rationale.
    /// </remarks>
    public static bool TryBuildReferencesOnlyTimestampMessageImprintInput(
        ReadOnlyMemory<byte>? uHeadersEncodedArray,
        int? uHeadersSliceBound,
        BaseMemoryPool pool,
        out PooledMemory? result) =>
        TryBuildReferencesFamilyMessageImprintInputCore(includeSignatureValue: false, default, uHeadersEncodedArray, uHeadersSliceBound, pool, out result);


    /// <summary>
    /// The shared core behind <see cref="TryBuildSignatureAndReferencesTimestampMessageImprintInput"/> and
    /// <see cref="TryBuildReferencesOnlyTimestampMessageImprintInput"/> — Annex A.1.2.1.2 and A.1.2.2.2 are
    /// identical except for the leading signature-value element (leg-5 implication: one shared core with an
    /// include-signature-value parameter).
    /// </summary>
    /// <param name="includeSignatureValue">
    /// <see langword="true"/> to prepend <paramref name="signatureValue"/> (Annex A.1.2.1.2, <c>sigRTst</c>);
    /// <see langword="false"/> to omit it entirely (Annex A.1.2.2.2, <c>rfsTst</c>).
    /// </param>
    /// <param name="signatureValue">
    /// The COSE signature value's raw content bytes. Ignored when <paramref name="includeSignatureValue"/> is
    /// <see langword="false"/>.
    /// </param>
    /// <param name="uHeadersEncodedArray">The encoded <c>uHeaders</c> CBOR array bytes, or <see langword="null"/>.</param>
    /// <param name="uHeadersSliceBound">
    /// <see langword="null"/> to filter over every element of <paramref name="uHeadersEncodedArray"/>
    /// (generation time); otherwise the exclusive upper bound (element count to take from the array's start)
    /// the filter runs over, mirroring <see cref="TryBuildArchiveTimestampMessageImprintInputCore"/>'s
    /// <c>uHeadersSliceBound</c> precedent exactly (D15, wavecb-contract.md R-6).
    /// </param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <param name="result">The message-imprint input on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; <see langword="false"/> on malformed <c>uHeaders</c> bytes, or a negative <paramref name="uHeadersSliceBound"/>.</returns>
    /// <remarks>
    /// Fails closed (returns <see langword="false"/>) when <paramref name="uHeadersEncodedArray"/> is present
    /// but empty — a present <c>uHeaders</c> shall be non-empty (CB-5.3.1-07) — or when
    /// <paramref name="uHeadersSliceBound"/> is negative.
    /// </remarks>
    private static bool TryBuildReferencesFamilyMessageImprintInputCore(
        bool includeSignatureValue,
        ReadOnlyMemory<byte> signatureValue,
        ReadOnlyMemory<byte>? uHeadersEncodedArray,
        int? uHeadersSliceBound,
        BaseMemoryPool pool,
        out PooledMemory? result)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(uHeadersSliceBound is { } negativeCheck && negativeCheck < 0)
        {
            result = null;
            return false;
        }

        try
        {
            List<byte[]>? filteredElements = null;
            if(uHeadersEncodedArray.HasValue)
            {
                var uHeadersReader = new CborReader(uHeadersEncodedArray.Value, CborConformanceMode.Canonical);
                int elementCount = uHeadersReader.ReadStartArrayExpectLengthRange(1, int.MaxValue);
                int itemsToConsider = uHeadersSliceBound.HasValue ? Math.Min(uHeadersSliceBound.Value, elementCount) : elementCount;

                var items = new List<byte[]>(Math.Min(elementCount, 64));
                for(int i = 0; i < elementCount; ++i)
                {
                    byte[] elementContent = uHeadersReader.ReadByteString();

                    //D15: only elements strictly before the specific sigRTst/rfsTst instance's own position
                    //contribute -- elements at or after uHeadersSliceBound are read off the wire (to stay
                    //positioned correctly) but never offered to the filter.
                    if(i < itemsToConsider && IsSigTstOrRefsElement(elementContent))
                    {
                        items.Add(elementContent);
                    }
                }

                uHeadersReader.ReadEndArray();
                if(uHeadersReader.BytesRemaining != 0)
                {
                    result = null;
                    return false;
                }

                filteredElements = items;
            }

            int filteredCount = filteredElements is not null ? filteredElements.Count : 0;
            int totalCount = (includeSignatureValue ? 1 : 0) + (filteredCount > 0 ? filteredCount : 1);

            var writer = new CborWriter(CborConformanceMode.Canonical);
            writer.WriteStartArray(totalCount);

            if(includeSignatureValue)
            {
                writer.WriteByteString(signatureValue.Span);
            }

            if(filteredCount > 0)
            {
                foreach(byte[] elementContent in filteredElements!)
                {
                    writer.WriteByteString(elementContent);
                }
            }
            else
            {
                writer.WriteByteString(ReadOnlySpan<byte>.Empty);
            }

            writer.WriteEndArray();

            result = PooledMemory.FromBytes(writer.Encode(), pool, EncodedMessageImprintInputTag);
            return true;
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            result = null;
            return false;
        }

        static bool IsSigTstOrRefsElement(byte[] elementContent)
        {
            var innerReader = new CborReader(elementContent, CborConformanceMode.Canonical);
            _ = innerReader.ReadStartMapExpectLength(1);
            if(innerReader.PeekState() == CborReaderState.TextString)
            {
                return false;
            }

            int label = innerReader.ReadInt32();
            return label == CBAdESUnsignedHeaderElement.SignatureTimestampLabel || label == CBAdESUnsignedHeaderElement.ReferencesLabel;
        }
    }


    /// <summary>
    /// Concatenates an ordered sequence of byte views into one contiguous buffer, preserving order — the
    /// shared implementation behind the <c>sigD</c>-processed arm of both the <c>arcTst</c> builder (which
    /// additionally wraps the result in a CBOR byte string) and the <c>adoTst</c> builder (which does not —
    /// see <see cref="BuildPayloadTimestampMessageImprintInput"/>'s CB-5.2.6-06 remarks).
    /// </summary>
    /// <param name="segments">The ordered byte views to concatenate.</param>
    /// <returns>A newly allocated buffer holding every segment's bytes, in order.</returns>
    private static ReadOnlyMemory<byte> ConcatenateSegments(IReadOnlyList<ReadOnlyMemory<byte>> segments)
    {
        int totalLength = 0;
        for(int i = 0; i < segments.Count; ++i)
        {
            totalLength += segments[i].Length;
        }

        byte[] buffer = new byte[totalLength];
        int offset = 0;
        for(int i = 0; i < segments.Count; ++i)
        {
            segments[i].Span.CopyTo(buffer.AsSpan(offset));
            offset += segments[i].Length;
        }

        return buffer;
    }
}
