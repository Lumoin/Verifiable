using System.Diagnostics;

namespace Verifiable.JCose;

//The CB-AdES message-imprint-INPUT seam delegates: the shapes the augmentation and
//validation orchestrators consume, implemented as thin adapters in Verifiable.Cbor over the shipped
//CBAdESMessageImprints builders. Verifiable.JCose cannot reference Verifiable.Cbor -- the reference
//graph runs the other way (Verifiable.Cbor -> Verifiable.JCose -> Verifiable.Cryptography) -- so every
//byte-assembly operation these orchestrators need crosses one of these three seams, mirroring
//CBAdESSerializationDelegates.cs's shape and registration mechanism (a delegate TYPE declared here,
//implemented as a public static getter property of that delegate type in Verifiable.Cbor). A fourth
//seam, TryBuildArchiveTimestampValidationMessageImprintInputDelegate, covers the arcTst validation-time
//imprint (clause 5.3.5.3's twelve-step algorithm, prefix-bounded to each instance's own position), and a fifth,
//TryBuildArchiveTimestampGenerationMessageImprintInputDelegate, covers the arcTst generation-time imprint the
//AddArchiveTimestampAsync verb consumes (5.3.5.2 steps 2-5) -- identical shape to its validation sibling minus
//the arcTst instance's own position, since generation always covers every uHeaders element already present.
//Both arcTst imprint-input delegates are un-pinned from their former
//COSE_Sign1-only assumption: the two delegates below gain a structure-context/signer-layer-header/RFC 9338
//other_fields parameter trio the imprint core (CBAdESArchiveTimestampImprintContext, Verifiable.Cbor) already
//accepted, so a caller now supplies these three facts explicitly rather than the Cbor-side adapter
//hardcoding CBAdESCoseSign1StructureContext.Instance/null/null.

/// <summary>
/// The JCose-visible mirror of <c>Verifiable.Cbor.CBAdESSignatureStructureContext</c> (clause 5.3.5.3 step 2's
/// context-text selector) — needed because that Cbor-only closed sum cannot appear in a JCose delegate's public
/// signature (Verifiable.JCose cannot reference Verifiable.Cbor). The Cbor-side adapter
/// (<c>CBAdESLevelMessageImprintAdapters.ToCborStructureContext</c>) translates one arm of THIS type into the
/// matching arm of the Cbor-only type before delegating into <c>CBAdESMessageImprints</c> — a structural
/// translation only, mirroring <see cref="CBAdESPayloadTimestampImprintSource"/>'s own precedent for the
/// payload-source union. A DU-ready closed sum: no external type may derive from it.
/// </summary>
public abstract record CBAdESImprintStructureContext
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESImprintStructureContext()
    {
    }
}


/// <summary>
/// The <c>COSE_Sign</c> arm of <see cref="CBAdESImprintStructureContext"/> — step 2's context text is the fixed
/// literal <c>"Signature"</c>. A stateless marker; use <see cref="Instance"/> rather than constructing a new
/// value.
/// </summary>
public sealed record CBAdESImprintCoseSignStructureContext: CBAdESImprintStructureContext
{
    /// <summary>Prevents external construction; use <see cref="Instance"/>.</summary>
    private CBAdESImprintCoseSignStructureContext()
    {
    }


    /// <summary>Gets the single shared instance of this marker.</summary>
    public static CBAdESImprintCoseSignStructureContext Instance { get; } = new();
}


/// <summary>
/// The <c>COSE_Sign1</c> arm of <see cref="CBAdESImprintStructureContext"/> — step 2's context text is the
/// fixed literal <c>"Signature1"</c>. A stateless marker; use <see cref="Instance"/> rather than constructing a
/// new value. <c>COSE_Sign1</c> has no signer layer distinct from the body layer, so a caller pairs this arm
/// with a <see langword="null"/> signer-layer protected header.
/// </summary>
public sealed record CBAdESImprintCoseSign1StructureContext: CBAdESImprintStructureContext
{
    /// <summary>Prevents external construction; use <see cref="Instance"/>.</summary>
    private CBAdESImprintCoseSign1StructureContext()
    {
    }


    /// <summary>Gets the single shared instance of this marker.</summary>
    public static CBAdESImprintCoseSign1StructureContext Instance { get; } = new();
}


/// <summary>
/// The counter-signature arm of <see cref="CBAdESImprintStructureContext"/> — step 2's context text is the RFC
/// 9338 clause 3.3 context string for whichever countersignature shape the caller resolved, carried as data
/// (mirroring <c>Verifiable.Cbor.CBAdESCountersignatureStructureContext</c>'s own reasoning: this seam does not
/// itself resolve which of RFC 9338's four context strings applies).
/// </summary>
/// <param name="ContextText">The RFC 9338 clause 3.3 context text string. Must not be null or empty.</param>
[DebuggerDisplay("CBAdESImprintCountersignatureStructureContext: {ContextText}")]
public sealed record CBAdESImprintCountersignatureStructureContext: CBAdESImprintStructureContext
{
    /// <summary>
    /// Initializes a new <see cref="CBAdESImprintCountersignatureStructureContext"/>.
    /// </summary>
    /// <param name="contextText">The RFC 9338 clause 3.3 context text string corresponding to the counter signature's structure.</param>
    /// <exception cref="ArgumentException"><paramref name="contextText"/> is null or empty.</exception>
    public CBAdESImprintCountersignatureStructureContext(string contextText)
    {
        ArgumentException.ThrowIfNullOrEmpty(contextText);

        ContextText = contextText;
    }


    /// <summary>Gets the RFC 9338 clause 3.3 context text string.</summary>
    public string ContextText { get; }
}


/// <summary>
/// The three-way source union for <see cref="BuildPayloadTimestampMessageImprintInputDelegate"/> — a
/// JCose-visible mirror of <c>Verifiable.Cbor.CBAdESPayloadImprintSource</c> (the shared vocabulary that
/// type's own remarks document), since that Cbor-only type cannot appear in a JCose delegate's public
/// signature. The Cbor-side adapter (<c>CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput</c>)
/// translates one arm of THIS type into the matching arm of the Cbor-only type before delegating straight
/// into <c>CBAdESMessageImprints.BuildPayloadTimestampMessageImprintInput</c> — a structural translation
/// only, zero algorithm re-implementation. A DU-ready closed sum: no external type may derive from it.
/// </summary>
public abstract class CBAdESPayloadTimestampImprintSource
{
    /// <summary>Restricts direct subtyping to the sibling types declared in this file.</summary>
    private protected CBAdESPayloadTimestampImprintSource()
    {
    }
}


/// <summary>
/// The attached-payload arm of <see cref="CBAdESPayloadTimestampImprintSource"/>: the COSE Payload field is
/// present, and <see cref="PayloadBytes"/> is its content (CB-5.2.6-05).
/// </summary>
[DebuggerDisplay("CBAdESAttachedPayloadTimestampImprintSource: {PayloadBytes.Length} bytes")]
public sealed class CBAdESAttachedPayloadTimestampImprintSource : CBAdESPayloadTimestampImprintSource
{
    /// <summary>Initializes a new <see cref="CBAdESAttachedPayloadTimestampImprintSource"/>.</summary>
    /// <param name="payloadBytes">
    /// The COSE Payload field's content bytes. <strong>Borrowed</strong> view — the caller owns the underlying
    /// memory.
    /// </param>
    public CBAdESAttachedPayloadTimestampImprintSource(ReadOnlyMemory<byte> payloadBytes)
    {
        PayloadBytes = payloadBytes;
    }

    /// <summary>
    /// The COSE Payload field's content bytes. <strong>Borrowed</strong> view — the caller owns the underlying
    /// memory.
    /// </summary>
    public ReadOnlyMemory<byte> PayloadBytes { get; }
}


/// <summary>
/// The detached-and-unreferenced arm of <see cref="CBAdESPayloadTimestampImprintSource"/>: the COSE Payload
/// field is absent, <c>sigD</c> does not reference it, and <see cref="PayloadBytes"/> is the out-of-band-
/// retrieved detached payload (CB-5.2.6-05; retrieval mechanism out of this document's scope).
/// </summary>
[DebuggerDisplay("CBAdESDetachedPayloadTimestampImprintSource: {PayloadBytes.Length} bytes")]
public sealed class CBAdESDetachedPayloadTimestampImprintSource : CBAdESPayloadTimestampImprintSource
{
    /// <summary>Initializes a new <see cref="CBAdESDetachedPayloadTimestampImprintSource"/>.</summary>
    /// <param name="payloadBytes">
    /// The out-of-band-retrieved detached COSE Payload bytes. <strong>Borrowed</strong> view — the caller owns
    /// the underlying memory.
    /// </param>
    public CBAdESDetachedPayloadTimestampImprintSource(ReadOnlyMemory<byte> payloadBytes)
    {
        PayloadBytes = payloadBytes;
    }

    /// <summary>
    /// The out-of-band-retrieved detached COSE Payload bytes. <strong>Borrowed</strong> view — the caller owns
    /// the underlying memory.
    /// </summary>
    public ReadOnlyMemory<byte> PayloadBytes { get; }
}


/// <summary>
/// The <c>sigD</c>-present arm of <see cref="CBAdESPayloadTimestampImprintSource"/>: <see cref="ProcessedParBytes"/>
/// is the ordered sequence of byte views already produced by clause 5.2.8.2.2's <c>pars</c>-processing
/// algorithm in <see cref="CBAdESDetachedObjectDereferencing"/> — this type receives that dereferenced
/// output; it does not itself dereference a <c>pars</c> URI-reference. CB-5.2.6-06: the resulting
/// concatenation is raw, with NO CBOR byte-string wrapping (contrast with the <c>arcTst</c> builder's own
/// step 7).
/// </summary>
/// <param name="ProcessedParBytes">
/// The ordered, already-dereferenced byte sequences to concatenate. Must be non-empty (CB-5.2.8-06). Each
/// element is a <strong>borrowed</strong> view.
/// </param>
[DebuggerDisplay("CBAdESSigDProcessedPayloadTimestampImprintSource: {ProcessedParBytes.Count} segments")]
public sealed class CBAdESSigDProcessedPayloadTimestampImprintSource : CBAdESPayloadTimestampImprintSource
{
    /// <summary>
    /// Initializes a new <see cref="CBAdESSigDProcessedPayloadTimestampImprintSource"/>.
    /// </summary>
    /// <param name="processedParBytes">The ordered, already-dereferenced byte sequences to concatenate.</param>
    /// <exception cref="ArgumentNullException"><paramref name="processedParBytes"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="processedParBytes"/> is empty.</exception>
    public CBAdESSigDProcessedPayloadTimestampImprintSource(IReadOnlyList<ReadOnlyMemory<byte>> processedParBytes)
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
/// Builds the <c>adoTst</c> message-imprint input (clause 5.2.6) from <paramref name="source"/>. A thin
/// seam over <c>CBAdESMessageImprints.BuildPayloadTimestampMessageImprintInput</c> (implemented in Verifiable.Cbor) —
/// zero algorithm re-implementation; see <see cref="CBAdESPayloadTimestampImprintSource"/>'s remarks for why
/// this seam exists beside the Cbor-only builder rather than exposing it directly.
/// </summary>
/// <param name="source">The three-way payload contribution source.</param>
/// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
/// <returns>The pool-rented carrier for the message-imprint input. The caller owns and disposes it.</returns>
public delegate PooledMemory BuildPayloadTimestampMessageImprintInputDelegate(CBAdESPayloadTimestampImprintSource source, BaseMemoryPool pool);


/// <summary>
/// Builds the <c>sigRTst</c> message-imprint input (Annex A.1.2.1.2): the COSE signature value, followed by
/// the <c>sigTst</c>/<c>refs</c> elements from <paramref name="uHeadersEncodedArray"/>, in wire order. A
/// thin seam over <c>CBAdESMessageImprints.TryBuildSignatureAndReferencesTimestampMessageImprintInput</c>
/// (implemented in Verifiable.Cbor) — the shipped builder's own signature already avoids Cbor-only types, so the
/// Cbor-side implementation is a direct method-group assignment (zero adapter logic, zero algorithm
/// re-implementation).
/// </summary>
/// <param name="signatureValue">The COSE signature value's raw content bytes (step 2).</param>
/// <param name="uHeadersEncodedArray">
/// The encoded <c>uHeaders</c> CBOR array bytes from the layer the caller has already selected — under
/// <c>COSE_Sign1</c>, the body layer's <c>uHeaders</c> (the RAW wire bytes
/// captured at parse, e.g. <see cref="CBAdESSign1ParseResult.RawUnsignedHeaders"/>, never a re-encoding of
/// the decoded model) — or <see langword="null"/> when that layer does not have the <c>uHeaders</c> header
/// parameter (steps 3/4).
/// </param>
/// <param name="uHeadersSliceBound">
/// <strong>Ruled by analogy.</strong> Annex A.1.2.1.2 lacks the
/// explicit validation-time prefix replacement clause 5.3.5.3 gives <c>arcTst</c> ("elements that precede...");
/// a repeated <c>sigTst</c> instance appended AFTER a <c>sigRTst</c> is legal (Table 14 note 7), so a
/// full-final-array reading at validation time would compute a different imprint than the one the
/// Time-Stamping Authority attested at generation. RULED by analogy with 5.3.5.3's own validation variant: the
/// imprint input for a SPECIFIC <c>sigRTst</c> instance is built from only the elements that precede its own
/// position — <see langword="null"/> for a generation-time call (every element already present contributes);
/// otherwise the exclusive upper bound (element count to take from the start of
/// <paramref name="uHeadersEncodedArray"/>) for the validation-time call.
/// </param>
/// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
/// <param name="result">The message-imprint input on success; <see langword="null"/> on failure.</param>
/// <returns>
/// <see langword="true"/> on success; <see langword="false"/> when <paramref name="uHeadersEncodedArray"/>
/// is present but malformed or non-conformant, or <paramref name="uHeadersSliceBound"/> is negative (never
/// throws for either case).
/// </returns>
public delegate bool TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate(
    ReadOnlyMemory<byte> signatureValue,
    ReadOnlyMemory<byte>? uHeadersEncodedArray,
    int? uHeadersSliceBound,
    BaseMemoryPool pool,
    out PooledMemory? result);


/// <summary>
/// Builds the <c>rfsTst</c> message-imprint input (Annex A.1.2.2.2): identical to
/// <see cref="TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate"/> minus the leading
/// signature value. A thin seam over <c>CBAdESMessageImprints.TryBuildReferencesOnlyTimestampMessageImprintInput</c>
/// (implemented in Verifiable.Cbor) — same direct method-group registration as the <c>sigRTst</c> seam.
/// </summary>
/// <param name="uHeadersEncodedArray">
/// The encoded <c>uHeaders</c> CBOR array bytes from the layer the caller has already selected, or
/// <see langword="null"/> when that layer does not have the <c>uHeaders</c> header parameter. See
/// <see cref="TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate"/>'s remarks for the raw-
/// bytes requirement, identical here.
/// </param>
/// <param name="uHeadersSliceBound">
/// The same validation-time prefix bound
/// <see cref="TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate"/>'s own remarks document,
/// identical rationale for Annex A.1.2.2.2 — <see langword="null"/> for a generation-time call; otherwise the
/// exclusive upper bound (element count to take from the start of <paramref name="uHeadersEncodedArray"/>) for
/// the validation-time call.
/// </param>
/// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
/// <param name="result">The message-imprint input on success; <see langword="null"/> on failure.</param>
/// <returns>
/// <see langword="true"/> on success; <see langword="false"/> when <paramref name="uHeadersEncodedArray"/>
/// is present but malformed or non-conformant, or <paramref name="uHeadersSliceBound"/> is negative (never
/// throws for either case).
/// </returns>
public delegate bool TryBuildReferencesOnlyTimestampMessageImprintInputDelegate(
    ReadOnlyMemory<byte>? uHeadersEncodedArray,
    int? uHeadersSliceBound,
    BaseMemoryPool pool,
    out PooledMemory? result);


/// <summary>
/// Builds the <c>arcTst</c> message-imprint input in VALIDATION mode (clause 5.3.5.3, steps 10/11 replaced:
/// only the <c>uHeaders</c> elements strictly before the <c>arcTst</c> instance under validation contribute).
/// A thin seam over <c>CBAdESMessageImprints.TryBuildArchiveTimestampValidationMessageImprintInput</c>
/// (Verifiable.Cbor), composing the SAME structural translation
/// <see cref="BuildPayloadTimestampMessageImprintInputDelegate"/>'s adapter already performs for
/// <see cref="CBAdESPayloadTimestampImprintSource"/> (this reuses that mirror union verbatim — clause
/// 5.3.5.3 steps 6/7 branch identically to clause 5.2.6, per <c>CBAdESMessageImprints</c>'s own remarks — no
/// new payload-source type is declared for <c>arcTst</c>). The caller supplies step 2's
/// context text, step 4's signer-layer header, and step 8's RFC 9338 <c>other_fields</c> explicitly, as
/// parameters of this delegate — the Cbor-side adapter treats each as caller-supplied input, not a constant.
/// </summary>
/// <param name="structureContext">
/// The signature-structure context selecting step 2's context text (<see cref="CBAdESImprintCoseSign1StructureContext.Instance"/>
/// for every orchestrator this surface wires — <c>COSE_Sign</c>/countersignature callers thread the matching arm
/// once their own orchestration lands).
/// </param>
/// <param name="bodyProtectedHeader">
/// The body layer's protected-header bytes for step 3 (<see cref="CBAdESSign1ParseResult.RawProtectedHeader"/>'s
/// own captured wire bytes) — never itself <c>bstr</c>-wrapped by the caller; the adapter
/// performs that wrapping.
/// </param>
/// <param name="signerProtectedHeader">
/// The signer layer's protected-header bytes for step 4, or <see langword="null"/> when
/// <paramref name="structureContext"/> is <see cref="CBAdESImprintCoseSign1StructureContext"/> (no signer layer
/// distinct from the body layer). See <c>CBAdESArchiveTimestampImprintContext.SignerProtectedHeader</c>'s own
/// remarks for the nullability discriminator this mirrors.
/// </param>
/// <param name="externallySuppliedData">
/// The externally supplied application data for step 5 (clause 5.3.5.3 NOTE alongside step 5); empty when
/// none was supplied to the application, which produces the zero-length <c>bstr</c> step 5 calls for in that
/// case.
/// </param>
/// <param name="payloadSource">The payload contribution for steps 6/7 (identical three-way branch to <c>adoTst</c>'s own).</param>
/// <param name="countersignatureOtherFields">
/// The RFC 9338 <c>other_fields</c> CBOR array's already-encoded bytes for step 8, or
/// <see langword="null"/> when the CB-AdES signature is not built on a version 2 counter signature.
/// </param>
/// <param name="signatureValue">The COSE signature value's raw content bytes for step 9.</param>
/// <param name="uHeadersEncodedArray">
/// The raw captured <c>uHeaders</c> wire bytes for steps 10/11 (<see cref="CBAdESSign1ParseResult.RawUnsignedHeaders"/>),
/// or <see langword="null"/> when the body layer does not have the
/// <c>uHeaders</c> header parameter at all (the zero-length <c>bstr</c> sentinel fires only on this
/// ABSENT case, never on a present array whose validation prefix happens to be empty).
/// </param>
/// <param name="arcTstElementIndex">
/// The specific <c>arcTst</c> instance's own zero-based position within <c>uHeaders</c> — the exclusive
/// validation-time prefix bound (5.3.5.3's own validation variant, prefix-before-own-position): only the
/// elements strictly before this position contribute, so a later sibling <c>arcTst</c> instance appended after
/// this one never changes what THIS instance is checked against (the repeated-arcTst
/// regression).
/// </param>
/// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
/// <param name="result">The message-imprint input on success; <see langword="null"/> on failure.</param>
/// <returns>
/// <see langword="true"/> on success; <see langword="false"/> when <paramref name="uHeadersEncodedArray"/> is
/// present but malformed or non-conformant (never throws for that case).
/// </returns>
public delegate bool TryBuildArchiveTimestampValidationMessageImprintInputDelegate(
    CBAdESImprintStructureContext structureContext,
    ReadOnlyMemory<byte> bodyProtectedHeader,
    ReadOnlyMemory<byte>? signerProtectedHeader,
    ReadOnlyMemory<byte> externallySuppliedData,
    CBAdESPayloadTimestampImprintSource payloadSource,
    ReadOnlyMemory<byte>? countersignatureOtherFields,
    ReadOnlyMemory<byte> signatureValue,
    ReadOnlyMemory<byte>? uHeadersEncodedArray,
    int arcTstElementIndex,
    BaseMemoryPool pool,
    out PooledMemory? result);


/// <summary>
/// Builds the <c>arcTst</c> message-imprint input in GENERATION mode (clause 5.3.5.3, steps 10/11 over EVERY
/// <c>uHeaders</c> element already present — the new <c>arcTst</c> instance being minted is not itself among
/// them yet). A thin seam over <c>CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput</c>
/// (Verifiable.Cbor), composing the SAME structural translation
/// <see cref="BuildPayloadTimestampMessageImprintInputDelegate"/>'s adapter already performs for
/// <see cref="CBAdESPayloadTimestampImprintSource"/> — its validation-mode sibling
/// <see cref="TryBuildArchiveTimestampValidationMessageImprintInputDelegate"/> reuses that same mirror union
/// verbatim, and so does this one. The caller supplies step 2's context
/// text, step 4's signer-layer header, and step 8's RFC 9338 <c>other_fields</c> explicitly, identically to its
/// validation-mode sibling.
/// </summary>
/// <param name="structureContext">
/// The signature-structure context selecting step 2's context text (<see cref="CBAdESImprintCoseSign1StructureContext.Instance"/>
/// for every orchestrator this surface wires).
/// </param>
/// <param name="bodyProtectedHeader">
/// The body layer's protected-header bytes for step 3 (<see cref="CBAdESSign1ParseResult.RawProtectedHeader"/>'s
/// own captured wire bytes) — never itself <c>bstr</c>-wrapped by the caller; the adapter
/// performs that wrapping.
/// </param>
/// <param name="signerProtectedHeader">
/// The signer layer's protected-header bytes for step 4, or <see langword="null"/> when
/// <paramref name="structureContext"/> is <see cref="CBAdESImprintCoseSign1StructureContext"/>. See the
/// validation-mode sibling's own remarks for the nullability discriminator this mirrors.
/// </param>
/// <param name="externallySuppliedData">
/// The externally supplied application data for step 5 (clause 5.3.5.3 NOTE alongside step 5); empty when
/// none was supplied to the application, which produces the zero-length <c>bstr</c> step 5 calls for in that
/// case.
/// </param>
/// <param name="payloadSource">The payload contribution for steps 6/7 (identical three-way branch to <c>adoTst</c>'s own).</param>
/// <param name="countersignatureOtherFields">
/// The RFC 9338 <c>other_fields</c> CBOR array's already-encoded bytes for step 8, or
/// <see langword="null"/> when the CB-AdES signature is not built on a version 2 counter signature.
/// </param>
/// <param name="signatureValue">The COSE signature value's raw content bytes for step 9.</param>
/// <param name="uHeadersEncodedArray">
/// The raw captured <c>uHeaders</c> wire bytes for steps 10/11 — every element the signature ALREADY carries
/// before this call appends its own new <c>arcTst</c> instance (<see cref="CBAdESSign1ParseResult.RawUnsignedHeaders"/>)
/// — or <see langword="null"/> when the body layer does not have the
/// <c>uHeaders</c> header parameter at all.
/// </param>
/// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
/// <param name="result">The message-imprint input on success; <see langword="null"/> on failure.</param>
/// <returns>
/// <see langword="true"/> on success; <see langword="false"/> when <paramref name="uHeadersEncodedArray"/> is
/// present but malformed or non-conformant (never throws for that case).
/// </returns>
public delegate bool TryBuildArchiveTimestampGenerationMessageImprintInputDelegate(
    CBAdESImprintStructureContext structureContext,
    ReadOnlyMemory<byte> bodyProtectedHeader,
    ReadOnlyMemory<byte>? signerProtectedHeader,
    ReadOnlyMemory<byte> externallySuppliedData,
    CBAdESPayloadTimestampImprintSource payloadSource,
    ReadOnlyMemory<byte>? countersignatureOtherFields,
    ReadOnlyMemory<byte> signatureValue,
    ReadOnlyMemory<byte>? uHeadersEncodedArray,
    BaseMemoryPool pool,
    out PooledMemory? result);
