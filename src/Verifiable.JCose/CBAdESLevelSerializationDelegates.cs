using System.Diagnostics;

namespace Verifiable.JCose;

//The CB-AdES stage-4 (wavecb S4) message-imprint-INPUT seam delegates: the shapes the augmentation and
//validation orchestrators consume, implemented as thin adapters in Verifiable.Cbor over the shipped
//CBAdESMessageImprints builders (S2). Verifiable.JCose cannot reference Verifiable.Cbor -- the reference
//graph runs the other way (Verifiable.Cbor -> Verifiable.JCose -> Verifiable.Cryptography) -- so every
//byte-assembly operation these orchestrators need crosses one of these three seams, mirroring
//CBAdESSerializationDelegates.cs's shape and registration mechanism (a delegate TYPE declared here,
//implemented as a public static getter property of that delegate type in Verifiable.Cbor).

/// <summary>
/// The three-way source union for <see cref="BuildPayloadTimestampMessageImprintInputDelegate"/> — a
/// JCose-visible mirror of <c>Verifiable.Cbor.CBAdESPayloadImprintSource</c> (the S2 shared vocabulary that
/// type's own remarks document), since that Cbor-only type cannot appear in a JCose delegate's public
/// signature. The Cbor-side adapter (<c>CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput</c>)
/// translates one arm of THIS type into the matching arm of the Cbor-only type before delegating straight
/// into <c>CBAdESMessageImprints.BuildPayloadTimestampMessageImprintInput</c> — a structural translation
/// only, zero algorithm re-implementation. A DU-ready closed sum: no external type may derive from it.
/// </summary>
public abstract record CBAdESPayloadTimestampImprintSource
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESPayloadTimestampImprintSource()
    {
    }
}


/// <summary>
/// The attached-payload arm of <see cref="CBAdESPayloadTimestampImprintSource"/>: the COSE Payload field is
/// present, and <see cref="PayloadBytes"/> is its content (CB-5.2.6-05).
/// </summary>
/// <param name="PayloadBytes">
/// The COSE Payload field's content bytes. <strong>Borrowed</strong> view — the caller owns the underlying
/// memory.
/// </param>
[DebuggerDisplay("CBAdESAttachedPayloadTimestampImprintSource: {PayloadBytes.Length} bytes")]
public sealed record CBAdESAttachedPayloadTimestampImprintSource(ReadOnlyMemory<byte> PayloadBytes)
    : CBAdESPayloadTimestampImprintSource;


/// <summary>
/// The detached-and-unreferenced arm of <see cref="CBAdESPayloadTimestampImprintSource"/>: the COSE Payload
/// field is absent, <c>sigD</c> does not reference it, and <see cref="PayloadBytes"/> is the out-of-band-
/// retrieved detached payload (CB-5.2.6-05; retrieval mechanism out of this document's scope).
/// </summary>
/// <param name="PayloadBytes">
/// The out-of-band-retrieved detached COSE Payload bytes. <strong>Borrowed</strong> view — the caller owns
/// the underlying memory.
/// </param>
[DebuggerDisplay("CBAdESDetachedPayloadTimestampImprintSource: {PayloadBytes.Length} bytes")]
public sealed record CBAdESDetachedPayloadTimestampImprintSource(ReadOnlyMemory<byte> PayloadBytes)
    : CBAdESPayloadTimestampImprintSource;


/// <summary>
/// The <c>sigD</c>-present arm of <see cref="CBAdESPayloadTimestampImprintSource"/>: <see cref="ProcessedParBytes"/>
/// is the ordered sequence of byte views already produced by clause 5.2.8.2.2's <c>pars</c>-processing
/// algorithm (the S3 dereference seam, <see cref="CBAdESDetachedObjectDereferencing"/> — this type receives
/// its output, it does not itself dereference anything). CB-5.2.6-06: the resulting concatenation is raw,
/// with NO CBOR byte-string wrapping (contrast with the <c>arcTst</c> builder's own step 7).
/// </summary>
/// <param name="ProcessedParBytes">
/// The ordered, already-dereferenced byte sequences to concatenate. Must be non-empty (CB-5.2.8-06). Each
/// element is a <strong>borrowed</strong> view.
/// </param>
[DebuggerDisplay("CBAdESSigDProcessedPayloadTimestampImprintSource: {ProcessedParBytes.Count} segments")]
public sealed record CBAdESSigDProcessedPayloadTimestampImprintSource : CBAdESPayloadTimestampImprintSource
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
/// seam over <c>CBAdESMessageImprints.BuildPayloadTimestampMessageImprintInput</c> (Verifiable.Cbor, S2) —
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
/// (Verifiable.Cbor, S2) — the shipped builder's own signature already avoids Cbor-only types, so the
/// Cbor-side implementation is a direct method-group assignment (zero adapter logic, zero algorithm
/// re-implementation).
/// </summary>
/// <param name="signatureValue">The COSE signature value's raw content bytes (step 2).</param>
/// <param name="uHeadersEncodedArray">
/// The encoded <c>uHeaders</c> CBOR array bytes from the layer the caller has already selected — under
/// <c>COSE_Sign1</c>, the body layer's <c>uHeaders</c> (S4 coordinator ruling (3): the RAW wire bytes
/// captured at parse, e.g. <see cref="CBAdESSign1ParseResult.RawUnsignedHeaders"/>, never a re-encoding of
/// the decoded model) — or <see langword="null"/> when that layer does not have the <c>uHeaders</c> header
/// parameter (steps 3/4).
/// </param>
/// <param name="uHeadersSliceBound">
/// <strong>D15 (wavecb-contract.md R-6, added at S4 review, RULED).</strong> Annex A.1.2.1.2 lacks the
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
/// throws for either case — contract R-5).
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
/// (Verifiable.Cbor, S2) — same direct method-group registration as the <c>sigRTst</c> seam.
/// </summary>
/// <param name="uHeadersEncodedArray">
/// The encoded <c>uHeaders</c> CBOR array bytes from the layer the caller has already selected, or
/// <see langword="null"/> when that layer does not have the <c>uHeaders</c> header parameter. See
/// <see cref="TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate"/>'s remarks for the raw-
/// bytes requirement, identical here.
/// </param>
/// <param name="uHeadersSliceBound">
/// D15 (wavecb-contract.md R-6): the same validation-time prefix bound
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
/// throws for either case — contract R-5).
/// </returns>
public delegate bool TryBuildReferencesOnlyTimestampMessageImprintInputDelegate(
    ReadOnlyMemory<byte>? uHeadersEncodedArray,
    int? uHeadersSliceBound,
    BaseMemoryPool pool,
    out PooledMemory? result);
