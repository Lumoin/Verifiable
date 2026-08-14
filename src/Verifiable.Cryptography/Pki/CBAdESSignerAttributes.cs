using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One element of <see cref="AdESSignerAttributes.SignedAssertions"/> or
/// <see cref="AdESSignerAttributes.Claimed"/> when produced by CB-AdES (<c>NotCertifiedItem</c>,
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.2.5, <c>AttrArrays = [+NotCertifiedItem]</c>).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Owner flag — CDDL/prose contradiction:</strong> clause 5.2.5's prose names a <c>qVals</c> member
/// ("The <c>qVals</c> member ... shall be a CBOR array of at least one item") and an <c>encoding</c> member
/// ("the values of the signed assertions or claimed attributes, encoded as indicated within the <c>encoding</c>
/// member"), but the CDDL for <c>NotCertifiedItem</c> defines only <c>mediaType: tstr</c> followed by an
/// unparseable <c>*label =&gt; any the not certified item</c> fragment — neither <c>qVals</c> nor
/// <c>encoding</c> is a named CDDL label, and it is not specified which (if any) catch-all label values they
/// correspond to. A byte-exact codec for this type cannot be written from clause 5.2.5 alone (flagged for
/// spec-liaison follow-up). Pending ETSI clarification,
/// <see cref="QualifyingValues"/> models the "qualifying-values collection" the prose describes
/// (CB-5.2.5-10/12/13) as an array of OPAQUE encoded items — each carrying its own
/// <see cref="CBAdESSignerAttributeOpaqueQualifyingValue.Kind"/> discriminator rather than a decoded value —
/// so a producer/consumer using this library today emits/reads well-formed bytes without this library
/// silently asserting a decoding it cannot substantiate. This is why <see cref="AdESSignerAttributes"/> does
/// not force this item shape and JAdES's <see cref="JAdESQualifyingAttribute"/> into one type.
/// </para>
/// <para>
/// <see cref="QualifyingValues"/> should contain at least one entry when present (CB-5.2.5-12); mirroring
/// <see cref="AdESSignerCommitments"/>'s convention, that invariant is documented here rather than
/// runtime-enforced — this type owns no disposable resources, so no constructor is otherwise required.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESSignerAttributeNotCertifiedItem: {MediaType}, {QualifyingValues.Count} values")]
public sealed record CBAdESSignerAttributeNotCertifiedItem
{
    /// <summary>
    /// Gets the media type identifying the type of the values in <see cref="QualifyingValues"/>
    /// (<c>mediaType</c>, clause 5.2.5), per the IANA media-types registry.
    /// </summary>
    public required string MediaType { get; init; }

    /// <summary>
    /// Gets the qualifying-values collection (the prose's <c>qVals</c>, clause 5.2.5). See the remarks on
    /// this type for why each element is opaque.
    /// </summary>
    public required IReadOnlyList<CBAdESSignerAttributeOpaqueQualifyingValue> QualifyingValues { get; init; }
}


/// <summary>
/// What encoding convention a <see cref="CBAdESSignerAttributeOpaqueQualifyingValue"/>'s
/// <see cref="CBAdESSignerAttributeOpaqueQualifyingValue.EncodedValue"/> is known to follow — see the
/// remarks on <see cref="CBAdESSignerAttributeNotCertifiedItem"/>.
/// </summary>
public enum CBAdESSignerAttributeOpaqueQualifyingValueKind
{
    /// <summary>
    /// The encoding convention clause 5.2.5's prose calls the <c>encoding</c> member is unspecified —
    /// <see cref="CBAdESSignerAttributeOpaqueQualifyingValue.EncodedValue"/> is a well-formed CBOR data item
    /// exactly as it appeared in the wire <c>qVals</c> array, uninterpreted. This is the only kind this
    /// library produces or expects until this is resolved.
    /// </summary>
    Unspecified = 0
}


/// <summary>
/// One opaque element of <see cref="CBAdESSignerAttributeNotCertifiedItem.QualifyingValues"/> — the raw
/// encoded bytes of one <c>qVals</c> item plus a <see cref="Kind"/> discriminator, per the remarks on
/// <see cref="CBAdESSignerAttributeNotCertifiedItem"/>.
/// </summary>
/// <param name="Kind">What <paramref name="EncodedValue"/>'s encoding convention is known to be.</param>
/// <param name="EncodedValue">
/// The item's raw encoded bytes. <strong>Borrowed</strong> view — the caller (creation path) or the wire-bytes
/// source (parse path) owns the underlying memory.
/// </param>
[DebuggerDisplay("CBAdESSignerAttributeOpaqueQualifyingValue: {Kind}, {EncodedValue.Length} bytes")]
public sealed record CBAdESSignerAttributeOpaqueQualifyingValue(
    CBAdESSignerAttributeOpaqueQualifyingValueKind Kind,
    ReadOnlyMemory<byte> EncodedValue);
