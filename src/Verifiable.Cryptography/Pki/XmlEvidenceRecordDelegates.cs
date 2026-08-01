using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The bounds a parse of an <c>EvidenceRecord</c> document applies to a document it did not produce.
/// </summary>
/// <remarks>
/// An Evidence Record arrives from whoever archived the data, inside a container or beside it, and is not
/// authenticated by anything until its own time-stamps have been verified — which cannot happen until it has
/// been parsed. Every bound here therefore exists to make a document that is hostile rather than merely large a
/// refusal instead of a resource exhaustion. The values mirror the ones the ASN.1 form of the mechanism is read
/// under, so the same archive is admitted in either syntax.
/// </remarks>
public sealed record XmlEvidenceRecordParseLimits
{
    /// <summary>The bounds a conformant Evidence Record fits inside.</summary>
    public static XmlEvidenceRecordParseLimits Conformant { get; } = new();

    /// <summary>The largest document, in octets, 16 MiB.</summary>
    public int MaximumDocumentByteLength { get; init; } = 16 * 1024 * 1024;

    /// <summary>The largest number of <c>ArchiveTimeStampChain</c> elements, 256 — one per Hash-Tree Renewal the record has ever undergone.</summary>
    public int MaximumChains { get; init; } = 256;

    /// <summary>The largest number of <c>ArchiveTimeStamp</c> elements in any one chain, 1024 — one per Time-Stamp Renewal within that chain.</summary>
    public int MaximumArchiveTimeStampsPerChain { get; init; } = 1024;

    /// <summary>The largest number of <c>Sequence</c> elements in one hash tree, 64 — the depth of a reduced tree over more leaves than any archive this library serves.</summary>
    public int MaximumSequencesPerHashTree { get; init; } = 64;

    /// <summary>The largest number of <c>DigestValue</c> elements in one <c>Sequence</c>, 4096.</summary>
    public int MaximumDigestValuesPerSequence { get; init; } = 4096;

    /// <summary>The largest number of <c>CryptographicInformation</c> elements beside one time-stamp, 256.</summary>
    public int MaximumCryptographicInformationPerTimeStamp { get; init; } = 256;

    /// <summary>The largest number of <c>Attribute</c> elements on one Archive Time-Stamp, 64.</summary>
    public int MaximumAttributesPerArchiveTimeStamp { get; init; } = 64;

    /// <summary>The largest number of <c>SupportingInformation</c> elements on the record, 256.</summary>
    public int MaximumSupportingInformation { get; init; } = 256;

    /// <summary>The deepest element nesting the document may reach, 64. Only the lax-processed content of an <c>Attribute</c>, a <c>CryptographicInformation</c> or a <c>SupportingInformation</c> can nest at all.</summary>
    public int MaximumElementDepth { get; init; } = 64;
}


/// <summary>
/// Why <see cref="ParseEvidenceRecordXmlDelegate"/> did, or did not, produce an <see cref="XmlEvidenceRecord"/>.
/// </summary>
/// <remarks>
/// <see cref="Valid"/> is deliberately not zero: a status that has not been computed must not read as a
/// successful parse. The shape is the one every seam of this wave has.
/// </remarks>
public enum XmlEvidenceRecordParseStatus
{
    /// <summary>No parse has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The document parsed into a well-formed <see cref="XmlEvidenceRecord"/>.</summary>
    Valid = 1,

    /// <summary>The document is not well-formed at all — malformed markup, truncated, or a root element that is not <c>ers:EvidenceRecord</c>.</summary>
    Malformed = 2,

    /// <summary>
    /// A particle clause 8's schema requires was absent: the <c>Version</c> attribute, the
    /// <c>ArchiveTimeStampSequence</c>, a chain's <c>DigestMethod</c> or <c>CanonicalizationMethod</c>, an
    /// <c>ArchiveTimeStamp</c>, its <c>TimeStamp</c>, or an <c>Order</c> attribute clause 2.1 makes required.
    /// </summary>
    MissingRequiredElement = 3,

    /// <summary>
    /// A <c>DigestMethod</c> named an algorithm this library will not compute. Distinct from
    /// <see cref="Malformed"/>: the document is well-formed and its producer's choice is what is refused, since
    /// a hash tree nothing can recompute proves nothing a verifier could report.
    /// </summary>
    UnsupportedDigestAlgorithm = 4,

    /// <summary>
    /// A <c>CanonicalizationMethod</c> named an identifier outside the space clause 4.1.2 binds it to
    /// (IETF RFC 3275 and IETF RFC 4051). Whether the seam a caller supplied implements a recognised one is that
    /// seam's own statement, reported as <see cref="XmlEvidenceRecordCanonicalizationStatus.UnsupportedAlgorithm"/>.
    /// </summary>
    UnsupportedCanonicalizationAlgorithm = 5,

    /// <summary>A <c>DigestValue</c> is not base64, or does not hold as many octets as the algorithm its chain names produces.</summary>
    DigestValueMalformed = 6,

    /// <summary>
    /// A <c>TimeStampToken</c> named a format outside the two clause 3.1.2 registers, or its content is not the
    /// base64 the format it named requires.
    /// </summary>
    TimeStampTokenMalformed = 7,

    /// <summary>
    /// The <c>Order</c> attributes of a set of siblings are not the run 1..n clause 2.1 and clause 8's
    /// <c>OrderType</c> together require: a duplicate, a gap, or a value below 1.
    /// </summary>
    OrderMalformed = 8,

    /// <summary>The document exceeds one of <see cref="XmlEvidenceRecordParseLimits"/>' bounds.</summary>
    LimitExceeded = 9
}


/// <summary>
/// The outcome of <see cref="ParseEvidenceRecordXmlDelegate"/>. On success it owns an
/// <see cref="XmlEvidenceRecord"/> and every carrier that record holds; the caller disposes it. On failure it
/// owns nothing.
/// </summary>
[DebuggerDisplay("XmlEvidenceRecordParseResult: {Status}")]
public sealed record XmlEvidenceRecordParseResult: IDisposable
{
    /// <summary>The parse outcome; <see cref="XmlEvidenceRecordParseStatus.Valid"/> is the only success.</summary>
    public required XmlEvidenceRecordParseStatus Status { get; init; }

    /// <summary>The parsed record; non-<see langword="null"/> only when <see cref="Status"/> is <see cref="XmlEvidenceRecordParseStatus.Valid"/>.</summary>
    public XmlEvidenceRecord? EvidenceRecord { get; init; }

    /// <summary>A short, human-readable reason, present on every non-<see cref="XmlEvidenceRecordParseStatus.Valid"/> outcome.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Status"/> is <see cref="XmlEvidenceRecordParseStatus.Valid"/>.</summary>
    public bool IsValid => Status == XmlEvidenceRecordParseStatus.Valid;


    /// <summary>Creates a successful result owning <paramref name="evidenceRecord"/>.</summary>
    /// <param name="evidenceRecord">The parsed record; ownership transfers to the result.</param>
    /// <returns>A <see cref="XmlEvidenceRecordParseStatus.Valid"/> result.</returns>
    public static XmlEvidenceRecordParseResult Valid(XmlEvidenceRecord evidenceRecord) =>
        new() { Status = XmlEvidenceRecordParseStatus.Valid, EvidenceRecord = evidenceRecord };

    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="status">The failure status; must not be <see cref="XmlEvidenceRecordParseStatus.Valid"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    public static XmlEvidenceRecordParseResult Failed(XmlEvidenceRecordParseStatus status, string reason) =>
        new() { Status = status, FailureReason = reason };


    /// <summary>Disposes <see cref="EvidenceRecord"/>, when present.</summary>
    public void Dispose() => EvidenceRecord?.Dispose();
}


/// <summary>
/// Everything <see cref="ParseEvidenceRecordXmlDelegate"/> is given about one parse.
/// </summary>
/// <remarks>
/// The bounds travel in the context rather than being captured by the implementation, so a caller that varies
/// them varies them per call and a delegate instance carries no state of its own — the same discipline every
/// context record in this namespace applies.
/// </remarks>
[DebuggerDisplay("XmlEvidenceRecordParseContext: {Document.Length} octets")]
public sealed record XmlEvidenceRecordParseContext
{
    /// <summary>The Evidence Record document's octets. The caller retains ownership.</summary>
    public required ReadOnlyMemory<byte> Document { get; init; }

    /// <summary>The bounds the parse applies.</summary>
    public XmlEvidenceRecordParseLimits Limits { get; init; } = XmlEvidenceRecordParseLimits.Conformant;
}


/// <summary>
/// Parses one <c>EvidenceRecord</c> document's octets into the serialisation-agnostic
/// <see cref="XmlEvidenceRecord"/> model — a document conformant to
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-8">IETF RFC 6283 clause 8</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation.</strong> An Evidence Record in this syntax is XML, and this
/// project stays serialization-agnostic — it references neither an XML package nor a JSON or CBOR one — exactly
/// as <see cref="ParseTrustedListDelegate"/> and <see cref="ParseAsicManifestDelegate"/> do for their profiles.
/// A worked implementation over the base class library's own XML reader and canonicalizer is staged as a
/// promotable example under the test project.
/// </para>
/// <para>
/// <strong>Fail-closed on structure.</strong> Every particle clause 8's schema requires is required in the
/// returned model too; an implementation that cannot populate one MUST return
/// <see cref="XmlEvidenceRecordParseResult.Failed(XmlEvidenceRecordParseStatus, string)"/> rather than inventing
/// a default. A <c>DigestMethod</c> naming an algorithm
/// <see cref="XmlSignatureWellKnown.DigestAlgorithmFromUri"/> does not resolve MUST be refused as
/// <see cref="XmlEvidenceRecordParseStatus.UnsupportedDigestAlgorithm"/>, and a
/// <c>CanonicalizationMethod</c> naming an identifier
/// <see cref="XmlSignatureWellKnown.IsRecognizedCanonicalizationUri"/> does not recognise MUST be refused as
/// <see cref="XmlEvidenceRecordParseStatus.UnsupportedCanonicalizationAlgorithm"/> — clause 4.1.1 and clause
/// 4.1.2 bind both identifier spaces, and a chain naming something outside them is not extensible, it is
/// non-conformant.
/// </para>
/// <para>
/// <strong>The <c>Order</c> attributes are the document's own ordering, and the model is sorted by them.</strong>
/// Clause 2.1 makes <c>Order</c> required "in every case where sibling elements of the same name occur at the
/// same level", and clause 4.1 makes both chain and Archive Time-Stamp sequences sorted by time ascending with
/// the order "indicated by the <c>Order</c> attribute". An implementation MUST therefore return the chains and
/// the Archive Time-Stamps in ascending <c>Order</c> rather than in document order, and MUST refuse a set whose
/// orders are not the run 1..n as <see cref="XmlEvidenceRecordParseStatus.OrderMalformed"/> — a duplicate or a
/// gap makes "the ATS with the largest <c>Order</c>" of clause 4.1 name something no verifier can agree on.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> An implementation MUST prohibit document type definitions (entity
/// expansion and external entity fetch), MUST resolve no external resource, MUST bound the nesting of the
/// lax-processed content elements, and MUST honour <see cref="XmlEvidenceRecordParseLimits"/>.
/// </para>
/// </remarks>
/// <param name="context">The document and the bounds to parse it under.</param>
/// <param name="pool">The memory pool the implementation rents every carrier from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The parse result.</returns>
public delegate ValueTask<XmlEvidenceRecordParseResult> ParseEvidenceRecordXmlDelegate(
    XmlEvidenceRecordParseContext context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Which element of an Evidence Record, or which supplied archive data, the canonicalization seam is being
/// asked for the binary representation of.
/// </summary>
/// <remarks>
/// The seam names an element rather than being handed one because the octets that are hashed are the octets of
/// a <em>sub-tree of the document as it stands</em>, in whatever namespace declarations, prefixes and comments
/// that document actually carries — which a model cannot reproduce and a re-serialisation would not preserve.
/// The library therefore states which sub-tree it needs, in the document's own terms (clause and order numbers),
/// and the seam produces its canonical form.
/// </remarks>
public enum XmlEvidenceRecordCanonicalizationTarget
{
    /// <summary>No target stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>
    /// The whole <c>TimeStamp</c> element of the Archive Time-Stamp named by
    /// <see cref="XmlEvidenceRecordCanonicalizationContext.ChainOrder"/> and
    /// <see cref="XmlEvidenceRecordCanonicalizationContext.ArchiveTimeStampOrder"/>, including any
    /// <c>CryptographicInformationList</c> inside it — the value clause 4.2.1 step 2 hashes for a Time-Stamp
    /// Renewal and Appendix A step 4.b.i verifies one against.
    /// </summary>
    TimeStampElement = 1,

    /// <summary>
    /// An <c>ArchiveTimeStampSequence</c> element holding the first
    /// <see cref="XmlEvidenceRecordCanonicalizationContext.ChainCount"/> chains in ascending <c>Order</c> and no
    /// others — the "ordered ATSSeq without this and successive chains" of Appendix A step 4.a.ii, which
    /// clause 4.2.2 step 5 produced.
    /// </summary>
    ArchiveTimeStampSequencePrefix = 2,

    /// <summary>
    /// The XML archive data supplied in
    /// <see cref="XmlEvidenceRecordCanonicalizationContext.ArchiveData"/> — the "canonicalization MUST be
    /// applied over XML structured archive data" of clause 4.1.2, which is the only case where the octets to
    /// canonicalize are not part of the Evidence Record.
    /// </summary>
    ArchiveDataObject = 3
}


/// <summary>
/// Why <see cref="CanonicalizeXmlEvidenceRecordDelegate"/> did, or did not, produce a binary representation.
/// </summary>
/// <remarks>
/// <see cref="Canonicalized"/> is deliberately not zero, for the same reason every other status enumeration of
/// this wave reserves zero for "not computed".
/// </remarks>
public enum XmlEvidenceRecordCanonicalizationStatus
{
    /// <summary>No canonicalization has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The binary representation was produced.</summary>
    Canonicalized = 1,

    /// <summary>The implementation does not perform the canonicalization algorithm the chain names.</summary>
    UnsupportedAlgorithm = 2,

    /// <summary>The element the target names is not in the document — an <c>Order</c> nothing carries, or a chain count beyond what the sequence holds.</summary>
    TargetNotFound = 3,

    /// <summary>The document, or the supplied archive data, is not well-formed XML.</summary>
    Malformed = 4
}


/// <summary>
/// The outcome of <see cref="CanonicalizeXmlEvidenceRecordDelegate"/>. On success it owns the produced octets;
/// the caller disposes them. On failure it owns nothing.
/// </summary>
[DebuggerDisplay("XmlEvidenceRecordCanonicalizationResult: {Status}")]
public sealed record XmlEvidenceRecordCanonicalizationResult: IDisposable
{
    /// <summary>The outcome; <see cref="XmlEvidenceRecordCanonicalizationStatus.Canonicalized"/> is the only success.</summary>
    public required XmlEvidenceRecordCanonicalizationStatus Status { get; init; }

    /// <summary>
    /// The binary representation, tagged <see cref="XmlEvidenceRecordTags.CanonicalizedElement"/>;
    /// non-<see langword="null"/> only when <see cref="Status"/> is
    /// <see cref="XmlEvidenceRecordCanonicalizationStatus.Canonicalized"/>. These are the exact octets a digest
    /// is taken over, so an implementation returns them verbatim and never re-encodes them.
    /// </summary>
    public PooledMemory? BinaryRepresentation { get; init; }

    /// <summary>A short, human-readable reason, present on every non-<see cref="XmlEvidenceRecordCanonicalizationStatus.Canonicalized"/> outcome.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Status"/> is <see cref="XmlEvidenceRecordCanonicalizationStatus.Canonicalized"/>.</summary>
    public bool IsCanonicalized => Status == XmlEvidenceRecordCanonicalizationStatus.Canonicalized;


    /// <summary>Creates a successful result owning <paramref name="binaryRepresentation"/>.</summary>
    /// <param name="binaryRepresentation">The produced octets; ownership transfers to the result.</param>
    /// <returns>A <see cref="XmlEvidenceRecordCanonicalizationStatus.Canonicalized"/> result.</returns>
    public static XmlEvidenceRecordCanonicalizationResult Canonicalized(PooledMemory binaryRepresentation) =>
        new() { Status = XmlEvidenceRecordCanonicalizationStatus.Canonicalized, BinaryRepresentation = binaryRepresentation };

    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="status">The failure status; must not be <see cref="XmlEvidenceRecordCanonicalizationStatus.Canonicalized"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    public static XmlEvidenceRecordCanonicalizationResult Failed(XmlEvidenceRecordCanonicalizationStatus status, string reason) =>
        new() { Status = status, FailureReason = reason };


    /// <summary>Disposes <see cref="BinaryRepresentation"/>, when present.</summary>
    public void Dispose() => BinaryRepresentation?.Dispose();
}


/// <summary>
/// Everything <see cref="CanonicalizeXmlEvidenceRecordDelegate"/> is given about one canonicalization.
/// </summary>
/// <remarks>
/// Everything the implementation needs is stated per call: the document's octets, the algorithm the chain in
/// force names, which sub-tree is wanted and, for the one target that is not part of the document, the archive
/// data itself. Nothing is captured — a delegate instance holds no state, so the same instance serves every
/// chain of every record a caller validates, under whichever algorithm each of them names.
/// </remarks>
[DebuggerDisplay("XmlEvidenceRecordCanonicalizationContext: {Target} under {AlgorithmUri}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "An algorithm identifier is compared as written: RFC 6283 clause 4.1.2 identifies a canonicalization algorithm by the URI string, and System.Uri normalises case, escaping and default ports, which would make two identifiers that name different algorithms compare equal.")]
public sealed record XmlEvidenceRecordCanonicalizationContext
{
    /// <summary>The Evidence Record document's octets. The caller retains ownership.</summary>
    public required ReadOnlyMemory<byte> Document { get; init; }

    /// <summary>
    /// The <c>CanonicalizationMethod</c> identifier of the chain in force — which, for
    /// <see cref="XmlEvidenceRecordCanonicalizationTarget.ArchiveTimeStampSequencePrefix"/>, is the SUCCEEDING
    /// chain's rather than the prefix's own: clause 4.1.2 states that "in case of succeeding ATSC the
    /// canonicalization method indicated within the ATSC must also be used for the calculation of the digest
    /// value of the preceding ATSC".
    /// </summary>
    public required string AlgorithmUri { get; init; }

    /// <summary>Which sub-tree, or which supplied data, is wanted.</summary>
    public required XmlEvidenceRecordCanonicalizationTarget Target { get; init; }

    /// <summary>The <c>Order</c> of the chain the wanted <c>TimeStamp</c> element sits in; unused by the other targets.</summary>
    public int ChainOrder { get; init; }

    /// <summary>The <c>Order</c> of the Archive Time-Stamp whose <c>TimeStamp</c> element is wanted; unused by the other targets.</summary>
    public int ArchiveTimeStampOrder { get; init; }

    /// <summary>How many chains, counted from the lowest <c>Order</c>, the wanted <c>ArchiveTimeStampSequence</c> prefix holds; unused by the other targets.</summary>
    public int ChainCount { get; init; }

    /// <summary>The XML archive data to canonicalize; used only by <see cref="XmlEvidenceRecordCanonicalizationTarget.ArchiveDataObject"/>. The caller retains ownership.</summary>
    public ReadOnlyMemory<byte> ArchiveData { get; init; }
}


/// <summary>
/// Produces the canonical binary representation of one XML element, per
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-4.1.2">IETF RFC 6283 clause 4.1.2</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation</strong>, for the same reason
/// <see cref="ParseEvidenceRecordXmlDelegate"/> ships none. A worked implementation over the base class
/// library's own canonicalizer is staged as a promotable example under the test project.
/// </para>
/// <para>
/// <strong>This is the whole reason the XML syntax needs a seam the ASN.1 syntax does not.</strong> An ASN.1
/// Evidence Record's internal structures have one canonical binary form by construction, so RFC 4998 never
/// defines a canonicalization step and its renewal procedures hash octets that are simply there. XML has no such
/// form: clause 4.1.2 makes <c>CanonicalizationMethod</c> a REQUIRED element of every chain precisely because
/// the binary representation of an element has to be produced rather than read. An implementation that returned
/// the document's own octets for a sub-tree would be right only by accident.
/// </para>
/// <para>
/// <strong>The comment-preserving forms are not interchangeable with the plain ones.</strong> Three of the six
/// identifiers <see cref="XmlSignatureWellKnown.IsRecognizedCanonicalizationUri"/> recognises preserve comments,
/// and Evidence Records carrying comments inside the sequence exist. An implementation MUST honour
/// <see cref="XmlSignatureWellKnown.IsCanonicalizationWithComments"/> rather than choosing one behaviour for
/// both, or it computes a root nothing matches.
/// </para>
/// <para>
/// <strong>Faults are statuses, not exceptions.</strong> A seam is implemented by whoever supplies it, and
/// making exception behaviour part of the contract would make every implementation's failure mode part of it
/// too. An algorithm the implementation does not perform is
/// <see cref="XmlEvidenceRecordCanonicalizationStatus.UnsupportedAlgorithm"/>, never a thrown exception and
/// never a silent substitution of a different algorithm.
/// </para>
/// </remarks>
/// <param name="context">The document, the algorithm, and which sub-tree is wanted.</param>
/// <param name="pool">The memory pool the implementation rents the produced octets' carrier from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The canonicalization result.</returns>
public delegate ValueTask<XmlEvidenceRecordCanonicalizationResult> CanonicalizeXmlEvidenceRecordDelegate(
    XmlEvidenceRecordCanonicalizationContext context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Why <see cref="WriteEvidenceRecordXmlDelegate"/> did, or did not, produce a document.
/// </summary>
/// <remarks>
/// <see cref="Written"/> is deliberately not zero, for the same reason every other status enumeration of this
/// namespace reserves zero for "not computed".
/// </remarks>
public enum XmlEvidenceRecordWriteStatus
{
    /// <summary>No write has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The document's octets were produced.</summary>
    Written = 1,

    /// <summary>The model states something the implementation cannot serialise into clause 8's schema.</summary>
    Unwritable = 2
}


/// <summary>
/// The outcome of <see cref="WriteEvidenceRecordXmlDelegate"/>. On success it owns the produced octets; the
/// caller disposes them. On failure it owns nothing.
/// </summary>
[DebuggerDisplay("XmlEvidenceRecordWriteResult: {Status}")]
public sealed record XmlEvidenceRecordWriteResult: IDisposable
{
    /// <summary>Whether ownership of <see cref="Document"/> has been transferred out by <see cref="TakeDocument"/>.</summary>
    private bool taken;


    /// <summary>The outcome; <see cref="XmlEvidenceRecordWriteStatus.Written"/> is the only success.</summary>
    public required XmlEvidenceRecordWriteStatus Status { get; init; }

    /// <summary>
    /// The <c>EvidenceRecord</c> document's octets, tagged <see cref="XmlEvidenceRecordTags.EvidenceRecord"/>;
    /// non-<see langword="null"/> only when <see cref="Status"/> is
    /// <see cref="XmlEvidenceRecordWriteStatus.Written"/>.
    /// </summary>
    public PooledMemory? Document { get; init; }

    /// <summary>A short, human-readable reason, present on every non-<see cref="XmlEvidenceRecordWriteStatus.Written"/> outcome.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Status"/> is <see cref="XmlEvidenceRecordWriteStatus.Written"/>.</summary>
    public bool IsWritten => Status == XmlEvidenceRecordWriteStatus.Written;


    /// <summary>Creates a successful result owning <paramref name="document"/>.</summary>
    /// <param name="document">The produced octets; ownership transfers to the result.</param>
    /// <returns>A <see cref="XmlEvidenceRecordWriteStatus.Written"/> result.</returns>
    public static XmlEvidenceRecordWriteResult Written(PooledMemory document) =>
        new() { Status = XmlEvidenceRecordWriteStatus.Written, Document = document };

    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="status">The failure status; must not be <see cref="XmlEvidenceRecordWriteStatus.Written"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    public static XmlEvidenceRecordWriteResult Failed(XmlEvidenceRecordWriteStatus status, string reason) =>
        new() { Status = status, FailureReason = reason };


    /// <summary>
    /// Transfers ownership of <see cref="Document"/> out of this result, so that disposing the result no
    /// longer releases it — the produced document outlives the write that produced it, the same transfer
    /// <see cref="XmlEvidenceRecordRootComputation.TakeRoot"/> states for the recomputed root.
    /// </summary>
    /// <returns>The document, now owned by the caller, or <see langword="null"/> when none was produced.</returns>
    internal PooledMemory? TakeDocument()
    {
        taken = true;

        return Document;
    }


    /// <summary>Disposes <see cref="Document"/>, when present and not taken.</summary>
    public void Dispose()
    {
        if(!taken)
        {
            Document?.Dispose();
        }
    }
}


/// <summary>
/// Everything <see cref="WriteEvidenceRecordXmlDelegate"/> is given about one write.
/// </summary>
/// <remarks>
/// The model travels in the context and the caller retains its ownership — the implementation reads it, writes
/// the document, and owns nothing afterwards, the same statelessness every context record in this namespace
/// keeps its delegate to.
/// </remarks>
[DebuggerDisplay("XmlEvidenceRecordWriteContext: {EvidenceRecord.Chains.Count} chains")]
public sealed record XmlEvidenceRecordWriteContext
{
    /// <summary>The assembled record to serialise. The caller retains ownership.</summary>
    public required XmlEvidenceRecord EvidenceRecord { get; init; }
}


/// <summary>
/// Serialises one <see cref="XmlEvidenceRecord"/> model into an <c>EvidenceRecord</c> document conformant to
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-8">IETF RFC 6283 clause 8</see> — the write
/// direction of <see cref="ParseEvidenceRecordXmlDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation</strong>, for the same reason
/// <see cref="ParseEvidenceRecordXmlDelegate"/> ships none: an Evidence Record in this syntax is XML, and this
/// project stays serialization-agnostic. A worked implementation over the base class library's own XML writer
/// is staged as a promotable example under the test project.
/// </para>
/// <para>
/// <strong>Clause 8's schema is the contract.</strong> An implementation writes the <c>EvidenceRecord</c>
/// element in the <see cref="XmlEvidenceRecordWellKnown.EvidenceRecordNamespace"/> namespace with
/// <c>Version</c> as the model states it, every <c>Order</c> attribute the model carries, <c>DigestMethod</c>
/// and <c>CanonicalizationMethod</c> with their <c>Algorithm</c> attributes as written, hash values and
/// time-stamp tokens as base64 text, and the <c>TimeStampToken</c>'s required <c>Type</c> attribute. A model
/// stating something the schema cannot carry is refused as
/// <see cref="XmlEvidenceRecordWriteStatus.Unwritable"/> rather than approximated — the parse seam is the
/// strict reader of what this seam writes, and a document it refuses protects nothing.
/// </para>
/// <para>
/// <strong>The emitted octets become load-bearing later.</strong> A renewal canonicalizes sub-trees of the
/// document as it stands (<see cref="CanonicalizeXmlEvidenceRecordDelegate"/>), so the document this seam
/// produces is the one those digests will be computed over. Nothing in the initial record's own verification
/// digests the document itself — the hash tree binds the archive data, not the record — but an implementation
/// still writes well-formed, namespace-correct XML whose sub-trees canonicalize under the chain's stated
/// method, or the record it wrote cannot be renewed.
/// </para>
/// <para>
/// <strong>Faults are statuses, not exceptions</strong>, exactly as the parse and canonicalization seams have
/// it: a seam is implemented by whoever supplies it, and exception behaviour must not become part of the
/// contract.
/// </para>
/// </remarks>
/// <param name="context">The assembled record to serialise.</param>
/// <param name="pool">The memory pool the implementation rents the produced octets' carrier from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The write result.</returns>
public delegate ValueTask<XmlEvidenceRecordWriteResult> WriteEvidenceRecordXmlDelegate(
    XmlEvidenceRecordWriteContext context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
