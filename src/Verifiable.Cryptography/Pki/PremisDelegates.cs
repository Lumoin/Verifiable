using System;
using System.Buffers;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The bounds a preservation-metadata parse applies to a document it did not produce.
/// </summary>
/// <remarks>
/// A preservation-metadata document arrives inside a package this library did not build and is read before
/// anything about that package has been verified, so every bound here exists to make a document that is hostile
/// rather than merely large a refusal instead of a resource exhaustion. The defaults are the ones
/// <see cref="Conformant"/> states.
/// </remarks>
public sealed record PremisParseLimits
{
    /// <summary>The bounds a conformant package's preservation-metadata documents fit inside.</summary>
    public static PremisParseLimits Conformant { get; } = new();

    /// <summary>The largest document, in octets, 64 MiB — a document may describe one object per file of a package.</summary>
    public int MaximumDocumentByteLength { get; init; } = 64 * 1024 * 1024;

    /// <summary>The largest number of <c>object</c> elements, 1 048 576.</summary>
    public int MaximumObjects { get; init; } = 1024 * 1024;

    /// <summary>The largest number of <c>event</c> elements, 1 048 576 — a long-lived package accumulates one per preservation action.</summary>
    public int MaximumEvents { get; init; } = 1024 * 1024;

    /// <summary>The largest number of <c>agent</c> elements, 65 536.</summary>
    public int MaximumAgents { get; init; } = 64 * 1024;

    /// <summary>The largest number of <c>rightsStatement</c> elements, 65 536.</summary>
    public int MaximumRightsStatements { get; init; } = 64 * 1024;

    /// <summary>The largest number of child elements — identifiers, fixities, relationships, links — any one element may carry, 4096.</summary>
    public int MaximumChildElements { get; init; } = 4096;

    /// <summary>
    /// The largest number of characters any one attribute value or text node may occupy, 8192. It bounds
    /// identifier values, names, notes and instants alike, because each of them is producer-controlled and none of
    /// them has a legitimate use at that length.
    /// </summary>
    public int MaximumTextLength { get; init; } = 8192;

    /// <summary>
    /// The deepest element nesting the document may reach, 64. The vocabulary's own particles sit at a fixed
    /// depth, so this bounds a document that nests to exhaust a reader rather than to say anything.
    /// </summary>
    public int MaximumElementDepth { get; init; } = 64;
}


/// <summary>
/// Why <see cref="ParsePremisDelegate"/> did, or did not, produce a <see cref="PremisDocument"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Valid"/> is deliberately not zero: a status that has not been computed must not read as a successful
/// parse.
/// </para>
/// <para>
/// As with <see cref="MetsParseStatus"/>, there is no unsupported-algorithm status: a <c>fixity</c> block naming
/// an algorithm this library does not compute is carried as <see cref="EArkStatedFixity"/> with its reason rather
/// than refused, and what to do about it is a validation rule's decision.
/// </para>
/// </remarks>
public enum PremisParseStatus
{
    /// <summary>No parse has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The document parsed into a well-formed <see cref="PremisDocument"/>.</summary>
    Valid = 1,

    /// <summary>The document is not well-formed at all — malformed markup, truncated, or a root element that is not <c>premis</c>.</summary>
    Malformed = 2,

    /// <summary>
    /// A particle the specification requires was absent: the <c>@version</c> attribute, an object's
    /// <c>@xsi:type</c> category, an identifier's type or value, an event's type or instant, an agent's name or
    /// type, a relationship's type or subtype, or a rights statement's basis.
    /// </summary>
    MissingRequiredElement = 3,

    /// <summary>The document exceeds one of <see cref="PremisParseLimits"/>' bounds.</summary>
    LimitExceeded = 4
}


/// <summary>
/// The outcome of <see cref="ParsePremisDelegate"/>. On success it owns a <see cref="PremisDocument"/> (and every
/// fixity carrier that document holds); the caller disposes it. On failure it owns nothing.
/// </summary>
[DebuggerDisplay("PremisParseResult: {Status}")]
public sealed record PremisParseResult: IDisposable
{
    /// <summary>The parse outcome; <see cref="PremisParseStatus.Valid"/> is the only success.</summary>
    public required PremisParseStatus Status { get; init; }

    /// <summary>The parsed document; non-<see langword="null"/> only when <see cref="Status"/> is <see cref="PremisParseStatus.Valid"/>.</summary>
    public PremisDocument? Document { get; init; }

    /// <summary>A short, human-readable reason, present on every non-<see cref="PremisParseStatus.Valid"/> outcome.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Status"/> is <see cref="PremisParseStatus.Valid"/>.</summary>
    public bool IsValid => Status == PremisParseStatus.Valid;


    /// <summary>Creates a successful result owning <paramref name="document"/>.</summary>
    /// <param name="document">The parsed document; ownership transfers to the result.</param>
    /// <returns>A <see cref="PremisParseStatus.Valid"/> result.</returns>
    public static PremisParseResult Valid(PremisDocument document) =>
        new() { Status = PremisParseStatus.Valid, Document = document };

    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="status">The failure status; must not be <see cref="PremisParseStatus.Valid"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    public static PremisParseResult Failed(PremisParseStatus status, string reason) =>
        new() { Status = status, FailureReason = reason };


    /// <summary>Disposes <see cref="Document"/>, when present.</summary>
    public void Dispose() => Document?.Dispose();
}


/// <summary>
/// Everything <see cref="ParsePremisDelegate"/> is given about one parse.
/// </summary>
/// <remarks>
/// The bounds travel in the context rather than being captured by the implementation, so a caller that varies them
/// varies them per call and a delegate instance carries no state of its own — the same discipline every context
/// record in this namespace applies.
/// </remarks>
[DebuggerDisplay("PremisParseContext: {Document.Length} octets")]
public sealed record PremisParseContext
{
    /// <summary>The document's octets. The caller retains ownership and disposes them.</summary>
    public required PooledMemory Document { get; init; }

    /// <summary>The bounds the parse applies.</summary>
    public PremisParseLimits Limits { get; init; } = PremisParseLimits.Conformant;
}


/// <summary>
/// Parses one preservation-metadata document's octets into the serialisation-agnostic
/// <see cref="PremisDocument"/> model — a <c>premis</c> element instance conformant to
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation.</strong> The document is XML, and this project stays
/// serialization-agnostic — it references neither an XML package nor <c>Verifiable.Json</c> — exactly as
/// <see cref="ParseMetsDelegate"/> does for the package manifest. A worked <c>System.Xml.Linq</c>-based
/// implementation is staged as a promotable example under the test project.
/// </para>
/// <para>
/// <strong>Fail-closed on structure, open on fixity and on vocabulary.</strong> Every particle the specification
/// makes mandatory is required in the returned model too; an implementation that cannot populate one MUST return
/// <see cref="PremisParseResult.Failed(PremisParseStatus, string)"/> rather than inventing a default. Every
/// <c>fixity</c> block MUST go through <see cref="EArkFixity.Read"/> and be carried with whatever status that
/// produces. Values from the externally hosted vocabularies — event types, relationship types and subtypes, agent
/// types, outcomes — MUST be carried as stated and never mapped onto a closed set, because those vocabularies are
/// open and a term added to one after this library was written is still conformant.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> An implementation MUST prohibit document type definitions (entity
/// expansion and external entity fetch), MUST NOT resolve any external resource the document names, and MUST
/// honour <see cref="PremisParseLimits"/>; the staged example walks the document with an explicit
/// <see cref="System.Collections.Generic.Stack{T}"/> rather than recursively, so the depth bound is a counter on
/// that stack.
/// </para>
/// <para>
/// <strong>The specification's subset is what round-trips.</strong> The model carries what the catalogue names; a
/// foreign document's elements outside it — a characterisation extension, a technical-metadata extension — are
/// read past rather than kept, so a document read and written again is equal as a model and not necessarily as
/// octets. A caller that has committed to a document's octets keeps the octets.
/// </para>
/// </remarks>
/// <param name="context">The document and the bounds to parse it under.</param>
/// <param name="pool">The memory pool the implementation rents fixity carriers from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The parse result.</returns>
public delegate ValueTask<PremisParseResult> ParsePremisDelegate(
    PremisParseContext context,
    BaseMemoryPool pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Why <see cref="EncodePremisDelegate"/> did, or did not, produce a preservation-metadata document.
/// </summary>
/// <remarks>
/// <see cref="Encoded"/> is deliberately not zero: a status that has not been computed must not read as a
/// successful encoding.
/// </remarks>
public enum PremisEncodeStatus
{
    /// <summary>No encoding has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The document was written.</summary>
    Encoded = 1,

    /// <summary>
    /// An entity the model carries states no identifier, which requirements <c>PM3</c>, <c>PM15</c>, <c>PM29</c>,
    /// <c>PM70</c>, <c>PM81</c> and <c>PM95</c> each make mandatory for their entity: an object, an agent, an
    /// event or a rights statement nothing can name cannot be referenced, and every link in this vocabulary is
    /// by identifier.
    /// </summary>
    MissingIdentifier = 2,

    /// <summary>
    /// The model carries a fixity this library cannot recompute and the context did not state that carrying it
    /// through is intended. See <see cref="PremisEncodeContext.AllowUnrecomputableFixity"/>.
    /// </summary>
    UnrecomputableFixity = 3
}


/// <summary>
/// The outcome of <see cref="EncodePremisDelegate"/>. On success it owns the produced octets; the caller disposes
/// them. On failure it owns nothing.
/// </summary>
[DebuggerDisplay("PremisEncodeResult: {Status}")]
public sealed record PremisEncodeResult: IDisposable
{
    /// <summary>The encoding outcome; <see cref="PremisEncodeStatus.Encoded"/> is the only success.</summary>
    public required PremisEncodeStatus Status { get; init; }

    /// <summary>
    /// The document's octets, tagged <see cref="EArkTags.PremisDocument"/>; non-<see langword="null"/> only when
    /// <see cref="Status"/> is <see cref="PremisEncodeStatus.Encoded"/>. These octets are what the package
    /// manifest's own fixity value over the document commits to, so a caller stores them verbatim.
    /// </summary>
    public PooledMemory? Document { get; init; }

    /// <summary>A short, human-readable reason, present on every non-<see cref="PremisEncodeStatus.Encoded"/> outcome.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Status"/> is <see cref="PremisEncodeStatus.Encoded"/>.</summary>
    public bool IsEncoded => Status == PremisEncodeStatus.Encoded;


    /// <summary>Creates a successful result owning <paramref name="document"/>.</summary>
    /// <param name="document">The produced octets; ownership transfers to the result.</param>
    /// <returns>A <see cref="PremisEncodeStatus.Encoded"/> result.</returns>
    public static PremisEncodeResult Encoded(PooledMemory document) =>
        new() { Status = PremisEncodeStatus.Encoded, Document = document };

    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="status">The failure status; must not be <see cref="PremisEncodeStatus.Encoded"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    public static PremisEncodeResult Failed(PremisEncodeStatus status, string reason) =>
        new() { Status = status, FailureReason = reason };


    /// <summary>Disposes <see cref="Document"/>, when present.</summary>
    public void Dispose() => Document?.Dispose();
}


/// <summary>
/// Everything <see cref="EncodePremisDelegate"/> is given about one encoding.
/// </summary>
[DebuggerDisplay("PremisEncodeContext: {Document.Objects.Count} objects")]
public sealed record PremisEncodeContext
{
    /// <summary>The document to write. The caller retains ownership and disposes it.</summary>
    public required PremisDocument Document { get; init; }

    /// <summary>
    /// Whether a fixity this library cannot recompute may be written through as the text it was read as.
    /// </summary>
    /// <remarks>
    /// <see langword="false"/> is the secure default, for the reason
    /// <see cref="MetsEncodeContext.AllowUnrecomputableFixity"/> states at length: neither specification imposes a
    /// minimum strength, so a writer that emitted whatever it was handed would keep emitting the weak algorithms
    /// the ecosystem already produces. Requirement <c>PREMIS-CHECKSUMS</c> is the one place either specification
    /// names a preferred algorithm, and it names one of the three this library writes.
    /// </remarks>
    public bool AllowUnrecomputableFixity { get; init; }
}


/// <summary>
/// Writes one <see cref="PremisDocument"/> as a preservation-metadata document conformant to
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation</strong>, for the same reason <see cref="ParsePremisDelegate"/>
/// ships none. The worked example staged under the test project validates what it writes against a schema stating
/// the specification's own catalogue.
/// </para>
/// <para>
/// <strong>The produced octets are what the package manifest commits to.</strong> A document written here is
/// referenced from a <c>digiprovMD/mdRef</c> whose <c>@CHECKSUM</c> is computed over exactly these octets, so a
/// caller stores what this seam returns, byte for byte, and never re-encodes a document it has already computed a
/// fixity over. The root element MUST declare the namespaces its content uses, which is the seam's responsibility
/// rather than the model's.
/// </para>
/// <para>
/// <strong>Faults are statuses, not exceptions.</strong> A seam is implemented by whoever supplies it, and making
/// exception behaviour part of the contract would make every implementation's failure mode part of it too.
/// </para>
/// </remarks>
/// <param name="context">The document to write and the fixity policy to write it under.</param>
/// <param name="pool">The memory pool the implementation rents the produced document's carrier from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The encoding result.</returns>
public delegate ValueTask<PremisEncodeResult> EncodePremisDelegate(
    PremisEncodeContext context,
    BaseMemoryPool pool,
    CancellationToken cancellationToken = default);
