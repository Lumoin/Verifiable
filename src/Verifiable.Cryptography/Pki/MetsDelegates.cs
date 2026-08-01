using System;
using System.Buffers;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The bounds a METS parse applies to a document it did not produce.
/// </summary>
/// <remarks>
/// A package arrives from wherever packages come from and its manifest is read before anything about it has been
/// verified, so every bound here exists to make a document that is hostile rather than merely large a refusal
/// instead of a resource exhaustion. The defaults are the ones <see cref="Conformant"/> states; they are wide
/// enough for the packages the reference corpus carries and for a package several orders of magnitude larger, and
/// no wider.
/// </remarks>
public sealed record MetsParseLimits
{
    /// <summary>The bounds a conformant package's METS documents fit inside.</summary>
    public static MetsParseLimits Conformant { get; } = new();

    /// <summary>The largest METS document, in octets, 64 MiB — a manifest carries one entry per file and a package may carry very many files.</summary>
    public int MaximumDocumentByteLength { get; init; } = 64 * 1024 * 1024;

    /// <summary>The largest number of <c>file</c> elements across every file group, 1 048 576.</summary>
    public int MaximumFiles { get; init; } = 1024 * 1024;

    /// <summary>The largest number of <c>fileGrp</c> elements, 4096 — the profile mandates three and adds one per representation.</summary>
    public int MaximumFileGroups { get; init; } = 4096;

    /// <summary>The largest number of <c>dmdSec</c>, <c>digiprovMD</c> and <c>rightsMD</c> elements each, 4096.</summary>
    public int MaximumMetadataSections { get; init; } = 4096;

    /// <summary>The largest number of <c>div</c> elements across every structural map, 65 536.</summary>
    public int MaximumDivisions { get; init; } = 64 * 1024;

    /// <summary>The largest number of <c>metsHdr/agent</c> elements, 256.</summary>
    public int MaximumAgents { get; init; } = 256;

    /// <summary>The largest number of <c>structMap</c> elements, 64 — the profile mandates one and admits an implementer's own beside it.</summary>
    public int MaximumStructuralMaps { get; init; } = 64;

    /// <summary>
    /// The largest number of characters any one attribute value or text node may occupy, 8192. It bounds
    /// identifiers, locations, labels and note text alike, because each of them is producer-controlled and none of
    /// them has a legitimate use at that length.
    /// </summary>
    public int MaximumTextLength { get; init; } = 8192;

    /// <summary>
    /// The deepest element nesting the document may reach, 128. Only <c>div</c> elements nest without bound in
    /// this vocabulary, so this bounds exactly the one place a producer controls the depth.
    /// </summary>
    public int MaximumElementDepth { get; init; } = 128;
}


/// <summary>
/// Why <see cref="ParseMetsDelegate"/> did, or did not, produce a <see cref="MetsDocument"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Valid"/> is deliberately not zero: a status that has not been computed must not read as a successful
/// parse.
/// </para>
/// <para>
/// <strong>There is no unsupported-algorithm status here, and that is deliberate.</strong> The manifest seam of
/// <see cref="ParseAsicManifestDelegate"/> refuses a digest algorithm it cannot compute, because a reference whose
/// digest nothing can recompute cannot take part in a comparison that specification makes unconditional. This
/// vocabulary is the opposite case: its <c>@CHECKSUMTYPE</c> enumeration admits MD5, CRC32 and Adler-32 as
/// first-class values, the reference material's own worked packages use MD5, and a reader that refused such a
/// document would refuse most of the corpus it exists to read. A fixity this library cannot recompute is therefore
/// carried as <see cref="EArkStatedFixity"/> with its reason — visible, never silently dropped — and what to do
/// about it is a validation rule's decision rather than the parser's.
/// </para>
/// </remarks>
public enum MetsParseStatus
{
    /// <summary>No parse has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The document parsed into a well-formed <see cref="MetsDocument"/>.</summary>
    Valid = 1,

    /// <summary>The document is not well-formed at all — malformed markup, truncated, or a root element that is not <c>mets</c>.</summary>
    Malformed = 2,

    /// <summary>
    /// A particle the profile requires was absent: <c>mets/@OBJID</c>, <c>mets/@TYPE</c>, <c>mets/@PROFILE</c>,
    /// the <c>metsHdr</c> element, its <c>@CREATEDATE</c> or <c>@csip:OAISPACKAGETYPE</c>, a <c>structMap</c>, its
    /// root <c>div</c>, or one of the mandatory attributes of a <c>file</c>, an <c>mdRef</c>, an <c>FLocat</c> or
    /// an <c>mptr</c>.
    /// </summary>
    MissingRequiredElement = 3,

    /// <summary>
    /// A value is present but is not of its declared type: an <c>xsd:dateTime</c> that does not parse, an
    /// <c>xsd:long</c> size that does not, or an <c>@ID</c> that is not an XML <c>NCName</c>. Distinct from
    /// <see cref="Malformed"/>: the markup is well-formed and it is the producer's value that is refused.
    /// </summary>
    MalformedValue = 4,

    /// <summary>The document exceeds one of <see cref="MetsParseLimits"/>' bounds.</summary>
    LimitExceeded = 5
}


/// <summary>
/// The outcome of <see cref="ParseMetsDelegate"/>. On success it owns a <see cref="MetsDocument"/> (and every
/// fixity carrier that document holds); the caller disposes it. On failure it owns nothing.
/// </summary>
[DebuggerDisplay("MetsParseResult: {Status}")]
public sealed record MetsParseResult: IDisposable
{
    /// <summary>The parse outcome; <see cref="MetsParseStatus.Valid"/> is the only success.</summary>
    public required MetsParseStatus Status { get; init; }

    /// <summary>The parsed document; non-<see langword="null"/> only when <see cref="Status"/> is <see cref="MetsParseStatus.Valid"/>.</summary>
    public MetsDocument? Document { get; init; }

    /// <summary>A short, human-readable reason, present on every non-<see cref="MetsParseStatus.Valid"/> outcome.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Status"/> is <see cref="MetsParseStatus.Valid"/>.</summary>
    public bool IsValid => Status == MetsParseStatus.Valid;


    /// <summary>Creates a successful result owning <paramref name="document"/>.</summary>
    /// <param name="document">The parsed document; ownership transfers to the result.</param>
    /// <returns>A <see cref="MetsParseStatus.Valid"/> result.</returns>
    public static MetsParseResult Valid(MetsDocument document) =>
        new() { Status = MetsParseStatus.Valid, Document = document };

    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="status">The failure status; must not be <see cref="MetsParseStatus.Valid"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    public static MetsParseResult Failed(MetsParseStatus status, string reason) =>
        new() { Status = status, FailureReason = reason };


    /// <summary>Disposes <see cref="Document"/>, when present.</summary>
    public void Dispose() => Document?.Dispose();
}


/// <summary>
/// Everything <see cref="ParseMetsDelegate"/> is given about one parse.
/// </summary>
/// <remarks>
/// The bounds travel in the context rather than being captured by the implementation, so a caller that varies them
/// varies them per call and a delegate instance carries no state of its own — the same discipline every context
/// record in this namespace applies.
/// </remarks>
[DebuggerDisplay("MetsParseContext: {Document.Length} octets")]
public sealed record MetsParseContext
{
    /// <summary>The METS document's octets. The caller retains ownership and disposes them.</summary>
    public required PooledMemory Document { get; init; }

    /// <summary>The bounds the parse applies.</summary>
    public MetsParseLimits Limits { get; init; } = MetsParseLimits.Conformant;
}


/// <summary>
/// Parses one METS document's octets into the serialisation-agnostic <see cref="MetsDocument"/> model — a package-
/// or representation-level <c>METS.xml</c> conformant to the METS profile of
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation.</strong> A METS document is XML, and this project stays
/// serialization-agnostic — it references neither an XML package nor <c>Verifiable.Json</c> — exactly as
/// <see cref="ParseAsicManifestDelegate"/> does for the container manifest and
/// <see cref="ParseTrustedListDelegate"/> for the Trusted List profile. A worked <c>System.Xml.Linq</c>-based
/// implementation, validated against the base METS schema and the extension schema the profile declares, is
/// staged as a promotable example under the test project.
/// </para>
/// <para>
/// <strong>Fail-closed on structure, open on fixity.</strong> Every particle the profile makes mandatory is
/// required in the returned model too (non-nullable, non-optional); an implementation that cannot populate one
/// MUST return <see cref="MetsParseResult.Failed(MetsParseStatus, string)"/> rather than inventing a default. The
/// one deliberate exception is the fixity pair, which MUST go through <see cref="EArkFixity.Read"/> and be carried
/// with whatever status that produces — see <see cref="MetsParseStatus"/> for why refusing it instead would refuse
/// most conformant packages. Every <c>@ID</c> MUST be checked with <see cref="MetsWellKnown.IsNCName"/>, which is
/// where clause 5.1's un-numbered identifier obligation lives.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> The document arrives from outside and nothing about the package has
/// been verified when it is read. An implementation MUST prohibit document type definitions (entity expansion and
/// external entity fetch), MUST NOT resolve any external resource named by <c>xsi:schemaLocation</c> or by any
/// reference in the document, MUST bound the nesting of <c>div</c> elements — the one particle of this vocabulary
/// whose depth a producer controls — and MUST honour <see cref="MetsParseLimits"/>; the staged example walks the
/// document with an explicit <see cref="System.Collections.Generic.Stack{T}"/> rather than recursively, so the
/// depth bound is a counter on that stack.
/// </para>
/// <para>
/// <strong>The profile's subset is what round-trips.</strong> The model carries what the requirement catalogue
/// names; a foreign document's attributes outside it are read past rather than kept, so a document read and
/// written again is equal as a model and not necessarily as octets. A caller that has committed to a document's
/// octets — because a fixity value or an evidence record covers them — keeps the octets.
/// </para>
/// </remarks>
/// <param name="context">The document and the bounds to parse it under.</param>
/// <param name="pool">The memory pool the implementation rents fixity carriers from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The parse result.</returns>
public delegate ValueTask<MetsParseResult> ParseMetsDelegate(
    MetsParseContext context,
    BaseMemoryPool pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Why <see cref="EncodeMetsDelegate"/> did, or did not, produce a METS document.
/// </summary>
/// <remarks>
/// <see cref="Encoded"/> is deliberately not zero: a status that has not been computed must not read as a
/// successful encoding.
/// </remarks>
public enum MetsEncodeStatus
{
    /// <summary>No encoding has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The document was written.</summary>
    Encoded = 1,

    /// <summary>
    /// The model carries no structural map, which requirement <c>CSIP80</c> forbids: a METS document has one or
    /// more, and the base vocabulary makes <c>structMap</c> its only mandatory section.
    /// </summary>
    NoStructuralMap = 2,

    /// <summary>
    /// An identifier the model carries is not an XML <c>NCName</c>, so writing it would produce a document no
    /// conformant reader can accept. See <see cref="MetsWellKnown.IsNCName"/>.
    /// </summary>
    InvalidIdentifier = 3,

    /// <summary>
    /// The model carries a fixity this library cannot recompute and the context did not state that carrying it
    /// through is intended. See <see cref="MetsEncodeContext.AllowUnrecomputableFixity"/>.
    /// </summary>
    UnrecomputableFixity = 4
}


/// <summary>
/// The outcome of <see cref="EncodeMetsDelegate"/>. On success it owns the produced octets; the caller disposes
/// them. On failure it owns nothing.
/// </summary>
[DebuggerDisplay("MetsEncodeResult: {Status}")]
public sealed record MetsEncodeResult: IDisposable
{
    /// <summary>The encoding outcome; <see cref="MetsEncodeStatus.Encoded"/> is the only success.</summary>
    public required MetsEncodeStatus Status { get; init; }

    /// <summary>
    /// The document's octets, tagged <see cref="EArkTags.MetsDocument"/>; non-<see langword="null"/> only when
    /// <see cref="Status"/> is <see cref="MetsEncodeStatus.Encoded"/>. These octets are what a fixity value or an
    /// evidence record over the manifest commits to, so a caller stores them verbatim.
    /// </summary>
    public PooledMemory? Document { get; init; }

    /// <summary>A short, human-readable reason, present on every non-<see cref="MetsEncodeStatus.Encoded"/> outcome.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Status"/> is <see cref="MetsEncodeStatus.Encoded"/>.</summary>
    public bool IsEncoded => Status == MetsEncodeStatus.Encoded;


    /// <summary>Creates a successful result owning <paramref name="document"/>.</summary>
    /// <param name="document">The produced octets; ownership transfers to the result.</param>
    /// <returns>An <see cref="MetsEncodeStatus.Encoded"/> result.</returns>
    public static MetsEncodeResult Encoded(PooledMemory document) =>
        new() { Status = MetsEncodeStatus.Encoded, Document = document };

    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="status">The failure status; must not be <see cref="MetsEncodeStatus.Encoded"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    public static MetsEncodeResult Failed(MetsEncodeStatus status, string reason) =>
        new() { Status = status, FailureReason = reason };


    /// <summary>Disposes <see cref="Document"/>, when present.</summary>
    public void Dispose() => Document?.Dispose();
}


/// <summary>
/// Everything <see cref="EncodeMetsDelegate"/> is given about one encoding.
/// </summary>
[DebuggerDisplay("MetsEncodeContext: {Document.ObjectIdentifier,nq}")]
public sealed record MetsEncodeContext
{
    /// <summary>The document to write. The caller retains ownership and disposes it.</summary>
    public required MetsDocument Document { get; init; }

    /// <summary>
    /// Whether a fixity this library cannot recompute may be written through as the text it was read as.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see langword="false"/> is the secure default and the reason it is the default is that nothing else in the
    /// specification supplies one. Neither the base vocabulary nor the profile imposes a minimum strength on
    /// <c>@CHECKSUMTYPE</c> — MD5, CRC32 and Adler-32 are as schema-valid as SHA-256, and the reference material's
    /// own worked packages use MD5 — so a writer that emitted whatever it was handed would emit MD5 fixity for as
    /// long as the ecosystem keeps producing it. What this library writes states the SHA-2 family and nothing
    /// else.
    /// </para>
    /// <para>
    /// <see langword="true"/> is the documented departure, and it has exactly one honest use: writing back a
    /// document that was read, where changing a fixity value would mean asserting a digest the writer did not
    /// compute over content it may not even hold. A caller that states it is stating that it is preserving
    /// somebody else's assertion, not making one.
    /// </para>
    /// </remarks>
    public bool AllowUnrecomputableFixity { get; init; }
}


/// <summary>
/// Writes one <see cref="MetsDocument"/> as a METS document conformant to the METS profile of
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation</strong>, for the same reason <see cref="ParseMetsDelegate"/>
/// ships none. The worked example staged under the test project validates what it writes against the base METS
/// schema and the extension schema the profile declares.
/// </para>
/// <para>
/// <strong>The produced octets are what everything above commits to.</strong> A package's own fixity values, an
/// evidence record over the package, and an archive time-stamp chain all cover the octets of this document as it
/// was stored — so a caller stores what this seam returns, byte for byte, and never re-encodes a document it has
/// already committed to. The root element MUST declare every namespace the document's content uses, which is a
/// requirement of the profile's own prose ("the METS document's root <c>mets</c> element must define all of the
/// relevant namespaces") and a responsibility of the seam rather than of the model.
/// </para>
/// <para>
/// <strong>Faults are statuses, not exceptions.</strong> A seam is implemented by whoever supplies it, and making
/// exception behaviour part of the contract would make every implementation's failure mode part of it too. The
/// library-side refusals of a model that cannot become a conformant document — an algorithm with no conformant
/// checksum-type name, a digest of the wrong length — are raised where the model is built, by
/// <see cref="EArkRecomputableFixity"/>'s constructor, before this seam is reached.
/// </para>
/// </remarks>
/// <param name="context">The document to write and the fixity policy to write it under.</param>
/// <param name="pool">The memory pool the implementation rents the produced document's carrier from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The encoding result.</returns>
public delegate ValueTask<MetsEncodeResult> EncodeMetsDelegate(
    MetsEncodeContext context,
    BaseMemoryPool pool,
    CancellationToken cancellationToken = default);
