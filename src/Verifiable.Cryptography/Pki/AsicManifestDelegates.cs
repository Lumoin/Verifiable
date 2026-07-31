using System;
using System.Buffers;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The bounds a manifest parse applies to a document it did not produce.
/// </summary>
/// <remarks>
/// A manifest arrives inside a container someone else built, so every bound here exists to make a document
/// that is hostile rather than merely large a refusal instead of a resource exhaustion. The defaults are the
/// ones <see cref="Conformant"/> states; they are wide enough for any container
/// <see cref="AsicZipReadLimits.Conformant"/> admits and no wider.
/// </remarks>
public sealed record AsicManifestParseLimits
{
    /// <summary>The bounds a conformant container's manifests fit inside.</summary>
    public static AsicManifestParseLimits Conformant { get; } = new();

    /// <summary>
    /// The largest manifest document, in octets, 4 MiB. A manifest holds one reference per file object, and
    /// <see cref="AsicZipReadLimits.MaximumEntryCount"/> bounds how many of those a container has.
    /// </summary>
    public int MaximumDocumentByteLength { get; init; } = 4 * 1024 * 1024;

    /// <summary>
    /// The largest number of <c>DataObjectReference</c> elements, 4096 — the same bound the container reader
    /// puts on entries, since Annex A.4.2 admits one reference per referenced file object and a container holds
    /// no more file objects than that.
    /// </summary>
    public int MaximumDataObjectReferences { get; init; } = 4096;

    /// <summary>The largest number of <c>Extension</c> elements in any one extensions list, 64.</summary>
    public int MaximumExtensions { get; init; } = 64;

    /// <summary>The largest number of octets one <c>Extension</c> element may serialise to, 64 KiB.</summary>
    public int MaximumExtensionByteLength { get; init; } = 64 * 1024;

    /// <summary>
    /// The largest number of characters a <c>URI</c> attribute may occupy, taken from
    /// <see cref="AsicContainerUri.DefaultMaximumLength"/> so that a reference this parse accepts is one the
    /// resolver will also accept.
    /// </summary>
    public int MaximumUriLength { get; init; } = AsicContainerUri.DefaultMaximumLength;

    /// <summary>
    /// The deepest element nesting the document may reach, 64. Only an <c>Extension</c>'s content can nest at
    /// all — every other particle of Annex A.4.2's schema is at a fixed depth — so this bounds exactly the one
    /// place a producer controls the depth.
    /// </summary>
    public int MaximumElementDepth { get; init; } = 64;
}


/// <summary>
/// Why <see cref="ParseAsicManifestDelegate"/> did, or did not, produce an <see cref="AsicManifest"/>.
/// </summary>
/// <remarks>
/// <see cref="Valid"/> is deliberately not zero: a status that has not been computed must not read as a
/// successful parse.
/// </remarks>
public enum AsicManifestParseStatus
{
    /// <summary>No parse has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The document parsed into a well-formed <see cref="AsicManifest"/>.</summary>
    Valid = 1,

    /// <summary>The document is not well-formed at all — malformed markup, truncated, or a root element that is not <c>ASiCManifest</c>.</summary>
    Malformed = 2,

    /// <summary>
    /// A particle Annex A.4.2's schema requires was absent: the <c>SigReference</c> element, its <c>URI</c>
    /// attribute, a <c>DataObjectReference</c>, one of its <c>ds:DigestMethod</c>/<c>ds:DigestValue</c>
    /// children, or a <c>Critical</c> attribute on an <c>Extension</c>.
    /// </summary>
    MissingRequiredElement = 3,

    /// <summary>
    /// A <c>ds:DigestMethod</c> named an algorithm this library will not compute. Distinct from
    /// <see cref="Malformed"/>: the document is well-formed and its producer's choice is what is refused —
    /// the same distinction <see cref="TimestampTokenInfoStatus.UnsupportedMessageImprintAlgorithm"/> makes.
    /// </summary>
    UnsupportedDigestAlgorithm = 4,

    /// <summary>A <c>ds:DigestValue</c> is not base64, or does not hold as many octets as the algorithm it is stated under produces.</summary>
    DigestValueMalformed = 5,

    /// <summary>
    /// A <c>URI</c> attribute does not resolve to a container entry name — see
    /// <see cref="AsicContainerUri.Resolve(string?)"/> and Annex A.6 item 3, "References to data objects
    /// outside the container shall not be allowed".
    /// </summary>
    InvalidUriReference = 6,

    /// <summary>The document exceeds one of <see cref="AsicManifestParseLimits"/>' bounds.</summary>
    LimitExceeded = 7
}


/// <summary>
/// The outcome of <see cref="ParseAsicManifestDelegate"/>. On success it owns an <see cref="AsicManifest"/>
/// (and every digest and extension that manifest carries); the caller disposes it. On failure it owns nothing.
/// </summary>
[DebuggerDisplay("AsicManifestParseResult: {Status}")]
public sealed record AsicManifestParseResult: IDisposable
{
    /// <summary>The parse outcome; <see cref="AsicManifestParseStatus.Valid"/> is the only success.</summary>
    public required AsicManifestParseStatus Status { get; init; }

    /// <summary>The parsed manifest; non-<see langword="null"/> only when <see cref="Status"/> is <see cref="AsicManifestParseStatus.Valid"/>.</summary>
    public AsicManifest? Manifest { get; init; }

    /// <summary>A short, human-readable reason, present on every non-<see cref="AsicManifestParseStatus.Valid"/> outcome.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Status"/> is <see cref="AsicManifestParseStatus.Valid"/>.</summary>
    public bool IsValid => Status == AsicManifestParseStatus.Valid;


    /// <summary>Creates a successful result owning <paramref name="manifest"/>.</summary>
    /// <param name="manifest">The parsed manifest; ownership transfers to the result.</param>
    /// <returns>A <see cref="AsicManifestParseStatus.Valid"/> result.</returns>
    public static AsicManifestParseResult Valid(AsicManifest manifest) =>
        new() { Status = AsicManifestParseStatus.Valid, Manifest = manifest };

    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="status">The failure status; must not be <see cref="AsicManifestParseStatus.Valid"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    public static AsicManifestParseResult Failed(AsicManifestParseStatus status, string reason) =>
        new() { Status = status, FailureReason = reason };


    /// <summary>Disposes <see cref="Manifest"/>, when present.</summary>
    public void Dispose() => Manifest?.Dispose();
}


/// <summary>
/// Everything <see cref="ParseAsicManifestDelegate"/> is given about one parse.
/// </summary>
/// <remarks>
/// The bounds travel in the context rather than being captured by the implementation, so a caller that varies
/// them varies them per call and a delegate instance carries no state of its own — the same discipline every
/// context record in this namespace applies.
/// </remarks>
[DebuggerDisplay("AsicManifestParseContext: {Document.Length} octets")]
public sealed record AsicManifestParseContext
{
    /// <summary>The manifest document's octets. The caller retains ownership and disposes them.</summary>
    public required PooledMemory Document { get; init; }

    /// <summary>The bounds the parse applies.</summary>
    public AsicManifestParseLimits Limits { get; init; } = AsicManifestParseLimits.Conformant;
}


/// <summary>
/// Parses one manifest document's octets into the serialisation-agnostic <see cref="AsicManifest"/> model —
/// an <c>ASiCManifest</c> element instance conformant to
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.4.2, in whichever of its three roles.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation.</strong> The manifest is XML, and this project stays
/// serialization-agnostic — it references neither an XML package nor <c>Verifiable.Json</c> — exactly as
/// <see cref="ParseTrustedListDelegate"/> does for the Trusted List profile. A worked
/// <c>System.Xml.Linq</c>-based implementation, validated against the schema attachment Annex A.3 makes
/// normative, is staged as a promotable example under the test project.
/// </para>
/// <para>
/// <strong>Fail-closed on structure.</strong> Every particle Annex A.4.2 requires is required in the returned
/// model too (non-nullable, non-optional); an implementation that cannot populate one MUST return
/// <see cref="AsicManifestParseResult.Failed(AsicManifestParseStatus, string)"/> rather than inventing a
/// default. A <c>ds:DigestMethod</c> naming an algorithm
/// <see cref="XmlSignatureWellKnown.DigestAlgorithmFromUri"/> does not resolve MUST be refused as
/// <see cref="AsicManifestParseStatus.UnsupportedDigestAlgorithm"/> rather than carried as text: a reference
/// whose digest nothing can recompute cannot take part in the clause 4.4.4.2 item d comparison, which is
/// unconditional. Every <c>URI</c> attribute MUST go through
/// <see cref="AsicContainerUri.Resolve(string?, int)"/>, which is where Annex A.6's
/// resolve-against-the-container-root rule lives.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> The document arrives inside a container this library did not
/// produce. An implementation MUST prohibit document type definitions (entity expansion and external entity
/// fetch), MUST bound the nesting of an <c>Extension</c>'s content — the one particle of the schema whose
/// depth a producer controls — and MUST honour <see cref="AsicManifestParseLimits"/>; the staged example walks
/// the document with an explicit <see cref="System.Collections.Generic.Stack{T}"/> rather than recursively, so
/// the depth bound is a counter on that stack.
/// </para>
/// </remarks>
/// <param name="context">The document and the bounds to parse it under.</param>
/// <param name="pool">The memory pool the implementation rents digest and extension carriers from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The parse result.</returns>
public delegate ValueTask<AsicManifestParseResult> ParseAsicManifestDelegate(
    AsicManifestParseContext context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Why <see cref="EncodeAsicManifestDelegate"/> did, or did not, produce a manifest document.
/// </summary>
/// <remarks>
/// <see cref="Encoded"/> is deliberately not zero: a status that has not been computed must not read as a
/// successful encoding.
/// </remarks>
public enum AsicManifestEncodeStatus
{
    /// <summary>No encoding has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The manifest was written.</summary>
    Encoded = 1,

    /// <summary>
    /// The manifest carries no <c>DataObjectReference</c>, which Annex A.4.1 item 2 forbids: "The
    /// <c>ASiCManifest</c> element shall reference one or more data files".
    /// </summary>
    NoDataObjectReferences = 2,

    /// <summary>A digest algorithm has no registered <c>ds:DigestMethod</c> URI, so no conformant document can name it.</summary>
    UnsupportedDigestAlgorithm = 3,

    /// <summary>A digest does not hold as many octets as the algorithm it is stated under produces.</summary>
    DigestValueMalformed = 4,

    /// <summary>A <c>URI</c> attribute value does not name a container entry, so writing it would state a reference Annex A.6 item 3 forbids.</summary>
    InvalidUriReference = 5,

    /// <summary>An <c>Extension</c>'s carried content is not something the seam can write back into the document.</summary>
    ExtensionMalformed = 6
}


/// <summary>
/// The outcome of <see cref="EncodeAsicManifestDelegate"/>. On success it owns the produced octets; the caller
/// disposes them. On failure it owns nothing.
/// </summary>
[DebuggerDisplay("AsicManifestEncodeResult: {Status}")]
public sealed record AsicManifestEncodeResult: IDisposable
{
    /// <summary>The encoding outcome; <see cref="AsicManifestEncodeStatus.Encoded"/> is the only success.</summary>
    public required AsicManifestEncodeStatus Status { get; init; }

    /// <summary>
    /// The manifest document's octets, tagged <see cref="AsicTags.Manifest"/>; non-<see langword="null"/> only
    /// when <see cref="Status"/> is <see cref="AsicManifestEncodeStatus.Encoded"/>. These octets are what a
    /// detached signature or a time-stamp token commits to, so a caller stores them verbatim.
    /// </summary>
    public PooledMemory? Document { get; init; }

    /// <summary>A short, human-readable reason, present on every non-<see cref="AsicManifestEncodeStatus.Encoded"/> outcome.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Status"/> is <see cref="AsicManifestEncodeStatus.Encoded"/>.</summary>
    public bool IsEncoded => Status == AsicManifestEncodeStatus.Encoded;


    /// <summary>Creates a successful result owning <paramref name="document"/>.</summary>
    /// <param name="document">The produced octets; ownership transfers to the result.</param>
    /// <returns>An <see cref="AsicManifestEncodeStatus.Encoded"/> result.</returns>
    public static AsicManifestEncodeResult Encoded(PooledMemory document) =>
        new() { Status = AsicManifestEncodeStatus.Encoded, Document = document };

    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="status">The failure status; must not be <see cref="AsicManifestEncodeStatus.Encoded"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    public static AsicManifestEncodeResult Failed(AsicManifestEncodeStatus status, string reason) =>
        new() { Status = status, FailureReason = reason };


    /// <summary>Disposes <see cref="Document"/>, when present.</summary>
    public void Dispose() => Document?.Dispose();
}


/// <summary>
/// Everything <see cref="EncodeAsicManifestDelegate"/> is given about one encoding.
/// </summary>
[DebuggerDisplay("AsicManifestEncodeContext: {Manifest.DataObjectReferences.Count} data objects")]
public sealed record AsicManifestEncodeContext
{
    /// <summary>The manifest to write. The caller retains ownership and disposes it.</summary>
    public required AsicManifest Manifest { get; init; }
}


/// <summary>
/// Writes one <see cref="AsicManifest"/> as a manifest document conformant to
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.4.2.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation</strong>, for the same reason
/// <see cref="ParseAsicManifestDelegate"/> ships none. The worked example staged under the test project
/// validates what it writes against the schema attachment Annex A.3 makes normative.
/// </para>
/// <para>
/// <strong>The produced octets are the signed object.</strong> Annex A.4.1 states that a CAdES object or a
/// time-stamp token named by <c>SigReference</c> "shall apply to the file containing the <c>ASiCManifest</c>
/// element", and Annex A.7 item 2 a) renames a previous archive manifest while its content stays exactly as it
/// was. A caller therefore stores what this seam returns, byte for byte, and never re-encodes a manifest it
/// has already committed to: two encodings of one model that differ in a single octet of whitespace are two
/// different signed objects.
/// </para>
/// <para>
/// <strong>Faults are statuses, not exceptions.</strong> A seam is implemented by whoever supplies it, and
/// making exception behaviour part of the contract would make every implementation's failure mode part of it
/// too. The library-side refusals of a model that cannot become a conformant container — the ones
/// <see cref="AsicZipAuthoringException"/> is the precedent for — are raised by the composition layer that
/// builds the manifest, before this seam is reached.
/// </para>
/// </remarks>
/// <param name="context">The manifest to write.</param>
/// <param name="pool">The memory pool the implementation rents the produced document's carrier from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The encoding result.</returns>
public delegate ValueTask<AsicManifestEncodeResult> EncodeAsicManifestDelegate(
    AsicManifestEncodeContext context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
