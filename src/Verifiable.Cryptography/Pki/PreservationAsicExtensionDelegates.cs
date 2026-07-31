using System;
using System.Buffers;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The bounds one container-extension payload of clause 5.5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> is read within.
/// </summary>
/// <remarks>
/// <strong>The specification states no numeric bound anywhere in clause 5.5</strong>, so every value here is this
/// library's, chosen so that a conformant extension passes and an extension built to exhaust a reader does not.
/// An extension arrives inside a container a peer produced, which makes every one of these an attacker-input
/// bound in the sense <see cref="AsicManifestParseLimits"/> already uses the term.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationAsicExtensionLimits
{
    /// <summary>The bounds a conformant extension is read within.</summary>
    public static PreservationAsicExtensionLimits Conformant { get; } = new();

    /// <summary>The largest number of octets one <c>Extension</c> element is read from, 1 048 576.</summary>
    /// <remarks>
    /// A validation report is a preservation object and can legitimately be large, which is why this bound is a
    /// megabyte rather than the few kilobytes the other six payloads need.
    /// </remarks>
    public int MaximumExtensionByteLength { get; init; } = 1_048_576;

    /// <summary>The largest number of characters one identifier, submitter or reference value is read with, 4 096.</summary>
    public int MaximumValueLength { get; init; } = 4_096;

    /// <summary>The largest nesting depth an implementation reads inside one extension, 16.</summary>
    /// <remarks>
    /// The deepest payload this vocabulary states is three elements — an <c>Extension</c>, a <c>ContainerID</c>
    /// and its <c>POID</c> — so the bound leaves room for a producer's own wrapping while staying a counter
    /// rather than a stack.
    /// </remarks>
    public int MaximumDepth { get; init; } = 16;


    /// <summary>A short debugger string showing the three bounds.</summary>
    private string DebuggerDisplay =>
        $"PreservationAsicExtensionLimits({MaximumExtensionByteLength} octets, {MaximumValueLength} characters, depth {MaximumDepth})";
}


/// <summary>
/// Why <see cref="EncodePreservationAsicExtensionDelegate"/> did, or did not, produce an extension.
/// </summary>
/// <remarks>
/// <see cref="Encoded"/> is deliberately not zero: a status that has not been computed must not read as a
/// successful encoding.
/// </remarks>
public enum PreservationAsicExtensionEncodeStatus
{
    /// <summary>No encoding has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The extension was written.</summary>
    Encoded = 1,

    /// <summary>The payload is one this implementation does not write.</summary>
    PayloadNotSupported = 2,

    /// <summary>
    /// The payload is a canonicalization method and the caller stated no namespace for it. The element is
    /// declared in a schema of the external base specification, so an implementation cannot write it under a
    /// namespace this document states — there is none.
    /// </summary>
    CanonicalizationMethodNamespaceNotStated = 3,

    /// <summary>A value the payload's own clause requires was absent, so no conformant extension could be written.</summary>
    MissingRequiredElement = 4,

    /// <summary>The payload exceeds one of <see cref="PreservationAsicExtensionLimits"/>' bounds.</summary>
    LimitExceeded = 5
}


/// <summary>
/// The outcome of <see cref="EncodePreservationAsicExtensionDelegate"/>. On success it owns the produced
/// extension; the caller disposes it, usually by disposing the manifest it was placed into. On failure it owns
/// nothing.
/// </summary>
[DebuggerDisplay("PreservationAsicExtensionEncodeResult: {Status}")]
public sealed record PreservationAsicExtensionEncodeResult: IDisposable
{
    /// <summary>The encoding outcome; <see cref="PreservationAsicExtensionEncodeStatus.Encoded"/> is the only success.</summary>
    public required PreservationAsicExtensionEncodeStatus Status { get; init; }

    /// <summary>The written extension; non-<see langword="null"/> only when <see cref="Status"/> is <see cref="PreservationAsicExtensionEncodeStatus.Encoded"/>.</summary>
    public AsicManifestExtension? Extension { get; init; }

    /// <summary>A short, human-readable reason, present on every outcome that is not an encoding.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Status"/> is <see cref="PreservationAsicExtensionEncodeStatus.Encoded"/>.</summary>
    public bool IsEncoded => Status == PreservationAsicExtensionEncodeStatus.Encoded;


    /// <summary>Creates a successful result owning <paramref name="extension"/>.</summary>
    /// <param name="extension">The written extension; ownership transfers to the result.</param>
    /// <returns>An <see cref="PreservationAsicExtensionEncodeStatus.Encoded"/> result.</returns>
    public static PreservationAsicExtensionEncodeResult Encoded(AsicManifestExtension extension) =>
        new() { Status = PreservationAsicExtensionEncodeStatus.Encoded, Extension = extension };


    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="status">The failure status; must not be <see cref="PreservationAsicExtensionEncodeStatus.Encoded"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    public static PreservationAsicExtensionEncodeResult Failed(PreservationAsicExtensionEncodeStatus status, string reason) =>
        new() { Status = status, FailureReason = reason };


    /// <summary>Disposes <see cref="Extension"/>, when present.</summary>
    public void Dispose() => Extension?.Dispose();
}


/// <summary>
/// Everything <see cref="EncodePreservationAsicExtensionDelegate"/> is given about one encoding.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> The caller retains ownership of <see cref="Payload"/> and disposes it; the written
/// extension is the result's.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationAsicExtensionEncodeContext
{
    /// <summary>The payload to write.</summary>
    public required PreservationAsicExtensionPayload Payload { get; init; }

    /// <summary>
    /// The value of the <c>Critical</c> attribute to write, or <see langword="null"/> to write the value the
    /// payload's own criticality clause recommends
    /// (<see cref="PreservationAsicExtensionWellKnown.IsCriticalRecommended"/>).
    /// </summary>
    /// <remarks>
    /// The default is the recommendation because a producer that states nothing should produce what clause 5.5
    /// asks for; a producer departing from it has to say so, which is what makes the departure visible on the
    /// wire and in this member.
    /// </remarks>
    public bool? Critical { get; init; }

    /// <summary>
    /// The namespace to write a canonicalization method under, or <see langword="null"/> when the payload is one
    /// of the six this document's own schema declares.
    /// </summary>
    public string? CanonicalizationMethodNamespace { get; init; }

    /// <summary>The bounds the encoding applies before writing anything.</summary>
    public PreservationAsicExtensionLimits Limits { get; init; } = PreservationAsicExtensionLimits.Conformant;


    /// <summary>A short debugger string showing what is written and how.</summary>
    private string DebuggerDisplay =>
        $"PreservationAsicExtensionEncodeContext({Payload.Kind}, critical {Critical?.ToString() ?? "as recommended"})";
}


/// <summary>
/// Writes one container-extension payload of clause 5.5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> as an <c>Extension</c> element of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.4.2.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation.</strong> An <c>Extension</c>'s content is XML and this project
/// stays serialization-agnostic — it references no XML package — exactly as
/// <see cref="EncodeAsicManifestDelegate"/> and <see cref="EncodePreservationMessageDelegate"/> already do for
/// their own documents. A worked implementation is staged as a promotable example under the test project.
/// </para>
/// <para>
/// <strong>What an implementation writes.</strong> The element names are
/// <see cref="PreservationAsicExtensionWellKnown"/>'s and, for the six this document declares, the namespace is
/// <see cref="PreservationWellKnown.PreservationNamespace"/>; the seventh is written under the namespace the
/// context states and refused when it states none, because this document declares no namespace for it. The
/// produced <see cref="AsicManifestExtension"/> carries the whole element's octets and names its first child, so
/// a reader can classify it with <see cref="PreservationAsicExtensionWellKnown.KindOf(AsicManifestExtensionName?)"/>
/// without parsing it again.
/// </para>
/// </remarks>
/// <param name="context">The payload to write and how to write it.</param>
/// <param name="pool">The memory pool the implementation rents the extension's carrier from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The encoding result.</returns>
public delegate ValueTask<PreservationAsicExtensionEncodeResult> EncodePreservationAsicExtensionDelegate(
    PreservationAsicExtensionEncodeContext context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Why <see cref="ParsePreservationAsicExtensionDelegate"/> did, or did not, produce a payload.
/// </summary>
/// <remarks>
/// <see cref="Valid"/> is deliberately not zero: a status that has not been computed must not read as a
/// successful parse.
/// </remarks>
public enum PreservationAsicExtensionParseStatus
{
    /// <summary>No parse has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The extension carried one of the seven payloads and it was read.</summary>
    Valid = 1,

    /// <summary>The extension's octets are not well-formed markup at all.</summary>
    Malformed = 2,

    /// <summary>
    /// The extension is well-formed but carries no payload this vocabulary names. This is not a defect: Annex
    /// A.4.2 admits arbitrary content in an <c>Extension</c>, and what a consumer does about an unrecognised one
    /// is <see cref="AsicManifestExtensionPolicy"/>'s answer, not this seam's.
    /// </summary>
    PayloadNotRecognized = 3,

    /// <summary>A particle the payload's own clause requires was absent.</summary>
    MissingRequiredElement = 4,

    /// <summary>A value is present but is not of the form its own clause states — a period that is not a date, a reference that is not a reference.</summary>
    MalformedValue = 5,

    /// <summary>The extension exceeds one of <see cref="PreservationAsicExtensionLimits"/>' bounds.</summary>
    LimitExceeded = 6
}


/// <summary>
/// The outcome of <see cref="ParsePreservationAsicExtensionDelegate"/>. On success it owns the payload and
/// anything the payload owns; the caller disposes it. On failure it owns nothing.
/// </summary>
[DebuggerDisplay("PreservationAsicExtensionParseResult: {Status}")]
public sealed record PreservationAsicExtensionParseResult: IDisposable
{
    /// <summary>The parse outcome; <see cref="PreservationAsicExtensionParseStatus.Valid"/> is the only success.</summary>
    public required PreservationAsicExtensionParseStatus Status { get; init; }

    /// <summary>The payload read; non-<see langword="null"/> only when <see cref="Status"/> is <see cref="PreservationAsicExtensionParseStatus.Valid"/>.</summary>
    public PreservationAsicExtensionPayload? Payload { get; init; }

    /// <summary>
    /// The criticality the extension stated beside the recommendation of the payload's own clause; stated only on
    /// a valid parse, so a caller reads the departure from the same result as the value.
    /// </summary>
    public PreservationAsicExtensionCriticality Criticality { get; init; }

    /// <summary>A short, human-readable reason, present on every outcome that is not a valid parse.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Status"/> is <see cref="PreservationAsicExtensionParseStatus.Valid"/>.</summary>
    public bool IsValid => Status == PreservationAsicExtensionParseStatus.Valid;


    /// <summary>Creates a successful result owning <paramref name="payload"/>.</summary>
    /// <param name="payload">The payload read; ownership transfers to the result.</param>
    /// <param name="criticality">What the extension stated about its criticality beside what its clause recommends.</param>
    /// <returns>A <see cref="PreservationAsicExtensionParseStatus.Valid"/> result.</returns>
    public static PreservationAsicExtensionParseResult Valid(
        PreservationAsicExtensionPayload payload,
        PreservationAsicExtensionCriticality criticality) =>
        new() { Status = PreservationAsicExtensionParseStatus.Valid, Payload = payload, Criticality = criticality };


    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="status">The failure status; must not be <see cref="PreservationAsicExtensionParseStatus.Valid"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    public static PreservationAsicExtensionParseResult Failed(PreservationAsicExtensionParseStatus status, string reason) =>
        new() { Status = status, FailureReason = reason };


    /// <summary>Disposes <see cref="Payload"/>, when present.</summary>
    public void Dispose() => Payload?.Dispose();
}


/// <summary>
/// Everything <see cref="ParsePreservationAsicExtensionDelegate"/> is given about one parse.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> The caller retains ownership of <see cref="Extension"/> — which is normally owned
/// by the manifest that carried it — and the payload read is the result's.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationAsicExtensionParseContext
{
    /// <summary>The extension a manifest or a data object reference carried.</summary>
    public required AsicManifestExtension Extension { get; init; }

    /// <summary>
    /// The namespace a canonicalization method is recognised under, or <see langword="null"/> to recognise only
    /// the six extensions this document's own schema declares.
    /// </summary>
    public string? CanonicalizationMethodNamespace { get; init; }

    /// <summary>The bounds the parse applies.</summary>
    public PreservationAsicExtensionLimits Limits { get; init; } = PreservationAsicExtensionLimits.Conformant;


    /// <summary>A short debugger string showing what is being read.</summary>
    private string DebuggerDisplay =>
        $"PreservationAsicExtensionParseContext({Extension.ElementName ?? "text"}, {Extension.Content.Length} octets)";
}


/// <summary>
/// Reads one container-extension payload of clause 5.5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> out of an <c>Extension</c> element.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation</strong>, for the reason
/// <see cref="EncodePreservationAsicExtensionDelegate"/> gives. A worked implementation is staged as a promotable
/// example under the test project.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> An extension arrives inside a container a peer produced. An
/// implementation MUST prohibit document type definitions — entity expansion and external entity fetch — MUST
/// honour <see cref="PreservationAsicExtensionParseContext.Limits"/>, and MUST walk the element with an explicit
/// <see cref="System.Collections.Generic.Stack{T}"/> rather than recursively, so the depth bound is a counter
/// rather than a stack overflow.
/// </para>
/// <para>
/// <strong>An unrecognised extension is not an error.</strong> Annex A.4.2 of the container specification admits
/// arbitrary content, so an implementation answers
/// <see cref="PreservationAsicExtensionParseStatus.PayloadNotRecognized"/> and lets
/// <see cref="AsicManifestExtensionPolicy"/> decide whether the consumer may proceed — which is the one place
/// this library answers that question.
/// </para>
/// </remarks>
/// <param name="context">The extension to read and the bounds to read it under.</param>
/// <param name="pool">The memory pool the implementation rents a payload's carriers from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The parse result.</returns>
public delegate ValueTask<PreservationAsicExtensionParseResult> ParsePreservationAsicExtensionDelegate(
    PreservationAsicExtensionParseContext context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
