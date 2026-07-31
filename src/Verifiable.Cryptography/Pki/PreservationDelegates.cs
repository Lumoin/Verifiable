using System;
using System.Buffers;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// How a peer disposed of one operation of the preservation protocol of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> clause 5.3.
/// </summary>
/// <remarks>
/// <para>
/// The cases are the specification's own: one success and the fifteen error codes clauses 5.3.2 to 5.3.9
/// enumerate, mapped both ways by <see cref="PreservationResultWellKnown.ResultMinorFromOutcome"/> and
/// <see cref="PreservationResultWellKnown.OutcomeFromResultMinor"/>. The two warning codes are not cases here: a
/// warning accompanies a call that succeeded, and it rides in the response's own
/// <see cref="PreservationResult.ResultMinor"/> where the wire puts it.
/// </para>
/// <para>
/// <see cref="Succeeded"/> is deliberately not zero: a status that has not been computed must not read as an
/// operation that worked.
/// </para>
/// </remarks>
public enum PreservationOperationOutcome
{
    /// <summary>No outcome stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The operation succeeded; the result carries the response, which may itself carry a warning code.</summary>
    Succeeded = 1,

    /// <summary>The client is not allowed to perform the operation.</summary>
    NoPermission = 2,

    /// <summary>The service failed for a reason of its own.</summary>
    InternalError = 3,

    /// <summary>A request parameter is malformed or inconsistent.</summary>
    ParameterError = 4,

    /// <summary>The operation, or an option of it, is not supported.</summary>
    NotSupported = 5,

    /// <summary>The submitted or requested data could not be transferred.</summary>
    TransferError = 6,

    /// <summary>The service has no storage left for the submission.</summary>
    NoSpaceError = 7,

    /// <summary>The stated preservation object format is not one the service knows.</summary>
    UnknownPreservationObjectFormat = 8,

    /// <summary>The submitted object does not conform to the format it was stated under.</summary>
    PreservationObjectFormatError = 9,

    /// <summary>A service the preservation service depends on could not be reached.</summary>
    ExternalServiceUnavailable = 10,

    /// <summary>The stated evidence format is not one the service knows.</summary>
    UnknownEvidenceFormat = 11,

    /// <summary>The stated preservation object identifier addresses nothing.</summary>
    UnknownPreservationObjectIdentifier = 12,

    /// <summary>The stated version identifier addresses no version of that object.</summary>
    UnknownVersionIdentifier = 13,

    /// <summary>The stated deletion mode is not one the enumeration of clause 5.4.2 states.</summary>
    UnknownDeletionMode = 14,

    /// <summary>The stated delta is of a type the container format does not support.</summary>
    UnknownDeltaContainerType = 15,

    /// <summary>The stated delta could not be applied to the container.</summary>
    DeltaContainerInternalProblem = 16
}


/// <summary>
/// Everything an operation seam of the preservation protocol is given about one call.
/// </summary>
/// <typeparam name="TRequest">Which of the eight requests this call carries.</typeparam>
/// <remarks>
/// <para>
/// The request and the bounds travel in the context rather than being captured by the implementation, so a caller
/// that varies them varies them per call and a seam instance carries no state of its own — the same discipline
/// every context record in this namespace applies.
/// </para>
/// <para>
/// <strong>Ownership.</strong> The caller retains ownership of <see cref="Request"/> and disposes it; a seam that
/// wants to keep a payload beyond the call copies it into a carrier of its own.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationOperationContext<TRequest> where TRequest: PreservationRequest
{
    /// <summary>The request as the caller built it or as a parse produced it.</summary>
    public required TRequest Request { get; init; }

    /// <summary>The bounds the seam applies to the request, per <see cref="PreservationMessageBounds"/>.</summary>
    public PreservationMessageLimits Limits { get; init; } = PreservationMessageLimits.Conformant;


    /// <summary>A short debugger string showing which message the context carries.</summary>
    private string DebuggerDisplay => $"PreservationOperationContext({Request.Kind})";
}


/// <summary>
/// The outcome of one operation seam of the preservation protocol: an outcome and, on success, the response.
/// </summary>
/// <typeparam name="TResponse">Which of the eight responses this result carries.</typeparam>
/// <remarks>
/// <strong>Ownership.</strong> On success the result owns <see cref="Response"/> and every payload that response
/// carries; the caller disposes it. On failure it owns nothing.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationOperationResult<TResponse>: IDisposable where TResponse: PreservationResponse
{
    /// <summary>How the peer disposed of the call; <see cref="PreservationOperationOutcome.Succeeded"/> is the only success.</summary>
    public required PreservationOperationOutcome Outcome { get; init; }

    /// <summary>The response; non-<see langword="null"/> only when <see cref="Outcome"/> is <see cref="PreservationOperationOutcome.Succeeded"/>.</summary>
    public TResponse? Response { get; init; }

    /// <summary>A short, human-readable reason, present on every outcome that is not a success.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Outcome"/> is <see cref="PreservationOperationOutcome.Succeeded"/>.</summary>
    public bool IsSucceeded => Outcome == PreservationOperationOutcome.Succeeded;


    /// <summary>Creates a successful result owning <paramref name="response"/>.</summary>
    /// <param name="response">The response; ownership transfers to the result.</param>
    /// <returns>A <see cref="PreservationOperationOutcome.Succeeded"/> result.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="response"/> is <see langword="null"/>.</exception>
    public static PreservationOperationResult<TResponse> Succeeded(TResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);

        return new PreservationOperationResult<TResponse> { Outcome = PreservationOperationOutcome.Succeeded, Response = response };
    }


    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="outcome">The failure outcome; must not be <see cref="PreservationOperationOutcome.Succeeded"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="outcome"/> is a success, which would leave the result claiming a response it does not carry.</exception>
    public static PreservationOperationResult<TResponse> Failed(PreservationOperationOutcome outcome, string reason)
    {
        if(outcome == PreservationOperationOutcome.Succeeded)
        {
            throw new ArgumentException("A failed result cannot carry the successful outcome.", nameof(outcome));
        }

        return new PreservationOperationResult<TResponse> { Outcome = outcome, FailureReason = reason };
    }


    /// <summary>Disposes <see cref="Response"/>, when present.</summary>
    public void Dispose() => Response?.Dispose();


    /// <summary>A short debugger string showing the outcome.</summary>
    private string DebuggerDisplay => $"PreservationOperationResult({Outcome})";
}


/// <summary>
/// Performs the <c>RetrieveInfo</c> operation of clause 5.3.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> — the one operation clause 5.2 requires every preservation service to support.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation.</strong> Behind this seam is a preservation service: storage,
/// key custody, an evidence-generation policy engine and the profiles a service publishes about itself. What the
/// library ships is the vocabulary the two peers exchange, so that a service or a client built on it speaks the
/// specification's own shapes without hand-rolling them.
/// </para>
/// <para>
/// <strong>Transport is the caller's.</strong> Clause 5.1 asserts a binding to two transports and gives neither
/// in its body; the request and the response are message bodies here, and whichever envelope carries them is
/// supplied by whoever calls this seam.
/// </para>
/// <para>
/// <strong>Faults are outcomes, not exceptions.</strong> A seam is implemented by whoever supplies it, and making
/// exception behaviour part of the contract would make every implementation's failure mode part of it too.
/// </para>
/// </remarks>
/// <param name="context">The request and the bounds to answer it under.</param>
/// <param name="pool">The memory pool the implementation rents the response's payload carriers from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The outcome and, on success, the response.</returns>
public delegate ValueTask<PreservationOperationResult<RetrieveInfoResponse>> RetrieveInfoDelegate(
    PreservationOperationContext<RetrieveInfoRequest> context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Performs the <c>PreservePO</c> operation of clause 5.3.3 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> — the submission every Annex F scheme requires.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation</strong>, for the reason <see cref="RetrieveInfoDelegate"/>
/// gives; transport is likewise the caller's.
/// </para>
/// <para>
/// A submission stating no preservation object at all is a conformant call, not an empty one: clause 5.3.3.1.1
/// notes it is how a client obtains an identifier for a container it populates later.
/// </para>
/// </remarks>
/// <param name="context">The request and the bounds to answer it under.</param>
/// <param name="pool">The memory pool the implementation rents the response's payload carriers from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The outcome and, on success, the response.</returns>
public delegate ValueTask<PreservationOperationResult<PreservePreservationObjectResponse>> PreservePreservationObjectDelegate(
    PreservationOperationContext<PreservePreservationObjectRequest> context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Performs the <c>RetrievePO</c> operation of clause 5.3.4 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation</strong>, for the reason <see cref="RetrieveInfoDelegate"/>
/// gives; transport is likewise the caller's.
/// </para>
/// <para>
/// Clause 5.3.4.1.1 permits this operation only in a scheme with storage or with temporary storage, which
/// <see cref="PreservationWellKnown.IsOperationPermittedUnderStorageModel"/> answers: a service without storage
/// exposes no such seam at all rather than answering it with a failure.
/// </para>
/// </remarks>
/// <param name="context">The request and the bounds to answer it under.</param>
/// <param name="pool">The memory pool the implementation rents the response's payload carriers from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The outcome and, on success, the response.</returns>
public delegate ValueTask<PreservationOperationResult<RetrievePreservationObjectResponse>> RetrievePreservationObjectDelegate(
    PreservationOperationContext<RetrievePreservationObjectRequest> context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Performs the <c>DeletePO</c> operation of clause 5.3.5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation</strong>, for the reason <see cref="RetrieveInfoDelegate"/>
/// gives; transport is likewise the caller's.
/// </para>
/// <para>
/// Clause 5.3.5.1.1 permits this operation only in a scheme with storage, and an omitted <c>Mode</c> means
/// <see cref="PreservationWellKnown.DefaultDeletionMode"/> — the mode that deletes the evidences too, which is
/// the wider of the two and therefore the one an implementation must not assume away.
/// </para>
/// </remarks>
/// <param name="context">The request and the bounds to answer it under.</param>
/// <param name="pool">The memory pool the implementation rents the response's payload carriers from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The outcome and, on success, the response.</returns>
public delegate ValueTask<PreservationOperationResult<DeletePreservationObjectResponse>> DeletePreservationObjectDelegate(
    PreservationOperationContext<DeletePreservationObjectRequest> context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Performs the <c>UpdatePOC</c> operation of clause 5.3.6 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <strong>This library ships no implementation</strong>, for the reason <see cref="RetrieveInfoDelegate"/>
/// gives; transport is likewise the caller's. Which of the two update strategies a request states is a property
/// of the container format rather than of the message, so it is the implementation that decides how a delta is
/// applied.
/// </remarks>
/// <param name="context">The request and the bounds to answer it under.</param>
/// <param name="pool">The memory pool the implementation rents the response's payload carriers from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The outcome and, on success, the response.</returns>
public delegate ValueTask<PreservationOperationResult<UpdatePreservationObjectContainerResponse>> UpdatePreservationObjectContainerDelegate(
    PreservationOperationContext<UpdatePreservationObjectContainerRequest> context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Performs the <c>RetrieveTrace</c> operation of clause 5.3.7 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <strong>This library ships no implementation</strong>, for the reason <see cref="RetrieveInfoDelegate"/>
/// gives; transport is likewise the caller's. The events a service records about a preservation object are the
/// service's own, which is why the trace is a payload here and not something the library computes.
/// </remarks>
/// <param name="context">The request and the bounds to answer it under.</param>
/// <param name="pool">The memory pool the implementation rents the response's payload carriers from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The outcome and, on success, the response.</returns>
public delegate ValueTask<PreservationOperationResult<RetrieveTraceResponse>> RetrieveTraceDelegate(
    PreservationOperationContext<RetrieveTraceRequest> context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Performs the <c>ValidateEvidence</c> operation of clause 5.3.8 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <strong>This library ships no implementation of the seam</strong>, for the reason
/// <see cref="RetrieveInfoDelegate"/> gives — but unlike the other seven, what sits behind this one is a
/// capability this library does have: verifying an evidence record, a time-stamp token or an archive time-stamp
/// is what the shipped verification surfaces do. The operation adds a wire wrapper around invoking one, not a new
/// validation algorithm.
/// </remarks>
/// <param name="context">The request and the bounds to answer it under.</param>
/// <param name="pool">The memory pool the implementation rents the response's payload carriers from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The outcome and, on success, the response.</returns>
public delegate ValueTask<PreservationOperationResult<ValidateEvidenceResponse>> ValidateEvidenceDelegate(
    PreservationOperationContext<ValidateEvidenceRequest> context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Performs the <c>Search</c> operation of clause 5.3.9 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <strong>This library ships no implementation</strong>, for the reason <see cref="RetrieveInfoDelegate"/>
/// gives; transport is likewise the caller's. The query language a filter is written in is defined by the
/// profile and not by this document, so the filter is opaque to the vocabulary and its meaning is entirely the
/// implementation's.
/// </remarks>
/// <param name="context">The request and the bounds to answer it under.</param>
/// <param name="pool">The memory pool the implementation rents the response's payload carriers from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The outcome and, on success, the response.</returns>
public delegate ValueTask<PreservationOperationResult<SearchResponse>> SearchDelegate(
    PreservationOperationContext<SearchRequest> context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Which of the two syntaxes
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> makes normative a message is written in or read from.
/// </summary>
/// <remarks>
/// Every component of clause 5 has an XML-syntax clause and a JSON-syntax clause, and the two are not a
/// mechanical re-encoding of each other: the member names differ per component with no derivation rule, the
/// inheritance of the base types is flattened in one of them, instants are written differently, and the value
/// choice of a preservation object loses one alternative. A seam is therefore told which syntax it is working in
/// rather than inferring it. <see cref="NotEvaluated"/> occupies zero so a default-initialised value names
/// neither.
/// </remarks>
public enum PreservationSyntax
{
    /// <summary>No syntax stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The XML syntax of the clause-5 components.</summary>
    Xml = 1,

    /// <summary>The JSON syntax of the clause-5 components.</summary>
    Json = 2
}


/// <summary>
/// Why <see cref="EncodePreservationMessageDelegate"/> did, or did not, produce a message document.
/// </summary>
/// <remarks>
/// <see cref="Encoded"/> is deliberately not zero: a status that has not been computed must not read as a
/// successful encoding.
/// </remarks>
public enum PreservationMessageEncodeStatus
{
    /// <summary>No encoding has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The message was written.</summary>
    Encoded = 1,

    /// <summary>The requested syntax is one this implementation does not write.</summary>
    SyntaxNotSupported = 2,

    /// <summary>
    /// The message carries a payload whose content form is <see cref="PreservationContentForm.XmlData"/> and the
    /// requested syntax is one with no representation for it. The JSON schema of the <c>PO</c> component omits
    /// that alternative of the value choice altogether, and nothing in the document authorises re-encoding such a
    /// payload as the other alternative, so an implementation refuses rather than choosing for the submitter.
    /// </summary>
    ContentFormNotRepresentable = 3,

    /// <summary>A value the message's own clause requires was absent, so no conformant document could be written.</summary>
    MissingRequiredElement = 4,

    /// <summary>The message exceeds one of <see cref="PreservationMessageLimits"/>' bounds.</summary>
    LimitExceeded = 5
}


/// <summary>
/// The outcome of <see cref="EncodePreservationMessageDelegate"/>. On success it owns the produced octets; the
/// caller disposes them. On failure it owns nothing.
/// </summary>
[DebuggerDisplay("PreservationMessageEncodeResult: {Status}")]
public sealed record PreservationMessageEncodeResult: IDisposable
{
    /// <summary>The encoding outcome; <see cref="PreservationMessageEncodeStatus.Encoded"/> is the only success.</summary>
    public required PreservationMessageEncodeStatus Status { get; init; }

    /// <summary>The message document's octets; non-<see langword="null"/> only when <see cref="Status"/> is <see cref="PreservationMessageEncodeStatus.Encoded"/>.</summary>
    public PooledMemory? Document { get; init; }

    /// <summary>A short, human-readable reason, present on every outcome that is not an encoding.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Status"/> is <see cref="PreservationMessageEncodeStatus.Encoded"/>.</summary>
    public bool IsEncoded => Status == PreservationMessageEncodeStatus.Encoded;


    /// <summary>Creates a successful result owning <paramref name="document"/>.</summary>
    /// <param name="document">The produced octets; ownership transfers to the result.</param>
    /// <returns>An <see cref="PreservationMessageEncodeStatus.Encoded"/> result.</returns>
    public static PreservationMessageEncodeResult Encoded(PooledMemory document) =>
        new() { Status = PreservationMessageEncodeStatus.Encoded, Document = document };


    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="status">The failure status; must not be <see cref="PreservationMessageEncodeStatus.Encoded"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    public static PreservationMessageEncodeResult Failed(PreservationMessageEncodeStatus status, string reason) =>
        new() { Status = status, FailureReason = reason };


    /// <summary>Disposes <see cref="Document"/>, when present.</summary>
    public void Dispose() => Document?.Dispose();
}


/// <summary>
/// Everything <see cref="EncodePreservationMessageDelegate"/> is given about one encoding.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> The caller retains ownership of <see cref="Message"/> and disposes it; the
/// produced octets are the result's.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationMessageEncodeContext
{
    /// <summary>The message to write.</summary>
    public required PreservationMessage Message { get; init; }

    /// <summary>Which of the two normative syntaxes to write it in.</summary>
    public required PreservationSyntax Syntax { get; init; }

    /// <summary>The bounds the encoding applies before writing anything.</summary>
    public PreservationMessageLimits Limits { get; init; } = PreservationMessageLimits.Conformant;


    /// <summary>A short debugger string showing what is written and in which syntax.</summary>
    private string DebuggerDisplay => $"PreservationMessageEncodeContext({Message.Kind}, {Syntax})";
}


/// <summary>
/// Writes one message of the preservation protocol of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> clause 5.3 in one of its two normative syntaxes.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation.</strong> One syntax is XML and the other is JSON, and this
/// project stays serialization-agnostic — it references neither an XML package nor a JSON one — exactly as
/// <see cref="EncodeAsicManifestDelegate"/> and <see cref="ParseTrustedListDelegate"/> already do for their own
/// documents. A worked implementation of both syntaxes is staged as a promotable example under the test project.
/// </para>
/// <para>
/// <strong>The names are not derivable, so an implementation must read them from the registry.</strong> Every
/// element name and its JSON member name are stated as pairs in <see cref="PreservationName"/>-valued getters,
/// one class per component; an implementation that derived one spelling from the other would diverge from the
/// specification silently. The XML names are qualified by
/// <see cref="PreservationWellKnown.PreservationNamespace"/>.
/// </para>
/// <para>
/// <strong>Fail closed on what a syntax cannot carry.</strong> A payload whose content form is
/// <see cref="PreservationContentForm.XmlData"/> has no representation in the JSON binding, and an
/// implementation MUST answer <see cref="PreservationMessageEncodeStatus.ContentFormNotRepresentable"/> rather
/// than re-encoding it as the other alternative of the choice.
/// </para>
/// </remarks>
/// <param name="context">The message to write and the syntax to write it in.</param>
/// <param name="pool">The memory pool the implementation rents the produced document's carrier from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The encoding result.</returns>
public delegate ValueTask<PreservationMessageEncodeResult> EncodePreservationMessageDelegate(
    PreservationMessageEncodeContext context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Why <see cref="ParsePreservationMessageDelegate"/> did, or did not, produce a message.
/// </summary>
/// <remarks>
/// <see cref="Valid"/> is deliberately not zero: a status that has not been computed must not read as a
/// successful parse.
/// </remarks>
public enum PreservationMessageParseStatus
{
    /// <summary>No parse has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The document parsed into the message the context asked for.</summary>
    Valid = 1,

    /// <summary>The document is not well-formed in the stated syntax at all.</summary>
    Malformed = 2,

    /// <summary>The stated syntax is one this implementation does not read.</summary>
    SyntaxNotSupported = 3,

    /// <summary>
    /// The document is well-formed but is not the message the context asked for. The wire carries no
    /// discriminator a reader may trust before parsing, so what a document is meant to be is stated by the caller
    /// and a mismatch is a refusal rather than a re-interpretation.
    /// </summary>
    UnexpectedMessage = 4,

    /// <summary>A particle the message's own clause requires was absent.</summary>
    MissingRequiredElement = 5,

    /// <summary>The document exceeds one of <see cref="PreservationMessageLimits"/>' bounds.</summary>
    LimitExceeded = 6
}


/// <summary>
/// The outcome of <see cref="ParsePreservationMessageDelegate"/>. On success it owns the parsed message and every
/// payload that message carries; the caller disposes it. On failure it owns nothing.
/// </summary>
[DebuggerDisplay("PreservationMessageParseResult: {Status}")]
public sealed record PreservationMessageParseResult: IDisposable
{
    /// <summary>The parse outcome; <see cref="PreservationMessageParseStatus.Valid"/> is the only success.</summary>
    public required PreservationMessageParseStatus Status { get; init; }

    /// <summary>The parsed message; non-<see langword="null"/> only when <see cref="Status"/> is <see cref="PreservationMessageParseStatus.Valid"/>.</summary>
    public PreservationMessage? Message { get; init; }

    /// <summary>A short, human-readable reason, present on every outcome that is not a valid parse.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Status"/> is <see cref="PreservationMessageParseStatus.Valid"/>.</summary>
    public bool IsValid => Status == PreservationMessageParseStatus.Valid;


    /// <summary>Creates a successful result owning <paramref name="message"/>.</summary>
    /// <param name="message">The parsed message; ownership transfers to the result.</param>
    /// <returns>A <see cref="PreservationMessageParseStatus.Valid"/> result.</returns>
    public static PreservationMessageParseResult Valid(PreservationMessage message) =>
        new() { Status = PreservationMessageParseStatus.Valid, Message = message };


    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="status">The failure status; must not be <see cref="PreservationMessageParseStatus.Valid"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    public static PreservationMessageParseResult Failed(PreservationMessageParseStatus status, string reason) =>
        new() { Status = status, FailureReason = reason };


    /// <summary>Disposes <see cref="Message"/>, when present.</summary>
    public void Dispose() => Message?.Dispose();
}


/// <summary>
/// Everything <see cref="ParsePreservationMessageDelegate"/> is given about one parse.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> The caller retains ownership of <see cref="Document"/> and disposes it; the parsed
/// message is the result's.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationMessageParseContext
{
    /// <summary>The message document's octets, as they arrived.</summary>
    public required PooledMemory Document { get; init; }

    /// <summary>Which of the sixteen messages the document is expected to be.</summary>
    public required PreservationMessageKind ExpectedKind { get; init; }

    /// <summary>Which of the two normative syntaxes the document is written in.</summary>
    public required PreservationSyntax Syntax { get; init; }

    /// <summary>The bounds the parse applies.</summary>
    public PreservationMessageLimits Limits { get; init; } = PreservationMessageLimits.Conformant;


    /// <summary>A short debugger string showing what is expected and in which syntax.</summary>
    private string DebuggerDisplay =>
        $"PreservationMessageParseContext({ExpectedKind}, {Syntax}, {Document.Length} octets)";
}


/// <summary>
/// Reads one message of the preservation protocol of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> clause 5.3 from one of its two normative syntaxes.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This library ships no implementation</strong>, for the reason
/// <see cref="EncodePreservationMessageDelegate"/> gives. A worked implementation of both syntaxes is staged as a
/// promotable example under the test project.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> A request arrives from a client and a response from a service. An
/// implementation MUST prohibit document type definitions in the XML syntax — entity expansion and external
/// entity fetch — MUST bound the nesting of anything a peer controls, and MUST honour
/// <see cref="PreservationMessageParseContext.Limits"/>, which is the same record
/// <see cref="PreservationMessageBounds"/> applies. Walking a document with an explicit
/// <see cref="System.Collections.Generic.Stack{T}"/> rather than recursively is what makes the depth bound a
/// counter rather than a stack overflow.
/// </para>
/// <para>
/// <strong>Payload carriers are tagged.</strong> The octets a preservation object or an evidence carries are
/// rented from <paramref name="pool"/> and tagged <see cref="PreservationTags.PreservationObject"/> or
/// <see cref="PreservationTags.PreservationEvidence"/>, so a payload can be routed and reported on without being
/// parsed again; a sub-component carried verbatim is tagged <see cref="PreservationTags.OpaqueElement"/>.
/// </para>
/// <para>
/// <strong>Fail closed on structure.</strong> Every particle a message's own clause requires is required in the
/// returned model too, and an implementation that cannot populate one MUST answer
/// <see cref="PreservationMessageParseStatus.MissingRequiredElement"/> rather than inventing a default. Where the
/// specification states a default for an omitted optional element — the status of a discovery request, the
/// subject of a retrieval, the mode of a deletion — the element stays absent in the model and the default is read
/// from <see cref="PreservationWellKnown"/> by whoever acts on it, so that "absent" and "stated as the default"
/// stay distinguishable.
/// </para>
/// </remarks>
/// <param name="context">The document, the message it is expected to be, and the bounds to read it under.</param>
/// <param name="pool">The memory pool the implementation rents the message's payload carriers from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The parse result.</returns>
public delegate ValueTask<PreservationMessageParseResult> ParsePreservationMessageDelegate(
    PreservationMessageParseContext context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
