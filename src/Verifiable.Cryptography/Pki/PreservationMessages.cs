using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Which of the sixteen messages of clause 5.3 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> a <see cref="PreservationMessage"/> is — the request and the response of each of
/// the eight operations.
/// </summary>
/// <remarks>
/// A serialisation seam is given octets and has to be told what to read them as, since the wire carries no
/// discriminator a reader can trust before parsing. <see cref="NotEvaluated"/> occupies zero so a
/// default-initialised value never names a message.
/// </remarks>
public enum PreservationMessageKind
{
    /// <summary>No message kind stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>A <c>RetrieveInfo</c> request (clause 5.3.2.1).</summary>
    RetrieveInfoRequest = 1,

    /// <summary>A <c>RetrieveInfoResponse</c> (clause 5.3.2.2).</summary>
    RetrieveInfoResponse = 2,

    /// <summary>A <c>PreservePO</c> request (clause 5.3.3.1).</summary>
    PreservePreservationObjectRequest = 3,

    /// <summary>A <c>PreservePOResponse</c> (clause 5.3.3.2).</summary>
    PreservePreservationObjectResponse = 4,

    /// <summary>A <c>RetrievePO</c> request (clause 5.3.4.1).</summary>
    RetrievePreservationObjectRequest = 5,

    /// <summary>A <c>RetrievePOResponse</c> (clause 5.3.4.2).</summary>
    RetrievePreservationObjectResponse = 6,

    /// <summary>A <c>DeletePO</c> request (clause 5.3.5.1).</summary>
    DeletePreservationObjectRequest = 7,

    /// <summary>A <c>DeletePOResponse</c> (clause 5.3.5.2).</summary>
    DeletePreservationObjectResponse = 8,

    /// <summary>An <c>UpdatePOC</c> request (clause 5.3.6.1).</summary>
    UpdatePreservationObjectContainerRequest = 9,

    /// <summary>An <c>UpdatePOCResponse</c> (clause 5.3.6.2).</summary>
    UpdatePreservationObjectContainerResponse = 10,

    /// <summary>A <c>RetrieveTrace</c> request (clause 5.3.7.1).</summary>
    RetrieveTraceRequest = 11,

    /// <summary>A <c>RetrieveTraceResponse</c> (clause 5.3.7.2).</summary>
    RetrieveTraceResponse = 12,

    /// <summary>A <c>ValidateEvidence</c> request (clause 5.3.8.1).</summary>
    ValidateEvidenceRequest = 13,

    /// <summary>A <c>ValidateEvidenceResponse</c> (clause 5.3.8.2).</summary>
    ValidateEvidenceResponse = 14,

    /// <summary>A <c>Search</c> request (clause 5.3.9.1).</summary>
    SearchRequest = 15,

    /// <summary>A <c>SearchResponse</c> (clause 5.3.9.2).</summary>
    SearchResponse = 16
}


/// <summary>
/// One message of the preservation protocol of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> clause 5.3 — a request or a response, serialisation-agnostic.
/// </summary>
/// <remarks>
/// <para>
/// <strong>A closed hierarchy of exactly sixteen cases.</strong> The constructor below is
/// <see langword="private protected"/>, so nothing outside this assembly can add a seventeenth: the protocol has
/// eight operations and each has one request and one response, and a switch over
/// <see cref="PreservationMessageKind"/> is exhaustive by construction.
/// </para>
/// <para>
/// <strong>The base types are real here even though the JSON binding flattens them.</strong> The XML syntax
/// extends <c>RequestType</c> and <c>ResponseType</c> by inheritance while every JSON object re-lists the
/// inherited members directly. The inheritance is what the document's semantics clauses describe — every
/// operation "shall extend the <c>Request</c> component ... and shall inherit the set of sub-components" — so it
/// is what the model carries; the flattening is a property of one binding.
/// </para>
/// <para>
/// <strong>Ownership.</strong> A message owns every payload it carries, and disposing it disposes them.
/// </para>
/// </remarks>
public abstract record PreservationMessage: IDisposable
{
    /// <summary>Restricts the cases to those declared in this assembly, making this a closed hierarchy.</summary>
    private protected PreservationMessage()
    {
    }


    /// <summary>Which of the sixteen messages this is.</summary>
    public abstract PreservationMessageKind Kind { get; }

    /// <summary>The name of the operation this message belongs to — one of the eight of <see cref="PreservationWellKnown.IsOperationName"/>.</summary>
    public abstract string OperationName { get; }

    /// <summary>
    /// The <c>RequestID</c> attribute, or <see langword="null"/> when none was stated. Clause 5.3.1.1 requires a
    /// service that received one to return it in the response, which is why the member sits on both.
    /// </summary>
    public string? RequestId { get; init; }


    /// <summary>Disposes every payload this message owns.</summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }


    /// <summary>
    /// Disposes the payloads this case owns when <paramref name="disposing"/> is <see langword="true"/>.
    /// </summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    /// <remarks>
    /// The hierarchy is closed by the constructor above and no case holds an unmanaged resource, so this exists to
    /// give each case one place to release its carriers rather than to support a finalizer — the shape
    /// <see cref="EArkFixity"/> already established in this namespace for a closed sum whose cases own pooled
    /// memory.
    /// </remarks>
    protected abstract void Dispose(bool disposing);


    /// <summary>Disposes every element of a payload list, tolerating a list that is empty.</summary>
    /// <param name="objects">The preservation objects to dispose.</param>
    private protected static void DisposeAll(IReadOnlyList<PreservationObject> objects)
    {
        foreach(PreservationObject preservationObject in objects)
        {
            preservationObject.Dispose();
        }
    }


    /// <summary>Disposes every element of an opaque-element list, tolerating a list that is empty.</summary>
    /// <param name="elements">The opaque elements to dispose.</param>
    private protected static void DisposeAll(IReadOnlyList<PreservationOpaqueElement> elements)
    {
        foreach(PreservationOpaqueElement element in elements)
        {
            element.Dispose();
        }
    }


    /// <summary>Disposes every element of a profile list, tolerating a list that is empty.</summary>
    /// <param name="profiles">The profiles to dispose.</param>
    private protected static void DisposeAll(IReadOnlyList<PreservationProfile> profiles)
    {
        foreach(PreservationProfile profile in profiles)
        {
            profile.Dispose();
        }
    }
}


/// <summary>
/// The <c>Request</c> base component every operation request extends, per clause 5.3.1.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
public abstract record PreservationRequest: PreservationMessage
{
    /// <summary>Restricts the cases to those declared in this assembly.</summary>
    private protected PreservationRequest()
    {
    }


    /// <summary>The <c>OptionalInputs</c> sub-components, carried verbatim per <see cref="PreservationOpaqueElement"/>.</summary>
    public IReadOnlyList<PreservationOpaqueElement> OptionalInputs { get; init; } = [];


    /// <summary>Disposes the optional inputs every request may carry.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            DisposeAll(OptionalInputs);
        }
    }
}


/// <summary>
/// The <c>Response</c> base component every operation response extends, per clause 5.3.1.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <see cref="Result"/> is required because clause 5.3.1.2 states it shall be present: a response with no result
/// says nothing about whether the operation succeeded, which is exactly what a response is for.
/// </remarks>
public abstract record PreservationResponse: PreservationMessage
{
    /// <summary>Restricts the cases to those declared in this assembly.</summary>
    private protected PreservationResponse()
    {
    }


    /// <summary>The mandatory <c>Result</c> element.</summary>
    public required PreservationResult Result { get; init; }

    /// <summary>The <c>OptionalOutputs</c> sub-components, carried verbatim per <see cref="PreservationOpaqueElement"/>.</summary>
    public IReadOnlyList<PreservationOpaqueElement> OptionalOutputs { get; init; } = [];


    /// <summary>Disposes the optional outputs every response may carry.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            DisposeAll(OptionalOutputs);
        }
    }
}


/// <summary>
/// The <c>RetrieveInfo</c> request (clause 5.3.2.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>) — the discovery call clause 5.2 requires every service to support.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "A profile identifier is compared as an exact character sequence; System.Uri normalises case, escaping and trailing separators, which would make two identifiers naming different profiles compare equal.")]
public sealed record RetrieveInfoRequest: PreservationRequest
{
    /// <inheritdoc/>
    public override PreservationMessageKind Kind => PreservationMessageKind.RetrieveInfoRequest;

    /// <inheritdoc/>
    public override string OperationName => PreservationWellKnown.RetrieveInfoOperation;

    /// <summary>The optional <c>Profile</c> element — the one profile information is wanted about, or <see langword="null"/> for all of them.</summary>
    public string? ProfileIdentifier { get; init; }

    /// <summary>
    /// The optional <c>Status</c> element, or <see langword="null"/> — which the clause says means
    /// <see cref="PreservationWellKnown.DefaultStatus"/>, not "no filter".
    /// </summary>
    public string? Status { get; init; }


    /// <summary>A short debugger string showing the filter this request states.</summary>
    private string DebuggerDisplay =>
        $"RetrieveInfoRequest({ProfileIdentifier ?? "every profile"}, {Status ?? PreservationWellKnown.DefaultStatus})";
}


/// <summary>
/// The <c>RetrieveInfoResponse</c> (clause 5.3.2.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>Ownership: this response owns the profiles it carries.</remarks>
[DebuggerDisplay("RetrieveInfoResponse: {Profiles.Count} profiles")]
public sealed record RetrieveInfoResponse: PreservationResponse
{
    /// <inheritdoc/>
    public override PreservationMessageKind Kind => PreservationMessageKind.RetrieveInfoResponse;

    /// <inheritdoc/>
    public override string OperationName => PreservationWellKnown.RetrieveInfoOperation;

    /// <summary>The <c>Profile</c> elements — zero or more, each satisfying clause 5.4.7.</summary>
    public IReadOnlyList<PreservationProfile> Profiles { get; init; } = [];


    /// <summary>Disposes the profiles and then the inherited optional outputs.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            DisposeAll(Profiles);
        }

        base.Dispose(disposing);
    }
}


/// <summary>
/// The <c>PreservePO</c> request (clause 5.3.3.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>) — the submission call every Annex F scheme requires.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Zero objects is a real request, not an empty one.</strong> Clause 5.3.3.1.1 notes that submitting no
/// preservation object at all is how a client obtains an identifier for a container it will populate later
/// through the update operation, so the list is optional while the profile is mandatory.
/// </para>
/// <para>Ownership: this request owns the objects it carries.</para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "A profile identifier is compared as an exact character sequence, for the reason given on RetrieveInfoRequest.")]
public sealed record PreservePreservationObjectRequest: PreservationRequest
{
    /// <inheritdoc/>
    public override PreservationMessageKind Kind => PreservationMessageKind.PreservePreservationObjectRequest;

    /// <inheritdoc/>
    public override string OperationName => PreservationWellKnown.PreservePreservationObjectOperation;

    /// <summary>The mandatory <c>Profile</c> element — the operational profile the submission is preserved under.</summary>
    public required string ProfileIdentifier { get; init; }

    /// <summary>The <c>PO</c> elements — zero or more preservation objects.</summary>
    public IReadOnlyList<PreservationObject> PreservationObjects { get; init; } = [];


    /// <summary>Disposes the submitted objects and then the inherited optional inputs.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            DisposeAll(PreservationObjects);
        }

        base.Dispose(disposing);
    }


    /// <summary>A short debugger string showing the profile and how many objects are submitted.</summary>
    private string DebuggerDisplay =>
        $"PreservePreservationObjectRequest({ProfileIdentifier}, {PreservationObjects.Count} objects)";
}


/// <summary>
/// The <c>PreservePOResponse</c> (clause 5.3.3.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>
/// <para>
/// <strong><see cref="PreservationObjectId"/> is optional in shape and conditionally mandatory in meaning.</strong>
/// Clause 5.3.3.2.1 requires it after a successful call whenever the service stores anything, permanently or
/// temporarily, or supports the trace operation — two conditions about the service rather than about this
/// message, which is why the member is optional here.
/// </para>
/// <para>
/// A service that stores nothing returns one object per submitted object, with the evidence produced
/// synchronously and enveloped in each.
/// </para>
/// <para>Ownership: this response owns the objects it carries.</para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservePreservationObjectResponse: PreservationResponse
{
    /// <inheritdoc/>
    public override PreservationMessageKind Kind => PreservationMessageKind.PreservePreservationObjectResponse;

    /// <inheritdoc/>
    public override string OperationName => PreservationWellKnown.PreservePreservationObjectOperation;

    /// <summary>The optional <c>POID</c> element — the identifier later calls address the submission by.</summary>
    public string? PreservationObjectId { get; init; }

    /// <summary>The <c>PO</c> elements — zero or more, one per submitted object when the evidence was produced synchronously.</summary>
    public IReadOnlyList<PreservationObject> PreservationObjects { get; init; } = [];


    /// <summary>Disposes the returned objects and then the inherited optional outputs.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            DisposeAll(PreservationObjects);
        }

        base.Dispose(disposing);
    }


    /// <summary>A short debugger string showing the identifier and how many objects came back.</summary>
    private string DebuggerDisplay =>
        $"PreservePreservationObjectResponse({PreservationObjectId ?? "no identifier"}, {PreservationObjects.Count} objects)";
}


/// <summary>
/// The <c>RetrievePO</c> request (clause 5.3.4.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>), which the same clause permits only in a scheme with storage or with temporary
/// storage.
/// </summary>
/// <remarks>
/// <see cref="VersionIds"/> carries a sentinel as well as identifiers: an element equal to
/// <see cref="PreservationWellKnown.AllVersionsIdentifier"/> asks for every version, and no element at all asks
/// for the latest.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "Format identifiers are compared as exact character sequences against PreservationFormatWellKnown, for the reason given there.")]
public sealed record RetrievePreservationObjectRequest: PreservationRequest
{
    /// <inheritdoc/>
    public override PreservationMessageKind Kind => PreservationMessageKind.RetrievePreservationObjectRequest;

    /// <inheritdoc/>
    public override string OperationName => PreservationWellKnown.RetrievePreservationObjectOperation;

    /// <summary>The mandatory <c>POID</c> element — which preservation object is wanted.</summary>
    public required string PreservationObjectId { get; init; }

    /// <summary>The <c>VersionID</c> elements — zero or more; none of them means the latest version.</summary>
    public IReadOnlyList<string> VersionIds { get; init; } = [];

    /// <summary>
    /// The optional <c>SubjectOfRetrieval</c> element, or <see langword="null"/> — which the clause says means
    /// <see cref="PreservationWellKnown.DefaultSubjectOfRetrieval"/>.
    /// </summary>
    public string? SubjectOfRetrieval { get; init; }

    /// <summary>The optional <c>POFormat</c> element — which the clause says must be among the formats the applicable profile's retrieval operation announces.</summary>
    public string? PreservationObjectFormat { get; init; }

    /// <summary>The optional <c>EvidenceFormat</c> element — or <see langword="null"/> for the profile's own default.</summary>
    public string? EvidenceFormat { get; init; }


    /// <summary>A short debugger string showing what is being retrieved and how.</summary>
    private string DebuggerDisplay =>
        $"RetrievePreservationObjectRequest({PreservationObjectId}, {VersionIds.Count} versions, {SubjectOfRetrieval ?? PreservationWellKnown.DefaultSubjectOfRetrieval})";
}


/// <summary>
/// The <c>RetrievePOResponse</c> (clause 5.3.4.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>
/// A partly successful retrieval is reported with the partial-success warning code, and clause 5.3.4.2.1
/// recommends the details go in <see cref="PreservationResult.ResultMessage"/>. Ownership: this response owns the
/// objects it carries.
/// </remarks>
[DebuggerDisplay("RetrievePreservationObjectResponse: {PreservationObjects.Count} objects")]
public sealed record RetrievePreservationObjectResponse: PreservationResponse
{
    /// <inheritdoc/>
    public override PreservationMessageKind Kind => PreservationMessageKind.RetrievePreservationObjectResponse;

    /// <inheritdoc/>
    public override string OperationName => PreservationWellKnown.RetrievePreservationObjectOperation;

    /// <summary>The <c>PO</c> elements — the objects and evidences the request asked for.</summary>
    public IReadOnlyList<PreservationObject> PreservationObjects { get; init; } = [];


    /// <summary>Disposes the returned objects and then the inherited optional outputs.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            DisposeAll(PreservationObjects);
        }

        base.Dispose(disposing);
    }
}


/// <summary>
/// The <c>DeletePO</c> request (clause 5.3.5.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>), which the same clause permits only in a scheme with storage.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record DeletePreservationObjectRequest: PreservationRequest
{
    /// <inheritdoc/>
    public override PreservationMessageKind Kind => PreservationMessageKind.DeletePreservationObjectRequest;

    /// <inheritdoc/>
    public override string OperationName => PreservationWellKnown.DeletePreservationObjectOperation;

    /// <summary>The mandatory <c>POID</c> element — which preservation object is to be deleted.</summary>
    public required string PreservationObjectId { get; init; }

    /// <summary>
    /// The optional <c>Mode</c> element, or <see langword="null"/> — which the clause says means
    /// <see cref="PreservationWellKnown.DefaultDeletionMode"/>, the wider of the two modes.
    /// </summary>
    public string? Mode { get; init; }

    /// <summary>The optional <c>ClaimedRequestorName</c> element — who claims to be asking, or <see langword="null"/>.</summary>
    public string? ClaimedRequestorName { get; init; }

    /// <summary>The optional <c>Reason</c> element — free text, or <see langword="null"/>.</summary>
    public string? Reason { get; init; }


    /// <summary>A short debugger string showing what is deleted and how.</summary>
    private string DebuggerDisplay =>
        $"DeletePreservationObjectRequest({PreservationObjectId}, {Mode ?? PreservationWellKnown.DefaultDeletionMode})";
}


/// <summary>
/// The <c>DeletePOResponse</c> (clause 5.3.5.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>
/// The only response of the eight with no payload of its own: success is stated entirely by the inherited
/// <see cref="PreservationResponse.Result"/>, which is why this record adds no member.
/// </remarks>
[DebuggerDisplay("DeletePreservationObjectResponse: {Result.ResultMajor}")]
public sealed record DeletePreservationObjectResponse: PreservationResponse
{
    /// <inheritdoc/>
    public override PreservationMessageKind Kind => PreservationMessageKind.DeletePreservationObjectResponse;

    /// <inheritdoc/>
    public override string OperationName => PreservationWellKnown.DeletePreservationObjectOperation;
}


/// <summary>
/// The <c>UpdatePOC</c> request (clause 5.3.6.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>
/// <para>
/// <strong>A delta is a preservation object.</strong> The <c>DeltaPOC</c> element has no type of its own in
/// either syntax: the XML schema references the <c>PO</c> element and the JSON schema references the <c>PO</c>
/// type, so the list below is a list of preservation objects under a different element name.
/// </para>
/// <para>
/// The clause describes two update strategies a container format may support — several deltas treated as plain
/// additions, or a single delta specifying the whole difference — and which one applies is a property of the
/// format rather than of this message.
/// </para>
/// <para>Ownership: this request owns the deltas it carries.</para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record UpdatePreservationObjectContainerRequest: PreservationRequest
{
    /// <inheritdoc/>
    public override PreservationMessageKind Kind => PreservationMessageKind.UpdatePreservationObjectContainerRequest;

    /// <inheritdoc/>
    public override string OperationName => PreservationWellKnown.UpdatePreservationObjectContainerOperation;

    /// <summary>The mandatory <c>POID</c> element — which container is to be updated.</summary>
    public required string PreservationObjectId { get; init; }

    /// <summary>The <c>DeltaPOC</c> elements — one or more; a request stating none is not a conformant update.</summary>
    public required IReadOnlyList<PreservationObject> DeltaContainers { get; init; }


    /// <summary>Disposes the deltas and then the inherited optional inputs.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            DisposeAll(DeltaContainers);
        }

        base.Dispose(disposing);
    }


    /// <summary>A short debugger string showing the container and how many deltas are stated.</summary>
    private string DebuggerDisplay =>
        $"UpdatePreservationObjectContainerRequest({PreservationObjectId}, {DeltaContainers.Count} deltas)";
}


/// <summary>
/// The <c>UpdatePOCResponse</c> (clause 5.3.6.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>
/// The clause recommends a sequential versioning scheme assigning identifiers such as <c>v1</c>, <c>v2</c> and
/// <c>v3</c>. That is a recommendation about how a service names versions, not a format a client may parse, so
/// the value is carried as the string it is.
/// </remarks>
[DebuggerDisplay("UpdatePreservationObjectContainerResponse: {VersionId}")]
public sealed record UpdatePreservationObjectContainerResponse: PreservationResponse
{
    /// <inheritdoc/>
    public override PreservationMessageKind Kind => PreservationMessageKind.UpdatePreservationObjectContainerResponse;

    /// <inheritdoc/>
    public override string OperationName => PreservationWellKnown.UpdatePreservationObjectContainerOperation;

    /// <summary>The optional <c>VersionID</c> element — the version the update produced, or <see langword="null"/>.</summary>
    public string? VersionId { get; init; }
}


/// <summary>
/// The <c>RetrieveTrace</c> request (clause 5.3.7.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
[DebuggerDisplay("RetrieveTraceRequest: {PreservationObjectId}")]
public sealed record RetrieveTraceRequest: PreservationRequest
{
    /// <inheritdoc/>
    public override PreservationMessageKind Kind => PreservationMessageKind.RetrieveTraceRequest;

    /// <inheritdoc/>
    public override string OperationName => PreservationWellKnown.RetrieveTraceOperation;

    /// <summary>The mandatory <c>POID</c> element — whose audit trail is wanted.</summary>
    public required string PreservationObjectId { get; init; }
}


/// <summary>
/// The <c>RetrieveTraceResponse</c> (clause 5.3.7.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>
/// The clause says the response "shall contain the <c>Trace</c> element", and the reproduced schema agrees, so
/// the member is required — a trace with no events is how a service says it recorded none.
/// </remarks>
[DebuggerDisplay("RetrieveTraceResponse: {Trace.Events.Count} events")]
public sealed record RetrieveTraceResponse: PreservationResponse
{
    /// <inheritdoc/>
    public override PreservationMessageKind Kind => PreservationMessageKind.RetrieveTraceResponse;

    /// <inheritdoc/>
    public override string OperationName => PreservationWellKnown.RetrieveTraceOperation;

    /// <summary>The mandatory <c>Trace</c> element.</summary>
    public required PreservationTrace Trace { get; init; }
}


/// <summary>
/// The <c>ValidateEvidence</c> request (clause 5.3.8.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>
/// <para>
/// <strong>A documented resolution of a spec-body inconsistency.</strong> Clause 5.3.8.1.1 states that the
/// request contains "the <c>Evidence</c> element ... It shall satisfy the requirements specified in clause
/// 5.4.4", while the schema fragment reproduced two clauses later marks the element <c>minOccurs="0"</c>. The
/// fragments are copied "for information" by the document's own words and the semantics clauses are its
/// normative body, so the element is required here — which is also the only reading under which the operation
/// has a subject at all.
/// </para>
/// <para>Ownership: this request owns the evidence and the objects it carries.</para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record ValidateEvidenceRequest: PreservationRequest
{
    /// <inheritdoc/>
    public override PreservationMessageKind Kind => PreservationMessageKind.ValidateEvidenceRequest;

    /// <inheritdoc/>
    public override string OperationName => PreservationWellKnown.ValidateEvidenceOperation;

    /// <summary>The <c>Evidence</c> element — the evidence to be validated.</summary>
    public required PreservationEvidence Evidence { get; init; }

    /// <summary>The <c>PO</c> elements — the objects the evidence protects, when the caller supplies them.</summary>
    public IReadOnlyList<PreservationObject> PreservationObjects { get; init; } = [];


    /// <summary>Disposes the evidence and the objects, and then the inherited optional inputs.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            Evidence.Dispose();
            DisposeAll(PreservationObjects);
        }

        base.Dispose(disposing);
    }


    /// <summary>A short debugger string showing the evidence format and how many objects came with it.</summary>
    private string DebuggerDisplay =>
        $"ValidateEvidenceRequest({Evidence.FormatId}, {PreservationObjects.Count} objects)";
}


/// <summary>
/// The <c>ValidateEvidenceResponse</c> (clause 5.3.8.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>
/// <para>
/// The validation report is carried as a preservation object, which is what clause 5.3.8.2.1 states by
/// referring to clause 5.4.5 for it, and the proof of existence is an instant at which the object is known to
/// have existed — a date and time in the XML binding, an integer of milliseconds since the epoch in the JSON one.
/// </para>
/// <para>Ownership: this response owns the validation report when it carries one.</para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record ValidateEvidenceResponse: PreservationResponse
{
    /// <inheritdoc/>
    public override PreservationMessageKind Kind => PreservationMessageKind.ValidateEvidenceResponse;

    /// <inheritdoc/>
    public override string OperationName => PreservationWellKnown.ValidateEvidenceOperation;

    /// <summary>The optional <c>ValidationReport</c> element, carried as a preservation object, or <see langword="null"/>.</summary>
    public PreservationObject? ValidationReport { get; init; }

    /// <summary>The optional <c>ProofOfExistence</c> element — when the object is known to have existed, or <see langword="null"/>.</summary>
    public DateTimeOffset? ProofOfExistence { get; init; }


    /// <summary>Disposes the validation report and then the inherited optional outputs.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            ValidationReport?.Dispose();
        }

        base.Dispose(disposing);
    }


    /// <summary>A short debugger string showing whether a report and a proof of existence came back.</summary>
    private string DebuggerDisplay =>
        $"ValidateEvidenceResponse({(ValidationReport is null ? "no report" : "report")}, {(ProofOfExistence is null ? "no proof of existence" : ProofOfExistence.Value.ToString("O"))})";
}


/// <summary>
/// The <c>Search</c> request (clause 5.3.9.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>
/// <strong>A documented resolution of a spec-body inconsistency.</strong> Clause 5.3.9.1.1 calls this "the
/// optional <c>Filter</c> element" while the schema fragment immediately below it declares the element without
/// <c>minOccurs</c>, which makes it mandatory. By the same rule applied to the validation request — the
/// semantics clause is the normative body and the fragments are copied for information — the element is optional
/// here. The query language itself is defined by the profile and not by this document, so the value is opaque.
/// </remarks>
[DebuggerDisplay("SearchRequest: {Filter}")]
public sealed record SearchRequest: PreservationRequest
{
    /// <inheritdoc/>
    public override PreservationMessageKind Kind => PreservationMessageKind.SearchRequest;

    /// <inheritdoc/>
    public override string OperationName => PreservationWellKnown.SearchOperation;

    /// <summary>The optional <c>Filter</c> element — a query string in the profile's own query language, or <see langword="null"/>.</summary>
    public string? Filter { get; init; }
}


/// <summary>
/// The <c>SearchResponse</c> (clause 5.3.9.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
[DebuggerDisplay("SearchResponse: {PreservationObjectIds.Count} identifiers")]
public sealed record SearchResponse: PreservationResponse
{
    /// <inheritdoc/>
    public override PreservationMessageKind Kind => PreservationMessageKind.SearchResponse;

    /// <inheritdoc/>
    public override string OperationName => PreservationWellKnown.SearchOperation;

    /// <summary>The <c>POID</c> elements — the identifiers matching the filter, of which there may be none.</summary>
    public IReadOnlyList<string> PreservationObjectIds { get; init; } = [];
}
