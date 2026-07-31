using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Which of the two alternatives of the value choice a preservation object's octets are, per clause 5.4.5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// The XML syntax offers a choice of <c>binaryData</c>, which is base64-encoded octets of any media type, and
/// <c>xmlData</c>, which is markup embedded natively. The reproduced JSON schema keeps only the first, so a
/// payload that is markup has no representation of its own over the JSON binding. Keeping the distinction in the
/// model is what lets a JSON binding refuse such a payload instead of silently re-encoding it into the other
/// alternative — a choice the document nowhere authorises.
/// </para>
/// <para>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised value never reads as either alternative.
/// </para>
/// </remarks>
public enum PreservationContentForm
{
    /// <summary>No content form stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The octets are the value of a <c>binaryData</c> element — arbitrary octets, base64-encoded on the wire.</summary>
    BinaryData = 1,

    /// <summary>The octets are the value of an <c>xmlData</c> element — markup embedded natively, with no counterpart in the JSON binding.</summary>
    XmlData = 2
}


/// <summary>
/// One sub-component this document defines only by reference to an external base specification, carried as the
/// octets the peer's syntax stated for it — an <c>OptionalInputs</c> or <c>OptionalOutputs</c> instance of clause
/// 5.3.1, or an <c>Extension</c> of the <c>Profile</c> component of clause 5.4.7 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why octets rather than a model.</strong> These shapes belong to specifications this document extends
/// by reference rather than redefines, and those texts are not among this repository's normative sources.
/// Modelling them from the little this document says would be inventing a wire shape; dropping them would make
/// every round trip lossy. Carrying them verbatim does neither.
/// </para>
/// <para><strong>Ownership.</strong> An instance owns <see cref="Content"/>; whoever holds the element disposes it.</para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationOpaqueElement: IDisposable
{
    /// <summary>The octets the carrying syntax stated for this sub-component, exactly as they arrived.</summary>
    public required PooledMemory Content { get; init; }

    /// <summary>
    /// What the carrying syntax named this sub-component, when it could state a name, or <see langword="null"/>.
    /// This document defines neither the name nor the content, so the value is carried and never interpreted.
    /// </summary>
    public string? Identifier { get; init; }


    /// <summary>Disposes <see cref="Content"/>.</summary>
    public void Dispose() => Content.Dispose();


    /// <summary>A short debugger string showing the identifier and the size of the carried octets.</summary>
    private string DebuggerDisplay => $"PreservationOpaqueElement({Identifier ?? "unnamed"}, {Content.Length} octets)";
}


/// <summary>
/// The <c>PO</c> component — the payload container every operation that carries data uses, per clause 5.4.5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The same type serves under three element names.</strong> A preservation object appears as <c>PO</c>
/// in five operations, as <c>DeltaPOC</c> in the update operation — where both syntaxes resolve the element to
/// this very component rather than to a type of its own — and as <c>ValidationReport</c> in the validation
/// response, whose clause states outright that the report satisfies the requirements of clause 5.4.5. Giving
/// any of the three a distinct record would diverge from the wire shape.
/// </para>
/// <para>
/// <strong>Two conditional obligations the type system cannot carry.</strong> Clause 5.4.5.1 makes
/// <see cref="FormatId"/> mandatory whenever the object needs treatment beyond base64 decoding — an evidence, a
/// specific submission format, an additional output format — and makes <see cref="MimeType"/> mandatory whenever
/// <see cref="FormatId"/> is omitted. Both are stated as obligations on the value rather than on the shape, so
/// both members are optional here and <see cref="PreservationMessageBounds"/> is where the second one is
/// checked.
/// </para>
/// <para>
/// <strong><see cref="RelatedObjects"/> is a list because the schema type is.</strong> The prose says "one
/// instance of a unique identifier reference" while the attribute's type is the plural identifier-reference list
/// type. A scalar reading would drop every reference but the first on a round trip through a document that
/// states several, so the reading that loses nothing is the one modelled.
/// </para>
/// <para><strong>Ownership.</strong> An instance owns <see cref="Content"/>; whoever holds the object disposes it.</para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "A format identifier is compared as an exact character sequence against the vocabulary of PreservationFormatWellKnown; System.Uri normalises case and escaping, which would make two identifiers naming different formats compare equal.")]
public sealed record PreservationObject: IDisposable
{
    /// <summary>The octets of the value choice — the object itself.</summary>
    public required PooledMemory Content { get; init; }

    /// <summary>Which alternative of the value choice <see cref="Content"/> came from.</summary>
    public required PreservationContentForm ContentForm { get; init; }

    /// <summary>The <c>FormatId</c> attribute — the format of the object, or <see langword="null"/> when the wire stated none.</summary>
    public string? FormatId { get; init; }

    /// <summary>The <c>MimeType</c> attribute — the media type of the object, which clause 5.4.5.1 requires whenever <see cref="FormatId"/> is absent.</summary>
    public string? MimeType { get; init; }

    /// <summary>The <c>PronomId</c> attribute — a persistent unique identifier of the file format, or <see langword="null"/>.</summary>
    public string? PronomId { get; init; }

    /// <summary>The <c>ID</c> attribute — unique within the document that carries it, or <see langword="null"/>.</summary>
    public string? Id { get; init; }

    /// <summary>The <c>RelatedObjects</c> attribute — the identifier references this object names, of which there may be none.</summary>
    public IReadOnlyList<string> RelatedObjects { get; init; } = [];


    /// <summary>Disposes <see cref="Content"/>.</summary>
    public void Dispose() => Content.Dispose();


    /// <summary>A short debugger string showing the format, the content form and the size of the payload.</summary>
    private string DebuggerDisplay =>
        $"PreservationObject({FormatId ?? MimeType ?? "unstated format"}, {ContentForm}, {Content.Length} octets)";
}


/// <summary>
/// The <c>Evidence</c> component — a preservation evidence, per clause 5.4.4 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why this is not a subtype of <see cref="PreservationObject"/> here.</strong> On the wire it extends
/// the <c>PO</c> component and inherits its six sub-components, and clause 5.4.4.1 then tightens one of them:
/// <see cref="FormatId"/>, optional on an object, "is mandatory in this case". A .NET hierarchy cannot state
/// that tightening without either hiding the inherited member — leaving two properties of the same name, one of
/// them empty — or losing the obligation. The six inherited members are therefore restated on this record with
/// the tightening applied, which is the shape the specification actually describes.
/// </para>
/// <para><strong>Ownership.</strong> An instance owns <see cref="Content"/>; whoever holds the evidence disposes it.</para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "A format identifier is compared as an exact character sequence against the vocabulary of PreservationFormatWellKnown; System.Uri normalises case and escaping, which would make two identifiers naming different formats compare equal.")]
public sealed record PreservationEvidence: IDisposable
{
    /// <summary>The octets of the inherited value choice — the evidence itself.</summary>
    public required PooledMemory Content { get; init; }

    /// <summary>Which alternative of the inherited value choice <see cref="Content"/> came from.</summary>
    public required PreservationContentForm ContentForm { get; init; }

    /// <summary>
    /// The <c>FormatId</c> attribute — mandatory on an evidence (clause 5.4.4.1), naming one of the evidence
    /// formats of clause A.2; see <see cref="PreservationFormatWellKnown.IsEvidenceFormat"/>.
    /// </summary>
    public required string FormatId { get; init; }

    /// <summary>The inherited <c>MimeType</c> attribute, or <see langword="null"/>.</summary>
    public string? MimeType { get; init; }

    /// <summary>The inherited <c>PronomId</c> attribute, or <see langword="null"/>.</summary>
    public string? PronomId { get; init; }

    /// <summary>The inherited <c>ID</c> attribute, or <see langword="null"/>.</summary>
    public string? Id { get; init; }

    /// <summary>The inherited <c>RelatedObjects</c> attribute — the identifier references this evidence names.</summary>
    public IReadOnlyList<string> RelatedObjects { get; init; } = [];

    /// <summary>The <c>POID</c> attribute this component adds — which preservation object the evidence belongs to, or <see langword="null"/>.</summary>
    public string? PreservationObjectId { get; init; }

    /// <summary>The <c>VersionID</c> attribute this component adds — which version of that object, or <see langword="null"/>.</summary>
    public string? VersionId { get; init; }


    /// <summary>Disposes <see cref="Content"/>.</summary>
    public void Dispose() => Content.Dispose();


    /// <summary>A short debugger string showing the evidence format and the size of the payload.</summary>
    private string DebuggerDisplay => $"PreservationEvidence({FormatId}, {ContentForm}, {Content.Length} octets)";
}


/// <summary>
/// The <c>Event</c> component — one event that occurred inside a preservation service, per clause 5.4.3 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// Clause 5.4.3.1 recommends that <see cref="Subject"/> identify the client when the client triggered the event
/// and indicate the service when the service did; the element is a mandatory string either way, and which of the
/// two a value states is not something a reader can decide.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationEvent
{
    /// <summary>
    /// The mandatory <c>Time</c> element — when the event occurred. The XML syntax states a date and time; the
    /// JSON syntax states an integer of milliseconds since the epoch, which is a binding difference rather than a
    /// difference in meaning.
    /// </summary>
    public required DateTimeOffset Time { get; init; }

    /// <summary>The mandatory <c>Subject</c> element — who or what triggered the event.</summary>
    public required string Subject { get; init; }

    /// <summary>The mandatory <c>Operation</c> element — the characteristic of the event, such as the operation that caused it.</summary>
    public required string Operation { get; init; }

    /// <summary>The optional <c>Object</c> element — which object the event addressed, or <see langword="null"/>.</summary>
    public string? Object { get; init; }

    /// <summary>The optional <c>Detail</c> element — free text, or <see langword="null"/>.</summary>
    public string? Detail { get; init; }


    /// <summary>A short debugger string showing when the event happened and what it was.</summary>
    private string DebuggerDisplay => $"PreservationEvent({Time:O}, {Operation}, {Subject})";
}


/// <summary>
/// The <c>Trace</c> component — the audit trail a <c>RetrieveTrace</c> response carries, per clause 5.4.10 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// The component is a wrapper around zero or more events, and an empty trace is a conformant answer: a service
/// that recorded nothing about a preservation object says so by returning no events, not by omitting the trace.
/// </remarks>
[DebuggerDisplay("PreservationTrace: {Events.Count} events")]
public sealed record PreservationTrace
{
    /// <summary>The <c>Event</c> elements, of which there may be none.</summary>
    public IReadOnlyList<PreservationEvent> Events { get; init; } = [];
}


/// <summary>
/// The <c>Result</c> component every response carries, per clause 5.3.1.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The major code is carried, not enumerated.</strong> <c>Result</c> is defined by reference to an
/// external base specification, and this document states only the minor codes — the fifteen errors and two
/// warnings of <see cref="PreservationResultWellKnown"/>. The major code is therefore a string carried exactly as
/// the peer sent it; no vocabulary is invented for it.
/// </para>
/// <para>
/// <strong><see cref="ResultMessage"/> is where a partly successful call explains itself</strong>: clause
/// 5.3.4.2.1 recommends that a service returning the partial-success warning put the details there.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "Result codes are compared as exact character sequences against the vocabulary of PreservationResultWellKnown; System.Uri normalises case and escaping, which would make two codes naming different failures compare equal.")]
public sealed record PreservationResult
{
    /// <summary>The major status code, carried verbatim from the wire.</summary>
    public required string ResultMajor { get; init; }

    /// <summary>The minor status code — one of the seventeen of <see cref="PreservationResultWellKnown"/>, another vocabulary's code, or <see langword="null"/>.</summary>
    public string? ResultMinor { get; init; }

    /// <summary>The human-readable message a service may add, or <see langword="null"/>.</summary>
    public string? ResultMessage { get; init; }


    /// <summary>A short debugger string showing both codes.</summary>
    private string DebuggerDisplay => $"PreservationResult({ResultMajor}, {ResultMinor ?? "no minor code"})";
}


/// <summary>
/// One <c>Format</c> element of a profile — a format a service accepts or produces, per clause 5.4.7 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// The element's own shape belongs to an external base specification and is not reproduced by this document,
/// which references exactly one of its children — the format identifier a <c>RetrievePO</c> request matches its
/// <c>POFormat</c> against (clause 5.3.4.1.1). That child is what this record carries; nothing else is invented.
/// </remarks>
[DebuggerDisplay("PreservationFormatDescriptor: {FormatId}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "A format identifier is compared as an exact character sequence against the vocabulary of PreservationFormatWellKnown, for the reason given on PreservationObject.")]
public sealed record PreservationFormatDescriptor
{
    /// <summary>The <c>FormatID</c> child — which format is meant.</summary>
    public required string FormatId { get; init; }
}


/// <summary>
/// One <c>Operation</c> element of a profile — an operation a service implements and in which formats, per clause
/// 5.4.7 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// A profile carries one of these per supported operation, which is how a client learns what it may call beyond
/// the one operation clause 5.2 makes mandatory. The element's own type comes from an external base
/// specification; the members below are the ones this document's clauses reference by name.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationOperationDescriptor
{
    /// <summary>The operation's name — one of the eight of <see cref="PreservationWellKnown.IsOperationName"/>.</summary>
    public required string Name { get; init; }

    /// <summary>The <c>Input/Format</c> children — submission formats this operation accepts that need treatment beyond base64 decoding.</summary>
    public IReadOnlyList<PreservationFormatDescriptor> InputFormats { get; init; } = [];

    /// <summary>The <c>Output/Format</c> children — formats this operation can return; a <c>RetrievePO</c> request's <c>POFormat</c> is matched against these.</summary>
    public IReadOnlyList<PreservationFormatDescriptor> OutputFormats { get; init; } = [];

    /// <summary>The <c>Option</c> children — the optional inputs this operation supports, carried as the identifiers the profile states.</summary>
    public IReadOnlyList<string> Options { get; init; } = [];


    /// <summary>A short debugger string showing the operation and how many formats it names.</summary>
    private string DebuggerDisplay =>
        $"PreservationOperationDescriptor({Name}, {InputFormats.Count} in, {OutputFormats.Count} out)";
}


/// <summary>
/// One <c>Policy</c> element of a profile — the policy a service operates under, per clause 5.4.7 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// A profile states this element once with the preservation-evidence policy type, and a second time with the
/// signature-validation policy type when the preservation goal is the preservation of digital signatures and the
/// validation data is not provided by the client. That second condition is a fact about how submissions are made
/// rather than a field of any component, so no reader can check it from a profile alone — which is why
/// <see cref="PreservationMessageBounds"/> checks the cardinality and not the condition.
/// </para>
/// <para>
/// The element's content shape belongs to an external base specification; what this document states is its type,
/// and a policy is human-readable in this version of the protocol.
/// </para>
/// </remarks>
[DebuggerDisplay("PreservationPolicyReference: {PolicyType}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "A policy type is compared as an exact character sequence against PreservationWellKnown.IsPolicyType, for the reason given there.")]
public sealed record PreservationPolicyReference
{
    /// <summary>The policy's type — one of the two of <see cref="PreservationWellKnown.IsPolicyType"/>.</summary>
    public required string PolicyType { get; init; }

    /// <summary>Where the policy document is to be found, when the profile stated it by reference, or <see langword="null"/>.</summary>
    public string? PolicyLocation { get; init; }
}


/// <summary>
/// One <c>Description</c> element of a profile — human-readable text in one language, per clause 5.4.7 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// The element's type is the international-string type of an external base specification, which is what makes a
/// profile able to describe itself in several languages; the two members below are the text and the language it
/// is in, and nothing further is assumed about that type.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationLocalizedText
{
    /// <summary>The text itself.</summary>
    public required string Text { get; init; }

    /// <summary>The language the text is in, as the carrying syntax stated it, or <see langword="null"/> when it stated none.</summary>
    public string? Language { get; init; }


    /// <summary>A short debugger string showing the language and the beginning of the text.</summary>
    private string DebuggerDisplay =>
        $"PreservationLocalizedText({Language ?? "no language"}, {(Text.Length <= 24 ? Text : Text[..24] + "…")})";
}


/// <summary>
/// The <c>ProfileValidityPeriod</c> element — when a profile is in force, per clause 5.4.7 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// A profile with no stated end is one still in force, which is why <see cref="ValidUntil"/> is optional while
/// <see cref="ValidFrom"/> is not.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationValidityPeriod
{
    /// <summary>The mandatory <c>ValidFrom</c> child — when the profile came into force.</summary>
    public required DateTimeOffset ValidFrom { get; init; }

    /// <summary>The optional <c>ValidUntil</c> child — when it ceased to be in force, or <see langword="null"/> when it has not.</summary>
    public DateTimeOffset? ValidUntil { get; init; }


    /// <summary>A short debugger string showing the period.</summary>
    private string DebuggerDisplay => $"PreservationValidityPeriod({ValidFrom:O} – {(ValidUntil is null ? "open" : ValidUntil.Value.ToString("O"))})";
}


/// <summary>
/// The <c>Profile</c> component — everything a service publishes about one operational profile, per clause 5.4.7
/// of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>, and the payload of the one operation clause 5.2 makes mandatory.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Required members are the ones the component's own clause makes mandatory</strong>, whether the element
/// is declared locally or inherited from the external base type: the identifier, at least one operation, at
/// least one policy, the validity period, the storage model, at least one preservation goal and at least one
/// evidence format. "At least one" is not something a list type can state, so those members are required and
/// their non-emptiness is checked by <see cref="PreservationMessageBounds"/>.
/// </para>
/// <para>
/// <strong>Durations are carried lexically.</strong> <see cref="ExpectedEvidenceDuration"/> and
/// <see cref="PreservationEvidenceRetentionPeriod"/> are schema durations, which may state years and months —
/// quantities no fixed-length interval can hold without assuming how long a year is. The lexical form is
/// therefore carried as the wire stated it.
/// </para>
/// <para>
/// <strong>The retention period is conditionally mandatory</strong>: clause 5.4.7.1 requires it "in case of
/// preservation with temporary storage", and each Annex F scheme's own clause restates that condition as either
/// "shall be present" or "shall not be present". The member is optional here and the condition is checked
/// against <see cref="StorageModel"/> where the bounds are.
/// </para>
/// <para><strong>Ownership.</strong> An instance owns its <see cref="Extensions"/>; disposing it disposes them.</para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "Profile, scheme and goal identifiers are compared as exact character sequences against the vocabulary of PreservationWellKnown; System.Uri normalises case, escaping and trailing separators, which would make two identifiers that name different profiles compare equal.")]
public sealed record PreservationProfile: IDisposable
{
    /// <summary>The mandatory <c>ProfileIdentifier</c> element — the identifier a request names this profile by.</summary>
    public required string ProfileIdentifier { get; init; }

    /// <summary>The <c>Operation</c> elements — one per operation the service implements under this profile, of which there is at least one.</summary>
    public required IReadOnlyList<PreservationOperationDescriptor> Operations { get; init; }

    /// <summary>The <c>Policy</c> elements — one or two, per the condition documented on <see cref="PreservationPolicyReference"/>.</summary>
    public required IReadOnlyList<PreservationPolicyReference> Policies { get; init; }

    /// <summary>The mandatory <c>ProfileValidityPeriod</c> element.</summary>
    public required PreservationValidityPeriod ValidityPeriod { get; init; }

    /// <summary>The mandatory <c>PreservationStorageModel</c> element — one of the three of <see cref="PreservationWellKnown.IsStorageModel"/>.</summary>
    public required string StorageModel { get; init; }

    /// <summary>The <c>PreservationGoal</c> elements — at least one of the three of <see cref="PreservationWellKnown.IsPreservationGoal"/>.</summary>
    public required IReadOnlyList<string> PreservationGoals { get; init; }

    /// <summary>The <c>EvidenceFormat</c> elements — at least one, naming the formats of clause A.2 this profile produces.</summary>
    public required IReadOnlyList<PreservationFormatDescriptor> EvidenceFormats { get; init; }

    /// <summary>The <c>SchemeIdentifier</c> element — which Annex F scheme this profile instantiates, or <see langword="null"/>.</summary>
    public string? SchemeIdentifier { get; init; }

    /// <summary>The <c>Specification</c> elements — where the specifications this profile follows can be retrieved.</summary>
    public IReadOnlyList<string> Specifications { get; init; } = [];

    /// <summary>The <c>Description</c> elements — the profile described for a reader, in as many languages as the service publishes.</summary>
    public IReadOnlyList<PreservationLocalizedText> Descriptions { get; init; } = [];

    /// <summary>The <c>ExpectedEvidenceDuration</c> element, as the wire's lexical duration, or <see langword="null"/>.</summary>
    public string? ExpectedEvidenceDuration { get; init; }

    /// <summary>The <c>PreservationEvidenceRetentionPeriod</c> element, as the wire's lexical duration, or <see langword="null"/> — conditionally mandatory, see the remarks.</summary>
    public string? PreservationEvidenceRetentionPeriod { get; init; }

    /// <summary>The <c>Extension</c> elements — carried verbatim, per <see cref="PreservationOpaqueElement"/>.</summary>
    public IReadOnlyList<PreservationOpaqueElement> Extensions { get; init; } = [];


    /// <summary>Disposes every element of <see cref="Extensions"/>.</summary>
    public void Dispose()
    {
        foreach(PreservationOpaqueElement extension in Extensions)
        {
            extension.Dispose();
        }
    }


    /// <summary>A short debugger string showing the profile, its storage model and how many operations it announces.</summary>
    private string DebuggerDisplay =>
        $"PreservationProfile({ProfileIdentifier}, {StorageModel}, {Operations.Count} operations)";
}
