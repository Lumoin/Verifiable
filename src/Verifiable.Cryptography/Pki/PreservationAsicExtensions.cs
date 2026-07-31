using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Which of the seven container-extension payloads of clause 5.5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> an <c>Extension</c> element carries.
/// </summary>
/// <remarks>
/// <para>
/// Six of them extend the <c>ASiCManifest</c> element (clause 5.5.2) and the seventh extends a
/// <c>DataObjectReference</c> element (clause 5.5.3), which is a difference in where an extension may appear
/// rather than in what it is; <see cref="PreservationAsicExtensionWellKnown.IsManifestExtension"/> and
/// <see cref="PreservationAsicExtensionWellKnown.IsDataObjectReferenceExtension"/> state which is which.
/// </para>
/// <para>
/// <see cref="None"/> occupies zero so a default-initialised value never reads as a recognised payload.
/// </para>
/// </remarks>
public enum PreservationAsicExtensionKind
{
    /// <summary>No payload kind stated, or an extension this vocabulary does not name. The value of an unset field, by design.</summary>
    None = 0,

    /// <summary>The <c>ContainerID</c> extension of clause 5.5.2.1 — the service-specific identifier of a preservation object container.</summary>
    ContainerId = 1,

    /// <summary>The <c>PreservationPeriod</c> extension of clause 5.5.2.2 — the period the container is preserved for.</summary>
    PreservationPeriod = 2,

    /// <summary>The <c>PreservationSubmitter</c> extension of clause 5.5.2.3 — the client in its role as submitter.</summary>
    PreservationSubmitter = 3,

    /// <summary>The <c>IsUpdatedVersionOf</c> extension of clause 5.5.2.4 — the container this one updates.</summary>
    IsUpdatedVersionOf = 4,

    /// <summary>The <c>CanonicalizationMethod</c> extension of clause 5.5.2.5 — how markup is canonicalized before preservation techniques are applied.</summary>
    CanonicalizationMethod = 5,

    /// <summary>The <c>ValidationReport</c> extension of clause 5.5.2.6 — a validation report over the evidence and the data objects the manifest refers to.</summary>
    ValidationReport = 6,

    /// <summary>The <c>IsMetaDataOf</c> extension of clause 5.5.3.1 — the data object this one is metadata of.</summary>
    IsMetaDataOf = 7
}


/// <summary>
/// The element names, the placement rules and the criticality guidance clause 5.5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> states for the seven container extensions, together with the extension policy
/// a consumer applies them through.
/// </summary>
/// <remarks>
/// <para>
/// <strong>These names are XML-only, so they are not <see cref="PreservationName"/> pairs.</strong> Every other
/// component of this protocol is carried in both of the document's normative syntaxes and therefore has an
/// element name and a JSON member name; these seven live inside an <c>Extension</c> element of a container
/// manifest, which is an XML document of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.4, and the document states no JSON mapping table for any of them.
/// Stating one would put a name on the wire nothing supports.
/// </para>
/// <para>
/// <strong>This is the first concrete criticality guidance for the container specification's own attribute.</strong>
/// Annex A.4.2 of EN 319 162-1 declares <c>Extension/@Critical</c> <c>use="required"</c> and states no consumer
/// obligation for it, which is why <see cref="AsicManifestExtensionPolicy"/> exists. Clause 5.5 is the first
/// text to say, per named extension, whether it <em>should</em> or <em>should not</em> be critical:
/// <see cref="PreservationAsicExtensionKind.CanonicalizationMethod"/> should be, "because preservation evidences
/// will appear to become invalid, if a required canonicalization method is missed to be applied", and the other
/// six should not. Both halves are recommendations, so
/// <see cref="StateCriticality(PreservationAsicExtensionKind, bool)"/> reports a departure rather than refusing
/// one.
/// </para>
/// <para>
/// <strong>One namespace is deliberately not stated.</strong> Clause 5.5.2.5.2 defines
/// <c>CanonicalizationMethod</c> in a schema of the external base specification this document builds on, whose
/// text this repository does not hold, so this class states the element's local name and no namespace for it.
/// <see cref="RecommendedPolicy"/> therefore recognises the six extensions this document's own schema declares,
/// and <see cref="RecommendedPolicyRecognizing(string)"/> adds the seventh once a caller states the namespace it
/// met. The
/// consequence is deliberate and secure: an unrecognised <em>critical</em> canonicalization method stops a
/// consumer under <see cref="AsicManifestExtensionPolicy.Strict"/>'s own rule, which is exactly what clause
/// 5.5.2.5.3's reason asks for.
/// </para>
/// <para>
/// <strong>Comparison is ordinal and case-sensitive</strong>, as everywhere else in this vocabulary: an XML
/// element name is an exact character sequence.
/// </para>
/// </remarks>
public static class PreservationAsicExtensionWellKnown
{
    /// <summary>The <c>ContainerID</c> element (clause 5.5.2.1.2).</summary>
    public static string ContainerIdElementName { get; } = "ContainerID";

    /// <summary>The <c>POID</c> element, the mandatory child of <c>ContainerID</c> (clause 5.5.2.1.1).</summary>
    public static string PreservationObjectIdElementName { get; } = "POID";

    /// <summary>The <c>VersionID</c> element, the optional child of <c>ContainerID</c> (clause 5.5.2.1.1).</summary>
    public static string VersionIdElementName { get; } = "VersionID";

    /// <summary>The <c>PreservationPeriod</c> element, of XML schema type <c>date</c> (clause 5.5.2.2.2).</summary>
    public static string PreservationPeriodElementName { get; } = "PreservationPeriod";

    /// <summary>The <c>PreservationSubmitter</c> element, of XML schema type <c>string</c> (clause 5.5.2.3.2).</summary>
    public static string PreservationSubmitterElementName { get; } = "PreservationSubmitter";

    /// <summary>The <c>IsUpdatedVersionOf</c> element, of XML schema type <c>anyURI</c> (clause 5.5.2.4.2).</summary>
    public static string IsUpdatedVersionOfElementName { get; } = "IsUpdatedVersionOf";

    /// <summary>
    /// The <c>CanonicalizationMethod</c> element (clause 5.5.2.5.2). Its namespace belongs to the external base
    /// specification's schema and is not stated here; see the class remarks.
    /// </summary>
    public static string CanonicalizationMethodElementName { get; } = "CanonicalizationMethod";

    /// <summary>The <c>ValidationReport</c> element, which clause 5.5.2.6.2 requires to satisfy clause 5.4.5 — that is, to be a preservation object.</summary>
    public static string ValidationReportElementName { get; } = "ValidationReport";

    /// <summary>The <c>IsMetaDataOf</c> element, of XML schema type <c>anyURI</c> (clause 5.5.3.1.2).</summary>
    public static string IsMetaDataOfElementName { get; } = "IsMetaDataOf";


    /// <summary>The qualified name of the <c>ContainerID</c> extension's content element.</summary>
    public static AsicManifestExtensionName ContainerIdExtensionName { get; } =
        new(PreservationWellKnown.PreservationNamespace, ContainerIdElementName);

    /// <summary>The qualified name of the <c>PreservationPeriod</c> extension's content element.</summary>
    public static AsicManifestExtensionName PreservationPeriodExtensionName { get; } =
        new(PreservationWellKnown.PreservationNamespace, PreservationPeriodElementName);

    /// <summary>The qualified name of the <c>PreservationSubmitter</c> extension's content element.</summary>
    public static AsicManifestExtensionName PreservationSubmitterExtensionName { get; } =
        new(PreservationWellKnown.PreservationNamespace, PreservationSubmitterElementName);

    /// <summary>The qualified name of the <c>IsUpdatedVersionOf</c> extension's content element.</summary>
    public static AsicManifestExtensionName IsUpdatedVersionOfExtensionName { get; } =
        new(PreservationWellKnown.PreservationNamespace, IsUpdatedVersionOfElementName);

    /// <summary>The qualified name of the <c>ValidationReport</c> extension's content element.</summary>
    public static AsicManifestExtensionName ValidationReportExtensionName { get; } =
        new(PreservationWellKnown.PreservationNamespace, ValidationReportElementName);

    /// <summary>The qualified name of the <c>IsMetaDataOf</c> extension's content element.</summary>
    public static AsicManifestExtensionName IsMetaDataOfExtensionName { get; } =
        new(PreservationWellKnown.PreservationNamespace, IsMetaDataOfElementName);


    /// <summary>
    /// The extension policy a consumer of this profile applies: the six extensions whose element this document's
    /// own schema declares are recognised, and an unrecognised critical extension still stops the evaluation.
    /// </summary>
    /// <remarks>
    /// The seventh extension is absent for the reason the class remarks give, and its absence is what makes a
    /// critical <c>CanonicalizationMethod</c> from an unknown namespace fail closed rather than pass unread.
    /// </remarks>
    public static AsicManifestExtensionPolicy RecommendedPolicy { get; } = new()
    {
        RecognizedExtensions =
        [
            ContainerIdExtensionName,
            PreservationPeriodExtensionName,
            PreservationSubmitterExtensionName,
            IsUpdatedVersionOfExtensionName,
            ValidationReportExtensionName,
            IsMetaDataOfExtensionName
        ]
    };


    /// <summary>
    /// The extension policy of <see cref="RecommendedPolicy"/> with the canonicalization method recognised in the
    /// namespace the caller states it met it in.
    /// </summary>
    /// <param name="canonicalizationMethodNamespace">The namespace of the external schema's <c>CanonicalizationMethod</c> element.</param>
    /// <returns>A policy recognising all seven extensions.</returns>
    /// <exception cref="ArgumentException">When the namespace is absent or empty; an extension recognised under no namespace is not recognised.</exception>
    public static AsicManifestExtensionPolicy RecommendedPolicyRecognizing(string canonicalizationMethodNamespace)
    {
        ArgumentException.ThrowIfNullOrEmpty(canonicalizationMethodNamespace);

        return new AsicManifestExtensionPolicy
        {
            RecognizedExtensions =
            [
                .. RecommendedPolicy.RecognizedExtensions,
                new AsicManifestExtensionName(canonicalizationMethodNamespace, CanonicalizationMethodElementName)
            ]
        };
    }


    /// <summary>
    /// Classifies the content element of an <c>Extension</c> into one of the seven payloads of clause 5.5.
    /// </summary>
    /// <param name="name">The qualified name of the extension's content element, or <see langword="null"/> when it carried none.</param>
    /// <returns>The payload kind, or <see cref="PreservationAsicExtensionKind.None"/> when the name is not one of this vocabulary's.</returns>
    /// <remarks>
    /// The canonicalization method is not classified here: this document declares no namespace for it, and
    /// answering on the local name alone would classify any element of that name from any namespace as this
    /// extension. <see cref="KindOf(AsicManifestExtensionName?, string)"/> is the form that takes the namespace
    /// a caller met.
    /// </remarks>
    public static PreservationAsicExtensionKind KindOf(AsicManifestExtensionName? name)
    {
        if(name is not AsicManifestExtensionName qualified
            || !string.Equals(qualified.NamespaceName, PreservationWellKnown.PreservationNamespace, StringComparison.Ordinal))
        {
            return PreservationAsicExtensionKind.None;
        }

        return qualified.LocalName switch
        {
            var local when string.Equals(local, ContainerIdElementName, StringComparison.Ordinal) => PreservationAsicExtensionKind.ContainerId,
            var local when string.Equals(local, PreservationPeriodElementName, StringComparison.Ordinal) => PreservationAsicExtensionKind.PreservationPeriod,
            var local when string.Equals(local, PreservationSubmitterElementName, StringComparison.Ordinal) => PreservationAsicExtensionKind.PreservationSubmitter,
            var local when string.Equals(local, IsUpdatedVersionOfElementName, StringComparison.Ordinal) => PreservationAsicExtensionKind.IsUpdatedVersionOf,
            var local when string.Equals(local, ValidationReportElementName, StringComparison.Ordinal) => PreservationAsicExtensionKind.ValidationReport,
            var local when string.Equals(local, IsMetaDataOfElementName, StringComparison.Ordinal) => PreservationAsicExtensionKind.IsMetaDataOf,
            _ => PreservationAsicExtensionKind.None
        };
    }


    /// <summary>
    /// Classifies the content element of an <c>Extension</c>, recognising the canonicalization method in the
    /// namespace the caller states.
    /// </summary>
    /// <param name="name">The qualified name of the extension's content element, or <see langword="null"/> when it carried none.</param>
    /// <param name="canonicalizationMethodNamespace">The namespace of the external schema's <c>CanonicalizationMethod</c> element.</param>
    /// <returns>The payload kind, or <see cref="PreservationAsicExtensionKind.None"/>.</returns>
    /// <exception cref="ArgumentException">When the namespace is absent or empty.</exception>
    public static PreservationAsicExtensionKind KindOf(AsicManifestExtensionName? name, string canonicalizationMethodNamespace)
    {
        ArgumentException.ThrowIfNullOrEmpty(canonicalizationMethodNamespace);

        if(name is AsicManifestExtensionName qualified
            && string.Equals(qualified.NamespaceName, canonicalizationMethodNamespace, StringComparison.Ordinal)
            && string.Equals(qualified.LocalName, CanonicalizationMethodElementName, StringComparison.Ordinal))
        {
            return PreservationAsicExtensionKind.CanonicalizationMethod;
        }

        return KindOf(name);
    }


    /// <summary>Determines whether a payload extends the <c>ASiCManifest</c> element (clause 5.5.2).</summary>
    /// <param name="kind">The payload kind.</param>
    /// <returns><see langword="true"/> for the six manifest-level extensions.</returns>
    public static bool IsManifestExtension(PreservationAsicExtensionKind kind) => kind switch
    {
        PreservationAsicExtensionKind.ContainerId => true,
        PreservationAsicExtensionKind.PreservationPeriod => true,
        PreservationAsicExtensionKind.PreservationSubmitter => true,
        PreservationAsicExtensionKind.IsUpdatedVersionOf => true,
        PreservationAsicExtensionKind.CanonicalizationMethod => true,
        PreservationAsicExtensionKind.ValidationReport => true,
        _ => false
    };


    /// <summary>Determines whether a payload extends the <c>DataObjectReference</c> element (clause 5.5.3).</summary>
    /// <param name="kind">The payload kind.</param>
    /// <returns><see langword="true"/> for the one data-object-reference-level extension.</returns>
    public static bool IsDataObjectReferenceExtension(PreservationAsicExtensionKind kind) =>
        kind == PreservationAsicExtensionKind.IsMetaDataOf;


    /// <summary>
    /// States the criticality the specification recommends for a payload.
    /// </summary>
    /// <param name="kind">The payload kind.</param>
    /// <returns><see langword="true"/> when clause 5.5 recommends the extension be critical.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="kind"/> is not one of the seven payloads.</exception>
    /// <remarks>
    /// Exactly one of the seven — <see cref="PreservationAsicExtensionKind.CanonicalizationMethod"/>, clause
    /// 5.5.2.5.3 — is recommended to be critical; clauses 5.5.2.1.3, 5.5.2.2.3, 5.5.2.3.3, 5.5.2.4.3, 5.5.2.6.3
    /// and 5.5.3.1.3 recommend the other six not be.
    /// </remarks>
    public static bool IsCriticalRecommended(PreservationAsicExtensionKind kind) => kind switch
    {
        PreservationAsicExtensionKind.CanonicalizationMethod => true,
        PreservationAsicExtensionKind.ContainerId => false,
        PreservationAsicExtensionKind.PreservationPeriod => false,
        PreservationAsicExtensionKind.PreservationSubmitter => false,
        PreservationAsicExtensionKind.IsUpdatedVersionOf => false,
        PreservationAsicExtensionKind.ValidationReport => false,
        PreservationAsicExtensionKind.IsMetaDataOf => false,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Clause 5.5 states a criticality recommendation for its seven extensions and for nothing else.")
    };


    /// <summary>
    /// States whether an extension's <c>Critical</c> attribute follows the recommendation of its own clause.
    /// </summary>
    /// <param name="kind">The payload kind.</param>
    /// <param name="critical">The value of the extension's <c>Critical</c> attribute.</param>
    /// <returns>The criticality report.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="kind"/> is not one of the seven payloads.</exception>
    /// <remarks>
    /// A departure is reported and never refused, because both halves of the guidance are stated with the
    /// recommendation keyword. What a consumer refuses is a different question — an unrecognised critical
    /// extension — and that answer belongs to <see cref="AsicManifestExtensionPolicy"/>.
    /// </remarks>
    public static PreservationAsicExtensionCriticality StateCriticality(PreservationAsicExtensionKind kind, bool critical) =>
        new(kind, critical, IsCriticalRecommended(kind));
}


/// <summary>
/// Whether one <c>Extension</c>'s <c>Critical</c> attribute matches the recommendation clause 5.5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> states for its payload.
/// </summary>
/// <param name="Kind">Which payload the extension carries.</param>
/// <param name="Critical">The value of the extension's <c>Critical</c> attribute.</param>
/// <param name="RecommendedCritical">The value the payload's own criticality clause recommends.</param>
[DebuggerDisplay("PreservationAsicExtensionCriticality: {Kind}, critical {Critical}, recommended {RecommendedCritical}")]
public readonly record struct PreservationAsicExtensionCriticality(
    PreservationAsicExtensionKind Kind,
    bool Critical,
    bool RecommendedCritical)
{
    /// <summary>Gets whether the extension follows the recommendation.</summary>
    public bool FollowsRecommendation => Critical == RecommendedCritical;
}


/// <summary>
/// One of the seven container-extension payloads of clause 5.5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>, as a serialization-agnostic value.
/// </summary>
/// <remarks>
/// <para>
/// <strong>A closed hierarchy of exactly seven cases.</strong> The constructor is <see langword="private
/// protected"/>, so nothing outside this assembly can add an eighth and a switch over
/// <see cref="PreservationAsicExtensionKind"/> is exhaustive by construction — the shape
/// <see cref="PreservationMessage"/> already uses for the sixteen protocol messages.
/// </para>
/// <para>
/// <strong>The payload is the extension's content, not the extension.</strong> An <c>Extension</c> element
/// carries a <c>Critical</c> attribute and arbitrary content, and the shipped
/// <see cref="AsicManifestExtension"/> holds both — the whole element's octets and the name of its first child.
/// A payload here is what that child element means, which is why criticality is stated beside a payload
/// (<see cref="PreservationAsicExtensionWellKnown.StateCriticality"/>) rather than inside one.
/// </para>
/// <para>
/// <strong>Ownership.</strong> One case owns a carrier — <see cref="PreservationValidationReportExtension"/>
/// holds a preservation object — and disposing a payload disposes what it owns.
/// </para>
/// </remarks>
public abstract record PreservationAsicExtensionPayload: IDisposable
{
    /// <summary>Restricts the cases to those declared in this assembly, making this a closed hierarchy.</summary>
    private protected PreservationAsicExtensionPayload()
    {
    }


    /// <summary>Which of the seven payloads this is.</summary>
    public abstract PreservationAsicExtensionKind Kind { get; }


    /// <summary>Disposes whatever this payload owns.</summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }


    /// <summary>
    /// Disposes the carriers this case owns when <paramref name="disposing"/> is <see langword="true"/>.
    /// </summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    /// <remarks>
    /// The hierarchy is closed by the constructor above and no case holds an unmanaged resource, so this exists
    /// to give each case one place to release its carriers rather than to support a finalizer — the shape
    /// <see cref="EArkFixity"/> established in this namespace for a closed sum whose cases own pooled memory.
    /// </remarks>
    protected abstract void Dispose(bool disposing);
}


/// <summary>
/// The <c>ContainerID</c> extension (clause 5.5.2.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>): the preservation service's own identifier for a preservation object container,
/// and optionally which version of it this is.
/// </summary>
/// <remarks>
/// Clause A.3.1.4.5 names this extension as where the local identifier of a container is provided, which is what
/// makes an ASiC-ERS container addressable by the identifier a service's other operations use for it.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationContainerIdExtension: PreservationAsicExtensionPayload
{
    /// <inheritdoc/>
    public override PreservationAsicExtensionKind Kind => PreservationAsicExtensionKind.ContainerId;

    /// <summary>The mandatory <c>POID</c> element — the identifier of the preservation object container.</summary>
    public required string PreservationObjectId { get; init; }

    /// <summary>The optional <c>VersionID</c> element — which version of the container this is, or <see langword="null"/>.</summary>
    public string? VersionId { get; init; }


    /// <summary>Disposes nothing: this payload owns no carrier.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
    }


    /// <summary>A short debugger string showing the identifier and the version.</summary>
    private string DebuggerDisplay => $"PreservationContainerIdExtension({PreservationObjectId}, {VersionId ?? "no version"})";
}


/// <summary>
/// The <c>PreservationPeriod</c> extension (clause 5.5.2.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>): the preservation period of the preservation object container.
/// </summary>
/// <remarks>
/// The element's schema type is <c>date</c> — a calendar day and no time of day — so the value is a
/// <see cref="DateOnly"/> rather than an instant. Reading it as an instant would put a time on the wire the
/// producer never stated.
/// </remarks>
[DebuggerDisplay("PreservationPeriodExtension: {Period}")]
public sealed record PreservationPeriodExtension: PreservationAsicExtensionPayload
{
    /// <inheritdoc/>
    public override PreservationAsicExtensionKind Kind => PreservationAsicExtensionKind.PreservationPeriod;

    /// <summary>The single element's value — the preservation period of the container.</summary>
    public required DateOnly Period { get; init; }


    /// <summary>Disposes nothing: this payload owns no carrier.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
    }
}


/// <summary>
/// The <c>PreservationSubmitter</c> extension (clause 5.5.2.3 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>): the client in its role as preservation submitter.
/// </summary>
/// <remarks>
/// The element's schema type is <c>string</c> and the clause states no form for the value, so it is carried as
/// the producer wrote it.
/// </remarks>
[DebuggerDisplay("PreservationSubmitterExtension: {Submitter}")]
public sealed record PreservationSubmitterExtension: PreservationAsicExtensionPayload
{
    /// <inheritdoc/>
    public override PreservationAsicExtensionKind Kind => PreservationAsicExtensionKind.PreservationSubmitter;

    /// <summary>The single element's value — who submitted the container for preservation.</summary>
    public required string Submitter { get; init; }


    /// <summary>Disposes nothing: this payload owns no carrier.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
    }
}


/// <summary>
/// The <c>IsUpdatedVersionOf</c> extension (clause 5.5.2.4 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>): the preservation object container this one is an update of.
/// </summary>
/// <remarks>
/// Clause A.3.1.4.6 names this extension as the simple versioning strategy an ASiC-ERS container may support.
/// </remarks>
[DebuggerDisplay("IsUpdatedVersionOfExtension: {Reference}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "The element's schema type is anyURI and the value is carried and compared as the exact character sequence the producer wrote; System.Uri normalises case and escaping, which would make two references naming different containers compare equal. Nothing here is dereferenced.")]
public sealed record PreservationIsUpdatedVersionOfExtension: PreservationAsicExtensionPayload
{
    /// <inheritdoc/>
    public override PreservationAsicExtensionKind Kind => PreservationAsicExtensionKind.IsUpdatedVersionOf;

    /// <summary>The single element's value — the container this one updates.</summary>
    public required string Reference { get; init; }


    /// <summary>Disposes nothing: this payload owns no carrier.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
    }
}


/// <summary>
/// The <c>CanonicalizationMethod</c> extension (clause 5.5.2.5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>): how markup carried in a preservation object container is canonicalized before
/// preservation techniques are applied.
/// </summary>
/// <remarks>
/// <para>
/// The element is defined in a schema of the external base specification, so the only thing this document states
/// about its content is the element's name. The one value a consumer needs is the algorithm identifier, which is
/// what that element carries in every schema that declares it, so the payload holds exactly that and nothing is
/// invented around it.
/// </para>
/// <para>
/// This is the one extension clause 5.5 recommends be critical, and the reason is stated in the clause itself:
/// preservation evidences appear to become invalid if a required canonicalization is not applied.
/// </para>
/// </remarks>
[DebuggerDisplay("CanonicalizationMethodExtension: {Algorithm}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "An algorithm identifier is compared as an exact character sequence against a registry; System.Uri normalises case and escaping, which would make two identifiers naming different algorithms compare equal.")]
public sealed record PreservationCanonicalizationMethodExtension: PreservationAsicExtensionPayload
{
    /// <inheritdoc/>
    public override PreservationAsicExtensionKind Kind => PreservationAsicExtensionKind.CanonicalizationMethod;

    /// <summary>The canonicalization algorithm the element identifies.</summary>
    public required string Algorithm { get; init; }


    /// <summary>Disposes nothing: this payload owns no carrier.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
    }
}


/// <summary>
/// The <c>ValidationReport</c> extension (clause 5.5.2.6 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>): a validation report for the preservation evidence and the data objects the
/// manifest refers to.
/// </summary>
/// <remarks>
/// <para>
/// Clause 5.5.2.6.2 requires the element to satisfy clause 5.4.5, which is the preservation object component —
/// so the report rides in the same container as every other payload of this protocol and this library carries
/// its octets without interpreting them, exactly as <see cref="PreservationObject"/> documents.
/// </para>
/// <para><strong>Ownership.</strong> This payload owns <see cref="Report"/>; disposing it disposes the report.</para>
/// </remarks>
[DebuggerDisplay("ValidationReportExtension: {Report.Content.Length} octets")]
public sealed record PreservationValidationReportExtension: PreservationAsicExtensionPayload
{
    /// <inheritdoc/>
    public override PreservationAsicExtensionKind Kind => PreservationAsicExtensionKind.ValidationReport;

    /// <summary>The report, as the preservation object clause 5.4.5 makes it. Owned by this payload.</summary>
    public required PreservationObject Report { get; init; }


    /// <summary>Disposes the report.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            Report.Dispose();
        }
    }
}


/// <summary>
/// The <c>IsMetaDataOf</c> extension (clause 5.5.3.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>): the preservation object this data object is metadata of.
/// </summary>
/// <remarks>
/// This is the one extension that sits on a <c>DataObjectReference</c> rather than on the manifest, and clause
/// A.3.1.4.3 names it as how an ASiC-ERS container distinguishes content data objects from metadata objects —
/// the capability clause 6.2 item 2 asks a preservation object container to be able to offer.
/// </remarks>
[DebuggerDisplay("IsMetaDataOfExtension: {Reference}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "The element's schema type is anyURI and the value is carried and compared as the exact character sequence the producer wrote; System.Uri normalises case and escaping, which would make two references naming different data objects compare equal. Nothing here is dereferenced.")]
public sealed record PreservationIsMetaDataOfExtension: PreservationAsicExtensionPayload
{
    /// <inheritdoc/>
    public override PreservationAsicExtensionKind Kind => PreservationAsicExtensionKind.IsMetaDataOf;

    /// <summary>The single element's value — the data object this one describes.</summary>
    public required string Reference { get; init; }


    /// <summary>Disposes nothing: this payload owns no carrier.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
    }
}
