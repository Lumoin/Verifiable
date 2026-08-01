using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Whether a container, or one manifest of it, is the preservation object container profile Annex A.3.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> defines, and if not, which of the annex's six numbered requirements it is not.
/// </summary>
/// <remarks>
/// <see cref="Conformant"/> is deliberately not zero: a status that has not been computed must not read as a
/// container that satisfies the profile.
/// </remarks>
public enum PreservationContainerProfileStatus
{
    /// <summary>No evaluation has been performed. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>Everything the annex's six requirements state about the structure holds.</summary>
    Conformant = 1,

    /// <summary>
    /// Requirement 1: "The ASiC-ERS container shall be an ASiC-E container according to ETSI EN 319 162-1". The
    /// container's own layout puts it in the simple shape, which carries one data object and no manifest.
    /// </summary>
    NotExtendedContainer = 2,

    /// <summary>
    /// Requirement 2: the container "shall contain one or more ASiCEvidenceRecordManifest files whose names
    /// match "META-INF/ASiCEvidenceRecordManifest*.xml"". None of the container's manifests carries that role.
    /// </summary>
    NoEvidenceRecordManifest = 3,

    /// <summary>
    /// Requirement 2 again, stated of one manifest the caller supplied: the entry it was read from does not
    /// carry the evidence-record manifest role, so the profile's rules for a manifest do not apply to it and
    /// are not silently applied anyway.
    /// </summary>
    NotAnEvidenceRecordManifest = 4,

    /// <summary>
    /// Requirement 6, the profile's one tightening: "The optional <c>MimeType</c> element shall not be present."
    /// The container specification's own Annex A.4.2 makes the attribute optional, and this profile removes it.
    /// </summary>
    SignatureReferenceMediaTypeStated = 5,

    /// <summary>
    /// Requirement 6: the <c>SigReference</c>'s <c>URI</c> does not resolve to a container entry name at all, so
    /// it points at no evidence record file.
    /// </summary>
    SignatureReferenceNotResolvable = 6,

    /// <summary>
    /// Requirements 3 and 4: the <c>SigReference</c> resolves to a name that is not one of the two evidence
    /// record file names — <c>META-INF/*evidencerecord*.ers</c> for the ASN.1 form and
    /// <c>META-INF/*evidencerecord*.xml</c> for the XML form.
    /// </summary>
    SignatureReferenceNotAnEvidenceRecord = 7,

    /// <summary>
    /// Requirement 3: "there shall be exactly one evidence record file present in the META-INF folder". The
    /// name the <c>SigReference</c> resolves to is not an entry of this container.
    /// </summary>
    EvidenceRecordFileMissing = 8,

    /// <summary>
    /// Requirements 5 and 6: "The <c>DataObjectReference</c> element shall occur one or more times". The manifest
    /// references no data object file, so the evidence record it names protects nothing the manifest states.
    /// </summary>
    NoDataObjectReference = 9,

    /// <summary>
    /// The manifest carries an extension marked critical that the stated policy does not recognise. This is the
    /// container specification's own rule (<see cref="AsicManifestExtensionPolicy"/>), reported here because a
    /// consumer that may not proceed on the manifest may not conclude the profile holds either.
    /// </summary>
    UnrecognizedCriticalExtension = 10
}


/// <summary>
/// One <c>ASiCEvidenceRecordManifest</c> file of a container, as the profile evaluation takes it: the entry it
/// was read from and the manifest that entry's octets parsed into.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> <see cref="Manifest"/> is a non-owning reference to a manifest the caller parsed
/// and disposes; the profile evaluation reads it and keeps nothing.
/// </remarks>
[DebuggerDisplay("PreservationContainerManifest: {EntryName}")]
public sealed record PreservationContainerManifest
{
    /// <summary>The container entry the manifest was read from — the name its role is decided by.</summary>
    public required string EntryName { get; init; }

    /// <summary>The parsed manifest. The caller owns it.</summary>
    public required AsicManifest Manifest { get; init; }
}


/// <summary>
/// What one manifest of a container states against the six requirements of Annex A.3.1.3 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// The criticality departures are reported beside the status and never in it: clause 5.5's criticality
/// sub-clauses are recommendations, so a manifest departing from one is still the profile's container.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationContainerManifestReport
{
    /// <summary>The container entry the manifest was read from.</summary>
    public required string EntryName { get; init; }

    /// <summary>Whether this manifest satisfies the profile, and if not which requirement it does not.</summary>
    public required PreservationContainerProfileStatus Status { get; init; }

    /// <summary>The entry name the <c>SigReference</c> resolved to, or <see langword="null"/> when it did not resolve.</summary>
    public string? EvidenceRecordEntryName { get; init; }

    /// <summary>
    /// Which of the two evidence record forms of requirement 4 the referenced file's name states, or
    /// <see cref="AsicEvidenceRecordForm.NotEvaluated"/> when the reference did not resolve to one.
    /// </summary>
    public AsicEvidenceRecordForm EvidenceRecordForm { get; init; }

    /// <summary>How many data object files the manifest references (requirement 5).</summary>
    public int DataObjectReferenceCount { get; init; }

    /// <summary>What the stated extension policy made of the manifest's extensions.</summary>
    public AsicManifestExtensionEvaluation ExtensionEvaluation { get; init; }

    /// <summary>
    /// Every extension of clause 5.5 the manifest carries whose <c>Critical</c> attribute departs from the
    /// recommendation of the extension's own criticality clause.
    /// </summary>
    public IReadOnlyList<PreservationAsicExtensionCriticality> CriticalityDepartures { get; init; } = [];


    /// <summary>Gets whether this manifest satisfies the profile.</summary>
    public bool IsConformant => Status == PreservationContainerProfileStatus.Conformant;


    /// <summary>A short debugger string showing the manifest, its outcome and what it references.</summary>
    private string DebuggerDisplay =>
        $"PreservationContainerManifestReport({EntryName}, {Status}, {EvidenceRecordEntryName ?? "no evidence record"}, {DataObjectReferenceCount} data objects)";
}


/// <summary>
/// What a whole container states against Annex A.3.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>.
/// </summary>
/// <remarks>
/// The container's status is the first requirement that does not hold — the container-level ones first, then the
/// first manifest that fails one — and every manifest's own report is present either way, so a caller sees all
/// of what is wrong rather than only the first thing.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationContainerProfileReport
{
    /// <summary>Whether the container is the profile's, and if not which requirement it does not satisfy.</summary>
    public required PreservationContainerProfileStatus Status { get; init; }

    /// <summary>One report per manifest the caller supplied, in the order they were supplied.</summary>
    public IReadOnlyList<PreservationContainerManifestReport> Manifests { get; init; } = [];


    /// <summary>Gets whether the container satisfies the profile.</summary>
    public bool IsConformant => Status == PreservationContainerProfileStatus.Conformant;


    /// <summary>A short debugger string showing the outcome and how many manifests were judged.</summary>
    private string DebuggerDisplay => $"PreservationContainerProfileReport({Status}, {Manifests.Count} manifests)";
}


/// <summary>
/// Everything one profile evaluation is given: the container's facts, the manifests the caller parsed out of it,
/// and the policy its extensions are judged under.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> The caller owns the facts and every manifest and disposes them; the evaluation
/// reads them and keeps nothing.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationContainerProfileContext
{
    /// <summary>What the container states about itself, as <see cref="AsicContainerReading.Read"/> produced it.</summary>
    public required AsicContainerFacts Facts { get; init; }

    /// <summary>
    /// The <c>ASiCEvidenceRecordManifest</c> files of the container, parsed. Reading them is the caller's, because
    /// the manifest parse is a serialisation seam this library ships no implementation of.
    /// </summary>
    public required IReadOnlyList<PreservationContainerManifest> Manifests { get; init; }

    /// <summary>
    /// The policy the manifests' extensions are judged under; the seven extensions of clause 5.5 by default, per
    /// <see cref="PreservationAsicExtensionWellKnown.RecommendedPolicy"/>.
    /// </summary>
    public AsicManifestExtensionPolicy ExtensionPolicy { get; init; } = PreservationAsicExtensionWellKnown.RecommendedPolicy;

    /// <summary>
    /// The namespace a <c>CanonicalizationMethod</c> extension is recognised under when reporting criticality, or
    /// <see langword="null"/> to report only the six extensions this document's own schema declares.
    /// </summary>
    public string? CanonicalizationMethodNamespace { get; init; }


    /// <summary>A short debugger string showing what is being judged.</summary>
    private string DebuggerDisplay => $"PreservationContainerProfileContext({Facts.Shape}, {Manifests.Count} manifests)";
}


/// <summary>
/// The generator-side fault of being asked to create a container the profile of Annex A.3.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> does not admit.
/// </summary>
/// <remarks>
/// Creation faults in this namespace are exceptions and reading faults are statuses, the split
/// <see cref="AsicManifestNamingException"/> and <see cref="AsicContainerReadResult"/> already make: material a
/// caller supplied that no conformant container can be built from is a defect in the calling program, while a
/// container that arrived from elsewhere is data.
/// </remarks>
[DebuggerDisplay("PreservationContainerProfileException({Status}): {Message}")]
public sealed class PreservationContainerProfileException: Exception
{
    /// <summary>Gets which requirement of the profile the creation would not have satisfied.</summary>
    public PreservationContainerProfileStatus Status { get; }


    /// <summary>Initializes a new <see cref="PreservationContainerProfileException"/> with an unclassified fault.</summary>
    public PreservationContainerProfileException()
        : this(PreservationContainerProfileStatus.NotEvaluated, "The container does not satisfy the preservation object container profile.")
    {
    }


    /// <summary>Initializes a new <see cref="PreservationContainerProfileException"/> with an unclassified fault.</summary>
    /// <param name="message">The message describing the fault.</param>
    public PreservationContainerProfileException(string message): this(PreservationContainerProfileStatus.NotEvaluated, message)
    {
    }


    /// <summary>Initializes a new <see cref="PreservationContainerProfileException"/> with an unclassified fault.</summary>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public PreservationContainerProfileException(string message, Exception innerException)
        : this(PreservationContainerProfileStatus.NotEvaluated, message, innerException)
    {
    }


    /// <summary>Initializes a new <see cref="PreservationContainerProfileException"/>.</summary>
    /// <param name="status">Which requirement the creation would not have satisfied.</param>
    /// <param name="message">The message describing the fault.</param>
    public PreservationContainerProfileException(PreservationContainerProfileStatus status, string message): base(message)
    {
        Status = status;
    }


    /// <summary>Initializes a new <see cref="PreservationContainerProfileException"/>.</summary>
    /// <param name="status">Which requirement the creation would not have satisfied.</param>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public PreservationContainerProfileException(PreservationContainerProfileStatus status, string message, Exception innerException)
        : base(message, innerException)
    {
        Status = status;
    }
}


/// <summary>
/// The preservation object container profile "ASiC with Evidence Records", Annex A.3.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>: creating a container that satisfies it, and judging one that arrived.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This is a profile, not a container format.</strong> Clause A.3.1.2 says so outright — "The published
/// specification for ASiC-ERS is ETSI EN 319 162-1 with the profiling specified in clause A.3.1.3" — so
/// everything here composes with the shipped container surfaces
/// (<see cref="AsicContainerCreation.CreateEvidenceRecordAsync"/>,
/// <see cref="AsicContainerReading.Read"/>, <see cref="AsicManifest"/>) and adds no mechanism of its own. The
/// container this library already builds for an Evidence Record is the profile's container; what the annex adds
/// is one tightening and a set of extensions.
/// </para>
/// <para>
/// <strong>The one tightening, both ways.</strong> Requirement 6 states of the <c>SigReference</c> element that
/// "The optional <c>MimeType</c> element shall not be present", where Annex A.4.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> makes it optional. <see cref="CreateAsync"/> omits it and refuses a caller that
/// asks for it, rather than dropping the value silently — a container that states a media type is a container
/// the caller asked for and this profile cannot produce. <see cref="StateProfile"/> reports one that states it as
/// <see cref="PreservationContainerProfileStatus.SignatureReferenceMediaTypeStated"/>.
/// </para>
/// <para>
/// <strong>What this evaluation does not do.</strong> It judges structure, not proof: whether the evidence record
/// verifies, whether every digest matches and whether the data objects the manifest names are the ones the record
/// covers are <see cref="EvidenceRecords.VerifyAsync"/>'s and
/// <see cref="AsicContainerValidation.ValidateAsync"/>'s conclusions, exactly as
/// <see cref="AsicContainerFacts"/> already separates facts from validation.
/// </para>
/// </remarks>
public static class PreservationContainerProfile
{
    /// <summary>
    /// The format identifier of the profile, <c>http://uri.etsi.org/ades/ASiC/type/ASiC-ERS</c> (clause A.3.1.1),
    /// which a <c>PO</c> component states in its <c>FormatId</c> when it carries such a container.
    /// </summary>
    public static string FormatIdentifier { get; } = PreservationFormatWellKnown.EvidenceRecordContainerFormat;


    /// <summary>
    /// Creates a container satisfying the profile: the shipped Evidence Record container, with the annex's
    /// tightening enforced on what the caller asked for.
    /// </summary>
    /// <param name="context">Everything the container is built from, as the shipped surface takes it.</param>
    /// <param name="pool">The memory pool every allocation the call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="PreservationContainerProfileException">When the context asks for a container the profile does not admit.</exception>
    /// <exception cref="AsicContainerCreationException">When the supplied material is not a container the shipped surface builds.</exception>
    /// <remarks>
    /// Two of the annex's requirements are decidable before anything is built and are therefore refused here:
    /// requirement 1 makes the container the extended shape, and requirement 6 forbids the media type on the
    /// <c>SigReference</c>. Everything else the annex requires — the manifest's name and role, the evidence
    /// record file's name, one <c>DataObjectReference</c> per data object — is what the shipped surface already
    /// produces, which is why this method adds no assembly of its own.
    /// </remarks>
    public static ValueTask<AsicContainerCreationResult> CreateAsync(
        AsicContainerEvidenceRecordContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);

        return AsicContainerCreation.CreateEvidenceRecordAsync(StateCreationContext(context), pool, cancellationToken);
    }


    /// <summary>
    /// States the creation context the profile admits, refusing one it does not.
    /// </summary>
    /// <param name="context">The context the caller intends to build a container from.</param>
    /// <returns>The same context, once it is one the profile admits.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> is <see langword="null"/>.</exception>
    /// <exception cref="PreservationContainerProfileException">
    /// When the context asks for the simple container shape (requirement 1) or states a media type on the
    /// <c>SigReference</c> (requirement 6).
    /// </exception>
    /// <remarks>
    /// The context is returned rather than rewritten. Removing the media type for the caller would produce a
    /// container that differs from what was asked for in a way nothing on the wire records, and the value is one
    /// the caller stated deliberately — the shipped context's member exists precisely so a caller can state it.
    /// </remarks>
    public static AsicContainerEvidenceRecordContext StateCreationContext(AsicContainerEvidenceRecordContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if(context.Shape != AsicContainerShape.Extended)
        {
            throw new PreservationContainerProfileException(
                PreservationContainerProfileStatus.NotExtendedContainer,
                "Requirement 1 of clause A.3.1.3 makes the container an ASiC-E container, which is the extended shape.");
        }

        if(context.EvidenceRecordReferenceMediaType is not null)
        {
            throw new PreservationContainerProfileException(
                PreservationContainerProfileStatus.SignatureReferenceMediaTypeStated,
                "Requirement 6 of clause A.3.1.3 states of the SigReference element that the optional MimeType element shall not be present; state none.");
        }

        return context;
    }


    /// <summary>
    /// States whether a container that arrived is the profile's, requirement by requirement.
    /// </summary>
    /// <param name="context">The container's facts, its parsed manifests and the extension policy.</param>
    /// <returns>The report.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// The evaluation is pure over its inputs: it reads the facts and the manifests, computes nothing from a
    /// clock and touches no ambient state, so the same container answers the same thing every time.
    /// </remarks>
    public static PreservationContainerProfileReport StateProfile(PreservationContainerProfileContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var manifestReports = new List<PreservationContainerManifestReport>(context.Manifests.Count);
        for(int i = 0; i < context.Manifests.Count; ++i)
        {
            manifestReports.Add(StateManifestProfile(context, context.Manifests[i]));
        }

        PreservationContainerProfileStatus status = StateContainerStatus(context, manifestReports);

        return new PreservationContainerProfileReport { Status = status, Manifests = manifestReports };
    }


    /// <summary>
    /// States whether one manifest of a container satisfies the requirements the annex places on a manifest.
    /// </summary>
    /// <param name="context">The container's facts and the policy the extensions are judged under.</param>
    /// <param name="manifest">The manifest and the entry it was read from.</param>
    /// <returns>The manifest's report.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public static PreservationContainerManifestReport StateManifestProfile(
        PreservationContainerProfileContext context,
        PreservationContainerManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(manifest);

        List<PreservationAsicExtensionCriticality> departures = StateCriticalityDepartures(context, manifest.Manifest);
        AsicManifestExtensionEvaluation evaluation = context.ExtensionPolicy.Evaluate(manifest.Manifest);
        int dataObjectReferenceCount = manifest.Manifest.DataObjectReferences.Count;

        (PreservationContainerProfileStatus status, string? referenced, AsicEvidenceRecordForm form) =
            StateManifestStatus(context, manifest, evaluation, dataObjectReferenceCount);

        return new PreservationContainerManifestReport
        {
            EntryName = manifest.EntryName,
            Status = status,
            EvidenceRecordEntryName = referenced,
            EvidenceRecordForm = form,
            DataObjectReferenceCount = dataObjectReferenceCount,
            ExtensionEvaluation = evaluation,
            CriticalityDepartures = departures
        };
    }


    /// <summary>
    /// States which requirement a manifest first fails, together with what its <c>SigReference</c> named.
    /// </summary>
    /// <param name="context">The container's facts.</param>
    /// <param name="manifest">The manifest and the entry it was read from.</param>
    /// <param name="evaluation">What the stated policy made of the manifest's extensions.</param>
    /// <param name="dataObjectReferenceCount">How many data object files the manifest references.</param>
    /// <returns>The status, the entry name the <c>SigReference</c> resolved to, and the evidence record form.</returns>
    /// <remarks>
    /// The requirements are checked in the order the annex numbers them, so a manifest failing several is
    /// reported by the first one it fails rather than by whichever check happened to run first.
    /// </remarks>
    private static (PreservationContainerProfileStatus Status, string? EvidenceRecordEntryName, AsicEvidenceRecordForm Form) StateManifestStatus(
        PreservationContainerProfileContext context,
        PreservationContainerManifest manifest,
        AsicManifestExtensionEvaluation evaluation,
        int dataObjectReferenceCount)
    {
        if(!AsicManifestNaming.IsEvidenceRecordManifestEntryName(manifest.EntryName))
        {
            return (PreservationContainerProfileStatus.NotAnEvidenceRecordManifest, null, AsicEvidenceRecordForm.NotEvaluated);
        }

        if(manifest.Manifest.SignatureReference.MimeType is not null)
        {
            return (PreservationContainerProfileStatus.SignatureReferenceMediaTypeStated, null, AsicEvidenceRecordForm.NotEvaluated);
        }

        AsicContainerUriResolution resolution = AsicContainerUri.Resolve(manifest.Manifest.SignatureReference.Uri);
        if(!resolution.IsResolved)
        {
            return (PreservationContainerProfileStatus.SignatureReferenceNotResolvable, null, AsicEvidenceRecordForm.NotEvaluated);
        }

        string referenced = resolution.EntryName!;
        AsicEvidenceRecordForm form = FormOfEntryName(referenced);
        if(form == AsicEvidenceRecordForm.NotEvaluated)
        {
            return (PreservationContainerProfileStatus.SignatureReferenceNotAnEvidenceRecord, referenced, form);
        }

        if(context.Facts.FindEntry(referenced) is null)
        {
            return (PreservationContainerProfileStatus.EvidenceRecordFileMissing, referenced, form);
        }

        if(dataObjectReferenceCount == 0)
        {
            return (PreservationContainerProfileStatus.NoDataObjectReference, referenced, form);
        }

        return !evaluation.IsAccepted
            ? (PreservationContainerProfileStatus.UnrecognizedCriticalExtension, referenced, form)
            : (PreservationContainerProfileStatus.Conformant, referenced, form);
    }


    /// <summary>
    /// States the container-level outcome: the two requirements about the container itself, and then the first
    /// manifest that did not satisfy one of its own.
    /// </summary>
    /// <param name="context">The container's facts and manifests.</param>
    /// <param name="manifestReports">What each manifest answered.</param>
    /// <returns>The container's status.</returns>
    private static PreservationContainerProfileStatus StateContainerStatus(
        PreservationContainerProfileContext context,
        List<PreservationContainerManifestReport> manifestReports)
    {
        if(context.Facts.Shape != AsicContainerShape.Extended)
        {
            return PreservationContainerProfileStatus.NotExtendedContainer;
        }

        if(!CarriesEvidenceRecordManifest(context.Facts))
        {
            return PreservationContainerProfileStatus.NoEvidenceRecordManifest;
        }

        if(manifestReports.Count == 0)
        {
            return PreservationContainerProfileStatus.NoEvidenceRecordManifest;
        }

        for(int i = 0; i < manifestReports.Count; ++i)
        {
            if(!manifestReports[i].IsConformant)
            {
                return manifestReports[i].Status;
            }
        }

        return PreservationContainerProfileStatus.Conformant;
    }


    /// <summary>
    /// Determines whether a container carries at least one manifest whose name gives it the evidence-record role
    /// (requirement 2).
    /// </summary>
    /// <param name="facts">The container's facts.</param>
    /// <returns><see langword="true"/> when at least one manifest carries that role.</returns>
    private static bool CarriesEvidenceRecordManifest(AsicContainerFacts facts)
    {
        IReadOnlyList<AsicManifestFile> manifests = facts.Manifests;
        for(int i = 0; i < manifests.Count; ++i)
        {
            if(manifests[i].Role == AsicManifestRole.EvidenceRecord)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// States which of the two evidence record forms of requirement 4 a resolved entry name names.
    /// </summary>
    /// <param name="entryName">The entry name the <c>SigReference</c> resolved to.</param>
    /// <returns>The form, or <see cref="AsicEvidenceRecordForm.NotEvaluated"/> when the name is neither.</returns>
    /// <remarks>
    /// Requirement 4 states the two names outright — <c>*evidencerecord*.ers</c> for the ASN.1 form of IETF RFC
    /// 4998 and <c>*evidencerecord*.xml</c> for the XML form of IETF RFC 6283 — and requirement 6 says the type
    /// "is indicated by its file name and extension", so the name is the whole of the answer and no octet of the
    /// referenced file is read to reach it.
    /// </remarks>
    private static AsicEvidenceRecordForm FormOfEntryName(string entryName) => entryName switch
    {
        var name when AsicManifestNaming.IsBinaryEvidenceRecordEntryName(name) => AsicEvidenceRecordForm.Binary,
        var name when AsicManifestNaming.IsXmlEvidenceRecordEntryName(name) => AsicEvidenceRecordForm.Xml,
        _ => AsicEvidenceRecordForm.NotEvaluated
    };


    /// <summary>
    /// Collects every extension of clause 5.5 whose <c>Critical</c> attribute departs from the recommendation of
    /// its own criticality clause, over the manifest's extensions and those of every data object reference.
    /// </summary>
    /// <param name="context">The context, which states the namespace a canonicalization method is recognised under.</param>
    /// <param name="manifest">The manifest to read.</param>
    /// <returns>The departures, in the order the extensions appear.</returns>
    private static List<PreservationAsicExtensionCriticality> StateCriticalityDepartures(
        PreservationContainerProfileContext context,
        AsicManifest manifest)
    {
        var departures = new List<PreservationAsicExtensionCriticality>();
        Collect(departures, manifest.Extensions, context.CanonicalizationMethodNamespace);
        for(int i = 0; i < manifest.DataObjectReferences.Count; ++i)
        {
            Collect(departures, manifest.DataObjectReferences[i].Extensions, context.CanonicalizationMethodNamespace);
        }

        return departures;

        //One pass over one list of extensions, classifying each and keeping only what departs; an extension this
        //vocabulary does not name is not judged at all, because clause 5.5 states a recommendation for its own
        //seven and for nothing else.
        static void Collect(
            List<PreservationAsicExtensionCriticality> departures,
            IReadOnlyList<AsicManifestExtension> extensions,
            string? canonicalizationMethodNamespace)
        {
            for(int i = 0; i < extensions.Count; ++i)
            {
                AsicManifestExtension extension = extensions[i];
                PreservationAsicExtensionKind kind = canonicalizationMethodNamespace is string canonicalizationNamespace
                    ? PreservationAsicExtensionWellKnown.KindOf(extension.Name, canonicalizationNamespace)
                    : PreservationAsicExtensionWellKnown.KindOf(extension.Name);

                if(kind == PreservationAsicExtensionKind.None)
                {
                    continue;
                }

                PreservationAsicExtensionCriticality criticality =
                    PreservationAsicExtensionWellKnown.StateCriticality(kind, extension.Critical);

                if(!criticality.FollowsRecommendation)
                {
                    departures.Add(criticality);
                }
            }
        }
    }
}
