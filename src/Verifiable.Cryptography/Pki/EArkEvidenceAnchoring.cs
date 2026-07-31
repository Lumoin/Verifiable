using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What stating which of a package's octets an anchor is to cover concluded.
/// </summary>
/// <remarks>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised status never reads as a plan that was
/// stated.
/// </remarks>
public enum EArkProvenanceAnchorStatus
{
    /// <summary>No plan has been stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The plan was stated; every entry it names is in the package.</summary>
    Stated = 1,

    /// <summary>The manifest states no digital-provenance section, so there is no provenance chain to anchor.</summary>
    NoProvenanceReferenced = 2,

    /// <summary>A digital-provenance reference names an entry the package does not hold, so what it points at cannot be covered.</summary>
    ReferencedEntryMissing = 3,

    /// <summary>The package does not hold the manifest the plan is stated from, so the references themselves cannot be covered.</summary>
    ManifestMissing = 4,

    /// <summary>The plan would cover more entries than the caller admitted.</summary>
    LimitExceeded = 5
}


/// <summary>
/// Which of a package's octets an evidential anchor is to cover: the digital-provenance documents the manifest
/// references, the manifest that references them, and whatever else the caller adds.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Ownership.</strong> The entries are non-owning references into the snapshot the plan was stated from,
/// which its own owner disposes.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EArkProvenanceAnchorPlan
{
    /// <summary>Gets what stating the plan concluded.</summary>
    public required EArkProvenanceAnchorStatus Status { get; init; }

    /// <summary>Gets the entries the anchor is to cover, in the order they were resolved. Not owned by this record.</summary>
    public IReadOnlyList<EArkPackageEntry> CoveredEntries { get; init; } = [];

    /// <summary>Gets the reference the package could not resolve, or <see langword="null"/> when every one resolved.</summary>
    public string? UnresolvedReference { get; init; }


    /// <summary>Gets whether a plan was stated and names something to cover.</summary>
    public bool IsStated => Status == EArkProvenanceAnchorStatus.Stated && CoveredEntries.Count > 0;


    /// <summary>
    /// States the entry names the plan covers, which is what an artifact's facts carry so that a validation rule
    /// can ask whether the package's provenance is inside the evidence.
    /// </summary>
    /// <returns>The names, in the plan's own order.</returns>
    public List<string> CoveredEntryNames()
    {
        var names = new List<string>(CoveredEntries.Count);
        for(int i = 0; i < CoveredEntries.Count; ++i)
        {
            names.Add(CoveredEntries[i].Name);
        }

        return names;
    }


    /// <summary>A short debugger string showing the conclusion and how much the plan covers.</summary>
    private string DebuggerDisplay => $"EArkProvenanceAnchorPlan({Status}, {CoveredEntries.Count} entries)";
}


/// <summary>
/// What one <see cref="EArkEvidenceAnchoring.StatePlan"/> call needs: the package as a snapshot, its manifest as
/// a parsed document, and how far the plan reaches.
/// </summary>
public sealed record EArkProvenanceAnchorContext
{
    /// <summary>Gets the package snapshot the plan resolves references against. Not owned by this record.</summary>
    public required EArkPackageSnapshot Snapshot { get; init; }

    /// <summary>Gets the package's own manifest as a parsed document, whose digital-provenance sections name what to cover.</summary>
    public required MetsDocument PackageManifest { get; init; }

    /// <summary>Gets the entry name the manifest itself sits under.</summary>
    public string ManifestEntryName { get; init; } = EArkWellKnown.PackageManifestFileName;

    /// <summary>Gets whether the manifest itself is covered, which it is by default.</summary>
    /// <remarks>
    /// <strong>Covering it is the point.</strong> The manifest is where the digital-provenance references and
    /// their digests live; an anchor that covered the preservation-metadata documents but not the manifest would
    /// leave a producer free to change which documents are referenced, or what digests they are referenced with,
    /// without breaking anything. Turning this off is for a caller anchoring one document deliberately, and it
    /// is not what an archival package's provenance chain wants.
    /// </remarks>
    public bool CoverManifest { get; init; } = true;

    /// <summary>Gets further entry names of the caller's own to cover, resolved the same way the references are.</summary>
    public IReadOnlyList<string> AdditionalEntryNames { get; init; } = [];

    /// <summary>Gets the largest number of entries a plan is stated with.</summary>
    public int MaximumCoveredEntries { get; init; } = 1024;
}


/// <summary>
/// What verifying that a package's provenance is inside what its evidence proves concluded.
/// </summary>
/// <remarks>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised status never reads as an anchored package.
/// </remarks>
public enum EArkProvenanceAnchorVerificationStatus
{
    /// <summary>No verification has been performed. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>Every entry the plan names verified against the evidence, and the evidence covers those entries and no others.</summary>
    Anchored = 1,

    /// <summary>No plan could be stated from the package, so there was nothing to verify against.</summary>
    PlanNotStated = 2,

    /// <summary>The evidence does not prove the package's provenance content as the package now holds it.</summary>
    ProvenanceNotCovered = 3
}


/// <summary>
/// What verifying a package's provenance anchor concluded, together with what each covered entry's verification
/// said.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> An instance owns every <see cref="Verifications"/> entry; the caller disposes it.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EArkProvenanceAnchorVerification: IDisposable
{
    /// <summary>Gets what the verification concluded.</summary>
    public required EArkProvenanceAnchorVerificationStatus Status { get; init; }

    /// <summary>Gets the plan the package was verified against, or <see langword="null"/> when none could be stated.</summary>
    public EArkProvenanceAnchorPlan? Plan { get; init; }

    /// <summary>Gets one verification per covered entry, in the plan's order. Owned by this instance.</summary>
    public IReadOnlyList<EvidenceRecordVerification> Verifications { get; init; } = [];

    /// <summary>Gets the name of the first entry whose verification failed, or <see langword="null"/> when none did.</summary>
    public string? UncoveredEntryName { get; init; }


    /// <summary>Gets whether the package's provenance really is inside what the evidence proves.</summary>
    public bool IsAnchored => Status == EArkProvenanceAnchorVerificationStatus.Anchored;


    /// <summary>Disposes every verification this result owns.</summary>
    public void Dispose()
    {
        for(int i = 0; i < Verifications.Count; ++i)
        {
            Verifications[i].Dispose();
        }
    }


    /// <summary>A short debugger string showing the conclusion and how much was verified.</summary>
    private string DebuggerDisplay =>
        $"EArkProvenanceAnchorVerification({Status}, {Verifications.Count} entries{(UncoveredEntryName is null ? string.Empty : $", first uncovered {UncoveredEntryName}")})";
}


/// <summary>
/// What one <see cref="EArkEvidenceAnchoring.VerifyProvenanceAnchorAsync"/> call needs: the evidence, and the
/// package as it now stands.
/// </summary>
public sealed record EArkProvenanceAnchorVerificationContext
{
    /// <summary>Gets the Evidence Record claimed to anchor the package's provenance. The caller owns it.</summary>
    public required EvidenceRecord EvidenceRecord { get; init; }

    /// <summary>Gets the package as it now stands, from which the plan is stated afresh.</summary>
    public required EArkProvenanceAnchorContext Package { get; init; }
}


/// <summary>
/// Binds an Information Package's digital-provenance content into the evidence an Evidence Record or an archive
/// chain covers — the cryptographic anchor the archival specification's own provenance chain does not have.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The gap this closes, in the archival specification's own words.</strong> An Archival Information
/// Package records what was done to it as preservation-metadata events, chained to one another by
/// <c>relatedEventIdentification</c>, and links its generations by a parent pointer in the structural map. Both
/// are plain text: nothing stops an event from naming any predecessor it likes, and the specification names the
/// fragility itself — "there is the risk that the integrity of the logical AIP is in danger if the latest
/// version of the parent-AIP is lost". Nothing in
/// <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0</see> specifies how a provenance event's integrity is
/// to be proven; that is out of its scope by design.
/// </para>
/// <para>
/// <strong>What this class does about it, and what it does not.</strong> It states which of a package's octets
/// an anchor must cover — the digital-provenance documents the manifest references, and the manifest that
/// references them — and hands that set to the shipped Evidence Record and container surfaces unchanged. No new
/// cryptographic machinery is added: the tree, the time-stamps, both renewal procedures and the verification
/// walk are the ones that already ship, and every digest still goes through the registered seam. What is new is
/// only the answer to "which octets".
/// </para>
/// <para>
/// <strong>Why the whole set, and why verified entry by entry.</strong>
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.2">RFC 4998 clause 4.2</see> makes one data
/// object group's members "proved to have existed together", which is exactly the statement an archival
/// provenance chain needs: these events, these documents, this manifest, at this time. Clause 4.3's walk starts
/// from one data object's own hash, so a covered document that was changed afterwards fails <em>its own</em>
/// verification while every other member of the group still verifies — which is why
/// <see cref="VerifyProvenanceAnchorAsync"/> verifies every covered entry rather than one, and why it also
/// performs the group check, which is what catches a member added or removed rather than altered.
/// </para>
/// </remarks>
public static class EArkEvidenceAnchoring
{
    /// <summary>The marker a relative reference may lead with to name the folder it sits in, <c>./</c>.</summary>
    private static string CurrentFolderMarker { get; } = "./";


    /// <summary>
    /// States which of a package's entries an anchor is to cover.
    /// </summary>
    /// <param name="context">The package and how far the plan reaches.</param>
    /// <returns>The plan, whose status says whether one could be stated at all.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// A reference that names an entry the package does not hold stops the plan rather than being skipped: an
    /// anchor stated over a subset of what the manifest references would prove less than the caller asked for
    /// while looking as though it proved it.
    /// </remarks>
    public static EArkProvenanceAnchorPlan StatePlan(EArkProvenanceAnchorContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var covered = new List<EArkPackageEntry>();
        if(context.CoverManifest)
        {
            EArkPackageEntry? manifestEntry = context.Snapshot.FindEntry(context.ManifestEntryName);
            if(manifestEntry is null || manifestEntry.IsFolder)
            {
                return new EArkProvenanceAnchorPlan
                {
                    Status = EArkProvenanceAnchorStatus.ManifestMissing,
                    UnresolvedReference = context.ManifestEntryName
                };
            }

            covered.Add(manifestEntry);
        }

        MetsAdministrativeMetadata? administrative = context.PackageManifest.AdministrativeMetadata;
        IReadOnlyList<MetsAdministrativeMetadataSection> provenanceSections =
            administrative?.DigitalProvenanceSections ?? [];

        int referencedCount = 0;
        for(int i = 0; i < provenanceSections.Count; ++i)
        {
            MetsMetadataReference? reference = provenanceSections[i].Reference;
            if(reference is null)
            {
                continue;
            }

            ++referencedCount;
            EArkPackageEntry? entry = Resolve(context.Snapshot, reference.Href);
            if(entry is null || entry.IsFolder)
            {
                return new EArkProvenanceAnchorPlan
                {
                    Status = EArkProvenanceAnchorStatus.ReferencedEntryMissing,
                    UnresolvedReference = reference.Href
                };
            }

            AddOnce(covered, entry);
        }

        for(int i = 0; i < context.AdditionalEntryNames.Count; ++i)
        {
            EArkPackageEntry? entry = Resolve(context.Snapshot, context.AdditionalEntryNames[i]);
            if(entry is null || entry.IsFolder)
            {
                return new EArkProvenanceAnchorPlan
                {
                    Status = EArkProvenanceAnchorStatus.ReferencedEntryMissing,
                    UnresolvedReference = context.AdditionalEntryNames[i]
                };
            }

            AddOnce(covered, entry);
        }

        if(referencedCount == 0 && context.AdditionalEntryNames.Count == 0)
        {
            return new EArkProvenanceAnchorPlan { Status = EArkProvenanceAnchorStatus.NoProvenanceReferenced };
        }

        return covered.Count > context.MaximumCoveredEntries
            ? new EArkProvenanceAnchorPlan { Status = EArkProvenanceAnchorStatus.LimitExceeded }
            : new EArkProvenanceAnchorPlan { Status = EArkProvenanceAnchorStatus.Stated, CoveredEntries = covered };

        //A reference is resolved against the package's entry names exactly, after stripping the marker a
        //relative path may lead with. Ordinal, for the reason every other name comparison in this wave is:
        //a reader that folded case would resolve a reference to a file the producer did not name.
        static EArkPackageEntry? Resolve(EArkPackageSnapshot snapshot, string? href)
        {
            if(string.IsNullOrEmpty(href))
            {
                return null;
            }

            string name = href.StartsWith(CurrentFolderMarker, StringComparison.Ordinal)
                ? href[CurrentFolderMarker.Length..]
                : href;

            return snapshot.FindEntry(name);
        }

        //An entry named twice — by two provenance sections, or by a section and the caller — is covered once,
        //because a data object group states each of its members once.
        static void AddOnce(List<EArkPackageEntry> covered, EArkPackageEntry entry)
        {
            for(int i = 0; i < covered.Count; ++i)
            {
                if(string.Equals(covered[i].Name, entry.Name, StringComparison.Ordinal))
                {
                    return;
                }
            }

            covered.Add(entry);
        }
    }


    /// <summary>
    /// States the plan's entries as the one data object group an Evidence Record is created over.
    /// </summary>
    /// <param name="plan">The plan.</param>
    /// <returns>One group holding every covered entry's octets, ready for <see cref="EvidenceRecords.CreateInitialAsync"/>.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="plan"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the plan states nothing to cover.</exception>
    /// <remarks>
    /// One group rather than one per entry, because clause 4.2 makes a group's members "proved to have existed
    /// together" and that togetherness is the whole statement: a provenance chain proved document by document,
    /// each at a time of its own, is not a chain.
    /// </remarks>
    public static List<EvidenceRecordDataObjectGroup> ToDataObjectGroups(EArkProvenanceAnchorPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if(!plan.IsStated)
        {
            throw new ArgumentException("A data object group is stated from a plan that names something to cover.", nameof(plan));
        }

        return [new EvidenceRecordDataObjectGroup { DataObjects = ToDataObjects(plan) }];
    }


    /// <summary>
    /// States the plan's entries as the octets of the group, which is what verification checks a record binds
    /// exactly.
    /// </summary>
    /// <param name="plan">The plan.</param>
    /// <returns>The octets of every covered entry, in the plan's order. Views into the snapshot, which its owner disposes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="plan"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the plan states nothing to cover.</exception>
    public static List<ReadOnlyMemory<byte>> ToDataObjects(EArkProvenanceAnchorPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if(!plan.IsStated)
        {
            throw new ArgumentException("A data object list is stated from a plan that names something to cover.", nameof(plan));
        }

        var objects = new List<ReadOnlyMemory<byte>>(plan.CoveredEntries.Count);
        for(int i = 0; i < plan.CoveredEntries.Count; ++i)
        {
            objects.Add(plan.CoveredEntries[i].Content.AsReadOnlyMemory());
        }

        return objects;
    }


    /// <summary>
    /// States the plan's entries as the data objects of an Associated Signature Container, for a caller
    /// anchoring the same content through the container surfaces instead of a bare Evidence Record.
    /// </summary>
    /// <param name="plan">The plan.</param>
    /// <returns>One container data object per covered entry, in the plan's order.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="plan"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the plan states nothing to cover.</exception>
    /// <remarks>
    /// The two anchors differ in what a package ends up holding, not in what is proven: a container carries the
    /// covered octets inside itself and gains the archive chain of Annex A.7, while a bare Evidence Record leaves
    /// them where the package already has them. Both go through the shipped surfaces unchanged.
    /// </remarks>
    public static List<AsicDataObject> ToContainerDataObjects(EArkProvenanceAnchorPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if(!plan.IsStated)
        {
            throw new ArgumentException("A container data object list is stated from a plan that names something to cover.", nameof(plan));
        }

        var objects = new List<AsicDataObject>(plan.CoveredEntries.Count);
        for(int i = 0; i < plan.CoveredEntries.Count; ++i)
        {
            EArkPackageEntry entry = plan.CoveredEntries[i];
            objects.Add(new AsicDataObject { Name = entry.Name, Content = entry.Content.AsReadOnlyMemory() });
        }

        return objects;
    }


    /// <summary>
    /// Creates the Evidence Record that anchors a package's provenance, over the plan's entries as one group.
    /// </summary>
    /// <param name="plan">The plan naming what to cover.</param>
    /// <param name="creation">The creation context whose data object groups this call supplies; every other member is the caller's.</param>
    /// <param name="pool">The memory pool the record and its intermediates are rented from.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The creation result, holding one record for the one group. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the plan states nothing to cover.</exception>
    /// <remarks>
    /// This is composition and nothing else: the data object groups come from the plan and everything else — the
    /// algorithm, the authority, the transport, the tree arity, the attributes — is what the caller stated, and
    /// the record is built by the shipped surface.
    /// </remarks>
    public static ValueTask<EvidenceRecordCreation> CreateProvenanceEvidenceAsync(
        EArkProvenanceAnchorPlan plan,
        EvidenceRecordCreationContext creation,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(creation);
        ArgumentNullException.ThrowIfNull(pool);

        return EvidenceRecords.CreateInitialAsync(
            creation with { DataObjectGroups = ToDataObjectGroups(plan) },
            pool,
            cancellationToken);
    }


    /// <summary>
    /// Verifies that a package's digital-provenance content, as the package now holds it, is inside what an
    /// Evidence Record proves.
    /// </summary>
    /// <param name="context">The evidence and the package.</param>
    /// <param name="pool">The memory pool the verification rents from.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The conclusion. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// <para>
    /// The plan is stated afresh from the package rather than remembered from creation, which is the point: a
    /// verifier holds the package and the evidence and nothing else, and what it establishes is that the two
    /// agree now.
    /// </para>
    /// <para>
    /// Every covered entry is verified, and each with the group check, so both ways of breaking the anchor are
    /// caught: altering one covered document fails that document's own walk, and adding or removing a document
    /// fails the group check on all of them.
    /// </para>
    /// </remarks>
    public static async ValueTask<EArkProvenanceAnchorVerification> VerifyProvenanceAnchorAsync(
        EArkProvenanceAnchorVerificationContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);

        EArkProvenanceAnchorPlan plan = StatePlan(context.Package);
        if(!plan.IsStated)
        {
            return new EArkProvenanceAnchorVerification
            {
                Status = EArkProvenanceAnchorVerificationStatus.PlanNotStated,
                Plan = plan
            };
        }

        List<ReadOnlyMemory<byte>> dataObjects = ToDataObjects(plan);
        var verifications = new List<EvidenceRecordVerification>(dataObjects.Count);
        string? uncovered = null;
        try
        {
            for(int i = 0; i < dataObjects.Count; ++i)
            {
                EvidenceRecordVerification verification = await EvidenceRecords.VerifyAsync(
                    new EvidenceRecordVerificationContext
                    {
                        EvidenceRecord = context.EvidenceRecord,
                        DataObject = dataObjects[i],
                        DataObjectGroup = dataObjects
                    },
                    pool,
                    cancellationToken).ConfigureAwait(false);

                verifications.Add(verification);
                if(verification.Status != EvidenceRecordVerificationStatus.Verified && uncovered is null)
                {
                    uncovered = plan.CoveredEntries[i].Name;
                }
            }
        }
        catch
        {
            for(int i = 0; i < verifications.Count; ++i)
            {
                verifications[i].Dispose();
            }

            throw;
        }

        return new EArkProvenanceAnchorVerification
        {
            Status = uncovered is null
                ? EArkProvenanceAnchorVerificationStatus.Anchored
                : EArkProvenanceAnchorVerificationStatus.ProvenanceNotCovered,
            Plan = plan,
            Verifications = verifications,
            UncoveredEntryName = uncovered
        };
    }
}
