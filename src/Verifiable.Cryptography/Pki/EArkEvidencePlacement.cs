using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Which of the three extension points an evidential artifact carried its self-description in.
/// </summary>
/// <remarks>
/// <para>
/// The three are the ones the three shipped formats already have: the <c>attributes [1]</c> field of an
/// <c>ArchiveTimeStamp</c> (<see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.1">IETF RFC 4998 clause
/// 4.1</see>), the <c>unsignedAttrs</c> field of a <c>SignerInfo</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.3">IETF RFC 5652 clause 5.3</see>), and an
/// <c>Extension</c> of a manifest
/// (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.4.2). One convention, three carriers — never three designs.
/// </para>
/// <para>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised carrier never reads as one an artifact
/// really used.
/// </para>
/// </remarks>
public enum EArkEvidenceSelfDescriptionCarrier
{
    /// <summary>No carrier stated. The value of an unset field, by design, and the value when no self-description was found.</summary>
    NotEvaluated = 0,

    /// <summary>The <c>attributes</c> field of an Evidence Record's archive time-stamp.</summary>
    ArchiveTimeStampAttributes = 1,

    /// <summary>An unsigned attribute of a Signed Data Object's signer.</summary>
    UnsignedAttribute = 2,

    /// <summary>An <c>Extension</c> of a container manifest.</summary>
    ManifestExtension = 3
}


/// <summary>
/// What a caller states about one evidential artifact an Information Package carries: which kind it is, where it
/// sits, what it covers, and what it says about the preservation service, policy and profile it was produced
/// under.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Facts, not judgments, and stated rather than parsed inside a rule.</strong> A validation rule reads
/// what it was handed and never opens a file of its own, so the extraction happens here — where the shipped
/// readers are — and the result travels into
/// <c>Verifiable.Core.Assessment.EArchiving.EArkValidationContext</c> as a value. That is the same discipline
/// the package snapshot follows and it is what lets one rule list run over a package read from a folder, from an
/// archive, or rebuilt from wire octets.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Nothing here owns a carrier: the entry names are text and the self-description is
/// a plain record. The artifact's octets stay in the package snapshot, whose owner disposes them.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EArkEvidenceArtifactFacts
{
    /// <summary>Gets which kind of evidential artifact this is.</summary>
    public required EArkEvidenceKind Kind { get; init; }

    /// <summary>Gets the entry name the artifact sits under, root-relative and <c>/</c>-separated.</summary>
    public required string EntryName { get; init; }

    /// <summary>
    /// Gets the label of the representation the artifact covers (<c>CSIPSTR10</c>), or <see langword="null"/>
    /// when it is a package-level artifact.
    /// </summary>
    public string? RepresentationLabel { get; init; }

    /// <summary>
    /// Gets the entry names of everything the artifact's evidence covers, so that a rule can ask whether the
    /// package's own provenance content is inside it.
    /// </summary>
    /// <remarks>
    /// <strong>These are names, and a name is not a proof.</strong> The list says which entries the caller
    /// believes the artifact's evidence is about; it establishes nothing about the octets the package now holds
    /// under those names. A rule that has to decide whether the package's content really is inside the evidence
    /// reads <see cref="Evidence"/> and verifies against it, and uses this list only to decide whether such a
    /// verification is worth attempting.
    /// </remarks>
    public IReadOnlyList<string> CoveredEntryNames { get; init; } = [];

    /// <summary>
    /// Gets the Evidence Record whose proof the artifact's coverage rests on, or <see langword="null"/> when the
    /// caller states none.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>This is what turns coverage from a claim into a check.</strong>
    /// <see cref="EArkEvidenceAnchoring.VerifyProvenanceAnchorAsync"/> re-states the plan from the package as it
    /// now stands and walks
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.3">IETF RFC 4998 clause 4.3</see> for every
    /// covered entry with the group check, so a document rewritten after the evidence was produced fails its own
    /// walk however the entry names still read. A rule given the names alone can only repeat what the package
    /// says about itself.
    /// </para>
    /// <para>
    /// <strong>Ownership.</strong> Not owned by this record: the reader that produced the record disposes it,
    /// and it must outlive every validation that reads these facts.
    /// </para>
    /// </remarks>
    public EvidenceRecord? Evidence { get; init; }

    /// <summary>Gets what the artifact says about itself, or <see langword="null"/> when it says nothing.</summary>
    public EArkEvidenceSelfDescription? SelfDescription { get; init; }

    /// <summary>Gets which extension point the self-description was found in.</summary>
    public EArkEvidenceSelfDescriptionCarrier SelfDescriptionCarrier { get; init; }

    /// <summary>
    /// Gets whether the self-description sits inside octets some later cryptographic structure of the same
    /// artifact proves — which is what
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
    /// ETSI TS 119 511 V1.2.1</see> requirement <c>OVR-9.2-05</c> asks of an embedded policy reference.
    /// </summary>
    /// <remarks>
    /// The three carriers reach protection differently and this library states each where it can compute it: an
    /// Evidence Record's archive-time-stamp attributes are covered once a Hash-Tree Renewal has hashed the chain
    /// they sit in; a Signed Data Object's unsigned attribute is covered once an archive time-stamp indexing it
    /// has been added; a manifest extension is covered by whatever signature or time assertion the manifest is
    /// referenced by, which only the container's own reader can say.
    /// </remarks>
    public bool SelfDescriptionIsProtected { get; init; }


    /// <summary>Gets whether the artifact states a self-description at all.</summary>
    public bool HasSelfDescription => SelfDescription is not null;


    /// <summary>
    /// Determines whether the artifact's stated coverage names one entry of the package.
    /// </summary>
    /// <param name="entryName">The entry name, compared ordinally.</param>
    /// <returns><see langword="true"/> when the entry is one of <see cref="CoveredEntryNames"/>.</returns>
    /// <remarks>
    /// A name comparison and nothing more, so it answers whether a cryptographic check is worth running rather
    /// than what such a check would conclude. <see cref="Evidence"/> is what settles that.
    /// </remarks>
    public bool Covers(string? entryName)
    {
        for(int i = 0; i < CoveredEntryNames.Count; ++i)
        {
            if(string.Equals(CoveredEntryNames[i], entryName, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>A short debugger string showing the kind, where the artifact sits and how much it covers.</summary>
    private string DebuggerDisplay =>
        $"EArkEvidenceArtifactFacts({Kind}, {EntryName}, covers {CoveredEntryNames.Count}, self-description {(HasSelfDescription ? SelfDescriptionCarrier.ToString() : "none")})";
}


/// <summary>
/// What one <see cref="EArkEvidencePlacement.StatePlacementAsync"/> call needs: the artifact, its octets as the
/// package carries them, the instant to stamp the records with, and what the artifact attests.
/// </summary>
public sealed record EArkEvidencePlacementContext
{
    /// <summary>Gets what the caller states about the artifact.</summary>
    public required EArkEvidenceArtifactFacts Artifact { get; init; }

    /// <summary>Gets the artifact's own entry of the package snapshot, whose octets the fixity is computed over. Not owned by this record.</summary>
    public required EArkPackageEntry Entry { get; init; }

    /// <summary>
    /// Gets the instant the file entry and the event are stamped with. Stated by the caller rather than read
    /// from a clock, so a package this library writes is reproducible.
    /// </summary>
    public required DateTimeOffset Instant { get; init; }

    /// <summary>Gets the identifiers of the preservation-metadata objects the artifact attests.</summary>
    public required IReadOnlyList<PremisIdentifier> AttestedObjectIdentifiers { get; init; }

    /// <summary>Gets the identifiers of the agents that produced the artifact — the preservation service, and whatever else took part.</summary>
    public IReadOnlyList<PremisIdentifier> AgentIdentifiers { get; init; } = [];

    /// <summary>Gets the algorithm the artifact's fixity is stated under.</summary>
    /// <remarks>
    /// Only an algorithm <see cref="MetsWellKnown.ChecksumTypeFromDigestAlgorithm"/> names may be stated, which
    /// is this library's creation-side floor rather than the specification's — the checksum-type enumeration
    /// admits error-detection codes and broken hash functions as equally legal values.
    /// </remarks>
    public PkiDigestAlgorithm DigestAlgorithm { get; init; } = PkiDigestAlgorithm.Sha256;

    /// <summary>Gets the event type the placement records, one of the three <see cref="EArkEvidenceWellKnown"/> states.</summary>
    public string EventType { get; init; } = EArkEvidenceWellKnown.CreationEventType;

    /// <summary>Gets the <c>eventOutcome</c> the recorded event states, or <see langword="null"/> to state none.</summary>
    public string? EventOutcome { get; init; }

    /// <summary>
    /// Gets the identifier of the event this one followed — a renewal names the event that produced the evidence
    /// it renewed — or <see langword="null"/> when there is none.
    /// </summary>
    /// <remarks>
    /// This is requirement <c>AIP17</c>'s chaining mechanism and <c>prov:wasInformedBy</c> in the ontology
    /// alignment. Unlike the plain-text chain the archival specification builds out of it, the evidence a
    /// renewal produces binds the evidence it renewed cryptographically.
    /// </remarks>
    public PremisIdentifier? RelatedEventIdentifier { get; init; }
}


/// <summary>
/// Where one evidential artifact sits in a package, as the four elements a package states it with.
/// </summary>
/// <remarks>
/// <para>
/// The four are one placement, which is why they are produced together: the manifest's file entry says the
/// package holds the artifact and states its digest; the preservation-metadata object gives the artifact an
/// identity and its own fixity; the event says what was done and by whom; and the relationship says which
/// objects the artifact attests. A package stating only some of them states a placement a reader cannot follow.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns <see cref="FileEntry"/> and <see cref="Object"/> — and through
/// them the two fixity carriers — until the caller places them in a manifest and a preservation-metadata
/// document, which then own them. Disposing this result disposes both, so a caller that abandons a placement
/// releases what it rented.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EArkEvidencePlacementResult: IDisposable
{
    /// <summary>Gets the manifest file entry naming the artifact, with its recomputable digest. Owned by this instance until placed.</summary>
    public required MetsFile FileEntry { get; init; }

    /// <summary>
    /// Gets the preservation-metadata object identifying the artifact — the <c>prov:Entity</c> a consumer's
    /// provenance graph names it by — carrying the relationship towards everything it attests. Owned by this
    /// instance until placed.
    /// </summary>
    public required PremisObject Object { get; init; }

    /// <summary>Gets the event recording what was done — the <c>prov:Activity</c> of the consumer's graph.</summary>
    public required PremisEvent Event { get; init; }

    /// <summary>
    /// Gets the relationship an attested object states towards the artifact, which the caller places on each
    /// object of <see cref="EArkEvidencePlacementContext.AttestedObjectIdentifiers"/>. It is the inverse of the
    /// one <see cref="Object"/> already carries.
    /// </summary>
    public required PremisRelationship AttestedByRelationship { get; init; }

    /// <summary>Gets the file group the manifest entry belongs under (<c>CSIP90</c> or <c>CSIP114</c>).</summary>
    public required string FileGroupUse { get; init; }


    /// <summary>Disposes the two carriers-owning elements this result holds.</summary>
    public void Dispose()
    {
        FileEntry.Dispose();
        Object.Dispose();
    }


    /// <summary>A short debugger string showing what the placement names.</summary>
    private string DebuggerDisplay => $"EArkEvidencePlacementResult({FileEntry.Locator.Href}, group {FileGroupUse}, {Event.Type})";
}


/// <summary>
/// States where an evidential artifact sits inside an E-ARK Information Package and reads what one already
/// there says about itself.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Everything here is composition.</strong> No digest, signature or time-stamp is computed by anything
/// in this class that does not go through the seams the rest of the library uses: the fixity comes from the
/// registered <see cref="ComputeDigestDelegate"/>, and the artifacts themselves are created, augmented, renewed
/// and verified by the surfaces that already ship. What this class adds is the convention
/// <see cref="EArkEvidenceWellKnown"/> states, applied.
/// </para>
/// <para>
/// <strong>Why a package needs a convention at all.</strong> Neither the package specification nor the
/// preservation-metadata specification has any notion of a signature, a time assertion or an evidence record: a
/// systematic search of both finds no mention of them. An artifact therefore sits in a package as an opaque
/// payload file that nothing distinguishes from ordinary content — unless the package says so, in the two
/// extension points that do exist. Saying so is what this class does.
/// </para>
/// </remarks>
public static class EArkEvidencePlacement
{
    /// <summary>
    /// States the four elements a package places one evidential artifact with: the manifest file entry, the
    /// preservation-metadata object, the event, and the relationship an attested object carries back.
    /// </summary>
    /// <param name="context">What is being placed and where.</param>
    /// <param name="pool">The memory pool the two fixity carriers are rented from.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The placement. The caller owns and disposes it until it places its parts.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When the artifact states no kind, when its entry names a folder, or when the event type is not one this
    /// convention states.
    /// </exception>
    /// <remarks>
    /// <para>
    /// <strong>One digest, two owners.</strong> The manifest's file entry and the preservation-metadata object
    /// each state a fixity of their own — the two specifications compute them independently and neither
    /// cross-checks the other — so two carriers are produced. They are produced from one pass through the digest
    /// seam rather than two, because computing the same digest twice would say the same thing at twice the cost
    /// and would emit two provenance events for one act.
    /// </para>
    /// <para>
    /// <strong>The identifiers agree by construction.</strong> The manifest entry's <c>@ID</c> and the
    /// preservation-metadata object's identifier value are both
    /// <see cref="EArkEvidenceWellKnown.EvidenceObjectIdentifier"/>'s, so the two documents name the same
    /// artifact by the same token and a reader can join them without guessing.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of both fixity carriers transfers to the returned result, which the caller disposes; the catch disposes what was built on a partial failure.")]
    public static async ValueTask<EArkEvidencePlacementResult> StatePlacementAsync(
        EArkEvidencePlacementContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);

        EArkEvidenceArtifactFacts artifact = context.Artifact;
        if(artifact.Kind == EArkEvidenceKind.NotEvaluated)
        {
            throw new ArgumentException("A placement is stated for an artifact of a stated kind.", nameof(context));
        }

        if(context.Entry.IsFolder)
        {
            throw new ArgumentException("An evidential artifact is a file, not a folder.", nameof(context));
        }

        if(!EArkEvidenceWellKnown.IsEvidenceEventType(context.EventType))
        {
            throw new ArgumentException(
                $"'{context.EventType}' is not one of the event types this convention states.", nameof(context));
        }

        PkiDigestAlgorithm algorithm = context.DigestAlgorithm;
        PremisIdentifier objectIdentifier = EArkEvidenceWellKnown.EvidenceObjectIdentifier(artifact.EntryName);

        using DigestValue computed = await CryptographicKeyEvents.ComputeDigestAsync(
            context.Entry.Content.AsReadOnlyMemory(),
            algorithm.OutputByteLength,
            algorithm.DigestTag,
            pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        EArkRecomputableFixity manifestFixity = CopyFixity(computed, algorithm, pool);
        try
        {
            EArkRecomputableFixity objectFixity = CopyFixity(computed, algorithm, pool);
            try
            {
                var fileEntry = new MetsFile
                {
                    Id = objectIdentifier.Value,
                    MediaType = EArkEvidenceWellKnown.MediaTypeOf(artifact.Kind)!,
                    Size = context.Entry.Content.Length,
                    Created = context.Instant,
                    Fixity = manifestFixity,
                    Locator = new MetsFileLocator(
                        MetsWellKnown.UrlLocatorType,
                        MetsWellKnown.SimpleLinkType,
                        artifact.EntryName)
                };

                var characteristics = new PremisObjectCharacteristics { Fixities = [objectFixity] };
                var evidenceObject = new PremisObject
                {
                    Category = PremisWellKnown.FileObjectCategory,
                    Identifiers = [objectIdentifier],
                    Characteristics = [characteristics],
                    Relationships =
                    [
                        new PremisRelationship
                        {
                            Type = EArkEvidenceWellKnown.EvidenceRelationshipType,
                            SubType = EArkEvidenceWellKnown.AttestsSubType,
                            RelatedObjectIdentifiers = context.AttestedObjectIdentifiers
                        }
                    ]
                };

                var recordedEvent = new PremisEvent
                {
                    Identifiers = [EArkEvidenceWellKnown.EvidenceEventIdentifier(artifact.EntryName, context.EventType)],
                    Type = context.EventType,
                    EventDateTime = context.Instant.ToString("O", CultureInfo.InvariantCulture),
                    Outcome = context.EventOutcome,
                    LinkingAgentIdentifiers = context.AgentIdentifiers,
                    LinkingObjectIdentifiers = LinkedObjects(objectIdentifier, context.AttestedObjectIdentifiers)
                };

                var attestedBy = new PremisRelationship
                {
                    Type = EArkEvidenceWellKnown.EvidenceRelationshipType,
                    SubType = EArkEvidenceWellKnown.AttestedBySubType,
                    RelatedObjectIdentifiers = [objectIdentifier],
                    RelatedEventIdentifiers = RelatedEvents(context.RelatedEventIdentifier)
                };

                return new EArkEvidencePlacementResult
                {
                    FileEntry = fileEntry,
                    Object = evidenceObject,
                    Event = recordedEvent,
                    AttestedByRelationship = attestedBy,
                    FileGroupUse = EArkEvidenceWellKnown.EvidenceFileGroupUse(artifact.RepresentationLabel)
                };
            }
            catch
            {
                objectFixity.Dispose();

                throw;
            }
        }
        catch
        {
            manifestFixity.Dispose();

            throw;
        }

        //The event's linking objects are the artifact the activity produced followed by everything it used,
        //which is the order a consumer's graph reads as prov:generated then prov:used.
        static List<PremisIdentifier> LinkedObjects(PremisIdentifier produced, IReadOnlyList<PremisIdentifier> used)
        {
            var linked = new List<PremisIdentifier>(used.Count + 1) { produced };
            for(int i = 0; i < used.Count; ++i)
            {
                linked.Add(used[i]);
            }

            return linked;
        }

        //The one related event a renewal names, or none. Written as a function rather than a conditional so that
        //the empty case is an empty list of the right type rather than a target-typing accident.
        static List<PremisIdentifier> RelatedEvents(PremisIdentifier? relatedEventIdentifier)
        {
            var related = new List<PremisIdentifier>(1);
            if(relatedEventIdentifier is PremisIdentifier stated)
            {
                related.Add(stated);
            }

            return related;
        }
    }


    /// <summary>
    /// Reads what an Evidence Record says about itself and states the facts a package records it by.
    /// </summary>
    /// <param name="evidenceRecord">The Evidence Record, as the package carries it.</param>
    /// <param name="entryName">The entry name it sits under.</param>
    /// <param name="coveredEntryNames">The entry names of everything it proves.</param>
    /// <param name="representationLabel">The representation it covers, or <see langword="null"/> for a package-level artifact.</param>
    /// <returns>The facts, with the self-description read from the archive-time-stamp attributes if one is there.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="evidenceRecord"/> or <paramref name="coveredEntryNames"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="entryName"/> is <see langword="null"/> or empty.</exception>
    /// <remarks>
    /// <para>
    /// <strong>Whether the self-description is protected is computed, not assumed.</strong> Clause 5.2's
    /// Hash-Tree Renewal hashes the whole encoded <c>ArchiveTimeStampSequence</c>, so an attribute in a chain
    /// that a later chain follows is inside what that later chain proves; Timestamp Renewal within one chain
    /// hashes only the previous <c>timeStamp</c> field and therefore proves nothing about its siblings'
    /// attributes. The answer is exactly "a later chain exists".
    /// </para>
    /// <para>
    /// <strong>The record travels with the facts.</strong> It is carried into
    /// <see cref="EArkEvidenceArtifactFacts.Evidence"/> so that a rule deciding whether the package's provenance
    /// really is inside the evidence verifies against the record rather than against
    /// <paramref name="coveredEntryNames"/>, which the caller states and the package itself produced. Not owned
    /// by the returned facts; the caller keeps it alive for as long as they are read.
    /// </para>
    /// </remarks>
    public static EArkEvidenceArtifactFacts StateEvidenceRecordFacts(
        EvidenceRecord evidenceRecord,
        string entryName,
        IReadOnlyList<string> coveredEntryNames,
        string? representationLabel = null)
    {
        ArgumentNullException.ThrowIfNull(evidenceRecord);
        ArgumentNullException.ThrowIfNull(coveredEntryNames);
        ArgumentException.ThrowIfNullOrEmpty(entryName);

        IReadOnlyList<EvidenceRecordArchiveTimeStampChain> chains = evidenceRecord.ArchiveTimeStampSequence.Chains;
        EArkEvidenceSelfDescription? found = null;
        bool protectedByRenewal = false;
        for(int chainIndex = chains.Count - 1; chainIndex >= 0 && found is null; --chainIndex)
        {
            IReadOnlyList<EvidenceRecordArchiveTimeStamp> archiveTimeStamps = chains[chainIndex].ArchiveTimeStamps;
            for(int stampIndex = archiveTimeStamps.Count - 1; stampIndex >= 0; --stampIndex)
            {
                if(EArkEvidenceSelfDescription.TryReadFromAttributes(archiveTimeStamps[stampIndex].Attributes, out EArkEvidenceSelfDescription? read))
                {
                    found = read;
                    protectedByRenewal = chainIndex < chains.Count - 1;
                    break;
                }
            }
        }

        return new EArkEvidenceArtifactFacts
        {
            Kind = EArkEvidenceKind.EvidenceRecord,
            EntryName = entryName,
            RepresentationLabel = representationLabel,
            CoveredEntryNames = coveredEntryNames,
            Evidence = evidenceRecord,
            SelfDescription = found,
            SelfDescriptionCarrier = found is null
                ? EArkEvidenceSelfDescriptionCarrier.NotEvaluated
                : EArkEvidenceSelfDescriptionCarrier.ArchiveTimeStampAttributes,
            SelfDescriptionIsProtected = protectedByRenewal
        };
    }


    /// <summary>
    /// Reads what a Signed Data Object says about itself and states the facts a package records it by.
    /// </summary>
    /// <param name="signedData">The Signed Data Object, as the package carries it.</param>
    /// <param name="signerIndex">The zero-based index of the signer whose unsigned attributes are read.</param>
    /// <param name="entryName">The entry name it sits under.</param>
    /// <param name="coveredEntryNames">The entry names of everything it attests.</param>
    /// <param name="representationLabel">The representation it covers, or <see langword="null"/> for a package-level artifact.</param>
    /// <returns>The facts, with the self-description read from the signer's unsigned attributes if one is there.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/> or <paramref name="coveredEntryNames"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative.</exception>
    /// <exception cref="ArgumentException">When <paramref name="entryName"/> is <see langword="null"/> or empty.</exception>
    /// <remarks>
    /// <strong>Whether the self-description is protected is computed, not assumed.</strong> An unsigned attribute
    /// is outside the signature by definition; what covers it is an archive time-stamp added afterwards, whose
    /// hash index of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1 clause 5.5.2</see> holds one entry per unsigned attribute value present when it
    /// ran. The answer is therefore "an archive time-stamp attribute follows this one in encoding order", which
    /// is what clause 5.5.3's append-only augmentation makes decidable from the order alone.
    /// </remarks>
    public static EArkEvidenceArtifactFacts StateSignedDataObjectFacts(
        CmsSignedData signedData,
        int signerIndex,
        string entryName,
        IReadOnlyList<string> coveredEntryNames,
        string? representationLabel = null)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(coveredEntryNames);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);
        ArgumentException.ThrowIfNullOrEmpty(entryName);

        EArkEvidenceSelfDescription? found = null;
        bool protectedByArchiveTimestamp = false;
        IReadOnlyList<CmsUnsignedAttributeValueLocation> locations =
            CmsSignedDataAugmentation.LocateUnsignedAttributeValues(signedData, signerIndex);

        for(int i = 0; i < locations.Count && found is null; ++i)
        {
            if(!string.Equals(locations[i].AttributeType, EArkEvidenceWellKnown.SelfDescriptionAttributeType, StringComparison.Ordinal))
            {
                continue;
            }

            ReadOnlyMemory<byte> value = CmsSignedDataAugmentation.ReadUnsignedAttributeValue(
                signedData, signerIndex, locations[i].AttributeIndex, locations[i].ValueIndex);

            if(EArkEvidenceSelfDescription.TryDecodeValue(value, out EArkEvidenceSelfDescription? read))
            {
                found = read;
                protectedByArchiveTimestamp = FollowedByArchiveTimestamp(locations, locations[i].AttributeIndex);
            }
        }

        return new EArkEvidenceArtifactFacts
        {
            Kind = EArkEvidenceKind.SignedDataObject,
            EntryName = entryName,
            RepresentationLabel = representationLabel,
            CoveredEntryNames = coveredEntryNames,
            SelfDescription = found,
            SelfDescriptionCarrier = found is null
                ? EArkEvidenceSelfDescriptionCarrier.NotEvaluated
                : EArkEvidenceSelfDescriptionCarrier.UnsignedAttribute,
            SelfDescriptionIsProtected = protectedByArchiveTimestamp
        };

        //Whether an archive time-stamp attribute sits after the one at the given index, which is what makes an
        //earlier unsigned attribute value part of what that time-stamp's hash index covers.
        static bool FollowedByArchiveTimestamp(IReadOnlyList<CmsUnsignedAttributeValueLocation> locations, int attributeIndex)
        {
            for(int i = 0; i < locations.Count; ++i)
            {
                if(locations[i].AttributeIndex > attributeIndex
                    && string.Equals(locations[i].AttributeType, CAdESSignatureFacts.ArchiveTimestampV3AttributeOid, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>
    /// States the facts a package records a container by, from what its manifest's extensions carried.
    /// </summary>
    /// <param name="selfDescriptionText">The text content of the manifest extension carrying the self-description, or <see langword="null"/> when the manifest carried none.</param>
    /// <param name="entryName">The entry name the container sits under.</param>
    /// <param name="coveredEntryNames">The entry names of everything the container's evidence attests.</param>
    /// <param name="pool">The memory pool the decode rents from for the duration of the call.</param>
    /// <param name="isManifestProtected">Whether the manifest carrying the extension is covered by the signature or time assertion that references it.</param>
    /// <param name="representationLabel">The representation the container covers, or <see langword="null"/> for a package-level artifact.</param>
    /// <param name="evidence">The Evidence Record the container carries, or <see langword="null"/> when the container's reader found none. Not owned by the returned facts.</param>
    /// <returns>The facts, with the self-description read from the extension text if one decodes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="coveredEntryNames"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="entryName"/> is <see langword="null"/> or empty.</exception>
    /// <remarks>
    /// <para>
    /// Unlike the other two, this one is given the extension's text rather than finding it: an <c>Extension</c>'s
    /// content is XML, and reading XML is the manifest parse seam's business — this project references no XML
    /// package. The caller states whether the manifest is protected for the same reason: only the container's
    /// own reader knows which signature or time assertion references the manifest the extension sits in.
    /// </para>
    /// <para>
    /// <paramref name="evidence"/> is stated for the same reason and matters for the same one: a container holds
    /// its own copies of what it proves, so a name list established over those copies says nothing about the
    /// package's copies of the same documents. Handing the record over lets a rule verify the package's octets
    /// against it instead of comparing the two sets of names.
    /// </para>
    /// </remarks>
    public static EArkEvidenceArtifactFacts StateContainerFacts(
        string? selfDescriptionText,
        string entryName,
        IReadOnlyList<string> coveredEntryNames,
        MemoryPool<byte> pool,
        bool isManifestProtected = false,
        string? representationLabel = null,
        EvidenceRecord? evidence = null)
    {
        ArgumentNullException.ThrowIfNull(coveredEntryNames);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentException.ThrowIfNullOrEmpty(entryName);

        bool read = EArkEvidenceSelfDescription.TryReadExtensionText(selfDescriptionText, pool, out EArkEvidenceSelfDescription? found);

        return new EArkEvidenceArtifactFacts
        {
            Kind = EArkEvidenceKind.Container,
            EntryName = entryName,
            RepresentationLabel = representationLabel,
            CoveredEntryNames = coveredEntryNames,
            Evidence = evidence,
            SelfDescription = read ? found : null,
            SelfDescriptionCarrier = read
                ? EArkEvidenceSelfDescriptionCarrier.ManifestExtension
                : EArkEvidenceSelfDescriptionCarrier.NotEvaluated,
            SelfDescriptionIsProtected = read && isManifestProtected
        };
    }


    /// <summary>
    /// Copies a computed digest into a fixity carrier of its own, so that the manifest and the
    /// preservation-metadata document each own the value they state.
    /// </summary>
    /// <param name="computed">The digest the seam produced, which the caller still owns.</param>
    /// <param name="algorithm">The algorithm it was computed under.</param>
    /// <param name="pool">The memory pool the copy is rented from.</param>
    /// <returns>The fixity. The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented buffer transfers to the DigestValue and from it to the returned fixity, which the caller disposes; the catch disposes it on a partial failure.")]
    private static EArkRecomputableFixity CopyFixity(DigestValue computed, PkiDigestAlgorithm algorithm, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(algorithm.OutputByteLength);
        try
        {
            computed.AsReadOnlyMemory().Span[..algorithm.OutputByteLength].CopyTo(owner.Memory.Span);

            return new EArkRecomputableFixity(algorithm, new DigestValue(owner, algorithm.DigestTag));
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }
}
