using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for this library's evidence-placement convention: where an evidential artifact sits inside
/// an E-ARK Information Package, how the package manifest names it, how the preservation-metadata document
/// records what it attests, and what a package carrying one of each artifact kind is judged to be.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Everything asserted here is a convention and is asserted as one.</strong> A systematic search of
/// <see href="https://earkcsip.dilcis.eu/">E-ARK CSIP v2.2.0</see> and
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> for signatures, time
/// assertions and evidence records returns nothing, so the two positions, the event types, the relationship
/// subtypes and the identifier forms are this library's, stated over the two extension points those
/// specifications do have — the preservation-metadata <c>event</c> and <c>relationship</c> elements, whose type
/// vocabularies are externally hosted and open.
/// </para>
/// <para>
/// The artifacts the package tests carry are minted by the shipped surfaces against a Time-Stamping Authority
/// that signs real tokens — a real Evidence Record, a real Signed Data Object, a real Associated Signature
/// Container — because a placement rule that only ever saw invented octets would not have been told anything.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EArkEvidencePlacementTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The identifier the test issuer states as its own.</summary>
    private const string IssuerId = "eark-evidence-validator";

    /// <summary>The correlation identifier the test issuer carries through a run.</summary>
    private const string CorrelationId = "eark-evidence-validation";

    /// <summary>The time provider the issuer stamps its results with.</summary>
    private static FakeTimeProvider IssuerTime { get; } = new(EArkValidationSource.Instant);

    /// <summary>The label of the representation the representation-level placement tests use.</summary>
    private static string RepresentationLabel { get; } = "rep1";

    /// <summary>The content the minted artifacts of this class attest.</summary>
    private static string AttestedContent { get; } = "the archived provenance document";


    /// <summary>
    /// The convention puts package-level evidence in <c>metadata/other</c> and evidence over a representation's
    /// data beside that data, and the tree classifier really puts an entry at each of those names where the
    /// convention says it does — which is the fact the placement rule reads.
    /// </summary>
    /// <returns>A task that completes when the package has been classified.</returns>
    [TestMethod]
    public async Task TheTwoPositionsTheConventionStatesAreTheOnesTheClassifierGives()
    {
        string packageLevel = EArkEvidenceWellKnown.PackageEvidenceEntryName("provenance.ers");
        string representationLevel = EArkEvidenceWellKnown.RepresentationEvidenceEntryName(RepresentationLabel, "records.ers");

        Assert.AreEqual("metadata/other/provenance.ers", packageLevel);
        Assert.AreEqual("representations/rep1/data/records.ers", representationLevel);
        Assert.AreEqual(EArkWellKnown.OtherMetadataFolderName, EArkEvidenceWellKnown.PackageEvidenceFolderName,
            "Clause 5.2 of the preservation-metadata specification reserves metadata/preservation for documents of that vocabulary.");

        List<EArkPackageEntrySource> entries =
        [
            .. EArkValidationSource.ConformantPackageEntries(),
            EArkPackageSource.TextFile(packageLevel, "package-level evidence"),
            EArkPackageSource.TextFile(representationLevel, "representation-level evidence"),
        ];

        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(entries, EArkPackageLimits.Conformant, BaseMemoryPool.Shared);
        Assert.AreEqual(EArkPackageSnapshotStatus.Read, read.Status);

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        Assert.AreEqual(EArkPackageEntryPlacement.OtherMetadata, PlacementOf(facts, packageLevel));
        Assert.AreEqual(EArkPackageEntryPlacement.Data, PlacementOf(facts, representationLevel));

        Assert.IsTrue(EArkEvidenceWellKnown.IsEvidencePlacement(EArkPackageEntryPlacement.OtherMetadata));
        Assert.IsTrue(EArkEvidenceWellKnown.IsEvidencePlacement(EArkPackageEntryPlacement.Data));
        Assert.IsFalse(EArkEvidenceWellKnown.IsEvidencePlacement(EArkPackageEntryPlacement.PreservationMetadata));
        Assert.IsFalse(EArkEvidenceWellKnown.IsEvidencePlacement(EArkPackageEntryPlacement.DescriptiveMetadata));
        Assert.IsFalse(EArkEvidenceWellKnown.IsEvidencePlacement(EArkPackageEntryPlacement.Schemas));
        Assert.IsFalse(EArkEvidenceWellKnown.IsEvidencePlacement(EArkPackageEntryPlacement.Documentation));
        Assert.IsFalse(EArkEvidenceWellKnown.IsEvidencePlacement(default), "A position nothing evaluated is not one the convention claims.");

        await Task.CompletedTask.ConfigureAwait(false);
    }


    /// <summary>
    /// No new file-group value is minted: a package-level artifact belongs to the metadata group the profile
    /// already states and a representation's artifact to that representation's own group.
    /// </summary>
    [TestMethod]
    public void TheFileGroupUseIsOneTheProfileAlreadyStates()
    {
        Assert.AreEqual(MetsWellKnown.MetadataLabel, EArkEvidenceWellKnown.EvidenceFileGroupUse(null));
        Assert.AreEqual(MetsWellKnown.RepresentationsPrefix + RepresentationLabel, EArkEvidenceWellKnown.EvidenceFileGroupUse(RepresentationLabel));
    }


    /// <summary>
    /// Every identifier the convention mints out of an entry name is a legal <c>NCName</c>, whatever the file
    /// name it was derived from starts with — which is what clause 5.1's binding of every package identifier to
    /// that production requires.
    /// </summary>
    /// <param name="entryName">The entry name the identifier is minted from.</param>
    [TestMethod]
    [DataRow("metadata/other/provenance.ers", DisplayName = "an ordinary package-level name")]
    [DataRow("metadata/other/2026-record.p7s", DisplayName = "a name starting with a digit")]
    [DataRow("representations/rep1/data/records.asice", DisplayName = "a representation-level name")]
    [DataRow("metadata/other/a name with spaces.ers", DisplayName = "a name carrying characters the production refuses")]
    [DataRow("metadata/other/.hidden", DisplayName = "a name starting with a character the production refuses")]
    public void AnIdentifierMintedFromAnEntryNameIsALegalNCName(string entryName)
    {
        PremisIdentifier objectIdentifier = EArkEvidenceWellKnown.EvidenceObjectIdentifier(entryName);
        PremisIdentifier eventIdentifier = EArkEvidenceWellKnown.EvidenceEventIdentifier(entryName, EArkEvidenceWellKnown.CreationEventType);

        Assert.AreEqual(PremisWellKnown.LocalIdentifierType, objectIdentifier.Type);
        Assert.AreEqual(PremisWellKnown.LocalIdentifierType, eventIdentifier.Type);
        Assert.IsTrue(MetsWellKnown.IsNCName(objectIdentifier.Value), $"'{objectIdentifier.Value}' is not a legal NCName.");
        Assert.IsTrue(MetsWellKnown.IsNCName(eventIdentifier.Value), $"'{eventIdentifier.Value}' is not a legal NCName.");
        Assert.StartsWith(EArkEvidenceWellKnown.EvidenceIdentifierPrefix, objectIdentifier.Value);
        Assert.StartsWith(EArkEvidenceWellKnown.EvidenceEventIdentifierPrefix, eventIdentifier.Value);
        Assert.AreNotEqual(objectIdentifier.Value, eventIdentifier.Value);
    }


    /// <summary>
    /// The fold that makes an identifier legal is not injective, and the convention documents it rather than
    /// hiding it: two entry names differing only in characters the production refuses mint one identifier, which
    /// is a uniqueness obligation on the producer's file naming and not a failure this library can detect.
    /// </summary>
    [TestMethod]
    public void TheIdentifierFoldIsNotInjectiveAndTheConventionSaysSo()
    {
        Assert.AreEqual(
            EArkEvidenceWellKnown.ToIdentifierToken("metadata/other/a b.ers"),
            EArkEvidenceWellKnown.ToIdentifierToken("metadata/other/a:b.ers"),
            "Two characters the NCName production refuses fold to the same one, so the two names fold together.");

        Assert.AreNotEqual(
            EArkEvidenceWellKnown.ToIdentifierToken("metadata/other/a.ers"),
            EArkEvidenceWellKnown.ToIdentifierToken("metadata/other/A.ers"),
            "Comparison is ordinal everywhere in this wave, and the fold keeps what the production admits.");
    }


    /// <summary>
    /// An event identifier is minted only for an event type this convention states, because an identifier naming
    /// an event nothing recognises would be a claim the convention cannot make.
    /// </summary>
    [TestMethod]
    public void AnEventIdentifierIsMintedOnlyForAnEventTypeTheConventionStates()
    {
        Assert.IsTrue(EArkEvidenceWellKnown.IsEvidenceEventType(EArkEvidenceWellKnown.CreationEventType));
        Assert.IsTrue(EArkEvidenceWellKnown.IsEvidenceEventType(EArkEvidenceWellKnown.RenewalEventType));
        Assert.IsTrue(EArkEvidenceWellKnown.IsEvidenceEventType(EArkEvidenceWellKnown.ValidationEventType));
        Assert.IsFalse(EArkEvidenceWellKnown.IsEvidenceEventType("ingestion"));
        Assert.IsFalse(EArkEvidenceWellKnown.IsEvidenceEventType(null));
        Assert.IsFalse(EArkEvidenceWellKnown.IsEvidenceEventType(EArkEvidenceWellKnown.CreationEventType.ToUpperInvariant()));

        _ = Assert.Throws<ArgumentException>(
            () => EArkEvidenceWellKnown.EvidenceEventIdentifier("metadata/other/provenance.ers", "ingestion"));

        Assert.IsTrue(EArkEvidenceWellKnown.IsEvidenceRelationship(
            EArkEvidenceWellKnown.EvidenceRelationshipType, EArkEvidenceWellKnown.AttestsSubType));
        Assert.IsTrue(EArkEvidenceWellKnown.IsEvidenceRelationship(
            EArkEvidenceWellKnown.EvidenceRelationshipType, EArkEvidenceWellKnown.AttestedBySubType));
        Assert.IsFalse(EArkEvidenceWellKnown.IsEvidenceRelationship("structural", "is part of"));
        Assert.IsFalse(EArkEvidenceWellKnown.IsEvidenceRelationship(EArkEvidenceWellKnown.EvidenceRelationshipType, "some other direction"));
    }


    /// <summary>
    /// One placement produces the four elements a package states an artifact with, and they agree by
    /// construction: the manifest entry and the preservation-metadata object carry the same identifier and the
    /// same digest, computed once through the registered seam and recomputed independently here.
    /// </summary>
    /// <returns>A task that completes when the placement has been stated.</returns>
    [TestMethod]
    public async Task OnePlacementStatesFourElementsThatAgreeByConstruction()
    {
        byte[] artifactOctets = Encoding.UTF8.GetBytes("the evidential artifact's own octets");
        string entryName = EArkEvidenceWellKnown.PackageEvidenceEntryName("provenance.ers");

        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [new EArkPackageEntrySource { Name = entryName, Content = artifactOctets }],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        var attested = new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "file-1");
        var agent = new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "agent-1");

        using EArkEvidencePlacementResult placement = await EArkEvidencePlacement.StatePlacementAsync(
            new EArkEvidencePlacementContext
            {
                Artifact = new EArkEvidenceArtifactFacts { Kind = EArkEvidenceKind.EvidenceRecord, EntryName = entryName },
                Entry = read.Snapshot!.FindEntry(entryName)!,
                Instant = EArkValidationSource.Instant,
                AttestedObjectIdentifiers = [attested],
                AgentIdentifiers = [agent],
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        PremisIdentifier expectedIdentifier = EArkEvidenceWellKnown.EvidenceObjectIdentifier(entryName);
        Assert.AreEqual(expectedIdentifier.Value, placement.FileEntry.Id);
        Assert.HasCount(1, placement.Object.Identifiers);
        Assert.AreEqual(expectedIdentifier, placement.Object.Identifiers[0], "One artifact, one identifier, in both documents.");

        Assert.AreEqual(entryName, placement.FileEntry.Locator.Href);
        Assert.AreEqual(EArkEvidenceWellKnown.EvidenceRecordMediaType, placement.FileEntry.MediaType);
        Assert.AreEqual(artifactOctets.Length, placement.FileEntry.Size);
        Assert.AreEqual(EArkValidationSource.Instant, placement.FileEntry.Created);
        Assert.AreEqual(MetsWellKnown.MetadataLabel, placement.FileGroupUse);

        using DigestValue independent = await CryptographicKeyEvents.ComputeDigestAsync(
            artifactOctets,
            PkiDigestAlgorithm.Sha256.OutputByteLength,
            PkiDigestAlgorithm.Sha256.DigestTag,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var manifestFixity = Assert.IsInstanceOfType<EArkRecomputableFixity>(placement.FileEntry.Fixity);
        var objectFixity = Assert.IsInstanceOfType<EArkRecomputableFixity>(placement.Object.Characteristics[0].Fixities[0]);

        Assert.AreSequenceEqual(
            independent.AsReadOnlyMemory().Span[..PkiDigestAlgorithm.Sha256.OutputByteLength].ToArray(),
            manifestFixity.Digest.AsReadOnlyMemory().Span[..PkiDigestAlgorithm.Sha256.OutputByteLength].ToArray(),
            "The manifest's digest is the one the registered seam computes over the artifact's octets.");

        Assert.AreSequenceEqual(
            manifestFixity.Digest.AsReadOnlyMemory().Span[..PkiDigestAlgorithm.Sha256.OutputByteLength].ToArray(),
            objectFixity.Digest.AsReadOnlyMemory().Span[..PkiDigestAlgorithm.Sha256.OutputByteLength].ToArray(),
            "One digest, two owners: the two documents state the same value from one pass through the seam.");

        Assert.AreNotSame(manifestFixity.Digest, objectFixity.Digest,
            "Two owners means two carriers, so placing one into a document does not hand the other's memory away with it.");

        Assert.HasCount(1, placement.Object.Relationships);
        Assert.AreEqual(EArkEvidenceWellKnown.EvidenceRelationshipType, placement.Object.Relationships[0].Type);
        Assert.AreEqual(EArkEvidenceWellKnown.AttestsSubType, placement.Object.Relationships[0].SubType);
        Assert.Contains(attested, placement.Object.Relationships[0].RelatedObjectIdentifiers);

        Assert.AreEqual(EArkEvidenceWellKnown.AttestedBySubType, placement.AttestedByRelationship.SubType);
        Assert.Contains(expectedIdentifier, placement.AttestedByRelationship.RelatedObjectIdentifiers,
            "The relationship an attested object carries back names the artifact, which is the inverse direction.");

        Assert.AreEqual(EArkEvidenceWellKnown.CreationEventType, placement.Event.Type);
        Assert.Contains(agent, placement.Event.LinkingAgentIdentifiers);
        Assert.AreEqual(expectedIdentifier, placement.Event.LinkingObjectIdentifiers[0],
            "What the activity produced comes first, which a provenance graph reads as the generated entity.");
        Assert.AreEqual(attested, placement.Event.LinkingObjectIdentifiers[1],
            "What it used follows, which the same graph reads as the used entities.");
    }


    /// <summary>
    /// A renewal states the event that produced the evidence it renewed, which is the plain-text chaining
    /// mechanism the archival specification builds its preservation history from.
    /// </summary>
    /// <returns>A task that completes when the placement has been stated.</returns>
    [TestMethod]
    public async Task ARenewalPlacementNamesTheEventItFollowed()
    {
        byte[] artifactOctets = Encoding.UTF8.GetBytes("the renewed evidential artifact");
        string entryName = EArkEvidenceWellKnown.PackageEvidenceEntryName("provenance.ers");
        PremisIdentifier creation = EArkEvidenceWellKnown.EvidenceEventIdentifier(entryName, EArkEvidenceWellKnown.CreationEventType);

        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [new EArkPackageEntrySource { Name = entryName, Content = artifactOctets }],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        using EArkEvidencePlacementResult placement = await EArkEvidencePlacement.StatePlacementAsync(
            new EArkEvidencePlacementContext
            {
                Artifact = new EArkEvidenceArtifactFacts { Kind = EArkEvidenceKind.EvidenceRecord, EntryName = entryName },
                Entry = read.Snapshot!.FindEntry(entryName)!,
                Instant = EArkValidationSource.Instant,
                AttestedObjectIdentifiers = [],
                EventType = EArkEvidenceWellKnown.RenewalEventType,
                EventOutcome = "success",
                RelatedEventIdentifier = creation,
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EArkEvidenceWellKnown.RenewalEventType, placement.Event.Type);
        Assert.AreEqual("success", placement.Event.Outcome);
        Assert.Contains(creation, placement.AttestedByRelationship.RelatedEventIdentifiers);
        Assert.AreNotEqual(
            EArkEvidenceWellKnown.EvidenceEventIdentifier(entryName, EArkEvidenceWellKnown.CreationEventType).Value,
            placement.Event.Identifiers[0].Value,
            "A renewal is a second event about one artifact, so it needs an identifier of its own.");
    }


    /// <summary>
    /// A placement is refused for anything the convention cannot state one for, rather than being written around
    /// the defect: an artifact of no kind, a folder, or an event type this convention does not state.
    /// </summary>
    /// <returns>A task that completes when every refusal has been observed.</returns>
    [TestMethod]
    public async Task APlacementIsRefusedForWhatTheConventionCannotState()
    {
        string entryName = EArkEvidenceWellKnown.PackageEvidenceEntryName("provenance.ers");
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [
                new EArkPackageEntrySource { Name = entryName, Content = Encoding.UTF8.GetBytes("octets") },
                EArkPackageSource.Folder(EArkWellKnown.OtherMetadataFolderName),
            ],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        //A folder entry keeps the trailing separator that is what makes it a folder entry, so it is looked up
        //under the name the snapshot really holds it under rather than under the folder's bare name.
        EArkPackageEntry file = read.Snapshot!.FindEntry(entryName)!;
        EArkPackageEntry folder = read.Snapshot!.FindEntry(EArkWellKnown.OtherMetadataFolderName + EArkWellKnown.PathSeparator)!;
        Assert.IsNotNull(folder);
        Assert.IsTrue(folder.IsFolder);

        _ = await Assert.ThrowsAsync<ArgumentException>(async () => await EArkEvidencePlacement.StatePlacementAsync(
            ContextWith(new EArkEvidenceArtifactFacts { Kind = default, EntryName = entryName }, file),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        _ = await Assert.ThrowsAsync<ArgumentException>(async () => await EArkEvidencePlacement.StatePlacementAsync(
            ContextWith(new EArkEvidenceArtifactFacts { Kind = EArkEvidenceKind.EvidenceRecord, EntryName = entryName }, folder),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        _ = await Assert.ThrowsAsync<ArgumentException>(async () => await EArkEvidencePlacement.StatePlacementAsync(
            ContextWith(new EArkEvidenceArtifactFacts { Kind = EArkEvidenceKind.EvidenceRecord, EntryName = entryName }, file) with
            {
                EventType = "ingestion",
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        //One context shape the three refusals differ from in exactly one way each.
        static EArkEvidencePlacementContext ContextWith(EArkEvidenceArtifactFacts artifact, EArkPackageEntry entry) => new()
        {
            Artifact = artifact,
            Entry = entry,
            Instant = EArkValidationSource.Instant,
            AttestedObjectIdentifiers = [],
        };
    }


    /// <summary>
    /// A package carrying an artifact of each kind — a real Evidence Record, a real Signed Data Object and a real
    /// Associated Signature Container, each with a self-description and each placed by the convention — reaches
    /// the convention's claims and the two rows of TS 119 511 a package can answer.
    /// </summary>
    /// <param name="kind">The kind of artifact the package carries.</param>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    [DataRow(EArkEvidenceKind.EvidenceRecord, DisplayName = "an Evidence Record")]
    [DataRow(EArkEvidenceKind.SignedDataObject, DisplayName = "a Signed Data Object")]
    [DataRow(EArkEvidenceKind.Container, DisplayName = "an Associated Signature Container")]
    public async Task APackageCarryingEachArtifactKindReachesTheConventionsClaims(EArkEvidenceKind kind)
    {
        using MintedArtifact artifact = await MintAsync(kind, protectedSelfDescription: true).ConfigureAwait(false);
        using EArkEvidencePackage package = await EArkEvidenceSource.BuildAsync(
            artifact.Octets, artifact.Facts, TestContext.CancellationToken).ConfigureAwait(false);

        ClaimIssueResult result = await RunAsync(package.ToValidationContext()).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageEvidencePlacement, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageEvidenceSelfDescription, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, PreservationClaimIds.Ovr92Item04, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, PreservationClaimIds.Ovr92Item05, ClaimOutcome.Success, EArkClaimReason.RequirementMet);

        Assert.AreEqual(kind, package.Artifact.Kind);
        Assert.AreEqual(EArkEvidenceWellKnown.MediaTypeOf(kind), EArkEvidenceWellKnown.MediaTypeOf(package.Artifact.Kind));
    }


    /// <summary>
    /// An artifact whose self-description nothing protects leaves <c>OVR-9.2-05</c> unmet as a recommendation
    /// rather than met, which is what makes the requirement's condition — something is embedded — decidable at
    /// all from a package.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task AnUnprotectedSelfDescriptionLeavesTheProtectionRowUnmet()
    {
        using MintedArtifact artifact = await MintAsync(EArkEvidenceKind.EvidenceRecord, protectedSelfDescription: false).ConfigureAwait(false);
        using EArkEvidencePackage package = await EArkEvidenceSource.BuildAsync(
            artifact.Octets, artifact.Facts, TestContext.CancellationToken).ConfigureAwait(false);

        ClaimIssueResult result = await RunAsync(package.ToValidationContext()).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageEvidenceSelfDescription, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, PreservationClaimIds.Ovr92Item04, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, PreservationClaimIds.Ovr92Item05, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
    }


    /// <summary>
    /// An artifact carrying no self-description at all makes the absence visible without declaring the package
    /// broken: both recommendations are declined and the protection row never triggers, because nothing was
    /// embedded for anything to protect.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task AnArtifactCarryingNoSelfDescriptionMakesTheAbsenceVisibleWithoutFailingThePackage()
    {
        using EvidenceRecord plain = await EArkEvidenceSource.MintEvidenceRecordAsync(
            [Encoding.UTF8.GetBytes(AttestedContent)], selfDescription: null, TestContext.CancellationToken).ConfigureAwait(false);

        EArkEvidenceArtifactFacts facts = EArkEvidencePlacement.StateEvidenceRecordFacts(
            plain, EArkEvidenceSource.EntryNameFor(EArkEvidenceKind.EvidenceRecord), [AttestedContent]);

        using EArkEvidencePackage package = await EArkEvidenceSource.BuildAsync(
            plain.AsReadOnlyMemory(), facts, TestContext.CancellationToken).ConfigureAwait(false);

        ClaimIssueResult result = await RunAsync(package.ToValidationContext()).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageEvidencePlacement, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageEvidenceSelfDescription, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, PreservationClaimIds.Ovr92Item04, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, PreservationClaimIds.Ovr92Item05, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
    }


    /// <summary>
    /// An artifact sitting where the convention does not put one fails the placement rule, because a signature
    /// file a reader cannot tell from ordinary content is exactly the failure the convention exists to prevent.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task AnArtifactSittingWhereTheConventionDoesNotPutOneFailsThePlacementRule()
    {
        using MintedArtifact artifact = await MintAsync(EArkEvidenceKind.EvidenceRecord, protectedSelfDescription: true).ConfigureAwait(false);
        EArkEvidenceArtifactFacts misplaced = artifact.Facts with
        {
            EntryName = EArkWellKnown.PreservationMetadataFolderName + "/provenance.ers",
        };

        using EArkEvidencePackage package = await EArkEvidenceSource.BuildAsync(
            artifact.Octets, misplaced, TestContext.CancellationToken).ConfigureAwait(false);

        ClaimIssueResult result = await RunAsync(package.ToValidationContext()).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageEvidencePlacement, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageEvidenceSelfDescription, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
    }


    /// <summary>
    /// An artifact no preservation event and no relationship names fails the placement rule even though the
    /// manifest names it: a file the package holds and says nothing about is a file, not evidence.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task AnArtifactNoPreservationEventNamesFailsThePlacementRule()
    {
        using MintedArtifact artifact = await MintAsync(EArkEvidenceKind.EvidenceRecord, protectedSelfDescription: true).ConfigureAwait(false);
        using EArkEvidencePackage package = await EArkEvidenceSource.BuildAsync(
            artifact.Octets, artifact.Facts, TestContext.CancellationToken, recordInPreservationMetadata: false).ConfigureAwait(false);

        ClaimIssueResult result = await RunAsync(package.ToValidationContext()).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageEvidencePlacement, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
    }


    /// <summary>
    /// A caller that states no artifacts is never reported as conformant: a package holding no evidence and a
    /// caller that never looked for any are indistinguishable from inside a rule, and reporting the second as
    /// conformance would be the worst answer available.
    /// </summary>
    /// <returns>A task that completes when the empty context has been validated.</returns>
    [TestMethod]
    public async Task ACallerThatStatesNoArtifactsIsNeverReportedAsConformant()
    {
        using MetsDocument manifest = EArkValidationSource.ConformantManifest();

        ClaimIssueResult result = await RunAsync(new EArkValidationContext
        {
            EntryNames = [],
            CurrentTime = EArkValidationSource.Instant,
            PackageManifest = manifest,
        }).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageEvidencePlacement, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageEvidenceSelfDescription, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);
        EArkStructuralRuleTests.AssertOutcome(result, PreservationClaimIds.Ovr92Item04, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);
        EArkStructuralRuleTests.AssertOutcome(result, PreservationClaimIds.Ovr92Item05, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageProvenanceAnchored, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);
    }


    /// <summary>
    /// No rule of the evidence profile ever answers with an empty claim list, whatever it was handed — which is
    /// what makes a missing row in the result mean something went wrong rather than nothing applied.
    /// </summary>
    /// <returns>A task that completes when every rule has been run over an empty context.</returns>
    [TestMethod]
    public async Task NoRuleOfTheEvidenceProfileAnswersWithAnEmptyClaimList()
    {
        IList<ClaimDelegate<EArkValidationContext>> rules = EArkValidationProfiles.EvidencePlacementRules();
        Assert.HasCount(3, rules);

        var empty = new EArkValidationContext { EntryNames = [], CurrentTime = EArkValidationSource.Instant };
        for(int i = 0; i < rules.Count; ++i)
        {
            List<Claim> claims = await rules[i].Delegate(empty, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsNotEmpty(claims, $"Rule {i} of the evidence profile answered with nothing at all.");
            for(int j = 0; j < claims.Count; ++j)
            {
                Assert.AreNotEqual(ClaimOutcome.Success, claims[j].Outcome, "A rule given nothing never reaches success.");
            }
        }
    }


    /// <summary>
    /// The evidence profile is part of what an Archival Information Package is judged by, rather than a rule list
    /// a caller has to remember to add.
    /// </summary>
    [TestMethod]
    public void TheEvidenceProfileIsPartOfTheArchivalProfile()
    {
        IList<ClaimDelegate<EArkValidationContext>> archival = EArkValidationProfiles.ArchivalPackageRules();

        var issued = new List<int>();
        for(int i = 0; i < archival.Count; ++i)
        {
            for(int j = 0; j < archival[i].ExpectedClaimIds.Count; ++j)
            {
                issued.Add(archival[i].ExpectedClaimIds[j].Code);
            }
        }

        Assert.Contains(EArkClaimIds.PackageEvidencePlacement.Code, issued);
        Assert.Contains(EArkClaimIds.PackageEvidenceSelfDescription.Code, issued);
        Assert.Contains(EArkClaimIds.PackageProvenanceAnchored.Code, issued);
        Assert.Contains(PreservationClaimIds.Ovr92Item04.Code, issued);
        Assert.Contains(PreservationClaimIds.Ovr92Item05.Code, issued);
    }


    /// <summary>
    /// States the position the tree classifier gave one entry of a classified package.
    /// </summary>
    /// <param name="facts">What the classifier stated.</param>
    /// <param name="entryName">The entry name to look up.</param>
    /// <returns>The position.</returns>
    private static EArkPackageEntryPlacement PlacementOf(EArkPackageFacts facts, string entryName)
    {
        for(int i = 0; i < facts.Entries.Count; ++i)
        {
            if(string.Equals(facts.Entries[i].Entry.Name, entryName, StringComparison.Ordinal))
            {
                return facts.Entries[i].Placement;
            }
        }

        Assert.Fail($"The classified package holds no entry named '{entryName}'.");

        return EArkPackageEntryPlacement.NotEvaluated;
    }


    /// <summary>Runs the evidence profile over one context.</summary>
    /// <param name="context">The package validation is given.</param>
    /// <returns>What the issuer concluded.</returns>
    private async Task<ClaimIssueResult> RunAsync(EArkValidationContext context)
    {
        var issuer = new ClaimIssuer<EArkValidationContext>(IssuerId, EArkValidationProfiles.EvidencePlacementRules(), IssuerTime);

        return await issuer.GenerateClaimsAsync(context, CorrelationId, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Mints one real artifact of the requested kind together with the facts a package records it by.
    /// </summary>
    /// <param name="kind">The kind to mint.</param>
    /// <param name="protectedSelfDescription">Whether the self-description ends up inside something the artifact itself proves.</param>
    /// <returns>The artifact. The caller owns and disposes it.</returns>
    private async Task<MintedArtifact> MintAsync(EArkEvidenceKind kind, bool protectedSelfDescription)
    {
        byte[] attested = Encoding.UTF8.GetBytes(AttestedContent);
        string entryName = EArkEvidenceSource.EntryNameFor(kind);

        if(kind == EArkEvidenceKind.EvidenceRecord)
        {
            EvidenceRecord initial = await EArkEvidenceSource.MintEvidenceRecordAsync(
                [attested], EArkEvidenceSource.SelfDescription, TestContext.CancellationToken).ConfigureAwait(false);

            if(!protectedSelfDescription)
            {
                return new MintedArtifact(initial, EArkEvidencePlacement.StateEvidenceRecordFacts(initial, entryName, [AttestedContent]), initial.AsReadOnlyMemory());
            }

            using(initial)
            {
                EvidenceRecord renewed = await EArkEvidenceSource.RenewHashTreeAsync(
                    initial, [attested], TestContext.CancellationToken).ConfigureAwait(false);

                return new MintedArtifact(renewed, EArkEvidencePlacement.StateEvidenceRecordFacts(renewed, entryName, [AttestedContent]), renewed.AsReadOnlyMemory());
            }
        }

        if(kind == EArkEvidenceKind.SignedDataObject)
        {
            CmsSignedData signature = await EArkEvidenceSource.MintSignedDataObjectAsync(
                attested, EArkEvidenceSource.SelfDescription, protectedSelfDescription, TestContext.CancellationToken).ConfigureAwait(false);

            return new MintedArtifact(
                signature,
                EArkEvidencePlacement.StateSignedDataObjectFacts(signature, 0, entryName, [AttestedContent]),
                signature.AsReadOnlyMemory());
        }

        AsicContainerCreationResult container = await EArkEvidenceSource.MintContainerAsync(
            [new AsicDataObject { Name = "provenance.xml", Content = attested }], TestContext.CancellationToken).ConfigureAwait(false);

        string extensionText = EArkEvidenceSource.SelfDescription.ToExtensionText(BaseMemoryPool.Shared);

        return new MintedArtifact(
            container,
            EArkEvidencePlacement.StateContainerFacts(
                extensionText, entryName, [AttestedContent], BaseMemoryPool.Shared, isManifestProtected: protectedSelfDescription),
            container.Container.AsReadOnlyMemory());
    }


    /// <summary>
    /// One minted artifact: whatever owns its octets, the facts a package records it by, and the octets
    /// themselves as a view into the owner.
    /// </summary>
    /// <param name="Owner">The carrier owning the artifact's octets.</param>
    /// <param name="Facts">What a caller states about the artifact.</param>
    /// <param name="Octets">The artifact's octets, a view into <paramref name="Owner"/>.</param>
    private sealed record MintedArtifact(IDisposable Owner, EArkEvidenceArtifactFacts Facts, ReadOnlyMemory<byte> Octets): IDisposable
    {
        /// <summary>Disposes the carrier owning the artifact's octets.</summary>
        public void Dispose() => Owner.Dispose();
    }
}
