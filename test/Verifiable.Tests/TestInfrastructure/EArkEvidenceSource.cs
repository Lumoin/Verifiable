using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// One hand-built Information Package carrying one evidential artifact, together with everything the evidence
/// rules read about it.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> An instance owns the snapshot, the manifest and the preservation-metadata
/// document. The placement result the manifest and the document were built from is deliberately not owned and
/// deliberately not disposed: its two carrier-owning parts were placed into those two documents, which own them
/// now.
/// </remarks>
internal sealed record EArkEvidencePackage: IDisposable
{
    /// <summary>Gets the package as a value snapshot. Owned by this instance.</summary>
    public required EArkPackageSnapshot Snapshot { get; init; }

    /// <summary>Gets what the package's layout states about itself.</summary>
    public required EArkPackageFacts Facts { get; init; }

    /// <summary>Gets the package's own root manifest. Owned by this instance.</summary>
    public required MetsDocument Manifest { get; init; }

    /// <summary>Gets the package's preservation-metadata document. Owned by this instance.</summary>
    public required PremisDocument PreservationMetadata { get; init; }

    /// <summary>Gets what the caller states about the one evidential artifact the package carries.</summary>
    public required EArkEvidenceArtifactFacts Artifact { get; init; }


    /// <summary>Builds the validation context the evidence rules run over.</summary>
    /// <returns>The context.</returns>
    public EArkValidationContext ToValidationContext() => new()
    {
        EntryNames = EntryNames(),
        CurrentTime = EArkValidationSource.Instant,
        PackageFacts = Facts,
        PackageManifest = Manifest,
        PreservationMetadata = [PreservationMetadata],
        EvidenceArtifacts = [Artifact],
        MemoryPool = BaseMemoryPool.Shared,
    };


    /// <summary>Builds the anchoring context the plan is stated from.</summary>
    /// <returns>The context.</returns>
    public EArkProvenanceAnchorContext ToAnchorContext() => new()
    {
        Snapshot = Snapshot,
        PackageManifest = Manifest,
    };


    /// <summary>States the snapshot's entry names, which the bounds rule reads.</summary>
    /// <returns>The names, in the snapshot's own order.</returns>
    public List<string> EntryNames()
    {
        var names = new List<string>(Snapshot.Entries.Count);
        for(int i = 0; i < Snapshot.Entries.Count; ++i)
        {
            names.Add(Snapshot.Entries[i].Name);
        }

        return names;
    }


    /// <summary>Disposes the snapshot and the two documents.</summary>
    public void Dispose()
    {
        Manifest.Dispose();
        PreservationMetadata.Dispose();
        Snapshot.Dispose();
    }
}


/// <summary>
/// Hand-built packages carrying evidential artifacts, and the container-extension carrier's XML half.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why the XML lives here.</strong> The container carrier's self-description travels inside an
/// <c>Extension</c> element, whose content the manifest binding carries verbatim as octets. Building and reading
/// that element is the serialisation seam's business and this project references no XML package, so it is staged
/// test-side beside the worked manifest binding — the same split every other XML-shaped value of this wave
/// takes.
/// </para>
/// <para>
/// <strong>Everything else goes through the shipped surfaces.</strong> Digests are the registered seam's,
/// fixities and identifiers are <see cref="EArkEvidencePlacement"/>'s, and the manifest and preservation-metadata
/// documents are the conformant ones the other rule tests are written over, extended rather than replaced.
/// </para>
/// </remarks>
internal static class EArkEvidenceSource
{
    /// <summary>The entry name of the preservation-metadata document the conformant manifest references.</summary>
    internal static string ProvenanceEntryName { get; } = "metadata/preservation/PREMIS.xml";

    /// <summary>The content of that document, as the package carries it.</summary>
    internal static string ProvenanceContent { get; } =
        "<premis version=\"3.0\"><event><eventType>ingestion</eventType></event></premis>";

    /// <summary>A self-description stating all three identifiers of the requirement's items a) to c).</summary>
    internal static EArkEvidenceSelfDescription SelfDescription { get; } = new()
    {
        PreservationServiceIdentifier = "urn:example:preservation-service:1",
        EvidencePolicyIdentifier = "urn:example:preservation-evidence-policy:1",
        PreservationProfileIdentifier = "urn:example:preservation-profile:1",
    };

    /// <summary>The ASiC namespace the <c>Extension</c> element itself is declared in (Annex A.3).</summary>
    private static string AsicNamespace { get; } = "http://uri.etsi.org/02918/v1.2.1#";

    /// <summary>
    /// The address handed to the time-stamp transport delegate. No socket is opened for it: the delegate answers
    /// from the in-process authority, and the value exists because the shipped surface makes a caller name the
    /// authority it is talking to.
    /// </summary>
    private static string TimestampAuthorityAddress { get; } = "https://preservation-authority.example.test/tsa";

    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The <c>genTime</c> the initial archive time-stamp of a minted Evidence Record states.</summary>
    internal static DateTimeOffset InitialArchiveTime { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The <c>genTime</c> a Hash-Tree Renewal's archive time-stamp states.</summary>
    internal static DateTimeOffset RenewalArchiveTime { get; } = TestClock.CanonicalEpoch.AddHours(2);

    /// <summary>The claimed signing time a minted Signed Data Object states.</summary>
    internal static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    /// <summary>The <c>genTime</c> an archive time-stamp attached to a minted Signed Data Object states.</summary>
    internal static DateTimeOffset SignatureArchiveTime { get; } = TestClock.CanonicalEpoch.AddHours(1);


    /// <summary>
    /// States the entry name an artifact of one kind sits under, by the placement convention.
    /// </summary>
    /// <param name="kind">The kind of artifact.</param>
    /// <returns>The entry name.</returns>
    internal static string EntryNameFor(EArkEvidenceKind kind) => kind switch
    {
        EArkEvidenceKind.SignedDataObject => EArkEvidenceWellKnown.PackageEvidenceEntryName("provenance.p7s"),
        EArkEvidenceKind.Container => EArkEvidenceWellKnown.PackageEvidenceEntryName("provenance.asice"),
        EArkEvidenceKind.EvidenceRecord => EArkEvidenceWellKnown.PackageEvidenceEntryName("provenance.ers"),
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "An artifact of no kind sits nowhere.")
    };


    /// <summary>
    /// Builds a package whose manifest, preservation-metadata document and layout all record one evidential
    /// artifact by the placement convention.
    /// </summary>
    /// <param name="artifactOctets">The artifact's own octets.</param>
    /// <param name="artifact">What the caller states about the artifact.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <param name="recordInPreservationMetadata">Whether the preservation-metadata document records the artifact, which the placement convention asks for.</param>
    /// <param name="provenanceContent">The preservation-metadata document's octets as the package carries them, or <see langword="null"/> for the default.</param>
    /// <returns>The package. The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the snapshot and both documents transfers to the returned package, which the caller disposes; the placement's two carrier-owning parts are placed into those documents and are therefore not disposed here.")]
    internal static async ValueTask<EArkEvidencePackage> BuildAsync(
        ReadOnlyMemory<byte> artifactOctets,
        EArkEvidenceArtifactFacts artifact,
        CancellationToken cancellationToken,
        bool recordInPreservationMetadata = true,
        string? provenanceContent = null)
    {
        string provenance = provenanceContent ?? ProvenanceContent;
        List<EArkPackageEntrySource> entries =
        [
            .. EArkValidationSource.ConformantPackageEntries(),
            new EArkPackageEntrySource { Name = artifact.EntryName, Content = artifactOctets },
        ];

        for(int i = 0; i < entries.Count; ++i)
        {
            if(string.Equals(entries[i].Name, ProvenanceEntryName, StringComparison.Ordinal))
            {
                entries[i] = EArkPackageSource.TextFile(ProvenanceEntryName, provenance);
            }
        }

        EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(entries, EArkPackageLimits.Conformant, BaseMemoryPool.Shared);
        try
        {
            EArkPackageSnapshot snapshot = read.Snapshot!;
            EArkPackageFacts facts = EArkPackageReading.StateFacts(snapshot);
            EArkPackageEntry artifactEntry = snapshot.FindEntry(artifact.EntryName)!;

            EArkEvidencePlacementResult placement = await EArkEvidencePlacement.StatePlacementAsync(
                new EArkEvidencePlacementContext
                {
                    Artifact = artifact,
                    Entry = artifactEntry,
                    Instant = EArkValidationSource.Instant,
                    AttestedObjectIdentifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "file-1")],
                    AgentIdentifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "agent-1")],
                },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);

            MetsDocument manifest = EArkValidationSource.ConformantManifest(
                provenanceReference: EArkValidationSource.Reference(
                    ProvenanceEntryName,
                    MetsWellKnown.PremisMetadataType,
                    PremisWellKnown.PremisVersion,
                    await ChecksumOfAsync(Encoding.UTF8.GetBytes(provenance), cancellationToken).ConfigureAwait(false)),
                additionalFileGroups:
                [
                    new MetsFileGroup
                    {
                        Id = "group-evidence",
                        Use = placement.FileGroupUse,
                        Files = [placement.FileEntry],
                    }
                ]);

            PremisDocument preservationMetadata = recordInPreservationMetadata
                ? EArkValidationSource.ConformantPreservationMetadata([placement.Object], [placement.Event])
                : EArkValidationSource.ConformantPreservationMetadata();

            //The placement result is not disposed: its file entry now belongs to the manifest and its object to
            //the preservation-metadata document, and each of those disposes what it holds.
            return new EArkEvidencePackage
            {
                Snapshot = snapshot,
                Facts = facts,
                Manifest = manifest,
                PreservationMetadata = preservationMetadata,
                Artifact = artifact,
            };
        }
        catch
        {
            read.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Computes a checksum through the registered digest seam, as the hexadecimal a checksum attribute carries.
    /// </summary>
    /// <param name="content">The octets to hash.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The digest as lowercase hexadecimal.</returns>
    internal static async ValueTask<string> ChecksumOfAsync(ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            content,
            PkiDigestAlgorithm.Sha256.OutputByteLength,
            PkiDigestAlgorithm.Sha256.DigestTag,
            BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return Convert.ToHexStringLower(digest.AsReadOnlyMemory().Span[..PkiDigestAlgorithm.Sha256.OutputByteLength]);
    }


    /// <summary>
    /// Builds the container-extension carrier: one <c>Extension</c> element whose single child is this
    /// convention's element carrying the self-description in base 64.
    /// </summary>
    /// <param name="extensionText">The base-64 text the element carries.</param>
    /// <returns>The extension. The caller owns and disposes it, usually by disposing the manifest holding it.</returns>
    internal static AsicManifestExtension BuildSelfDescriptionExtension(string extensionText)
    {
        string element = string.Concat(
            "<Extension xmlns=\"", AsicNamespace, "\" Critical=\"",
            EArkEvidenceWellKnown.SelfDescriptionExtensionIsCritical ? "true" : "false",
            "\"><", EArkEvidenceWellKnown.SelfDescriptionElementName,
            " xmlns=\"", EArkEvidenceWellKnown.SelfDescriptionElementNamespace, "\">", extensionText,
            "</", EArkEvidenceWellKnown.SelfDescriptionElementName, "></Extension>");

        XElement parsed = XElement.Parse(element);

        return new AsicManifestExtension
        {
            Critical = EArkEvidenceWellKnown.SelfDescriptionExtensionIsCritical,
            ElementNamespace = EArkEvidenceWellKnown.SelfDescriptionElementNamespace,
            ElementName = EArkEvidenceWellKnown.SelfDescriptionElementName,
            Content = PooledMemory.FromBytes(
                Encoding.UTF8.GetBytes(parsed.ToString(SaveOptions.DisableFormatting)),
                BaseMemoryPool.Shared,
                AsicTags.ManifestExtension),
        };
    }


    /// <summary>
    /// Reads the text a self-description extension carries, out of the whole <c>Extension</c> element octets the
    /// manifest model holds.
    /// </summary>
    /// <param name="extension">The extension a manifest carried.</param>
    /// <returns>The text, or <see langword="null"/> when the extension is not this convention's.</returns>
    internal static string? ReadSelfDescriptionText(AsicManifestExtension extension)
    {
        ArgumentNullException.ThrowIfNull(extension);

        if(extension.Name != EArkEvidenceWellKnown.SelfDescriptionExtensionName)
        {
            return null;
        }

        XElement parsed = XElement.Parse(Encoding.UTF8.GetString(extension.Content.AsReadOnlySpan()));

        return parsed.Elements().FirstOrDefault()?.Value;
    }


    /// <summary>
    /// Mints an Evidence Record over one data object group through the shipped creation surface, optionally
    /// carrying a self-description in the <c>attributes</c> field of its one archive time-stamp.
    /// </summary>
    /// <param name="dataObjects">The octets the record is to prove, as one group.</param>
    /// <param name="selfDescription">The self-description the record carries, or <see langword="null"/> to carry none.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The record. The caller owns and disposes it.</returns>
    /// <remarks>
    /// The hash tree and the time-stamp token are the shipped surface's and the authority's; only the
    /// <c>attributes</c> field is added here, because
    /// <see cref="EvidenceRecordCreationContext"/> has no member for it — the field is reached exactly as the
    /// convention's own documentation says, by re-encoding the archive time-stamp through
    /// <see cref="EvidenceRecords.EncodeArchiveTimeStamp"/>, which leaves the reduced hash tree and the token
    /// untouched and therefore leaves the record verifiable.
    /// </remarks>
    internal static async ValueTask<EvidenceRecord> MintEvidenceRecordAsync(
        IReadOnlyList<ReadOnlyMemory<byte>> dataObjects,
        EArkEvidenceSelfDescription? selfDescription,
        CancellationToken cancellationToken)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        var responder = new MintingTimestampResponder(authority, [authority, root], InitialArchiveTime);

        using EvidenceRecordCreation creation = await EvidenceRecords.CreateInitialAsync(
            new EvidenceRecordCreationContext
            {
                DataObjectGroups = [new EvidenceRecordDataObjectGroup { DataObjects = dataObjects }],
                DigestAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TimestampAuthorityAddress,
                FetchTimestampResponse = responder.FetchAsync,
            },
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        EvidenceRecord created = creation.EvidenceRecords[0];

        return selfDescription is null
            ? EvidenceRecord.Read(created.AsReadOnlySpan(), BaseMemoryPool.Shared)
            : CarrySelfDescription(created, selfDescription);
    }


    /// <summary>
    /// Performs a Hash-Tree Renewal of a record through the shipped surface, which is what puts a second chain
    /// after the one a self-description sits in.
    /// </summary>
    /// <param name="evidenceRecord">The record to renew.</param>
    /// <param name="dataObjects">The data objects of its group that are still present.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The renewed record. The caller owns and disposes it.</returns>
    internal static async ValueTask<EvidenceRecord> RenewHashTreeAsync(
        EvidenceRecord evidenceRecord,
        IReadOnlyList<ReadOnlyMemory<byte>> dataObjects,
        CancellationToken cancellationToken)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        var responder = new MintingTimestampResponder(authority, [authority, root], RenewalArchiveTime);

        using EvidenceRecordRenewal renewal = await EvidenceRecords.RenewHashTreeAsync(
            new EvidenceRecordHashTreeRenewalContext
            {
                DataObjectGroups =
                [
                    new EvidenceRecordHashTreeRenewalGroup { EvidenceRecord = evidenceRecord, DataObjects = dataObjects }
                ],
                DigestAlgorithm = PkiDigestAlgorithm.Sha512,
                TsaUri = TimestampAuthorityAddress,
                FetchTimestampResponse = responder.FetchAsync,
            },
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        return EvidenceRecord.Read(renewal.EvidenceRecords[0].AsReadOnlySpan(), BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Mints a Signed Data Object over content, optionally carrying a self-description as an unsigned attribute
    /// and optionally carrying an archive time-stamp after it.
    /// </summary>
    /// <param name="content">The content the signature covers.</param>
    /// <param name="selfDescription">The self-description the signer carries, or <see langword="null"/> to carry none.</param>
    /// <param name="withArchiveTimestamp">Whether an archive time-stamp is attached after the self-description.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The Signed Data Object. The caller owns and disposes it.</returns>
    /// <remarks>
    /// The order matters and is the point of the parameter: an unsigned attribute is covered by an archive
    /// time-stamp attached <em>after</em> it, so attaching the time-stamp last is what makes the self-description
    /// protected, and leaving it off is what makes it unprotected.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Each augmentation produces a new carrier and the one it augmented is disposed as soon as it is superseded; ownership of the last one transfers to the caller, and the catch disposes whatever is held on a partial failure.")]
    internal static async ValueTask<CmsSignedData> MintSignedDataObjectAsync(
        ReadOnlyMemory<byte> content,
        EArkEvidenceSelfDescription? selfDescription,
        bool withArchiveTimestamp,
        CancellationToken cancellationToken)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode signer = X509ChainTestRing.CreateLeaf(root, "preservation-signer.example.test", timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);

        CmsSignedData current = CAdESSignatureTestFactory.SignBaseline(content, signer, SigningTime);
        try
        {
            if(selfDescription is not null)
            {
                using CmsAttribute attribute = selfDescription.ToAttribute(BaseMemoryPool.Shared);
                CmsSignedData described = CmsSignedDataAugmentation.AppendUnsignedAttributes(current, 0, [attribute], BaseMemoryPool.Shared);
                current.Dispose();
                current = described;
            }

            if(withArchiveTimestamp)
            {
                CmsSignedData archived = await CAdESSignatureTestFactory.AttachArchiveTimestampAsync(
                    current, authority, [authority, root], SignatureArchiveTime, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

                current.Dispose();
                current = archived;
            }

            return current;
        }
        catch
        {
            current.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Creates the Evidence Record that anchors a package's provenance, through the shipped anchoring surface,
    /// against a Time-Stamping Authority that mints a genuine token over whatever imprint the request states.
    /// </summary>
    /// <param name="plan">The plan naming which of the package's entries the anchor covers.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The creation result, holding one record for the one group. The caller owns and disposes it.</returns>
    /// <remarks>
    /// Everything but the data object groups is stated here and the groups come from the plan, which is exactly
    /// the division of labour <see cref="EArkEvidenceAnchoring.CreateProvenanceEvidenceAsync"/> documents: the
    /// anchor decides <em>which octets</em> and the shipped surface decides everything else.
    /// </remarks>
    internal static async ValueTask<EvidenceRecordCreation> CreateProvenanceEvidenceAsync(
        EArkProvenanceAnchorPlan plan,
        CancellationToken cancellationToken)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        var responder = new MintingTimestampResponder(authority, [authority, root], InitialArchiveTime);

        return await EArkEvidenceAnchoring.CreateProvenanceEvidenceAsync(
            plan,
            new EvidenceRecordCreationContext
            {
                DataObjectGroups = [],
                DigestAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TimestampAuthorityAddress,
                FetchTimestampResponse = responder.FetchAsync,
            },
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Mints an extended Associated Signature Container holding an Evidence Record over the supplied data
    /// objects, through the shipped container-creation surface.
    /// </summary>
    /// <param name="dataObjects">The data objects the container carries and its Evidence Record proves.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The creation result, whose <c>Container</c> is the container's octets. The caller owns and disposes it.</returns>
    /// <remarks>
    /// The extended form is the one a package wants: an Information Package holds several data objects, which is
    /// what the extended container is for. The manifest is written by the worked binding staged beside the
    /// container tests, because the shipped surface ships no serialisation of its own.
    /// </remarks>
    internal static async ValueTask<AsicContainerCreationResult> MintContainerAsync(
        IReadOnlyList<AsicDataObject> dataObjects,
        CancellationToken cancellationToken)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        var responder = new MintingTimestampResponder(authority, [authority, root], InitialArchiveTime);

        return await AsicContainerCreation.CreateEvidenceRecordAsync(
            new AsicContainerEvidenceRecordContext
            {
                Shape = AsicContainerShape.Extended,
                DataObjects = dataObjects,
                LastModified = TestClock.CanonicalEpoch,
                TsaUri = TimestampAuthorityAddress,
                FetchTimestampResponse = responder.FetchAsync,
                DigestAlgorithm = PkiDigestAlgorithm.Sha256,
                EncodeManifest = Verifiable.Cryptography.Pki.Xml.AsicManifestXmlBinding.EncodeAsync,
            },
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Rewrites a record's one archive time-stamp with the self-description in its <c>attributes</c> field,
    /// leaving every other field of it exactly as the creation surface wrote it.
    /// </summary>
    /// <param name="evidenceRecord">The record to rewrite, which the caller still owns.</param>
    /// <param name="selfDescription">The self-description to carry.</param>
    /// <returns>The rewritten record. The caller owns and disposes it.</returns>
    /// <exception cref="InvalidOperationException">When the record is not the single-chain, single-stamp shape this helper rewrites.</exception>
    private static EvidenceRecord CarrySelfDescription(EvidenceRecord evidenceRecord, EArkEvidenceSelfDescription selfDescription)
    {
        EvidenceRecordArchiveTimeStampSequence sequence = evidenceRecord.ArchiveTimeStampSequence;
        if(sequence.Chains.Count != 1 || sequence.Chains[0].ArchiveTimeStamps.Count != 1)
        {
            throw new InvalidOperationException(
                "A self-description is carried into a freshly created record, which holds one chain of one archive time-stamp.");
        }

        EvidenceRecordArchiveTimeStamp stamp = sequence.Chains[0].ArchiveTimeStamps[0];
        using CmsAttribute attribute = selfDescription.ToAttribute(BaseMemoryPool.Shared);
        using PooledMemory rewrittenStamp = EvidenceRecords.EncodeArchiveTimeStamp(
            stamp.DigestAlgorithm, [attribute], stamp.ReducedHashtree, stamp.TimeStamp, BaseMemoryPool.Shared);

        using PooledMemory rewrittenChain = EvidenceRecords.EncodeArchiveTimeStampChain(
            [rewrittenStamp.AsReadOnlyMemory()], BaseMemoryPool.Shared);

        return EvidenceRecord.Create(
            evidenceRecord.DigestAlgorithms, cryptoInfos: null, [rewrittenChain.AsReadOnlyMemory()], BaseMemoryPool.Shared);
    }
}
