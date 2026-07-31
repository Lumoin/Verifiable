using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Microsoft;
using Verifiable.Tests.X509;
using PkiAlgorithmIdentifier = Verifiable.Cryptography.Pki.AlgorithmIdentifier;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Everything one run of <see cref="EArkCapstoneSource.MintAsync"/> is given: who signs the preservation
/// container, what validation material its long-term form carries, and how the Time-Stamping Authority is
/// reached.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> The caller owns every certificate carrier and the signing node and disposes them;
/// the mint reads them and keeps nothing. Nothing reaches the shipped surfaces through a closure — the transport
/// is a delegate the caller states and the signer is a configured object.
/// </remarks>
internal sealed record EArkCapstoneMintContext
{
    /// <summary>The leaf whose private key signs the container's <c>ASiCManifest</c>. Owned by the caller.</summary>
    public required X509ChainTestRingNode Signer { get; init; }

    /// <summary>The signer's certificate as a carrier, which the container embeds. Owned by the caller.</summary>
    public required PkiCertificateMemory SignerCertificate { get; init; }

    /// <summary>
    /// The material the B-LT augmentation places inside the container's own signature — the issuing authority's
    /// certificate and whatever revocation evidence the caller decided the signer's status with.
    /// </summary>
    public required CAdESValidationMaterial ValidationMaterial { get; init; }

    /// <summary>The Time-Stamping Authority address, in whatever form the transport delegate understands.</summary>
    public required string TsaUri { get; init; }

    /// <summary>The transport every time-stamp of the mint is acquired over.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchTimestampResponse { get; init; }

    /// <summary>The claimed signing time the container's signature states.</summary>
    public required DateTimeOffset SigningTime { get; init; }

    /// <summary>The instant every archive entry the mint writes records, stated rather than read from a clock.</summary>
    public required DateTimeOffset PackageInstant { get; init; }

    /// <summary>The instant the package's own documents are stamped with.</summary>
    public required DateTimeOffset MetadataInstant { get; init; }

    /// <summary>The <c>genTime</c> the authority the transport reaches states in every token of this mint.</summary>
    public required DateTimeOffset TimestampGenerationTime { get; init; }
}


/// <summary>
/// One minted Archival Information Package: the archive octets that are the only thing crossing a firewall, and
/// the public names and instants a receiving party would be told about the archive it received.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> An instance owns <see cref="Archive"/> and nothing else; every other member is a
/// name, an instant or a copy of public octets.
/// </remarks>
internal sealed record EArkCapstonePackage: IDisposable
{
    /// <summary>The package as one archive that unpacks to a single root folder. Owned by this instance.</summary>
    public required PooledMemory Archive { get; init; }

    /// <summary>The name of the root folder the archive unpacks to, which is also the package identifier.</summary>
    public required string RootFolderName { get; init; }

    /// <summary>The entry name the package's own manifest sits under.</summary>
    public required string ManifestEntryName { get; init; }

    /// <summary>The entry name the package's digital-provenance document sits under.</summary>
    public required string ProvenanceEntryName { get; init; }

    /// <summary>The entry name the preservation container sits under, by the placement convention.</summary>
    public required string ContainerEntryName { get; init; }

    /// <summary>The entry names of the content files the package preserves.</summary>
    public required IReadOnlyList<string> ContentEntryNames { get; init; }

    /// <summary>The container-internal entry name of the detached signature the container's Evidence Record also proves.</summary>
    public required string ContainerSignatureEntryName { get; init; }

    /// <summary>The container-internal entry name of the Evidence Record.</summary>
    public required string ContainerEvidenceRecordEntryName { get; init; }

    /// <summary>The instant the Evidence Record's initial archive time-stamp asserts.</summary>
    public required DateTimeOffset EvidenceRecordArchiveTime { get; init; }

    /// <summary>The claimed signing time the container's signature states.</summary>
    public required DateTimeOffset SigningTime { get; init; }


    /// <summary>Copies the archive octets out, which is what crosses a firewall.</summary>
    /// <returns>A fresh array holding the archive.</returns>
    public byte[] ArchiveBytes() => Archive.AsReadOnlySpan().ToArray();


    /// <summary>Disposes the archive carrier.</summary>
    public void Dispose() => Archive.Dispose();
}


/// <summary>
/// Mints the Archival Information Package the eArchiving capstone and the preservation-service wire flow are both
/// written over: a package conformant to
/// <see href="https://earkcsip.dilcis.eu/">E-ARK CSIP v2.2.0</see> and
/// <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0</see>, carrying its content, its digital-provenance
/// document, and one preservation container of the "ASiC with Evidence Records" profile of Annex A.3.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> placed by this library's own evidence-placement convention.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Everything is minted through the shipped surfaces.</strong> The container is an ASiC-E container of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> carrying a detached CAdES signature raised to B-LT and an Evidence Record of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see>; every digest goes through the
/// registered digest seam; the manifest and the preservation-metadata document are written through the worked
/// bindings staged beside their seams. Nothing here computes a hash, a signature or a time-stamp of its own.
/// </para>
/// <para>
/// <strong>The order of operations is forced, and the reason is a fixed point.</strong> The package's manifest
/// states a digest over the preservation container, so the manifest cannot exist before the container does; and
/// the container's Evidence Record proves the octets of the digital-provenance document, so that document cannot
/// state a digest over the container either. The order is therefore: content, then the provenance document
/// (which records the container by the identifiers the placement convention derives from its entry NAME, never
/// from its octets), then the container, then the manifest. What that order cannot reach — a manifest inside the
/// evidence whose digest the manifest itself states — is not an accident of this source but a property of the
/// two requirements together, and the capstone asserts it as one.
/// </para>
/// </remarks>
internal static class EArkCapstoneSource
{
    /// <summary>The package identifier, in a form a root folder can be named with (<c>CSIPSTR2</c>).</summary>
    internal static string PackageIdentifier { get; } = "uuid-6b9f2c14-3d80-4a51-9e7c-2f0a5d18c4b3";

    /// <summary>The entry name of the package's digital-provenance document.</summary>
    internal static string ProvenanceEntryName { get; } = "metadata/preservation/PREMIS.xml";

    /// <summary>The entry name of the package's descriptive metadata document.</summary>
    internal static string DescriptiveEntryName { get; } = "metadata/descriptive/EAD.xml";

    /// <summary>The entry name of the package's rights document.</summary>
    internal static string RightsEntryName { get; } = "metadata/other/rights.xml";

    /// <summary>The entry name of the package's documentation file.</summary>
    internal static string DocumentationEntryName { get; } = "documentation/manual.txt";

    /// <summary>The entry name of the package's schema file.</summary>
    internal static string SchemaEntryName { get; } = "schemas/mets.xsd";

    /// <summary>The entry name of the representation's own manifest, which the structural map points at.</summary>
    internal static string RepresentationManifestEntryName { get; } = "representations/rep1/METS.xml";

    /// <summary>The entry name of the representation's own metadata file.</summary>
    internal static string RepresentationMetadataEntryName { get; } = "representations/rep1/metadata/summary.txt";

    /// <summary>The entry name the preservation container sits under, by the placement convention (<c>CSIPSTR8</c>).</summary>
    internal static string ContainerEntryName { get; } = EArkEvidenceWellKnown.PackageEvidenceEntryName("preservation.asice");

    /// <summary>The entry names of the two content files the package preserves.</summary>
    internal static IReadOnlyList<string> ContentEntryNames { get; } =
        ["representations/rep1/data/record-1.bin", "representations/rep1/data/record-2.bin"];

    /// <summary>The label of the one representation the package carries.</summary>
    internal static string RepresentationLabel { get; } = "rep1";

    /// <summary>The self-description every artifact this source mints carries, per <c>OVR-6.5-09</c> items a) to c).</summary>
    internal static EArkEvidenceSelfDescription SelfDescription { get; } = new()
    {
        PreservationServiceIdentifier = "urn:example:preservation-service:capstone",
        EvidencePolicyIdentifier = "urn:example:preservation-evidence-policy:capstone",
        PreservationProfileIdentifier = "urn:example:preservation-profile:capstone",
    };

    /// <summary>The algorithm every fixity, hash tree and manifest digest of the mint states.</summary>
    internal static PkiDigestAlgorithm DigestAlgorithm { get; } = PkiDigestAlgorithm.Sha256;

    /// <summary>The first content file's octets.</summary>
    private static byte[] FirstRecord { get; } = [.. "the first archived record of the eArchiving capstone"u8];

    /// <summary>The second content file's octets.</summary>
    private static byte[] SecondRecord { get; } = [.. "the second archived record of the eArchiving capstone"u8];

    /// <summary>The descriptive metadata document's octets.</summary>
    private static byte[] DescriptiveContent { get; } = [.. "<ead><archdesc/></ead>"u8];

    /// <summary>The rights document's octets.</summary>
    private static byte[] RightsContent { get; } = [.. "<rights statement=\"copyrighted\"/>"u8];

    /// <summary>The documentation file's octets.</summary>
    private static byte[] DocumentationContent { get; } = [.. "how this archival package was produced"u8];

    /// <summary>The schema file's octets.</summary>
    private static byte[] SchemaContent { get; } = [.. "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"/>"u8];

    /// <summary>The representation manifest's octets, which the package's structural map points at rather than digests.</summary>
    private static byte[] RepresentationManifestContent { get; } = [.. "<mets/>"u8];

    /// <summary>The representation metadata file's octets.</summary>
    private static byte[] RepresentationMetadataContent { get; } = [.. "about this representation"u8];


    /// <summary>
    /// Mints the whole package, through the shipped surfaces, in the order the fixed point above forces.
    /// </summary>
    /// <param name="context">Who signs, what validation material rides inside, and how the authority is reached.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The package. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the archive carrier transfers to the returned package, which the caller disposes; every intermediate carrier is released by a using declaration or by the explicit dispose the placement's unused half documents.")]
    internal static async ValueTask<EArkCapstonePackage> MintAsync(
        EArkCapstoneMintContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        //=== The digital-provenance document. It records the preservation container by the identifiers the
        //placement convention derives from the container's ENTRY NAME, so the document does not depend on a
        //single octet of the container — which is exactly what lets the container's Evidence Record prove it. ===
        using PremisDocument provenance = BuildProvenance(context.MetadataInstant);
        using PremisEncodeResult encodedProvenance = await PremisXmlBinding.EncodeAsync(
            new PremisEncodeContext { Document = provenance }, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
        if(!encodedProvenance.IsEncoded)
        {
            throw new InvalidOperationException($"The provenance document has to be writable ({encodedProvenance.Status}).");
        }

        byte[] provenanceOctets = encodedProvenance.Document!.AsReadOnlySpan().ToArray();

        //=== The preservation container: an ASiC-E container carrying the content and the provenance document,
        //signed detached, raised to B-LT, and given an Evidence Record covering all three plus the signature. ===
        byte[] containerOctets = await MintContainerAsync(context, provenanceOctets, cancellationToken).ConfigureAwait(false);
        (string signatureEntryName, string evidenceRecordEntryName) = StateContainerEntryNames(containerOctets);

        //=== The manifest, written last because it states a digest over the container. ===
        List<EArkPackageEntrySource> entries = StateEntries(provenanceOctets, containerOctets);
        using EArkPackageSnapshotResult beforeManifest = EArkPackageSnapshotReading.Create(
            entries, EArkPackageLimits.Conformant, BaseMemoryPool.Shared, PackageIdentifier);
        if(beforeManifest.Snapshot is null)
        {
            throw new InvalidOperationException($"The package's own entries have to read as a snapshot ({beforeManifest.Status}).");
        }

        EArkPackageEntry containerEntry = beforeManifest.Snapshot.FindEntry(ContainerEntryName)
            ?? throw new InvalidOperationException($"The package carries no entry named '{ContainerEntryName}'.");

        EArkEvidencePlacementResult placement = await EArkEvidencePlacement.StatePlacementAsync(
            new EArkEvidencePlacementContext
            {
                Artifact = new EArkEvidenceArtifactFacts { Kind = EArkEvidenceKind.Container, EntryName = ContainerEntryName },
                Entry = containerEntry,
                Instant = context.MetadataInstant,
                DigestAlgorithm = DigestAlgorithm,
                AttestedObjectIdentifiers = [ContentObjectIdentifier],
                AgentIdentifiers = [AgentIdentifier],
            },
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        //The placement's preservation-metadata object states the container's own fixity and is deliberately not
        //used: a document stating that digest could not be inside what the container proves, which is the fixed
        //point this source's remarks name. Its file entry — which the manifest does state — is kept, so exactly
        //the half that is not used is released here.
        placement.Object.Dispose();

        using MetsDocument manifest = await BuildManifestAsync(
            placement.FileEntry, placement.FileGroupUse, provenanceOctets, containerOctets, context.MetadataInstant, cancellationToken).ConfigureAwait(false);

        using MetsEncodeResult encodedManifest = await MetsXmlBinding.EncodeAsync(
            new MetsEncodeContext { Document = manifest }, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
        if(!encodedManifest.IsEncoded)
        {
            throw new InvalidOperationException($"The package manifest has to be writable ({encodedManifest.Status}).");
        }

        entries.Add(new EArkPackageEntrySource
        {
            Name = EArkWellKnown.PackageManifestFileName,
            Content = encodedManifest.Document!.AsReadOnlySpan().ToArray()
        });

        return new EArkCapstonePackage
        {
            Archive = EArkPackageSource.WriteArchive(entries, PackageIdentifier, context.PackageInstant, BaseMemoryPool.Shared),
            RootFolderName = PackageIdentifier,
            ManifestEntryName = EArkWellKnown.PackageManifestFileName,
            ProvenanceEntryName = ProvenanceEntryName,
            ContainerEntryName = ContainerEntryName,
            ContentEntryNames = ContentEntryNames,
            ContainerSignatureEntryName = signatureEntryName,
            ContainerEvidenceRecordEntryName = evidenceRecordEntryName,
            EvidenceRecordArchiveTime = context.TimestampGenerationTime,
            SigningTime = context.SigningTime,
        };
    }


    /// <summary>
    /// States the entries the package holds, in the order a producer writes them, with the manifest deliberately
    /// absent — it is appended once it has been written over these.
    /// </summary>
    /// <param name="provenanceOctets">The digital-provenance document as the package carries it.</param>
    /// <param name="containerOctets">The preservation container as the package carries it.</param>
    /// <returns>The entries, which the snapshot reader and the archive writer both copy.</returns>
    private static List<EArkPackageEntrySource> StateEntries(byte[] provenanceOctets, byte[] containerOctets) =>
    [
        new EArkPackageEntrySource { Name = ProvenanceEntryName, Content = provenanceOctets },
        new EArkPackageEntrySource { Name = DescriptiveEntryName, Content = DescriptiveContent },
        new EArkPackageEntrySource { Name = RightsEntryName, Content = RightsContent },
        new EArkPackageEntrySource { Name = ContainerEntryName, Content = containerOctets },
        new EArkPackageEntrySource { Name = SchemaEntryName, Content = SchemaContent },
        new EArkPackageEntrySource { Name = DocumentationEntryName, Content = DocumentationContent },
        new EArkPackageEntrySource { Name = RepresentationManifestEntryName, Content = RepresentationManifestContent },
        new EArkPackageEntrySource { Name = RepresentationMetadataEntryName, Content = RepresentationMetadataContent },
        new EArkPackageEntrySource { Name = ContentEntryNames[0], Content = FirstRecord },
        new EArkPackageEntrySource { Name = ContentEntryNames[1], Content = SecondRecord },
    ];


    /// <summary>
    /// Mints the preservation container: an extended Associated Signature Container carrying the content files and
    /// the provenance document, a detached CAdES signature raised to B-LT, and an Evidence Record proving all of
    /// them together with the signature, carrying the self-description as the attributes Annex H of
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
    /// ETSI TS 119 512 V1.2.1</see> defines.
    /// </summary>
    /// <param name="context">Who signs, what validation material rides inside, and how the authority is reached.</param>
    /// <param name="provenanceOctets">The provenance document the container is to prove.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The container's octets.</returns>
    /// <remarks>
    /// <para>
    /// <strong>The two protective objects have different scopes on purpose.</strong> The detached signature covers
    /// every data object the container carries — the content and the provenance document alike, through the
    /// <c>ASiCManifest</c>'s digests — while the Evidence Record's data object group is exactly the digital
    /// provenance. That is what makes the record an archival provenance anchor in the sense
    /// <see cref="EArkEvidenceAnchoring"/> defines: clause 4.2 of
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.2">IETF RFC 4998</see> makes a group's members
    /// "proved to have existed together", and a group holding anything else would prove a different statement and
    /// would fail the group check a verifier performs against the plan.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Every carrier this method rents is released by its using declaration before the octets are copied out; the attachment's two carriers are released by the using block that holds them.")]
    private static async ValueTask<byte[]> MintContainerAsync(
        EArkCapstoneMintContext context,
        byte[] provenanceOctets,
        CancellationToken cancellationToken)
    {
        using AsicContainerSignaturePreparation preparation = await AsicContainerCreation.PrepareSignatureAsync(
            new AsicContainerSignatureContext
            {
                Shape = AsicContainerShape.Extended,
                DataObjects =
                [
                    new AsicDataObject { Name = ContentEntryNames[0], Content = FirstRecord, MediaType = "application/octet-stream" },
                    new AsicDataObject { Name = ContentEntryNames[1], Content = SecondRecord, MediaType = "application/octet-stream" },
                    new AsicDataObject { Name = ProvenanceEntryName, Content = provenanceOctets, MediaType = "text/xml" }
                ],
                SignerCertificate = context.SignerCertificate,
                SigningTime = context.SigningTime,
                LastModified = context.PackageInstant,
                ManifestDigestAlgorithm = DigestAlgorithm,
                SignatureDigestAlgorithm = DigestAlgorithm,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync
            },
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        byte[] signatureValueP1363 = context.Signer.SigningKey.SignData(
            preparation.SignaturePreparation.SigningInput.AsReadOnlySpan().ToArray(), HashAlgorithmName.SHA256);
        using IMemoryOwner<byte> signatureValueDer = EcdsaSignatureEncoding.ConvertP1363ToDer(
            signatureValueP1363, BaseMemoryPool.Shared, out int derLength);
        using AsicContainerCreationResult created = AsicContainerCreation.CompleteSignature(
            preparation, context.SignerCertificate, CryptoAlgorithm.P256, signatureValueDer.Memory[..derLength],
            additionalCertificates: null, BaseMemoryPool.Shared);

        using AsicContainerAugmentationResult timestamped = await AsicContainerAugmentation.AddSignatureTimestampsAsync(
            new AsicContainerSignatureTimestampContext
            {
                Container = created.Container.AsReadOnlyMemory(),
                LastModified = context.PackageInstant,
                TsaUri = context.TsaUri,
                FetchTimestampResponse = context.FetchTimestampResponse,
                SigningCertificate = context.SignerCertificate
            },
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        using AsicContainerAugmentationResult longTerm = AsicContainerAugmentation.AddSignatureValidationData(
            new AsicContainerValidationDataContext
            {
                Container = timestamped.Container.AsReadOnlyMemory(),
                LastModified = context.PackageInstant,
                ValidationMaterial = context.ValidationMaterial
            },
            BaseMemoryPool.Shared);

        string signatureEntryName = created.SignatureEntryName!;
        AsicAttachedEvidenceRecord attachment = await AsicEvidenceRecordAttaching.AttachAsync(
            new AsicEvidenceRecordAttachmentContext
            {
                Container = longTerm.Container.AsReadOnlyMemory(),
                ProtectedEntryNames = [ProvenanceEntryName],
                LastModified = context.PackageInstant,
                TsaUri = context.TsaUri,
                FetchTimestampResponse = context.FetchTimestampResponse,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync,
                DigestAlgorithm = DigestAlgorithm
            },
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        using(attachment.Container)
        using(attachment.EvidenceRecord)
        {
            using EvidenceRecord described = CarrySelfDescription(attachment.EvidenceRecord);
            using PooledMemory rewritten = AsicEvidenceRecordAttaching.ReplaceEntry(
                attachment.Container.AsReadOnlyMemory(),
                attachment.EvidenceRecordEntryName,
                described.AsReadOnlyMemory(),
                context.PackageInstant,
                BaseMemoryPool.Shared);

            return rewritten.AsReadOnlySpan().ToArray();
        }
    }


    /// <summary>
    /// Rewrites a freshly created Evidence Record's one archive time-stamp with the three attributes Annex H
    /// defines, leaving its reduced hash tree and its token exactly as the creation surface wrote them.
    /// </summary>
    /// <param name="evidenceRecord">The record to rewrite, which the caller still owns.</param>
    /// <returns>The rewritten record. The caller owns and disposes it.</returns>
    /// <remarks>
    /// The <c>attributes [1]</c> field of an <c>ArchiveTimeStamp</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.1">IETF RFC 4998 clause 4.1</see>) is the
    /// carrier clause H.1 names and the one a Hash-Tree Renewal protects; the creation context has no member for
    /// it, so it is reached by re-encoding the stamp through the shipped encoder, which leaves the record
    /// verifiable.
    /// </remarks>
    private static EvidenceRecord CarrySelfDescription(EvidenceRecord evidenceRecord)
    {
        EvidenceRecordArchiveTimeStampSequence sequence = evidenceRecord.ArchiveTimeStampSequence;
        if(sequence.Chains.Count != 1 || sequence.Chains[0].ArchiveTimeStamps.Count != 1)
        {
            throw new InvalidOperationException(
                "A self-description is carried into a freshly created record, which holds one chain of one archive time-stamp.");
        }

        EvidenceRecordArchiveTimeStamp stamp = sequence.Chains[0].ArchiveTimeStamps[0];
        IReadOnlyList<CmsAttribute> attributes = PreservationEvidenceAttributes.ToAttributes(SelfDescription, BaseMemoryPool.Shared);
        try
        {
            using PooledMemory rewrittenStamp = EvidenceRecords.EncodeArchiveTimeStamp(
                stamp.DigestAlgorithm, attributes, stamp.ReducedHashtree, stamp.TimeStamp, BaseMemoryPool.Shared);
            using PooledMemory rewrittenChain = EvidenceRecords.EncodeArchiveTimeStampChain(
                [rewrittenStamp.AsReadOnlyMemory()], BaseMemoryPool.Shared);

            return EvidenceRecord.Create(
                evidenceRecord.DigestAlgorithms, cryptoInfos: null, [rewrittenChain.AsReadOnlyMemory()], BaseMemoryPool.Shared);
        }
        finally
        {
            for(int i = 0; i < attributes.Count; ++i)
            {
                attributes[i].Dispose();
            }
        }
    }


    /// <summary>
    /// Reads the two container-internal entry names the capstone reports: the detached signature and the
    /// Evidence Record.
    /// </summary>
    /// <param name="containerOctets">The finished container.</param>
    /// <returns>The signature's entry name and the Evidence Record's.</returns>
    private static (string SignatureEntryName, string EvidenceRecordEntryName) StateContainerEntryNames(byte[] containerOctets)
    {
        using AsicContainerReadResult read = AsicContainerReading.Read(
            containerOctets, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);
        if(!read.IsRead)
        {
            throw new InvalidOperationException($"The minted container has to read back ({read.Status}).");
        }

        AsicContainerFacts facts = read.Facts!;

        return (facts.Signatures[0].Name, facts.EvidenceRecords[0].Entry.Name);
    }


    /// <summary>The identifier of the preservation-metadata object standing for the package's preserved content.</summary>
    private static PremisIdentifier ContentObjectIdentifier { get; } =
        new(PremisWellKnown.LocalIdentifierType, "file-1");

    /// <summary>The identifier of the agent every event of the package names.</summary>
    private static PremisIdentifier AgentIdentifier { get; } =
        new(PremisWellKnown.LocalIdentifierType, "agent-1");


    /// <summary>
    /// Builds the digital-provenance document: the conformant preservation-metadata document of the rule tests,
    /// with the evidence-placement convention's own event and relationship added.
    /// </summary>
    /// <param name="instant">The instant the recorded events state.</param>
    /// <returns>The document. The caller owns and disposes it.</returns>
    /// <remarks>
    /// Both halves the placement rule reads — an event of one of the convention's types linking the artifact's
    /// object identifier, and a relationship of the convention's type naming it — are derived from the container's
    /// entry name alone, so this document is complete before a single octet of the container exists. That is what
    /// lets the container's Evidence Record prove this document rather than chase it.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The copy made with a record expression shares the carriers of the document it was copied from and exactly one of the two is returned and disposed; the source is never disposed separately.")]
    private static PremisDocument BuildProvenance(DateTimeOffset instant)
    {
        PremisIdentifier containerIdentifier = EArkEvidenceWellKnown.EvidenceObjectIdentifier(ContainerEntryName);
        var creation = new PremisEvent
        {
            Identifiers = [EArkEvidenceWellKnown.EvidenceEventIdentifier(ContainerEntryName, EArkEvidenceWellKnown.CreationEventType)],
            Type = EArkEvidenceWellKnown.CreationEventType,
            EventDateTime = instant.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
            Outcome = "success",
            LinkingAgentIdentifiers = [AgentIdentifier],
            LinkingObjectIdentifiers = [containerIdentifier, ContentObjectIdentifier],
        };

        PremisDocument document = EArkValidationSource.ConformantPreservationMetadata(additionalEvents: [creation]);
        PremisObject content = document.Objects[2];

        return document with
        {
            Objects =
            [
                document.Objects[0],
                document.Objects[1],
                content with
                {
                    Relationships =
                    [
                        .. content.Relationships,
                        new PremisRelationship
                        {
                            Type = EArkEvidenceWellKnown.EvidenceRelationshipType,
                            SubType = EArkEvidenceWellKnown.AttestedBySubType,
                            RelatedObjectIdentifiers = [containerIdentifier],
                            RelatedEventIdentifiers = [.. creation.Identifiers],
                        }
                    ],
                }
            ],
        };
    }


    /// <summary>
    /// Builds the package's own manifest, with every fixity computed over the octets the package really holds.
    /// </summary>
    /// <param name="evidenceFile">The file entry the placement convention states for the preservation container. Ownership transfers to the returned document.</param>
    /// <param name="evidenceFileGroupUse">The file group the container's entry belongs under.</param>
    /// <param name="provenanceOctets">The provenance document as the package carries it.</param>
    /// <param name="containerOctets">The preservation container as the package carries it.</param>
    /// <param name="instant">The instant the manifest states of itself and of what it names.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The manifest. The caller owns and disposes it.</returns>
    /// <remarks>
    /// Every checksum here goes through <see cref="CryptographicKeyEvents.ComputeDigestAsync"/> — the registered
    /// digest seam — so the package a validator recomputes agrees with the package a producer wrote, which is what
    /// makes the fixity rule a real assertion rather than a restatement of a placeholder.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every fixity carrier built here transfers to the returned MetsDocument, whose own Dispose releases them and which the caller disposes.")]
    private static async ValueTask<MetsDocument> BuildManifestAsync(
        MetsFile evidenceFile,
        string evidenceFileGroupUse,
        byte[] provenanceOctets,
        byte[] containerOctets,
        DateTimeOffset instant,
        CancellationToken cancellationToken)
    {
        string provenanceChecksum = await EArkEvidenceSource.ChecksumOfAsync(provenanceOctets, cancellationToken).ConfigureAwait(false);
        string descriptiveChecksum = await EArkEvidenceSource.ChecksumOfAsync(DescriptiveContent, cancellationToken).ConfigureAwait(false);
        string rightsChecksum = await EArkEvidenceSource.ChecksumOfAsync(RightsContent, cancellationToken).ConfigureAwait(false);
        string documentationChecksum = await EArkEvidenceSource.ChecksumOfAsync(DocumentationContent, cancellationToken).ConfigureAwait(false);
        string schemaChecksum = await EArkEvidenceSource.ChecksumOfAsync(SchemaContent, cancellationToken).ConfigureAwait(false);
        string firstChecksum = await EArkEvidenceSource.ChecksumOfAsync(FirstRecord, cancellationToken).ConfigureAwait(false);
        string secondChecksum = await EArkEvidenceSource.ChecksumOfAsync(SecondRecord, cancellationToken).ConfigureAwait(false);

        return new MetsDocument
        {
            ObjectIdentifier = PackageIdentifier,
            ContentCategory = "OTHER",
            OtherContentCategory = "records",
            ContentInformationType = "MIXED",
            Profile = MetsWellKnown.CsipProfileUri,
            Header = new MetsHeader
            {
                CreateDate = instant,
                LastModificationDate = instant,
                OaisPackageType = MetsWellKnown.ArchivalPackageType,
                Agents =
                [
                    new MetsAgent
                    {
                        Role = MetsWellKnown.CreatorAgentRole,
                        Type = MetsWellKnown.OtherAgentType,
                        OtherType = MetsWellKnown.SoftwareAgentOtherType,
                        Name = "the archival package writer of the eArchiving capstone",
                        Notes = [new MetsAgentNote(MetsWellKnown.SoftwareVersionNoteType, "1.0.0")],
                    }
                ],
            },
            DescriptiveMetadataSections =
            [
                new MetsDescriptiveMetadataSection
                {
                    Id = "dmd-1",
                    Created = instant,
                    Status = MetsWellKnown.CurrentStatus,
                    Reference = Reference(DescriptiveEntryName, MetsWellKnown.OtherMetadataType, null, descriptiveChecksum, DescriptiveContent.Length, instant),
                }
            ],
            AdministrativeMetadata = new MetsAdministrativeMetadata
            {
                DigitalProvenanceSections =
                [
                    new MetsAdministrativeMetadataSection
                    {
                        Id = "digiprov-1",
                        Status = MetsWellKnown.CurrentStatus,
                        Reference = Reference(ProvenanceEntryName, MetsWellKnown.PremisMetadataType, PremisWellKnown.PremisVersion, provenanceChecksum, provenanceOctets.Length, instant),
                    }
                ],
                RightsSections =
                [
                    new MetsAdministrativeMetadataSection
                    {
                        Id = "rights-1",
                        Status = MetsWellKnown.CurrentStatus,
                        Reference = Reference(RightsEntryName, MetsWellKnown.OtherMetadataType, null, rightsChecksum, RightsContent.Length, instant),
                    }
                ],
            },
            FileSection = new MetsFileSection
            {
                Id = "file-section-1",
                FileGroups =
                [
                    new MetsFileGroup
                    {
                        Id = "group-documentation",
                        Use = MetsWellKnown.DocumentationLabel,
                        Files = [FileEntry("file-documentation-1", DocumentationEntryName, documentationChecksum, DocumentationContent.Length, instant)],
                    },
                    new MetsFileGroup
                    {
                        Id = "group-schemas",
                        Use = MetsWellKnown.SchemasLabel,
                        Files = [FileEntry("file-schema-1", SchemaEntryName, schemaChecksum, SchemaContent.Length, instant)],
                    },
                    new MetsFileGroup
                    {
                        Id = "group-representations-rep1",
                        Use = MetsWellKnown.RepresentationsPrefix + RepresentationLabel,
                        ContentInformationType = MetsWellKnown.OtherContentInformationType,
                        OtherContentInformationType = "records",
                        Files =
                        [
                            FileEntry("file-data-1", ContentEntryNames[0], firstChecksum, FirstRecord.Length, instant),
                            FileEntry("file-data-2", ContentEntryNames[1], secondChecksum, SecondRecord.Length, instant)
                        ],
                    },
                    new MetsFileGroup
                    {
                        Id = "group-evidence",
                        Use = evidenceFileGroupUse,
                        Files = [evidenceFile],
                    }
                ],
            },
            StructuralMaps =
            [
                new MetsStructuralMap
                {
                    Id = "struct-map-1",
                    Type = MetsWellKnown.PhysicalStructuralMapType,
                    Label = MetsWellKnown.CsipStructuralMapLabel,
                    RootDivision = new MetsDivision
                    {
                        Id = "div-root",
                        Label = "the package",
                        Divisions =
                        [
                            new MetsDivision
                            {
                                Id = "div-metadata",
                                Label = MetsWellKnown.MetadataLabel,
                                AdministrativeMetadataIds = ["digiprov-1"],
                                DescriptiveMetadataIds = ["dmd-1"],
                            },
                            new MetsDivision
                            {
                                Id = "div-documentation",
                                Label = MetsWellKnown.DocumentationLabel,
                                FilePointers = [new MetsFilePointer("file-documentation-1")],
                            },
                            new MetsDivision
                            {
                                Id = "div-schemas",
                                Label = MetsWellKnown.SchemasLabel,
                                FilePointers = [new MetsFilePointer("file-schema-1")],
                            },
                            new MetsDivision
                            {
                                Id = "div-representations",
                                Label = MetsWellKnown.RepresentationsLabel,
                                FilePointers = [new MetsFilePointer("file-data-1"), new MetsFilePointer("file-data-2")],
                            },
                            new MetsDivision
                            {
                                Id = "div-rep1",
                                Label = MetsWellKnown.RepresentationsPrefix + RepresentationLabel,
                                MetsPointers =
                                [
                                    new MetsPointer(
                                        RepresentationManifestEntryName,
                                        MetsWellKnown.UrlLocatorType,
                                        MetsWellKnown.SimpleLinkType,
                                        RepresentationLabel)
                                ],
                            }
                        ],
                    },
                }
            ],
        };
    }


    /// <summary>Builds a metadata reference stating a fixity this library recomputes.</summary>
    /// <param name="href">The resource location the reference names.</param>
    /// <param name="metadataType">The metadata type the referenced document is written in.</param>
    /// <param name="metadataTypeVersion">The version of that type, or <see langword="null"/>.</param>
    /// <param name="checksum">The checksum the digest seam computed, as hexadecimal.</param>
    /// <param name="size">The referenced document's length in octets.</param>
    /// <param name="instant">The instant the reference states.</param>
    /// <returns>The reference. Ownership transfers to the document it is placed in.</returns>
    private static MetsMetadataReference Reference(
        string href,
        string metadataType,
        string? metadataTypeVersion,
        string checksum,
        int size,
        DateTimeOffset instant) =>
        new()
        {
            LocatorType = MetsWellKnown.UrlLocatorType,
            LinkType = MetsWellKnown.SimpleLinkType,
            Href = href,
            MetadataType = metadataType,
            MetadataTypeVersion = metadataTypeVersion,
            MediaType = "text/xml",
            Size = size,
            Created = instant,
            Fixity = EArkFixity.Read(MetsWellKnown.Sha256ChecksumType, checksum, BaseMemoryPool.Shared),
        };


    /// <summary>Builds a file entry stating a fixity this library recomputes.</summary>
    /// <param name="id">The file's identifier.</param>
    /// <param name="href">The resource location the file's locator names.</param>
    /// <param name="checksum">The checksum the digest seam computed, as hexadecimal.</param>
    /// <param name="size">The file's length in octets.</param>
    /// <param name="instant">The instant the entry states.</param>
    /// <returns>The file. Ownership transfers to the document it is placed in.</returns>
    private static MetsFile FileEntry(string id, string href, string checksum, int size, DateTimeOffset instant) =>
        new()
        {
            Id = id,
            MediaType = "application/octet-stream",
            Size = size,
            Created = instant,
            Fixity = EArkFixity.Read(MetsWellKnown.Sha256ChecksumType, checksum, BaseMemoryPool.Shared),
            Locator = new MetsFileLocator(MetsWellKnown.UrlLocatorType, MetsWellKnown.SimpleLinkType, href),
        };
}


/// <summary>
/// The verifying party of the eArchiving capstone: everything it holds was rebuilt from the package archive's
/// wire octets and the trust anchor's octets, and nothing else reaches it.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The firewall is what this class reads, not what the process holds.</strong> It is handed an archive
/// and a trust anchor and reconstructs the snapshot, the classified facts, the manifest, the provenance document,
/// the preservation container and the evidential facts from those octets alone — no model, key or carrier of the
/// minting side survives into it.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns every carrier it rented, released in reverse order.
/// </para>
/// </remarks>
internal sealed class ReconstructedEArkVerifyingParty: IDisposable
{
    /// <summary>The carriers this party rented, released in reverse order.</summary>
    private readonly List<IDisposable> owned = [];

    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>The package as a value snapshot, rebuilt from the archive's octets.</summary>
    public EArkPackageSnapshot Snapshot { get; private set; } = null!;

    /// <summary>What the package's layout states about itself.</summary>
    public EArkPackageFacts Facts { get; private set; } = null!;

    /// <summary>The package's own manifest, parsed from the octets the archive carried.</summary>
    public MetsDocument Manifest { get; private set; } = null!;

    /// <summary>The package's digital-provenance document, parsed from the octets the archive carried.</summary>
    public PremisDocument Provenance { get; private set; } = null!;

    /// <summary>The preservation container's octets, as the package carries them.</summary>
    public ReadOnlyMemory<byte> ContainerOctets { get; private set; }

    /// <summary>What the container states about itself.</summary>
    public AsicContainerFacts ContainerFacts { get; private set; } = null!;

    /// <summary>The container's parsed evidence-record manifests, as the profile evaluation takes them.</summary>
    public IReadOnlyList<PreservationContainerManifest> ContainerManifests { get; private set; } = [];

    /// <summary>The container's Evidence Record, read from the entry the container carries it in.</summary>
    public EvidenceRecord ContainerEvidenceRecord { get; private set; } = null!;

    /// <summary>What the party states about the one evidential artifact the package carries.</summary>
    public EArkEvidenceArtifactFacts Artifact { get; private set; } = null!;

    /// <summary>The trust anchor rebuilt from the received octets.</summary>
    public PkiCertificateMemory TrustAnchor { get; private set; } = null!;

    /// <summary>The instant this party validates at.</summary>
    public DateTimeOffset CurrentTime { get; private set; }

    /// <summary>The inputs the container layer states per embedded object.</summary>
    public SignatureValidationInputs Inputs { get; private set; } = null!;

    /// <summary>The seams the embedded objects' validation composes.</summary>
    public SignatureValidationSeams Seams { get; private set; } = null!;


    /// <summary>
    /// Reconstructs a verifying party from an archive and a trust anchor.
    /// </summary>
    /// <param name="archiveBytes">The package archive, exactly as it arrived.</param>
    /// <param name="trustAnchorCertificate">The trust anchor's own octets, which a Driving Application configures rather than receives.</param>
    /// <param name="containerEntryName">The entry name the preservation container is expected at.</param>
    /// <param name="provenanceEntryName">The entry name the digital-provenance document is expected at.</param>
    /// <param name="currentTime">The instant to validate at.</param>
    /// <param name="checkRevocation">
    /// The revocation seam, or <see langword="null"/> to decide revocation from the certificate revocation lists
    /// the received container's own signature embeds.
    /// </param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The party, which the caller disposes.</returns>
    public static async ValueTask<ReconstructedEArkVerifyingParty> CreateAsync(
        byte[] archiveBytes,
        byte[] trustAnchorCertificate,
        string containerEntryName,
        string provenanceEntryName,
        DateTimeOffset currentTime,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
        CancellationToken cancellationToken)
    {
        var party = new ReconstructedEArkVerifyingParty();
        try
        {
            await party.BuildAsync(
                archiveBytes, trustAnchorCertificate, containerEntryName, provenanceEntryName, currentTime, checkRevocation, cancellationToken).ConfigureAwait(false);

            return party;
        }
        catch
        {
            party.Dispose();

            throw;
        }
    }


    /// <summary>States the validation context one run of the package rule lists takes.</summary>
    /// <returns>The context.</returns>
    public EArkValidationContext ValidationContext() => new()
    {
        EntryNames = EntryNames(),
        CurrentTime = CurrentTime,
        PackageFacts = Facts,
        PackageManifest = Manifest,
        PreservationMetadata = [Provenance],
        EvidenceArtifacts = [Artifact],
        MemoryPool = BaseMemoryPool.Shared,
    };


    /// <summary>States the context one run of the container validation of clause 4.4.4.2 takes.</summary>
    /// <returns>The context.</returns>
    public AsicContainerValidationContext ContainerValidationContext() => new()
    {
        Container = ContainerOctets,
        CurrentTime = CurrentTime,
        ParseManifest = AsicManifestXmlBinding.ParseAsync,
        SignatureInputs = Inputs,
        SignatureSeams = Seams,
    };


    /// <summary>States the context one evaluation of the preservation object container profile takes.</summary>
    /// <returns>The context.</returns>
    public PreservationContainerProfileContext ProfileContext() => new()
    {
        Facts = ContainerFacts,
        Manifests = ContainerManifests,
    };


    /// <summary>States the context one provenance-anchor verification takes.</summary>
    /// <returns>The context.</returns>
    public EArkProvenanceAnchorContext AnchorContext() => new()
    {
        Snapshot = Snapshot,
        PackageManifest = Manifest,
    };


    /// <summary>States the snapshot's entry names, in the snapshot's own order.</summary>
    /// <returns>The names.</returns>
    public List<string> EntryNames()
    {
        var names = new List<string>(Snapshot.Entries.Count);
        for(int i = 0; i < Snapshot.Entries.Count; ++i)
        {
            names.Add(Snapshot.Entries[i].Name);
        }

        return names;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;
        for(int i = owned.Count - 1; i >= 0; --i)
        {
            owned[i].Dispose();
        }

        owned.Clear();
    }


    /// <summary>
    /// Rebuilds every model and carrier from the received archive.
    /// </summary>
    /// <param name="archiveBytes">The package archive.</param>
    /// <param name="trustAnchorCertificate">The trust anchor's octets.</param>
    /// <param name="containerEntryName">The entry name the preservation container is expected at.</param>
    /// <param name="provenanceEntryName">The entry name the digital-provenance document is expected at.</param>
    /// <param name="currentTime">The instant to validate at.</param>
    /// <param name="checkRevocation">The revocation seam, or <see langword="null"/> to use the container's own embedded lists.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    private async ValueTask BuildAsync(
        byte[] archiveBytes,
        byte[] trustAnchorCertificate,
        string containerEntryName,
        string provenanceEntryName,
        DateTimeOffset currentTime,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
        CancellationToken cancellationToken)
    {
        CurrentTime = currentTime;
        TrustAnchor = Own(ToCarrier(trustAnchorCertificate, PkiCertificateTags.X509Certificate));

        EArkPackageSnapshotResult read = Own(EArkPackageSnapshotReading.ReadArchive(
            archiveBytes, EArkPackageLimits.Conformant, BaseMemoryPool.Shared));
        if(read.Snapshot is null)
        {
            throw new InvalidOperationException($"The received archive has to read as an Information Package ({read.Status}).");
        }

        Snapshot = read.Snapshot;
        Facts = EArkPackageReading.StateFacts(Snapshot);

        Manifest = Own(await ParseManifestAsync(Snapshot, cancellationToken).ConfigureAwait(false));
        Provenance = Own(await ParseProvenanceAsync(Snapshot, provenanceEntryName, cancellationToken).ConfigureAwait(false));

        EArkPackageEntry containerEntry = Snapshot.FindEntry(containerEntryName)
            ?? throw new InvalidOperationException($"The received package carries no entry named '{containerEntryName}'.");
        ContainerOctets = containerEntry.Content.AsReadOnlyMemory();

        (AsicContainerReadResult containerRead, List<AsicManifestParseResult> manifests) =
            await PreservationProfileSource.ReadContainerAsync(ContainerOctets, cancellationToken).ConfigureAwait(false);

        _ = Own(containerRead);
        ContainerFacts = containerRead.Facts!;

        var containerManifests = new List<PreservationContainerManifest>(manifests.Count);
        int manifestIndex = 0;
        for(int i = 0; i < ContainerFacts.Manifests.Count; ++i)
        {
            if(ContainerFacts.Manifests[i].Role != AsicManifestRole.EvidenceRecord)
            {
                continue;
            }

            AsicManifestParseResult parsed = Own(manifests[manifestIndex++]);
            containerManifests.Add(new PreservationContainerManifest
            {
                EntryName = ContainerFacts.Manifests[i].Entry.Name,
                Manifest = parsed.Manifest!
            });
        }

        ContainerManifests = containerManifests;

        AsicEvidenceRecordFile recordFile = ContainerFacts.EvidenceRecords[0];
        ContainerEvidenceRecord = Own(EvidenceRecord.Read(recordFile.Entry.Content.AsReadOnlySpan(), BaseMemoryPool.Shared));

        IReadOnlyList<PkiCertificateMemory> revocationLists = checkRevocation is null
            ? await ReadEmbeddedRevocationListsAsync(cancellationToken).ConfigureAwait(false)
            : [];

        AssembleInputs(checkRevocation, revocationLists);
    }


    /// <summary>
    /// States the facts the package's evidence rules read about the one artifact it carries, from what the
    /// container proves and from what its Evidence Record says about itself.
    /// </summary>
    /// <param name="containerEntryName">The entry name the container sits under.</param>
    /// <param name="protectedEntryNames">The entry names the container's own validation reported as proved.</param>
    /// <remarks>
    /// The self-description is read from the record's archive-time-stamp attributes — the carrier clause H.1 of
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
    /// ETSI TS 119 512 V1.2.1</see> names — through the bridge that turns the standardised attributes into this
    /// library's own self-description record. Whether it is protected is computed rather than assumed: an
    /// attribute of a chain is inside what a LATER chain proves, so a record with one chain protects none of them.
    /// </remarks>
    public void StateArtifactFacts(string containerEntryName, IReadOnlyList<string> protectedEntryNames)
    {
        EArkEvidenceSelfDescription? selfDescription = PreservationEvidenceAttributes.ReadSelfDescription(ContainerEvidenceRecord);

        Artifact = new EArkEvidenceArtifactFacts
        {
            Kind = EArkEvidenceKind.Container,
            EntryName = containerEntryName,
            CoveredEntryNames = protectedEntryNames,
            SelfDescription = selfDescription,
            SelfDescriptionCarrier = selfDescription is null
                ? EArkEvidenceSelfDescriptionCarrier.NotEvaluated
                : EArkEvidenceSelfDescriptionCarrier.ArchiveTimeStampAttributes,
            SelfDescriptionIsProtected = ContainerEvidenceRecord.ArchiveTimeStampSequence.Chains.Count > 1,
        };
    }


    /// <summary>Parses the package's own manifest out of the snapshot.</summary>
    /// <param name="snapshot">The package as a value snapshot.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The manifest. The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parsed document transfers to the caller, which owns it; the parse result is disposed on every path that does not hand the document over.")]
    private static async ValueTask<MetsDocument> ParseManifestAsync(EArkPackageSnapshot snapshot, CancellationToken cancellationToken)
    {
        EArkPackageEntry entry = snapshot.FindEntry(EArkWellKnown.PackageManifestFileName)
            ?? throw new InvalidOperationException("The received package carries no manifest.");

        using PooledMemory document = PooledMemory.FromBytes(
            entry.Content.AsReadOnlySpan(), BaseMemoryPool.Shared, EArkTags.PackageEntry);
        MetsParseResult parsed = await MetsXmlBinding.ParseAsync(
            new MetsParseContext { Document = document }, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        if(!parsed.IsValid)
        {
            parsed.Dispose();

            throw new InvalidOperationException($"The received package's manifest has to parse ({parsed.Status}).");
        }

        return parsed.Document!;
    }


    /// <summary>Parses the package's digital-provenance document out of the snapshot.</summary>
    /// <param name="snapshot">The package as a value snapshot.</param>
    /// <param name="provenanceEntryName">The entry name the document sits under.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The document. The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parsed document transfers to the caller, which owns it; the parse result is disposed on every path that does not hand the document over.")]
    private static async ValueTask<PremisDocument> ParseProvenanceAsync(
        EArkPackageSnapshot snapshot,
        string provenanceEntryName,
        CancellationToken cancellationToken)
    {
        EArkPackageEntry entry = snapshot.FindEntry(provenanceEntryName)
            ?? throw new InvalidOperationException($"The received package carries no entry named '{provenanceEntryName}'.");

        using PooledMemory document = PooledMemory.FromBytes(
            entry.Content.AsReadOnlySpan(), BaseMemoryPool.Shared, EArkTags.PackageEntry);
        PremisParseResult parsed = await PremisXmlBinding.ParseAsync(
            new PremisParseContext { Document = document }, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        if(!parsed.IsValid)
        {
            parsed.Dispose();

            throw new InvalidOperationException($"The received package's provenance document has to parse ({parsed.Status}).");
        }

        return parsed.Document!;
    }


    /// <summary>
    /// Assembles this party's own constraints, the seams the container's embedded signature composes, and the
    /// inputs template the container layer states per object.
    /// </summary>
    /// <param name="checkRevocation">The revocation seam, or <see langword="null"/> to use the container's own embedded lists.</param>
    /// <param name="revocationLists">The certificate revocation lists read out of the container, empty when a seam was stated.</param>
    private void AssembleInputs(
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
        IReadOnlyList<PkiCertificateMemory> revocationLists)
    {
        var x509Constraints = new X509ValidationConstraints
        {
            TrustAnchors = [new TrustAnchorConstraint(TrustAnchor, SunsetDate: null)]
        };

        var cryptographicConstraints = new CryptographicConstraints
        {
            Entries =
            [
                new AlgorithmReliabilityEntry(
                    new PkiAlgorithmIdentifier(X509ChainTestRing.EcdsaWithSha256SignatureOid),
                    MinimumKeySizeBits: X509ChainTestRing.SigningKeySizeBits,
                    TrustedUntil: null),
                new AlgorithmReliabilityEntry(PkiAlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, TrustedUntil: null),
                new AlgorithmReliabilityEntry(PkiAlgorithmIdentifier.Sha512, MinimumKeySizeBits: null, TrustedUntil: null)
            ]
        };

        var constraints = new SignatureValidationConstraints
        {
            Identifier = SignatureValidationPolicyIdentifier.CallerSuppliedConstraints,
            X509 = x509Constraints,
            Cryptographic = cryptographicConstraints,
            SignatureElements = SignatureElementsConstraints.None
        };

        var completer = new CertificateChainCompleter([TrustAnchor]);

        Seams = new SignatureValidationSeams
        {
            Format = CAdESSignatureFacts.Seam,
            CompleteCertificateChain = completer.CompleteAsync,
            ValidateCertificateChain = MicrosoftX509Functions.ValidateChainAsync,
            CheckRevocation = checkRevocation ?? new CrlRevocationChecker(revocationLists).CheckAsync
        };

        Inputs = new SignatureValidationInputs
        {
            SignedDataObject = TrustAnchor,
            Constraints = constraints,
            TimestampConstraints = constraints,
            CertificateValidationData = [TrustAnchor]
        };
    }


    /// <summary>
    /// Reads the certificate revocation lists the container's own signature embeds, which is the only revocation
    /// material a party holding nothing but the archive has.
    /// </summary>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The lists as carriers this party owns.</returns>
    private async ValueTask<IReadOnlyList<PkiCertificateMemory>> ReadEmbeddedRevocationListsAsync(CancellationToken cancellationToken)
    {
        using CmsSignedData signedData = CmsSignedData.FromBytes(
            ContainerFacts.Signatures[0].Content.AsReadOnlySpan(), BaseMemoryPool.Shared);
        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = signedData },
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        var lists = new List<PkiCertificateMemory>(facts.EmbeddedCertificateRevocationLists.Count);
        for(int i = 0; i < facts.EmbeddedCertificateRevocationLists.Count; ++i)
        {
            lists.Add(Own(ToCarrier(facts.EmbeddedCertificateRevocationLists[i].AsReadOnlySpan().ToArray(), PkiCertificateTags.X509Crl)));
        }

        return lists;
    }


    /// <summary>Copies octets into a pooled carrier of the stated kind.</summary>
    /// <param name="derBytes">The octets to copy.</param>
    /// <param name="tag">The kind discriminator the carrier states.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToCarrier(byte[] derBytes, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>Takes ownership of one carrier.</summary>
    /// <typeparam name="T">The carrier's type.</typeparam>
    /// <param name="carrier">The carrier.</param>
    /// <returns>The same carrier.</returns>
    private T Own<T>(T carrier) where T: IDisposable
    {
        owned.Add(carrier);

        return carrier;
    }
}
