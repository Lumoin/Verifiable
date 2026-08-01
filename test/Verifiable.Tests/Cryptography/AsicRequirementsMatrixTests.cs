using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.Extensions.Time.Testing;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using BcCmsSignedData = Org.BouncyCastle.Cms.CmsSignedData;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The RFC 2119 requirements matrix for the two Associated Signature Container specifications this wave builds
/// against: every normative statement of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> (clause 4's container syntax, clause 5's baseline containers and Tables 1-5,
/// and Annex A's metadata specification) and of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916202/01.01.01_60/en_31916202v010101p.pdf">
/// ETSI EN 319 162-2 V1.1.1</see> (clause 4's three additional container profiles and its two informative
/// annexes), plus the wave-ratified ASiC-E-with-CAdES baseline table the first document does not state.
/// Mirrors the DynamicData-rows-as-spec-cells shape of <c>CAdESRequirementsMatrixTests</c>
/// (ETSI EN 319 122-1) and <c>SignatureValidationRequirementsMatrixTests</c> (ETSI EN 319 102-1).
/// </summary>
/// <remarks>
/// <para>
/// Every distinct normative statement of the two documents is one <see cref="RequirementMatrixRow"/>.
/// <see cref="RequirementMatrixTest"/> fails a row that is neither <see cref="RequirementCoverageStatus.Tested"/>
/// nor <see cref="RequirementCoverageStatus.OutOfScope"/> nor <see cref="RequirementCoverageStatus.KnownDefect"/>
/// — no silent gaps — and, for the first and last dispositions, additionally resolves the cited evidence through
/// reflection over the compiled test assembly: a row citing a class or method that does not exist, or that is
/// not itself a <c>[TestMethod]</c>, fails. A renamed or deleted evidence method is therefore caught here rather
/// than rotting into a stale citation.
/// </para>
/// <para>
/// <strong>The ASiC-E-with-CAdES baseline table is this wave's, not the specification's.</strong> Clause 5.1 of
/// EN 319 162-1 scopes its formal baseline container tables to ASiC-S with CAdES, ASiC-S with XAdES and ASiC-E
/// with XAdES; there is no table for the exact flavour this wave ships, and EN 319 162-2 clause 4.3.1's NOTE
/// states only that such implementations "can support the same levels". The <c>ratified-*</c> rows below are the
/// table this wave synthesised and holds itself to, each citing the Part 1 and Part 2 clauses it derives from.
/// </para>
/// <para>
/// <strong>Informative-annex rows are tagged.</strong> EN 319 162-2's Annex A (container-specification interop)
/// and Annex B (archival extraction using Evidence Records) use full RFC 2119 modal verbs while being labelled
/// informative; their rows carry the "informative annex — non-mandatory" tag in the evidence text so that a
/// completeness check over the matrix cannot misread a deliberate scope line as a missed obligation.
/// </para>
/// <para>
/// Most rows cite a deep behavioural test that already drives the clause through the shipped container surface
/// (stages 4-9 of this wave; every cited test was read before being cited, not merely matched by name). Three
/// clauses had no covering test anywhere in the suite and are driven directly by new tests in this class:
/// <see cref="TheSimpleTimeAssertionContainerGainsTheAnnexA7ChainUnderTheSignedDataRoute"/> (clause 4.3.4
/// item 2 and EN 319 162-2 clause 4.2.1 items b) and d)),
/// <see cref="RaisingAContainerRaisesEveryCAdESObjectItCarries"/> (clause 4.3.4 item 1's "this shall apply to
/// all the signatures present in the containers") and
/// <see cref="ASignedFileObjectMayItselfBeAContainer"/> (clause 4.3.2 item 2), each of which calls the shipped
/// creation and augmentation surface itself rather than asserting the row's metadata.
/// </para>
/// </remarks>
[TestClass]
internal sealed class AsicRequirementsMatrixTests
{
    /// <summary>Whether a requirement row has been driven through a concrete test, is explicitly out of this wave's scope, or is implemented and unit-tested at the building-block level but not reachable through the shipped default composition because of an already-flagged, unfixed defect elsewhere in the pipeline.</summary>
    internal enum RequirementCoverageStatus
    {
        /// <summary>No disposition has been recorded. The value of an unset field, by design: a row must never silently pass as covered.</summary>
        Untested = 0,

        /// <summary>The requirement is driven by at least one concrete, named test that calls the shipped surface.</summary>
        Tested = 1,

        /// <summary>The requirement is explicitly out of this wave's scope, per the arc contract, the charter, or a stage's own recorded flag.</summary>
        OutOfScope = 2,

        /// <summary>The requirement's own building block implements and unit-tests it, but the shipped default composition cannot reach it because of an already-flagged, unfixed defect elsewhere in the pipeline.</summary>
        KnownDefect = 3
    }


    /// <summary>One row of the matrix: a clause identifier, a short digest of the requirement it names, its coverage disposition, and the evidence for that disposition.</summary>
    /// <param name="ClauseId">The clause and, where applicable, table/row/letter identifier the requirement comes from, prefixed <c>p1-</c> for EN 319 162-1, <c>p2-</c> for EN 319 162-2 and <c>ratified-</c> for the wave-ratified table.</param>
    /// <param name="Requirement">A short digest of the normative statement, close enough to the specification's own wording to be checked against it.</param>
    /// <param name="Status">The coverage disposition.</param>
    /// <param name="Evidence">For <see cref="RequirementCoverageStatus.Tested"/>/<see cref="RequirementCoverageStatus.KnownDefect"/>, the asserting test's <c>ClassName.MethodName</c> (optionally followed by explanatory prose in parentheses) — the leading token is resolved through reflection; for <see cref="RequirementCoverageStatus.OutOfScope"/>, the contract, charter or recorded-flag reason.</param>
    internal sealed record RequirementMatrixRow(string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence);


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The address the new behavioural tests' transport delegates are handed; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.asic-requirements-matrix.example.test/";

    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The <c>signing-time</c> every signed container of this class states.</summary>
    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    /// <summary>The instant every container entry of this class records.</summary>
    private static DateTimeOffset ContainerInstant { get; } = TestClock.CanonicalEpoch;

    /// <summary>The <c>genTime</c> every minted token of this class states.</summary>
    private static DateTimeOffset TimeAssertionInstant { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The certificate revocation list's <c>thisUpdate</c>.</summary>
    private static DateTimeOffset ThisUpdate { get; } = TestClock.CanonicalEpoch.AddMinutes(-5);

    /// <summary>The certificate revocation list's <c>nextUpdate</c>.</summary>
    private static DateTimeOffset NextUpdate { get; } = TestClock.CanonicalEpoch.AddDays(7);

    /// <summary>The data object every container of this class carries at its root.</summary>
    private static byte[] RootDataObject { get; } = [.. "the archived data object of the requirements matrix"u8];

    /// <summary>The file object the nested container of <see cref="ASignedFileObjectMayItselfBeAContainer"/> carries.</summary>
    private static byte[] NestedDataObject { get; } = [.. "the data object inside the signed container"u8];


    /// <summary>The requirements matrix, one row per <c>object[]</c>.</summary>
    /// <returns>Every row.</returns>
    public static IEnumerable<object[]> Requirements()
    {
        foreach((string clauseId, string requirement, RequirementCoverageStatus status, string evidence) in RowData)
        {
            yield return [new RequirementMatrixRow(clauseId, requirement, status, evidence)];
        }
    }


    /// <summary>
    /// No row of the matrix may be left without a coverage disposition, and a <see cref="RequirementCoverageStatus.Tested"/>
    /// or <see cref="RequirementCoverageStatus.KnownDefect"/> row's evidence must resolve to a real, existing
    /// <c>[TestMethod]</c> in the compiled test assembly.
    /// </summary>
    /// <param name="row">The row under test.</param>
    [TestMethod]
    [DynamicData(nameof(Requirements))]
    public void RequirementMatrixTest(RequirementMatrixRow row)
    {
        Assert.AreNotEqual(RequirementCoverageStatus.Untested, row.Status, $"{row.ClauseId}: '{row.Requirement}' has no coverage disposition.");
        Assert.IsFalse(string.IsNullOrWhiteSpace(row.Evidence), $"{row.ClauseId}: '{row.Requirement}' needs a named test or a stated reason.");

        if(row.Status is RequirementCoverageStatus.Tested or RequirementCoverageStatus.KnownDefect)
        {
            AssertEvidenceNamesAShippedTestMethod(row);
        }
    }


    /// <summary>
    /// Every clause identifier of the matrix is stated once. A duplicated identifier would let a row silently
    /// replace another one's disposition in a reader's eye while both still pass, which is the failure mode a
    /// hand-maintained table of this size has.
    /// </summary>
    [TestMethod]
    public void EveryClauseIdentifierIsStatedOnce()
    {
        List<string> duplicated = [.. RowData
            .GroupBy(row => row.ClauseId, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)];

        Assert.IsEmpty(duplicated, $"These clause identifiers appear more than once: {string.Join(", ", duplicated)}.");
    }


    /// <summary>
    /// An ASiC-S time assertion container gains the container-level long-term-availability chain of Annex A.7:
    /// clause 4.3.4 item 2 states that for such a container "one or more ASiCArchiveManifest files and one
    /// time-stamp token for each ASiCArchiveManifest file applied to its content shall be added to the container
    /// following the rules specified in clause A.7", and EN 319 162-2 clause 4.2.1 d) narrows Annex A.7 item 1 b)
    /// for that profile to "only <c>SignedData</c> shall be used to include certificate and revocation
    /// information".
    /// </summary>
    /// <remarks>
    /// The complementary negative — the same profile refusing the <c>certificate-values</c>/<c>revocation-values</c>
    /// route — is <see cref="AsicContainerAugmentationTests.TheSimpleTimeAssertionProfileRefusesTheCertificateValuesRoute"/>;
    /// this test is the positive half, which nothing else in the suite drove: every other Annex A.7 test runs
    /// against an ASiC-E container. The container is taken apart by the independent raw-ZIP oracle, its manifest
    /// read by an independent XML reader, its digests recomputed independently and its token validated by the
    /// independent Time-Stamp Protocol validator.
    /// </remarks>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task TheSimpleTimeAssertionContainerGainsTheAnnexA7ChainUnderTheSignedDataRoute()
    {
        using var world = MatrixWorld.Create();
        using AsicContainerCreationResult created = await AsicContainerCreation.CreateTimeAssertionAsync(
            new AsicContainerTimeAssertionContext
            {
                Shape = AsicContainerShape.Simple,
                DataObjects = [new AsicDataObject { Name = "data.txt", Content = RootDataObject }],
                LastModified = ContainerInstant,
                TsaUri = TsaUri,
                FetchTimestampResponse = world.Responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        byte[] before = created.Container.AsReadOnlySpan().ToArray();

        //A certificate revocation list rather than a certificate: the minted token already embeds the whole
        //ring, and requirement e) of EN 319 122-1 Table 1 ("duplication of certificate values should be
        //avoided") is implemented one layer down, so placing a certificate the token already carries changes
        //nothing and the assertion below would pass vacuously.
        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(world.Root, ThisUpdate, NextUpdate, []);

        using AsicContainerAugmentationResult archived = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            new AsicContainerArchiveTimestampContext
            {
                Container = before,
                LastModified = ContainerInstant,
                TsaUri = TsaUri,
                FetchTimestampResponse = world.Responder.FetchAsync,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync,
                ParseManifest = AsicManifestXmlBinding.ParseAsync,
                ValidationMaterial = new CAdESValidationMaterial { CertificateRevocationLists = [revocationList] },
                Placement = AsicValidationMaterialPlacement.SignedDataFields
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicManifestNaming.FixedArchiveManifestEntryName, archived.ArchiveManifestEntryName,
            "Annex A.7 item 1 c a): the ASiCArchiveManifest file shall be named \"ASiCArchiveManifest.xml\".");
        Assert.AreEqual(1, archived.ArchiveManifestChainLength);
        Assert.IsTrue(AsicManifestNaming.IsTimestampEntryName(archived.ArchiveTimestampEntryName),
            "Annex A.7 item 1 c c): the token applied to the manifest is named \"META-INF/*timestamp*.tst\".");
        Assert.AreNotEqual(AsicManifestNaming.SimpleTimestampEntryName, archived.ArchiveTimestampEntryName,
            "The new token avoids the name the time assertion already occupies (Annex A.7 item 1 c c)'s collision rule).");

        byte[] after = archived.Container.AsReadOnlySpan().ToArray();
        Dictionary<string, byte[]> payloadsBefore = EntryPayloads(before);
        Dictionary<string, byte[]> payloadsAfter = EntryPayloads(after);

        Assert.AreSequenceEqual(payloadsBefore["data.txt"], payloadsAfter["data.txt"],
            "The data file is carried forward octet for octet.");
        Assert.IsFalse(
            payloadsBefore[AsicManifestNaming.SimpleTimestampEntryName].AsSpan().SequenceEqual(payloadsAfter[AsicManifestNaming.SimpleTimestampEntryName]),
            "Annex A.7 item 1 a): the time assertion already present gains the revocation information required to validate it, through EN 319 162-2 clause 4.2.1 d)'s SignedData route.");

        List<(string EntryName, PkiDigestAlgorithm Algorithm, byte[] Digest, bool? RootFile)> references =
            ReadReferences(payloadsAfter[archived.ArchiveManifestEntryName!]);

        Assert.AreSequenceEqual(
            new[] { "data.txt", AsicManifestNaming.SimpleTimestampEntryName },
            references.Select(reference => reference.EntryName).ToArray(),
            "Annex A.7 item 1 c b): the data file and the time assertion requiring long term validation support are referenced.");

        foreach((string entryName, PkiDigestAlgorithm algorithm, byte[] digest, bool? rootFile) in references)
        {
            Assert.IsNull(rootFile, "A first addition points back at nothing, so no reference states Rootfile.");
            Assert.AreSequenceEqual(EvidenceRecordOracle.Hash(payloadsAfter[entryName], algorithm), digest,
                $"The digest stated for '{entryName}' must be the digest of that entry as the container now stores it.");
        }

        byte[] token = payloadsAfter[archived.ArchiveTimestampEntryName!];
        Assert.IsTrue(VerifiesUnderAnyEmbeddedCertificate(token), "The independent validator must accept the archive time-stamp token.");
        Assert.AreSequenceEqual(
            EvidenceRecordOracle.Hash(payloadsAfter[archived.ArchiveManifestEntryName!], PkiDigestAlgorithm.Sha256),
            ImprintOf(token),
            "Annex A.7 item 1 c c): the token is applied to the ASiCArchiveManifest file as it is stored.");
    }


    /// <summary>
    /// Raising a container applies to EVERY CAdES object it carries, which is what clause 4.3.4 item 1's second
    /// sentence states ("This shall apply to all the signatures present in the containers") and what clause 5.1
    /// item 2's lowest-level rule makes necessary: raising one of two signatures raises nothing about the
    /// container.
    /// </summary>
    /// <remarks>
    /// The container carries a second CAdES object under a second name the clause 4.3.3.2 item 4 b pattern also
    /// dispatches as a signature file — the construction
    /// <see cref="AsicContainerAugmentationTests.TheContainerLevelIsTheLowestLevelOfTheSignaturesItIncorporates"/>
    /// established, and the only multi-signature shape reachable while parallel <c>SignerInfo</c> creation is an
    /// owner flag. An ASiC-S container is used because clause 4.3.3.2 item 4 b makes every CAdES object of such a
    /// container detached over the single root data file, so both objects are raisable without a manifest naming
    /// each.
    /// </remarks>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task RaisingAContainerRaisesEveryCAdESObjectItCarries()
    {
        using var world = MatrixWorld.Create();
        using AsicContainerCreationResult created = await CreateSimpleCAdESAsync(world, RootDataObject, null).ConfigureAwait(false);

        const string SecondSignatureEntryName = "META-INF/signature2.p7s";
        byte[] singleSignature = ReadEntry(created.Container.AsReadOnlySpan().ToArray(), AsicManifestNaming.SimpleSignatureEntryName);
        using PooledMemory twoSignatures = AddEntry(created.Container.AsReadOnlyMemory(), SecondSignatureEntryName, singleSignature);

        byte[] before = twoSignatures.AsReadOnlySpan().ToArray();
        Assert.AreEqual(AsicContainerLevel.BaselineB, LevelOf(before), "Both objects start at B-B, so the container does.");

        using AsicContainerAugmentationResult raised = await AsicContainerAugmentation.AddSignatureTimestampsAsync(
            new AsicContainerSignatureTimestampContext
            {
                Container = before,
                LastModified = ContainerInstant,
                TsaUri = TsaUri,
                FetchTimestampResponse = world.Responder.FetchAsync,
                SigningCertificate = world.SignerCertificate
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        byte[] after = raised.Container.AsReadOnlySpan().ToArray();

        Assert.AreSequenceEqual(
            new[] { AsicManifestNaming.SimpleSignatureEntryName, SecondSignatureEntryName },
            raised.RaisedSignatureEntryNames.OrderBy(name => name, StringComparer.Ordinal).ToArray(),
            "Clause 4.3.4 item 1: the augmentation applies to all the signatures present in the container.");

        Dictionary<string, byte[]> payloadsBefore = EntryPayloads(before);
        Dictionary<string, byte[]> payloadsAfter = EntryPayloads(after);

        foreach(string entryName in new[] { AsicManifestNaming.SimpleSignatureEntryName, SecondSignatureEntryName })
        {
            Assert.IsFalse(payloadsBefore[entryName].AsSpan().SequenceEqual(payloadsAfter[entryName]),
                $"'{entryName}' was raised, so its octets differ.");
            Assert.IsTrue(VerifiesDetached(payloadsAfter[entryName], payloadsAfter["data.txt"]),
                $"'{entryName}' still verifies detached over the data file it was created over.");
        }

        Assert.AreSequenceEqual(payloadsBefore["data.txt"], payloadsAfter["data.txt"], "The data file is untouched.");
        Assert.AreEqual(AsicContainerLevel.BaselineT, LevelOf(after),
            "Clause 5.1 item 2: the container reaches B-T only because the lowest of its signatures does.");
    }


    /// <summary>
    /// The signed file object of an ASiC-S container may itself be a container (clause 4.3.2 item 2, "for example
    /// ZIP, OCF, ODF or another ASiC"), and when it carries a media type of its own that media type becomes the
    /// outer container's own <c>mimetype</c> content (clause 4.3.3.1 item 1 b).
    /// </summary>
    /// <remarks>
    /// The inner container is written by <see cref="AsicZipAuthoring"/> and read back out of the outer container
    /// by the independent raw-ZIP oracle, so what is asserted is that the outer container carries the inner
    /// archive's octets unchanged — a nested archive that had been recompressed would still be a valid ZIP while
    /// no longer being the object the signature covers.
    /// </remarks>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ASignedFileObjectMayItselfBeAContainer()
    {
        using var world = MatrixWorld.Create();
        using PooledMemory inner = AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                MediaType = AsicWellKnown.AsicExtendedMediaType,
                Entries = [new AsicZipEntrySource { Name = "inner/payload.bin", Content = NestedDataObject }],
                LastModified = ContainerInstant
            },
            BaseMemoryPool.Shared);

        byte[] innerOctets = inner.AsReadOnlySpan().ToArray();
        using AsicContainerCreationResult outer = await CreateSimpleCAdESAsync(world, innerOctets, AsicWellKnown.AsicExtendedMediaType).ConfigureAwait(false);
        byte[] octets = outer.Container.AsReadOnlySpan().ToArray();

        Assert.AreEqual(AsicWellKnown.AsicSimpleExtension, outer.FileExtension,
            "Clause 4.3.3.1 item 2 a): the outer container is an ASiC-S container whatever its data object is.");
        Assert.AreEqual(AsicWellKnown.AsicExtendedMediaType, AsicZipStructureOracle.MediaTypeAtOffset38(octets),
            "Clause 4.3.3.1 item 1 b): the media type associated to the signed file object is the container's media type.");

        byte[] stored = ReadEntry(octets, "data.txt");
        Assert.AreSequenceEqual(innerOctets, stored, "The signed container's octets appear in the outer container unchanged.");

        using AsicZipReadResult read = AsicZipReading.Read(stored, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);
        Assert.IsTrue(read.IsRead, $"The signed file object is still a container after the outer container carried it ({read.Status}).");
        Assert.AreEqual(AsicWellKnown.AsicExtendedMediaType, read.Container!.MediaType);

        Assert.IsTrue(VerifiesDetached(ReadEntry(octets, AsicManifestNaming.SimpleSignatureEntryName), stored),
            "The CAdES object verifies detached over the nested container.");
    }


    /// <summary>
    /// Resolves the <c>ClassName.MethodName</c> token a row's evidence leads with against the compiled test
    /// assembly and asserts that it names a real <c>[TestMethod]</c>.
    /// </summary>
    /// <param name="row">The row whose evidence is being resolved.</param>
    private static void AssertEvidenceNamesAShippedTestMethod(RequirementMatrixRow row)
    {
        string token = row.Evidence.Split([' ', '('], 2, StringSplitOptions.RemoveEmptyEntries)[0];
        int separatorIndex = token.LastIndexOf('.');
        Assert.IsGreaterThan(0, separatorIndex, $"{row.ClauseId}: evidence '{row.Evidence}' must lead with a Class.Method pair.");

        string className = token[..separatorIndex];
        string methodName = token[(separatorIndex + 1)..];
        Type? evidenceType = typeof(AsicRequirementsMatrixTests).Assembly.GetTypes()
            .FirstOrDefault(candidate => string.Equals(candidate.Name, className, StringComparison.Ordinal));
        Assert.IsNotNull(evidenceType, $"{row.ClauseId}: evidence class '{className}' does not exist in the test assembly.");

        MethodInfo? evidenceMethod = evidenceType!.GetMethod(
            methodName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
        Assert.IsNotNull(evidenceMethod, $"{row.ClauseId}: evidence method '{className}.{methodName}' does not exist.");
        Assert.IsNotEmpty(evidenceMethod!.GetCustomAttributes(typeof(TestMethodAttribute), inherit: false),
            $"{row.ClauseId}: evidence '{className}.{methodName}' is not a [TestMethod] — the matrix must cite a real test.");
    }


    /// <summary>
    /// Builds an ASiC-S container carrying one CAdES object detached over a single root data file.
    /// </summary>
    /// <param name="world">The minted signer and Time-Stamping Authority.</param>
    /// <param name="content">The data object's octets.</param>
    /// <param name="mediaType">The data object's media type, or <see langword="null"/> to state none.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    private async Task<AsicContainerCreationResult> CreateSimpleCAdESAsync(MatrixWorld world, byte[] content, string? mediaType) =>
        await AsicContainerCreation.SignAsync(
            new AsicContainerSignatureContext
            {
                Shape = AsicContainerShape.Simple,
                DataObjects = [new AsicDataObject { Name = "data.txt", Content = content, MediaType = mediaType }],
                SignerCertificate = world.SignerCertificate,
                SigningTime = SigningTime,
                LastModified = ContainerInstant,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync
            },
            world.SignerPrivateKey,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// States a container's level through the shipped reading surface.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <returns>The level.</returns>
    private static AsicContainerLevel LevelOf(ReadOnlyMemory<byte> container) =>
        AsicContainerAugmentation.StateContainerLevel(container, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared).Level;


    /// <summary>
    /// Rewrites a container with one more entry in it, carrying every entry already present forward unchanged.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <param name="entryName">The name the added entry is stored under.</param>
    /// <param name="content">The added entry's octets.</param>
    /// <returns>The rewritten container. The caller disposes it.</returns>
    private static PooledMemory AddEntry(ReadOnlyMemory<byte> container, string entryName, byte[] content)
    {
        using AsicZipReadResult read = AsicZipReading.Read(container, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);
        Assert.IsTrue(read.IsRead, $"The container must read before an entry can be added to it ({read.Status}).");

        var entries = new List<AsicZipEntrySource>(read.Container!.Entries.Count + 1);
        foreach(AsicZipEntry entry in read.Container.Entries)
        {
            if(AsicWellKnown.IsMimetypeEntryName(entry.Name))
            {
                continue;
            }

            entries.Add(new AsicZipEntrySource
            {
                Name = entry.Name,
                Content = entry.Content.AsReadOnlySpan().ToArray(),
                CompressionMethod = entry.CompressionMethod,
                LastModified = entry.LastModified
            });
        }

        entries.Add(new AsicZipEntrySource { Name = entryName, Content = content, LastModified = ContainerInstant });

        return AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                MediaType = read.Container.MediaType,
                Entries = entries,
                LastModified = ContainerInstant,
                ArchiveComment = read.Container.ArchiveComment
            },
            BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Reads every entry's octets out of a container through the independent raw-ZIP oracle.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <returns>The payloads, keyed by entry name.</returns>
    private static Dictionary<string, byte[]> EntryPayloads(byte[] container)
    {
        OracleZipArchive archive = AsicZipStructureOracle.Parse(container);
        var payloads = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach(OracleZipEntry header in archive.LocalHeaders)
        {
            payloads.Add(header.Name, AsicZipStructureOracle.ReadEntryContent(container, header));
        }

        return payloads;
    }


    /// <summary>
    /// Reads one entry's octets out of a container through the independent raw-ZIP oracle.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <param name="name">The entry name.</param>
    /// <returns>The entry's octets.</returns>
    private static byte[] ReadEntry(byte[] container, string name)
    {
        OracleZipArchive archive = AsicZipStructureOracle.Parse(container);
        foreach(OracleZipEntry header in archive.LocalHeaders)
        {
            if(string.Equals(header.Name, name, StringComparison.Ordinal))
            {
                return AsicZipStructureOracle.ReadEntryContent(container, header);
            }
        }

        throw new InvalidOperationException($"The container carries no entry named '{name}'.");
    }


    /// <summary>
    /// Reads the <c>DataObjectReference</c> elements of a manifest document with an independent XML reader.
    /// </summary>
    /// <param name="manifest">The manifest document's octets, as the container stores them.</param>
    /// <returns>The references, in document order.</returns>
    private static List<(string EntryName, PkiDigestAlgorithm Algorithm, byte[] Digest, bool? RootFile)> ReadReferences(byte[] manifest)
    {
        XDocument document = XDocument.Parse(Encoding.UTF8.GetString(manifest));
        XNamespace asic = AsicManifestXmlBinding.AsicNamespace;
        XNamespace ds = XmlSignatureWellKnown.XmlSignatureNamespace;

        var references = new List<(string EntryName, PkiDigestAlgorithm Algorithm, byte[] Digest, bool? RootFile)>();
        foreach(XElement element in document.Root!.Elements(asic + "DataObjectReference"))
        {
            string algorithmUri = element.Element(ds + XmlSignatureWellKnown.DigestMethodElementName)!
                .Attribute(XmlSignatureWellKnown.AlgorithmAttributeName)!.Value;
            PkiDigestAlgorithm algorithm = XmlSignatureWellKnown.DigestAlgorithmFromUri(algorithmUri)
                ?? throw new InvalidOperationException($"'{algorithmUri}' does not name a digest algorithm this library computes.");

            references.Add((
                element.Attribute("URI")!.Value,
                algorithm,
                Convert.FromBase64String(element.Element(ds + XmlSignatureWellKnown.DigestValueElementName)!.Value),
                element.Attribute("Rootfile") is { } rootFile ? bool.Parse(rootFile.Value) : null));
        }

        return references;
    }


    /// <summary>
    /// Verifies a detached CMS signature over the supplied content with the independent BouncyCastle reader,
    /// which never sees the creation surface's objects.
    /// </summary>
    /// <param name="signature">The DER-encoded CMS <c>SignedData</c>.</param>
    /// <param name="content">The detached content the signature is claimed to cover.</param>
    /// <returns><see langword="true"/> when the independent reader verifies the signature over that content.</returns>
    private static bool VerifiesDetached(byte[] signature, byte[] content)
    {
        var signedData = new BcCmsSignedData(new CmsProcessableByteArray(content), signature);
        foreach(SignerInformation signer in signedData.GetSignerInfos().GetSigners())
        {
            foreach(BcX509Certificate candidate in signedData.GetCertificates().EnumerateMatches(signer.SignerID))
            {
                try
                {
                    if(signer.Verify(candidate))
                    {
                        return true;
                    }
                }
                catch(CmsException)
                {
                    //This embedded certificate is not the signer's; try the next one the object carries.
                }
            }
        }

        return false;
    }


    /// <summary>
    /// Checks a time-stamp token against the independent BouncyCastle Time-Stamp Protocol validator, trying each
    /// certificate the token itself embeds.
    /// </summary>
    /// <param name="token">The DER-encoded RFC 3161 <c>TimeStampToken</c>.</param>
    /// <returns><see langword="true"/> when the independent validator accepts the token.</returns>
    private static bool VerifiesUnderAnyEmbeddedCertificate(byte[] token)
    {
        var signedData = new BcCmsSignedData(token);
        var timeStampToken = new TimeStampToken(signedData);
        foreach(BcX509Certificate candidate in signedData.GetCertificates().EnumerateMatches(null))
        {
            try
            {
                timeStampToken.Validate(candidate);

                return true;
            }
            catch(TspException)
            {
                //This embedded certificate is not the authority's own; try the next.
            }
        }

        return false;
    }


    /// <summary>
    /// Reads the <c>messageImprint</c> a time-stamp token binds, through the independent BouncyCastle reader.
    /// </summary>
    /// <param name="token">The DER-encoded RFC 3161 <c>TimeStampToken</c>.</param>
    /// <returns>The imprint octets.</returns>
    private static byte[] ImprintOf(byte[] token) =>
        new TimeStampToken(new BcCmsSignedData(token)).TimeStampInfo.TstInfo.MessageImprint.GetHashedMessage();


    /// <summary>Copies DER octets into a pooled carrier tagged as an X.509 certificate.</summary>
    /// <param name="certificate">The DER-encoded certificate.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToCertificateCarrier(byte[] certificate)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(certificate.Length);
        certificate.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>
    /// The minted world the behavioural tests of this class run against: a root certification authority, a
    /// Time-Stamping Authority under it answering through a <see cref="MintingTimestampResponder"/>, and a signer
    /// whose key material comes from <see cref="BouncyCastleKeyMaterialCreator"/>.
    /// </summary>
    private sealed class MatrixWorld: IDisposable
    {
        /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
        private bool disposed;


        /// <summary>Initialises a new world.</summary>
        /// <param name="root">The root certification authority.</param>
        /// <param name="authority">The Time-Stamping Authority.</param>
        /// <param name="responder">The transport that mints tokens.</param>
        /// <param name="signerCertificate">The signer's certificate.</param>
        /// <param name="signerPrivateKey">The signer's private key.</param>
        private MatrixWorld(
            X509ChainTestRingNode root,
            X509ChainTestRingNode authority,
            MintingTimestampResponder responder,
            PkiCertificateMemory signerCertificate,
            PrivateKeyMemory signerPrivateKey)
        {
            Root = root;
            Authority = authority;
            Responder = responder;
            SignerCertificate = signerCertificate;
            SignerPrivateKey = signerPrivateKey;
        }


        /// <summary>Gets the root certification authority.</summary>
        public X509ChainTestRingNode Root { get; }

        /// <summary>Gets the Time-Stamping Authority whose key signs every minted token.</summary>
        public X509ChainTestRingNode Authority { get; }

        /// <summary>Gets the transport delegate's owner, which mints a genuine token over whatever imprint a request states.</summary>
        public MintingTimestampResponder Responder { get; }

        /// <summary>Gets the signer's certificate.</summary>
        public PkiCertificateMemory SignerCertificate { get; }

        /// <summary>Gets the signer's private key.</summary>
        public PrivateKeyMemory SignerPrivateKey { get; }


        /// <summary>
        /// Mints a world: the two-node ring, the responder, and a P-256 signer whose key material comes from
        /// <see cref="BouncyCastleKeyMaterialCreator"/> and whose self-signed certificate carries the same
        /// public point.
        /// </summary>
        /// <returns>The world. The caller disposes it.</returns>
        public static MatrixWorld Create()
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            var responder = new MintingTimestampResponder(authority, [authority, root], TimeAssertionInstant);

            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
            using(keys.PublicKey)
            {
                byte[] uncompressedPoint = EllipticCurveUtilities.NormalizeToUncompressed(keys.PublicKey.AsReadOnlySpan(), EllipticCurveTypes.P256);
                var ecParameters = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    D = keys.PrivateKey.AsReadOnlySpan().ToArray(),
                    Q = new ECPoint
                    {
                        X = EllipticCurveUtilities.SliceXCoordinate(uncompressedPoint).ToArray(),
                        Y = EllipticCurveUtilities.SliceYCoordinate(uncompressedPoint).ToArray()
                    }
                };

                using ECDsa platformKey = ECDsa.Create(ecParameters);
                using X509Certificate2 platformCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(platformKey, NotBefore, NotAfter);

                return new MatrixWorld(root, authority, responder, ToCertificateCarrier(platformCertificate.RawData), keys.PrivateKey);
            }
        }


        /// <summary>Disposes the minted certificates and key material.</summary>
        public void Dispose()
        {
            if(!disposed)
            {
                SignerPrivateKey.Dispose();
                SignerCertificate.Dispose();
                Authority.Dispose();
                Root.Dispose();
                disposed = true;
            }
        }
    }


    /// <summary>
    /// Every row of the matrix, as a plain data table. Kept as one literal so a reviewer can scan the whole ASiC
    /// requirement surface — and its disposition — in one place. Rows follow the two specifications' own
    /// structure: EN 319 162-1 clause 4 (general syntax, ASiC-S, ASiC-E), clause 5 (baseline containers and
    /// Tables 1-5), Annex A (metadata specification, A.1-A.7); EN 319 162-2 clause 4 (the three additional
    /// profiles) and its two informative annexes; and finally the wave-ratified ASiC-E-with-CAdES baseline table
    /// this wave synthesised because Part 1 clause 5 states none.
    /// </summary>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] RowData { get; } =
    [
        ("p1-4.2-1", "The container format shall comply with the ZIP specification.",
            RequirementCoverageStatus.Tested, "AsicZipAuthoringTests.TheCentralDirectoryRepeatsEveryLocalFileHeader (the independent raw-ZIP oracle walks the end record, the central directory and every local file header of what this library wrote)"),
        ("p1-4.2-2a", "ASiC containers shall not use the multiple volumes split feature.",
            RequirementCoverageStatus.Tested, "AsicZipReadingTests.ASplitArchiveIsRefused"),
        ("p1-4.2-2b", "File names and comments shall be encoded with ISO/IEC 10646 UNICODE UTF-8.",
            RequirementCoverageStatus.Tested, "AsicZipAuthoringTests.AnEntryNameStatesItsUtf8OctetLength (writing; AsicZipReadingTests.AnEntryNameThatIsNotUtf8IsRefused is the reading half)"),
        ("p1-4.2-2c", "Only no compression (0, stored) or the deflated format (8) should be used as the ZIP compression method.",
            RequirementCoverageStatus.Tested, "AsicZipAuthoringPropertyTests.EveryContainerWrittenReadsBackWithItsEntriesUnchanged (both admitted methods over generated mixes: Stored is the default an entry takes and Deflated is the stated departure; the closed set itself is AsicZipAuthoringTests.ACompressionMethodOutsideClause42Item2CIsRefused)"),
        ("p1-4.2-3", "At least one container type specified in clause 4.3 or 4.4 shall be supported.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.SimpleCAdESContainerIsTheArchiveAnnexA1Describes (ASiC-S; ASiC-E is ExtendedCAdESContainerIsTheShapeClause4442Describes)"),

        ("p1-4.3.2-1", "The ASiC-S container shall comply with clause 4.2 and with the file structure of clause 4.3.3.2.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.SimpleCAdESContainerIsTheArchiveAnnexA1Describes"),
        ("p1-4.3.2-2", "The signed file object may itself be a container, for example ZIP, OCF, ODF or another ASiC.",
            RequirementCoverageStatus.Tested, "AsicRequirementsMatrixTests.ASignedFileObjectMayItselfBeAContainer"),
        ("p1-4.3.2-3", "When signing a ZIP container, the per-file comment field may state each contained file's media type as \"mimetype=\" followed by it.",
            RequirementCoverageStatus.OutOfScope, "The comment this clause admits belongs to the FOREIGN archive being signed, not to the ASiC container: it is that archive's own metadata, written by whoever produced it. This library writes ASiC containers and exposes the \"mimetype=\" convention at the container level only (AsicWellKnown.MediaTypeComment/MediaTypeFromComment, clause 4.3.3.1 item 3); AsicZipEntrySource carries no per-entry comment. Stage-10 scope line."),

        ("p1-4.3.3.1-1a", "The mimetype file content shall be \"application/vnd.etsi.asic-s+zip\" when the signed file object has no media type of its own.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.SimpleContainerStatesTheMediaTypeClause4331Item1Selects"),
        ("p1-4.3.3.1-1b", "The mimetype file content shall be the media type associated to the signed file object in all other cases.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.SimpleContainerStatesTheMediaTypeClause4331Item1Selects (and AsicRequirementsMatrixTests.ASignedFileObjectMayItselfBeAContainer for a nested container's own media type)"),
        ("p1-4.3.3.1-2a", "The container file extension shall be \".asics\" unless item 2 b) or 2 c) applies.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.SimpleCAdESSignatureIsDetachedOverTheDataFile (the clause 4.3.3.1 BODY text governs the citation, not Table 2's reference column, which carries a published cross-reference swap)"),
        ("p1-4.3.3.1-2b", "The container file extension shall be \".scs\" on file systems limited to three-character extensions.",
            RequirementCoverageStatus.Tested, "AsicWellKnownTests.EachContainerExtensionIsRecognisedByItsOwnFamily (accepted on reading; creation states the primary form)"),
        ("p1-4.3.3.1-2c", "The container file extension shall be \".zip\" when the container is handled manually.",
            RequirementCoverageStatus.Tested, "AsicWellKnownTests.EachContainerExtensionIsRecognisedByItsOwnFamily (accepted on reading; creation states the primary form)"),
        ("p1-4.3.3.1-2c-forcing", "In the \".zip\" case, item 1 a)'s fixed ASiC-S media type shall apply to the mimetype file content.",
            RequirementCoverageStatus.OutOfScope, "Creation always states the primary extension (clause 4.3.3.1 item 2 a), so the manual-handling branch is never produced and the forcing rule has no creation-side effect; reading takes the media type from the mimetype entry itself rather than from the file extension, so the branch changes nothing there either. Stage-10 scope line."),
        ("p1-4.3.3.1-3", "The ZIP file comment field may contain \"mimetype=\" followed by the original media type of the signed file object.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.TheMediaTypeArchiveCommentIsWrittenOnlyWhenAskedFor (absent by default, written when the caller states the departure)"),

        ("p1-4.3.3.2-1-may", "An ASiC-S container may contain a mimetype file.",
            RequirementCoverageStatus.Tested, "AsicZipAuthoringTests.AContainerWithoutAMediaTypeCarriesNoMimetypeEntry (and AsicZipReadingTests.AContainerWithNoMimetypeEntryReadsAndStatesNoMediaType)"),
        ("p1-4.3.3.2-1-root", "The mimetype file shall be at the root level.",
            RequirementCoverageStatus.Tested, "AsicZipAuthoringTests.TheMimetypeEntryIsFirstStoredAndCarriesNoExtraField"),
        ("p1-4.3.3.2-1-encoding", "The mimetype file shall be encoded as specified in clause A.1.",
            RequirementCoverageStatus.Tested, "AsicZipAuthoringTests.TheMediaTypeIsReadableAtOffset38ByTheAnnexA1NoteAlgorithm"),
        ("p1-4.3.3.2-1-content", "The mimetype file content shall be the media type specified in clause 4.3.3.1 item 1.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.SimpleContainerStatesTheMediaTypeClause4331Item1Selects"),
        ("p1-4.3.3.2-2-one-data-file", "An ASiC-S container shall contain one data file at the root level.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.AContainerWithNoDataObjectIsRefused (and ASimpleContainerWithTwoDataObjectsIsRefused for the upper bound)"),
        ("p1-4.3.3.2-2-only-root-file", "That data file shall be the only file object at the container root level besides the optional mimetype file.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ASimpleDataObjectBelowTheContainerRootIsRefused (and SimpleCAdESContainerIsTheArchiveAnnexA1Describes for the produced entry set)"),
        ("p1-4.3.3.2-3", "An ASiC-S container shall contain one META-INF folder at the root level.",
            RequirementCoverageStatus.Tested, "AsicWellKnownTests.TheMetaInfFolderIsRecognisedAtTheContainerRoot (and AsicContainerCreationTests.SimpleCAdESContainerIsTheArchiveAnnexA1Describes, whose metadata file sits directly under it)"),
        ("p1-4.3.3.2-4", "The META-INF folder shall contain only one of the five named files.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.SimpleCAdESContainerIsTheArchiveAnnexA1Describes (the produced entry set is closed at exactly one metadata file)"),
        ("p1-4.3.3.2-4a", "\"timestamp.tst\" containing an RFC 3161 time-stamp token applying to the data file.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.SimpleTimeAssertionContainerCarriesATokenOverTheDataFile"),
        ("p1-4.3.3.2-4b", "\"signature.p7s\" containing a CAdES object applying to the data file.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.SimpleCAdESSignatureIsDetachedOverTheDataFile"),
        ("p1-4.3.3.2-4c", "\"signatures.xml\" containing XAdES signatures applying to the data file.",
            RequirementCoverageStatus.OutOfScope, "XAdES-flavoured containers are out of this wave per the arc charter (XAdES deliberately last; charter clause 7 question 3 open) and per the waveasic contract's Out list."),
        ("p1-4.3.3.2-4c-i", "Where the ds:Reference URI attribute is present it shall reference the data file, and clause A.6's rules shall apply.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only; out of this wave per the arc charter and the waveasic contract's Out list."),
        ("p1-4.3.3.2-4c-ii", "Canonicalization computed on descendants of a ds:Signature shall keep that element a child of asic:XAdESSignatures.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only; out of this wave per the arc charter and the waveasic contract's Out list."),
        ("p1-4.3.3.2-4c-iii", "Exclusive canonicalization may be used, in which case the result shall not include the ancestor's context.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only; out of this wave per the arc charter and the waveasic contract's Out list."),
        ("p1-4.3.3.2-4d", "\"evidencerecord.ers\" containing an RFC 4998 Evidence Record applying to the data file.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.SimpleEvidenceRecordContainerCarriesARecordProvingTheDataFile"),
        ("p1-4.3.3.2-4e", "\"evidencerecord.xml\" containing an RFC 6283 Evidence Record applying to the data file.",
            RequirementCoverageStatus.Tested, "AsicContainerValidationTests.AnXmlFormEvidenceRecordIsVerifiedThroughTheSuppliedSeams (the XML form is read and verified; library-level XMLERS creation ships as XmlEvidenceRecords.CreateInitialAsync — the container creation path still emits the RFC 4998 form only, and wiring an XML-form container branch is a separate consumer step)"),
        ("p1-4.3.3.2-5a", "The META-INF folder may additionally contain one or more ASiCArchiveManifest files and the time-stamp tokens that apply to them.",
            RequirementCoverageStatus.Tested, "AsicRequirementsMatrixTests.TheSimpleTimeAssertionContainerGainsTheAnnexA7ChainUnderTheSignedDataRoute"),
        ("p1-4.3.3.2-5b", "The META-INF folder may additionally contain revocation status information or certificates referenced by extended signatures.",
            RequirementCoverageStatus.OutOfScope, "This library places validation material inside the protected object, which is the route Annex A.7 item 1 b) names and EN 319 122-1 clause 5.5.3 decides between; free-standing certificate or revocation files in META-INF are neither produced nor consumed this wave. Stage-10 scope line."),
        ("p1-4.3.3.2-5c", "The META-INF folder may additionally contain other application specific information.",
            RequirementCoverageStatus.OutOfScope, "Creation admits data objects and the metadata file it writes itself; a caller-supplied extra file object is not a creation input this wave states. Stage-10 scope line, and the same boundary as clause 4.4.3.2 item 5 d) below."),

        ("p1-4.3.4-intro", "Long term availability and integrity of ASiC-S shall be achieved for the different container types as the items below state.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.ASimpleContainerResolvesItsDetachedContentFromTheSingleDataFile"),
        ("p1-4.3.4-1", "For ASiC-S containers with CAdES (or XAdES) signatures, the attributes specified in the signature specifications shall be used for long term availability and integrity.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.ASimpleContainerResolvesItsDetachedContentFromTheSingleDataFile (the signature reaches B-LTA through the CAdES archive-time-stamp attribute)"),
        ("p1-4.3.4-1-all-signatures", "This shall apply to all the signatures present in the containers.",
            RequirementCoverageStatus.Tested, "AsicRequirementsMatrixTests.RaisingAContainerRaisesEveryCAdESObjectItCarries"),
        ("p1-4.3.4-2", "For ASiC-S containers with a time-stamp token, one or more ASiCArchiveManifest files and one time-stamp token for each of them shall be added following clause A.7.",
            RequirementCoverageStatus.Tested, "AsicRequirementsMatrixTests.TheSimpleTimeAssertionContainerGainsTheAnnexA7ChainUnderTheSignedDataRoute"),
        ("p1-4.3.4-3", "For ASiC-S containers with an Evidence Record, the internal mechanism of RFC 4998 and RFC 6283 shall be used.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.EveryPriorChainStillVerifiesAfterEachRenewal (the RFC 4998 renewal mechanism; XmlEvidenceRecordsTests.BothRenewalsInSuccessionStillProveTheDataObject is the RFC 6283 half)"),

        ("p1-4.4.2-1", "ASiC-E containers shall comply with clause 4.2 items 1) and 2) and with the file structure of clause 4.4.3.2 or 4.4.4.2.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESContainerIsTheShapeClause4442Describes"),
        ("p1-4.4.2-2", "One or more data files digitally signed or time asserted shall be present in any folder structure outside the root META-INF folder.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESContainerIsTheShapeClause4442Describes (a data object in a sub-folder; ADataObjectInsideMetaInfIsRefused is the negative)"),

        ("p1-4.4.3.1-1", "The file extension shall be \".asice\" or \".sce\".",
            RequirementCoverageStatus.OutOfScope, "XAdES-only clause; out of this wave per the arc charter. The structurally identical CAdES rule is clause 4.4.4.1 item 1 below."),
        ("p1-4.4.3.1-2", "The mimetype file content shall be \"application/vnd.etsi.asic-e+zip\" or the original media type of the container.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only clause; out of this wave per the arc charter. The CAdES flavour's own rule (clause 4.4.4.1 item 2) has no alternative branch and is covered below."),
        ("p1-4.4.3.1-3", "The ZIP file comment field may state \"mimetype=application/vnd.etsi.asic-e+zip\".",
            RequirementCoverageStatus.OutOfScope, "XAdES-only clause; out of this wave per the arc charter. The CAdES flavour's own permission is clause 4.4.4.1 item 3 below."),

        ("p1-4.4.3.2-intro", "Clause A.6 shall apply on referencing signed file objects.",
            RequirementCoverageStatus.OutOfScope, "Stated inside the XAdES container clause, which is out of this wave per the arc charter; Annex A.6's own rows below are Tested, and the CAdES flavour reaches them through clause 4.4.4.2."),
        ("p1-4.4.3.2-2", "One or more \"*signatures*.xml\" files shall be present under META-INF, each containing one or more XAdES signatures.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only; out of this wave per the arc charter and the waveasic contract's Out list."),
        ("p1-4.4.3.2-3", "Each \"*signatures*.xml\" file shall contain one of the five named root elements.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only; out of this wave per the arc charter and the waveasic contract's Out list."),
        ("p1-4.4.3.2-3-should-a", "Item 3 a)'s asic:XAdESSignatures root element should be used.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only; out of this wave per the arc charter and the waveasic contract's Out list."),
        ("p1-4.4.3.2-3-should-same", "The root elements in all the signature files of one container should be the same.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only; out of this wave per the arc charter and the waveasic contract's Out list."),
        ("p1-4.4.3.2-3-canonicalization", "Canonicalization on descendants of a ds:Signature shall keep it in place, and exclusive canonicalization may be used without the ancestor's context.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only; out of this wave per the arc charter and the waveasic contract's Out list."),
        ("p1-4.4.3.2-4-may", "One or more ASiCEvidenceRecordManifest files may be present.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedEvidenceRecordProvesTheManifestsTargetsAndNotTheManifest"),
        ("p1-4.4.3.2-4-element", "They shall contain one ASiCManifest element instance conformant to clause A.4.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.TheProducedManifestValidatesAgainstTheAuthenticSchema"),
        ("p1-4.4.3.2-4-sigreference", "The SigReference element shall reference a file containing an Evidence Record.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedEvidenceRecordProvesTheManifestsTargetsAndNotTheManifest"),
        ("p1-4.4.3.2-4-digestmethod", "The ds:DigestMethod element shall match the digest algorithm used to create the initial Archive Time-stamp protecting the first ReducedHashTree.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.TheEvidenceRecordManifestStatesTheAlgorithmTheRecordWasBuiltUnder"),
        ("p1-4.4.3.2-4a", "The Evidence Record file shall be present in the META-INF folder.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedEvidenceRecordProvesTheManifestsTargetsAndNotTheManifest"),
        ("p1-4.4.3.2-4b", "The Evidence Record shall apply to all the container files referenced by the ASiCManifest's DataObjectReference elements.",
            RequirementCoverageStatus.Tested, "AsicContainerValidationTests.AnEvidenceRecordProvesTheManifestTargetsAndNotTheManifestFile"),
        ("p1-4.4.3.2-4c", "The Evidence Record file shall be named \"evidencerecord.ers\" (ERS) or \"evidencerecord.xml\" (XMLERS).",
            RequirementCoverageStatus.Tested, "AsicManifestNamingTests.EachNonManifestFileKindIsRecognisedFromItsOwnPattern"),
        ("p1-4.4.3.2-5a", "\"container.xml\", if present, shall be as specified in OCF.",
            RequirementCoverageStatus.OutOfScope, "OCF/ODF/UCF interoperability is out of this wave per the waveasic contract's Out list."),
        ("p1-4.4.3.2-5b", "\"manifest.xml\", if present, shall be as specified in ODF.",
            RequirementCoverageStatus.OutOfScope, "OCF/ODF/UCF interoperability is out of this wave per the waveasic contract's Out list."),
        ("p1-4.4.3.2-5c", "\"META-INF/metadata.xml\", if present, shall be as specified in OCF.",
            RequirementCoverageStatus.OutOfScope, "OCF/ODF/UCF interoperability is out of this wave per the waveasic contract's Out list."),
        ("p1-4.4.3.2-5d-i", "Any other file object's name shall not contain \"signature\", \"timestamp\", \"manifest\" or \"container.xml\" (case insensitive).",
            RequirementCoverageStatus.OutOfScope, "The item governs \"any other file object\" — a file neither signed nor required to validate the container — and creation admits no such input this wave (stage-6 decision 9 records why the rule is deliberately NOT applied to data objects: a signed file named \"signature-policy.pdf\" is a container the specification admits)."),
        ("p1-4.4.3.2-5d-ii", "Any other file object shall not be required to validate the container.",
            RequirementCoverageStatus.OutOfScope, "Same boundary as item 5 d) i): creation admits no caller-supplied extra file object this wave, so nothing this library writes can be required to validate the container. Stage-6 decision 9."),

        ("p1-4.4.4.1-1", "The file extension shall be \".asice\", or \".sce\" on file systems limited to three-character extensions.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESContainerIsTheShapeClause4442Describes (the primary form; AsicWellKnownTests.EachContainerExtensionIsRecognisedByItsOwnFamily accepts both on reading)"),
        ("p1-4.4.4.1-2", "The mimetype file content shall be \"application/vnd.etsi.asic-e+zip\", with no alternative branch.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESContainerIsTheShapeClause4442Describes"),
        ("p1-4.4.4.1-3", "The ZIP file comment field may state \"mimetype=application/vnd.etsi.asic-e+zip\".",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.TheMediaTypeArchiveCommentIsWrittenOnlyWhenAskedFor (absent by default, written when the caller states the departure)"),

        ("p1-4.4.4.2-1-may", "A mimetype file may be present.",
            RequirementCoverageStatus.Tested, "AsicZipAuthoringTests.AContainerWithoutAMediaTypeCarriesNoMimetypeEntry"),
        ("p1-4.4.4.2-1-shall", "It shall be as defined in clause A.1 with the content specified in clause 4.4.4.1 item 2.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESContainerIsTheShapeClause4442Describes"),
        ("p1-4.4.4.2-2", "One or more ASiCManifest and/or ASiCEvidenceRecordManifest files shall be present.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESContainerIsTheShapeClause4442Describes"),
        ("p1-4.4.4.2-3", "For each ASiCManifest file one time-stamp token file or one signature file shall be present in the META-INF folder.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESContainerIsTheShapeClause4442Describes"),
        ("p1-4.4.4.2-3a", "\"*signature*.p7s\": a CAdES object with one or more detached CAdES signatures applied to the ASiCManifest file.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESSignatureIsDetachedOverTheManifestOctetsAsStored"),
        ("p1-4.4.4.2-3b", "\"*timestamp*.tst\": an RFC 3161 time-stamp token applied to the ASiCManifest file.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedTimeAssertionContainerCarriesATokenOverTheManifest"),
        ("p1-4.4.4.2-4", "For each ASiCEvidenceRecordManifest file one Evidence Record file shall be present in the META-INF folder.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedEvidenceRecordProvesTheManifestsTargetsAndNotTheManifest"),
        ("p1-4.4.4.2-4a", "\"*evidencerecord*.ers\": an RFC 4998 Evidence Record applying to the file objects the ASiCManifest names.",
            RequirementCoverageStatus.Tested, "AsicContainerValidationTests.AnEvidenceRecordProvesTheManifestTargetsAndNotTheManifestFile"),
        ("p1-4.4.4.2-4b", "\"*evidencerecord*.xml\": an RFC 6283 Evidence Record applying to the file objects the ASiCManifest names.",
            RequirementCoverageStatus.Tested, "AsicContainerValidationTests.AnXmlFormEvidenceRecordIsVerifiedThroughTheSuppliedSeams"),
        ("p1-4.4.4.2-validate-intro", "Validation applications shall, for each \"META-INF/ASiCManifest*.xml\" file, verify that its content conforms to clause A.4 and identify the file the SigReference URI points at.",
            RequirementCoverageStatus.Tested, "AsicContainerValidationTests.AnExtendedCAdESContainerValidatesWithEveryReferenceRecomputedAndTheSignatureTotalPassed (and AContainerWhoseManifestCannotBeReadIsRefusedRatherThanAssumedValid)"),
        ("p1-4.4.4.2-validate-a", "A \"*signature*.p7s\" target references a CAdES signature that shall be validated against the ASiCManifest file content.",
            RequirementCoverageStatus.Tested, "AsicContainerValidationTests.AnExtendedCAdESContainerValidatesWithEveryReferenceRecomputedAndTheSignatureTotalPassed (a container this library wrote); AsicContainerValidationTests.AContainerSignedWithRsaPssValidatesThroughTheRegisteredDetachedCmsBackend (the same obligation over a third-party container whose signature algorithm the fallback CMS backend does not implement — validated through the registered VerifyDetachedCmsSignedDataDelegate, which is what makes the obligation hold for material this library did not write); AsicContainerValidationTests.TheManagedBackendStillVerifiesTheDetachedObjectOfAnEllipticCurveContainer (the same obligation with nothing registered for that seam)"),
        ("p1-4.4.4.2-validate-b", "A \"*timestamp*.tst\" target references a time-stamp token that shall be validated against the ASiCManifest file content.",
            RequirementCoverageStatus.Tested, "AsicContainerValidationTests.TheArchiveManifestChainWalksBackwardThroughEveryRenewal (each link's token is validated against that link's manifest octets) and AsicContainerValidationTests.ATimeAssertionIsNotEvaluatedRatherThanValidWhenTheRunSuppliesNoSeams, which states what \"validated\" is: the message-imprint recomputation binds the token to the ASiCManifest file content and the time-stamp validation building block of EN 319 102-1 clause 5.4 validates the token itself. The imprint is necessary and not sufficient, so a run supplying no inputs or no seams reports the token — and the container — as NotEvaluated rather than Valid, which is also what ReferenceArtifactAsicContainerTests asserts for every third-party artifact of the corpus carrying a token."),
        ("p1-4.4.4.2-validate-c-conform", "Validation applications shall, for each \"META-INF/ASiCEvidenceRecordManifest*.xml\" file, verify that its content conforms to clause A.4 and identify the Evidence Record file the SigReference names.",
            RequirementCoverageStatus.Tested, "AsicContainerValidationTests.AnEvidenceRecordProvesTheManifestTargetsAndNotTheManifestFile"),
        ("p1-4.4.4.2-validate-c-validate", "They shall then validate the referenced Evidence Record against all the ds:DigestValue in the DataObjectReference elements the ASiCManifest carries.",
            RequirementCoverageStatus.Tested, "AsicContainerValidationTests.AnEvidenceRecordProvesTheManifestTargetsAndNotTheManifestFile (and AnXmlFormEvidenceRecordOverOtherOctetsProvesNothing for the negative)"),
        ("p1-4.4.4.2-validate-d", "Validation applications shall raise an error whenever a digest value mismatch is detected between a ds:DigestValue and the digest computed over the referenced file object.",
            RequirementCoverageStatus.Tested, "AsicContainerValidationTests.AChangedDataObjectOctetFailsTheContainerClosedWhateverTheSignatureSays"),
        ("p1-4.4.4.2-note2", "NOTE 2: where the SigReference references an Evidence Record, the ASiCManifest file itself is not covered by that Evidence Record.",
            RequirementCoverageStatus.Tested, "AsicContainerValidationTests.AnEvidenceRecordProvesTheManifestTargetsAndNotTheManifestFile"),

        ("p1-4.4.5-1", "For ASiC-E containers with XAdES signatures, the XAdES mechanisms or the Evidence Record specifications shall be used, for all the signatures present.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only; out of this wave per the arc charter and the waveasic contract's Out list."),
        ("p1-4.4.5-2a", "For ASiC-E with CAdES/time assertions: one or more ASiCArchiveManifest files and related time-stamp tokens shall be added following clause A.7.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.TheFirstArchiveManifestReferencesEveryFileObjectAndCarriesNoBackwardPointer"),
        ("p1-4.4.5-2b", "Or: one or more ASiCEvidenceRecordManifest files shall apply to all the data, signature and time-stamp token files requiring long term validation support.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedEvidenceRecordProvesTheManifestsTargetsAndNotTheManifest"),
        ("p1-4.4.5-3", "For ASiC-E containers with an Evidence Record, the internal mechanism of RFC 4998 and RFC 6283 shall be used.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.EveryPriorChainStillVerifiesAfterEachRenewal (RFC 4998; XmlEvidenceRecordsTests.BothRenewalsInSuccessionStillProveTheDataObject is the RFC 6283 half)"),

        ("p1-5.1-scope", "All ASiC baseline container levels are defined for ASiC-S with CAdES, ASiC-S with XAdES and ASiC-E with XAdES.",
            RequirementCoverageStatus.OutOfScope, "Descriptive scoping statement, and the one this wave had to answer: ASiC-E with CAdES is absent from the list, so Part 1 states no baseline requirements table for the flavour this wave ships. The ratified-* rows below are the table this wave synthesised and holds itself to (waveasic contract R-8/R-9.1, scout fact 1)."),
        ("p1-5.1-1", "ASiC baseline containers shall contain only CAdES baseline signatures per EN 319 122-1 clause 6 or XAdES baseline signatures per EN 319 132-1 clause 6.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.SimpleCAdESSignatureIsDetachedOverTheDataFile (every CAdES object this library writes comes from CAdESSignatureCreation, whose EN 319 122-1 clause 6 conformance is the CAdES requirements matrix's subject; XAdES is never written)"),
        ("p1-5.1-2", "The level of an ASiC baseline container shall be the lowest level of the incorporated baseline signatures.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.TheContainerLevelIsTheLowestLevelOfTheSignaturesItIncorporates"),

        ("p1-5.2.1-1", "The algorithms and key lengths used to generate and augment digital signatures should be as specified in ETSI TS 119 312.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.TheSuppliedConstraintsTableDecidesWhetherTheManifestDigestIsAllowed (the dated constraints table is consulted at the signing instant when supplied, and the same table in force lets a conformant creation proceed — the default and the departure in one test)"),
        ("p1-5.2.1-2", "MD5 shall not be used as a digest algorithm.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ADigestAlgorithmCreationRefusesStopsTheContainer (MD5 and SHA-1, the latter this library's own creation-side line)"),

        ("p1-5.3.1-table1-a", "The container shall be compliant with ISO/IEC 21320-1.",
            RequirementCoverageStatus.OutOfScope, "SOURCE GAP recorded at stage 0 of this wave and discharged at stage 4: ISO/IEC 21320-1's text is not obtainable non-interactively (the ISO publicly-available-standards URL returns a licence gate), so conformance to that document cannot be checked against it. The constraint set EN 319 162-1 clause 4.2, Annex A.1 and this table's own NOTE state — no encryption, no split archives, stored or deflate only, no ZIP64 — is implemented directly, each at a named check, and is covered by the clause 4.2 and Annex A.1 rows of this matrix. Owner flag 5 of the waveasic contract."),
        ("p1-5.3.1-table1-note", "NOTE: the additional ZIP requirement excludes encryption and allows either no compression or the deflated algorithm.",
            RequirementCoverageStatus.Tested, "AsicZipReadingTests.AnEncryptedEntryIsRefused (the exclusion; the compression half is the clause 4.2 item 2 c row above)"),

        ("p1-5.3.2.1-table2-extension", "ASiC file extension is \".asics\": shall be present, cardinality 1.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.SimpleCAdESSignatureIsDetachedOverTheDataFile (Table 2's References column carries a published cross-reference swap; the clause 4.3.3.1 body text governs, per the waveasic contract's normative-texts note)"),
        ("p1-5.3.2.1-table2-mimetype", "mimetype: may be present, cardinality 0 or 1.",
            RequirementCoverageStatus.Tested, "AsicZipAuthoringTests.AContainerWithoutAMediaTypeCarriesNoMimetypeEntry (the same Table 2 reference-column swap applies; the clause 4.3.3.1 body text governs)"),
        ("p1-5.3.2.1-table2-datafile", "Data file: shall be present, cardinality 1.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.AContainerWithNoDataObjectIsRefused"),

        ("p1-5.3.2.2-table3-signature", "META-INF/signature.p7s: shall be present, cardinality 1.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.SimpleCAdESContainerIsTheArchiveAnnexA1Describes"),
        ("p1-5.3.2.2-table3-a", "The CAdES signatures shall be as specified in CAdES clause 6 according to the required ASiC level.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.TheContainerLevelIsTheLowestLevelOfTheSignaturesItIncorporates (the level a container reaches is read from the CAdES attributes each object carries)"),
        ("p1-5.3.2.2-table3-b", "No other element shall be present in the container besides this element, the mimetype file and the data file.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.SimpleCAdESContainerIsTheArchiveAnnexA1Describes (the produced entry set is exactly those three)"),

        ("p1-5.3.2.3-table4-signatures-xml", "META-INF/signatures.xml: shall be present, cardinality 1.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only; out of this wave per the arc charter and the waveasic contract's Out list."),
        ("p1-5.3.2.3-table4-xadessignatures", "asic:XAdESSignatures: shall be present, cardinality 1.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only; out of this wave per the arc charter and the waveasic contract's Out list."),
        ("p1-5.3.2.3-table4-a", "Each XAdES signature child shall be as specified in XAdES clause 6.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only; out of this wave per the arc charter and the waveasic contract's Out list."),
        ("p1-5.3.2.3-table4-b", "Each XAdES signature child shall reference the signed file object explicitly with a ds:Reference child of ds:SignedInfo.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only; out of this wave per the arc charter and the waveasic contract's Out list."),
        ("p1-5.3.2.3-table4-c", "No other element shall be present in the container besides this element, the mimetype file and the signed data.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only; out of this wave per the arc charter and the waveasic contract's Out list."),

        ("p1-5.3.3-table5-extension", "ASiC file extension is \".asice\": shall be present, cardinality 1.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only table (the only ASiC-E baseline table Part 1 defines); out of this wave per the arc charter. The CAdES flavour's equivalent is ratified-extension below."),
        ("p1-5.3.3-table5-mimetype", "mimetype: may be present, cardinality 0 or 1.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only table; out of this wave per the arc charter. The CAdES flavour's equivalent is ratified-mimetype below."),
        ("p1-5.3.3-table5-signed-file-object", "Signed file object: shall be present, cardinality one or more.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only table; out of this wave per the arc charter. The CAdES flavour's equivalent is ratified-data-objects below."),
        ("p1-5.3.3-table5-signature-files", "signature files: shall be present, cardinality one or more.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only table; out of this wave per the arc charter. The CAdES flavour's equivalent is ratified-signature below."),
        ("p1-5.3.3-table5-xadessignatures", "asic:XAdESSignatures: shall be present, cardinality 1.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only table; out of this wave per the arc charter and the waveasic contract's Out list."),
        ("p1-5.3.3-table5-manifest-xml", "META-INF/manifest.xml: shall be present, cardinality 1.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only table, and an ODF-specific file; out of this wave per the arc charter and the waveasic contract's Out list."),
        ("p1-5.3.3-table5-a", "At least one signed file object shall be in the container outside the META-INF folder.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only table; out of this wave per the arc charter. The general rule it repeats (clause 4.4.2 item 2) is Tested above."),
        ("p1-5.3.3-table5-b", "At least one signature shall be present in the META-INF folder.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only table; out of this wave per the arc charter."),
        ("p1-5.3.3-table5-c", "Each XAdES signature child shall reference the signed file objects explicitly with ds:Reference children of ds:SignedInfo.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only table; out of this wave per the arc charter."),
        ("p1-5.3.3-table5-e", "Additional signed or unsigned file objects complying with clause 4.4.3.2 item 5 d) may be present in the META-INF folder.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only table; out of this wave per the arc charter, and the same extra-file-object boundary as clause 4.4.3.2 item 5 d) above."),

        ("p1-A.1-1", "\"mimetype\" shall be the first file in the ASiC container.",
            RequirementCoverageStatus.Tested, "AsicZipAuthoringTests.TheMimetypeEntryIsFirstStoredAndCarriesNoExtraField (and AsicZipReadingTests.AMimetypeEntryThatIsNotFirstIsRefused)"),
        ("p1-A.1-2", "\"mimetype\" shall not contain extra fields in its ZIP header (extra field length at offset 28 shall be zero).",
            RequirementCoverageStatus.Tested, "AsicZipAuthoringTests.TheMimetypeEntryIsFirstStoredAndCarriesNoExtraField (and AsicZipReadingTests.AMimetypeEntryCarryingAnExtraFieldIsRefused)"),
        ("p1-A.1-3", "\"mimetype\" shall not be compressed (compression method at offset 8 shall be zero).",
            RequirementCoverageStatus.Tested, "AsicZipAuthoringTests.TheMimetypeEntryIsFirstStoredAndCarriesNoExtraField (and AsicZipReadingTests.ACompressedMimetypeEntryIsRefused)"),
        ("p1-A.1-4", "The first four octets of the ASiC container file shall be 50 4B 03 04.",
            RequirementCoverageStatus.Tested, "AsicZipAuthoringTests.TheContainerBeginsWithTheLocalFileHeaderMagicOfAnnexA1Item4"),
        ("p1-A.1-5", "All multi-octet values shall be little-endian.",
            RequirementCoverageStatus.Tested, "AsicZipAuthoringTests.TheEndRecordCountsAndLocatesTheCentralDirectoryOnOneDisk (the independent oracle reads every count, length and offset little-endian and reaches the values this library wrote)"),
        ("p1-A.1-6", "\"mimetype\" shall not be compressed or encrypted inside the ASiC container.",
            RequirementCoverageStatus.Tested, "AsicZipReadingTests.AnEncryptedEntryIsRefused (encryption; the compression half is item 3 above)"),
        ("p1-A.1-note", "NOTE: the string \"mimetype\" starting at offset 30 signals that the container media type starts at offset 38, its length being the four octets at offset 18.",
            RequirementCoverageStatus.Tested, "AsicZipAuthoringPropertyTests.TheMediaTypeIsAlwaysReadableAtOffset38 (and AsicWellKnownTests.TheThreeOffsetsAreTheOnesTheAnnexA1NoteNames for the three offsets themselves)"),

        ("p1-A.2-registrations", "The registered media types are application/vnd.etsi.asic-s+zip (asics, scs) and application/vnd.etsi.asic-e+zip (asice, sce).",
            RequirementCoverageStatus.Tested, "AsicWellKnownTests.TheTwoMediaTypesAreTheOnesAnnexA2Registers"),
        ("p1-A.2-note2", "NOTE 2: the media type Application/vnd.etsi.timestamp-token is defined in ETSI EN 319 422.",
            RequirementCoverageStatus.OutOfScope, "EN 319 422 is not one of this wave's normative texts (waveasic contract, normative-texts list). The MimeType attribute a SigReference may state is a caller-stated value the model carries verbatim (AsicContainerTimeAssertionContext.TimestampReferenceMediaType); Annex A.4.2 calls the attribute descriptive and nothing is validated against it."),

        ("p1-A.3-precedence", "The XML Schema is held in the attached file as a normative part, and in any case of difference in contents the attached file takes precedence.",
            RequirementCoverageStatus.Tested, "AsicManifestXmlBindingTests.TheProducedDocumentValidatesAgainstTheAuthenticSchema (the document is validated against the authentic attachment, not against the prose reproduction)"),
        ("p1-A.3-digest", "The attached schema file's SHA-256 is the value the annex states.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.TheProducedManifestValidatesAgainstTheAuthenticSchema (the schema is located BY the digest Annex A.3 states, so a substituted schema is not found at all)"),

        ("p1-A.4.1-1", "The ASiCManifest element shall reference one signature file or one time assertion file using the SigReference element.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.EveryManifestDigestIsTheDigestOfTheEntryItNames"),
        ("p1-A.4.1-2", "The ASiCManifest element shall reference one or more data files using the DataObjectReference element.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.EveryManifestDigestIsTheDigestOfTheEntryItNames"),
        ("p1-A.4.1-3", "For each referenced data file, the ASiCManifest element shall allow indicating the media type of the referenced file object.",
            RequirementCoverageStatus.Tested, "AsicManifestXmlBindingTests.AManifestRoundTripsThroughTheModel"),
        ("p1-A.4.1-4", "For each referenced data file, the ASiCManifest element shall contain the digest values of the referenced file objects.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.EveryManifestDigestIsTheDigestOfTheEntryItNames"),
        ("p1-A.4.1-5", "For each referenced data file, the ASiCManifest element shall allow incorporating additional information of any type qualifying it.",
            RequirementCoverageStatus.Tested, "AsicManifestXmlBindingTests.AnExtensionRoundTripsOctetForOctet"),

        ("p1-A.4.2-schema", "The ASiCManifestType grammar: SigReference, one or more DataObjectReference, optional ASiCManifestExtensions, in that order.",
            RequirementCoverageStatus.Tested, "AsicManifestXmlBindingTests.TheProducedDocumentCarriesTheElementsAnnexA42StatesInOrder (and TheSchemaValidationRefusesADocumentTheGrammarDoesNotAdmit)"),
        ("p1-A.4.2-sigreference-uri", "SigReference.URI shall point to the file containing the CAdES object or the time assertion.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.EveryManifestDigestIsTheDigestOfTheEntryItNames"),
        ("p1-A.4.2-sigreference-coverage", "Where the pointed file is a CAdES object or time-stamp token, it shall apply to the file containing the ASiCManifest element; where it is an Evidence Record, that record applies to all files the DataObjectReference elements name.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESSignatureIsDetachedOverTheManifestOctetsAsStored (the signature fork; ExtendedEvidenceRecordProvesTheManifestsTargetsAndNotTheManifest is the Evidence Record fork)"),
        ("p1-A.4.2-sigreference-mimetype", "SigReference.MimeType contains the media type of the pointed signature or time assertion.",
            RequirementCoverageStatus.Tested, "AsicManifestXmlBindingTests.AManifestRoundTripsThroughTheModel"),
        ("p1-A.4.2-dor-uri", "DataObjectReference.URI shall reference the signed file object.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.EveryManifestDigestIsTheDigestOfTheEntryItNames"),
        ("p1-A.4.2-dor-mimetype", "DataObjectReference.MimeType shall indicate the referenced file object's media type.",
            RequirementCoverageStatus.Tested, "AsicManifestXmlBindingTests.AManifestRoundTripsThroughTheModel"),
        ("p1-A.4.2-dor-rootfile", "DataObjectReference.Rootfile, when true, shall indicate that the signed file object is a root file as per OCF clause 3.5.1.",
            RequirementCoverageStatus.Tested, "AsicManifestXmlBindingTests.AManifestRoundTripsThroughTheModel (absent, false and true are kept apart, which Annex A.7 item 2 b) i)'s chain pointer depends on)"),
        ("p1-A.4.2-digestvalue", "ds:DigestValue shall contain the digest of the file object's content under the algorithm ds:DigestMethod names.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.EveryManifestDigestIsTheDigestOfTheEntryItNames"),
        ("p1-A.4.2-one-per-file-object", "There shall be one DataObjectReference element for each file object the ASiCManifest references.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.EveryManifestDigestIsTheDigestOfTheEntryItNames"),
        ("p1-A.4.2-extension-wellformed", "An Extension element, if present, shall contain well-formed XML.",
            RequirementCoverageStatus.Tested, "AsicManifestXmlBindingTests.AnExtensionRoundTripsOctetForOctet (and AnUnrecognisedCriticalExtensionFailsClosed for the consumer-side default and its stated departure)"),

        ("p1-A.5-1", "The XAdESSignatures element shall have one or more ds:Signature children.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only; out of this wave per the arc charter and the waveasic contract's Out list."),
        ("p1-A.5-2", "The XAdESSignatures element shall be defined as in the ASiC XML schema.",
            RequirementCoverageStatus.OutOfScope, "XAdES-only; out of this wave per the arc charter. The element is nevertheless declared in the schema set the manifest binding validates against, because the authentic schema does not compile without it."),

        ("p1-A.6-1", "Valid file object and metadata naming shall comply with ZIP and any supported specific container.",
            RequirementCoverageStatus.Tested, "AsicZipReadingTests.ANameThatEscapesTheContainerIsRefused (one shared rule set applies on writing and on reading)"),
        ("p1-A.6-wildcard", "The character \"*\" denotes an arbitrary character string of any length, including zero, in a file name pattern.",
            RequirementCoverageStatus.Tested, "AsicManifestNamingTests.MatchingIsCaseSensitiveWhichKeepsAManifestOutOfTheEvidenceRecordDispatch (the wildcard grammar is ordinal, which is what keeps ASiCEvidenceRecordManifest*.xml out of the *evidencerecord*.xml dispatch)"),
        ("p1-A.6-2-intro", "The following rules shall apply to references, expressed as URIs per IETF RFC 3986.",
            RequirementCoverageStatus.Tested, "AsicContainerUriTests.AReferenceResolvesToTheEntryItNames"),
        ("p1-A.6-2-1-relative", "References to file objects within the container shall be relative URIs.",
            RequirementCoverageStatus.Tested, "AsicContainerUriTests.AReferenceNamingSomethingOutsideTheContainerIsRefused (a scheme, an authority, a query or a fragment is refused before anything is decoded, so only a relative reference resolves)"),
        ("p1-A.6-2-1-odf", "The rules specified in ODF clause 3.7 shall apply to those relative URIs.",
            RequirementCoverageStatus.OutOfScope, "SOURCE GAP, recorded by stage 10: the ODF text this clause defers to is not in the wave's cached normative material, so conformance to that clause cannot be checked against it. What IS implemented and tested is the resolution this annex states itself — item 2's container-root base and item 3's no-external-reference rule — plus IETF RFC 3986 clause 2.1 percent-decoding and the container layer's own entry-name rules."),
        ("p1-A.6-2-2", "Relative URIs in metadata stored under META-INF shall be resolved against the root directory as the base URI, not against the META-INF folder.",
            RequirementCoverageStatus.Tested, "AsicContainerUriTests.AReferenceResolvesAgainstTheContainerRootAndNotAgainstTheManifestsFolder (the wrong answer is asserted explicitly)"),
        ("p1-A.6-3", "References to data objects outside the container shall not be allowed.",
            RequirementCoverageStatus.Tested, "AsicContainerUriPropertyTests.NoReferenceEverResolvesToANameTheContainerLayerWouldRefuse (a CsCheck invariant over ten hostile prefixes)"),

        ("p1-A.7-1", "One or more ASiCArchiveManifest files may be present.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.TheFirstArchiveManifestReferencesEveryFileObjectAndCarriesNoBackwardPointer (a container carries none until one is added)"),
        ("p1-A.7-2", "Each ASiCArchiveManifest file shall contain one ASiCManifest element instance conformant to clause A.4.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.TheFirstArchiveManifestReferencesEveryFileObjectAndCarriesNoBackwardPointer (an independent XML reader reads the element and its references out of the stored octets)"),
        ("p1-A.7-3", "The ASiCManifest element shall reference a set of signed and/or time-asserted file objects, including previously added ASiCArchiveManifest files, according to the rules below.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.ARenewalRenamesThePredecessorByteForByteAndPointsBackAtItAlone"),
        ("p1-A.7-4a", "The signatures and/or time-stamp tokens requiring long term availability already present shall each include the full set of certificates and the related revocation information.",
            RequirementCoverageStatus.Tested, "AsicRequirementsMatrixTests.TheSimpleTimeAssertionContainerGainsTheAnnexA7ChainUnderTheSignedDataRoute (material is placed into the time assertion present before the chain starts; AsicContainerAugmentationTests.RaisingToBaselineLTPlacesTheMaterialInSignedDataWhereTheIndependentReaderFindsIt is the signature half)"),
        ("p1-A.7-4b", "The generator shall use SignedData.certificates/SignedData.crls or the certificate-values/revocation-values unsigned attributes as specified in CAdES.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.TheCertificateValuesRouteIsRefusedForAnObjectClause553PlacesInSignedData (the route is an explicit parameter checked against EN 319 122-1 clause 5.5.3 in both directions)"),
        ("p1-A.7-4c-a", "The ASiCArchiveManifest file shall be named \"ASiCArchiveManifest.xml\".",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.TheFirstArchiveManifestReferencesEveryFileObjectAndCarriesNoBackwardPointer"),
        ("p1-A.7-4c-b", "It shall reference all the signed and/or time-asserted data, signature and time-stamp token files requiring long term validation support.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.TheFirstArchiveManifestReferencesEveryFileObjectAndCarriesNoBackwardPointer"),
        ("p1-A.7-4c-c", "It shall reference in the SigReference element a time-stamp token applied to it, named with any valid \"META-INF/*timestamp*.tst\" name avoiding collisions with names already present.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.TheFirstArchiveManifestReferencesEveryFileObjectAndCarriesNoBackwardPointer (and AsicManifestNamingTests.CreationAvoidsEveryNameAlreadyPresentAndFillsGaps for the collision rule)"),
        ("p1-A.7-5", "On every subsequent addition, the time-stamp token applied to the last ASiCArchiveManifest file shall include the full information required for its validation.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.ARenewalPlacesMaterialOnlyInTheTokenTheLastArchiveManifestApplies"),
        ("p1-A.7-5a", "The last ASiCArchiveManifest file already present shall be renamed to a valid \"META-INF/*ASiCArchiveManifest*.xml\" name avoiding collisions.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.ARenewalRenamesThePredecessorByteForByteAndPointsBackAtItAlone"),
        ("p1-A.7-5b-i", "The new ASiCArchiveManifest file shall be named \"ASiCArchiveManifest.xml\".",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.ARenewalRenamesThePredecessorByteForByteAndPointsBackAtItAlone"),
        ("p1-A.7-5b-ii-reference", "It shall reference in the SigReference element a time-stamp token applied to it.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.TheRenameChainWalksBackwardThroughEveryRenewal (every link's own token still binds that link's octets after every later renewal)"),
        ("p1-A.7-5b-ii-name", "That token shall be named with any valid \"META-INF/*timestamp*.tst\" name avoiding collisions with names already present.",
            RequirementCoverageStatus.Tested, "AsicManifestNamingTests.ACreatedNameNeverCollidesWithTheNameAnnexA7Fixes"),
        ("p1-A.7-5b-iii-reference", "It shall reference all the file objects requiring long term availability, including the ASiCArchiveManifest files already present and the tokens applying to them.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.ARenewalRenamesThePredecessorByteForByteAndPointsBackAtItAlone"),
        ("p1-A.7-5b-iii-rootfile", "All those referenced file objects shall not have the Rootfile attribute, or it shall be set to false.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.ARenewalRenamesThePredecessorByteForByteAndPointsBackAtItAlone (exactly one reference states Rootfile, and it is the renamed predecessor)"),
        ("p1-A.7-5b-iv", "It shall reference the ASiCArchiveManifest renamed per item 2 a) with the Rootfile attribute set to true.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.ARenewalRenamesThePredecessorByteForByteAndPointsBackAtItAlone"),
        ("p1-A.7-note", "NOTE: the file named \"ASiCArchiveManifest.xml\" is always the last one added, which is what lets a validator walk the chain backward.",
            RequirementCoverageStatus.Tested, "AsicContainerValidationTests.TheArchiveManifestChainWalksBackwardThroughEveryRenewal (and AsicManifestNamingTests.TheFixedArchiveManifestNameIsRefusedWhileThePreviousOneStillOccupiesIt, which makes the rename impossible to skip)"),

        ("p2-4.2.1-chapeau", "The requirements specified in ASiC part 1 for ASiC-S shall apply with the additional restrictions below.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.SimpleTimeAssertionContainerCarriesATokenOverTheDataFile"),
        ("p2-4.2.1-a", "It shall comply with ASiC part 1 clause 4.3.3.1 item 2 a) and clause 4.3.3.2 items 4 a), 4 d) or 4 e) — the time-assertion-only branches.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.SimpleTimeAssertionContainerCarriesATokenOverTheDataFile (the token branch; SimpleEvidenceRecordContainerCarriesARecordProvingTheDataFile is the Evidence Record branch)"),
        ("p2-4.2.1-b", "It may contain additional elements in the META-INF folder as specified in ASiC part 1 clause 4.3.3.2 items 5 a) and 5 b).",
            RequirementCoverageStatus.Tested, "AsicRequirementsMatrixTests.TheSimpleTimeAssertionContainerGainsTheAnnexA7ChainUnderTheSignedDataRoute"),
        ("p2-4.2.1-c", "It shall support ASiC part 1 clause 4.3.3.2 item 2 — one data file at the root level, and the only file object there besides mimetype.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ASimpleContainerWithTwoDataObjectsIsRefused (and ASimpleDataObjectBelowTheContainerRootIsRefused)"),
        ("p2-4.2.1-d-i", "If one or more ASiCArchiveManifest files are present they shall comply with ASiC part 1 clause A.7.",
            RequirementCoverageStatus.Tested, "AsicRequirementsMatrixTests.TheSimpleTimeAssertionContainerGainsTheAnnexA7ChainUnderTheSignedDataRoute"),
        ("p2-4.2.1-d-ii", "With the additional restriction that only SignedData shall be used to include certificate and revocation information.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.TheSimpleTimeAssertionProfileRefusesTheCertificateValuesRoute (the refusal; AsicRequirementsMatrixTests.TheSimpleTimeAssertionContainerGainsTheAnnexA7ChainUnderTheSignedDataRoute is the admitted route)"),

        ("p2-4.3.1-chapeau", "The requirements specified in ASiC part 1 clause 4.4 for ASiC-E shall apply with the additional restrictions below.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESContainerIsTheShapeClause4442Describes"),
        ("p2-4.3.1-a", "It shall comply with ASiC part 1 clause 4.4.4.1 item 1 a) and clause 4.4.4.2 item 3 a) — the \".asice\" extension and the CAdES-signature branch only.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESContainerIsTheShapeClause4442Describes"),
        ("p2-4.3.1-b", "It shall support ASiC part 1 clause 4.4.5 item 2 — the container-level long-term-availability alternatives.",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.TheFirstArchiveManifestReferencesEveryFileObjectAndCarriesNoBackwardPointer (branch a); AsicContainerCreationTests.ExtendedEvidenceRecordProvesTheManifestsTargetsAndNotTheManifest is branch b)"),

        ("p2-4.3.2-chapeau", "The requirements specified in ASiC part 1 for ASiC-E shall apply with the additional restrictions below.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedTimeAssertionContainerCarriesATokenOverTheManifest"),
        ("p2-4.3.2-a", "It shall comply with ASiC part 1 clause 4.4.4.1 item 1 a) and clause 4.4.4.2 item 3 b) or 4 a) or 4 b) — excluding the CAdES-signature branch.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedTimeAssertionContainerCarriesATokenOverTheManifest (the token branch; ExtendedEvidenceRecordProvesTheManifestsTargetsAndNotTheManifest is the Evidence Record branch)"),
        ("p2-4.3.2-b", "It shall support ASiC part 1 clause 4.4.5 item 2.",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedEvidenceRecordProvesTheManifestsTargetsAndNotTheManifest"),

        ("p2-A-1", "The container may be realized as a physical ZIP container or, when the external specification supports it, as an abstract container with a file system model.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. OCF/ODF/UCF interoperability is out of this wave per the waveasic contract's Out list; this wave writes physical ZIP containers per Part 1 clause 4.2 item 1."),
        ("p2-A-2", "ASiC part 1 clause 4.4.2 item 3 and clause 4.4.3.1 should apply, and clause 4.4.3.2 should apply with the additional requirements below.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory, and it activates the XAdES container clauses, which are out of this wave per the arc charter."),
        ("p2-A-3", "\"mimetype\" may be present and should comply with ASiC part 1 and contain the media type identifying the container type.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. OCF/ODF/UCF interoperability is out of this wave per the waveasic contract's Out list."),
        ("p2-A-4", "\"META-INF/container.xml\" may be present and should comply with OCF.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. OCF-specific; out of this wave per the waveasic contract's Out list."),
        ("p2-A-5", "\"META-INF/manifest.xml\" may be present and should comply with ODF.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. ODF-specific; out of this wave per the waveasic contract's Out list."),
        ("p2-A-6", "\"META-INF/metadata.xml\" may be present and should comply with ODF.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. ODF-specific; out of this wave per the waveasic contract's Out list."),
        ("p2-A-7", "\"META-INF/signatures.xml\" may be present and should comply with OCF when the mimetype is application/epub+zip.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. OCF/EPUB-specific and XAdES-shaped; out of this wave per the waveasic contract's Out list and the arc charter."),
        ("p2-A-8", "\"META-INF/*signatures*.xml\" may be present and should comply with ODF when the mimetype is an ODF supported media type.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. ODF-specific and XAdES-shaped; out of this wave per the waveasic contract's Out list and the arc charter."),
        ("p2-A-9", "Other files defined in OCF, UCF and ODF may be present and should not violate the format implied by the mimetype file.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. OCF/ODF/UCF interoperability is out of this wave per the waveasic contract's Out list."),
        ("p2-A-10", "Table A.1: the general requirements that should apply for all ASiC-E containers across the OCF, ODF and UCF columns.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. The table is the consolidated form of the bullets above; out of this wave per the waveasic contract's Out list."),
        ("p2-A-11", "Additional requirement a): if present, the mimetype value should conform to the relevant container specification.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. OCF/ODF/UCF-specific; out of this wave per the waveasic contract's Out list."),
        ("p2-A-12", "Additional requirement b): if present, the manifest.xml content should conform to ODF.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. ODF-specific; out of this wave per the waveasic contract's Out list."),
        ("p2-A-13", "Additional requirement c): if present, the container.xml and metadata.xml content should conform to OCF.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. OCF-specific; out of this wave per the waveasic contract's Out list."),
        ("p2-A-14", "Additional requirement d): the signature file name should conform to the relevant container specification and its root element to ASiC part 1 clause 4.4.3.2 item 3 b) or 3 c).",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory, and XAdES-shaped; out of this wave per the waveasic contract's Out list and the arc charter."),
        ("p2-A-15", "Additional requirement f): the file extension should comply with the container media type or with ASiC part 1 clause 4.4.3.1 item 2 b).",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. OCF/ODF/UCF-specific; out of this wave per the waveasic contract's Out list."),
        ("p2-A-16", "Additional requirement g): the archive-level ZIP comment's presence and value should be as specified in ASiC part 1 clause 4.4.3.1 item 3.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. The equivalent CAdES-flavour permission (clause 4.4.4.1 item 3) is Tested above; the OCF/ODF/UCF profile itself is out of this wave per the waveasic contract's Out list."),

        ("p2-B-1", "When one single signed data object protected with an Evidence Record is extracted from the archive, an ASiC-S container should be created.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. Archival-extraction guidance is out of this wave per the waveasic contract's Out list; the shipped surface it would compose on (ASiC-S Evidence Record containers) is Tested by AsicContainerCreationTests.SimpleEvidenceRecordContainerCarriesARecordProvingTheDataFile."),
        ("p2-B-2", "It should comply with ASiC part 1 clauses 4.3.2, 4.3.3 and 4.3.4 and should include the extracted signed data object in the root folder.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. Out of this wave per the waveasic contract's Out list; the clauses it defers to are Tested rows of this matrix."),
        ("p2-B-3", "The extracted Evidence Record should be named according to ASiC part 1 clause 4.3.3.2 item 4 d) or 4 e) depending on its format.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. Out of this wave per the waveasic contract's Out list; the naming rule it defers to is Tested (rows p1-4.3.3.2-4d and p1-4.3.3.2-4e)."),
        ("p2-B-4", "When multiple signed data objects are extracted, an ASiC-E container should be created complying with ASiC part 1 clause 4.4.2 and clause 4.4.3 or 4.4.4.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. Out of this wave per the waveasic contract's Out list."),
        ("p2-B-5", "It should include one file for each extracted signed data object, with its detached signatures and ASiCManifest files where applicable.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. Out of this wave per the waveasic contract's Out list."),
        ("p2-B-6", "It should include one file for each extracted Evidence Record, renamed according to ASiC part 1 clause 4.4.3.2 item 4 a) or 4 b).",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. Out of this wave per the waveasic contract's Out list; the naming rule it defers to is Tested (row p1-4.4.3.2-4c)."),
        ("p2-B-7", "An ASiCEvidenceRecordManifest file should be created for each extracted Evidence Record, referencing it through SigReference and the extracted files through DataObjectReference.",
            RequirementCoverageStatus.OutOfScope, "Informative annex — non-mandatory. Out of this wave per the waveasic contract's Out list; the manifest shape it describes is Tested by AsicContainerCreationTests.ExtendedEvidenceRecordProvesTheManifestsTargetsAndNotTheManifest."),

        ("ratified-basis", "EN 319 162-2 clause 4.3.1 NOTE: implementations compliant with the ASiC-E CAdES additional container requirements CAN support the same levels defined for baseline containers in ASiC part 1 clause 5.",
            RequirementCoverageStatus.OutOfScope, "Not an obligation: the NOTE states a capability with \"can\", and Part 1 clause 5 defines no requirements table for ASiC-E with CAdES (row p1-5.1-scope). The ratified-* rows below are the table this wave synthesised from Part 1 clauses 4.4, 4.4.5 item 2 and Annex A.7 together with Part 2 clause 4.3.1, and holds itself to."),
        ("ratified-extension", "The container file extension is \".asice\" [Part 1 clause 4.4.4.1 item 1 a); Part 2 clause 4.3.1 a)].",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESContainerIsTheShapeClause4442Describes"),
        ("ratified-mimetype", "A mimetype file may be present, cardinality 0 or 1, and its content is \"application/vnd.etsi.asic-e+zip\" with no alternative branch [Part 1 clause 4.4.4.1 item 2, clause 4.4.4.2 item 1 and Annex A.1].",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESContainerIsTheShapeClause4442Describes (and AsicZipAuthoringTests.AContainerWithoutAMediaTypeCarriesNoMimetypeEntry for the absent case)"),
        ("ratified-data-objects", "One or more signed file objects are present outside the META-INF folder, cardinality one or more [Part 1 clause 4.4.2 item 2].",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESContainerIsTheShapeClause4442Describes (and ADataObjectInsideMetaInfIsRefused, AContainerWithNoDataObjectIsRefused)"),
        ("ratified-manifest", "One or more \"META-INF/ASiCManifest*.xml\" files are present, each conformant to Annex A.4 [Part 1 clause 4.4.4.2 item 2 and Annex A.4].",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.TheProducedManifestValidatesAgainstTheAuthenticSchema"),
        ("ratified-signature", "One \"META-INF/*signature*.p7s\" CAdES object is present for each ASiCManifest file [Part 1 clause 4.4.4.2 item 3 a); Part 2 clause 4.3.1 a)].",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESContainerIsTheShapeClause4442Describes"),
        ("ratified-signature-covers-manifest", "Each CAdES object is detached over the octets of the ASiCManifest file naming it, as those octets are stored [Part 1 Annex A.4.1; Part 2 clause 4.3.1].",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESSignatureIsDetachedOverTheManifestOctetsAsStored"),
        ("ratified-digests", "Each manifest carries one DataObjectReference per referenced file object, whose ds:DigestValue recomputes over that file object [Part 1 Annex A.4.2 and clause 4.4.4.2 item d)].",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.EveryManifestDigestIsTheDigestOfTheEntryItNames"),
        ("ratified-b-b", "B-B: every incorporated CAdES signature is a CAdES-B-B baseline signature [Part 1 clause 5.1 item 1 and Table 3 note a, read across to the CAdES flavour].",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.TheContainerLevelIsTheLowestLevelOfTheSignaturesItIncorporates"),
        ("ratified-b-t", "B-T: every incorporated signature additionally carries a signature-time-stamp [Part 1 clause 5.1 (B-T); EN 319 122-1 clause 6.3].",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.RaisingToBaselineTTimestampsTheSignatureAndPreservesEveryOtherEntry"),
        ("ratified-b-lt", "B-LT: every incorporated signature additionally carries the material required to validate it, placed as EN 319 122-1 clause 5.5.3 decides [Part 1 clause 5.1 (B-LT) and Annex A.7 items 1 a)/1 b)].",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.RaisingToBaselineLTPlacesTheMaterialInSignedDataWhereTheIndependentReaderFindsIt"),
        ("ratified-b-lta-signature", "B-LTA: every incorporated signature additionally carries an archive time-stamp over the manifest it is detached across [Part 1 clause 5.1 (B-LTA); clause 4.3.4 item 1 read across to ASiC-E].",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.RaisingToBaselineLTAArchiveTimestampsTheSignatureOverTheManifestItIsDetachedAcross"),
        ("ratified-b-lta-container", "B-LTA of the CONTAINER additionally needs the Annex A.7 chain or an Evidence Record, because a signature-internal archive time-stamp does not cover file objects referenced only through an ASiCManifest [Part 1 clause 4.1.2 NOTE 1 and clause 4.4.5 item 2].",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.TheFirstArchiveManifestReferencesEveryFileObjectAndCarriesNoBackwardPointer (and AsicContainerCreationTests.ExtendedEvidenceRecordProvesTheManifestsTargetsAndNotTheManifest for the Evidence Record alternative)"),
        ("ratified-level-min", "The container's level is the lowest level of the signatures it incorporates [Part 1 clause 5.1 item 2].",
            RequirementCoverageStatus.Tested, "AsicContainerAugmentationTests.TheContainerLevelIsTheLowestLevelOfTheSignaturesItIncorporates"),
        ("ratified-raise-all", "Raising the container raises every CAdES object it carries and every signer of each [Part 1 clause 5.1 item 2 and clause 4.3.4 item 1's \"all the signatures present\"].",
            RequirementCoverageStatus.Tested, "AsicRequirementsMatrixTests.RaisingAContainerRaisesEveryCAdESObjectItCarries"),
        ("ratified-zip-profile", "The ZIP profile applies unchanged: mimetype first, stored, no extra field, no encryption, no split archive, stored or deflate only [Part 1 clause 4.2, Annex A.1 and clause 5.3.1 Table 1 item a)].",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ExtendedCAdESContainerIsTheShapeClause4442Describes (the produced ASiC-E container's media type is readable at offset 38, which only the whole Annex A.1 layout makes true; the individual rules are the clause 4.2 and Annex A.1 rows above)"),
        ("ratified-algorithms", "MD5 is refused, SHA-1 is refused creation-side, and a caller-supplied dated reliability table is consulted at the stated instant [Part 1 clause 5.2.1].",
            RequirementCoverageStatus.Tested, "AsicContainerCreationTests.ADigestAlgorithmCreationRefusesStopsTheContainer (and TheSuppliedConstraintsTableDecidesWhetherTheManifestDigestIsAllowed)"),
        ("ratified-validation", "A validator recomputes every DataObjectReference digest, fails closed on any mismatch, and validates each embedded CAdES object through EN 319 102-1 against the manifest it covers [Part 1 clause 4.4.4.2 items a) and d)].",
            RequirementCoverageStatus.Tested, "AsicContainerValidationTests.AnExtendedCAdESContainerValidatesWithEveryReferenceRecomputedAndTheSignatureTotalPassed (and AChangedDataObjectOctetFailsTheContainerClosedWhateverTheSignatureSays)")
    ];
}
