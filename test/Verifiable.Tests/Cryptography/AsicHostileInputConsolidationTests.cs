using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The hostile-input prong of the wave, consolidated where the per-component tests left a gap: the three
/// membership rules of the Evidence Record family cross-fed each other's violations, the stored order of a
/// reduced hash tree, and truncation at the boundaries an attacker's octets arrive through.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Three membership rules, three different correct answers.</strong> The wave ships three mechanisms
/// that each answer "does this set of hash values name exactly these objects", and they answer it differently
/// on purpose:
/// </para>
/// <list type="number">
///   <item><description>
///     <strong>The tree-path rule of <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.3">IETF
///     RFC 4998 clause 4.3</see></strong>: a data object is proved when its hash walks the reduced tree to the
///     root. The group check — "it can be verified additionally, that only the hash values of the given data
///     objects are in the first hash-value list" — is an ADDITIONAL proof the caller asks for by stating a
///     group, and not asking for it is a conformant way to verify.
///   </description></item>
///   <item><description>
///     <strong>The bidirectional rule of
///     <see href="https://www.rfc-editor.org/rfc/rfc6283#appendix-A">IETF RFC 6283 Appendix A step 5.b</see></strong>:
///     both directions are stated in one sentence with no condition, so the strict reading ships and the
///     clause 3.3 reading is a departure the caller states.
///   </description></item>
///   <item><description>
///     <strong>The asymmetric rule of <c>ats-hash-index-v3</c></strong>
///     (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.01.01_60/en_31912201v010101p.pdf">
///     ETSI EN 319 122-1 clause 5.5.2</see>): an index entry naming material the signature does not carry makes
///     the index INVALID, while material the index does not name is reported as uncovered and is NOT an error —
///     NOTE 5 of that clause names the asymmetry as the point of the design.
///   </description></item>
/// </list>
/// <para>
/// Each violation shape is therefore built once and run through all three, and the assertions are that the
/// three answers DIFFER. A test that checked each mechanism in isolation would pass just as well if two of them
/// had been collapsed into one rule, which is the mistake this class exists to make impossible.
/// </para>
/// </remarks>
[TestClass]
internal sealed class AsicHostileInputConsolidationTests
{
    /// <summary>The address handed to the transport delegate; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.hostile-input.example.test/";


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The instant every archive time-stamp and Archive Timestamp of this class asserts.</summary>
    private static DateTimeOffset ArchiveTime { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The instant the CAdES signatures of this class state.</summary>
    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    /// <summary>The algorithm every hash tree of this class is built under.</summary>
    private static PkiDigestAlgorithm Algorithm { get; } = PkiDigestAlgorithm.Sha256;

    /// <summary>The canonicalization identifier every XML-form record of this class names.</summary>
    private static string Canonicalization { get; } = XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri;

    /// <summary>The data object every verification of this class asks about.</summary>
    private static byte[] FirstDataObject { get; } = [.. "the object the verifier was shown"u8];

    /// <summary>A second data object, present in the hash values and absent from what the verifier states.</summary>
    private static byte[] SecondDataObject { get; } = [.. "the object the verifier was never shown"u8];

    /// <summary>The attribute type the archive time-stamp scenarios append material under.</summary>
    private static string AppendedAttributeType { get; } = CAdESSignatureFacts.CertificateValuesAttributeOid;

    /// <summary>A second attribute type, for the material added after an index was built.</summary>
    private static string LaterAttributeType { get; } = CAdESSignatureFacts.RevocationValuesAttributeOid;


    /// <summary>
    /// THE CROSS-FEED, first direction: a set of hash values naming an object the verifier was never shown.
    /// The tree-path rule of RFC 4998 answers it only when the caller asks; the bidirectional rule of RFC 6283
    /// answers it by default and can be told not to; the asymmetric rule of <c>ats-hash-index-v3</c> answers it
    /// unconditionally and has no knob at all. Three mechanisms, one violation, three different answers.
    /// </summary>
    [TestMethod]
    public async Task AnExtraneousMemberIsRefusedByThreeMembershipRulesInThreeDifferentWays()
    {
        //(1) RFC 4998: one group of two objects, verified against a group naming only one of them.
        using EvidenceRecordCreation creation = await CreateEvidenceRecordAsync([[FirstDataObject, SecondDataObject]]).ConfigureAwait(false);
        EvidenceRecord record = creation.EvidenceRecords[0];

        using(EvidenceRecordVerification notAsked = await VerifyEvidenceRecordAsync(record, FirstDataObject, []).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, notAsked.Status,
                "Clause 4.3's group check is an ADDITIONAL proof: a verifier that states no group is answered about the tree path alone.");
        }

        using(EvidenceRecordVerification asked = await VerifyEvidenceRecordAsync(record, FirstDataObject, [FirstDataObject]).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.DataObjectGroupNotCoveredExclusively, asked.Status,
                "Asked about a group of one, the same record answers that its first list holds a value that group does not.");
        }

        using(EvidenceRecordVerification whole = await VerifyEvidenceRecordAsync(record, FirstDataObject, [FirstDataObject, SecondDataObject]).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, whole.Status, "Asked about the group it was built over, it verifies.");
        }

        //(2) RFC 6283: the same shape in the XML syntax, where the second direction is on by default.
        byte[] document = MintXmlEvidenceRecord([[Digest(FirstDataObject), Digest(SecondDataObject)]]);

        using(XmlEvidenceRecordVerification strict = await VerifyXmlEvidenceRecordAsync(document, [FirstDataObject]).ConfigureAwait(false))
        {
            Assert.AreEqual(XmlEvidenceRecordVerificationStatus.DataObjectGroupNotCoveredExclusively, strict.Status,
                "Appendix A step 5.b states both directions in one sentence, so the strict reading needs no asking.");
        }

        using(XmlEvidenceRecordVerification loose = await VerifyXmlEvidenceRecordAsync(document, [FirstDataObject], requireExclusivity: false).ConfigureAwait(false))
        {
            Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, loose.Status,
                "The clause 3.3 reading is the documented departure, and it is the caller who states it.");
        }

        //(3) ats-hash-index-v3: an index entry naming material the signature no longer carries.
        using ArchiveTimestampWorld world = await MintArchiveTimestampWorldAsync().ConfigureAwait(false);
        using CmsSignedData reduced = RemoveAppendedAttribute(world.Signature, AppendedAttributeType);
        using ArchiveTimestampCoverage invalid = await StateCoverageAsync(reduced, world.Token).ConfigureAwait(false);

        Assert.AreEqual(ArchiveTimestampCoverageStatus.HashIndexInvalid, invalid.Status,
            "Clause 5.5.2: an entry for which no current material produces a matching hash value makes the index invalid.");
        Assert.IsFalse(invalid.ProtectedObjects!.EveryIndexEntryMatched, "The report names the direction that failed.");
        Assert.IsNull(invalid.MessageImprintInput, "An invalid index states no imprint input at all, so nothing downstream can proceed on it.");
    }


    /// <summary>
    /// THE CROSS-FEED, second direction: an object that is present and that the hash values do not name. Both
    /// Evidence Record syntaxes call it a failure to cover, and <c>ats-hash-index-v3</c> deliberately does not —
    /// which is what makes an archive time-stamp survive a later augmentation.
    /// </summary>
    [TestMethod]
    public async Task AnUnlistedObjectIsAnErrorInTwoMembershipRulesAndNotInTheThird()
    {
        //(1) RFC 4998: a record built over one object, asked about another.
        using EvidenceRecordCreation creation = await CreateEvidenceRecordAsync([[FirstDataObject]]).ConfigureAwait(false);
        using(EvidenceRecordVerification unlisted = await VerifyEvidenceRecordAsync(creation.EvidenceRecords[0], SecondDataObject, []).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.DataObjectNotCovered, unlisted.Status,
                "Clause 4.3 step 1: a data object whose hash is not in the first list is not proved by the record.");
            Assert.IsFalse(unlisted.Chains[0].CoversDataObject);
        }

        //(2) RFC 6283: the same shape in the XML syntax, and the answer does not depend on the exclusivity knob.
        byte[] document = MintXmlEvidenceRecord([[Digest(FirstDataObject)]]);
        using(XmlEvidenceRecordVerification strict = await VerifyXmlEvidenceRecordAsync(document, [SecondDataObject]).ConfigureAwait(false))
        {
            Assert.AreEqual(XmlEvidenceRecordVerificationStatus.DataObjectNotCovered, strict.Status);
        }

        using(XmlEvidenceRecordVerification loose = await VerifyXmlEvidenceRecordAsync(document, [SecondDataObject], requireExclusivity: false).ConfigureAwait(false))
        {
            Assert.AreEqual(XmlEvidenceRecordVerificationStatus.DataObjectNotCovered, loose.Status,
                "Turning off the SECOND direction leaves the first exactly as it was — the two are not one rule.");
        }

        //(3) ats-hash-index-v3: material the index does not name is uncovered and is not an error.
        using ArchiveTimestampWorld world = await MintArchiveTimestampWorldAsync().ConfigureAwait(false);
        using CmsAttribute later = CmsAttribute.Create(LaterAttributeType, WriteOctetString([0x71, 0x72]), BaseMemoryPool.Shared);
        using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(world.Signature, signerIndex: 0, [later], BaseMemoryPool.Shared);
        using ArchiveTimestampCoverage coverage = await StateCoverageAsync(augmented, world.Token).ConfigureAwait(false);

        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, coverage.Status,
            "Clause 5.5.2 NOTE 5: adding material after an archive time-stamp does not invalidate it, and this is the direction the two Evidence Record syntaxes treat as a failure.");
        Assert.IsTrue(coverage.ProtectedObjects!.EveryIndexEntryMatched, "The direction that IS checked still holds.");
        Assert.IsFalse(
            coverage.ProtectedObjects.UnsignedAttributeValues.Single(value => string.Equals(value.AttributeType, LaterAttributeType, StringComparison.Ordinal)).IsCovered,
            "The uncovered object is reported rather than made an error.");
        Assert.IsNotNull(coverage.MessageImprintInput, "The imprint input is still stated, which is what lets the earlier token keep verifying.");
    }


    /// <summary>
    /// The stored order of a reduced hash tree's values carries no meaning to a verifier: both syntaxes state
    /// that the values are sorted before they are concatenated, so a producer that stored them in another order
    /// is answered exactly as one that sorted them. Asserted for both syntaxes, because an implementation that
    /// took the stored order as given would pass every other test in the wave.
    /// </summary>
    /// <remarks>
    /// This is a hostile-input statement and not a leniency: the values are a SET whatever their order, so a
    /// permutation gives an attacker nothing. What would give an attacker something — a value added, removed or
    /// changed — is what the other tests of this class and of the two verification classes refuse.
    /// </remarks>
    [TestMethod]
    public async Task AStoredOrderThatIsNotBinaryAscendingIsAnsweredExactlyAsASortedOneIsInBothSyntaxes()
    {
        //RFC 4998: the two hash values of a two-object group, swapped inside the record's own octets.
        using EvidenceRecordCreation creation = await CreateEvidenceRecordAsync([[FirstDataObject, SecondDataObject]]).ConfigureAwait(false);
        byte[] asWritten = creation.EvidenceRecords[0].AsReadOnlySpan().ToArray();

        byte[] first = Digest(FirstDataObject);
        byte[] second = Digest(SecondDataObject);
        byte[] permuted = SwapOctetRuns(asWritten, first, second);
        Assert.IsFalse(permuted.AsSpan().SequenceEqual(asWritten), "The permutation changed the record's octets.");

        using EvidenceRecord reordered = EvidenceRecord.Read(permuted, BaseMemoryPool.Shared);
        using(EvidenceRecordVerification verification = await VerifyEvidenceRecordAsync(reordered, FirstDataObject, [FirstDataObject, SecondDataObject]).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Status,
                "Clause 4.3 step 2 sorts before it concatenates, so the order the producer stored is not an input to the root.");
        }

        //RFC 6283: the same permutation expressed as the order of two DigestValue elements.
        byte[] sorted = MintXmlEvidenceRecord([[first, second]]);
        byte[] unsorted = MintXmlEvidenceRecord([[second, first]]);
        Assert.IsFalse(sorted.AsSpan().SequenceEqual(unsorted), "The two documents differ in the order they write the two values in.");

        using XmlEvidenceRecordVerification sortedConclusion = await VerifyXmlEvidenceRecordAsync(sorted, [FirstDataObject, SecondDataObject]).ConfigureAwait(false);
        using XmlEvidenceRecordVerification unsortedConclusion = await VerifyXmlEvidenceRecordAsync(unsorted, [FirstDataObject, SecondDataObject]).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, sortedConclusion.Status);
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, unsortedConclusion.Status,
            "Clause 3.1.1 sorts the values of a Sequence, so the document order carries nothing.");
    }


    /// <summary>
    /// Truncation at every length, at the three boundaries an attacker's octets arrive through: the archive
    /// reader, the binary Evidence Record inside a container, and the XML-form record inside a container. Every
    /// length produces a typed status and no exception escapes.
    /// </summary>
    /// <remarks>
    /// The Evidence Record legs go through <see cref="AsicContainerValidation.ValidateAsync"/> rather than
    /// through <see cref="EvidenceRecord.Read"/> directly, because the container is where octets nobody wrote
    /// arrive: <see cref="EvidenceRecord.Read"/> is a decoding primitive whose documented contract is to throw
    /// on octets that are not a record, and the wave's fail-closed rule (contract R-10) is that the boundary
    /// composing it never lets that escape.
    /// </remarks>
    [TestMethod]
    public async Task TruncatedOctetsAreRefusedWithATypedReasonAtEveryLengthAndAtEveryBoundary()
    {
        using EvidenceRecordCreation creation = await CreateEvidenceRecordAsync([[FirstDataObject]]).ConfigureAwait(false);
        byte[] binaryRecord = creation.EvidenceRecords[0].AsReadOnlySpan().ToArray();
        byte[] xmlRecord = MintXmlEvidenceRecord([[Digest(FirstDataObject)]]);

        using PooledMemory binaryContainer = BuildSimpleEvidenceRecordContainer(AsicManifestNaming.SimpleBinaryEvidenceRecordEntryName, binaryRecord);
        using PooledMemory xmlContainer = BuildSimpleEvidenceRecordContainer(AsicManifestNaming.SimpleXmlEvidenceRecordEntryName, xmlRecord);

        //The archive reader itself: every prefix of a container this library wrote.
        byte[] archive = binaryContainer.AsReadOnlySpan().ToArray();
        for(int length = 0; length < archive.Length; length += Math.Max(1, archive.Length / 64))
        {
            using AsicZipReadResult read = AsicZipReading.Read(archive.AsMemory(0, length), AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);
            Assert.AreNotEqual(AsicZipReadStatus.Read, read.Status, $"A prefix of {length} octets is not the whole archive.");
            Assert.AreNotEqual(AsicZipReadStatus.NotRead, read.Status, $"A prefix of {length} octets was refused by a named rule rather than left unevaluated.");
        }

        //The two Evidence Record boundaries: every prefix of the record, inside an otherwise intact container.
        for(int length = 0; length < binaryRecord.Length; length += Math.Max(1, binaryRecord.Length / 32))
        {
            using PooledMemory truncated = BuildSimpleEvidenceRecordContainer(AsicManifestNaming.SimpleBinaryEvidenceRecordEntryName, binaryRecord[..length]);
            using AsicContainerValidationResult validation = await ValidateContainerAsync(truncated.AsReadOnlyMemory()).ConfigureAwait(false);
            Assert.AreEqual(AsicContainerValidationStatus.EvidenceRecordNotVerified, validation.Status, $"A record of {length} octets proves nothing.");
            Assert.AreNotEqual(EvidenceRecordVerificationStatus.Verified, validation.EvidenceRecords.Single().VerificationStatus);
            Assert.IsNotNull(validation.EvidenceRecords.Single().FailureReason, "Every refusal states its reason.");
        }

        for(int length = 0; length < xmlRecord.Length; length += Math.Max(1, xmlRecord.Length / 32))
        {
            using PooledMemory truncated = BuildSimpleEvidenceRecordContainer(AsicManifestNaming.SimpleXmlEvidenceRecordEntryName, xmlRecord[..length]);
            using AsicContainerValidationResult validation = await ValidateContainerAsync(truncated.AsReadOnlyMemory()).ConfigureAwait(false);
            Assert.AreEqual(AsicContainerValidationStatus.EvidenceRecordNotVerified, validation.Status, $"A document of {length} octets proves nothing.");
            Assert.AreNotEqual(XmlEvidenceRecordVerificationStatus.Verified, validation.EvidenceRecords.Single().XmlVerificationStatus);
            Assert.IsNotNull(validation.EvidenceRecords.Single().FailureReason, "Every refusal states its reason.");
        }

        //The whole record, in the other syntax's entry: each parser refuses what the other one writes.
        using PooledMemory binaryAsXml = BuildSimpleEvidenceRecordContainer(AsicManifestNaming.SimpleXmlEvidenceRecordEntryName, binaryRecord);
        using AsicContainerValidationResult binaryAsXmlConclusion = await ValidateContainerAsync(binaryAsXml.AsReadOnlyMemory()).ConfigureAwait(false);
        Assert.AreEqual(AsicContainerValidationStatus.EvidenceRecordNotVerified, binaryAsXmlConclusion.Status);
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Malformed, binaryAsXmlConclusion.EvidenceRecords.Single().XmlVerificationStatus,
            "Clause 4.4.4.2 item 4 dispatches by file name, so DER octets under an XML name reach the XML parser and are refused there.");

        using PooledMemory xmlAsBinary = BuildSimpleEvidenceRecordContainer(AsicManifestNaming.SimpleBinaryEvidenceRecordEntryName, xmlRecord);
        using AsicContainerValidationResult xmlAsBinaryConclusion = await ValidateContainerAsync(xmlAsBinary.AsReadOnlyMemory()).ConfigureAwait(false);
        Assert.AreEqual(AsicContainerValidationStatus.EvidenceRecordNotVerified, xmlAsBinaryConclusion.Status);
        Assert.AreEqual(EvidenceRecordVerificationStatus.Malformed, xmlAsBinaryConclusion.EvidenceRecords.Single().VerificationStatus,
            "And an XML document under a binary name reaches the DER decoder and is refused there.");
    }


    /// <summary>
    /// Creates an initial Evidence Record over the supplied groups through the shipped surface, against a
    /// Time-Stamping Authority that mints a genuine token over whatever imprint the request states.
    /// </summary>
    /// <param name="groups">The data object groups, each a list of data object octets.</param>
    /// <returns>The creation result. The caller disposes it.</returns>
    private async Task<EvidenceRecordCreation> CreateEvidenceRecordAsync(IReadOnlyList<byte[][]> groups)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        var responder = new MintingTimestampResponder(authority, [authority, root], ArchiveTime);

        var dataObjectGroups = new List<EvidenceRecordDataObjectGroup>(groups.Count);
        for(int i = 0; i < groups.Count; ++i)
        {
            var dataObjects = new List<ReadOnlyMemory<byte>>(groups[i].Length);
            for(int j = 0; j < groups[i].Length; ++j)
            {
                dataObjects.Add(new ReadOnlyMemory<byte>(groups[i][j]));
            }

            dataObjectGroups.Add(new EvidenceRecordDataObjectGroup { DataObjects = dataObjects });
        }

        return await EvidenceRecords.CreateInitialAsync(
            new EvidenceRecordCreationContext
            {
                DataObjectGroups = dataObjectGroups,
                DigestAlgorithm = Algorithm,
                TsaUri = TsaUri,
                FetchTimestampResponse = responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies a binary Evidence Record against a data object through the shipped surface.
    /// </summary>
    /// <param name="evidenceRecord">The record.</param>
    /// <param name="dataObject">The data object it is asked about.</param>
    /// <param name="dataObjectGroup">The group to check exclusivity for, or an empty list to skip that check.</param>
    /// <returns>The conclusion. The caller disposes it.</returns>
    private async Task<EvidenceRecordVerification> VerifyEvidenceRecordAsync(
        EvidenceRecord evidenceRecord,
        byte[] dataObject,
        IReadOnlyList<byte[]> dataObjectGroup)
    {
        var group = new List<ReadOnlyMemory<byte>>(dataObjectGroup.Count);
        for(int i = 0; i < dataObjectGroup.Count; ++i)
        {
            group.Add(new ReadOnlyMemory<byte>(dataObjectGroup[i]));
        }

        return await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext
            {
                EvidenceRecord = evidenceRecord,
                DataObject = new ReadOnlyMemory<byte>(dataObject),
                DataObjectGroup = group
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Mints an XML-form Evidence Record over the supplied hash tree through the independent factory, which
    /// writes the documents the shipped surface only reads.
    /// </summary>
    /// <param name="hashTree">The <c>Sequence</c> elements, leaf list first.</param>
    /// <returns>The document's octets.</returns>
    private static byte[] MintXmlEvidenceRecord(IReadOnlyList<IReadOnlyList<byte[]>> hashTree)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);

        return XmlEvidenceRecordTestFactory.MintInitial(hashTree, Algorithm, Canonicalization, authority, [authority, root], ArchiveTime);
    }


    /// <summary>
    /// Parses an XML-form Evidence Record through the staged binding and verifies it through the shipped
    /// surface.
    /// </summary>
    /// <param name="document">The document's octets.</param>
    /// <param name="dataObjects">The archive object's data objects.</param>
    /// <param name="requireExclusivity">Whether Appendix A step 5.b's second direction is performed.</param>
    /// <returns>The conclusion. The caller disposes it.</returns>
    private async Task<XmlEvidenceRecordVerification> VerifyXmlEvidenceRecordAsync(
        byte[] document,
        byte[][] dataObjects,
        bool requireExclusivity = true)
    {
        using XmlEvidenceRecordParseResult parsed = await XmlEvidenceRecordXmlBinding.ParseAsync(
            new XmlEvidenceRecordParseContext { Document = document }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parsed.IsValid, $"The document has to parse before it can be verified ({parsed.Status}: {parsed.FailureReason}).");

        var objects = new List<XmlEvidenceRecordDataObject>(dataObjects.Length);
        for(int i = 0; i < dataObjects.Length; ++i)
        {
            objects.Add(new XmlEvidenceRecordDataObject { Content = dataObjects[i] });
        }

        return await XmlEvidenceRecords.VerifyAsync(
            new XmlEvidenceRecordVerificationContext
            {
                EvidenceRecord = parsed.EvidenceRecord!,
                Document = document,
                DataObjects = objects,
                Canonicalize = XmlEvidenceRecordXmlBinding.CanonicalizeAsync,
                RequireDataObjectGroupExclusivity = requireExclusivity
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Writes an ASiC-S container carrying one data file and one Evidence Record under the fixed name clause
    /// 4.3.3.2 item 4 gives that form.
    /// </summary>
    /// <param name="entryName">The Evidence Record's entry name.</param>
    /// <param name="evidenceRecord">The record's octets, which may be anything at all.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    private static PooledMemory BuildSimpleEvidenceRecordContainer(string entryName, byte[] evidenceRecord)
    {
        return AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                MediaType = AsicWellKnown.AsicSimpleMediaType,
                LastModified = TestClock.CanonicalEpoch,
                Entries =
                [
                    new AsicZipEntrySource { Name = "first.txt", Content = FirstDataObject },
                    new AsicZipEntrySource { Name = entryName, Content = evidenceRecord }
                ]
            },
            BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Validates a container through the shipped surface with both Evidence Record seams supplied and no
    /// signature validation inputs.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <returns>The conclusion. The caller disposes it.</returns>
    private async Task<AsicContainerValidationResult> ValidateContainerAsync(ReadOnlyMemory<byte> container)
    {
        return await AsicContainerValidation.ValidateAsync(
            new AsicContainerValidationContext
            {
                Container = container,
                CurrentTime = TestClock.CanonicalEpoch.AddDays(1),
                ParseManifest = AsicManifestXmlBinding.ParseAsync,
                ParseXmlEvidenceRecord = XmlEvidenceRecordXmlBinding.ParseAsync,
                CanonicalizeXml = XmlEvidenceRecordXmlBinding.CanonicalizeAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Mints a signature carrying an <c>archive-time-stamp-v3</c> whose <c>ats-hash-index-v3</c> names an
    /// appended unsigned attribute value, so that removing that value leaves an index entry matching nothing.
    /// </summary>
    /// <returns>The signature and the token, both owned by the returned world.</returns>
    private async Task<ArchiveTimestampWorld> MintArchiveTimestampWorldAsync()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);

        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using System.Security.Cryptography.X509Certificates.X509Certificate2 signerCertificate =
            CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using ECDsa timestampKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using System.Security.Cryptography.X509Certificates.X509Certificate2 timestampCertificate =
            CmsSignedDataTestFactory.MintSelfSignedCertificate(timestampKey, NotBefore, NotAfter);

        using CmsSignedData baseline = CmsSignedDataTestFactory.SignAsCAdEST(
            FirstDataObject, signerCertificate, SigningTime, timestampCertificate, SigningTime.AddMinutes(1));
        using CmsAttribute indexed = CmsAttribute.Create(AppendedAttributeType, WriteOctetString([0x61, 0x62]), BaseMemoryPool.Shared);
        using CmsSignedData richer = CmsSignedDataAugmentation.AppendUnsignedAttributes(baseline, signerIndex: 0, [indexed], BaseMemoryPool.Shared);

        using AtsHashIndexV3 hashIndex = await ArchiveTimestampV3.ComputeHashIndexAsync(
            richer, signerIndex: 0, Algorithm, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using SignedContentMemory imprintInput = await ArchiveTimestampV3.BuildMessageImprintInputAsync(
            new ArchiveTimestampImprintContext { SignedData = richer, HashIndex = hashIndex, MessageImprintAlgorithm = Algorithm },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory minted = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            authority, [authority, root], imprintInput.AsReadOnlyMemory(), ArchiveTime, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using CmsSignedData tokenAsSignedData = CmsSignedData.FromBytes(minted.AsReadOnlySpan(), BaseMemoryPool.Shared);
        using CmsAttribute indexAttribute = CmsAttribute.Create(
            CAdESSignatureFacts.AtsHashIndexV3AttributeOid, hashIndex.AsReadOnlySpan(), BaseMemoryPool.Shared);
        using CmsSignedData grafted = CmsSignedDataAugmentation.AppendUnsignedAttributes(
            tokenAsSignedData, signerIndex: 0, [indexAttribute], BaseMemoryPool.Shared);

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(grafted.AsReadOnlySpan().Length);
        grafted.AsReadOnlySpan().CopyTo(owner.Memory.Span);
        var token = new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);

        using CmsAttribute archiveAttribute = CmsAttribute.Create(
            CAdESSignatureFacts.ArchiveTimestampV3AttributeOid, grafted.AsReadOnlySpan(), BaseMemoryPool.Shared);
        CmsSignedData signature = CmsSignedDataAugmentation.AppendUnsignedAttributes(
            richer, signerIndex: 0, [archiveAttribute], BaseMemoryPool.Shared);

        return new ArchiveTimestampWorld(signature, token);
    }


    /// <summary>
    /// States what an <c>archive-time-stamp-v3</c> token protects in a signature, through the shipped component.
    /// </summary>
    /// <param name="signedData">The signature.</param>
    /// <param name="token">The token carrying the index.</param>
    /// <returns>The stated coverage. The caller disposes it.</returns>
    private async Task<ArchiveTimestampCoverage> StateCoverageAsync(CmsSignedData signedData, PkiCertificateMemory token)
    {
        return await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = signedData, ArchiveTimestampToken = token },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Removes every unsigned attribute value of one attribute type from a signature, through the shipped
    /// inverse-splice primitive.
    /// </summary>
    /// <param name="signedData">The signature.</param>
    /// <param name="attributeType">The attribute type whose values are to go.</param>
    /// <returns>The reduced signature. The caller disposes it.</returns>
    private static CmsSignedData RemoveAppendedAttribute(CmsSignedData signedData, string attributeType)
    {
        List<CmsUnsignedAttributeValueLocation> locations =
        [
            .. CmsSignedDataAugmentation.LocateUnsignedAttributeValues(signedData, signerIndex: 0)
                .Where(location => string.Equals(location.AttributeType, attributeType, StringComparison.Ordinal))
        ];
        Assert.IsNotEmpty(locations, $"The signature has to carry '{attributeType}' for the removal to mean anything.");

        return CmsSignedDataReduction.RemoveUnsignedAttributeValues(signedData, signerIndex: 0, locations, BaseMemoryPool.Shared);
    }


    /// <summary>Computes one digest through the independent oracle.</summary>
    /// <param name="content">The octets to hash.</param>
    /// <returns>The digest octets.</returns>
    private static byte[] Digest(byte[] content) => EvidenceRecordOracle.Hash(content, Algorithm);


    /// <summary>Writes a DER <c>OCTET STRING</c> around the supplied content.</summary>
    /// <param name="content">The content octets.</param>
    /// <returns>The encoded value.</returns>
    private static byte[] WriteOctetString(ReadOnlySpan<byte> content)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(content);

        return writer.Encode();
    }


    /// <summary>
    /// Swaps two equal-length octet runs wherever they occur in a buffer, producing a permutation of the same
    /// values inside a structure whose lengths are therefore unchanged.
    /// </summary>
    /// <param name="source">The octets to rewrite.</param>
    /// <param name="left">The first run.</param>
    /// <param name="right">The second run.</param>
    /// <returns>The rewritten octets.</returns>
    private static byte[] SwapOctetRuns(byte[] source, byte[] left, byte[] right)
    {
        Assert.HasCount(left.Length, right, "Only equal-length runs can be swapped without changing any length octet.");
        int leftAt = IndexOf(source, left);
        int rightAt = IndexOf(source, right);
        Assert.IsGreaterThanOrEqualTo(0, leftAt, "The first value has to be in the structure.");
        Assert.IsGreaterThanOrEqualTo(0, rightAt, "The second value has to be in the structure.");

        byte[] rewritten = [.. source];
        right.CopyTo(rewritten.AsSpan(leftAt));
        left.CopyTo(rewritten.AsSpan(rightAt));

        return rewritten;
    }


    /// <summary>Finds the first occurrence of an octet run.</summary>
    /// <param name="source">The octets to search.</param>
    /// <param name="value">The run to find.</param>
    /// <returns>The offset, or -1.</returns>
    private static int IndexOf(byte[] source, byte[] value)
    {
        for(int i = 0; i + value.Length <= source.Length; ++i)
        {
            if(source.AsSpan(i, value.Length).SequenceEqual(value))
            {
                return i;
            }
        }

        return -1;
    }


    /// <summary>
    /// A signature carrying one <c>archive-time-stamp-v3</c> and that attribute's own token, held together so a
    /// test can change the signature and ask the unchanged token what it still protects.
    /// </summary>
    private sealed class ArchiveTimestampWorld: IDisposable
    {
        /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
        private bool disposed;


        /// <summary>Initialises a new world.</summary>
        /// <param name="signature">The signature carrying the attribute.</param>
        /// <param name="token">The token the attribute carries.</param>
        public ArchiveTimestampWorld(CmsSignedData signature, PkiCertificateMemory token)
        {
            Signature = signature;
            Token = token;
        }


        /// <summary>The signature carrying the archive time-stamp.</summary>
        public CmsSignedData Signature { get; }

        /// <summary>The archive time-stamp token, carrying the index.</summary>
        public PkiCertificateMemory Token { get; }


        /// <inheritdoc/>
        public void Dispose()
        {
            if(disposed)
            {
                return;
            }

            disposed = true;
            Token.Dispose();
            Signature.Dispose();
        }
    }
}
