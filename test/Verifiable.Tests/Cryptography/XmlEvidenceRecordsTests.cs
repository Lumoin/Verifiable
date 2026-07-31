using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="XmlEvidenceRecords.VerifyAsync"/> — the detailed verification process of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#appendix-A">IETF RFC 6283 Appendix A</see>, which is the
/// authoritative expansion of clause 2.3, clause 3.3 and clause 4.3.
/// </summary>
/// <remarks>
/// <para>
/// Every document these tests verify was minted by <see cref="XmlEvidenceRecordTestFactory"/>, which computes
/// every hash value through <see cref="XmlEvidenceRecordOracle"/> and takes every time-stamp from the
/// independent minting authority. Nothing the surface under test produced takes part in building the artifact it
/// is then asked about, so a verification that succeeds is a statement about the specification's algorithm.
/// </para>
/// <para>
/// The documents are parsed through the staged <see cref="XmlEvidenceRecordXmlBinding"/> and canonicalized
/// through it too, because that is what a caller supplies: this library ships neither, and a test that reached
/// around the seams would be testing a composition nobody can build.
/// </para>
/// </remarks>
[TestClass]
internal sealed class XmlEvidenceRecordsTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The <c>genTime</c> of every initial Archive Time-Stamp in this class.</summary>
    private static DateTimeOffset InitialArchiveTime { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The <c>genTime</c> of every Time-Stamp Renewal in this class.</summary>
    private static DateTimeOffset TimeStampRenewalTime { get; } = TestClock.CanonicalEpoch.AddHours(2);

    /// <summary>The <c>genTime</c> of every Hash-Tree Renewal in this class.</summary>
    private static DateTimeOffset HashTreeRenewalTime { get; } = TestClock.CanonicalEpoch.AddHours(3);

    /// <summary>The algorithm every initial chain of this class names.</summary>
    private static PkiDigestAlgorithm Sha256 { get; } = PkiDigestAlgorithm.Sha256;

    /// <summary>The algorithm every Hash-Tree Renewal of this class selects.</summary>
    private static PkiDigestAlgorithm Sha512 { get; } = PkiDigestAlgorithm.Sha512;

    /// <summary>The canonicalization identifier every chain of this class names unless a test states another.</summary>
    private static string ExclusiveCanonicalization { get; } = XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri;

    /// <summary>The first data object every test of this class archives.</summary>
    private static byte[] FirstDataObject { get; } = [.. "the first archived data object"u8];

    /// <summary>The second data object, for the data-object-group cases.</summary>
    private static byte[] SecondDataObject { get; } = [.. "the second archived data object"u8];

    /// <summary>The third data object, for the data-object-group cases.</summary>
    private static byte[] ThirdDataObject { get; } = [.. "the third archived data object"u8];


    /// <summary>
    /// The initial Archive Time-Stamp of a record over one data object proves it: the hash value is in the first
    /// <c>Sequence</c>, the root the walk reaches is what the token binds, and the instant reported is the
    /// token's own.
    /// </summary>
    [TestMethod]
    public async Task ARecordOverOneDataObjectProvesIt()
    {
        using var world = TimestampingWorld.Create();
        byte[] document = world.MintInitial([[Digest(FirstDataObject, Sha256)]], Sha256);

        using XmlEvidenceRecordVerification verification = await VerifyAsync(document, [FirstDataObject]).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, verification.Status, "Appendix A: the initial Archive Time-Stamp proves the data object.");
        Assert.AreEqual(InitialArchiveTime, verification.InitialArchiveTime, "The instant proved is the initial Archive Time-Stamp's genTime.");
        Assert.AreEqual(InitialArchiveTime, verification.CoveredUntil, "One member is where the unbroken run of proofs ends.");
        Assert.HasCount(1, verification.Chains, "One chain was written.");
        Assert.IsTrue(verification.Chains[0].CoversDataObjects, "The chain's own initial member carries the data object.");

        XmlEvidenceRecordArchiveTimeStampVerification member = verification.Chains[0].ArchiveTimeStamps[0];
        Assert.AreEqual(XmlEvidenceRecordRenewalKind.Initial, member.RenewalKind, "The first member of the first chain is the initial Archive Time-Stamp.");
        Assert.AreEqual(XmlEvidenceRecordMembershipStatus.Satisfied, member.Membership, "Appendix A step 5.b held in both directions.");
        Assert.AreSequenceEqual(
            XmlEvidenceRecordTestFactory.RootOf([[Digest(FirstDataObject, Sha256)]], Sha256),
            member.Root!.AsReadOnlySpan().ToArray(),
            "The root reported is the one the independent computation reaches over the same tree.");
    }


    /// <summary>
    /// Clause 3.1.1: "when an archive object is a group and composed of more than one data object, the first hash
    /// list MUST contain the hash values of all its data objects". A record over a group of three proves the
    /// group, and the whole group is verified at once rather than one member at a time.
    /// </summary>
    [TestMethod]
    public async Task ARecordOverADataObjectGroupProvesTheWholeGroup()
    {
        using var world = TimestampingWorld.Create();
        byte[][] group = [FirstDataObject, SecondDataObject, ThirdDataObject];
        byte[] document = world.MintInitial([Digests(group, Sha256)], Sha256);

        using XmlEvidenceRecordVerification verification = await VerifyAsync(document, group).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, verification.Status, "The group's three hash values are exactly what the first Sequence holds.");
    }


    /// <summary>
    /// Appendix A step 5.b, first direction: a data object whose hash value is not in the first <c>Sequence</c>
    /// is not proved, and the record says so rather than reporting a mismatched root.
    /// </summary>
    [TestMethod]
    public async Task ADataObjectMissingFromTheFirstSequenceIsNotProved()
    {
        using var world = TimestampingWorld.Create();
        byte[] document = world.MintInitial([[Digest(FirstDataObject, Sha256)]], Sha256);

        using XmlEvidenceRecordVerification verification = await VerifyAsync(document, [FirstDataObject, SecondDataObject]).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.DataObjectNotCovered, verification.Status,
            "Appendix A step 5.b: a digest value of a protected object that cannot be found in the first sequence exits with a negative result.");
        Assert.IsFalse(verification.Chains[0].CoversDataObjects, "The chain does not carry the objects it was asked about.");
        Assert.IsNull(verification.CoveredUntil, "Nothing was proved, so no instant is claimed.");
    }


    /// <summary>
    /// Appendix A step 5.b, second direction — the one clause 3.3 step 2 phrases as a SHOULD and this library
    /// performs by default: a first <c>Sequence</c> holding a hash value the verifier was never shown is a
    /// negative result, and the caller can state the departure that tolerates it.
    /// </summary>
    [TestMethod]
    public async Task AFirstSequenceHoldingAValueTheVerifierWasNeverShownIsRefusedByDefault()
    {
        using var world = TimestampingWorld.Create();
        byte[] document = world.MintInitial([[Digest(FirstDataObject, Sha256), Digest(SecondDataObject, Sha256)]], Sha256);

        using XmlEvidenceRecordVerification strict = await VerifyAsync(document, [FirstDataObject]).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.DataObjectGroupNotCoveredExclusively, strict.Status,
            "Appendix A step 5.b states both directions unconditionally, and the strict reading is this library's default.");

        using XmlEvidenceRecordVerification loose = await VerifyAsync(document, [FirstDataObject], requireExclusivity: false).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, loose.Status,
            "Clause 3.3 step 2's SHOULD reading, available as the documented departure the caller states.");
    }


    /// <summary>
    /// Clause 4.2.1: a Time-Stamp Renewal appends an Archive Time-Stamp to the SAME chain whose first
    /// <c>Sequence</c> holds the digest of the previous <c>TimeStamp</c> element's canonical binary
    /// representation, and both members of the chain still verify.
    /// </summary>
    [TestMethod]
    public async Task ATimeStampRenewalLinksToThePreviousTimeStampElement()
    {
        using var world = TimestampingWorld.Create();
        byte[] initial = world.MintInitial([[Digest(FirstDataObject, Sha256)]], Sha256);
        byte[] renewed = world.AppendTimeStampRenewal(initial);

        using XmlEvidenceRecordVerification verification = await VerifyAsync(renewed, [FirstDataObject]).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, verification.Status, "Both members of the renewed chain verify.");
        Assert.HasCount(1, verification.Chains, "Clause 4.2.1 appends to the existing chain rather than starting a new one.");
        Assert.HasCount(2, verification.Chains[0].ArchiveTimeStamps, "The chain carries the initial member and the renewal.");
        Assert.AreEqual(XmlEvidenceRecordRenewalKind.TimeStampRenewal, verification.Chains[0].ArchiveTimeStamps[1].RenewalKind,
            "A later member of a chain came from a Time-Stamp Renewal, which is the branch clause 4.2's algorithm continuity decides.");
        Assert.AreEqual(TimeStampRenewalTime, verification.LatestArchiveTime, "The renewal's instant is the record's most recent.");
        Assert.AreEqual(TimeStampRenewalTime, verification.CoveredUntil, "The data object is carried to the renewal by an unbroken run of proofs.");
    }


    /// <summary>
    /// Clause 4.2.1: "Note that the new ATS MAY not contain a hash tree." A renewal written that way states the
    /// digest of the previous <c>TimeStamp</c> element as its time-stamped value directly, and verifies.
    /// </summary>
    [TestMethod]
    public async Task ATimeStampRenewalMayOmitItsHashTree()
    {
        using var world = TimestampingWorld.Create();
        byte[] initial = world.MintInitial([[Digest(FirstDataObject, Sha256)]], Sha256);
        byte[] renewed = world.AppendTimeStampRenewal(initial, includeHashTree: false);

        using XmlEvidenceRecordVerification verification = await VerifyAsync(renewed, [FirstDataObject]).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, verification.Status,
            "Appendix A step 5.a.ii: with no hash tree the time-stamped value must equal the digest of the previous Time-Stamp element.");
    }


    /// <summary>
    /// Clause 4.2.2: a Hash-Tree Renewal starts a NEW chain under the new algorithm whose first <c>Sequence</c>
    /// holds the data-object digests together with the digest of the canonical
    /// <c>ArchiveTimeStampSequence</c> of every preceding chain.
    /// </summary>
    [TestMethod]
    public async Task AHashTreeRenewalStartsANewChainBoundToTheSequenceBeforeIt()
    {
        using var world = TimestampingWorld.Create();
        byte[] initial = world.MintInitial([[Digest(FirstDataObject, Sha256)]], Sha256);
        byte[] renewed = world.AppendHashTreeRenewal(initial, [Digest(FirstDataObject, Sha512)], Sha512);

        using XmlEvidenceRecordVerification verification = await VerifyAsync(renewed, [FirstDataObject]).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, verification.Status, "Both chains verify.");
        Assert.HasCount(2, verification.Chains, "Clause 4.2.2 always creates a new chain, which is what the algorithm change means.");
        Assert.AreEqual(Sha512, verification.Chains[1].DigestAlgorithm, "The new chain names the new algorithm.");
        Assert.AreEqual(XmlEvidenceRecordRenewalKind.HashTreeRenewal, verification.Chains[1].ArchiveTimeStamps[0].RenewalKind,
            "The first member of a succeeding chain came from a Hash-Tree Renewal.");
        Assert.IsTrue(verification.Chains[1].CoversDataObjects, "The renewal re-hashed the data objects under the new algorithm, so the new chain carries them too.");
        Assert.AreEqual(HashTreeRenewalTime, verification.CoveredUntil, "The unbroken run of proofs reaches the renewal.");
    }


    /// <summary>
    /// Both renewals in succession, in the order a preserved archive actually accumulates them, and every member
    /// still verifies.
    /// </summary>
    [TestMethod]
    public async Task BothRenewalsInSuccessionStillProveTheDataObject()
    {
        using var world = TimestampingWorld.Create();
        byte[] initial = world.MintInitial([[Digest(FirstDataObject, Sha256)]], Sha256);
        byte[] afterTimeStampRenewal = world.AppendTimeStampRenewal(initial);
        byte[] afterHashTreeRenewal = world.AppendHashTreeRenewal(afterTimeStampRenewal, [Digest(FirstDataObject, Sha512)], Sha512);

        using XmlEvidenceRecordVerification verification = await VerifyAsync(afterHashTreeRenewal, [FirstDataObject]).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, verification.Status, "Every member of both chains verifies.");
        Assert.HasCount(2, verification.Chains, "One Time-Stamp Renewal and one Hash-Tree Renewal leave two chains.");
        Assert.HasCount(2, verification.Chains[0].ArchiveTimeStamps, "The first chain grew by the Time-Stamp Renewal.");
        Assert.HasCount(1, verification.Chains[1].ArchiveTimeStamps, "The second chain starts at Order 1.");
        Assert.AreEqual(InitialArchiveTime, verification.InitialArchiveTime, "The instant proved is still the initial Archive Time-Stamp's.");
    }


    /// <summary>
    /// Clause 4.1.1: "When algorithms used by a TSA are changed a new ATSC MUST be started using an equal or
    /// stronger digest algorithm." A renewal into a weaker one defeats the purpose the renewal had.
    /// </summary>
    [TestMethod]
    public async Task AHashTreeRenewalIntoAWeakerAlgorithmIsRefused()
    {
        using var world = TimestampingWorld.Create();
        byte[] initial = world.MintInitial([[Digest(FirstDataObject, Sha512)]], Sha512);
        byte[] renewed = world.AppendHashTreeRenewal(initial, [Digest(FirstDataObject, Sha256)], Sha256);

        using XmlEvidenceRecordVerification verification = await VerifyAsync(renewed, [FirstDataObject]).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.ChainAlgorithmWeakened, verification.Status,
            "Clause 4.1.1 makes the succeeding chain's algorithm equal or stronger, and a shorter digest is strictly weaker.");
    }


    /// <summary>
    /// The canonicalization axis stated as a property: a document whose octets differ but whose information set
    /// does not reaches the same conclusion, because every value an Evidence Record hashes about itself is taken
    /// over a canonical form rather than over the octets as they sit.
    /// </summary>
    [TestMethod]
    public async Task TheSameInformationSetSerialisedDifferentlyReachesTheSameConclusion()
    {
        using var world = TimestampingWorld.Create();
        byte[] initial = world.MintInitial([[Digest(FirstDataObject, Sha256)]], Sha256);
        byte[] renewed = world.AppendTimeStampRenewal(initial);
        byte[] respelled = RespellFirstTokenCharacterAsCharacterReference(renewed);

        Assert.AreNotEqual(Convert.ToBase64String(renewed), Convert.ToBase64String(respelled), "The two documents differ octet for octet.");

        using XmlEvidenceRecordVerification original = await VerifyAsync(renewed, [FirstDataObject]).ConfigureAwait(false);
        using XmlEvidenceRecordVerification variant = await VerifyAsync(respelled, [FirstDataObject]).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, original.Status, "The document as minted verifies.");
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, variant.Status,
            "A character reference is the same character after parsing, and canonicalization writes it back as that character — so the Time-Stamp Renewal's linkage still holds.");
    }


    /// <summary>
    /// The prefix a document declares its namespace under is not part of what an element means: a record written
    /// with another prefix verifies unchanged.
    /// </summary>
    [TestMethod]
    public async Task TheNamespacePrefixTheDocumentUsesChangesNothing()
    {
        using var world = TimestampingWorld.Create();
        byte[] document = world.MintInitial([[Digest(FirstDataObject, Sha256)]], Sha256, prefix: "e");

        Assert.Contains("xmlns:e=", Encoding.UTF8.GetString(document), StringComparison.Ordinal, "The document really does declare another prefix.");

        using XmlEvidenceRecordVerification verification = await VerifyAsync(document, [FirstDataObject]).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, verification.Status, "Elements are matched by namespace and local name, never by prefix.");
    }


    /// <summary>
    /// Clause 3.3 step 4: with no hash tree the archive object has to be a single data object. A group and no
    /// hash tree is a shape that proves nothing, and it is refused for that reason rather than for a mismatch.
    /// </summary>
    [TestMethod]
    public async Task AGroupWithNoHashTreeIsRefusedForTheMissingTree()
    {
        using var world = TimestampingWorld.Create();
        byte[] document = world.MintInitial([], Sha256, timestampedValueWhenNoHashTree: Digest(FirstDataObject, Sha256));

        using XmlEvidenceRecordVerification single = await VerifyAsync(document, [FirstDataObject]).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, single.Status,
            "Appendix A step 5.a.iii: one data object whose digest IS the time-stamped value needs no hash tree.");

        using XmlEvidenceRecordVerification group = await VerifyAsync(document, [FirstDataObject, SecondDataObject]).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.HashTreeMissing, group.Status,
            "Clause 3.3 step 4: an archive object with more data objects and no hash tree exits with a negative result.");
    }


    /// <summary>
    /// Clause 4.1.1: "Within a single ATSC, the digest algorithms used for the hash trees of its Archive
    /// Time-Stamps and the Time-Stamp Tokens MUST be the same." A token stating another algorithm binds a value
    /// the recomputed root is not even comparable with.
    /// </summary>
    [TestMethod]
    public async Task ATokenStatingAnotherAlgorithmThanItsChainIsRefused()
    {
        using var world = TimestampingWorld.Create();
        byte[] document = world.MintInitial([[Digest(FirstDataObject, Sha256)]], Sha256, tokenImprintAlgorithm: Sha512);

        using XmlEvidenceRecordVerification verification = await VerifyAsync(document, [FirstDataObject]).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.RootMismatch, verification.Status,
            "A root under one algorithm and an imprint under another are not comparable, which is the negative result reached one step earlier.");
    }


    /// <summary>
    /// Clause 3.1.2 registers two time-stamp formats and this library reads one. A record carrying the other is
    /// refused for its format rather than reported as unproved.
    /// </summary>
    [TestMethod]
    public async Task ATimeStampFormatThisLibraryDoesNotReadIsNamedAsSuch()
    {
        using var world = TimestampingWorld.Create();
        byte[] document = world.MintInitial([[Digest(FirstDataObject, Sha256)]], Sha256);
        byte[] respelled = Replace(document, "Type=\"RFC3161\"", "Type=\"XMLENTRUST\"");

        using XmlEvidenceRecordVerification verification = await VerifyAsync(respelled, [FirstDataObject]).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.UnsupportedTimeStampFormat, verification.Status,
            "Clause 3.1.2's other registered format is recognised by name and refused, never guessed at.");
    }


    /// <summary>
    /// One changed octet of a data object leaves the record proving nothing about it.
    /// </summary>
    [TestMethod]
    public async Task AChangedDataObjectIsNoLongerProved()
    {
        using var world = TimestampingWorld.Create();
        byte[] document = world.MintInitial([[Digest(FirstDataObject, Sha256)]], Sha256);
        byte[] changed = [.. FirstDataObject];
        changed[0] ^= 0x01;

        using XmlEvidenceRecordVerification verification = await VerifyAsync(document, [changed]).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.DataObjectNotCovered, verification.Status,
            "The changed object's hash value is not the one the first Sequence holds.");
    }


    /// <summary>
    /// One changed hash value inside the tree leaves the recomputed root different from what the token binds.
    /// </summary>
    [TestMethod]
    public async Task AChangedHashValueInsideTheTreeBreaksTheRoot()
    {
        using var world = TimestampingWorld.Create();
        byte[] sibling = Digest(SecondDataObject, Sha256);
        byte[] document = world.MintInitial([[Digest(FirstDataObject, Sha256)], [sibling]], Sha256);
        byte[] changed = XmlEvidenceRecordTestFactory.ReplaceDigestValue(
            document, Convert.ToBase64String(sibling), Convert.ToBase64String(Digest(ThirdDataObject, Sha256)));

        using XmlEvidenceRecordVerification verification = await VerifyAsync(changed, [FirstDataObject]).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.RootMismatch, verification.Status,
            "Appendix A step 5.b.ii: the calculated root hash value no longer matches the time-stamped value.");
    }


    /// <summary>
    /// Clause 5: a record carrying <c>EncryptionInformation</c> requires the data objects to be re-encrypted
    /// before its hash values mean anything, and this library refuses rather than verifying against octets that
    /// are not what the record covers.
    /// </summary>
    [TestMethod]
    public async Task ARecordStatingEncryptionInformationIsRefused()
    {
        using var world = TimestampingWorld.Create();
        byte[] document = world.MintInitial([[Digest(FirstDataObject, Sha256)]], Sha256);
        byte[] encrypted = Replace(
            document,
            "<ers:ArchiveTimeStampSequence>",
            "<ers:EncryptionInformation><ers:EncryptionInformationType>1.2.3</ers:EncryptionInformationType><ers:EncryptionInformationValue /></ers:EncryptionInformation><ers:ArchiveTimeStampSequence>");

        using XmlEvidenceRecordVerification verification = await VerifyAsync(encrypted, [FirstDataObject]).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.EncryptionInformationPresent, verification.Status,
            "Clause 5's re-encryption step is one this library cannot perform, so the record is refused with the reason.");
    }


    /// <summary>
    /// Clause 4.1.2: "Canonicalization MUST be applied over XML structured archive data." An archived XML
    /// document is proved by the canonical form of its information set, not by the octets it happens to be stored
    /// as, and the flag on the data object is what says so.
    /// </summary>
    [TestMethod]
    public async Task XmlArchiveDataIsProvedThroughItsCanonicalForm()
    {
        using var world = TimestampingWorld.Create();
        //Neither of these is its own canonical form: exclusive canonicalization drops the namespace declaration
        //nothing visibly utilises, sorts the attributes and writes an empty element as a start and an end tag.
        byte[] archived = Encoding.UTF8.GetBytes(
            "<root xmlns=\"urn:example:archive\" xmlns:unused=\"urn:example:unused\"><item b=\"2\" a=\"1\"/></root>");
        byte[] respelled = Encoding.UTF8.GetBytes(
            "<root xmlns:unused=\"urn:example:unused\" xmlns=\"urn:example:archive\"><item   a=\"1\"   b=\"2\"></item></root>");
        byte[] canonical = XmlEvidenceRecordOracle.CanonicalizeArchiveData(archived, ExclusiveCanonicalization);
        byte[] document = world.MintInitial([[EvidenceRecordOracle.Hash(canonical, Sha256)]], Sha256);

        using XmlEvidenceRecordVerification asStored = await VerifyAsync(document, [archived]).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.DataObjectNotCovered, asStored.Status,
            "Hashing XML archive data as it sits reaches a value the record does not carry, which is the defect clause 4.1.2 exists to rule out.");

        using XmlEvidenceRecordVerification canonicalized = await VerifyAsync(document, [archived], xmlArchiveData: true).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, canonicalized.Status,
            "Canonicalized under the chain's own method, the archived document's hash value is the one the record carries.");

        using XmlEvidenceRecordVerification variant = await VerifyAsync(document, [respelled], xmlArchiveData: true).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, variant.Status,
            "And a different serialisation of the same information set is proved by the same record, which is the whole point of the canonicalization axis.");
    }


    /// <summary>
    /// Parses a document through the staged binding and verifies it through the shipped surface.
    /// </summary>
    /// <param name="document">The Evidence Record document's octets.</param>
    /// <param name="dataObjects">The archive object's data objects.</param>
    /// <param name="requireExclusivity">Whether Appendix A step 5.b's second direction is performed.</param>
    /// <param name="xmlArchiveData">Whether the data objects are XML that clause 4.1.2 canonicalizes before hashing.</param>
    /// <returns>The conclusion, which the caller disposes.</returns>
    private async Task<XmlEvidenceRecordVerification> VerifyAsync(
        byte[] document,
        byte[][] dataObjects,
        bool requireExclusivity = true,
        bool xmlArchiveData = false)
    {
        using XmlEvidenceRecordParseResult parsed = await XmlEvidenceRecordXmlBinding.ParseAsync(
            new XmlEvidenceRecordParseContext { Document = document }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parsed.IsValid, $"The document has to parse before it can be verified ({parsed.Status}: {parsed.FailureReason}).");

        var objects = new List<XmlEvidenceRecordDataObject>(dataObjects.Length);
        for(int i = 0; i < dataObjects.Length; ++i)
        {
            objects.Add(new XmlEvidenceRecordDataObject { Content = dataObjects[i], IsXmlArchiveData = xmlArchiveData });
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


    /// <summary>Computes one digest through the independent oracle.</summary>
    /// <param name="content">The octets to hash.</param>
    /// <param name="algorithm">The algorithm.</param>
    /// <returns>The digest octets.</returns>
    private static byte[] Digest(byte[] content, PkiDigestAlgorithm algorithm) => EvidenceRecordOracle.Hash(content, algorithm);


    /// <summary>Computes the digests of several data objects through the independent oracle.</summary>
    /// <param name="contents">The data objects.</param>
    /// <param name="algorithm">The algorithm.</param>
    /// <returns>The digests, in the order the objects arrived.</returns>
    private static byte[][] Digests(byte[][] contents, PkiDigestAlgorithm algorithm)
    {
        var digests = new byte[contents.Length][];
        for(int i = 0; i < contents.Length; ++i)
        {
            digests[i] = EvidenceRecordOracle.Hash(contents[i], algorithm);
        }

        return digests;
    }


    /// <summary>Replaces the first occurrence of a substring in a document's UTF-8 text.</summary>
    /// <param name="document">The document's octets.</param>
    /// <param name="original">The text to replace.</param>
    /// <param name="replacement">The text to write in its place.</param>
    /// <returns>The changed document's octets.</returns>
    private static byte[] Replace(byte[] document, string original, string replacement)
    {
        string text = Encoding.UTF8.GetString(document);
        int at = text.IndexOf(original, StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, at, $"The document has to carry '{original}' for the case to mean anything.");

        return Encoding.UTF8.GetBytes(string.Concat(text.AsSpan(0, at), replacement, text.AsSpan(at + original.Length)));
    }


    /// <summary>
    /// Respells the first character of the first time-stamp token's base64 as a numeric character reference,
    /// which changes the document's octets and leaves its information set exactly as it was.
    /// </summary>
    /// <param name="document">The document's octets.</param>
    /// <returns>The changed document's octets.</returns>
    private static byte[] RespellFirstTokenCharacterAsCharacterReference(byte[] document)
    {
        string text = Encoding.UTF8.GetString(document);
        const string Opening = "Type=\"RFC3161\">";
        int at = text.IndexOf(Opening, StringComparison.Ordinal) + Opening.Length;
        char first = text[at];

        return Encoding.UTF8.GetBytes(string.Concat(
            text.AsSpan(0, at),
            $"&#{(int)first};",
            text.AsSpan(at + 1)));
    }


    /// <summary>
    /// The minting world every test of this class shares: a root certification authority and the Time-Stamping
    /// Authority under it that every token comes from.
    /// </summary>
    private sealed class TimestampingWorld: IDisposable
    {
        /// <summary>The carriers this world minted, released in reverse order.</summary>
        private readonly List<IDisposable> owned = [];

        /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
        private bool disposed;


        /// <summary>The Time-Stamping Authority node every token is minted by.</summary>
        public X509ChainTestRingNode Authority { get; private set; } = null!;

        /// <summary>The certificates every token carries.</summary>
        public IReadOnlyList<X509ChainTestRingNode> Chain { get; private set; } = null!;


        /// <summary>Mints the world.</summary>
        /// <returns>The world, which the caller disposes.</returns>
        public static TimestampingWorld Create()
        {
            var world = new TimestampingWorld();
            try
            {
                var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
                X509ChainTestRingNode root = world.Own(X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter));
                world.Authority = world.Own(X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter));
                world.Chain = [world.Authority, root];

                return world;
            }
            catch
            {
                world.Dispose();

                throw;
            }
        }


        /// <summary>Mints a document carrying one chain with one Archive Time-Stamp.</summary>
        /// <param name="hashTree">The sequences to write, leaf list first.</param>
        /// <param name="algorithm">The algorithm the chain names.</param>
        /// <param name="timestampedValueWhenNoHashTree">The value the token binds when the tree is empty.</param>
        /// <param name="prefix">The namespace prefix to declare.</param>
        /// <param name="tokenImprintAlgorithm">The algorithm the token's imprint is stated under, when deliberately not the chain's.</param>
        /// <returns>The document's octets.</returns>
        public byte[] MintInitial(
            IReadOnlyList<IReadOnlyList<byte[]>> hashTree,
            PkiDigestAlgorithm algorithm,
            byte[]? timestampedValueWhenNoHashTree = null,
            string? prefix = null,
            PkiDigestAlgorithm? tokenImprintAlgorithm = null) =>
            XmlEvidenceRecordTestFactory.MintInitial(
                hashTree, algorithm, ExclusiveCanonicalization, Authority, Chain, InitialArchiveTime,
                timestampedValueWhenNoHashTree, prefix, comment: null, tokenImprintAlgorithm);


        /// <summary>Appends a Time-Stamp Renewal to a document's last chain.</summary>
        /// <param name="document">The document to renew.</param>
        /// <param name="includeHashTree">Whether to write a hash tree at all.</param>
        /// <returns>The renewed document's octets.</returns>
        public byte[] AppendTimeStampRenewal(byte[] document, bool includeHashTree = true) =>
            XmlEvidenceRecordTestFactory.AppendTimestampRenewal(
                document, Authority, Chain, TimeStampRenewalTime, siblingLevels: null, includeHashTree);


        /// <summary>Appends a Hash-Tree Renewal to a document.</summary>
        /// <param name="document">The document to renew.</param>
        /// <param name="dataObjectDigests">The data objects' digests under the new algorithm.</param>
        /// <param name="algorithm">The new algorithm.</param>
        /// <returns>The renewed document's octets.</returns>
        public byte[] AppendHashTreeRenewal(byte[] document, IReadOnlyList<byte[]> dataObjectDigests, PkiDigestAlgorithm algorithm) =>
            XmlEvidenceRecordTestFactory.AppendHashTreeRenewal(
                document, dataObjectDigests, algorithm, ExclusiveCanonicalization, Authority, Chain, HashTreeRenewalTime);


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
}
