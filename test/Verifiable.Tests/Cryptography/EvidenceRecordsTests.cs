using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="EvidenceRecords"/>: creating the initial Evidence Record of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-3.2">IETF RFC 4998 clause 3.2</see> over one data
/// object and over data object groups, and verifying it back per
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.3">clause 4.3</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.3">clause 5.3</see>.
/// </summary>
/// <remarks>
/// <para>
/// Every record here is minted by the shipped creation surface and then checked twice: once by the shipped
/// verification surface, and once by <see cref="EvidenceRecordOracle"/> — an independent decoder and an
/// independent Merkle recomputation written from the clause text, hashing through a different digest
/// implementation. The oracle reads the record's octets, recomputes the root from the reduced hash tree it
/// finds there, and compares it with the message imprint of the token the record carries, which is a fact about
/// what crossed the wire rather than about the objects the library built.
/// </para>
/// <para>
/// Time-stamp tokens come from a <see cref="MintingTimestampResponder"/>, which answers the request octets that
/// crossed the transport seam by minting a genuine token over the imprint they state, so the acquisition path
/// runs end to end without a network.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EvidenceRecordsTests
{
    /// <summary>The address handed to the transport delegate; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.evidencerecord.example.test/";


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The <c>genTime</c> every minted archive time-stamp states.</summary>
    private static DateTimeOffset ArchiveTime { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The algorithm every record in this class is built under.</summary>
    private static PkiDigestAlgorithm Algorithm { get; } = PkiDigestAlgorithm.Sha256;

    /// <summary>The first synthetic attribute type of <see cref="TheAttributesSetIsWrittenInCanonicalOrderAndReadInWhateverOrderItArrives"/>, whose encoding sorts before the other's.</summary>
    private const string LowerAttributeType = "1.2.3.4";

    /// <summary>The second synthetic attribute type, whose encoding sorts after <see cref="LowerAttributeType"/>'s: the two differ in exactly the last content octet of the object identifier, so the DER <c>SET OF</c> order is decided there and nowhere else.</summary>
    private const string HigherAttributeType = "1.2.3.5";

    /// <summary>The synthetic <c>encryptionInfoType</c> of <see cref="ARecordStatingEncryptionInfoIsRefusedRatherThanVerified"/>. Clause 6 registers no algorithm at all, so any value here is one no verifier could act on, which is the point of the case.</summary>
    private const string EncryptionInfoType = "1.2.3.6";

    /// <summary>The data object <see cref="AVersionBelowOneIsRefused"/>, <see cref="TheAttributesSetIsWrittenInCanonicalOrderAndReadInWhateverOrderItArrives"/>, <see cref="ARecordStatingEncryptionInfoIsRefusedRatherThanVerified"/> and <see cref="AChainWhoseMembersNameDifferentAlgorithmsIsRefused"/> archive through <see cref="CreateInitialAsync"/>.</summary>
    private static byte[] DataObject { get; } = [.. "the archived data object of the Evidence Record requirements matrix"u8];


    /// <summary>
    /// An initial Evidence Record over a single data object verifies against that object, and states the
    /// archive time the acquired token asserts.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> rfc4998-4.1-R8,
    /// rfc4998-4.3-R16, rfc4998-5.3-R39.
    /// </remarks>
    [TestMethod]
    public async Task AnInitialRecordOverOneDataObjectVerifies()
    {
        byte[] dataObject = [.. "the single archived data object"u8];
        using EvidenceRecordCreation creation = await CreateAsync([[dataObject]]).ConfigureAwait(false);

        Assert.HasCount(1, creation.EvidenceRecords);
        Assert.AreEqual(ArchiveTime, creation.ArchiveTime);

        using EvidenceRecordVerification verification = await VerifyAsync(creation.EvidenceRecords[0], dataObject, []).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Status);
        Assert.AreEqual(ArchiveTime, verification.InitialArchiveTime);
        Assert.AreEqual(ArchiveTime, verification.LatestArchiveTime);
        Assert.HasCount(1, verification.Chains);
        Assert.IsTrue(verification.Chains[0].CoversDataObject);
        Assert.AreEqual(AlgorithmIdentifier.Sha256, verification.Chains[0].DigestAlgorithm);
    }


    /// <summary>
    /// The record the library writes states the root an independent build of the same tree reaches, and that
    /// root is what the embedded token's message imprint binds — checked by decoding the record's own octets
    /// with the independent decoder rather than by asking the library what it wrote.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> rfc4998-4.2-R12a, rfc4998-4.3-R19.
    /// </remarks>
    [TestMethod]
    public async Task TheRecordStatesTheRootTheIndependentBuildReaches()
    {
        byte[][] group1 = [[.. "d1"u8]];
        byte[][] group2 = [[.. "d2a"u8], [.. "d2b"u8], [.. "d2c"u8]];
        byte[][] group3 = [[.. "d3"u8]];
        using EvidenceRecordCreation creation = await CreateAsync([group1, group2, group3]).ConfigureAwait(false);

        byte[] expectedRoot = EvidenceRecordOracle.BuildRoot([group1, group2, group3], Algorithm, EvidenceRecordHashTree.DefaultNodeArity);
        byte[][][] groups = [group1, group2, group3];

        for(int groupIndex = 0; groupIndex < groups.Length; ++groupIndex)
        {
            OracleEvidenceRecord parsed = EvidenceRecordOracle.ParseEvidenceRecord(creation.EvidenceRecords[groupIndex].AsReadOnlySpan().ToArray());
            Assert.AreEqual(1, parsed.Version, "RFC 4998 clause 3.1 defines v1(1).");
            Assert.HasCount(1, parsed.Chains);
            Assert.HasCount(1, parsed.Chains[0]);

            OracleArchiveTimeStamp archiveTimeStamp = parsed.Chains[0][0];
            Assert.AreEqual(Algorithm.Identifier.Oid, archiveTimeStamp.MessageImprintAlgorithmOid);
            Assert.IsTrue(
                archiveTimeStamp.MessageImprint.AsSpan().SequenceEqual(expectedRoot),
                "The embedded token binds the root of the tree the independent build reaches.");

            byte[] dataObjectHash = EvidenceRecordOracle.Hash(groups[groupIndex][0], Algorithm);
            byte[]? recomputed = EvidenceRecordOracle.RecomputeRoot(dataObjectHash, archiveTimeStamp.ReducedHashtree, Algorithm);
            Assert.IsNotNull(recomputed, "The independent walk reaches a root from the record's own reduced hash tree.");
            Assert.IsTrue(recomputed.AsSpan().SequenceEqual(expectedRoot), "The independent walk reaches the same root.");
        }
    }


    /// <summary>
    /// One tree over several groups produces one record per group, each verifying against any of its own data
    /// objects and none of another group's — the "centralized" mode of clause 3.2 where one time-stamp binds
    /// many archived objects.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> rfc4998-4.3-R20, rfc4998-5.3-R47.
    /// </remarks>
    [TestMethod]
    public async Task OneTreeOverSeveralGroupsProducesOneRecordPerGroup()
    {
        byte[][] group1 = [[.. "first group's only object"u8]];
        byte[][] group2 = [[.. "second group, first object"u8], [.. "second group, second object"u8]];
        byte[][] group3 = [[.. "third group's only object"u8]];
        using EvidenceRecordCreation creation = await CreateAsync([group1, group2, group3]).ConfigureAwait(false);

        Assert.HasCount(3, creation.EvidenceRecords);

        using(EvidenceRecordVerification first = await VerifyAsync(creation.EvidenceRecords[0], group1[0], []).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, first.Status);
        }

        using(EvidenceRecordVerification secondMemberA = await VerifyAsync(creation.EvidenceRecords[1], group2[0], []).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, secondMemberA.Status, "Every member of a group is proved by that group's record.");
        }

        using(EvidenceRecordVerification secondMemberB = await VerifyAsync(creation.EvidenceRecords[1], group2[1], []).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, secondMemberB.Status);
        }

        using(EvidenceRecordVerification third = await VerifyAsync(creation.EvidenceRecords[2], group3[0], []).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, third.Status);
        }

        using(EvidenceRecordVerification crossed = await VerifyAsync(creation.EvidenceRecords[0], group3[0], []).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.DataObjectNotCovered, crossed.Status, "A record proves its own group and no other.");
        }
    }


    /// <summary>
    /// The additional group proof of clause 4.3 — "only the hash values of the given data objects are in the
    /// first hash-value list" — holds for the group a record was created for and fails for a group with a
    /// member the record does not bind.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> rfc4998-4.3-R21, rfc4998-5.3-R48.
    /// </remarks>
    [TestMethod]
    public async Task TheGroupProofHoldsForTheGroupTheRecordWasCreatedFor()
    {
        byte[][] group = [[.. "group member one"u8], [.. "group member two"u8], [.. "group member three"u8]];
        using EvidenceRecordCreation creation = await CreateAsync([group]).ConfigureAwait(false);

        var claimedGroup = new List<ReadOnlyMemory<byte>>();
        for(int i = 0; i < group.Length; ++i)
        {
            claimedGroup.Add(new ReadOnlyMemory<byte>(group[i]));
        }

        using(EvidenceRecordVerification exact = await VerifyAsync(creation.EvidenceRecords[0], group[0], claimedGroup).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, exact.Status);
        }

        var widerGroup = new List<ReadOnlyMemory<byte>>(claimedGroup) { new([.. "an object the record never bound"u8]) };
        using(EvidenceRecordVerification wider = await VerifyAsync(creation.EvidenceRecords[0], group[0], widerGroup).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.DataObjectGroupNotCoveredExclusively, wider.Status);
        }
    }


    /// <summary>
    /// A data object that differs from the archived one in a single octet is not covered: step 2 of clause 4.3
    /// terminates the walk rather than reaching some other root.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> rfc4998-4.3-R17.
    /// </remarks>
    [TestMethod]
    public async Task ATamperedDataObjectIsNotCovered()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        using EvidenceRecordCreation creation = await CreateAsync([[dataObject]]).ConfigureAwait(false);

        byte[] tampered = [.. dataObject];
        tampered[^1] ^= 0x01;

        using EvidenceRecordVerification verification = await VerifyAsync(creation.EvidenceRecords[0], tampered, []).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordVerificationStatus.DataObjectNotCovered, verification.Status);
        Assert.IsFalse(verification.Chains[0].CoversDataObject);
    }


    /// <summary>
    /// A record read back from the octets a record was written as is the same record: the same octets, the same
    /// version, the same algorithms and the same structure. Clause 5.2's Hash-Tree Renewal hashes prior chains
    /// as they are encoded, so a round trip that re-encoded anything would break every later renewal.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> rfc4998-2.1-R1.
    /// </remarks>
    [TestMethod]
    public async Task ARecordRoundTripsWithoutChangingItsOctets()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        using EvidenceRecordCreation creation = await CreateAsync([[dataObject]]).ConfigureAwait(false);

        EvidenceRecord written = creation.EvidenceRecords[0];
        using EvidenceRecord read = EvidenceRecord.Read(written.AsReadOnlySpan(), BaseMemoryPool.Shared);

        Assert.AreEqual(written, read);
        Assert.AreEqual(EvidenceRecord.Version1, read.Version);
        Assert.HasCount(1, read.DigestAlgorithms);
        Assert.AreEqual(AlgorithmIdentifier.Sha256, read.DigestAlgorithms[0]);
        Assert.IsEmpty(read.CryptoInfos);
        Assert.IsFalse(read.HasEncryptionInfo);
        Assert.HasCount(1, read.ArchiveTimeStampSequence.Chains);
        Assert.HasCount(1, read.ArchiveTimeStampSequence.Chains[0].ArchiveTimeStamps);

        EvidenceRecordArchiveTimeStamp archiveTimeStamp = read.ArchiveTimeStampSequence.Chains[0].ArchiveTimeStamps[0];
        Assert.IsNull(archiveTimeStamp.DigestAlgorithm, "The field is omitted when the request used the tree's own algorithm (clause 4.2 step 5).");
        Assert.HasCount(1, archiveTimeStamp.ReducedHashtree);
        Assert.IsEmpty(archiveTimeStamp.Attributes);
        Assert.IsFalse(archiveTimeStamp.TimeStamp.IsEmpty);
    }


    /// <summary>
    /// Stating the <c>digestAlgorithm [0]</c> field is the other way clause 4.2 step 5 admits of binding the
    /// tree's algorithm; a record written that way carries the field and still verifies.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> rfc4998-4.1-R6, rfc4998-4.2-R12b.
    /// </remarks>
    [TestMethod]
    public async Task StatingTheDigestAlgorithmFieldIsTheOtherWayToBindTheTreesAlgorithm()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        using EvidenceRecordCreation creation = await CreateAsync([[dataObject]], stateDigestAlgorithmField: true).ConfigureAwait(false);

        EvidenceRecordArchiveTimeStamp archiveTimeStamp =
            creation.EvidenceRecords[0].ArchiveTimeStampSequence.Chains[0].ArchiveTimeStamps[0];
        Assert.AreEqual(AlgorithmIdentifier.Sha256, archiveTimeStamp.DigestAlgorithm);

        using EvidenceRecordVerification verification = await VerifyAsync(creation.EvidenceRecords[0], dataObject, []).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Status);
    }


    /// <summary>
    /// The <c>atsc(i)</c> of clause 5.2 is a complete <c>ArchiveTimeStampSequence</c> element with its own outer
    /// tag and length octets on top of each chain's, not a bare concatenation of chain encodings — the same
    /// whole-element-inclusion rule the clause's own note states.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> rfc4998-5.2-R33.
    /// </remarks>
    [TestMethod]
    public void TheEncodedSequenceWrapsTheChainsInItsOwnElement()
    {
        byte[] firstChain = [0x30, 0x03, 0x02, 0x01, 0x01];
        byte[] secondChain = [0x30, 0x03, 0x02, 0x01, 0x02];

        using PooledMemory sequence = EvidenceRecords.EncodeArchiveTimeStampSequence(
            [new ReadOnlyMemory<byte>(firstChain), new ReadOnlyMemory<byte>(secondChain)], BaseMemoryPool.Shared);

        byte[] encoded = sequence.AsReadOnlySpan().ToArray();
        Assert.HasCount(firstChain.Length + secondChain.Length + 2, encoded, "The wrapper adds exactly its own tag and length octets.");
        Assert.AreEqual((byte)0x30, encoded[0]);
        Assert.AreEqual((byte)(firstChain.Length + secondChain.Length), encoded[1]);
        Assert.IsTrue(encoded.AsSpan(2, firstChain.Length).SequenceEqual(firstChain), "Each chain is written verbatim.");
        Assert.IsTrue(encoded.AsSpan(2 + firstChain.Length, secondChain.Length).SequenceEqual(secondChain));

        var reader = new AsnReader(encoded, AsnEncodingRules.DER);
        AsnReader chains = reader.ReadSequence();
        reader.ThrowIfNotEmpty();
        Assert.IsTrue(chains.HasData, "The wrapper is a SEQUENCE OF whose members are the chains.");
    }


    /// <summary>
    /// RFC 4998 clause 3.1: "An implementation conforming to this specification SHOULD reject a version value
    /// below 1." The floor is enforced where the octets are read, so a record stating a version this
    /// specification never defined never reaches a verifier at all.
    /// </summary>
    /// <remarks>
    /// The same rewrite at the stated floor is read back without complaint, which is what makes the refusal a
    /// statement about the version rather than about the rewriting. No test anywhere in the suite drove this
    /// clause before; it is closed here per the gap discipline. Proves <see
    /// href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> rfc4998-3.1-R2.
    /// </remarks>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AVersionBelowOneIsRefused()
    {
        using EvidenceRecordCreation creation = await CreateInitialAsync().ConfigureAwait(false);
        EvidenceRecord record = creation.EvidenceRecords[0];

        byte[] belowFloor = RewriteVersion(record, 0);
        _ = Assert.ThrowsExactly<AsnContentException>(
            () =>
            {
                using EvidenceRecord refused = EvidenceRecord.Read(belowFloor, BaseMemoryPool.Shared);
            },
            "Clause 3.1 states the floor, and a version below it is refused where the octets are read.");

        byte[] atFloor = RewriteVersion(record, EvidenceRecord.Version1);
        using EvidenceRecord read = EvidenceRecord.Read(atFloor, BaseMemoryPool.Shared);
        Assert.AreEqual(EvidenceRecord.Version1, read.Version, "The same rewrite at the floor is read, so the refusal is the version and not the rewriting.");
        Assert.AreSequenceEqual(
            record.ArchiveTimeStampSequence.Encoding.ToArray(),
            read.ArchiveTimeStampSequence.Encoding.ToArray(),
            "And the rewrite carried the archive time-stamp sequence verbatim, so the two readings differ in nothing else.");
    }


    /// <summary>
    /// RFC 4998 clause 4.1 declares <c>Attributes ::= SET SIZE (1..MAX) OF Attribute</c> and states the reason
    /// as "the ordering is relevant, which is why a SET is used instead of a SEQUENCE" — a rationale inverted
    /// relative to X.690 clause 11.6, under which a DER encoder sorts a <c>SET OF</c> into canonical order and
    /// the author's own order carries nothing. This library therefore writes the canonical order and reads
    /// whatever order arrives, surfacing the members verbatim.
    /// </summary>
    /// <remarks>
    /// The two synthetic attribute types differ in exactly the last content octet of their object identifiers
    /// and carry the same value, so the sort is decided there and by nothing else: supplied high-then-low, they
    /// come back low-then-high. The lenient half is a record whose <c>SET OF</c> was written under BER in the
    /// order a producer chose, which is read back in that order rather than refused. No test drove either half
    /// before. Proves <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> rfc4998-4.1-R7.
    /// </remarks>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task TheAttributesSetIsWrittenInCanonicalOrderAndReadInWhateverOrderItArrives()
    {
        using EvidenceRecordCreation creation = await CreateInitialAsync().ConfigureAwait(false);
        EvidenceRecord record = creation.EvidenceRecords[0];
        EvidenceRecordArchiveTimeStamp member = record.ArchiveTimeStampSequence.Chains[0].ArchiveTimeStamps[0];

        var valueWriter = new AsnWriter(AsnEncodingRules.DER);
        valueWriter.WriteOctetString("an attribute value both types carry"u8);
        byte[] attributeValue = valueWriter.Encode();

        using CmsAttribute lower = CmsAttribute.Create(LowerAttributeType, attributeValue, BaseMemoryPool.Shared);
        using CmsAttribute higher = CmsAttribute.Create(HigherAttributeType, attributeValue, BaseMemoryPool.Shared);

        using PooledMemory written = EvidenceRecords.EncodeArchiveTimeStamp(
            digestAlgorithm: null, [higher, lower], member.ReducedHashtree, member.TimeStamp, BaseMemoryPool.Shared);
        using EvidenceRecord canonical = ReadAsRecord(written.AsReadOnlySpan().ToArray(), record.DigestAlgorithms);
        IReadOnlyList<ReadOnlyMemory<byte>> canonicalAttributes = canonical.ArchiveTimeStampSequence.Chains[0].ArchiveTimeStamps[0].Attributes;

        Assert.HasCount(2, canonicalAttributes, "Both attributes were written.");
        Assert.AreSequenceEqual(lower.AsReadOnlySpan().ToArray(), canonicalAttributes[0].ToArray(),
            "The DER SET OF is written in canonical order however the members were supplied.");
        Assert.AreSequenceEqual(higher.AsReadOnlySpan().ToArray(), canonicalAttributes[1].ToArray());

        byte[] arrivalOrder = WriteArchiveTimeStampWithUnsortedAttributes(member, higher, lower);
        using EvidenceRecord lenient = ReadAsRecord(arrivalOrder, record.DigestAlgorithms);
        IReadOnlyList<ReadOnlyMemory<byte>> arrivedAttributes = lenient.ArchiveTimeStampSequence.Chains[0].ArchiveTimeStamps[0].Attributes;

        Assert.HasCount(2, arrivedAttributes, "A set another producer wrote in its own order is read rather than refused.");
        Assert.AreSequenceEqual(higher.AsReadOnlySpan().ToArray(), arrivedAttributes[0].ToArray(),
            "And its members are surfaced in the order they arrived, because that order is what the clause's rationale claims to carry.");
        Assert.AreSequenceEqual(lower.AsReadOnlySpan().ToArray(), arrivedAttributes[1].ToArray());

        using EvidenceRecordVerification verification = await VerifyAsync(lenient).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Status,
            "Attributes sit beside the reduced hash tree and change nothing the tree proves.");
    }


    /// <summary>
    /// RFC 4998 clause 6 and clause 3.3 step 2: a record carrying an <c>encryptionInfo</c> field requires the
    /// data objects to be re-encrypted before verification, and clause 6 registers no algorithm for the field at
    /// all ("The use of the specified encryptionInfoType and encryptionInfoValue may be heavily dependent on the
    /// mechanisms and has to be defined in other specifications"). The field is therefore recognised and the
    /// record refused, never verified against octets that are not what it covers.
    /// </summary>
    /// <remarks>
    /// The XML sibling's equivalent case is
    /// <see cref="XmlEvidenceRecordsTests.ARecordStatingEncryptionInformationIsRefused"/>; the ASN.1 form had
    /// none. The same record without the field verifies, so the refusal is the field and nothing else. Proves
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> rfc4998-6-R49.
    /// </remarks>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ARecordStatingEncryptionInfoIsRefusedRatherThanVerified()
    {
        using EvidenceRecordCreation creation = await CreateInitialAsync().ConfigureAwait(false);
        EvidenceRecord record = creation.EvidenceRecords[0];

        using EvidenceRecord withoutField = EvidenceRecord.Read(RewriteVersion(record, EvidenceRecord.Version1), BaseMemoryPool.Shared);
        Assert.IsFalse(withoutField.HasEncryptionInfo);
        using EvidenceRecordVerification baseline = await VerifyAsync(withoutField).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, baseline.Status, "The same record without the field verifies.");

        using EvidenceRecord withField = EvidenceRecord.Read(WriteWithEncryptionInfo(record), BaseMemoryPool.Shared);
        Assert.IsTrue(withField.HasEncryptionInfo, "The optional [1] field is recognised where the octets are read.");
        Assert.IsFalse(withField.EncryptionInfo.IsEmpty, "And its whole encoding is surfaced, so a caller can state what it refused.");

        using EvidenceRecordVerification refused = await VerifyAsync(withField).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordVerificationStatus.EncryptionInfoPresent, refused.Status,
            "Clause 3.3 step 2 requires re-encryption this library cannot perform, so the record is refused rather than verified against the wrong octets.");
        Assert.IsEmpty(refused.Chains, "Nothing is concluded about a chain whose covered octets could not be reconstructed.");
    }


    /// <summary>
    /// RFC 4998 clause 5.1: "Within an ArchiveTimeStampChain, all reducedHashtrees of the contained
    /// ArchiveTimeStamps MUST use the same Hash-Algorithm", restated as step 2 c) of clause 5.3 for the verifier.
    /// A chain whose second member names another algorithm is refused for that reason and for no other.
    /// </summary>
    /// <remarks>
    /// The shipped creation surface cannot produce such a chain — an algorithm change starts a new chain
    /// (<see cref="EvidenceRecordRenewalTests.AHashTreeRenewalStartsANewChainUnderTheNewAlgorithm"/>) and a
    /// mixed batch is refused
    /// (<see cref="EvidenceRecordRenewalTests.RenewingRecordsOfDifferentAlgorithmsTogetherIsRefused"/>) — so the
    /// verifier's own check had no test. The chain here is spliced from two independently minted records over
    /// the same data object, one under SHA-256 and one under SHA-512, each stating its algorithm in the
    /// <c>digestAlgorithm [0]</c> field. Proves <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC
    /// 4998</see> rfc4998-5.1-R24, rfc4998-5.3-R42.
    /// </remarks>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AChainWhoseMembersNameDifferentAlgorithmsIsRefused()
    {
        using EvidenceRecordCreation underSha256 = await CreateInitialAsync(PkiDigestAlgorithm.Sha256, stateDigestAlgorithmField: true).ConfigureAwait(false);
        using EvidenceRecordCreation underSha512 = await CreateInitialAsync(PkiDigestAlgorithm.Sha512, stateDigestAlgorithmField: true).ConfigureAwait(false);

        ReadOnlyMemory<byte> first = underSha256.EvidenceRecords[0].ArchiveTimeStampSequence.Chains[0].ArchiveTimeStamps[0].Encoding;
        ReadOnlyMemory<byte> second = underSha512.EvidenceRecords[0].ArchiveTimeStampSequence.Chains[0].ArchiveTimeStamps[0].Encoding;

        using PooledMemory chain = EvidenceRecords.EncodeArchiveTimeStampChain([first, second], BaseMemoryPool.Shared);
        using EvidenceRecord spliced = EvidenceRecord.Create(
            [AlgorithmIdentifier.Sha256], cryptoInfos: null, [chain.AsReadOnlyMemory()], BaseMemoryPool.Shared);

        using EvidenceRecordVerification verification = await VerifyAsync(spliced).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordVerificationStatus.ChainAlgorithmInconsistent, verification.Status);
        Assert.HasCount(1, verification.Chains);
        Assert.AreEqual(EvidenceRecordVerificationStatus.ChainAlgorithmInconsistent, verification.Chains[0].Status);
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Chains[0].ArchiveTimeStamps[0].Status,
            "The first member is a genuine initial Archive Timestamp and verifies, so the chain's refusal is the second member alone.");
        Assert.AreEqual(EvidenceRecordVerificationStatus.ChainAlgorithmInconsistent, verification.Chains[0].ArchiveTimeStamps[1].Status);
        Assert.AreEqual(AlgorithmIdentifier.Sha512, verification.Chains[0].ArchiveTimeStamps[1].DigestAlgorithm,
            "And the algorithm the refused member named is reported, because that is the fact the clause is about.");
    }


    /// <summary>
    /// Creates an initial Evidence Record over the supplied groups through the shipped surface, against a
    /// Time-Stamping Authority that mints a genuine token over whatever imprint the request states.
    /// </summary>
    /// <param name="groups">The data object groups, each a list of data object octets.</param>
    /// <param name="stateDigestAlgorithmField">Whether the produced structures carry the <c>digestAlgorithm [0]</c> field.</param>
    /// <returns>The creation result. The caller disposes it.</returns>
    private async ValueTask<EvidenceRecordCreation> CreateAsync(IReadOnlyList<byte[][]> groups, bool stateDigestAlgorithmField = false)
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
                FetchTimestampResponse = responder.FetchAsync,
                StateDigestAlgorithmField = stateDigestAlgorithmField
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies a record against a data object through the shipped surface.
    /// </summary>
    /// <param name="evidenceRecord">The record to verify.</param>
    /// <param name="dataObject">The data object it is claimed to prove.</param>
    /// <param name="dataObjectGroup">The group to check exclusivity for, or an empty list to skip that check.</param>
    /// <returns>The conclusion. The caller disposes it.</returns>
    private async ValueTask<EvidenceRecordVerification> VerifyAsync(
        EvidenceRecord evidenceRecord,
        byte[] dataObject,
        IReadOnlyList<ReadOnlyMemory<byte>> dataObjectGroup)
    {
        return await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext
            {
                EvidenceRecord = evidenceRecord,
                DataObject = new ReadOnlyMemory<byte>(dataObject),
                DataObjectGroup = dataObjectGroup
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Creates an initial Evidence Record over <see cref="DataObject"/> through the shipped surface, against a
    /// Time-Stamping Authority that mints a genuine token over whatever imprint the request states.
    /// </summary>
    /// <param name="algorithm">The algorithm the tree and the acquisition are built under.</param>
    /// <param name="stateDigestAlgorithmField">Whether the produced structure carries the <c>digestAlgorithm [0]</c> field.</param>
    /// <returns>The creation result. The caller owns and disposes it.</returns>
    private async ValueTask<EvidenceRecordCreation> CreateInitialAsync(PkiDigestAlgorithm? algorithm = null, bool stateDigestAlgorithmField = false)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        var responder = new MintingTimestampResponder(authority, [authority, root], ArchiveTime);

        return await EvidenceRecords.CreateInitialAsync(
            new EvidenceRecordCreationContext
            {
                DataObjectGroups = [new EvidenceRecordDataObjectGroup { DataObjects = [new ReadOnlyMemory<byte>(DataObject)] }],
                DigestAlgorithm = algorithm ?? PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchTimestampResponse = responder.FetchAsync,
                StateDigestAlgorithmField = stateDigestAlgorithmField
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Verifies a record against <see cref="DataObject"/> through the shipped surface.</summary>
    /// <param name="evidenceRecord">The record to verify.</param>
    /// <returns>The conclusion. The caller owns and disposes it.</returns>
    private async ValueTask<EvidenceRecordVerification> VerifyAsync(EvidenceRecord evidenceRecord) =>
        await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext
            {
                EvidenceRecord = evidenceRecord,
                DataObject = new ReadOnlyMemory<byte>(DataObject),
                DataObjectGroup = []
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// Rewrites a record with another <c>version</c> value, carrying its digest algorithms and its whole archive
    /// time-stamp sequence across verbatim so that the version is the only thing that changed.
    /// </summary>
    /// <param name="record">The record to rewrite.</param>
    /// <param name="version">The <c>version</c> value to state.</param>
    /// <returns>The rewritten record's octets.</returns>
    private static byte[] RewriteVersion(EvidenceRecord record, int version)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteInteger(version);
            WriteDigestAlgorithms(writer, record.DigestAlgorithms);
            writer.WriteEncodedValue(record.ArchiveTimeStampSequence.Encoding.Span);
        }

        return writer.Encode();
    }


    /// <summary>
    /// Rewrites a record with an <c>encryptionInfo [1]</c> field, which the shipped creation surface never emits
    /// because clause 6 registers no algorithm for it.
    /// </summary>
    /// <param name="record">The record to rewrite.</param>
    /// <returns>The rewritten record's octets.</returns>
    private static byte[] WriteWithEncryptionInfo(EvidenceRecord record)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteInteger(EvidenceRecord.Version1);
            WriteDigestAlgorithms(writer, record.DigestAlgorithms);

            //EncryptionInfo ::= SEQUENCE {encryptionInfoType OBJECT IDENTIFIER, encryptionInfoValue ANY DEFINED
            //BY encryptionInfoType}, carried under the implicit [1] tag of the Appendix B module.
            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                writer.WriteObjectIdentifier(EncryptionInfoType);
                writer.WriteOctetString("the parameters of a mechanism another specification would define"u8);
            }

            writer.WriteEncodedValue(record.ArchiveTimeStampSequence.Encoding.Span);
        }

        return writer.Encode();
    }


    /// <summary>
    /// Writes one <c>ArchiveTimeStamp</c> whose <c>attributes [1]</c> set holds its members in the order they are
    /// supplied rather than in the canonical order a DER encoder imposes — what a record another producer wrote
    /// looks like on the read path.
    /// </summary>
    /// <param name="member">The Archive Timestamp whose reduced hash tree and time-stamp are carried across.</param>
    /// <param name="first">The attribute to write first.</param>
    /// <param name="second">The attribute to write second.</param>
    /// <returns>The written structure's octets.</returns>
    private static byte[] WriteArchiveTimeStampWithUnsortedAttributes(EvidenceRecordArchiveTimeStamp member, CmsAttribute first, CmsAttribute second)
    {
        //BER rather than DER precisely because DER would sort the set and the case would assert nothing.
        var writer = new AsnWriter(AsnEncodingRules.BER);
        using(writer.PushSequence())
        {
            using(writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                writer.WriteEncodedValue(first.AsReadOnlySpan());
                writer.WriteEncodedValue(second.AsReadOnlySpan());
            }

            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                for(int i = 0; i < member.ReducedHashtree.Count; ++i)
                {
                    using(writer.PushSequence())
                    {
                        IReadOnlyList<ReadOnlyMemory<byte>> hashValues = member.ReducedHashtree[i].HashValues;
                        for(int j = 0; j < hashValues.Count; ++j)
                        {
                            writer.WriteOctetString(hashValues[j].Span);
                        }
                    }
                }
            }

            writer.WriteEncodedValue(member.TimeStamp.Span);
        }

        return writer.Encode();
    }


    /// <summary>
    /// Wraps one written <c>ArchiveTimeStamp</c> in a chain and a record, so that it can be read back through the
    /// shipped decoder.
    /// </summary>
    /// <param name="archiveTimeStamp">The whole encoding of the structure to wrap.</param>
    /// <param name="digestAlgorithms">The algorithms the record names.</param>
    /// <returns>The read record. The caller owns and disposes it.</returns>
    private static EvidenceRecord ReadAsRecord(byte[] archiveTimeStamp, IReadOnlyList<AlgorithmIdentifier> digestAlgorithms)
    {
        using PooledMemory chain = EvidenceRecords.EncodeArchiveTimeStampChain([new ReadOnlyMemory<byte>(archiveTimeStamp)], BaseMemoryPool.Shared);
        using EvidenceRecord created = EvidenceRecord.Create(digestAlgorithms, cryptoInfos: null, [chain.AsReadOnlyMemory()], BaseMemoryPool.Shared);

        return EvidenceRecord.Read(created.AsReadOnlySpan(), BaseMemoryPool.Shared);
    }


    /// <summary>Writes the <c>digestAlgorithms</c> field, each identifier with its parameters omitted per IETF RFC 5754 clause 2.</summary>
    /// <param name="writer">The writer to write into.</param>
    /// <param name="digestAlgorithms">The identifiers to write.</param>
    private static void WriteDigestAlgorithms(AsnWriter writer, IReadOnlyList<AlgorithmIdentifier> digestAlgorithms)
    {
        using(writer.PushSequence())
        {
            for(int i = 0; i < digestAlgorithms.Count; ++i)
            {
                using(writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(digestAlgorithms[i].Oid);
                }
            }
        }
    }
}
