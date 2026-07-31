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


    /// <summary>
    /// An initial Evidence Record over a single data object verifies against that object, and states the
    /// archive time the acquired token asserts.
    /// </summary>
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
}
