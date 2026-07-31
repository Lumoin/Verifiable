using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for the two renewal procedures of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.2">IETF RFC 4998 clause 5.2</see>:
/// <see cref="EvidenceRecords.RenewTimestampAsync"/>, which re-timestamps a record's most recent Archive
/// Timestamp into the same chain, and <see cref="EvidenceRecords.RenewHashTreeAsync"/>, which re-hashes the data
/// objects and every prior chain under a new algorithm into a new chain.
/// </summary>
/// <remarks>
/// <para>
/// Every renewed record is checked twice: once by the shipped verification surface, and once by
/// <see cref="EvidenceRecordOracle"/>, which recomputes both renewal formulas from the clause text through a
/// different digest implementation and decodes the produced octets with its own reader. What the tests assert is
/// therefore a fact about the octets that were written, not about the objects the library held while writing
/// them.
/// </para>
/// <para>
/// The preservation properties are asserted structurally rather than by re-verification alone: a renewal writes
/// every Archive Timestamp it did not create back octet for octet, because clause 5.2's Hash-Tree Renewal hashes
/// those octets and a re-encoding would silently break every renewal built on top.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EvidenceRecordRenewalTests
{
    /// <summary>The address handed to the transport delegate; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.evidencerecord.example.test/";


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The <c>genTime</c> the initial Archive Timestamp of every record in this class states.</summary>
    private static DateTimeOffset InitialArchiveTime { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The <c>genTime</c> the Timestamp Renewal of this class states.</summary>
    private static DateTimeOffset TimestampRenewalTime { get; } = TestClock.CanonicalEpoch.AddHours(2);

    /// <summary>The <c>genTime</c> the Hash-Tree Renewal of this class states.</summary>
    private static DateTimeOffset HashTreeRenewalTime { get; } = TestClock.CanonicalEpoch.AddHours(3);

    /// <summary>The algorithm the initial Archive Timestamp of every record in this class is built under.</summary>
    private static PkiDigestAlgorithm InitialAlgorithm { get; } = PkiDigestAlgorithm.Sha256;

    /// <summary>The algorithm the Hash-Tree Renewal of this class selects, which is not <see cref="InitialAlgorithm"/>.</summary>
    private static PkiDigestAlgorithm RenewalAlgorithm { get; } = PkiDigestAlgorithm.Sha512;


    /// <summary>
    /// A Timestamp Renewal appends to the chain the record already carries rather than starting a new one, keeps
    /// the record's stated algorithms unchanged, and leaves the Archive Timestamp it renewed octet for octet as
    /// it found it.
    /// </summary>
    [TestMethod]
    public async Task ATimestampRenewalAppendsToTheChainItRenews()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        using EvidenceRecordCreation creation = await CreateAsync([[dataObject]], InitialAlgorithm, InitialArchiveTime).ConfigureAwait(false);
        using EvidenceRecordRenewal renewal = await RenewTimestampAsync([creation.EvidenceRecords[0]], TimestampRenewalTime).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordRenewalKind.TimestampRenewal, renewal.Kind);
        Assert.AreEqual(TimestampRenewalTime, renewal.ArchiveTime);
        Assert.HasCount(1, renewal.EvidenceRecords);

        EvidenceRecord source = creation.EvidenceRecords[0];
        EvidenceRecord renewed = renewal.EvidenceRecords[0];
        Assert.HasCount(1, renewed.ArchiveTimeStampSequence.Chains, "Clause 5.2: the new Archive Timestamp MUST be added to the ArchiveTimestampChain, not to a new one.");
        Assert.HasCount(2, renewed.ArchiveTimeStampSequence.Chains[0].ArchiveTimeStamps);
        Assert.HasCount(1, renewed.DigestAlgorithms, "A Timestamp Renewal does not change the algorithm, so it names no new one.");
        Assert.AreEqual(AlgorithmIdentifier.Sha256, renewed.DigestAlgorithms[0]);

        Assert.IsTrue(
            renewed.ArchiveTimeStampSequence.Chains[0].ArchiveTimeStamps[0].Encoding.Span.SequenceEqual(
                source.ArchiveTimeStampSequence.Chains[0].ArchiveTimeStamps[0].Encoding.Span),
            "The renewed Archive Timestamp is written back exactly as it was read.");

        using EvidenceRecordVerification verification = await VerifyAsync(renewed, dataObject).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Status);
        Assert.AreEqual(InitialArchiveTime, verification.InitialArchiveTime);
        Assert.AreEqual(TimestampRenewalTime, verification.LatestArchiveTime);
        Assert.AreEqual(TimestampRenewalTime, verification.CoveredUntil, "The data object is carried by an unbroken run of proofs to the renewal.");
    }


    /// <summary>
    /// The value a Timestamp Renewal places in the new Archive Timestamp's first list is the hash of the whole
    /// <c>timeStamp</c> element of the Archive Timestamp before it, recomputed here by the independent oracle
    /// from the octets the record was written as.
    /// </summary>
    [TestMethod]
    public async Task ATimestampRenewalBindsTheWholeTimeStampElementOfTheStructureBeforeIt()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        using EvidenceRecordCreation creation = await CreateAsync([[dataObject]], InitialAlgorithm, InitialArchiveTime).ConfigureAwait(false);
        using EvidenceRecordRenewal renewal = await RenewTimestampAsync([creation.EvidenceRecords[0]], TimestampRenewalTime).ConfigureAwait(false);

        OracleEvidenceRecord parsed = EvidenceRecordOracle.ParseEvidenceRecord(renewal.EvidenceRecords[0].AsReadOnlySpan().ToArray());
        Assert.HasCount(1, parsed.Chains);
        Assert.HasCount(2, parsed.Chains[0]);

        OracleArchiveTimeStamp initial = parsed.Chains[0][0];
        OracleArchiveTimeStamp renewed = parsed.Chains[0][1];
        byte[] expected = EvidenceRecordOracle.TimestampRenewalValue(initial.TimeStampEncoding, InitialAlgorithm);
        Assert.IsTrue(
            EvidenceRecordOracle.ContainsValue(renewed.ReducedHashtree[0], expected),
            "Clause 5.3 step 2: the first hash value list holds the hash of the timestamp of the Archive Timestamp before.");

        byte[]? root = EvidenceRecordOracle.RecomputeRoot(expected, renewed.ReducedHashtree, InitialAlgorithm);
        Assert.IsNotNull(root);
        Assert.IsTrue(root.AsSpan().SequenceEqual(renewed.MessageImprint), "The renewal's own token binds the root that value walks to.");
    }


    /// <summary>
    /// A Hash-Tree Renewal starts a new chain under the new algorithm, names that algorithm in the record, and
    /// carries every chain the record already held forward octet for octet.
    /// </summary>
    [TestMethod]
    public async Task AHashTreeRenewalStartsANewChainUnderTheNewAlgorithm()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        using EvidenceRecordCreation creation = await CreateAsync([[dataObject]], InitialAlgorithm, InitialArchiveTime).ConfigureAwait(false);
        using EvidenceRecordRenewal renewal = await RenewHashTreeAsync(
            [(creation.EvidenceRecords[0], [dataObject])], RenewalAlgorithm, HashTreeRenewalTime).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordRenewalKind.HashTreeRenewal, renewal.Kind);

        EvidenceRecord source = creation.EvidenceRecords[0];
        EvidenceRecord renewed = renewal.EvidenceRecords[0];
        Assert.HasCount(2, renewed.ArchiveTimeStampSequence.Chains);
        Assert.HasCount(1, renewed.ArchiveTimeStampSequence.Chains[1].ArchiveTimeStamps, "Clause 5.2 step 6 creates a new chain containing the new Archive Timestamp.");
        Assert.HasCount(2, renewed.DigestAlgorithms);
        Assert.AreEqual(AlgorithmIdentifier.Sha256, renewed.DigestAlgorithms[0]);
        Assert.AreEqual(AlgorithmIdentifier.Sha512, renewed.DigestAlgorithms[1]);

        Assert.IsTrue(
            renewed.ArchiveTimeStampSequence.Chains[0].Encoding.Span.SequenceEqual(source.ArchiveTimeStampSequence.Chains[0].Encoding.Span),
            "The chain the renewal hashes as atsc is the chain it writes back, octet for octet.");

        using EvidenceRecordVerification verification = await VerifyAsync(renewed, dataObject).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Status);
        Assert.HasCount(2, verification.Chains);
        Assert.AreEqual(AlgorithmIdentifier.Sha256, verification.Chains[0].DigestAlgorithm, "Verification resolves each chain's own algorithm.");
        Assert.AreEqual(AlgorithmIdentifier.Sha512, verification.Chains[1].DigestAlgorithm);
        Assert.IsTrue(verification.Chains[0].CoversDataObject);
        Assert.IsTrue(verification.Chains[1].CoversDataObject);
        Assert.AreEqual(HashTreeRenewalTime, verification.CoveredUntil);
    }


    /// <summary>
    /// The value a Hash-Tree Renewal places in the new chain's first list is the positional combination of
    /// clause 5.2 step 4, recomputed here by the independent oracle from the octets the record was written as.
    /// </summary>
    [TestMethod]
    public async Task AHashTreeRenewalBindsThePositionalCombinationOfTheDataObjectAndThePriorSequence()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        using EvidenceRecordCreation creation = await CreateAsync([[dataObject]], InitialAlgorithm, InitialArchiveTime).ConfigureAwait(false);
        using EvidenceRecordRenewal renewal = await RenewHashTreeAsync(
            [(creation.EvidenceRecords[0], [dataObject])], RenewalAlgorithm, HashTreeRenewalTime).ConfigureAwait(false);

        OracleEvidenceRecord parsed = EvidenceRecordOracle.ParseEvidenceRecord(renewal.EvidenceRecords[0].AsReadOnlySpan().ToArray());
        Assert.HasCount(2, parsed.Chains);

        OracleArchiveTimeStamp renewed = parsed.Chains[1][0];
        byte[] positional = EvidenceRecordOracle.HashTreeRenewalValue(dataObject, [parsed.ChainEncodings[0]], RenewalAlgorithm);
        Assert.IsTrue(
            EvidenceRecordOracle.ContainsValue(renewed.ReducedHashtree[0], positional),
            "Clause 5.2 step 4: h(i)' = H(h(i) + ha(i)), the data object's hash first and the encoded prior sequence's second.");

        byte[]? root = EvidenceRecordOracle.RecomputeRoot(positional, renewed.ReducedHashtree, RenewalAlgorithm);
        Assert.IsNotNull(root);
        Assert.IsTrue(root.AsSpan().SequenceEqual(renewed.MessageImprint));
    }


    /// <summary>
    /// Where the two readings of clause 5.2 step 4 genuinely differ — the step-4 prose concatenating the pair
    /// positionally, the worked example of Figure 4 sorting it first — the value this library computes is the
    /// prose's. The inputs are searched for rather than fixed, because the two readings coincide for roughly
    /// half of all pairs and a fixed pair might be one of those.
    /// </summary>
    [TestMethod]
    public async Task TheRenewalCombinationIsThePositionalReadingWhereTheTwoReadingsDiffer()
    {
        //A stand-in for a prior chain: any well-formed element serves, because what step 3 hashes is the octets
        //of the sequence that wraps it, not anything it means.
        byte[] priorChain = [0x30, 0x03, 0x02, 0x01, 0x01];
        for(int counter = 0; counter < 64; ++counter)
        {
            byte[] dataObject = [.. "renewal candidate "u8, (byte)counter];

            byte[] positional = EvidenceRecordOracle.HashTreeRenewalValue(dataObject, [priorChain], RenewalAlgorithm);
            byte[] sorted = EvidenceRecordOracle.HashTreeRenewalValueSorted(dataObject, [priorChain], RenewalAlgorithm);
            if(positional.AsSpan().SequenceEqual(sorted))
            {
                continue;
            }

            byte[] encodedSequence = EvidenceRecordOracle.EncodeArchiveTimeStampSequence([priorChain]);
            using DigestValue computed = await EvidenceRecords.ComputeHashTreeRenewalValueAsync(
                new ReadOnlyMemory<byte>(dataObject),
                new ReadOnlyMemory<byte>(encodedSequence),
                RenewalAlgorithm,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(
                computed.AsReadOnlySpan()[..RenewalAlgorithm.OutputByteLength].SequenceEqual(positional),
                "The library computes the value clause 5.2 step 4's own formula states.");
            Assert.IsFalse(
                computed.AsReadOnlySpan()[..RenewalAlgorithm.OutputByteLength].SequenceEqual(sorted),
                "It is not the value the worked example of Figure 4 states, which this pair shows to be a different value.");

            return;
        }

        Assert.Fail("No pair was found for which the two readings of clause 5.2 step 4 differ, which they do for roughly half of all pairs.");
    }


    /// <summary>
    /// After both renewals in succession, every chain of the resulting record still verifies, the record the
    /// renewals were produced from still verifies exactly as it did, and every Archive Timestamp the renewals
    /// did not create is present octet for octet.
    /// </summary>
    [TestMethod]
    public async Task EveryPriorChainStillVerifiesAfterEachRenewal()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        using EvidenceRecordCreation creation = await CreateAsync([[dataObject]], InitialAlgorithm, InitialArchiveTime).ConfigureAwait(false);
        using EvidenceRecordRenewal timestampRenewal = await RenewTimestampAsync([creation.EvidenceRecords[0]], TimestampRenewalTime).ConfigureAwait(false);
        using EvidenceRecordRenewal hashTreeRenewal = await RenewHashTreeAsync(
            [(timestampRenewal.EvidenceRecords[0], [dataObject])], RenewalAlgorithm, HashTreeRenewalTime).ConfigureAwait(false);

        EvidenceRecord initial = creation.EvidenceRecords[0];
        EvidenceRecord afterTimestamp = timestampRenewal.EvidenceRecords[0];
        EvidenceRecord afterHashTree = hashTreeRenewal.EvidenceRecords[0];

        using(EvidenceRecordVerification original = await VerifyAsync(initial, dataObject).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, original.Status, "A renewal renews the protection; it does not invalidate the record it was produced from.");
            Assert.AreEqual(InitialArchiveTime, original.CoveredUntil);
        }

        using(EvidenceRecordVerification intermediate = await VerifyAsync(afterTimestamp, dataObject).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, intermediate.Status);
            Assert.AreEqual(TimestampRenewalTime, intermediate.CoveredUntil);
        }

        using EvidenceRecordVerification final = await VerifyAsync(afterHashTree, dataObject).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, final.Status);
        Assert.HasCount(2, final.Chains);
        Assert.IsTrue(final.Chains[0].CoversDataObject);
        Assert.IsTrue(final.Chains[1].CoversDataObject);
        Assert.AreEqual(HashTreeRenewalTime, final.CoveredUntil);

        Assert.IsTrue(
            afterHashTree.ArchiveTimeStampSequence.Chains[0].Encoding.Span.SequenceEqual(afterTimestamp.ArchiveTimeStampSequence.Chains[0].Encoding.Span),
            "The Hash-Tree Renewal wrote the whole chain it hashed back verbatim.");
        Assert.IsTrue(
            afterTimestamp.ArchiveTimeStampSequence.Chains[0].ArchiveTimeStamps[0].Encoding.Span.SequenceEqual(
                initial.ArchiveTimeStampSequence.Chains[0].ArchiveTimeStamps[0].Encoding.Span),
            "The Timestamp Renewal wrote the Archive Timestamp it renewed back verbatim.");
    }


    /// <summary>
    /// Changing one octet of a data object a renewed record covers leaves that record proving nothing about the
    /// changed octets: the walk of clause 4.3 step 2 terminates at the first list of the very first Archive
    /// Timestamp.
    /// </summary>
    [TestMethod]
    public async Task ChangingACoveredOctetLeavesTheRenewedRecordProvingNothing()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        using EvidenceRecordCreation creation = await CreateAsync([[dataObject]], InitialAlgorithm, InitialArchiveTime).ConfigureAwait(false);
        using EvidenceRecordRenewal renewal = await RenewHashTreeAsync(
            [(creation.EvidenceRecords[0], [dataObject])], RenewalAlgorithm, HashTreeRenewalTime).ConfigureAwait(false);

        byte[] changed = [.. dataObject];
        changed[^1] ^= 0x01;

        using EvidenceRecordVerification verification = await VerifyAsync(renewal.EvidenceRecords[0], changed).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordVerificationStatus.DataObjectNotCovered, verification.Status);
        Assert.IsFalse(verification.Chains[0].CoversDataObject);
        Assert.IsFalse(verification.Chains[1].CoversDataObject);
        Assert.IsNull(verification.CoveredUntil, "Nothing proves the changed octets, not even the initial Archive Timestamp.");
    }


    /// <summary>
    /// Changing one octet of a prior chain leaves the renewed record proving nothing about the data object at
    /// all. Every octet of a chain is reached by something: the chain's own reduced hash tree and its token's
    /// signature cover its interior, and the encoded sequence a later chain hashes covers all of it.
    /// </summary>
    [TestMethod]
    public async Task ChangingAPriorChainOctetLeavesTheRenewedRecordProvingNothing()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        using EvidenceRecordCreation creation = await CreateAsync([[dataObject]], InitialAlgorithm, InitialArchiveTime).ConfigureAwait(false);
        using EvidenceRecordRenewal renewal = await RenewHashTreeAsync(
            [(creation.EvidenceRecords[0], [dataObject])], RenewalAlgorithm, HashTreeRenewalTime).ConfigureAwait(false);

        EvidenceRecord renewed = renewal.EvidenceRecords[0];
        byte[] octets = renewed.AsReadOnlySpan().ToArray();
        byte[] firstChain = renewed.ArchiveTimeStampSequence.Chains[0].Encoding.ToArray();
        int offset = octets.AsSpan().IndexOf(firstChain);
        Assert.IsGreaterThanOrEqualTo(0, offset, "The chain's octets are part of the record's octets.");

        //The last octet of the chain sits deep inside its time-stamp token, so changing it leaves every tag and
        //length octet of the structure intact and the record is read back rather than rejected as malformed.
        octets[offset + firstChain.Length - 1] ^= 0x01;

        using EvidenceRecord damaged = EvidenceRecord.Read(octets, BaseMemoryPool.Shared);
        using EvidenceRecordVerification verification = await VerifyAsync(damaged, dataObject).ConfigureAwait(false);

        Assert.AreNotEqual(EvidenceRecordVerificationStatus.Verified, verification.Status);
        Assert.IsFalse(verification.Chains[0].CoversDataObject);
        Assert.IsFalse(verification.Chains[1].CoversDataObject, "What the second chain hashed as atsc is no longer what the record carries.");
        Assert.IsNull(verification.CoveredUntil);
    }


    /// <summary>
    /// Replacing a prior chain with a different chain that proves the same data object just as well breaks the
    /// link the new chain makes to it. The renewal bound the octets of the chain that was there, not the claim
    /// that some valid chain was — which is the whole content of clause 5.2 step 3's <c>atsc(i)</c>.
    /// </summary>
    [TestMethod]
    public async Task ReplacingAPriorChainWithAnEquallyValidOneBreaksTheLink()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        using EvidenceRecordCreation renewedFrom = await CreateAsync([[dataObject]], InitialAlgorithm, InitialArchiveTime).ConfigureAwait(false);
        using EvidenceRecordCreation substitute = await CreateAsync([[dataObject]], InitialAlgorithm, InitialArchiveTime).ConfigureAwait(false);
        using EvidenceRecordRenewal renewal = await RenewHashTreeAsync(
            [(renewedFrom.EvidenceRecords[0], [dataObject])], RenewalAlgorithm, HashTreeRenewalTime).ConfigureAwait(false);

        EvidenceRecord renewed = renewal.EvidenceRecords[0];
        using(EvidenceRecordVerification substituteOnItsOwn = await VerifyAsync(substitute.EvidenceRecords[0], dataObject).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, substituteOnItsOwn.Status, "The chain about to be substituted in proves the data object on its own.");
        }

        using EvidenceRecord spliced = EvidenceRecord.Create(
            renewed.DigestAlgorithms,
            cryptoInfos: null,
            [substitute.EvidenceRecords[0].ArchiveTimeStampSequence.Chains[0].Encoding, renewed.ArchiveTimeStampSequence.Chains[1].Encoding],
            BaseMemoryPool.Shared);

        using EvidenceRecordVerification verification = await VerifyAsync(spliced, dataObject).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordVerificationStatus.ChainLinkageBroken, verification.Status);
        Assert.IsTrue(verification.Chains[0].CoversDataObject, "The substituted chain is a genuine proof of the data object.");
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Chains[0].Status);
        Assert.IsFalse(verification.Chains[1].CoversDataObject);
        Assert.AreEqual(EvidenceRecordVerificationStatus.ChainLinkageBroken, verification.Chains[1].Status);
        Assert.AreEqual(InitialArchiveTime, verification.CoveredUntil, "The unbroken run of proofs ends where the link does.");
    }


    /// <summary>
    /// A data object left out of a Hash-Tree Renewal is proved only up to the chain that last carried it, which
    /// is what clause 5.2 step 2's "objects that are still present and not deleted" leaves behind, and the
    /// record says nothing at all about it thereafter — while its group companion is proved to the renewal.
    /// </summary>
    [TestMethod]
    public async Task ADataObjectLeftOutOfARenewalIsProvedOnlyToTheChainThatCarriedIt()
    {
        byte[] kept = [.. "the data object that is still present"u8];
        byte[] deleted = [.. "the data object that was deleted"u8];
        using EvidenceRecordCreation creation = await CreateAsync([[kept, deleted]], InitialAlgorithm, InitialArchiveTime).ConfigureAwait(false);
        using EvidenceRecordRenewal renewal = await RenewHashTreeAsync(
            [(creation.EvidenceRecords[0], [kept])], RenewalAlgorithm, HashTreeRenewalTime).ConfigureAwait(false);

        EvidenceRecord renewed = renewal.EvidenceRecords[0];

        using(EvidenceRecordVerification stillPresent = await VerifyAsync(renewed, kept).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, stillPresent.Status);
            Assert.AreEqual(HashTreeRenewalTime, stillPresent.CoveredUntil);
        }

        using EvidenceRecordVerification dropped = await VerifyAsync(renewed, deleted).ConfigureAwait(false);
        Assert.AreNotEqual(EvidenceRecordVerificationStatus.Verified, dropped.Status);
        Assert.HasCount(2, dropped.Chains);
        Assert.IsTrue(dropped.Chains[0].CoversDataObject, "Coverage is a per-chain property; the first chain still proves what it always proved.");
        Assert.IsFalse(dropped.Chains[1].CoversDataObject);
        Assert.AreEqual(InitialArchiveTime, dropped.CoveredUntil, "The proof reaches the chain that carried the object and stops there.");
    }


    /// <summary>
    /// The departure clause 5.2 step 5 makes from the reduction of clause 4.2: when one Hash-Tree Renewal renews
    /// several records at once, each renewed record's FIRST hash value list holds that record's own
    /// <c>h(i)'</c> and nothing else — "The first hash value list in the reduced hash tree should only contain
    /// h(i)'". The other records' renewal values are level-zero siblings in the shared tree, so they belong in
    /// the list after it, which is where the walk of clause 4.3 meets them; a first list holding them would make
    /// the Archive Timestamp relate, in the sense clause 1.3 defines, to data objects it proves nothing about,
    /// and would defeat the additional group proof clause 4.3 closes with.
    /// </summary>
    [TestMethod]
    public async Task ABatchedHashTreeRenewalGivesEachRecordAFirstListHoldingItsOwnRenewalValueAlone()
    {
        byte[] first = [.. "the first record's data object"u8];
        byte[] second = [.. "the second record's data object"u8];
        using EvidenceRecordCreation creation = await CreateAsync([[first], [second]], InitialAlgorithm, InitialArchiveTime).ConfigureAwait(false);
        using EvidenceRecordRenewal renewal = await RenewHashTreeAsync(
            [(creation.EvidenceRecords[0], [first]), (creation.EvidenceRecords[1], [second])], RenewalAlgorithm, HashTreeRenewalTime).ConfigureAwait(false);

        Assert.HasCount(2, renewal.EvidenceRecords);

        OracleEvidenceRecord parsedFirst = EvidenceRecordOracle.ParseEvidenceRecord(renewal.EvidenceRecords[0].AsReadOnlySpan().ToArray());
        OracleEvidenceRecord parsedSecond = EvidenceRecordOracle.ParseEvidenceRecord(renewal.EvidenceRecords[1].AsReadOnlySpan().ToArray());
        byte[] firstRenewalValue = EvidenceRecordOracle.HashTreeRenewalValue(first, [parsedFirst.ChainEncodings[0]], RenewalAlgorithm);
        byte[] secondRenewalValue = EvidenceRecordOracle.HashTreeRenewalValue(second, [parsedSecond.ChainEncodings[0]], RenewalAlgorithm);

        OracleArchiveTimeStamp firstRenewed = parsedFirst.Chains[1][0];
        OracleArchiveTimeStamp secondRenewed = parsedSecond.Chains[1][0];

        Assert.HasCount(1, firstRenewed.ReducedHashtree[0], "Clause 5.2 step 5: the first hash value list of a single-document group holds h(i)' alone.");
        Assert.IsTrue(firstRenewed.ReducedHashtree[0][0].AsSpan().SequenceEqual(firstRenewalValue), "And the one value it holds is that record's own renewal value.");
        Assert.HasCount(1, secondRenewed.ReducedHashtree[0]);
        Assert.IsTrue(secondRenewed.ReducedHashtree[0][0].AsSpan().SequenceEqual(secondRenewalValue));

        Assert.IsFalse(
            EvidenceRecordOracle.ContainsValue(firstRenewed.ReducedHashtree[0], secondRenewalValue),
            "The other record's renewal value is derived from another archive object and another prior sequence, so it is not in this record's first list.");
        Assert.IsFalse(EvidenceRecordOracle.ContainsValue(secondRenewed.ReducedHashtree[0], firstRenewalValue));

        //The value is not lost, it is one level up: the batch's tree does bind the two records together, and the
        //list after the first is where clause 4.3's walk inserts the value it just computed and meets the sibling.
        Assert.HasCount(2, firstRenewed.ReducedHashtree, "The extra level clause 5.2 step 5 needs is the level the siblings are carried on.");
        Assert.IsTrue(
            EvidenceRecordOracle.ContainsValue(firstRenewed.ReducedHashtree[1], secondRenewalValue),
            "The sibling value the reduction leaves out of the first list is in the next one.");
        Assert.IsTrue(EvidenceRecordOracle.ContainsValue(secondRenewed.ReducedHashtree[1], firstRenewalValue));

        byte[]? firstRoot = EvidenceRecordOracle.RecomputeRoot(firstRenewalValue, firstRenewed.ReducedHashtree, RenewalAlgorithm);
        Assert.IsNotNull(firstRoot);
        Assert.IsTrue(firstRoot.AsSpan().SequenceEqual(firstRenewed.MessageImprint), "The reduced tree still walks to the root the batch's one token binds.");

        byte[]? secondRoot = EvidenceRecordOracle.RecomputeRoot(secondRenewalValue, secondRenewed.ReducedHashtree, RenewalAlgorithm);
        Assert.IsNotNull(secondRoot);
        Assert.IsTrue(secondRoot.AsSpan().SequenceEqual(secondRenewed.MessageImprint));
        Assert.IsTrue(firstRenewed.MessageImprint.AsSpan().SequenceEqual(secondRenewed.MessageImprint), "One tree, one root, one time-stamp — the batched shape of clause 5.2.");

        using(EvidenceRecordVerification firstRecord = await VerifyAsync(renewal.EvidenceRecords[0], first).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, firstRecord.Status);
            Assert.AreEqual(HashTreeRenewalTime, firstRecord.CoveredUntil);
        }

        using EvidenceRecordVerification secondRecord = await VerifyAsync(renewal.EvidenceRecords[1], second).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, secondRecord.Status);
        Assert.AreEqual(HashTreeRenewalTime, secondRecord.CoveredUntil);
    }


    /// <summary>
    /// The multi-document half of the same sentence of clause 5.2 step 5 — "For a multi-document group, the
    /// first hash value list will contain the new hashes for all the documents in this group, i.e., h(i_a)',
    /// h(i_b)'.., h(i_n)'" — asserted where it can be told apart from the reduction of clause 4.2: a batch
    /// renewing a two-document group beside a one-document record gives the group a first list of exactly its own
    /// two renewal values, the other record's value excluded.
    /// </summary>
    [TestMethod]
    public async Task ABatchedRenewalOfAMultiDocumentGroupGivesItAFirstListOfExactlyItsOwnValues()
    {
        byte[] groupMemberA = [.. "the group's first data object"u8];
        byte[] groupMemberB = [.. "the group's second data object"u8];
        byte[] lone = [.. "the other record's only data object"u8];
        using EvidenceRecordCreation creation = await CreateAsync(
            [[groupMemberA, groupMemberB], [lone]], InitialAlgorithm, InitialArchiveTime).ConfigureAwait(false);
        using EvidenceRecordRenewal renewal = await RenewHashTreeAsync(
            [(creation.EvidenceRecords[0], [groupMemberA, groupMemberB]), (creation.EvidenceRecords[1], [lone])],
            RenewalAlgorithm,
            HashTreeRenewalTime).ConfigureAwait(false);

        OracleEvidenceRecord parsedGroup = EvidenceRecordOracle.ParseEvidenceRecord(renewal.EvidenceRecords[0].AsReadOnlySpan().ToArray());
        OracleEvidenceRecord parsedLone = EvidenceRecordOracle.ParseEvidenceRecord(renewal.EvidenceRecords[1].AsReadOnlySpan().ToArray());
        byte[] renewalValueA = EvidenceRecordOracle.HashTreeRenewalValue(groupMemberA, [parsedGroup.ChainEncodings[0]], RenewalAlgorithm);
        byte[] renewalValueB = EvidenceRecordOracle.HashTreeRenewalValue(groupMemberB, [parsedGroup.ChainEncodings[0]], RenewalAlgorithm);
        byte[] loneRenewalValue = EvidenceRecordOracle.HashTreeRenewalValue(lone, [parsedLone.ChainEncodings[0]], RenewalAlgorithm);

        List<byte[]> firstList = parsedGroup.Chains[1][0].ReducedHashtree[0];
        Assert.HasCount(2, firstList, "The group holds two documents, so its first list holds two new hashes and no more.");
        Assert.IsTrue(EvidenceRecordOracle.ContainsValue(firstList, renewalValueA));
        Assert.IsTrue(EvidenceRecordOracle.ContainsValue(firstList, renewalValueB));
        Assert.IsFalse(EvidenceRecordOracle.ContainsValue(firstList, loneRenewalValue), "The other record's renewal value is not a document of this group.");
        Assert.HasCount(1, parsedLone.Chains[1][0].ReducedHashtree[0], "And the one-document record beside it keeps its own singleton first list.");

        using(EvidenceRecordVerification memberA = await VerifyAsync(renewal.EvidenceRecords[0], groupMemberA).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, memberA.Status, "Every member of the group is still proved by the group's record.");
        }

        using EvidenceRecordVerification memberB = await VerifyAsync(renewal.EvidenceRecords[0], groupMemberB).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, memberB.Status);
    }


    /// <summary>
    /// Several records are renewed by one Timestamp Renewal, which clause 5.2 sanctions outright, and each of
    /// them comes back proving its own data object and none of another's.
    /// </summary>
    [TestMethod]
    public async Task SeveralRecordsAreRenewedTogetherByOneTimestampRenewal()
    {
        byte[] first = [.. "the first record's data object"u8];
        byte[] second = [.. "the second record's data object"u8];
        using EvidenceRecordCreation creation = await CreateAsync([[first], [second]], InitialAlgorithm, InitialArchiveTime).ConfigureAwait(false);
        using EvidenceRecordRenewal renewal = await RenewTimestampAsync(
            [creation.EvidenceRecords[0], creation.EvidenceRecords[1]], TimestampRenewalTime).ConfigureAwait(false);

        Assert.HasCount(2, renewal.EvidenceRecords);

        using(EvidenceRecordVerification firstRecord = await VerifyAsync(renewal.EvidenceRecords[0], first).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, firstRecord.Status);
            Assert.AreEqual(TimestampRenewalTime, firstRecord.CoveredUntil);
        }

        using(EvidenceRecordVerification secondRecord = await VerifyAsync(renewal.EvidenceRecords[1], second).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, secondRecord.Status);
        }

        byte[] neverArchived = [.. "a data object no record ever bound"u8];
        using EvidenceRecordVerification unbound = await VerifyAsync(renewal.EvidenceRecords[0], neverArchived).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordVerificationStatus.DataObjectNotCovered, unbound.Status, "A renewed record proves what its source proved and nothing more.");
        Assert.IsNull(unbound.CoveredUntil);
    }


    /// <summary>
    /// Renewing records whose chains resolve to different hash algorithms in one Timestamp Renewal is refused:
    /// clause 5.2 binds the new hash tree to "the same hash algorithm as the old one", and one tree cannot
    /// satisfy that for two algorithms at once.
    /// </summary>
    [TestMethod]
    public async Task RenewingRecordsOfDifferentAlgorithmsTogetherIsRefused()
    {
        byte[] first = [.. "a record under one algorithm"u8];
        byte[] second = [.. "a record under another algorithm"u8];
        using EvidenceRecordCreation underSha256 = await CreateAsync([[first]], PkiDigestAlgorithm.Sha256, InitialArchiveTime).ConfigureAwait(false);
        using EvidenceRecordCreation underSha512 = await CreateAsync([[second]], PkiDigestAlgorithm.Sha512, InitialArchiveTime).ConfigureAwait(false);

        EvidenceRecordCreationException exception = await Assert.ThrowsExactlyAsync<EvidenceRecordCreationException>(
            async () => await RenewTimestampAsync(
                [underSha256.EvidenceRecords[0], underSha512.EvidenceRecords[0]], TimestampRenewalTime).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordCreationFailureKind.RenewalAlgorithmMismatch, exception.FailureKind);
    }


    /// <summary>
    /// A renewal whose acquired time-stamp asserts an instant before the Archive Timestamp it renews is refused
    /// rather than written: clause 5.1 requires an <c>ArchiveTimeStampChain</c> and an
    /// <c>ArchiveTimeStampSequence</c> to be ordered ascending by time of timestamp, so the record would state a
    /// shape it also rejects.
    /// </summary>
    [TestMethod]
    public async Task ARenewalWhoseTokenPredatesWhatItRenewsIsRefused()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        using EvidenceRecordCreation creation = await CreateAsync([[dataObject]], InitialAlgorithm, InitialArchiveTime).ConfigureAwait(false);

        EvidenceRecordCreationException exception = await Assert.ThrowsExactlyAsync<EvidenceRecordCreationException>(
            async () => await RenewTimestampAsync(
                [creation.EvidenceRecords[0]], InitialArchiveTime.AddMinutes(-1)).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordCreationFailureKind.RenewalNotAfterSource, exception.FailureKind);
    }


    /// <summary>
    /// A record renewed twice under one new algorithm names that algorithm once. Clause 3.1 says nothing about
    /// repetition in <c>digestAlgorithms</c> and states that "The ordering of the values is not relevant";
    /// third-party records carrying more chains than algorithms name each once.
    /// </summary>
    [TestMethod]
    public async Task RenewingTwiceUnderOneAlgorithmNamesItOnce()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        using EvidenceRecordCreation creation = await CreateAsync([[dataObject]], InitialAlgorithm, InitialArchiveTime).ConfigureAwait(false);
        using EvidenceRecordRenewal first = await RenewHashTreeAsync(
            [(creation.EvidenceRecords[0], [dataObject])], RenewalAlgorithm, TimestampRenewalTime).ConfigureAwait(false);
        using EvidenceRecordRenewal second = await RenewHashTreeAsync(
            [(first.EvidenceRecords[0], [dataObject])], RenewalAlgorithm, HashTreeRenewalTime).ConfigureAwait(false);

        EvidenceRecord renewed = second.EvidenceRecords[0];
        Assert.HasCount(3, renewed.ArchiveTimeStampSequence.Chains);
        Assert.HasCount(2, renewed.DigestAlgorithms);

        using EvidenceRecordVerification verification = await VerifyAsync(renewed, dataObject).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Status, "Every chain proves the data object through the chains before it.");
        Assert.AreEqual(HashTreeRenewalTime, verification.CoveredUntil);
    }


    /// <summary>
    /// The <c>cryptoInfos</c> a record carries are carried across a renewal octet for octet. Clause 3.1 leaves
    /// what goes there to policy and states that nothing there is protected by any time-stamp, so a renewal
    /// neither validates nor rewrites it.
    /// </summary>
    [TestMethod]
    public async Task ARenewalCarriesTheRecordsCryptoInfosForward()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        byte[] attributeValue = [0x04, 0x04, 0x70, 0x6f, 0x6c, 0x79];
        using CmsAttribute policy = CmsAttribute.Create("1.2.840.113549.1.9.16.2.49", attributeValue, BaseMemoryPool.Shared);
        using EvidenceRecordCreation creation = await CreateAsync(
            [[dataObject]], InitialAlgorithm, InitialArchiveTime, cryptoInfos: [policy]).ConfigureAwait(false);

        Assert.HasCount(1, creation.EvidenceRecords[0].CryptoInfos);

        using EvidenceRecordRenewal renewal = await RenewTimestampAsync([creation.EvidenceRecords[0]], TimestampRenewalTime).ConfigureAwait(false);

        EvidenceRecord renewed = renewal.EvidenceRecords[0];
        Assert.HasCount(1, renewed.CryptoInfos);
        Assert.IsTrue(
            renewed.CryptoInfos[0].Span.SequenceEqual(creation.EvidenceRecords[0].CryptoInfos[0].Span),
            "The attribute is written back exactly as it was read.");

        using EvidenceRecordVerification verification = await VerifyAsync(renewed, dataObject).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Status);
    }


    /// <summary>
    /// Renewing nothing is refused rather than answered with an empty result.
    /// </summary>
    [TestMethod]
    public async Task RenewingNoRecordIsRefused()
    {
        EvidenceRecordCreationException timestampRenewal = await Assert.ThrowsExactlyAsync<EvidenceRecordCreationException>(
            async () => await RenewTimestampAsync([], TimestampRenewalTime).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordCreationFailureKind.NoEvidenceRecord, timestampRenewal.FailureKind);

        EvidenceRecordCreationException hashTreeRenewal = await Assert.ThrowsExactlyAsync<EvidenceRecordCreationException>(
            async () => await RenewHashTreeAsync([], RenewalAlgorithm, HashTreeRenewalTime).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordCreationFailureKind.NoEvidenceRecord, hashTreeRenewal.FailureKind);
    }


    /// <summary>
    /// Creates an initial Evidence Record over the supplied groups through the shipped surface, against a
    /// Time-Stamping Authority that mints a genuine token over whatever imprint the request states.
    /// </summary>
    /// <param name="groups">The data object groups, each a list of data object octets.</param>
    /// <param name="algorithm">The algorithm the tree is built under.</param>
    /// <param name="archiveTime">The <c>genTime</c> the minted token states.</param>
    /// <param name="cryptoInfos">The optional <c>cryptoInfos</c> attributes, or <see langword="null"/> to omit the field.</param>
    /// <returns>The creation result. The caller disposes it.</returns>
    private async ValueTask<EvidenceRecordCreation> CreateAsync(
        IReadOnlyList<byte[][]> groups,
        PkiDigestAlgorithm algorithm,
        DateTimeOffset archiveTime,
        IReadOnlyList<CmsAttribute>? cryptoInfos = null)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        var responder = new MintingTimestampResponder(authority, [authority, root], archiveTime);

        var dataObjectGroups = new List<EvidenceRecordDataObjectGroup>(groups.Count);
        for(int i = 0; i < groups.Count; ++i)
        {
            dataObjectGroups.Add(new EvidenceRecordDataObjectGroup { DataObjects = AsViews(groups[i]) });
        }

        return await EvidenceRecords.CreateInitialAsync(
            new EvidenceRecordCreationContext
            {
                DataObjectGroups = dataObjectGroups,
                DigestAlgorithm = algorithm,
                TsaUri = TsaUri,
                FetchTimestampResponse = responder.FetchAsync,
                CryptoInfos = cryptoInfos
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Performs a Timestamp Renewal of the supplied records through the shipped surface.
    /// </summary>
    /// <param name="evidenceRecords">The records to renew.</param>
    /// <param name="archiveTime">The <c>genTime</c> the minted token states.</param>
    /// <returns>The renewal result. The caller disposes it.</returns>
    private async ValueTask<EvidenceRecordRenewal> RenewTimestampAsync(IReadOnlyList<EvidenceRecord> evidenceRecords, DateTimeOffset archiveTime)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        var responder = new MintingTimestampResponder(authority, [authority, root], archiveTime);

        return await EvidenceRecords.RenewTimestampAsync(
            new EvidenceRecordTimestampRenewalContext
            {
                EvidenceRecords = evidenceRecords,
                TsaUri = TsaUri,
                FetchTimestampResponse = responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Performs a Hash-Tree Renewal of the supplied groups through the shipped surface.
    /// </summary>
    /// <param name="groups">The records to renew, each with the data objects of its group that are still present.</param>
    /// <param name="algorithm">The new algorithm the renewal selects.</param>
    /// <param name="archiveTime">The <c>genTime</c> the minted token states.</param>
    /// <returns>The renewal result. The caller disposes it.</returns>
    private async ValueTask<EvidenceRecordRenewal> RenewHashTreeAsync(
        IReadOnlyList<(EvidenceRecord EvidenceRecord, byte[][] DataObjects)> groups,
        PkiDigestAlgorithm algorithm,
        DateTimeOffset archiveTime)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        var responder = new MintingTimestampResponder(authority, [authority, root], archiveTime);

        var renewalGroups = new List<EvidenceRecordHashTreeRenewalGroup>(groups.Count);
        for(int i = 0; i < groups.Count; ++i)
        {
            renewalGroups.Add(new EvidenceRecordHashTreeRenewalGroup
            {
                EvidenceRecord = groups[i].EvidenceRecord,
                DataObjects = AsViews(groups[i].DataObjects)
            });
        }

        return await EvidenceRecords.RenewHashTreeAsync(
            new EvidenceRecordHashTreeRenewalContext
            {
                DataObjectGroups = renewalGroups,
                DigestAlgorithm = algorithm,
                TsaUri = TsaUri,
                FetchTimestampResponse = responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies a record against a data object through the shipped surface.
    /// </summary>
    /// <param name="evidenceRecord">The record to verify.</param>
    /// <param name="dataObject">The data object it is claimed to prove.</param>
    /// <returns>The conclusion. The caller disposes it.</returns>
    private async ValueTask<EvidenceRecordVerification> VerifyAsync(EvidenceRecord evidenceRecord, byte[] dataObject)
    {
        return await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext
            {
                EvidenceRecord = evidenceRecord,
                DataObject = new ReadOnlyMemory<byte>(dataObject)
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Wraps data object octets as the views the creation and renewal surfaces take.
    /// </summary>
    /// <param name="dataObjects">The octets.</param>
    /// <returns>The views, in the order supplied.</returns>
    private static List<ReadOnlyMemory<byte>> AsViews(byte[][] dataObjects)
    {
        var views = new List<ReadOnlyMemory<byte>>(dataObjects.Length);
        for(int i = 0; i < dataObjects.Length; ++i)
        {
            views.Add(new ReadOnlyMemory<byte>(dataObjects[i]));
        }

        return views;
    }
}
