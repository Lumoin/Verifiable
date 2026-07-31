using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The reference-artifact leg of the Evidence Record Syntax of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see>: third-party <c>.ers</c> artifacts
/// this library never produced are read by <see cref="EvidenceRecord.Read"/>, recomputed by the independent
/// <see cref="EvidenceRecordOracle"/>, and verified by <see cref="EvidenceRecords.VerifyAsync"/> against the
/// data objects they cover.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Where the artifacts come from.</strong> The same local reference-artifact clone under
/// <c>tempdocs/etsi-ades-reference/</c> that <c>ReferenceArtifactSignatureValidationTests</c> reads, discovered
/// by directory layout — an "evidence-record" directory under "src/test/resources/validation" that actually
/// holds <c>.ers</c> artifacts. Nothing is copied into this repository, and when the clone is absent every test
/// here reports <see cref="Assert.Inconclusive(string)"/> instead of failing.
/// </para>
/// <para>
/// <strong>What these artifacts pin.</strong> Three readings that the RFC leaves open or states twice with
/// different answers, and that no synthetic fixture of this library's own making could settle, because a
/// self-consistent implementation agrees with itself either way:
/// </para>
/// <list type="number">
///   <item><description>
///     <strong>The single-value first list is carried forward unhashed.</strong> A record over one data object
///     whose <c>reducedHashtree</c> holds one list of one hash value has that value as its root — not the hash
///     of it. Clause 4.3 step 3's prose would concatenate and hash any list; clause 4.2 step 3 hashes only
///     groups of more than one document, and RFC 6283 clause 3.1.1 states the exception outright for the XML
///     form of the same syntax. The artifacts settle it.
///   </description></item>
///   <item><description>
///     <strong>Timestamp Renewal hashes the whole <c>timeStamp</c> element.</strong> Clause 5.2 says "the
///     content of the timeStamp field ... has to be hashed"; the value the artifacts carry is the hash of the
///     complete element, its own tag and length octets included.
///   </description></item>
///   <item><description>
///     <strong>Hash-Tree Renewal concatenates positionally.</strong> Clause 5.2 step 4 states
///     <c>h(i)' = H (h(i)+ ha(i))</c> while Figure 4 of the same clause states
///     <c>H( binary sorted and concatenated (H(d1), ha(1)))</c>; the two disagree whenever the data object hash
///     sorts after the sequence hash, which is the case in the artifact read here. The artifact carries the
///     positional value, so that is what this library computes.
///   </description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class ReferenceArtifactEvidenceRecordTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The simplest form the corpus carries: an Evidence Record over one data object, whose single chain holds
    /// one Archive Timestamp whose <c>reducedHashtree</c> is one list of one hash value. The root is that hash
    /// value itself, which is what the embedded token's message imprint binds.
    /// </summary>
    /// <param name="recordName">The record's file name within the corpus directory.</param>
    /// <param name="dataObjectName">The covered data object's file name within the same directory.</param>
    [TestMethod]
    [DataRow("evidence-record-C-B-B-basic.ers", "C-B-B-basic.p7m")]
    [DataRow("evidence-record-Double-C-B-B-basic.ers", "Double-C-B-B-basic.p7m")]
    public async Task ASingleValueFirstListMakesTheDataObjectHashTheRoot(string recordName, string dataObjectName)
    {
        (byte[] recordOctets, byte[] dataObject)? artifacts = TryReadPair(recordName, dataObjectName);
        if(artifacts is not (byte[] octets, byte[] covered))
        {
            return;
        }

        OracleEvidenceRecord parsed = EvidenceRecordOracle.ParseEvidenceRecord(octets);
        Assert.AreEqual(1, parsed.Version);
        Assert.HasCount(1, parsed.Chains);
        Assert.HasCount(1, parsed.Chains[0]);

        OracleArchiveTimeStamp archiveTimeStamp = parsed.Chains[0][0];
        PkiDigestAlgorithm algorithm = ResolveAlgorithm(archiveTimeStamp);
        Assert.HasCount(1, archiveTimeStamp.ReducedHashtree, "The record carries one partial hash tree.");
        Assert.HasCount(1, archiveTimeStamp.ReducedHashtree[0], "That list holds one hash value.");

        byte[] dataObjectHash = EvidenceRecordOracle.Hash(covered, algorithm);
        Assert.IsTrue(
            archiveTimeStamp.ReducedHashtree[0][0].AsSpan().SequenceEqual(dataObjectHash),
            "The single hash value of the first list is the covered data object's hash.");
        Assert.IsTrue(
            archiveTimeStamp.MessageImprint.AsSpan().SequenceEqual(dataObjectHash),
            "The token binds that hash value as the root, unhashed a second time.");

        byte[]? oracleRoot = EvidenceRecordOracle.RecomputeRoot(dataObjectHash, archiveTimeStamp.ReducedHashtree, algorithm);
        Assert.IsNotNull(oracleRoot);
        Assert.IsTrue(oracleRoot.AsSpan().SequenceEqual(archiveTimeStamp.MessageImprint));

        using EvidenceRecord record = EvidenceRecord.Read(octets, BaseMemoryPool.Shared);
        Assert.AreEqual(EvidenceRecord.Version1, record.Version);
        Assert.HasCount(1, record.ArchiveTimeStampSequence.Chains);
        Assert.IsTrue(
            record.AsReadOnlySpan().SequenceEqual(octets),
            "Reading a record keeps its octets, which is what later renewals hash.");

        using EvidenceRecordVerification verification = await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext { EvidenceRecord = record, DataObject = new ReadOnlyMemory<byte>(covered) },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Status);
        Assert.IsTrue(verification.Chains[0].CoversDataObject);
    }


    /// <summary>
    /// A record carrying both renewal procedures of clause 5.2: a first chain of two Archive Timestamps (the
    /// second a Timestamp Renewal over the first's <c>timeStamp</c> element) and a second chain under a
    /// different algorithm (a Hash-Tree Renewal over the data object and the encoded first chain). Every link is
    /// recomputed independently before the shipped verification is asked for its own answer.
    /// </summary>
    [TestMethod]
    public async Task ARenewedRecordLinksItsChainsThePositionalWay()
    {
        (byte[] recordOctets, byte[] dataObject)? artifacts = TryReadPair(
            "evidence-record-d233a2d9-a257-40dc-bcdb-bf4516b6d1da_renewed_hashtree.ers",
            "Signature-C-LT-d233a2d9-a257-40dc-bcdb-bf4516b6d1da.p7m");
        if(artifacts is not (byte[] octets, byte[] covered))
        {
            return;
        }

        OracleEvidenceRecord parsed = EvidenceRecordOracle.ParseEvidenceRecord(octets);
        Assert.HasCount(2, parsed.DigestAlgorithmOids, "One digest algorithm per chain.");
        Assert.HasCount(2, parsed.Chains);
        Assert.HasCount(2, parsed.Chains[0], "The first chain carries an initial Archive Timestamp and a Timestamp Renewal.");
        Assert.HasCount(1, parsed.Chains[1], "The Hash-Tree Renewal starts a new chain with one member.");

        //Clause 5.3 step 1: the initial Archive Timestamp carries the data object's hash.
        OracleArchiveTimeStamp initial = parsed.Chains[0][0];
        PkiDigestAlgorithm firstChainAlgorithm = ResolveAlgorithm(initial);
        byte[] dataObjectHash = EvidenceRecordOracle.Hash(covered, firstChainAlgorithm);
        Assert.IsTrue(
            EvidenceRecordOracle.ContainsValue(initial.ReducedHashtree[0], dataObjectHash),
            "The initial Archive Timestamp's first list holds the covered data object's hash.");
        byte[]? initialRoot = EvidenceRecordOracle.RecomputeRoot(dataObjectHash, initial.ReducedHashtree, firstChainAlgorithm);
        Assert.IsNotNull(initialRoot);
        Assert.IsTrue(initialRoot.AsSpan().SequenceEqual(initial.MessageImprint));

        //Clause 5.3 step 2: the next member's first list holds the hash of the previous member's timeStamp
        //element, whole encoding included.
        OracleArchiveTimeStamp renewed = parsed.Chains[0][1];
        byte[] previousTimeStampHash = EvidenceRecordOracle.Hash(initial.TimeStampEncoding, firstChainAlgorithm);
        Assert.IsTrue(
            EvidenceRecordOracle.ContainsValue(renewed.ReducedHashtree[0], previousTimeStampHash),
            "Timestamp Renewal hashes the whole timeStamp element of the Archive Timestamp before.");
        byte[]? renewedRoot = EvidenceRecordOracle.RecomputeRoot(previousTimeStampHash, renewed.ReducedHashtree, firstChainAlgorithm);
        Assert.IsNotNull(renewedRoot);
        Assert.IsTrue(renewedRoot.AsSpan().SequenceEqual(renewed.MessageImprint));

        //Clause 5.3 step 3: the new chain's first list holds H(h(i) + ha(i)) — positionally, not sorted.
        OracleArchiveTimeStamp hashTreeRenewal = parsed.Chains[1][0];
        PkiDigestAlgorithm secondChainAlgorithm = ResolveAlgorithm(hashTreeRenewal);
        Assert.AreNotEqual(firstChainAlgorithm.Identifier, secondChainAlgorithm.Identifier, "A Hash-Tree Renewal selects a new algorithm.");

        byte[] positional = EvidenceRecordOracle.HashTreeRenewalValue(covered, [parsed.ChainEncodings[0]], secondChainAlgorithm);
        Assert.IsTrue(
            EvidenceRecordOracle.ContainsValue(hashTreeRenewal.ReducedHashtree[0], positional),
            "The Hash-Tree Renewal value is the positional concatenation of clause 5.2 step 4's own formula.");

        byte[] newDataObjectHash = EvidenceRecordOracle.Hash(covered, secondChainAlgorithm);
        var sortedPair = new List<byte[]>
        {
            newDataObjectHash,
            EvidenceRecordOracle.Hash(EncodeSequenceOf(parsed.ChainEncodings[0]), secondChainAlgorithm)
        };
        byte[] sorted = EvidenceRecordOracle.CombineNode(sortedPair, secondChainAlgorithm);
        Assert.IsFalse(
            sorted.AsSpan().SequenceEqual(positional),
            "This artifact is one where the two readings of clause 5.2 step 4 genuinely differ, so it settles which one is meant.");
        Assert.IsFalse(
            EvidenceRecordOracle.ContainsValue(hashTreeRenewal.ReducedHashtree[0], sorted),
            "Figure 4's sorted reading is not what the artifact carries.");

        using EvidenceRecord record = EvidenceRecord.Read(octets, BaseMemoryPool.Shared);
        using EvidenceRecordVerification verification = await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext { EvidenceRecord = record, DataObject = new ReadOnlyMemory<byte>(covered) },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Status);
        Assert.HasCount(2, verification.Chains);
        Assert.IsTrue(verification.Chains[0].CoversDataObject, "The first chain proves the data object directly.");
        Assert.IsTrue(verification.Chains[1].CoversDataObject, "The second chain proves it through the Hash-Tree Renewal value.");
        Assert.IsNotNull(verification.InitialArchiveTime);
        Assert.IsNotNull(verification.LatestArchiveTime);
        Assert.IsTrue(verification.InitialArchiveTime <= verification.LatestArchiveTime, "Clause 5.1 orders the sequence ascending by time.");
    }


    /// <summary>
    /// A damaged record and its intact twin, verified against the same data object. The intact one verifies;
    /// the damaged one — the two differ in a single octet of one hash value of the initial Archive Timestamp's
    /// first list, the sibling of the covered object's own hash — walks to a value the embedded token does not
    /// bind, and the reason reported says exactly that rather than a generic failure.
    /// </summary>
    [TestMethod]
    public async Task ADamagedFirstListWalksToARootTheTokenDoesNotBind()
    {
        (byte[] recordOctets, byte[] dataObject)? intactArtifacts = TryReadPair(
            "evidence-record-d233a2d9-a257-40dc-bcdb-bf4516b6d1da.ers",
            "Signature-C-LT-d233a2d9-a257-40dc-bcdb-bf4516b6d1da.p7m");
        if(intactArtifacts is not (byte[] intactOctets, byte[] covered))
        {
            return;
        }

        using(EvidenceRecord intact = EvidenceRecord.Read(intactOctets, BaseMemoryPool.Shared))
        {
            using EvidenceRecordVerification intactVerification = await EvidenceRecords.VerifyAsync(
                new EvidenceRecordVerificationContext { EvidenceRecord = intact, DataObject = new ReadOnlyMemory<byte>(covered) },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, intactVerification.Status, "The intact record proves the data object.");
        }

        (byte[] recordOctets, byte[] dataObject)? damagedArtifacts = TryReadPair(
            "evidence-record-d233a2d9-a257-40dc-bcdb-bf4516b6d1da-broken-tst.ers",
            "Signature-C-LT-d233a2d9-a257-40dc-bcdb-bf4516b6d1da.p7m");
        if(damagedArtifacts is not (byte[] damagedOctets, _))
        {
            return;
        }

        Assert.HasCount(intactOctets.Length, damagedOctets, "The damaged twin is the same record with one octet changed.");

        using EvidenceRecord damaged = EvidenceRecord.Read(damagedOctets, BaseMemoryPool.Shared);
        using EvidenceRecordVerification verification = await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext { EvidenceRecord = damaged, DataObject = new ReadOnlyMemory<byte>(covered) },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordVerificationStatus.RootMismatch, verification.Status);
        Assert.IsFalse(verification.Chains[0].CoversDataObject);
    }


    /// <summary>
    /// Records from a second, unrelated corpus of binary Evidence Records carry the same Hash-Tree Renewal
    /// combination: the positional one clause 5.2 step 4's own formula states, not the sorted one Figure 4 of
    /// the same clause states. Each record's new chain is recomputed here from the data object and the octets of
    /// the chain before it, and then verified end to end by the shipped surface.
    /// </summary>
    /// <param name="recordName">The record's file name within the corpus directory.</param>
    /// <param name="dataObjectName">The covered data object's file name within the same directory.</param>
    /// <remarks>
    /// These artifacts matter because they were produced years apart from the ones the other tests here read,
    /// over plain binary data objects rather than signatures, and by producers with no reason to agree with one
    /// another beyond both reading RFC 4998. Two corpora carrying the same reading of a clause that states two
    /// is what settles which reading is meant.
    /// </remarks>
    [TestMethod]
    [DataRow("BIN-3_ER.ers", "BIN-1.bin")]
    [DataRow("BIN-4_ER.ers", "BIN-1.bin")]
    [DataRow("ER-2Chains3ATS.ers", "ER-2Chains3ATS1.bin")]
    [DataRow("ER-2Chains3ATS.ers", "ER-2Chains3ATS2.bin")]
    public async Task TheBinaryCorpusRenewedRecordsCarryThePositionalCombination(string recordName, string dataObjectName)
    {
        (byte[] recordOctets, byte[] dataObject)? artifacts = TryReadBinaryCorpusPair(recordName, dataObjectName);
        if(artifacts is not (byte[] octets, byte[] covered))
        {
            return;
        }

        OracleEvidenceRecord parsed = EvidenceRecordOracle.ParseEvidenceRecord(octets);
        Assert.HasCount(2, parsed.Chains, "The record carries a Hash-Tree Renewal, which starts a second chain.");

        OracleArchiveTimeStamp initial = parsed.Chains[0][0];
        PkiDigestAlgorithm firstChainAlgorithm = ResolveAlgorithm(initial);
        byte[] dataObjectHash = EvidenceRecordOracle.Hash(covered, firstChainAlgorithm);
        Assert.IsTrue(
            EvidenceRecordOracle.ContainsValue(initial.ReducedHashtree[0], dataObjectHash),
            "The initial Archive Timestamp's first list holds the covered data object's hash.");

        for(int memberIndex = 1; memberIndex < parsed.Chains[0].Count; ++memberIndex)
        {
            OracleArchiveTimeStamp renewed = parsed.Chains[0][memberIndex];
            byte[] previous = EvidenceRecordOracle.TimestampRenewalValue(parsed.Chains[0][memberIndex - 1].TimeStampEncoding, firstChainAlgorithm);
            Assert.IsTrue(
                EvidenceRecordOracle.ContainsValue(renewed.ReducedHashtree[0], previous),
                "A Timestamp Renewal binds the whole timeStamp element of the Archive Timestamp before it.");
        }

        OracleArchiveTimeStamp hashTreeRenewal = parsed.Chains[1][0];
        PkiDigestAlgorithm secondChainAlgorithm = ResolveAlgorithm(hashTreeRenewal);
        byte[] positional = EvidenceRecordOracle.HashTreeRenewalValue(covered, [parsed.ChainEncodings[0]], secondChainAlgorithm);
        byte[] sorted = EvidenceRecordOracle.HashTreeRenewalValueSorted(covered, [parsed.ChainEncodings[0]], secondChainAlgorithm);

        Assert.IsTrue(
            EvidenceRecordOracle.ContainsValue(hashTreeRenewal.ReducedHashtree[0], positional),
            "Clause 5.2 step 4: h(i)' = H(h(i) + ha(i)), concatenated in that order and not sorted.");
        if(!positional.AsSpan().SequenceEqual(sorted))
        {
            Assert.IsFalse(
                EvidenceRecordOracle.ContainsValue(hashTreeRenewal.ReducedHashtree[0], sorted),
                "Where the two readings differ, the artifact carries the prose's and not the figure's.");
        }

        byte[]? renewedRoot = EvidenceRecordOracle.RecomputeRoot(positional, hashTreeRenewal.ReducedHashtree, secondChainAlgorithm);
        Assert.IsNotNull(renewedRoot);
        Assert.IsTrue(renewedRoot.AsSpan().SequenceEqual(hashTreeRenewal.MessageImprint), "The renewal's own token binds the root that value walks to.");

        using EvidenceRecord record = EvidenceRecord.Read(octets, BaseMemoryPool.Shared);
        using EvidenceRecordVerification verification = await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext { EvidenceRecord = record, DataObject = new ReadOnlyMemory<byte>(covered) },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Status);
        for(int chainIndex = 0; chainIndex < verification.Chains.Count; ++chainIndex)
        {
            Assert.IsTrue(verification.Chains[chainIndex].CoversDataObject, "Every chain of this record carries the data object forward.");
        }

        Assert.AreEqual(verification.LatestArchiveTime, verification.CoveredUntil, "Nothing was dropped, so the proof reaches the record's most recent Archive Timestamp.");
    }


    /// <summary>
    /// The damaged twin of the renewed record differs from it in exactly one octet, that octet lies inside the
    /// most recent Archive Timestamp's time-stamp, and the record is refused for it — while every hash-tree link
    /// of both records recomputes identically, which is what pins the damage to the token rather than the tree.
    /// </summary>
    [TestMethod]
    public async Task TheDamagedTwinOfARenewedRecordIsRefusedForItsTokenWhileItsHashTreeStaysIntact()
    {
        (byte[] recordOctets, byte[] dataObject)? intactArtifacts = TryReadPair(
            "evidence-record-d233a2d9-a257-40dc-bcdb-bf4516b6d1da_renewed_hashtree.ers",
            "Signature-C-LT-d233a2d9-a257-40dc-bcdb-bf4516b6d1da.p7m");
        if(intactArtifacts is not (byte[] intactOctets, byte[] covered))
        {
            return;
        }

        (byte[] recordOctets, byte[] dataObject)? damagedArtifacts = TryReadPair(
            "evidence-record-d233a2d9-a257-40dc-bcdb-bf4516b6d1da_renewed_hashtree-broken-tst.ers",
            "Signature-C-LT-d233a2d9-a257-40dc-bcdb-bf4516b6d1da.p7m");
        if(damagedArtifacts is not (byte[] damagedOctets, _))
        {
            return;
        }

        Assert.HasCount(intactOctets.Length, damagedOctets, "The damaged twin is the same record with octets changed in place.");

        int changed = -1;
        int changedCount = 0;
        for(int i = 0; i < intactOctets.Length; ++i)
        {
            if(intactOctets[i] != damagedOctets[i])
            {
                changed = i;
                ++changedCount;
            }
        }

        Assert.AreEqual(1, changedCount, "Exactly one octet differs.");

        //Both records carry the same hash-tree links: the damage is not in anything clauses 4.3 and 5.3 walk.
        OracleEvidenceRecord intactParsed = EvidenceRecordOracle.ParseEvidenceRecord(intactOctets);
        OracleEvidenceRecord damagedParsed = EvidenceRecordOracle.ParseEvidenceRecord(damagedOctets);
        PkiDigestAlgorithm renewalAlgorithm = ResolveAlgorithm(intactParsed.Chains[1][0]);
        byte[] intactValue = EvidenceRecordOracle.HashTreeRenewalValue(covered, [intactParsed.ChainEncodings[0]], renewalAlgorithm);
        byte[] damagedValue = EvidenceRecordOracle.HashTreeRenewalValue(covered, [damagedParsed.ChainEncodings[0]], renewalAlgorithm);
        Assert.IsTrue(intactValue.AsSpan().SequenceEqual(damagedValue), "The chain the renewal hashed is unchanged, so the renewal value it produces is unchanged.");
        Assert.IsTrue(
            EvidenceRecordOracle.ContainsValue(damagedParsed.Chains[1][0].ReducedHashtree[0], damagedValue),
            "The damaged record's own reduced hash tree still holds that value.");

        //The changed octet lies inside the most recent Archive Timestamp's timeStamp element.
        using EvidenceRecord damaged = EvidenceRecord.Read(damagedOctets, BaseMemoryPool.Shared);
        EvidenceRecordArchiveTimeStamp latest = damaged.ArchiveTimeStampSequence.Chains[^1].ArchiveTimeStamps[^1];
        int timeStampOffset = damagedOctets.AsSpan().IndexOf(latest.TimeStamp.Span);
        Assert.IsGreaterThanOrEqualTo(0, timeStampOffset);
        Assert.IsGreaterThanOrEqualTo(timeStampOffset, changed, "The changed octet is inside the most recent time-stamp.");
        Assert.IsLessThan(timeStampOffset + latest.TimeStamp.Length, changed);

        using EvidenceRecordVerification verification = await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext { EvidenceRecord = damaged, DataObject = new ReadOnlyMemory<byte>(covered) },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordVerificationStatus.TimestampNotRead, verification.Status, "A time-stamp whose own signature does not verify states nothing this library will read as a proof.");
        Assert.IsFalse(verification.Chains[1].CoversDataObject);
        Assert.IsTrue(verification.Chains[0].CoversDataObject, "The chain the damage is not in still proves what it always proved.");
        Assert.AreEqual(verification.Chains[0].ArchiveTimeStamps[^1].GenerationTime, verification.CoveredUntil);
    }


    /// <summary>
    /// Among the Evidence Records embedded in the corpus's CMS objects, every one whose first list of hash
    /// values holds the hash of a content file the corpus carries alongside its CMS objects is carried by
    /// <c>id-aa-er-external</c>, and at least one such record exists. This is the empirical half of the mapping
    /// RFC 4998 Appendix A never states in prose.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Appendix A defines two selection methods and two attribute identifiers, and never says which names which.
    /// The first method makes the CMS object the archived data object on its own — "a hash value of the CMS
    /// object MUST be located in the first list of hash values of Archive Timestamps" — and the second makes the
    /// CMS object and its content a group — "the hash value of the CMS Object as well as the hash value of the
    /// content have to be stored in the first list of hash values as a group of data objects".
    /// </para>
    /// <para>
    /// The discriminator asserted here is what the second method's group <em>holds</em>, not how many members it
    /// has. The count does not discriminate: the corpus carries a record under the internal identifier whose
    /// first list names two data objects, and both of them are CMS objects — a hash tree built over several
    /// signatures at once, which is clause 4.2's own data-object group and has nothing to do with Appendix A's
    /// selection. What only ever appears under the external identifier is a group holding the hash of the
    /// detached content the CMS object signs.
    /// </para>
    /// <para>
    /// What this test does not establish is the other half: whether the CMS-object hash in either selection is
    /// taken over the object with the Evidence Record attribute removed. That needs the pre-attribute
    /// reconstruction of Appendix A, which is not part of this surface.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void TheContentGroupOfAppendixAAppearsOnlyUnderTheExternalIdentifier()
    {
        string? directory = TryFindArtifactDirectory();
        if(directory is null)
        {
            Assert.Inconclusive(MissingCloneMessage);

            return;
        }

        string[] cmsObjects = [.. Directory.EnumerateFiles(directory)
            .Where(file => file.EndsWith(".p7m", StringComparison.OrdinalIgnoreCase) || file.EndsWith(".p7s", StringComparison.OrdinalIgnoreCase))
            .OrderBy(file => file, StringComparer.Ordinal)];
        if(cmsObjects.Length == 0)
        {
            Assert.Inconclusive("The corpus holds no CMS objects to read Evidence Record attributes from.");

            return;
        }

        string[] contentCandidates = [.. Directory.EnumerateFiles(directory)
            .Where(file => !file.EndsWith(".p7m", StringComparison.OrdinalIgnoreCase)
                && !file.EndsWith(".p7s", StringComparison.OrdinalIgnoreCase)
                && !file.EndsWith(".ers", StringComparison.OrdinalIgnoreCase)
                && !file.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))];

        int internalRecords = 0;
        int externalRecords = 0;
        int groupsHoldingDetachedContent = 0;
        foreach(string cmsObject in cmsObjects)
        {
            byte[] octets = File.ReadAllBytes(cmsObject);
            foreach((bool isInternal, byte[] evidenceRecord) in ReadEmbeddedEvidenceRecords(octets))
            {
                OracleEvidenceRecord parsed = EvidenceRecordOracle.ParseEvidenceRecord(evidenceRecord);
                if(isInternal)
                {
                    ++internalRecords;
                }
                else
                {
                    ++externalRecords;
                }

                List<List<byte[]>> tree = parsed.Chains[0][0].ReducedHashtree;
                if(tree.Count == 0)
                {
                    continue;
                }

                PkiDigestAlgorithm? algorithm = PkiDigestAlgorithm.FromOid(parsed.Chains[0][0].DigestAlgorithmOid ?? parsed.Chains[0][0].MessageImprintAlgorithmOid);
                if(algorithm is null)
                {
                    continue;
                }

                foreach(string candidate in contentCandidates)
                {
                    byte[] contentHash = EvidenceRecordOracle.Hash(File.ReadAllBytes(candidate), algorithm.Value);
                    if(EvidenceRecordOracle.ContainsValue(tree[0], contentHash))
                    {
                        Assert.IsFalse(
                            isInternal,
                            $"'{Path.GetFileName(cmsObject)}' groups the hash of detached content with its CMS object under the identifier that selects the CMS object on its own.");
                        Assert.IsGreaterThan(1, tree[0].Count, "The content is one member of a group, the CMS object the other.");
                        ++groupsHoldingDetachedContent;
                    }
                }
            }
        }

        Assert.IsGreaterThan(0, internalRecords, "The corpus carries Evidence Records under the internal identifier.");
        Assert.IsGreaterThan(0, externalRecords, "The corpus carries Evidence Records under the external identifier.");
        Assert.IsGreaterThan(
            0,
            groupsHoldingDetachedContent,
            "At least one record groups the hash of a detached content file with its CMS object, which is the second selection method of Appendix A.");
    }


    /// <summary>
    /// The pre-attribute reconstruction of RFC 4998 Appendix A is byte-exact, and the corpus proves it by
    /// carrying both files: an object with an embedded Evidence Record, and the object as it stood before that
    /// attachment. Removing the attribute and re-deriving the definite lengths of the containers that shrank
    /// reaches the second file octet for octet.
    /// </summary>
    /// <param name="recordBearingName">The file name of the object carrying an embedded Evidence Record.</param>
    /// <param name="preAttachmentName">The file name of the same object as it stood before the attachment.</param>
    /// <remarks>
    /// This is what makes <see cref="CmsSignedDataReduction"/> checked against third-party ground truth rather
    /// than only against its own inverse: the two files were produced by a party that never saw this code, and
    /// the reconstruction has to land on the second one exactly. "The length of fields containing tags has to be
    /// adapted. Apart from that, the existing coding must not be modified."
    /// </remarks>
    [TestMethod]
    [DataRow("C-E-ERS-basic.p7m", "C-B-B-basic.p7m")]
    [DataRow("C-E-ERS-basic-invalid-sig.p7m", "C-B-B-basic-der.p7m")]
    [DataRow("CAdEs-BpT+ER-without-reducedHashTree.p7m", "CAdES-BpT.p7m")]
    public void TheReconstructedViewIsThePreAttachmentFileTheCorpusAlsoCarries(string recordBearingName, string preAttachmentName)
    {
        if(TryReadPair(recordBearingName, preAttachmentName) is not (byte[] recordBearing, byte[] preAttachment))
        {
            return;
        }

        using CmsSignedData carrying = CmsSignedData.FromBytes(recordBearing, BaseMemoryPool.Shared);
        Assert.IsNotEmpty(EvidenceRecordCmsIntegration.LocateEvidenceRecords(carrying, signerIndex: 0), "The object carries at least one Evidence Record attribute.");

        using CmsSignedData view = EvidenceRecordCmsIntegration.BuildArchivedDataObject(carrying, signerIndex: 0, [], BaseMemoryPool.Shared);

        Assert.AreSequenceEqual(preAttachment, view.AsReadOnlySpan().ToArray(), "The reconstruction is the file that stood before the attachment, octet for octet.");
    }


    /// <summary>
    /// Third-party CMS objects carrying embedded Evidence Records verify through the shipped Appendix A path:
    /// the record proves a reconstructed view of the object it is carried by, never the file as it sits on disk.
    /// </summary>
    /// <param name="objectName">The CMS object's file name within the corpus directory.</param>
    /// <param name="expected">What the verification is expected to conclude.</param>
    /// <param name="recordCount">How many Evidence Record attribute values the object carries.</param>
    /// <remarks>
    /// The negatives are the corpus's own: an object whose record proves no view of it at all is what its name
    /// says it is. No detached content is stated for any of these, so what is exercised is coverage of the
    /// reconstructed object rather than the group check of the second selection method.
    /// <c>C-E-ERS-basic-invalid-sig.p7m</c> is refused for a reason of its own — it is the one artifact of the
    /// corpus whose single-value first list is HASHED into its root rather than carried forward, which
    /// <see cref="TheSingleValueFirstListIsCarriedForwardUnhashedThroughoutTheCorpus"/> states directly. Its
    /// reconstruction is nonetheless byte-exact, which
    /// <see cref="TheReconstructedViewIsThePreAttachmentFileTheCorpusAlsoCarries"/> pins.
    /// </remarks>
    [TestMethod]
    [DataRow("C-E-ERS-basic.p7m", EvidenceRecordCmsVerificationStatus.Verified, 1)]
    [DataRow("C-E-ERS-basic-invalid-sig.p7m", EvidenceRecordCmsVerificationStatus.EvidenceRecordNotVerified, 1)]
    [DataRow("CAdEs-BpT+ER-without-reducedHashTree.p7m", EvidenceRecordCmsVerificationStatus.Verified, 1)]
    [DataRow("C-E-ERS.p7m", EvidenceRecordCmsVerificationStatus.Verified, 1)]
    [DataRow("C-B-B-wrong-er-attribute.p7m", EvidenceRecordCmsVerificationStatus.Verified, 1)]
    [DataRow("C-E-ERS-detached-original-not-covered.p7s", EvidenceRecordCmsVerificationStatus.Verified, 1)]
    [DataRow("C-E-ERS-detached-ber.p7s", EvidenceRecordCmsVerificationStatus.Verified, 1)]
    [DataRow("C-E-ERS-detached-invalid.p7s", EvidenceRecordCmsVerificationStatus.EvidenceRecordNotVerified, 1)]
    [DataRow("C-B-B-basic.p7m", EvidenceRecordCmsVerificationStatus.NoEvidenceRecord, 0)]
    public async Task TheEmbeddedRecordsOfTheCorpusProveTheReconstructedViews(string objectName, EvidenceRecordCmsVerificationStatus expected, int recordCount)
    {
        if(TryReadArtifact(objectName) is not byte[] octets)
        {
            return;
        }

        using CmsSignedData carrying = CmsSignedData.FromBytes(octets, BaseMemoryPool.Shared);
        Assert.HasCount(recordCount, EvidenceRecordCmsIntegration.LocateEvidenceRecords(carrying, signerIndex: 0));

        using EvidenceRecordCmsVerification verification = await EvidenceRecordCmsIntegration.VerifyEmbeddedAsync(
            new EvidenceRecordCmsVerificationContext { SignedData = carrying, SignerIndex = 0 },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expected, verification.Status, StateRecordReasons(verification));
    }


    /// <summary>
    /// The decisive third-party evidence for the ruling this implementation follows: an object carrying two
    /// Evidence Records under one attribute identifier whose chronological order is the REVERSE of the order the
    /// <c>SET OF</c> holds them in. A verifier that read chronology off the encoding reports this object as
    /// unverified; discovering which view each record proves verifies it.
    /// </summary>
    /// <remarks>
    /// Both records sit under the same <c>attrType</c>, so a producer canonicalising <c>unsignedAttrs</c> orders
    /// the two <c>Attribute</c> structures by their values and the older record sorted second. Appendix A's
    /// "they have to be stored within the first signature in chronological order" is therefore not enforceable
    /// on the wire, which is why the shipped verification does not rely on it.
    /// </remarks>
    [TestMethod]
    public async Task TheChronologyOfATwoRecordObjectIsTheReverseOfItsEncodingOrder()
    {
        if(TryReadArtifact("C-E-ERS-two-er.p7m") is not byte[] octets)
        {
            return;
        }

        using CmsSignedData carrying = CmsSignedData.FromBytes(octets, BaseMemoryPool.Shared);
        Assert.HasCount(2, EvidenceRecordCmsIntegration.LocateEvidenceRecords(carrying, signerIndex: 0));

        using EvidenceRecordCmsVerification verification = await EvidenceRecordCmsIntegration.VerifyEmbeddedAsync(
            new EvidenceRecordCmsVerificationContext { SignedData = carrying, SignerIndex = 0 },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordCmsVerificationStatus.Verified, verification.Status);
        Assert.AreEqual(1, verification.EvidenceRecords[0].ChronologicalPosition, "The record encoded first proves the view holding the other one, so it is the later of the two.");
        Assert.AreEqual(1, verification.EvidenceRecords[0].ProvedViewEvidenceRecordCount);
        Assert.AreEqual(0, verification.EvidenceRecords[1].ChronologicalPosition, "The record encoded second proves the view holding neither, so it is the earlier one.");
        Assert.AreEqual(0, verification.EvidenceRecords[1].ProvedViewEvidenceRecordCount);
    }


    /// <summary>
    /// Two Evidence Records of one object may prove the SAME view. Appendix A describes a nested chain and this
    /// third-party object carries parallel records instead, so a verifier that assumed a strict chain would
    /// refuse an object nothing is wrong with.
    /// </summary>
    [TestMethod]
    public async Task TwoRecordsOfOneCorpusObjectProveTheSameView()
    {
        if(TryReadArtifact("C-E-ERS-parallel-ers.p7m") is not byte[] octets)
        {
            return;
        }

        using CmsSignedData carrying = CmsSignedData.FromBytes(octets, BaseMemoryPool.Shared);
        Assert.HasCount(2, EvidenceRecordCmsIntegration.LocateEvidenceRecords(carrying, signerIndex: 0));

        using EvidenceRecordCmsVerification verification = await EvidenceRecordCmsIntegration.VerifyEmbeddedAsync(
            new EvidenceRecordCmsVerificationContext { SignedData = carrying, SignerIndex = 0 },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordCmsVerificationStatus.Verified, verification.Status);
        Assert.AreEqual(0, verification.EvidenceRecords[0].ProvedViewEvidenceRecordCount);
        Assert.AreEqual(0, verification.EvidenceRecords[1].ProvedViewEvidenceRecordCount, "Both records prove the view holding neither of them.");
    }


    /// <summary>
    /// A DETACHED Evidence Record kept beside a record-bearing CMS object covers that object as it sits on disk,
    /// embedded Evidence Record attribute and all. The removal of Appendix A is performed for a record found
    /// INSIDE the object, never for one supplied beside it, and this artifact pair is what pins the difference.
    /// </summary>
    [TestMethod]
    public async Task ADetachedRecordCoversTheObjectAsItStandsIncludingItsEmbeddedRecord()
    {
        if(TryReadPair("evidence-record-C-E-ERS.ers", "C-E-ERS.p7m") is not (byte[] recordOctets, byte[] dataObject))
        {
            return;
        }

        using CmsSignedData carrying = CmsSignedData.FromBytes(dataObject, BaseMemoryPool.Shared);
        Assert.HasCount(1, EvidenceRecordCmsIntegration.LocateEvidenceRecords(carrying, signerIndex: 0), "The covered object carries an embedded Evidence Record of its own.");

        using EvidenceRecord detached = EvidenceRecord.Read(recordOctets, BaseMemoryPool.Shared);
        using(EvidenceRecordVerification asItStands = await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext { EvidenceRecord = detached, DataObject = new ReadOnlyMemory<byte>(dataObject) },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, asItStands.Status, "The detached record covers the file as it sits on disk.");
        }

        using CmsSignedData view = EvidenceRecordCmsIntegration.BuildArchivedDataObject(carrying, signerIndex: 0, [], BaseMemoryPool.Shared);
        using EvidenceRecordVerification reconstructed = await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext { EvidenceRecord = detached, DataObject = view.AsReadOnlyMemory() },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            EvidenceRecordVerificationStatus.DataObjectNotCovered,
            reconstructed.Status,
            "It does not cover the reconstructed view, which is what a record carried inside the object would.");
    }


    /// <summary>
    /// The corpus-wide census behind the single-value-first-list ruling. Every Evidence Record in the corpus,
    /// detached or embedded, whose reduced hash tree is one list holding one hash value states its own root in
    /// its time-stamp's message imprint, and that imprint decides which reading the record was written under
    /// with no data object needed: the value itself (carried forward unhashed) or the hash of it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The census is decisive because it is complete. All but one of the records take the unhashed reading —
    /// across detached and embedded records, under both attribute identifiers, with and without the
    /// <c>digestAlgorithm</c> field, so none of those is the discriminator. The single exception is
    /// <c>C-E-ERS-basic-invalid-sig.p7m</c>, and this library refuses it: clause 4.2 step 3 hashes only groups
    /// "containing more than one document", RFC 6283 clause 3.1.1 states the exception outright for the XML form
    /// of the same syntax, and a strict verifier does not accept both readings of a rule that decides what a
    /// root is.
    /// </para>
    /// <para>
    /// The counts are asserted as floors rather than exact numbers so that a corpus gaining artifacts does not
    /// fail the test, while a corpus whose records changed reading does.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void TheSingleValueFirstListIsCarriedForwardUnhashedThroughoutTheCorpus()
    {
        string? directory = TryFindArtifactDirectory();
        if(directory is null)
        {
            Assert.Inconclusive(MissingCloneMessage);

            return;
        }

        var unhashedReading = new List<string>();
        var hashedReading = new List<string>();
        var neitherReading = new List<string>();
        foreach(string file in Directory.EnumerateFiles(directory).OrderBy(file => file, StringComparer.Ordinal))
        {
            foreach(byte[] octets in ReadEveryEvidenceRecord(file))
            {
                OracleArchiveTimeStamp? initial = TryReadSingleValueInitialArchiveTimeStamp(octets);
                if(initial is null)
                {
                    continue;
                }

                PkiDigestAlgorithm? algorithm = PkiDigestAlgorithm.FromOid(initial.DigestAlgorithmOid ?? initial.MessageImprintAlgorithmOid);
                if(algorithm is null)
                {
                    continue;
                }

                byte[] onlyValue = initial.ReducedHashtree[0][0];
                string name = Path.GetFileName(file);
                if(onlyValue.AsSpan().SequenceEqual(initial.MessageImprint))
                {
                    unhashedReading.Add(name);
                }
                else if(EvidenceRecordOracle.Hash(onlyValue, algorithm.Value).AsSpan().SequenceEqual(initial.MessageImprint))
                {
                    hashedReading.Add(name);
                }
                else
                {
                    neitherReading.Add(name);
                }
            }
        }

        Assert.IsGreaterThanOrEqualTo(15, unhashedReading.Count, $"The unhashed reading is the corpus's: {string.Join(", ", unhashedReading)}.");
        Assert.IsEmpty(neitherReading, $"Every single-value record's imprint is one of the two readings: {string.Join(", ", neitherReading)}.");
        Assert.AreSequenceEqual(
            (string[])["C-E-ERS-basic-invalid-sig.p7m"],
            hashedReading,
            "Exactly one artifact of the corpus states the hashed reading, and this library refuses it.");
    }


    /// <summary>
    /// Reads every Evidence Record one corpus file carries: the file itself when it is a detached record, and
    /// each embedded attribute value when it is a CMS object.
    /// </summary>
    /// <param name="file">The artifact's full path.</param>
    /// <returns>The records' octets, in the order they appear.</returns>
    private static List<byte[]> ReadEveryEvidenceRecord(string file)
    {
        byte[] octets = File.ReadAllBytes(file);
        if(file.EndsWith(".ers", StringComparison.OrdinalIgnoreCase))
        {
            return [octets];
        }

        if(!file.EndsWith(".p7m", StringComparison.OrdinalIgnoreCase) && !file.EndsWith(".p7s", StringComparison.OrdinalIgnoreCase))
        {
            return [];
        }

        var embedded = new List<byte[]>();
        foreach((bool _, byte[] record) in ReadEmbeddedEvidenceRecords(octets))
        {
            embedded.Add(record);
        }

        return embedded;
    }


    /// <summary>
    /// Decodes a record and returns its initial <c>ArchiveTimeStamp</c> when that structure's reduced hash tree
    /// is exactly one list holding exactly one hash value — the shape whose root the message imprint decides on
    /// its own — and <see langword="null"/> for every other shape or for octets that do not decode.
    /// </summary>
    /// <param name="octets">The record's octets.</param>
    /// <returns>The initial <c>ArchiveTimeStamp</c>, or <see langword="null"/>.</returns>
    private static OracleArchiveTimeStamp? TryReadSingleValueInitialArchiveTimeStamp(byte[] octets)
    {
        OracleEvidenceRecord record;
        try
        {
            record = EvidenceRecordOracle.ParseEvidenceRecord(octets);
        }
        catch(System.Formats.Asn1.AsnContentException)
        {
            return null;
        }

        if(record.Chains.Count == 0 || record.Chains[0].Count == 0)
        {
            return null;
        }

        OracleArchiveTimeStamp initial = record.Chains[0][0];

        return initial.ReducedHashtree.Count == 1 && initial.ReducedHashtree[0].Count == 1 ? initial : null;
    }


    /// <summary>
    /// States, per embedded Evidence Record, what the Evidence Record Syntax verification concluded — the detail
    /// behind an unexpected overall status, so a corpus artifact that changes behaviour names its own reason.
    /// </summary>
    /// <param name="verification">The verification.</param>
    /// <returns>A one-line summary of the per-record conclusions.</returns>
    private static string StateRecordReasons(EvidenceRecordCmsVerification verification)
    {
        var reasons = new List<string>(verification.EvidenceRecords.Count);
        for(int i = 0; i < verification.EvidenceRecords.Count; ++i)
        {
            EvidenceRecordCmsRecordVerification record = verification.EvidenceRecords[i];
            reasons.Add($"[{i}] {record.Status}/{record.Verification?.Status.ToString() ?? "none"} at position {record.ChronologicalPosition}");
        }

        return string.Join(", ", reasons);
    }


    /// <summary>
    /// Reads one artifact of the corpus, or reports <see cref="Assert.Inconclusive(string)"/> and returns
    /// <see langword="null"/> when the local reference-artifact clone, or the file within it, is not present.
    /// </summary>
    /// <param name="artifactName">The artifact's file name within the corpus directory.</param>
    /// <returns>The file's octets, or <see langword="null"/>.</returns>
    private static byte[]? TryReadArtifact(string artifactName)
    {
        string? directory = TryFindArtifactDirectory();
        if(directory is null)
        {
            Assert.Inconclusive(MissingCloneMessage);

            return null;
        }

        string path = Path.Combine(directory, artifactName);
        if(!File.Exists(path))
        {
            Assert.Inconclusive($"The artifact '{artifactName}' is not present in the local reference-artifact corpus.");

            return null;
        }

        return File.ReadAllBytes(path);
    }


    /// <summary>
    /// Reads the Evidence Records embedded in a CMS object's attributes, by locating the two attribute
    /// identifiers of RFC 4998 Appendix A in the object's octets and decoding the attribute values that follow
    /// each.
    /// </summary>
    /// <param name="cmsObject">The CMS object's octets.</param>
    /// <returns>Each embedded record, paired with whether the identifier carrying it was the internal one.</returns>
    /// <remarks>
    /// The scan is deliberately structural rather than a walk of the CMS syntax: what is being checked is a
    /// property of third-party octets, and locating the attribute by its own identifier keeps the check
    /// independent of any surface that will later read these objects properly. An identifier's octets can occur
    /// by chance inside a signature, so a position that does not decode as an attribute value set is passed
    /// over rather than reported.
    /// </remarks>
    private static List<(bool IsInternal, byte[] EvidenceRecord)> ReadEmbeddedEvidenceRecords(byte[] cmsObject)
    {
        byte[] internalIdentifier = EncodeObjectIdentifier(EvidenceRecordWellKnown.InternalEvidenceRecordAttributeOid);
        byte[] externalIdentifier = EncodeObjectIdentifier(EvidenceRecordWellKnown.ExternalEvidenceRecordAttributeOid);

        var found = new List<(bool, byte[])>();
        for(int offset = 0; offset + internalIdentifier.Length <= cmsObject.Length; ++offset)
        {
            ReadOnlySpan<byte> candidate = cmsObject.AsSpan(offset, internalIdentifier.Length);
            bool isInternal = candidate.SequenceEqual(internalIdentifier);
            if(!isInternal && !candidate.SequenceEqual(externalIdentifier))
            {
                continue;
            }

            try
            {
                var reader = new System.Formats.Asn1.AsnReader(
                    cmsObject.AsMemory(offset + internalIdentifier.Length), System.Formats.Asn1.AsnEncodingRules.BER);
                System.Formats.Asn1.AsnReader values = reader.ReadSetOf(skipSortOrderValidation: true);
                while(values.HasData)
                {
                    byte[] value = values.ReadEncodedValue().ToArray();
                    _ = EvidenceRecordOracle.ParseEvidenceRecord(value);
                    found.Add((isInternal, value));
                }
            }
            catch(System.Formats.Asn1.AsnContentException)
            {
                //The identifier's octets occurred somewhere that is not an attribute; nothing to report.
            }
        }

        return found;
    }


    /// <summary>
    /// Encodes an object identifier as the DER element a scan looks for.
    /// </summary>
    /// <param name="oid">The dotted-decimal identifier.</param>
    /// <returns>The encoded element, tag and length octets included.</returns>
    private static byte[] EncodeObjectIdentifier(string oid)
    {
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        writer.WriteObjectIdentifier(oid);

        return writer.Encode();
    }


    /// <summary>
    /// Resolves the algorithm one Archive Timestamp's tree is built under: its own <c>digestAlgorithm</c> field
    /// when present, otherwise the algorithm of its token's message imprint, as clause 4.1 requires.
    /// </summary>
    /// <param name="archiveTimeStamp">The structure as the independent decoder read it.</param>
    /// <returns>The algorithm.</returns>
    private static PkiDigestAlgorithm ResolveAlgorithm(OracleArchiveTimeStamp archiveTimeStamp)
    {
        PkiDigestAlgorithm? algorithm = PkiDigestAlgorithm.FromOid(archiveTimeStamp.DigestAlgorithmOid ?? archiveTimeStamp.MessageImprintAlgorithmOid);
        Assert.IsNotNull(algorithm, "The artifact names a digest algorithm this library computes.");

        return algorithm.Value;
    }


    /// <summary>
    /// Wraps one already-encoded chain in the <c>SEQUENCE OF</c> an <c>ArchiveTimeStampSequence</c> is, with
    /// this file's own writer, for the sorted-reading counter-check.
    /// </summary>
    /// <param name="chainEncoding">The whole encoding of the chain.</param>
    /// <returns>The encoded sequence.</returns>
    private static byte[] EncodeSequenceOf(byte[] chainEncoding)
    {
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteEncodedValue(chainEncoding);
        }

        return writer.Encode();
    }


    /// <summary>
    /// Reads one record and the data object it covers, or reports <see cref="Assert.Inconclusive(string)"/> and
    /// returns <see langword="null"/> when the local reference-artifact clone, or either file within it, is not
    /// present.
    /// </summary>
    /// <param name="recordName">The record's file name.</param>
    /// <param name="dataObjectName">The covered data object's file name.</param>
    /// <returns>The two files' octets, or <see langword="null"/>.</returns>
    private static (byte[] RecordOctets, byte[] DataObject)? TryReadPair(string recordName, string dataObjectName)
    {
        string? directory = TryFindArtifactDirectory();
        if(directory is null)
        {
            Assert.Inconclusive(MissingCloneMessage);

            return null;
        }

        string recordPath = Path.Combine(directory, recordName);
        string dataObjectPath = Path.Combine(directory, dataObjectName);
        if(!File.Exists(recordPath) || !File.Exists(dataObjectPath))
        {
            Assert.Inconclusive($"The artifacts '{recordName}' and '{dataObjectName}' are not both present in the local reference-artifact corpus.");

            return null;
        }

        return (File.ReadAllBytes(recordPath), File.ReadAllBytes(dataObjectPath));
    }


    /// <summary>
    /// Reads one record and the data object it covers from the second corpus — the one holding binary Evidence
    /// Records over plain binary data objects — or reports <see cref="Assert.Inconclusive(string)"/> and returns
    /// <see langword="null"/> when that corpus, or either file within it, is not present.
    /// </summary>
    /// <param name="recordName">The record's file name.</param>
    /// <param name="dataObjectName">The covered data object's file name.</param>
    /// <returns>The two files' octets, or <see langword="null"/>.</returns>
    private static (byte[] RecordOctets, byte[] DataObject)? TryReadBinaryCorpusPair(string recordName, string dataObjectName)
    {
        string? directory = TryFindBinaryCorpusDirectory();
        if(directory is null)
        {
            Assert.Inconclusive(MissingCloneMessage);

            return null;
        }

        string recordPath = Path.Combine(directory, recordName);
        string dataObjectPath = Path.Combine(directory, dataObjectName);
        if(!File.Exists(recordPath) || !File.Exists(dataObjectPath))
        {
            Assert.Inconclusive($"The artifacts '{recordName}' and '{dataObjectName}' are not both present in the local reference-artifact corpus.");

            return null;
        }

        return (File.ReadAllBytes(recordPath), File.ReadAllBytes(dataObjectPath));
    }


    /// <summary>
    /// Resolves the second corpus's directory by layout: a test-resources directory that holds both binary
    /// Evidence Records and the binary data objects they cover.
    /// </summary>
    /// <returns>The directory's full path, or <see langword="null"/> when it is not present.</returns>
    /// <remarks>
    /// The corpus is found by what it contains rather than by what it is called, the same discovery the other
    /// tests here use. Its records cover plain binary files instead of signatures, which is what makes it a
    /// second, independent witness to the readings the RFC leaves open.
    /// </remarks>
    private static string? TryFindBinaryCorpusDirectory()
    {
        string? referenceMaterial = TryFindReferenceMaterialDirectory();
        if(referenceMaterial is null)
        {
            return null;
        }

        string tail = Path.Combine("src", "test", "resources");

        return Directory.EnumerateDirectories(referenceMaterial, "resources", SearchOption.AllDirectories)
            .Where(directory => directory.EndsWith(tail, StringComparison.OrdinalIgnoreCase))
            .Where(directory => Directory.EnumerateFiles(directory, "*.ers", SearchOption.TopDirectoryOnly).Any())
            .Where(directory => Directory.EnumerateFiles(directory, "*.bin", SearchOption.TopDirectoryOnly).Any())
            .OrderBy(directory => directory, StringComparer.Ordinal)
            .FirstOrDefault();
    }


    /// <summary>
    /// Walks up from the test assembly's output directory to the repository root and resolves the local
    /// reference-artifact clone's own root relative to it.
    /// </summary>
    /// <returns>The directory's full path, or <see langword="null"/> when it is not present.</returns>
    private static string? TryFindReferenceMaterialDirectory()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while(current is not null && !File.Exists(Path.Combine(current.FullName, "Verifiable.slnx")))
        {
            current = current.Parent;
        }

        if(current is null)
        {
            return null;
        }

        string referenceMaterial = Path.Combine(current.FullName, "tempdocs", "etsi-ades-reference");

        return Directory.Exists(referenceMaterial) ? referenceMaterial : null;
    }


    /// <summary>What every test reports when the optional local reference-artifact clone is not present.</summary>
    private static string MissingCloneMessage =>
        "The local reference-artifact clone (tempdocs/etsi-ades-reference) was not found; the Evidence Record corpus is optional local reference material, not a repository asset.";


    /// <summary>
    /// Walks up from the test assembly's output directory to the repository root and resolves the Evidence
    /// Record resources directory of the local reference-artifact clone relative to it — the same marker-file
    /// search <c>ReferenceArtifactArchiveTimestampCoverageTests</c> uses for its own corpus.
    /// </summary>
    /// <returns>The directory's full path, or <see langword="null"/> when it is not present.</returns>
    private static string? TryFindArtifactDirectory()
    {
        string? referenceMaterial = TryFindReferenceMaterialDirectory();
        if(referenceMaterial is null)
        {
            return null;
        }

        //The clone's own directory names are not spelled here. The Evidence Record resources are found by the
        //layout every module of that corpus shares — an "evidence-record" directory under
        //"src/test/resources/validation" — and the first such directory in ordinal order that actually holds
        //binary Evidence Records is the one used.
        string tail = Path.Combine("src", "test", "resources", "validation", "evidence-record");

        return Directory.EnumerateDirectories(referenceMaterial, "evidence-record", SearchOption.AllDirectories)
            .Where(directory => directory.EndsWith(tail, StringComparison.OrdinalIgnoreCase))
            .Where(directory => Directory.EnumerateFiles(directory, "*.ers", SearchOption.TopDirectoryOnly).Any())
            .OrderBy(directory => directory, StringComparer.Ordinal)
            .FirstOrDefault();
    }
}
