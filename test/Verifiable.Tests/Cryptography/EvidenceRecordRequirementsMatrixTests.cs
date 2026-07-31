using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The RFC 2119 requirements matrix for the two Evidence Record specifications this wave builds against: every
/// normative statement of <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> (Evidence Record
/// Syntax, the ASN.1 form) and of <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see>
/// (Extensible Markup Language Evidence Record Syntax, the XML form). Mirrors the DynamicData-rows-as-spec-cells
/// shape of <c>AsicRequirementsMatrixTests</c> (ETSI EN 319 162-1/-2),
/// <c>CAdESRequirementsMatrixTests</c> (ETSI EN 319 122-1) and
/// <c>SignatureValidationRequirementsMatrixTests</c> (ETSI EN 319 102-1).
/// </summary>
/// <remarks>
/// <para>
/// Every distinct normative statement of the two documents is one <see cref="RequirementMatrixRow"/>.
/// <see cref="RequirementMatrixTest"/> fails a row that is neither <see cref="RequirementCoverageStatus.Tested"/>
/// nor <see cref="RequirementCoverageStatus.OutOfScope"/> nor <see cref="RequirementCoverageStatus.KnownDefect"/>
/// — no silent gaps — and, for the first and last dispositions, additionally resolves the cited evidence through
/// reflection over the compiled test assembly: a row citing a class or method that does not exist, or that is not
/// itself a <c>[TestMethod]</c>, fails.
/// </para>
/// <para>
/// <strong>Both documents hide obligations in lowercase modal verbs, and the rows below carry them.</strong>
/// RFC 4998's clause 1.4 blesses only the capitalized keyword forms, yet roughly half of its real obligations —
/// concentrated in clauses 4.3, 5.2, 5.3 and the whole of Appendix A — are written "must"/"has to be"/"have to
/// be"/"it is recommended" in lower case; the R1-R79 identifiers below are the enumeration that already folds
/// them in. RFC 6283 has the same defect in a different place: its S1-S95 identifiers are the capitalized
/// statements, and the four most operationally load-bearing procedures it defines (the clause 3.2.2 reduction,
/// the clause 4.2.2 hash-tree renewal, the clause 4.3 chain verification and the whole of Appendix A) are each
/// introduced by a lowercase or keyword-free governing phrase. Those carry <c>-lc</c> identifiers and are treated
/// as binding regardless of their capitalization.
/// </para>
/// <para>
/// <strong>Two rulings this wave made against the specification text are stated at their own rows.</strong>
/// The Hash-Tree Renewal concatenation of RFC 4998 clause 5.2 step 4 (<c>rfc4998-5.2-R34</c>) is a genuine
/// internal contradiction in that document, and the empirical cross-check the wave ran against third-party
/// records overrode the ruling the wave contract had made from the text alone. The
/// <c>id-aa-er-internal</c>/<c>id-aa-er-external</c> selection-method mapping (<c>rfc4998-A-mapping</c>) is
/// never stated in the RFC's prose at all and was settled the same way. Both rows carry the verdict.
/// </para>
/// <para>
/// Most rows cite a deep behavioural test that already drives the clause through the shipped surface (stages 1-3
/// and 8-9 of this wave; every cited test was read before being cited, not merely matched by name). Five clauses
/// had no covering test anywhere in the suite and are driven directly by new tests in this class:
/// <see cref="AVersionBelowOneIsRefused"/> (RFC 4998 clause 3.1),
/// <see cref="TheAttributesSetIsWrittenInCanonicalOrderAndReadInWhateverOrderItArrives"/> (clause 4.1),
/// <see cref="ARecordStatingEncryptionInfoIsRefusedRatherThanVerified"/> (clause 6),
/// <see cref="AChainWhoseMembersNameDifferentAlgorithmsIsRefused"/> (clauses 5.1 and 5.3 step 2 c)) and
/// <see cref="TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel"/> (RFC 6283 clauses 2.1 and
/// 3.1.3), each of which calls the shipped surface itself rather than asserting the row's metadata.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EvidenceRecordRequirementsMatrixTests
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
    /// <param name="ClauseId">The clause and statement identifier the requirement comes from, prefixed <c>rfc4998-</c> or <c>rfc6283-</c>; the trailing <c>R</c>/<c>S</c> number is the spec leg's own enumeration and a <c>-lc</c> suffix marks a lowercase-governed obligation.</param>
    /// <param name="Requirement">A short digest of the normative statement, close enough to the specification's own wording to be checked against it.</param>
    /// <param name="Status">The coverage disposition.</param>
    /// <param name="Evidence">For <see cref="RequirementCoverageStatus.Tested"/>/<see cref="RequirementCoverageStatus.KnownDefect"/>, the asserting test's <c>ClassName.MethodName</c> (optionally followed by explanatory prose in parentheses) — the leading token is resolved through reflection; for <see cref="RequirementCoverageStatus.OutOfScope"/>, the contract, charter or recorded-flag reason.</param>
    internal sealed record RequirementMatrixRow(string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence);


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The address the new behavioural tests' transport delegates are handed; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.evidence-record-matrix.example.test/";

    /// <summary>The first synthetic attribute type of <see cref="TheAttributesSetIsWrittenInCanonicalOrderAndReadInWhateverOrderItArrives"/>, whose encoding sorts before the other's.</summary>
    private const string LowerAttributeType = "1.2.3.4";

    /// <summary>The second synthetic attribute type, whose encoding sorts after <see cref="LowerAttributeType"/>'s: the two differ in exactly the last content octet of the object identifier, so the DER <c>SET OF</c> order is decided there and nowhere else.</summary>
    private const string HigherAttributeType = "1.2.3.5";

    /// <summary>The synthetic <c>encryptionInfoType</c> of <see cref="ARecordStatingEncryptionInfoIsRefusedRatherThanVerified"/>. Clause 6 registers no algorithm at all, so any value here is one no verifier could act on, which is the point of the case.</summary>
    private const string EncryptionInfoType = "1.2.3.6";

    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The <c>genTime</c> every minted archive time-stamp of this class asserts.</summary>
    private static DateTimeOffset ArchiveTime { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The data object every record of this class archives.</summary>
    private static byte[] DataObject { get; } = [.. "the archived data object of the Evidence Record requirements matrix"u8];


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
    /// RFC 4998 clause 3.1: "An implementation conforming to this specification SHOULD reject a version value
    /// below 1." The floor is enforced where the octets are read, so a record stating a version this
    /// specification never defined never reaches a verifier at all.
    /// </summary>
    /// <remarks>
    /// The same rewrite at the stated floor is read back without complaint, which is what makes the refusal a
    /// statement about the version rather than about the rewriting. No test anywhere in the suite drove this
    /// clause before; it is closed here per the stage-10 gap discipline.
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
    /// before.
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
    /// none. The same record without the field verifies, so the refusal is the field and nothing else.
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
    /// <c>digestAlgorithm [0]</c> field.
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
    /// RFC 6283 clause 2.1 makes <c>SupportingInformationList</c> and the <c>Attributes</c> element of an Archive
    /// Time-Stamp optional, clause 3.1.3 makes <c>CryptographicInformationList</c> optional and both its
    /// <c>Order</c> and <c>Type</c> attributes required, and clause 10 closes the <c>Type</c> enumeration at four
    /// IANA-registered values. A record carrying all three optional structures is read into the model with each
    /// surfaced, and still proves its data object.
    /// </summary>
    /// <remarks>
    /// The model carried these members from stage 9 and no document in the suite exercised any of them: every
    /// minted document and every case built on it carries a hash tree and a time-stamp and nothing else. The
    /// structures are added to a minted document rather than written from scratch, so what is read is a record an
    /// independent factory produced with three elements inserted into it.
    /// </remarks>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel()
    {
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(new FakeTimeProvider(TestClock.CanonicalEpoch), notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, new FakeTimeProvider(TestClock.CanonicalEpoch), notBefore: NotBefore, notAfter: NotAfter);
        byte[] minted = XmlEvidenceRecordTestFactory.MintInitial(
            [[EvidenceRecordOracle.Hash(DataObject, PkiDigestAlgorithm.Sha256)]],
            PkiDigestAlgorithm.Sha256,
            XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri,
            authority,
            [authority, root],
            ArchiveTime);

        string certificate = Convert.ToBase64String(root.Certificate.RawData);
        byte[] document = WithOptionalInformationElements(minted, certificate);

        using XmlEvidenceRecordParseResult parsed = await XmlEvidenceRecordXmlBinding.ParseAsync(
            new XmlEvidenceRecordParseContext { Document = document }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parsed.IsValid, $"The record with all three optional structures parses ({parsed.Status}: {parsed.FailureReason}).");

        XmlEvidenceRecord record = parsed.EvidenceRecord!;
        Assert.HasCount(1, record.SupportingInformation, "Clause 2.1's optional SupportingInformationList is read.");
        Assert.AreEqual(XmlEvidenceRecordWellKnown.CertificateInformationType, record.SupportingInformation[0].InformationType,
            "Clause 2.1: cryptographic information stored there uses the type clause 3.1.3 defines.");

        XmlEvidenceRecordArchiveTimeStamp member = record.Chains[0].ArchiveTimeStamps[0];
        Assert.HasCount(1, member.Attributes, "Clause 2.1's optional Attributes element is read.");
        Assert.AreEqual(1, member.Attributes[0].Order, "Its Order attribute is required and is read.");

        Assert.HasCount(1, member.TimeStamp.CryptographicInformation, "Clause 3.1.3's optional CryptographicInformationList is read.");
        XmlEvidenceRecordCryptographicInformation information = member.TimeStamp.CryptographicInformation[0];
        Assert.AreEqual(1, information.Order, "Clause 3.1.3 makes Order required.");
        Assert.AreEqual(XmlEvidenceRecordWellKnown.CertificateInformationType, information.InformationType, "Clause 3.1.3 makes Type required and closes it at four registered values.");
        Assert.AreSequenceEqual(root.Certificate.RawData, information.Content.AsReadOnlySpan().ToArray(),
            "A CERT entry's content is the base64 of a DER-encoded certificate, decoded to those octets and no others.");

        using XmlEvidenceRecordVerification verification = await XmlEvidenceRecords.VerifyAsync(
            new XmlEvidenceRecordVerificationContext
            {
                EvidenceRecord = record,
                Document = document,
                DataObjects = [new XmlEvidenceRecordDataObject { Content = DataObject }],
                Canonicalize = XmlEvidenceRecordXmlBinding.CanonicalizeAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, verification.Status,
            "The three structures sit outside everything the initial Archive Time-Stamp's hash tree covers, so the record still proves its data object.");
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
        Type? evidenceType = typeof(EvidenceRecordRequirementsMatrixTests).Assembly.GetTypes()
            .FirstOrDefault(candidate => string.Equals(candidate.Name, className, StringComparison.Ordinal));
        Assert.IsNotNull(evidenceType, $"{row.ClauseId}: evidence class '{className}' does not exist in the test assembly.");

        MethodInfo? evidenceMethod = evidenceType!.GetMethod(
            methodName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
        Assert.IsNotNull(evidenceMethod, $"{row.ClauseId}: evidence method '{className}.{methodName}' does not exist.");
        Assert.IsNotEmpty(evidenceMethod!.GetCustomAttributes(typeof(TestMethodAttribute), inherit: false),
            $"{row.ClauseId}: evidence '{className}.{methodName}' is not a [TestMethod] — the matrix must cite a real test.");
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


    /// <summary>
    /// Adds the three optional information structures of RFC 6283 clauses 2.1 and 3.1.3 to a minted document: a
    /// <c>SupportingInformationList</c> at the record level, a <c>CryptographicInformationList</c> inside the
    /// Archive Time-Stamp's <c>TimeStamp</c> element, and an <c>Attributes</c> element on the Archive Time-Stamp
    /// itself, each placed where clause 8's schema sequences it.
    /// </summary>
    /// <param name="document">The minted document's octets.</param>
    /// <param name="certificateBase64">The base64 of a DER-encoded certificate, which is what a <c>CERT</c>-typed entry carries.</param>
    /// <returns>The changed document's octets.</returns>
    private static byte[] WithOptionalInformationElements(byte[] document, string certificateBase64)
    {
        XNamespace ns = XmlEvidenceRecordWellKnown.EvidenceRecordNamespace;
        XDocument parsed = XDocument.Parse(System.Text.Encoding.UTF8.GetString(document));
        XElement root = parsed.Root!;

        //Clause 8: EvidenceRecordType sequences EncryptionInformation?, SupportingInformationList?,
        //ArchiveTimeStampSequence, so the list goes before the sequence that is already there.
        root.AddFirst(new XElement(
            ns + XmlEvidenceRecordWellKnown.SupportingInformationListElementName,
            new XElement(
                ns + XmlEvidenceRecordWellKnown.SupportingInformationElementName,
                new XAttribute(XmlEvidenceRecordWellKnown.TypeAttributeName, XmlEvidenceRecordWellKnown.CertificateInformationType),
                certificateBase64)));

        XElement archiveTimeStamp = root.Descendants(ns + XmlEvidenceRecordWellKnown.ArchiveTimeStampElementName).First();
        XElement timeStamp = archiveTimeStamp.Element(ns + XmlEvidenceRecordWellKnown.TimeStampElementName)!;

        //Clause 8: TimeStampType sequences TimeStampToken, CryptographicInformationList?.
        timeStamp.Add(new XElement(
            ns + XmlEvidenceRecordWellKnown.CryptographicInformationListElementName,
            new XElement(
                ns + XmlEvidenceRecordWellKnown.CryptographicInformationElementName,
                new XAttribute(XmlEvidenceRecordWellKnown.OrderAttributeName, 1),
                new XAttribute(XmlEvidenceRecordWellKnown.TypeAttributeName, XmlEvidenceRecordWellKnown.CertificateInformationType),
                certificateBase64)));

        //Clause 8: ArchiveTimeStampType sequences HashTree?, TimeStamp, Attributes?.
        archiveTimeStamp.Add(new XElement(
            ns + XmlEvidenceRecordWellKnown.AttributesElementName,
            new XElement(
                ns + XmlEvidenceRecordWellKnown.AttributeElementName,
                new XAttribute(XmlEvidenceRecordWellKnown.OrderAttributeName, 1),
                new XAttribute(XmlEvidenceRecordWellKnown.TypeAttributeName, "urn:example:an-attribute-type"),
                "the policy information clause 2.1 would have an Attributes element carry")));

        return System.Text.Encoding.UTF8.GetBytes(parsed.ToString(SaveOptions.DisableFormatting));
    }


    /// <summary>
    /// Every row of the matrix, as a plain data table. Kept as one literal so a reviewer can scan the whole
    /// Evidence Record requirement surface — and its disposition — in one place. Rows follow the two documents'
    /// own structure: RFC 4998 clauses 2-7 and its normative Appendix A, then RFC 6283 clauses 2-10 and its
    /// normative Appendix A, with each document's lowercase-governed obligations at the end of the clause they
    /// govern.
    /// </summary>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] RowData { get; } =
    [
        //---- IETF RFC 4998 clause 2.1 — module precedence ----
        ("rfc4998-2.1-R1", "If there is a conflict between both ASN.1 modules, the 1988-ASN.1 module precedes.",
            RequirementCoverageStatus.Tested, "EvidenceRecordsTests.ARecordRoundTripsWithoutChangingItsOctets (the codec is written against Appendix B's 1988 module throughout; both modules declare IMPLICIT TAGS with identical tag numbers, so a conformant value's DER octets are the same either way, and third-party records of two independent corpora decode under this grammar in ReferenceArtifactEvidenceRecordTests.TheBinaryCorpusRenewedRecordsCarryThePositionalCombination)"),

        //---- IETF RFC 4998 clause 3.1 — EvidenceRecord syntax ----
        ("rfc4998-3.1-R2", "An implementation SHOULD reject a version value below 1.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.AVersionBelowOneIsRefused (the floor is enforced where the octets are read; the same rewrite at the floor is read back, so the refusal is the version)"),
        ("rfc4998-3.1-R3", "cryptoInfos items may be added based on the policy used.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.ARenewalCarriesTheRecordsCryptoInfosForward (the field is optional, carried octet for octet across a renewal, and never rewritten — stage-2 decision 7)"),
        ("rfc4998-3.1-R4", "Since cryptoInfos data is not protected within any timestamp, it should be verifiable through other mechanisms.",
            RequirementCoverageStatus.OutOfScope, "An external trust obligation on the CONTENT of an unprotected field, not a structural check the Evidence Record verifier performs. The \"other mechanism\" in this repository is the already-shipped trust machinery (the trusted-list qualification surface of wave 1 and the party trust engine); the Evidence Record surface parses cryptoInfos and neither trusts nor validates it, which is what the clause's own \"not protected within any timestamp\" requires of it."),
        ("rfc4998-3.1-R5", "The ordering of the digestAlgorithms values is not relevant.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.RenewingTwiceUnderOneAlgorithmNamesItOnce (creation states each algorithm once and never sorts; the reading side never consults the field's order, which is why the two-chain third-party records of ReferenceArtifactEvidenceRecordTests.ARenewedRecordLinksItsChainsThePositionalWay verify whatever order their producers wrote)"),

        //---- IETF RFC 4998 clause 4.1 — ArchiveTimeStamp syntax ----
        ("rfc4998-4.1-R6", "If the optional digestAlgorithm field is not present, the digest algorithm of the timestamp MUST be used.",
            RequirementCoverageStatus.Tested, "EvidenceRecordsTests.StatingTheDigestAlgorithmFieldIsTheOtherWayToBindTheTreesAlgorithm (both resolutions reach the same tree; the absent-field case is the default every other test of the class runs under)"),
        ("rfc4998-4.1-R7", "Attributes is a SET rather than a SEQUENCE because \"the ordering is relevant\".",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.TheAttributesSetIsWrittenInCanonicalOrderAndReadInWhateverOrderItArrives (the clause's rationale is inverted relative to X.690 clause 11.6, so this library writes the canonical order DER requires and reads whatever order arrives, surfacing the members verbatim — stage-1 decision 9)"),
        ("rfc4998-4.1-R8", "timeStamp should contain the timestamp as defined in clause 1.3, for example an RFC 3161 TimeStampToken.",
            RequirementCoverageStatus.Tested, "EvidenceRecordsTests.AnInitialRecordOverOneDataObjectVerifies (creation acquires an RFC 3161 token through the shipped acquisition seam and embeds it as the timeStamp field's ContentInfo)"),
        ("rfc4998-4.1-R9", "Other types of timestamp MAY be used if they carry time data, timestamped data and a cryptographically secure confirmation.",
            RequirementCoverageStatus.OutOfScope, "A permission this wave does not take up on the ASN.1 side: the library reads the timeStamp field as an RFC 3161 token through the shipped seam and reports EvidenceRecordVerificationStatus.TimestampNotRead for anything it cannot open, which is the graceful degradation the permission's converse demands of a verifier. The XML sibling's equivalent permission IS exercised, because RFC 6283 clause 3.1.2 registers a second named format to test against (XmlEvidenceRecordsTests.ATimeStampFormatThisLibraryDoesNotReadIsNamedAsSuch); RFC 4998 registers none."),

        //---- IETF RFC 4998 clause 4.2 — ArchiveTimeStamp generation ----
        ("rfc4998-4.2-R10", "A data group's document hashes are binary sorted ascending, concatenated and hashed, over the complete output with leading zeros retained and the most significant bit first.",
            RequirementCoverageStatus.Tested, "EvidenceRecordHashTreeTests.TheComparatorIsUnsignedAndKeepsLeadingZeros (the near-misses a signed compare, zero-stripping and a hex compare would produce, each ruled out) and EvidenceRecordHashTreePropertyTests.TheComparatorAgreesWithAnIndependentUnsignedComparisonOnEveryPair"),
        ("rfc4998-4.2-R11", "Hash values are placed in groups, each group sorted binary ascending, concatenated and hashed to build the next level; any data may be hashed and used where additional hash values are needed.",
            RequirementCoverageStatus.Tested, "EvidenceRecordHashTreeTests.EveryDataObjectOfAMultiLevelTreeReducesBackToTheRoot (arity 2, 3 and 4 over 2, 4, 7, 16, 10 and 17 groups) and EvidenceRecordHashTreeTests.AnOddNodeCountCarriesTheTrailingNodeUpAndStillReducesToTheRoot (the padding permission is NOT taken: a lone trailing node is carried up unchanged rather than padded with a value the record would have to preserve forever — stage-1 decision 4)"),
        ("rfc4998-4.2-R12a", "The hash algorithm in the timestamp request MUST be the same as the hash algorithm of the hash tree...",
            RequirementCoverageStatus.Tested, "EvidenceRecordsTests.TheRecordStatesTheRootTheIndependentBuildReaches (the independent decoder reads the message imprint's algorithm off the record's own octets and finds the tree's)"),
        ("rfc4998-4.2-R12b", "...or the digestAlgorithm field of the ArchiveTimeStamp MUST be present and specify the hash algorithm of the hash tree.",
            RequirementCoverageStatus.Tested, "EvidenceRecordsTests.StatingTheDigestAlgorithmFieldIsTheOtherWayToBindTheTreesAlgorithm"),
        ("rfc4998-4.2-R13", "The first list of hash values is the sibling set in binary ascending order; the step repeats for the father node of all hashes until the root; the father nodes themselves are not saved.",
            RequirementCoverageStatus.Tested, "EvidenceRecordHashTreeTests.TheThreeGroupExampleOfClause42ReducesAsFigures2And3Print (the clause's own worked example reproduced structurally) and EvidenceRecordHashTreeTests.EveryPartialHashtreeIsStoredInBinaryAscendingOrder"),
        ("rfc4998-4.2-R14", "It is profitable but not required to build hash trees and reduce them: an Archive Timestamp may consist of one list of hash values and a timestamp, or of a timestamp with no hash value lists.",
            RequirementCoverageStatus.Tested, "EvidenceRecordHashTreeTests.AnEmptyReducedHashtreeMakesTheDataObjectHashTheRoot (the degenerate form is verified; seven artifacts of the reference corpus are written that way, which ReferenceArtifactEvidenceRecordTests.TheBinaryCorpusRenewedRecordsCarryThePositionalCombination reads)"),
        ("rfc4998-4.2-R15", "The data needed to verify the timestamp MUST be preserved, and SHOULD be stored in the timestamp itself unless this causes unnecessary duplication.",
            RequirementCoverageStatus.Tested, "EvidenceRecordSignatureValidationTests.StepOneReportsWhatTheRecordAndItsTimestampConcluded (the record's most recent Archive Timestamp is validated through the EN 319 102-1 clause 5.4 building block, and the certificate material that validation needs comes from the token's own SignedData — the placement the SHOULD names)"),

        //---- IETF RFC 4998 clause 4.3 — ArchiveTimeStamp verification ----
        ("rfc4998-4.3-R16", "An Archive Timestamp shall prove that a data object existed at a certain time, given by timestamp.",
            RequirementCoverageStatus.Tested, "EvidenceRecordsTests.AnInitialRecordOverOneDataObjectVerifies (the goal statement the numbered procedure of R17-R21 exists to establish; the instant is reported as InitialArchiveTime and LatestArchiveTime)"),
        ("rfc4998-4.3-R17", "Step 2: search for hash value h in the first list; if not present, terminate verification with a negative result.",
            RequirementCoverageStatus.Tested, "EvidenceRecordHashTreeTests.AHashValueAbsentFromTheFirstListTerminatesTheWalk and EvidenceRecordsTests.ATamperedDataObjectIsNotCovered"),
        ("rfc4998-4.3-R18", "Step 3: the calculated hash value h' MUST become a member of the next higher list of hash values; continue until a root hash value is calculated.",
            RequirementCoverageStatus.Tested, "EvidenceRecordHashTreeTests.EveryDataObjectOfAMultiLevelTreeReducesBackToTheRoot and EvidenceRecordHashTreePropertyTests.EveryDataObjectWalksItsReducedTreeBackToTheRoot"),
        ("rfc4998-4.3-R19", "Step 4: the root hash value must correspond to hashedMessage and digestAlgorithm must correspond to the hashAlgorithm field, both in the messageImprint of the timeStampToken.",
            RequirementCoverageStatus.Tested, "EvidenceRecordsTests.TheRecordStatesTheRootTheIndependentBuildReaches (both correspondences, read off the record's octets by the independent oracle) and ReferenceArtifactEvidenceRecordTests.ADamagedFirstListWalksToARootTheTokenDoesNotBind (the negative)"),
        ("rfc4998-4.3-R20", "If a proof is necessary for more than one data object, steps 1 and 2 have to be done for all data objects to be proved.",
            RequirementCoverageStatus.Tested, "EvidenceRecordsTests.OneTreeOverSeveralGroupsProducesOneRecordPerGroup (each record proves every one of its own group's objects and none of another group's)"),
        ("rfc4998-4.3-R21", "If an additional proof is necessary that the Archive Timestamp relates to a data object group, it can be verified additionally that only the hash values of the given data objects are in the first hash-value list.",
            RequirementCoverageStatus.Tested, "EvidenceRecordsTests.TheGroupProofHoldsForTheGroupTheRecordWasCreatedFor (the exclusivity check holds for the exact group and fails for a wider one; the check is a caller-stated option, as the clause's \"if\" makes it)"),

        //---- IETF RFC 4998 clause 5 (intro) — lifecycle framing ----
        ("rfc4998-5-R22", "After the renewal, always only the most recent ArchiveTimeStamp and the algorithms and timestamps it uses must be watched regarding expiration and loss of security.",
            RequirementCoverageStatus.OutOfScope, "Operational monitoring over calendar time, which the waveasic contract's Out list names explicitly (\"renewal-TIMING advisory/monitoring (operational guidance; the algorithm-constraints table is the existing seam)\"). What a monitor needs IS surfaced: EvidenceRecordVerification reports LatestArchiveTime, CoveredUntil and the per-member GenerationTime of every Archive Timestamp."),

        //---- IETF RFC 4998 clause 5.1 — chain and sequence syntax ----
        ("rfc4998-5.1-R23", "ArchiveTimeStampChain and ArchiveTimeStampSequence MUST be ordered ascending by time of timestamp.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.ARenewalWhoseTokenPredatesWhatItRenewsIsRefused (creation refuses to write a structure the clause forbids) and EvidenceRecordRenewalTests.ATimestampRenewalAppendsToTheChainItRenews (the produced order). The verifier's own ascending-time check is reported only when nothing else has already failed, so that the first reason a record stopped verifying is the one reported — stage-2 decision 10; no test reaches it, because every structure that breaks the ordering also breaks the linkage the clause-5.3 walk checks first, and the shipped creation surface cannot produce one that does not."),
        ("rfc4998-5.1-R24", "Within an ArchiveTimeStampChain, all reducedHashtrees of the contained ArchiveTimeStamps MUST use the same Hash-Algorithm.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.AChainWhoseMembersNameDifferentAlgorithmsIsRefused (the verifier) and EvidenceRecordRenewalTests.AHashTreeRenewalStartsANewChainUnderTheNewAlgorithm (the generator, which starts a new chain rather than mixing algorithms in one)"),

        //---- IETF RFC 4998 clause 5.2 — Timestamp Renewal and Hash-Tree Renewal ----
        ("rfc4998-5.2-R25", "Before cryptographic algorithms become weak or timestamp certificates become invalid, Archive Timestamps have to be renewed by generating a new Archive Timestamp.",
            RequirementCoverageStatus.OutOfScope, "The trigger is operational monitoring over calendar time, which the waveasic contract's Out list names (renewal-TIMING advisory/monitoring). The MECHANICS the clause then prescribes are R26-R37 below, all implemented and tested."),
        ("rfc4998-5.2-R26", "In the case of Timestamp Renewal, the content of the timeStamp field of the old Archive Timestamp has to be hashed and timestamped by a new Archive Timestamp.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.ATimestampRenewalBindsTheWholeTimeStampElementOfTheStructureBeforeIt (RULING: the WHOLE timeStamp element, tag and length octets included, not its content octets — stage-1 decision 7, confirmed empirically on six records of two independent third-party corpora, which ReferenceArtifactEvidenceRecordTests.TheBinaryCorpusRenewedRecordsCarryThePositionalCombination reads)"),
        ("rfc4998-5.2-R27", "The new Archive Timestamp MAY omit a reducedHashtree field if the timestamp only covers the previous timestamp.",
            RequirementCoverageStatus.Tested, "EvidenceRecordHashTreeTests.AnEmptyReducedHashtreeMakesTheDataObjectHashTheRoot (verification accepts both forms, and seven artifacts of the reference corpus are written the omitting way). The permission is not taken on the generation side: a renewal always writes the tree, because a structure that names what it covers is checkable on its own — stage-2 decision 5."),
        ("rfc4998-5.2-R28", "The new Archive Timestamp MUST be added to the ArchiveTimestampChain.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.ATimestampRenewalAppendsToTheChainItRenews (the renewed structure appends and leaves the Archive Timestamp it renews verbatim)"),
        ("rfc4998-5.2-R29", "This hash tree of the new Archive Timestamp MUST use the same hash algorithm as the old one, taken from the digestAlgorithm field or, if unset, from the timestamp itself.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.RenewingRecordsOfDifferentAlgorithmsTogetherIsRefused (the algorithm is DERIVED from the structure being renewed and never taken from the caller, and a batch resolving to two algorithms is refused rather than split — stage-2 decision 3)"),
        ("rfc4998-5.2-R30", "In the case of Hash-Tree Renewal, the Archive Timestamp and the archived data objects covered by it must be hashed and timestamped again.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.AHashTreeRenewalBindsThePositionalCombinationOfTheDataObjectAndThePriorSequence"),
        ("rfc4998-5.2-R31", "Step 1: select a secure hash algorithm H.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.AHashTreeRenewalStartsANewChainUnderTheNewAlgorithm (the new algorithm is the caller's choice and is named in the record's digestAlgorithms; the algorithm space this library computes at all is closed at SHA-256/384/512, which is the R56 row)"),
        ("rfc4998-5.2-R32", "Step 2: select the data objects referred to by the initial Archive Timestamp that are still present and not deleted.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.ADataObjectLeftOutOfARenewalIsProvedOnlyToTheChainThatCarriedIt (a dropped object is not an error and its group companion is still proved to the renewal — the deletion tolerance the clause states)"),
        ("rfc4998-5.2-R33", "Step 3: atsc(i) is the encoded ArchiveTimeStampSequence of all previous chains related to the data object; the chains used are DER encoded, i.e. they contain sequence and length tags.",
            RequirementCoverageStatus.Tested, "EvidenceRecordsTests.TheEncodedSequenceWrapsTheChainsInItsOwnElement (the wrapper adds exactly its own tag and length octets on top of each chain's) and EvidenceRecordRenewalTests.ReplacingAPriorChainWithAnEquallyValidOneBreaksTheLink (what atsc(i) binds is those octets and not an equivalent proof)"),
        ("rfc4998-5.2-R34", "Step 4: concatenate each h(i) with ha(i) and generate hash values h(i)' = H(h(i) + ha(i)).",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.TheRenewalCombinationIsThePositionalReadingWhereTheTwoReadingsDiffer — RULING, and the wave contract's own ruling was OVERTURNED by evidence (owner flag 3): RFC 4998 contradicts itself here — this step-4 prose states a POSITIONAL concatenation while the worked example of Figure 4 states \"binary sorted and concatenated\" for the very same value, and the two are wire-incompatible. Contract R-2 chose the figure's sorted reading from the text alone and required an empirical cross-check before the surface froze; the cross-check found FIVE discriminating third-party records across two independent corpora carrying the POSITIONAL value and ZERO carrying the sorted one, so the wave ships the prose. ReferenceArtifactEvidenceRecordTests.TheBinaryCorpusRenewedRecordsCarryThePositionalCombination is the third-party half and the property test EvidenceRecordRenewalPropertyTests.TheRenewalCombinationIsDeterministicAndMatchesTheIndependentComputation asserts the sorted reading is NOT what the library computes wherever the two differ."),
        ("rfc4998-5.2-R35", "Step 5: the first hash value list in the reduced hash tree should only contain h(i)'.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.ABatchedHashTreeRenewalGivesEachRecordAFirstListHoldingItsOwnRenewalValueAlone (each record of a batch gets a first list holding its own h(i)' and nothing else, the other records' renewal values carried on the level after it) and EvidenceRecordRenewalTests.ABatchedRenewalOfAMultiDocumentGroupGivesItAFirstListOfExactlyItsOwnValues (the sentence's second half: a multi-document group's first list holds the new hashes of all its own documents and no others). This step is where clause 5.2 DEPARTS from the reduction of clause 4.2, whose own Figure 2 merges a one-document group's value with its level-zero siblings into the first list — the departure needs the extra PartialHashtree level RFC 6283 clause 3.2.2 steps 2 and 3 print for the same mechanism, and it is what makes clause 1.3's \"relates to\" and clause 4.3's closing group proof true of a renewal chain. Both shapes recompute the same root, which is why the earlier citations (AHashTreeRenewalBindsThePositionalCombinationOfTheDataObjectAndThePriorSequence and EvidenceRecordRenewalPropertyTests.EveryRenewalValueWalksItsReducedTreeBackToTheRoot) did NOT assert this requirement's content: they hold under the merged shape too, and a batch of several single-document records produced it."),
        ("rfc4998-5.2-R36", "Step 6: create a new ArchiveTimeStampChain containing the new Archive Timestamp and append it to the ArchiveTimeStampSequence.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.AHashTreeRenewalStartsANewChainUnderTheNewAlgorithm (the prior chain is carried verbatim and the new one appended)"),
        ("rfc4998-5.2-R37", "ArchiveTimeStamps that are not necessary for verification should not be added to an ArchiveTimeStampChain or ArchiveTimeStampSequence.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.SeveralRecordsAreRenewedTogetherByOneTimestampRenewal (one Archive Timestamp per renewal, shared by every record the batch renewed — the batched shape of clause 3.2's centralized mode, which is exactly the economy this clause asks for; nothing else is ever appended)"),

        //---- IETF RFC 4998 clause 5.3 — chain and sequence verification ----
        ("rfc4998-5.3-R38", "The Archive Timestamp Chains and their relations to each other and to the data objects have to be proved.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.EveryPriorChainStillVerifiesAfterEachRenewal (the framing the numbered steps R39-R48 implement, taken across both renewal kinds in succession)"),
        ("rfc4998-5.3-R39", "Step 1: verify that the initial Archive Timestamp contains the hash value of the data object.",
            RequirementCoverageStatus.Tested, "EvidenceRecordsTests.AnInitialRecordOverOneDataObjectVerifies"),
        ("rfc4998-5.3-R40", "Step 2 a): the first hash value list of each ArchiveTimeStamp MUST contain the hash value of the timestamp of the Archive Timestamp before.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.ATimestampRenewalBindsTheWholeTimeStampElementOfTheStructureBeforeIt"),
        ("rfc4998-5.3-R41", "Step 2 b): each Archive Timestamp MUST be valid relative to the time of the following Archive Timestamp.",
            RequirementCoverageStatus.OutOfScope, "PARTIAL, and the part that is missing is stated exactly. Three halves of \"valid relative to the time of the following Archive Timestamp\" ARE decided: the structural link (R40's first-list check), the ascending order (R23), and the algorithm's reliability at the following member's instant (R43, which the engine now gates the proof on). What is NOT decided is the TOKEN trust of an earlier member — its certificate path, its revocation state and its trust anchor evaluated at the instant of the member that follows it. That is the EN 319 102-1 clause 5.4 building block run at a historical instant, and the engine composes it for the record's most recent Archive Timestamp alone (the R46 row); running it for every earlier member is a per-token past-validation walk this wave did not build. Stage-1 decision 14 left the temporal half to the caller, and what this surface states for such a caller is the per-member GenerationTime of every Archive Timestamp. The row stays OutOfScope rather than Tested because a chain whose earlier token was minted with a compromised authority key is not detected."),
        ("rfc4998-5.3-R42", "Step 2 c): all Archive Timestamps within a chain MUST use the same hash algorithm.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.AChainWhoseMembersNameDifferentAlgorithmsIsRefused (the offending member is named and the algorithm it stated reported)"),
        ("rfc4998-5.3-R43", "Step 2 d): that algorithm MUST be secure at the time of the first Archive Timestamp of the following ArchiveTimeStampChain.",
            RequirementCoverageStatus.Tested, "EvidenceRecordSignatureValidationTests.AnEarlierChainAlgorithmTheTableDatesUnreliableAtTheRenewalWithholdsTheProof (a record whose first chain's algorithm the caller's dated table stops asserting reliable BEFORE the renewal instant establishes no proof of existence, and the assessment naming that chain and that instant is reported) and EvidenceRecordSignatureValidationTests.TheSameRenewedRecordProvesTheSignatureWhenTheTableReachesTheRenewalInstant (the same record and the same run with one date changed, at the boundary instant the step's \"AT the time of\" includes). The gate is the engine's, not this surface's: the record itself carries no policy, so EN 319 102-1 clause 5.6.3.4 step 1) applies the caller's AlgorithmReliabilityEntry table to each chain's own digest algorithm at the instant the chain after it was created, and to the most recent chain at the validation time. A run supplying no table is left where it was — EvidenceRecordSignatureValidationTests.ARunStatingNoCryptographicTableLeavesTheEvidenceRecordStepWhereItWas — because this library ships no dated table and invents none (waveasic contract R-10)."),
        ("rfc4998-5.3-R44", "Step 3 a): verify that the first hash value list of the first Archive Timestamp of every other chain contains the hash value of the concatenation of the data object hash and the hash of all older chains.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.AHashTreeRenewalBindsThePositionalCombinationOfTheDataObjectAndThePriorSequence and EvidenceRecordRenewalTests.ChangingAPriorChainOctetLeavesTheRenewedRecordProvingNothing (the same concatenation ruling as R34 governs what this step must reproduce)"),
        ("rfc4998-5.3-R45", "Step 3 b): verify that this Archive Timestamp was generated before the last Archive Timestamp of the previous chain became invalid.",
            RequirementCoverageStatus.OutOfScope, "\"Became invalid\" is the same historical-instant TOKEN-validity question the R41 row states as the remaining gap — the clause 5.4 building block run against an earlier member, which a caller composes (stage-1 decision 14). The two halves a verifier can settle without a trust evaluation ARE settled: the ordering is refused at generation by EvidenceRecordRenewalTests.ARenewalWhoseTokenPredatesWhatItRenewsIsRefused, and the previous chain's algorithm having become unreliable by the new chain's instant withholds the proof (the R43 row's biting test)."),
        ("rfc4998-5.3-R46", "In order to complete the non-repudiation proof, the last Archive Timestamp has to be valid at the time the verification is performed.",
            RequirementCoverageStatus.Tested, "EvidenceRecordSignatureValidationTests.StepOneReportsWhatTheRecordAndItsTimestampConcluded (the engine validates the record's most recent Archive Timestamp through the EN 319 102-1 clause 5.4 building block at validation time). This row states THAT obligation and no more: validating the newest token establishes that the newest token is trustworthy now, and the chain linkage of R40 establishes only that an earlier token's octets existed by the newest token's genTime — never that an earlier token's own asserted genTime is trustworthy, which is why R41 and R45 remain OutOfScope. What the engine additionally requires before it states the initial-time proof is that the object's own unbroken run of proofs REACHES this validated token — coverage is per chain, so EvidenceRecordSignatureValidationTests.TheSameRenewedRecordProvesTheSignatureWhenTheTableReachesTheRenewalInstant asserts CoveredUntil against the record's most recent Archive Timestamp rather than assuming they coincide."),
        ("rfc4998-5.3-R47", "If the proof is necessary for more than one data object, steps 1 and 3 have to be done for all these data objects.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.ADataObjectLeftOutOfARenewalIsProvedOnlyToTheChainThatCarriedIt (each object is walked separately across every chain, which is what makes the per-object answer differ) and EvidenceRecordsTests.OneTreeOverSeveralGroupsProducesOneRecordPerGroup"),
        ("rfc4998-5.3-R48", "To prove the sequence relates to a data object group, verify that the first hash value list of the first Archive Timestamp of the first chain contains no other hash values than the group's.",
            RequirementCoverageStatus.Tested, "EvidenceRecordsTests.TheGroupProofHoldsForTheGroupTheRecordWasCreatedFor (the sequence-level analogue of R21, checked on the first chain's initial structure, which is where the data objects themselves are named)"),

        //---- IETF RFC 4998 clause 6 — encryption ----
        ("rfc4998-6-R49", "Where encrypted data objects are archived, additional special precautions have to be taken.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.ARecordStatingEncryptionInfoIsRefusedRatherThanVerified (the precaution this library takes is to recognise the field and refuse the record: clause 3.3 step 2 requires the data objects to be re-encrypted before verification and clause 6 registers no algorithm that would say how)"),
        ("rfc4998-6-R50", "Only encryption methods should be used that make it possible to prove that archive-timestamped encrypted data objects unambiguously represent unencrypted data objects.",
            RequirementCoverageStatus.OutOfScope, "The waveasic contract's Out list: \"EncryptionInfo (RFC 4998 clause 6: zero registered algorithm bindings in the base RFC — recognition-only, never emitted)\". This is an obligation on the choice of an external encryption scheme, not a structural rule of the Evidence Record syntax."),
        ("rfc4998-6-R51", "All data necessary to prove unambiguous representation should be included in the archived data objects.",
            RequirementCoverageStatus.OutOfScope, "Same contract Out list entry as R50; a property of the external scheme's own inputs."),
        ("rfc4998-6-R52", "The long-term security of the encryption schemes should be analysed to determine whether it could be used to create collision attacks.",
            RequirementCoverageStatus.OutOfScope, "Same contract Out list entry as R50; an external cryptanalysis obligation, not an implementer check."),
        ("rfc4998-6-R53", "It must be possible to unambiguously re-encrypt the unencrypted data to get exactly the data that was originally archived.",
            RequirementCoverageStatus.OutOfScope, "Same contract Out list entry as R50; a property of the chosen encryption scheme. This library refuses rather than assumes it (the R49 row)."),
        ("rfc4998-6-R54", "Additional data necessary to re-encrypt data objects should be inserted into the evidence record by the client.",
            RequirementCoverageStatus.OutOfScope, "Same contract Out list entry as R50: encryptionInfo is recognised and NEVER emitted, because anything this library wrote there would be a value clause 6 gives no verifier a way to act on."),
        ("rfc4998-6-R55", "The use of encryptionInfoType and encryptionInfoValue may be heavily dependent on the mechanisms and has to be defined in other specifications.",
            RequirementCoverageStatus.OutOfScope, "Addressed to other specifications, not to an implementation of this one. It is also the stated reason the field is never emitted (the R54 row)."),

        //---- IETF RFC 4998 clause 7 — security considerations ----
        ("rfc4998-7-R56", "Cryptographic algorithms and parameters used within Archive Timestamps must be secure at the time of generation.",
            RequirementCoverageStatus.Tested, "XmlSignatureWellKnownTests.TheXmlFormReachesExactlyTheAlgorithmsTheObjectIdentifierFormReaches (the digest space this library computes at all is closed at SHA-256, SHA-384 and SHA-512 in one place; SHA-1 and MD5 are recognised by name and resolve to nothing, which XmlSignatureWellKnownTests.TheRefusedIdentifiersAreRecognisedByNameAndResolveToNothing asserts). A weak algorithm therefore cannot be named at generation, because the type the creation surface takes has no member for one — the waveasic contract R-10 rule, satisfied by construction rather than by a runtime gate."),
        ("rfc4998-7-R57", "Publications regarding the security suitability of cryptographic algorithms have to be considered by verifying components.",
            RequirementCoverageStatus.OutOfScope, "The dated algorithm-reliability table is a caller-supplied policy input of the EN 319 102-1 engine, consulted where a validation instant exists to evaluate it at; the Evidence Record surface reports the instants and does not evaluate suitability itself (stage-1 decision 14, the same scope line as R41/R43)."),
        ("rfc4998-7-R58", "It is recommended to generate and manage at least two redundant Evidence Records using different hash algorithms and different Time-Stamping Authorities.",
            RequirementCoverageStatus.OutOfScope, "A deployment recommendation about how many Evidence Records an archive keeps, not a structural property of any one of them. The surface produces and verifies one record at a time and a caller is free to keep two; nothing in the library prevents or requires it."),
        ("rfc4998-7-R59", "It is recommended to manage the Archive Timestamps in a central Long-Term Archive service.",
            RequirementCoverageStatus.OutOfScope, "Deployment topology, not implementable as a structural check. The centralized mode itself IS the shape the creation surface takes (one tree, one token, one record per group)."),
        ("rfc4998-7-R60", "Security requirements for Time-Stamping Authorities stated in security policies have to be met.",
            RequirementCoverageStatus.OutOfScope, "Delegates to Time-Stamping Authority and public-key-infrastructure trust evaluation, which is the already-shipped trusted-list and party-trust machinery of wave 1, not new Evidence Record code."),
        ("rfc4998-7-R61", "Renewed Archive Timestamps should have the same or higher quality as the initial Archive Timestamp.",
            RequirementCoverageStatus.OutOfScope, "\"Quality\" is undefined in this document — no metric is given anywhere in it — so there is no pass or fail a verifier could report. The one comparable obligation of the same family that IS checkable was implemented for the XML sibling, whose clause 4.1.1 states it concretely as \"equal or stronger\" (the rfc6283-4.1.1-S63 row)."),
        ("rfc4998-7-R62", "Archive Timestamps used for signature renewal of signed data should have the same or higher quality than the maximum quality of the signatures.",
            RequirementCoverageStatus.OutOfScope, "Same undefined \"quality\" as R61, and a policy-layer concern of the EN 319 102-1 validation policy rather than of the Evidence Record syntax."),
        ("rfc4998-7-R63", "Users should keep secret their private keys and randoms used for encryption and disclose them only if needed.",
            RequirementCoverageStatus.OutOfScope, "End-user operational security, outside any library's reach."),
        ("rfc4998-7-R64", "They should use encryption algorithms and parameters that are prospected to be unbreakable as long as confidentiality of the archived data is important.",
            RequirementCoverageStatus.OutOfScope, "Same contract Out list entry as R50-R55: the encryption feature is recognition-only."),

        //---- IETF RFC 4998 Appendix A — Evidence Record using CMS ----
        ("rfc4998-A-mapping", "The two attribute identifiers are used \"depending on the selection method\", but the document never states which identifier names which method.",
            RequirementCoverageStatus.Tested, "ReferenceArtifactEvidenceRecordTests.TheContentGroupOfAppendixAAppearsOnlyUnderTheExternalIdentifier — RULING (owner flag 4), made from structure and then confirmed empirically against 26 third-party CMS objects and 16 detached records: id-aa-er-internal is selection method 1 (the CMS object alone is the archived data object) and id-aa-er-external is selection method 2 (the CMS object and its detached content as a group of data objects). What survives as an assertion is what the group HOLDS, not how many members it has — cardinality does not discriminate, and the first shape of this test was wrong for exactly that reason."),
        ("rfc4998-A-R65", "Selection method 1: a hash value of the CMS object MUST be located in the first list of hash values of Archive Timestamps.",
            RequirementCoverageStatus.Tested, "EvidenceRecordCmsIntegrationTests.ARecordCarriedByASignatureProvesTheViewWithoutIt"),
        ("rfc4998-A-R66", "Selection method 2: the hash value of the CMS object as well as the hash value of the content have to be stored in the first list of hash values as a group of data objects.",
            RequirementCoverageStatus.Tested, "EvidenceRecordCmsIntegrationTests.ARecordUnderTheExternalIdentifierGroupsTheObjectWithItsDetachedContent (the group check holds for the right content, fails closed for another and for an empty stated one, and is skipped when no content is stated)"),
        ("rfc4998-A-R67", "The Evidence Record has to be added to the first signature of the CMS Object of signed data.",
            RequirementCoverageStatus.Tested, "EvidenceRecordCmsIntegrationTests.ARecordCarriedByASignatureProvesTheViewWithoutIt (the attachment surface takes NO signer index, because the appendix admits one place — stage-3 decision 3; verification does take one, because a reader states which signature it is looking at)"),
        ("rfc4998-A-R68", "The attributes SHOULD only occur once.",
            RequirementCoverageStatus.Tested, "EvidenceRecordCmsIntegrationTests.ASecondRecordIsRefusedUnlessTheCallerStatesTheDeparture (the SHOULD is the default and the departure is an explicit caller-stated policy — the same convention every SHOULD of this wave takes)"),
        ("rfc4998-A-R69", "If they appear several times, they have to be stored within the first signature in chronological order.",
            RequirementCoverageStatus.Tested, "EvidenceRecordCmsIntegrationTests.TheChronologyIsDiscoveredEvenWhenTheSetHoldsTheRecordsInReverseOrder — RULING: this order is NOT enforceable by a conformant producer and a verifier must never read chronology off the encoding — the attribute set is a DER SET OF whose canonical sort orders the Attribute structures by their values, and ReferenceArtifactEvidenceRecordTests.TheChronologyOfATwoRecordObjectIsTheReverseOfItsEncodingOrder is a third-party object where the chronological order is exactly the reverse of the encoded one. The shipped verification DISCOVERS the order level by level instead of counting it (stage-3 section 3.2)."),
        ("rfc4998-A-R70", "If the CMS object does not carry the EvidenceRecord attributes, the archive timestamped data object has to be generated over the complete CMS object within the existing coding.",
            RequirementCoverageStatus.Tested, "ReferenceArtifactEvidenceRecordTests.ADetachedRecordCoversTheObjectAsItStandsIncludingItsEmbeddedRecord (a detached record covers the file as it sits on disk and NOT a reconstructed view — the removal is performed for a record found INSIDE the object, never for one supplied beside it) and EvidenceRecordCmsIntegrationTests.AnObjectCarryingNoRecordHasNothingEmbeddedToVerify"),
        ("rfc4998-A-R71", "For verification, the hash value must be generated over the CMS object without the one EvidenceRecord.",
            RequirementCoverageStatus.Tested, "EvidenceRecordCmsIntegrationTests.ARecordCarriedByASignatureProvesTheViewWithoutIt and ReferenceArtifactEvidenceRecordTests.TheReconstructedViewIsThePreAttachmentFileTheCorpusAlsoCarries (the reconstruction is byte-identical to the pre-attachment file three third-party artifact pairs carry, so the reading is a conformance statement rather than a self-consistency one)"),
        ("rfc4998-A-R72", "This means that the attribute has to be removed before verification.",
            RequirementCoverageStatus.Tested, "CmsSignedDataReductionTests.RemovingTheOnlyAttributeRestoresTheStructureExactly (the inverse-splice primitive, judged against an independent rebuild rather than against its own inverse) and ReferenceArtifactEvidenceRecordTests.TheEmbeddedRecordsOfTheCorpusProveTheReconstructedViews"),
        ("rfc4998-A-R73", "The length of fields containing tags has to be adapted.",
            RequirementCoverageStatus.Tested, "CmsSignedDataReductionPropertyTests.RemovingWhatWasAppendedRestoresTheOriginalOctets (a full definite-length re-derivation up every ancestor whose content shrank, across every length-octet boundary) and CmsSignedDataReductionTests.RefusesAContainerWhoseDefiniteLengthIsNotMinimallyEncoded (a coding it cannot re-derive is refused rather than guessed at)"),
        ("rfc4998-A-R74", "Apart from that, the existing coding must not be modified.",
            RequirementCoverageStatus.Tested, "CmsSignedDataReductionPropertyTests.RemovingASubsetLeavesEveryUntouchedRegionIdentical and CmsSignedDataReductionTests.PreservesIndefiniteLengthOuterWrappers"),
        ("rfc4998-A-R75", "If several Archive Timestamps occur, the data object has to be generated as follows.",
            RequirementCoverageStatus.Tested, "EvidenceRecordCmsIntegrationTests.NestedRecordsProveTheViewsTheAppendixDescribes (the framing the R76-R79 steps implement)"),
        ("rfc4998-A-R76", "During verification of the first EvidenceRecord in chronological order, all EvidenceRecord attributes have to be removed in order to generate the data object.",
            RequirementCoverageStatus.Tested, "EvidenceRecordCmsIntegrationTests.ARecordCarriedByASignatureProvesTheViewWithoutIt (the view holding no record, which is also the only view a single-record object has and the first view the discovery reconstructs)"),
        ("rfc4998-A-R77", "During verification of the nth EvidenceRecord, the first n-1 attributes should remain within the CMS object.",
            RequirementCoverageStatus.Tested, "EvidenceRecordCmsIntegrationTests.NestedRecordsProveTheViewsTheAppendixDescribes (the view is named by a SET of retained records rather than by a count — a count in encoding order names the wrong view whenever the chronological and canonical orders differ, and the corpus proves they do; EvidenceRecordCmsIntegrationTests.TwoRecordsProvingTheSameViewAreBothAccepted is the shape a strict chain reading would wrongly reject)"),
        ("rfc4998-A-R78", "The verification of the nth EvidenceRecord must result in a point of time when the document must have existed with the first n attributes.",
            RequirementCoverageStatus.Tested, "EvidenceRecordCmsIntegrationTests.ARecordProvingAWiderViewMayNotAssertAnEarlierInstant"),
        ("rfc4998-A-R79", "The verification of the n+1th attribute must prove that this requirement has been met.",
            RequirementCoverageStatus.Tested, "EvidenceRecordCmsIntegrationTests.ARecordProvingAWiderViewMayNotAssertAnEarlierInstant (the consistency is checked across the DISCOVERED positions, not the encoded ones, and a violation is reported as a broken chronology)"),

        //---- IETF RFC 6283 clause 2.1 — structure ----
        ("rfc6283-2.1-S1", "The renewal process MUST continue during the whole desired archiving period.",
            RequirementCoverageStatus.OutOfScope, "An operational obligation on the archive's own lifecycle, and a creation-side one: XMLERS CREATION does not ship this wave (owner flag 1 of the waveasic contract, R-3 — \"XMLERS creation does NOT ship\"; the producer emits the RFC 4998 form and XMLERS creation waits for a consumer). The equivalent monitoring obligation of the ASN.1 form is the rfc4998-5-R22 row."),
        ("rfc6283-2.1-S2", "The EvidenceRecord Version attribute MUST be included.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordXmlBindingTests.AMissingRequiredParticleIsRefusedRatherThanDefaulted (a document without it is refused rather than defaulted) and XmlEvidenceRecordXmlBindingTests.AWellFormedRecordParsesIntoTheModel (the value clause 8's schema fixes is read)"),
        ("rfc6283-2.1-S3", "The EncryptionInformation element is OPTIONAL.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ARecordStatingEncryptionInformationIsRefused (present: recognised and the record refused, because clause 5's re-encryption is something this library cannot perform) and XmlEvidenceRecordXmlBindingTests.AWellFormedRecordParsesIntoTheModel (absent: read as absent)"),
        ("rfc6283-2.1-S4", "The SupportingInformationList element is OPTIONAL.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel (present) and XmlEvidenceRecordXmlBindingTests.AWellFormedRecordParsesIntoTheModel (absent)"),
        ("rfc6283-2.1-S5", "The Type attribute of a SupportingInformation element is OPTIONAL.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel (the attribute is read when stated and the model carries it as nullable, so an entry without one is read too)"),
        ("rfc6283-2.1-S6", "If cryptographic information is stored in SupportingInformation, the Type defined in clause 3.1.3 MUST be used.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel (the entry states the clause 3.1.3 type and the model reports it) and XmlEvidenceRecordWellKnownTests.TheCryptographicInformationTypesAreTheFourTheRegistryHolds (the closed set those types come from)"),
        ("rfc6283-2.1-S7", "Cryptographic policies conformant to RFC 5698 MAY be stored in SupportingInformation using the type defined there.",
            RequirementCoverageStatus.OutOfScope, "The waveasic contract's Out list: \"DSSC/RFC 5698 policy interpretation (RFC 6283 clause 7: opaque pass-through — the repo's own algorithm-agility registries govern)\". The container for such a policy IS read and surfaced verbatim (the S4 row); nothing interprets it, which is what an opaque pass-through means."),
        ("rfc6283-2.1-S8", "Policy or attribute information available at or before an individual renewal step SHOULD be stored in that Archive Time-Stamp's Attributes element rather than in SupportingInformation.",
            RequirementCoverageStatus.OutOfScope, "A creation-side placement obligation, and XMLERS creation does not ship (owner flag 1, contract R-3). The read side of both placements is covered by the S4 and S20 rows."),
        ("rfc6283-2.1-S9", "The ArchiveTimeStampSequence element is REQUIRED.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordXmlBindingTests.AMissingRequiredParticleIsRefusedRatherThanDefaulted and XmlEvidenceRecordXmlBindingTests.ADocumentTypeDefinitionAndOctetsThatAreNotXmlAreBothRefused (a document whose root is not the record element at all)"),
        ("rfc6283-2.1-S10", "The ArchiveTimeStampChain element is REQUIRED, one or more.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordXmlBindingTests.AMissingRequiredParticleIsRefusedRatherThanDefaulted"),
        ("rfc6283-2.1-S11", "The sequence of ArchiveTimeStampChain elements MUST be ordered, indicated by the Order attribute.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordXmlBindingTests.OrderAttributesThatAreNotTheRunAreRefused (duplicated, gapped and absent) — the parse validates the run 1..n and returns the model sorted by it, because clause 4.1 names \"the chain with the largest Order\" and a duplicate or a gap makes that name something no two verifiers agree on"),
        ("rfc6283-2.1-S12", "The sequence of ArchiveTimeStamp elements within a chain MUST be ordered, indicated by the Order attribute.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordXmlBindingTests.OrderAttributesThatAreNotTheRunAreRefused (the case is built on a two-member chain precisely so an Order run exists to break)"),
        ("rfc6283-2.1-S13", "The DigestMethod element is REQUIRED per ArchiveTimeStampChain.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordXmlBindingTests.AMissingRequiredParticleIsRefusedRatherThanDefaulted and XmlEvidenceRecordXmlBindingTests.AWellFormedRecordParsesIntoTheModel (the identifier is resolved at the seam rather than carried as text)"),
        ("rfc6283-2.1-S14", "The CanonicalizationMethod element is REQUIRED per ArchiveTimeStampChain.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordXmlBindingTests.AMissingRequiredParticleIsRefusedRatherThanDefaulted (a chain without one is refused — the case names it explicitly)"),
        ("rfc6283-2.1-S15", "The HashTree element is OPTIONAL.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ATimeStampRenewalMayOmitItsHashTree and XmlEvidenceRecordsTests.AGroupWithNoHashTreeIsRefusedForTheMissingTree (the omission is admitted only where clause 4.3 step 1 admits it — a single data object — and refused for a group)"),
        ("rfc6283-2.1-S16", "The TimeStamp element is REQUIRED.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordXmlBindingTests.AMissingRequiredParticleIsRefusedRatherThanDefaulted"),
        ("rfc6283-2.1-S17", "The CryptographicInformationList child of a TimeStamp element is OPTIONAL.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel (present) and XmlEvidenceRecordXmlBindingTests.AWellFormedRecordParsesIntoTheModel (absent)"),
        ("rfc6283-2.1-S18", "The CryptographicInformationList element is OPTIONAL wherever it occurs.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel (clause 2.1 restates for the record what clause 3.1.3 states for the element; the S17 row is the same optionality read at the TimeStamp element)"),
        ("rfc6283-2.1-S19", "Each CryptographicInformation child MUST carry an Order attribute.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel (the parse requires both Order and Type on such an element and reports the values it read)"),
        ("rfc6283-2.1-S20", "The Attributes element of an ArchiveTimeStamp is OPTIONAL.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel (present) and XmlEvidenceRecordXmlBindingTests.AWellFormedRecordParsesIntoTheModel (absent)"),
        ("rfc6283-2.1-S21", "Each Attribute child MUST carry an Order attribute; its Type attribute is OPTIONAL.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel (the Order is read and reported; the Type is carried as nullable, which is the optionality)"),
        ("rfc6283-2.1-S22", "The Order attribute is REQUIRED wherever sibling elements of the same name occur at the same level of the ArchiveTimeStampSequence structure.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordXmlBindingTests.OrderAttributesThatAreNotTheRunAreRefused (the general rule S11, S12, S19 and S21 each instantiate, checked as the run 1..n at the seam)"),

        //---- IETF RFC 6283 clause 2.2 — generation ----
        ("rfc6283-2.2-S23", "Generation of an EvidenceRecord MUST follow the three-step procedure: select the archive object, create the initial Archive Time-Stamp, refresh it by renewal when necessary.",
            RequirementCoverageStatus.OutOfScope, "XMLERS creation does not ship this wave (owner flag 1, contract R-3: the producer emits IETF RFC 4998 only and XMLERS creation waits for a consumer). Every structure the three steps produce IS verified — the initial Archive Time-Stamp, both renewals and their relations — against documents an independent factory minted."),
        ("rfc6283-2.2-lc-cryptographic-information-scope", "The CryptographicInformationList element is not to be used to store cryptographic material related to signed archive data; its use is limited to material related to the Time-Stamps. (lowercase, functions as a prohibition)",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel (the element is read only as a child of a TimeStamp element and its entries are surfaced there and nowhere else, so nothing this library reads out of it is ever offered as material for the archived data's own signature; a container-borne signature's validation material comes from the signature file itself, which the ASiC validation surface supplies)"),

        //---- IETF RFC 6283 clause 2.3 — verification (top level) ----
        ("rfc6283-2.3-S24", "Verification MUST follow the three-step procedure: select the archive object, re-encrypt if EncryptionInformation is used, verify the Archive Time-Stamp Sequence.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ARecordOverOneDataObjectProvesIt (steps 1 and 3) and XmlEvidenceRecordsTests.ARecordStatingEncryptionInformationIsRefused (step 2, which this library refuses rather than performs, because clause 5 registers no mechanism it could re-encrypt with)"),

        //---- IETF RFC 6283 clause 3 (intro) — Archive Time-Stamp ----
        ("rfc6283-3-S25", "An Archive Time-Stamp MUST be renewed before it becomes invalid through a weakening algorithm, certificate invalidation or the Time-Stamping Authority ceasing operation.",
            RequirementCoverageStatus.OutOfScope, "Creation-side and operationally triggered: XMLERS creation does not ship (owner flag 1, contract R-3), and the renewal TIMING is the monitoring guidance the contract's Out list excludes. Both renewal procedures' resulting structures are verified (the S68-S75 rows' verification halves)."),

        //---- IETF RFC 6283 clause 3.1.1 — hash tree ----
        ("rfc6283-3.1.1-S26", "The root hash value generated from the HashTree MUST equal the Time-Stamped value.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.AChangedHashValueInsideTheTreeBreaksTheRoot and XmlEvidenceRecordHashTreeTests.AFourLevelTreeReachesTheRootTheOracleReaches (the recomputation cross-checked against an independent from-clause-text implementation)"),
        ("rfc6283-3.1.1-S27", "When a single Time-Stamp is obtained for a group of archive objects, a hash tree MUST be constructed to bind them.",
            RequirementCoverageStatus.OutOfScope, "Creation-side; XMLERS creation does not ship (owner flag 1, contract R-3). The verification consequence IS driven: XmlEvidenceRecordsTests.AGroupWithNoHashTreeIsRefusedForTheMissingTree refuses a group whose record carries no tree, which is this obligation seen from the other side."),
        ("rfc6283-3.1.1-S28", "A reduced hash tree MUST then be calculated per archive object.",
            RequirementCoverageStatus.OutOfScope, "Creation-side; XMLERS creation does not ship (owner flag 1, contract R-3). What the reduction produces is what the verification walk consumes, and that walk is driven by XmlEvidenceRecordHashTreeTests.AFourLevelTreeReachesTheRootTheOracleReaches."),
        ("rfc6283-3.1.1-S29", "When an archive object is a group of more than one data object, the first hash list MUST contain the hash values of all its data objects.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ARecordOverADataObjectGroupProvesTheWholeGroup and XmlEvidenceRecordsTests.ADataObjectMissingFromTheFirstSequenceIsNotProved"),
        ("rfc6283-3.1.1-lc-singleton-first-sequence", "When the first Sequence element has only one DigestValue element, its binary value is added to the next list rather than hashed. (stated in clause 3.1.1's prose without a keyword)",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordHashTreeTests.AFirstSequenceOfOneValueIsCarriedForwardUnhashed (with the hashed reading asserted NOT to reach the same root) and XmlEvidenceRecordHashTreeTests.ASingleValueDeeperInTheTreeIsCombinedRatherThanCarriedForward (the exception is first-Sequence-only, exactly as the clause words it). The census ReferenceArtifactXmlEvidenceRecordTests.TheRootRuleOfClause311HoldsAcrossTheCorpus found 33 third-party records taking this reading and zero taking the other, which is also what confirmed the same ruling for the ASN.1 form, where RFC 4998 leaves the rule implicit."),

        //---- IETF RFC 6283 clause 3.1.2 — time-stamp ----
        ("rfc6283-3.1.2-S30", "The TimeStamp Type attribute MUST be used to indicate the format, with the values \"XMLENTRUST\" or \"RFC3161\".",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordXmlBindingTests.ATimeStampTokenTypeOutsideTheRegistryIsRefused and XmlEvidenceRecordWellKnownTests.TheTimeStampTokenTypesAreTheTwoTheRegistryHolds (both registered values, letter for letter, compared as the NMTOKEN values they are)"),
        ("rfc6283-3.1.2-S31", "For an \"RFC3161\"-typed TimeStamp, the element MUST contain the base64 of the DER-encoded ASN.1 TimeStampToken.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordXmlBindingTests.AWellFormedRecordParsesIntoTheModel (the base64 is decoded into a carrier and the token read through the shipped RFC 3161 surface) and XmlEvidenceRecordsTests.ATimeStampFormatThisLibraryDoesNotReadIsNamedAsSuch (the other registered value, named rather than assumed)"),

        //---- IETF RFC 6283 clause 3.1.3 — cryptographic information list ----
        ("rfc6283-3.1.3-S32", "Data needed to verify the Time-Stamp Token SHOULD be stored in the token itself.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordXmlBindingTests.AWellFormedRecordParsesIntoTheModel (the minted documents carry their certificate material inside the token, which is the placement the SHOULD names, and the token is read from there)"),
        ("rfc6283-3.1.3-S33", "When that is not possible, such data MAY be stored in the CryptographicInformationList.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel (the alternative placement is read and its entries surfaced with their type)"),
        ("rfc6283-3.1.3-S34", "Each CryptographicInformation child MUST carry an Order attribute (restated in this clause).",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel (the same obligation as S19, restated by the specification in this clause and cited twice for that reason)"),
        ("rfc6283-3.1.3-S35", "The Type attribute of a CryptographicInformation element is REQUIRED.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel (the parse requires it and refuses an element without it, rather than defaulting a type)"),
        ("rfc6283-3.1.3-S36", "The Type MUST use one of the registered values CRL, OCSP, SCVP or CERT.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordWellKnownTests.TheCryptographicInformationTypesAreTheFourTheRegistryHolds (all four, letter for letter, with a lowercase spelling and an unregistered name both refused — the enumeration is closed and clause 10 makes registering another one a specification-required act)"),
        ("rfc6283-3.1.3-S37", "Type CRL content MUST be the base64 of a DER-encoded X.509 CertificateList.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordWellKnownTests.TheCryptographicInformationTypesAreTheFourTheRegistryHolds (the type is recognised) and EvidenceRecordRequirementsMatrixTests.TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel (an entry's base64 content is decoded to the octets it carries and surfaced verbatim; this library reports the material rather than interpreting a revocation list out of the Evidence Record, because the container's own validation material is what a validator acts on)"),
        ("rfc6283-3.1.3-S38", "Type OCSP content MUST be the base64 of a DER-encoded OCSPResponse.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordWellKnownTests.TheCryptographicInformationTypesAreTheFourTheRegistryHolds and EvidenceRecordRequirementsMatrixTests.TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel (same reading as S37: recognised type, content decoded and surfaced)"),
        ("rfc6283-3.1.3-S39", "Type SCVP content MUST be the base64 of a DER-encoded CVResponse.",
            RequirementCoverageStatus.OutOfScope, "The waveasic contract's Out list: \"SCVP inside CryptographicInformation (recognized structurally, documented gap)\". The type name is in the closed enumeration and is recognised (XmlEvidenceRecordWellKnownTests.TheCryptographicInformationTypesAreTheFourTheRegistryHolds); no Server-Based Certificate Validation Protocol response parser exists anywhere in this repository and none is built for a payload no caller has asked for."),
        ("rfc6283-3.1.3-S40", "Type CERT content MUST be the base64 of a DER-encoded X.509 certificate.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel (a CERT entry carrying a minted certificate is decoded to exactly that certificate's octets and no others)"),

        //---- IETF RFC 6283 clause 3.2 — generation at the Archive Time-Stamp level ----
        ("rfc6283-3.2-S41", "Initial Archive Time-Stamp generation MUST follow the five-step procedure: collect objects, select the canonicalization method, select the hash algorithm, generate the hash tree, acquire the Time-Stamp Token.",
            RequirementCoverageStatus.OutOfScope, "Creation-side; XMLERS creation does not ship (owner flag 1, contract R-3). Every structure the five steps produce is verified against documents an independent factory minted, and the reference leg proves the verification against documents this project did not produce at all (ReferenceArtifactXmlEvidenceRecordTests.ARecordOfTheCorpusProvesADataObjectOfTheCorpus)."),
        ("rfc6283-3.2-S42", "The selected canonicalization method MUST also be used for the archive data itself when that data is XML.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.XmlArchiveDataIsProvedThroughItsCanonicalForm (hashing the archived document as it sits reaches a value the record does not carry; canonicalized under the chain's own method it reaches the one it does, and a second serialisation of the same information set is proved by the same record). The flag travels with the DATA OBJECT and not with the caller's preparation, because the method in force changes as the walk crosses a Hash-Tree Renewal — stage-9 decision 9."),
        ("rfc6283-3.2-S43", "The selected hash algorithm MUST be the same one used in the Time-Stamp Token and in the hash-tree computations.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ATokenStatingAnotherAlgorithmThanItsChainIsRefused (a root under one algorithm and an imprint under another are not comparable at all, which is the negative result of Appendix A step 5.b reached one step earlier — stage-9 decision 8)"),
        ("rfc6283-3.2-S44", "If the hash tree is omitted for a single-object archive object, the Time-Stamped value MUST equal that object's digest value.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ATimeStampRenewalMayOmitItsHashTree and the third-party witness ReferenceArtifactXmlEvidenceRecordTests.ARecordOfTheCorpusProvesADataObjectOfTheCorpus (one of its five pairs is a record with no hash tree at all)"),

        //---- IETF RFC 6283 clause 3.2.1 — generation of the hash tree ----
        ("rfc6283-3.2.1-S45", "DigestValue elements within a Sequence MUST be ordered in binary ascending order.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordHashTreeTests.TheLevelRuleOrdersValuesBinaryAscendingWhateverOrderTheyArriveIn (the verifier's own recomputation replicates the sort, which is the half that ships; the comparator itself is the one primitive shared with the ASN.1 form, because \"binary ascending order\" is the single rule both documents state identically and two copies of an ordering rule are two rules that can disagree — stage-9 decision 1)"),
        ("rfc6283-3.2.1-S46", "The base64 text of a DigestValue MUST be base64-decoded before use as a binary hash value.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordXmlBindingTests.ADigestValueTheChainsAlgorithmCouldNotHaveProducedIsRefused (a value that is not base64 and one of the wrong length for the chain's algorithm) and XmlEvidenceRecordXmlBindingTests.AWellFormedRecordParsesIntoTheModel (the decoded length is the algorithm's)"),
        ("rfc6283-3.2.1-S47", "A hash tree MUST be generated whenever the Time-Stamped value is not the hash of a single input data object.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.AGroupWithNoHashTreeIsRefusedForTheMissingTree (the verifier refuses exactly the shape this obligation forbids a producer to write, while a single object with no tree verifies)"),
        ("rfc6283-3.2.1-S48", "For a multi-object archive-object group, the first hash list MUST contain the hash values of all — and only — its own data objects.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.AFirstSequenceHoldingAValueTheVerifierWasNeverShownIsRefusedByDefault (the \"and only\" half, refused by default and accepted under the stated departure) and XmlEvidenceRecordsTests.ARecordOverADataObjectGroupProvesTheWholeGroup (the \"all\" half)"),
        ("rfc6283-3.2.1-S49", "The hash-tree calculation MUST follow the stated four-step procedure: collect, digest per group, group by N with sort and concatenate and hash, repeat to the root.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordHashTreeTests.AFirstSequenceOfSeveralValuesIsSortedConcatenatedAndHashed and XmlEvidenceRecordHashTreeTests.AFourLevelTreeReachesTheRootTheOracleReaches (the verifier reproduces the same level rule the generation procedure states, checked against an independent from-clause-text implementation)"),
        ("rfc6283-3.2.1-S50", "An equal children count per node is RECOMMENDED for processing efficiency.",
            RequirementCoverageStatus.OutOfScope, "A creation-side efficiency recommendation about the tree's shape; XMLERS creation does not ship (owner flag 1, contract R-3). The verifier is shape-agnostic by construction — it walks whatever Sequence elements a document carries, which XmlEvidenceRecordHashTreeTests.AFourLevelTreeReachesTheRootTheOracleReaches exercises over an uneven tree."),
        ("rfc6283-3.2.1-S51", "Padding a node with arbitrary extra values to equalize children counts MAY be done.",
            RequirementCoverageStatus.OutOfScope, "A creation-side permission; XMLERS creation does not ship (owner flag 1, contract R-3). A padded level is indistinguishable from any other level on the read side, so the verifier needs nothing for it."),
        ("rfc6283-3.2.1-S52", "The selected hash algorithm MUST be the same one declared in the chain's DigestMethod.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordXmlBindingTests.ADigestValueTheChainsAlgorithmCouldNotHaveProducedIsRefused (a hash value whose length the chain's declared algorithm could not have produced is refused at the seam) and XmlEvidenceRecordsTests.ATokenStatingAnotherAlgorithmThanItsChainIsRefused"),
        ("rfc6283-3.2.1-S53", "The arbitrary padding values of the worked example are OPTIONAL.",
            RequirementCoverageStatus.OutOfScope, "The same creation-side permission as S51, restated by the specification inside its worked example; XMLERS creation does not ship (owner flag 1, contract R-3)."),

        //---- IETF RFC 6283 clause 3.2.2 — reduction of the hash tree ----
        ("rfc6283-3.2.2-S54", "For a data-object-group archive object, the first Sequence MUST be formed from the hash values of all of its own data objects.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ARecordOverADataObjectGroupProvesTheWholeGroup (the verifier requires exactly that membership, in both directions by default)"),
        ("rfc6283-3.2.2-S55", "DigestValue order within each Sequence MUST be binary ascending, restated for the reduced-tree output.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordHashTreeTests.TheLevelRuleOrdersValuesBinaryAscendingWhateverOrderTheyArriveIn (the same obligation as S45, restated by the specification for this clause's output)"),
        ("rfc6283-3.2.2-lc-procedure", "The four-step reduction procedure itself is introduced by \"can be reduced ... as follows\", with no governing capitalized keyword — treated as binding regardless.",
            RequirementCoverageStatus.OutOfScope, "The procedure is creation-side and XMLERS creation does not ship (owner flag 1, contract R-3). It is recorded as its own row because a hyper-literal RFC 2119 reading would treat the whole reduction as non-mandatory, which is the editorial defect the RFC 6283 spec leg flagged (its section 4 sharp edge 4) and which this matrix answers by carrying the row rather than by omitting it."),

        //---- IETF RFC 6283 clause 3.3 — verification at the Archive Time-Stamp level ----
        ("rfc6283-3.3-S56", "Archive Time-Stamp verification MUST follow the stated five-step procedure: identify the algorithm and hash the data objects, locate the first-Sequence hashes, recompute the root and compare it to the Time-Stamped value, the single-object fallback comparison, and the Time-Stamp Token's formal validity.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ARecordOverOneDataObjectProvesIt (steps 1-3), XmlEvidenceRecordsTests.ATimeStampRenewalMayOmitItsHashTree (step 4's fallback) and XmlEvidenceRecordsTests.ATimeStampFormatThisLibraryDoesNotReadIsNamedAsSuch (step 5's read, beyond which the formal validity of a token is the EN 319 102-1 clause 5.4 building block the engine composes)"),
        ("rfc6283-3.3-S57", "If a group-exclusivity proof is also sought, it SHOULD additionally be verified that the first hash list contains only the group's own data-object hashes.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.AFirstSequenceHoldingAValueTheVerifierWasNeverShownIsRefusedByDefault — RULING (contract R-3): Appendix A step 5.b states BOTH directions in one unconditional sentence while this clause conditions the second on the verifier \"also seeking\" group proof, so the strict reading ships as the default and the loose reading is a stated caller departure — both are tested, and XmlEvidenceRecordHashTreeTests.TheMembershipComparisonRunsInBothDirections asserts the comparison itself."),

        //---- IETF RFC 6283 clause 4.1 — chain and sequence structure ----
        ("rfc6283-4.1-S58", "The ArchiveTimeStampChain and ArchiveTimeStamp sequences MUST both be sorted by Time-Stamp time, ascending.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.BothRenewalsInSuccessionStillProveTheDataObject (the ascending order across a Time-Stamp Renewal and a Hash-Tree Renewal, read off the Order attributes the parse validates as the run 1..n) and XmlEvidenceRecordXmlBindingTests.OrderAttributesThatAreNotTheRunAreRefused"),
        ("rfc6283-4.1-S59", "The Archive Time-Stamp with the largest Order within the chain with the largest Order is the latest one and MUST be valid at the present time.",
            RequirementCoverageStatus.OutOfScope, "The same temporal half as the ASN.1 form's R46: the formal validity of a token at an instant is the EN 319 102-1 clause 5.4 time-stamp validation building block, which the engine composes for a record's most recent Archive Time-Stamp (EvidenceRecordSignatureValidationTests.StepOneReportsWhatTheRecordAndItsTimestampConcluded is that composition for the ASN.1 form). The XML surface identifies the latest member structurally — the model is returned sorted by Order and the conclusion carries that member's generation time — and does not evaluate trust itself."),

        //---- IETF RFC 6283 clause 4.1.1 — digest method ----
        ("rfc6283-4.1.1-S60", "The DigestMethod MUST be used for all hash calculations related to Archive Time-Stamps within its chain.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ATokenStatingAnotherAlgorithmThanItsChainIsRefused and XmlEvidenceRecordsTests.AHashTreeRenewalStartsANewChainBoundToTheSequenceBeforeIt (the chain in force supplies the algorithm for every value the walk computes, including the digest of the preceding sequence)"),
        ("rfc6283-4.1.1-S61", "The Algorithm URI MUST be as defined in IETF RFC 3275 and IETF RFC 4051.",
            RequirementCoverageStatus.Tested, "XmlSignatureWellKnownTests.TheIdentifiersAreTheOnesTheRegistriesState and XmlEvidenceRecordXmlBindingTests.ADigestIdentifierThisLibraryWillNotComputeIsRefusedForTheAlgorithm (three identifiers refused: two registered but weak, one of no registry at all). The identifier space is bound at the seam rather than passed through, because a chain naming an algorithm nothing can compute proves nothing a verifier could report — stage-9 decision 10."),
        ("rfc6283-4.1.1-S62", "Within a single chain, the hash algorithm used by the hash trees and by the embedded Time-Stamp Tokens MUST be identical.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ATokenStatingAnotherAlgorithmThanItsChainIsRefused"),
        ("rfc6283-4.1.1-S63", "When the Time-Stamping Authority's algorithm changes, a new chain MUST be started using an equal-or-stronger digest algorithm.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.AHashTreeRenewalIntoAWeakerAlgorithmIsRefused — a ruling the contract did not anticipate (stage-9 decision 7): \"equal or stronger\" is enforced as a digest-length comparison, which is the one obligation of this clause a verifier can settle without a dated reliability table — a succeeding chain naming a shorter digest has defeated the only purpose the renewal had. The new-chain half is XmlEvidenceRecordsTests.AHashTreeRenewalStartsANewChainBoundToTheSequenceBeforeIt."),

        //---- IETF RFC 6283 clause 4.1.2 — canonicalization method ----
        ("rfc6283-4.1.2-S64", "Canonicalization algorithm URIs MUST be as defined in IETF RFC 3275 and IETF RFC 4051.",
            RequirementCoverageStatus.Tested, "XmlSignatureWellKnownTests.TheCanonicalizationIdentifiersAreTheOnesTheRegistriesState (the six identifiers, letter for letter) and XmlEvidenceRecordXmlBindingTests.ACanonicalizationIdentifierOutsideTheBoundSpaceIsRefused"),
        ("rfc6283-4.1.2-S65", "Canonicalization MUST be applied to XML-structured archive data before hashing.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.XmlArchiveDataIsProvedThroughItsCanonicalForm (the same obligation the S42 row states from the generation clause, driven here on the verification side)"),
        ("rfc6283-4.1.2-S66", "Canonicalization MUST also be applied to the Evidence Record's own elements during the renewal process, since renewal hashes their XML serialization.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ATimeStampRenewalLinksToThePreviousTimeStampElement (the TimeStamp element's binary representation) and XmlEvidenceRecordsTests.AHashTreeRenewalStartsANewChainBoundToTheSequenceBeforeIt (the ArchiveTimeStampSequence prefix). The canonicalization seam NAMES a sub-tree rather than being handed octets, because the octets hashed are those of a sub-tree as it stands — prefixes, namespace declarations and comments included — which no model reproduces; stage-9 decision 3, and the two-chain third-party artifact of ReferenceArtifactXmlEvidenceRecordTests.ARecordOfTheCorpusProvesADataObjectOfTheCorpus verifying is the evidence the shape is right."),
        ("rfc6283-4.1.2-S67", "The CanonicalizationMethod MUST be used for all binary representations of Archive Time-Stamps within its chain.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordXmlBindingTests.TheCommentPreservingFormOfAnAlgorithmIsNotTheOtherOne (the identifier decides the octets, so \"the method of its chain\" is a load-bearing statement rather than a formality) and XmlEvidenceRecordsTests.TheSameInformationSetSerialisedDifferentlyReachesTheSameConclusion"),
        ("rfc6283-4.1.2-lc-preceding-chain-method", "In the case of a succeeding chain, the canonicalization method indicated within that chain must also be used for the digest value of the PRECEDING chain. (lowercase, load-bearing)",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.AHashTreeRenewalStartsANewChainBoundToTheSequenceBeforeIt — the SUCCEEDING chain's method is applied to the preceding sequence (stage-9 decision 4), and a reading that used the prefix's own method fails the two-chain third-party artifact of ReferenceArtifactXmlEvidenceRecordTests.ARecordOfTheCorpusProvesADataObjectOfTheCorpus, which is written under Canonical XML 1.0 WITH COMMENTS and carries comments inside the sequence"),

        //---- IETF RFC 6283 clause 4.2.1 — Time-Stamp renewal ----
        ("rfc6283-4.2.1-S68", "Time-Stamp renewal MUST follow the stated three-step procedure: add missing cryptographic information, hash the last TimeStamp element under the chain's methods and acquire a new token, append the new Archive Time-Stamp at the end of the current chain.",
            RequirementCoverageStatus.OutOfScope, "Creation-side; XMLERS creation does not ship (owner flag 1, contract R-3). The structure the procedure produces is verified end to end by XmlEvidenceRecordsTests.ATimeStampRenewalLinksToThePreviousTimeStampElement, including that the link is to the previous TimeStamp ELEMENT's canonical binary representation."),
        ("rfc6283-4.2.1-S69", "The new Archive Time-Stamp's hash tree MUST use the same digest algorithm as the chain's DigestMethod.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ATokenStatingAnotherAlgorithmThanItsChainIsRefused (the verifier refuses a member whose algorithm is not the chain's, whichever renewal produced it)"),
        ("rfc6283-4.2.1-S70", "The new Archive Time-Stamp MAY omit a hash tree entirely.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ATimeStampRenewalMayOmitItsHashTree (verification accepts both forms; the corpus carries renewals written each way, which ReferenceArtifactXmlEvidenceRecordTests.EveryRecordOfTheCorpusIsReadToADecision reads)"),

        //---- IETF RFC 6283 clause 4.2.2 — hash-tree renewal ----
        ("rfc6283-4.2.2-S71", "The chain and Archive Time-Stamp elements MUST be processed in chronological Order when computing the digest of the sequence.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.AHashTreeRenewalStartsANewChainBoundToTheSequenceBeforeIt (the prefix handed to the canonicalization seam is named by the chain COUNT, so the octets are the sequence's chains in Order and nothing else) and XmlEvidenceRecordXmlBindingTests.OrderAttributesThatAreNotTheRunAreRefused"),
        ("rfc6283-4.2.2-S72", "The canonicalization method MUST be applied before hashing the ArchiveTimeStampSequence.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.AHashTreeRenewalStartsANewChainBoundToTheSequenceBeforeIt and the third-party witness ReferenceArtifactXmlEvidenceRecordTests.ARecordOfTheCorpusProvesADataObjectOfTheCorpus"),
        ("rfc6283-4.2.2-S73", "Hash values MUST be calculated with the new algorithm for all data objects and for the whole sequence.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.AHashTreeRenewalStartsANewChainBoundToTheSequenceBeforeIt (the new chain's own algorithm computes both the data-object values and the sequence value, which is why a renewal into a weaker algorithm is a question at all — the S63 row)"),
        ("rfc6283-4.2.2-S74", "The sequence MUST be chronologically ordered and canonicalized before its binary representation is taken.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.AHashTreeRenewalStartsANewChainBoundToTheSequenceBeforeIt (the specification restates S71 and S72 inside its worked example; the row is carried separately because the leg enumerated it separately)"),
        ("rfc6283-4.2.2-S75", "Hash values in the first Sequence MUST be sorted in binary ascending order, restated for the renewal case.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordHashTreeTests.TheLevelRuleOrdersValuesBinaryAscendingWhateverOrderTheyArriveIn and XmlEvidenceRecordsTests.AHashTreeRenewalStartsANewChainBoundToTheSequenceBeforeIt (the renewal's own first Sequence walked back to the root)"),
        ("rfc6283-4.2.2-lc-procedure", "The whole eight-step hash-tree-renewal procedure is governed by a lowercase \"must be Time-Stamped as follows\".",
            RequirementCoverageStatus.OutOfScope, "The procedure is creation-side and XMLERS creation does not ship (owner flag 1, contract R-3). Carried as its own row because a hyper-literal RFC 2119 reading would treat the entire renewal as non-mandatory; every structure it produces is verified by the S71-S75 rows' evidence."),
        ("rfc6283-4.2.2-lc-first-list", "Step 7: the first hash value list in the reduced hash tree should only contain the data object's value and the sequence value. (lowercase)",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.AHashTreeRenewalStartsANewChainBoundToTheSequenceBeforeIt (the renewing chain's first Sequence holds exactly those two values, which is also what the default bidirectional membership check of the S57 row requires of it)"),

        //---- IETF RFC 6283 clause 4.3 — chain and sequence verification ----
        ("rfc6283-4.3-S76", "Step 1: when the hash tree is omitted, the calculated archive-object value MUST match the Time-Stamped value.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ATimeStampRenewalMayOmitItsHashTree and XmlEvidenceRecordsTests.AGroupWithNoHashTreeIsRefusedForTheMissingTree (the fallback holds for one value and is refused for a group, which is exactly the condition the clause attaches to it)"),
        ("rfc6283-4.3-S77", "Step 2: if a hash tree is present in the second or later Archive Time-Stamp of a chain, its first Sequence MUST contain the hash value of the previous TimeStamp element.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ATimeStampRenewalLinksToThePreviousTimeStampElement (and the linkage values are compared SEPARATELY from the data-object values so that a missing one names which obligation failed — stage-9 decision 6)"),
        ("rfc6283-4.3-S78", "Step 2: each Archive Time-Stamp MUST be valid relative to the time of its succeeding one.",
            RequirementCoverageStatus.OutOfScope, "The temporal half, identical in shape to the ASN.1 form's R41: the formal validity of a token at a historical instant is the EN 319 102-1 clause 5.4 building block a caller composes (stage-1 decision 14, carried into the XML form by stage 9). The conclusion carries every member's generation time for exactly that composition, and the structural half of step 2 — the Order run and the algorithm continuity — is covered by the S58 and S79 rows."),
        ("rfc6283-4.3-S79", "Step 2: all Archive Time-Stamps within a chain MUST use the same hash algorithm, and it MUST have been secure at the time of the first Archive Time-Stamp of the succeeding chain.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ATokenStatingAnotherAlgorithmThanItsChainIsRefused (the same-algorithm half) and XmlEvidenceRecordsTests.AHashTreeRenewalIntoAWeakerAlgorithmIsRefused (the strength half, as far as a verifier can settle it without a dated reliability table — the S63 ruling)"),
        ("rfc6283-4.3-S80", "For overall non-repudiation, the last Archive Time-Stamp MUST be valid at verification time.",
            RequirementCoverageStatus.OutOfScope, "The same temporal half as S59 and as the ASN.1 form's R46: token trust at the verification instant is the EN 319 102-1 clause 5.4 building block the engine composes, not a structural property of the record. The structural identification of \"the last\" member is covered by the S58 row."),
        ("rfc6283-4.3-lc-procedure", "The whole four-step chain-verification procedure is governed by \"the last ATS has to be valid and ATSCs and their relations to each other have to be proved\", with no capitalized header.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.BothRenewalsInSuccessionStillProveTheDataObject (the relations across a Time-Stamp Renewal and a Hash-Tree Renewal, proved together) — carried as its own row because a hyper-literal RFC 2119 reading would treat the entire chain verification as non-mandatory, which is the editorial defect this matrix answers by carrying the row"),

        //---- IETF RFC 6283 clause 5 — encryption ----
        ("rfc6283-5-S81", "EncryptionInformation is an OPTIONAL extensible structure.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ARecordStatingEncryptionInformationIsRefused (recognised and the record refused, the same stance the ASN.1 form's rfc4998-6-R49 row records; the waveasic contract's Out list excludes the feature itself, and refusing is what \"recognition-only\" means for a verifier that cannot re-encrypt)"),

        //---- IETF RFC 6283 clause 6 — version numbering ----
        ("rfc6283-6-S82", "Major and minor version numbers MUST be treated as separate integers.",
            RequirementCoverageStatus.OutOfScope, "Clause 8's schema fixes the Version attribute at \"1.0\", so no other value is schema-valid and the comparison machinery this clause describes is unreachable for conformant input. What ships is the attribute's presence and value, which the S2 row covers; a version comparator for values that cannot legally arrive would be code no test could reach honestly."),
        ("rfc6283-6-S83", "Each number MAY be incremented past a single digit.",
            RequirementCoverageStatus.OutOfScope, "Same reason as S82: the schema's fixed \"1.0\" makes multi-digit version components unreachable for conformant input."),
        ("rfc6283-6-S84", "Leading zeros MUST be ignored by recipients.",
            RequirementCoverageStatus.OutOfScope, "Same reason as S82."),
        ("rfc6283-6-S85", "Leading zeros MUST NOT be sent.",
            RequirementCoverageStatus.OutOfScope, "Same reason as S82, and creation-side besides: XMLERS creation does not ship (owner flag 1, contract R-3)."),

        //---- IETF RFC 6283 clause 9 — security considerations ----
        ("rfc6283-9.2-S86", "Generating and managing at least two redundant Evidence Records per data object is RECOMMENDED.",
            RequirementCoverageStatus.OutOfScope, "A deployment recommendation about how many records an archive keeps, identical in kind to the ASN.1 form's rfc4998-7-R58 row. The surface verifies one record at a time and a caller is free to keep two."),
        ("rfc6283-9.2-S87", "Redundant Evidence Records SHOULD use different hash algorithms and different Time-Stamping Authorities.",
            RequirementCoverageStatus.OutOfScope, "Same deployment-policy reason as S86, and creation-side besides (owner flag 1, contract R-3)."),
        ("rfc6283-9.3-S88", "Renewed Archive Time-Stamps MUST have the same or higher quality than the initial one.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.AHashTreeRenewalIntoAWeakerAlgorithmIsRefused (the one component of \"quality\" this document makes concrete — clause 4.1.1's equal-or-stronger digest — is enforced; the rest of the notion is as undefined here as it is in the ASN.1 form's rfc4998-7-R61 row)"),
        ("rfc6283-9.3-S89", "Archive Time-Stamps protecting signed archive data SHOULD have the same or higher quality than the maximum quality of the signatures they protect.",
            RequirementCoverageStatus.OutOfScope, "Compares an Evidence Record's \"quality\" against a signature's, and neither document defines the metric; it is a validation-policy concern of EN 319 102-1 rather than a structural rule of this syntax. The same reading as the ASN.1 form's rfc4998-7-R62 row."),
        ("rfc6283-9.4-S90", "Before applying a new Time-Stamp Token, it MUST be ascertained that the certificate of the prior token was not revoked for key compromise before the renewal time.",
            RequirementCoverageStatus.OutOfScope, "A revocation question at a historical instant — the EN 319 102-1 clause 5.4 building block and the proof-of-existence model the engine already implements, which the XML surface reports generation times into rather than evaluating itself (the same scope line as S78 and the ASN.1 form's R41). It is also creation-side: XMLERS creation does not ship (owner flag 1, contract R-3)."),
        ("rfc6283-9.4-S91", "Once a new Archive Time-Stamp protects prior structures, no data may be added to or modified in those prior elements afterwards.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.AChangedHashValueInsideTheTreeBreaksTheRoot and XmlEvidenceRecordsTests.ATimeStampRenewalLinksToThePreviousTimeStampElement (a renewal binds the canonical octets of what it protects, so a later change to a protected element is exactly what stops verifying). The XML form's preservation model differs from the ASN.1 form's: re-serialization of already-covered XML is tolerated as long as the same canonicalization is reapplied, which XmlEvidenceRecordsTests.TheSameInformationSetSerialisedDifferentlyReachesTheSameConclusion asserts."),
        ("rfc6283-9.1-lc-secure-algorithms", "Cryptographic algorithms and parameters must always be secure at the time of generation. (lowercase)",
            RequirementCoverageStatus.Tested, "XmlSignatureWellKnownTests.TheRefusedIdentifiersAreRecognisedByNameAndResolveToNothing (the identifier space is closed at the algorithms this library computes, and the two weak ones a producer might name are recognised by name and resolve to nothing — the same construction-level answer the ASN.1 form's rfc4998-7-R56 row records)"),
        ("rfc6283-9.4-lc-supporting-information", "Data added to SupportingInformationList after the fact must rely on its own authenticity and integrity protection mechanism. (lowercase)",
            RequirementCoverageStatus.Tested, "EvidenceRecordRequirementsMatrixTests.TheOptionalInformationElementsOfTheXmlFormAreAllReadIntoTheModel (the list sits outside everything the Archive Time-Stamp's hash tree covers — the record verifies identically with and without it — so nothing this library concludes rests on its content, which is what the clause warns a reader about)"),

        //---- IETF RFC 6283 clause 10 — IANA considerations ----
        ("rfc6283-10-S92", "IANA registrations under this document MUST use the Specification Required policy.",
            RequirementCoverageStatus.OutOfScope, "Registry governance addressed to IANA, not implementer-facing. Its consequence for an implementation is that both enumerations are closed, which the S30 and S36 rows cover."),
        ("rfc6283-10-S93", "Registering a new Time-Stamp Token Type MUST provide a textual name conforming to xs:NMTOKEN and a reference to its defining specification.",
            RequirementCoverageStatus.OutOfScope, "Registry governance. The implementer-facing consequence — that the two registered values are the whole set and are compared as NMTOKEN values — is the S30 row, whose evidence asserts the comparison is ordinal."),
        ("rfc6283-10-S94", "Registering a new Cryptographic Information Type MUST provide a textual name conforming to xs:NMTOKEN and a reference to its defining specification.",
            RequirementCoverageStatus.OutOfScope, "Registry governance; the implementer-facing consequence is the closed four-value enumeration of the S36 row."),

        //---- IETF RFC 6283 Appendix A — detailed verification process ----
        ("rfc6283-A-S95", "Step 4: the built list of digest values MUST contain exactly the objects protected by the current Archive Time-Stamp, per the sub-rules for a first-versus-later Archive Time-Stamp and chain.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.ARecordOverOneDataObjectProvesIt (step 4.a.i), XmlEvidenceRecordsTests.AHashTreeRenewalStartsANewChainBoundToTheSequenceBeforeIt (step 4.a.ii, the sequence value joined with the data-object values) and XmlEvidenceRecordsTests.ATimeStampRenewalLinksToThePreviousTimeStampElement (step 4.b.i, the previous TimeStamp element alone) — the authoritative expansion of clause 3.3 step 1/2 and clause 4.3 steps 2-3, which is the walk the shipped verification is written against"),
        ("rfc6283-A-lc-procedure", "The whole detailed verification process is introduced by \"start with the first ATS till the last ATS ... and perform verification for each ATS, as follows\", with no capitalized header, despite being the most operationally load-bearing section of the document.",
            RequirementCoverageStatus.Tested, "XmlEvidenceRecordsTests.BothRenewalsInSuccessionStillProveTheDataObject (the walk from the first member of the first chain to the last member of the last, across both renewal kinds) — carried as its own row because a hyper-literal RFC 2119 reading would treat the appendix as non-mandatory while the shipped verification is written against it")
    ];
}
