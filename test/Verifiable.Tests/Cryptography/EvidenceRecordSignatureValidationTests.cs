using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using PkiAlgorithmIdentifier = Verifiable.Cryptography.Pki.AlgorithmIdentifier;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for step 1) of clause 5.6.3.4 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>: "the SVA shall validate the Evidence Records according to
/// <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> or
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see>", and the proofs of existence a
/// verified record establishes for everything it protects.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The scenario is the one the mechanism exists for.</strong> The signing certificate has expired by the
/// time the signature is validated, so the validation process for Signatures with Time can only report
/// <c>INDETERMINATE</c>: nothing in the signature proves it existed while the certificate was valid. An Evidence
/// Record taken over the Signed Data Object while the certificate still was valid supplies exactly that proof,
/// and the past signature validation building block of clause 5.6.2.4 then reaches <c>TOTAL-PASSED</c>. Both runs
/// are asserted, so the difference is attributable to the record and to nothing else.
/// </para>
/// <para>
/// <strong>The path validation seam ignores the validity range on purpose.</strong> Step 7) of clause 5.2.6.4 is
/// what reports <c>OUT_OF_BOUNDS_*</c> for an expired certificate, and it is reached only when path validation
/// itself did not already reject the certificate — the same construction, and the same reason for it, that
/// <see cref="SignatureValidationBuildingBlockGapTests"/> records for its own step 7) test.
/// </para>
/// <para>
/// The Evidence Record is built by the shipped <see cref="EvidenceRecords.CreateInitialAsync"/> over a
/// time-stamp token minted by the independent BouncyCastle TSP oracle
/// (<see cref="MintingTimestampResponder"/>), and its structure is re-verified by the independent
/// <see cref="EvidenceRecordOracle"/> before the engine is asked about it.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EvidenceRecordSignatureValidationTests
{
    /// <summary>The address handed to the transport delegate; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.evidence-record.example.test/";

    /// <summary>The DNS name the signer's leaf certificate carries.</summary>
    private const string SignerDnsName = "evidence-record-signer.example.test";


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The content every minted signature encapsulates and covers.</summary>
    private static ReadOnlyMemory<byte> Content { get; } = new("the archived signed content"u8.ToArray());

    /// <summary>The instant the signature is created at, inside the signing certificate's validity.</summary>
    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    /// <summary>The instant the Evidence Record's initial Archive Timestamp asserts, still inside that validity.</summary>
    private static DateTimeOffset ArchiveTime { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The instant the Hash-Tree Renewal's Archive Timestamp asserts — after <see cref="ArchiveTime"/>, which RFC 4998 clause 5.1's ascending order requires, and before <see cref="ValidationTime"/>.</summary>
    private static DateTimeOffset RenewalTime { get; } = TestClock.CanonicalEpoch.AddHours(2);

    /// <summary>The identifier the Driving Application names the detached Signer's Document by, as Table 8 of clause 5.2.2.2 has it supply one.</summary>
    private const string DetachedDocumentIdentifier = "detached-document.txt";

    /// <summary>The instant the signature is validated at, after the signing certificate has expired.</summary>
    private static DateTimeOffset ValidationTime { get; } = TestClock.CanonicalEpoch.AddDays(30);

    /// <summary>The signing certificate's validity end — before <see cref="ValidationTime"/> and after <see cref="ArchiveTime"/>.</summary>
    private static DateTimeOffset SignerNotAfter { get; } = TestClock.CanonicalEpoch.AddDays(10);


    /// <summary>
    /// The capstone of the engine wiring: a signature whose certificate has expired reaches
    /// <c>TOTAL-PASSED</c> when an Evidence Record proves it existed while the certificate was valid, and reports
    /// <c>INDETERMINATE</c> when the same run is given no record. Step 1) of clause 5.6.3.4, composed with the
    /// past signature validation building block of clause 5.6.2.4.
    /// </summary>
    [TestMethod]
    public async Task AnEvidenceRecordProvesAnExpiredCertificateSignatureAndCarriesItToTotalPassed()
    {
        using var world = await EvidenceRecordValidationWorld.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome withoutRecord = await SignatureValidation.ValidateAsync(
            world.Inputs, world.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.Indeterminate, withoutRecord.Conclusion.Indication,
            "Step 7) of clause 5.2.6.4: a signing certificate outside its validity range at the validation time, with nothing proving when the signature existed, is INDETERMINATE.");
        Assert.IsNotNull(withoutRecord.LongTermValidation, "The process of clause 5.6.3 ran.");
        Assert.IsEmpty(withoutRecord.LongTermValidation!.EvidenceRecordValidations,
            "A run given no Evidence Record has nothing for step 1) to do, and reports exactly that.");
        Assert.IsFalse(withoutRecord.LongTermValidation.HasLongTermAvailabilityAttributes,
            "The signature carries no archive time-stamp attribute and no record accompanies it, so step 3)'s early return applies.");

        using SignatureValidationOutcome withRecord = await SignatureValidation.ValidateAsync(
            world.InputsWithEvidenceRecord, world.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.TotalPassed, withRecord.Conclusion.Indication,
            $"Step 1) of clause 5.6.3.4: the record's proof of existence at a time the certificate was valid is what clause 5.6.2.4 step 3) needs to settle an out-of-bounds status. Sub-indications: {string.Join(", ", withRecord.Conclusion.SubIndications.Select(s => s.Value))}.");
        Assert.IsNotNull(withRecord.LongTermValidation, "The process of clause 5.6.3 ran.");
        Assert.IsTrue(withRecord.LongTermValidation!.HasLongTermAvailabilityAttributes,
            "An Evidence Record IS material for long term availability (EN 319 162-1 clause 4.4.5 item 2), so step 3)'s early return does not apply.");
        Assert.AreEqual(ArchiveTime, withRecord.LongTermValidation.BestSignatureTime,
            "Step 6): best-signature-time is the earliest instant the accumulated proofs prove the signature value existed at, which is the record's initial Archive Timestamp.");
    }


    /// <summary>
    /// Step 1)'s own conclusion, read from the result: the record verified, its most recent Archive Timestamp
    /// validated through the building block of clause 5.4, and the Signed Data Object is reported as proven.
    /// </summary>
    [TestMethod]
    public async Task StepOneReportsWhatTheRecordAndItsTimestampConcluded()
    {
        using var world = await EvidenceRecordValidationWorld.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            world.InputsWithEvidenceRecord, world.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        EvidenceRecordValidationResult record = outcome.LongTermValidation!.EvidenceRecordValidations.Single();
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, record.Status,
            "RFC 4998 clause 5.3: the reduced hash tree carries the Signed Data Object up to the root the embedded time-stamp binds.");
        Assert.AreEqual(ArchiveTime, record.InitialArchiveTime, "The record's initial Archive Timestamp is what states the instant.");
        Assert.IsNotNull(record.ArchiveTimestampValidation, "Step 1) validates the time-stamp within, per clause 5.4.");
        Assert.AreEqual(BuildingBlockIndication.Passed, record.ArchiveTimestampValidation!.Conclusion.Indication,
            "Clause 5.3: the last Archive Timestamp has to be valid at the time the verification is performed.");
        Assert.IsTrue(record.EstablishedProofOfExistence, "A record that verified and whose time-stamp validated establishes proofs.");

        EvidenceRecordProtectedObjectResult protectedObject = record.ProtectedObjects.Single();
        Assert.IsTrue(protectedObject.IsProven, "The Signed Data Object the Driving Application named is the one the record carries.");
        Assert.AreEqual(ArchiveTime, protectedObject.CoveredUntil,
            "A record of one chain carries its data object exactly as far as that chain's own most recent Archive Timestamp.");
    }


    /// <summary>
    /// The report of clause 4.4.7 of
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
    /// ETSI TS 119 102-2 V1.4.1</see>: the Evidence Record is projected as a validation object and its
    /// <c>ProvidesProofOfExistenceFor</c> names, at the record's own archive time, the objects the Signed Data
    /// Object contains.
    /// </summary>
    [TestMethod]
    public async Task TheReportAttributesTheProofOfExistenceToTheEvidenceRecord()
    {
        using var world = await EvidenceRecordValidationWorld.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            world.InputsWithEvidenceRecord, world.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        ValidationReport report = await SignatureValidationReportBuilder.BuildAsync(
            outcome, world.InputsWithEvidenceRecord, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        ValidationObject recordObject = report.SignatureValidationObjects.Single(o => o.ObjectType == ValidationObjectKind.EvidenceRecord);
        Assert.IsNotEmpty(recordObject.ProvidesProofOfExistenceFor,
            "Clause 4.4.7: the member is populated for a time-stamp token or an evidence record, and this run has one of the latter.");

        ProofOfExistenceProvisioning provisioning = recordObject.ProvidesProofOfExistenceFor.Single();
        Assert.AreEqual(ArchiveTime, provisioning.ProofTime,
            "Clause 4.4.7.1: the time value of the proof is the record's own initial Archive Timestamp.");

        ValidationObject signedContent = report.SignatureValidationObjects.Single(o => o.ObjectType == ValidationObjectKind.SignedDataObject);
        Assert.Contains(signedContent.Representation, provisioning.CoveredObjects.ToList(),
            "Clause 5.6.2.3 step 5): a proof for the Signed Data Object is a proof for each object it contains, the signed content among them.");
        Assert.IsNotNull(signedContent.ProofOfExistence, "Clause 4.4.6: the covered object carries the proof the record established for it.");
        Assert.AreEqual(ProofOfExistenceOrigin.EvidenceRecord, signedContent.ProofOfExistence!.Origin,
            "The proof is attributed to the evidence record that established it, not to the process itself.");
    }


    /// <summary>
    /// Fail-closed: a record that verifies over other octets than the ones it is stated to protect proves nothing
    /// here, establishes no proof of existence, and leaves the conclusion exactly where it was without it.
    /// </summary>
    [TestMethod]
    public async Task ARecordOverOtherOctetsEstablishesNothingAndDoesNotChangeTheConclusion()
    {
        using var world = await EvidenceRecordValidationWorld.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            world.InputsWithForeignEvidenceRecord, world.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.Indeterminate, outcome.Conclusion.Indication,
            "A record that does not carry the Signed Data Object proves nothing about it, so the out-of-bounds status stands.");

        EvidenceRecordValidationResult record = outcome.LongTermValidation!.EvidenceRecordValidations.Single();
        Assert.AreEqual(EvidenceRecordVerificationStatus.DataObjectNotCovered, record.Status,
            "RFC 4998 clause 4.3 step 2: the hash of the data object is not in the first list of hash values.");
        Assert.IsFalse(record.EstablishedProofOfExistence, "A record proving nothing establishes no proof of existence.");
        Assert.IsFalse(record.ProtectedObjects.Single().IsProven, "The object the caller named is not the one the record carries.");
    }


    /// <summary>
    /// Step 2 d) of <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.3">RFC 4998 clause 5.3</see>: an
    /// earlier chain's digest algorithm that the caller's dated table does not assert reliable at the instant the
    /// following chain was created withholds the proof of existence the record's initial Archive Timestamp would
    /// otherwise state. The record's structure is sound and its most recent Archive Timestamp validates — the
    /// only thing missing is the algorithm's reliability across the renewal, which is exactly the link the
    /// initial instant is carried forward by.
    /// </summary>
    [TestMethod]
    public async Task AnEarlierChainAlgorithmTheTableDatesUnreliableAtTheRenewalWithholdsTheProof()
    {
        using var world = await EvidenceRecordValidationWorld.CreateAsync(
            new EvidenceRecordValidationWorldOptions
            {
                RenewedRecord = true,
                InitialDigestAlgorithm = PkiDigestAlgorithm.Sha384,
                InitialChainAlgorithmTrustedUntil = RenewalTime.AddMinutes(-1)
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            world.InputsWithEvidenceRecord, world.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        EvidenceRecordValidationResult record = outcome.LongTermValidation!.EvidenceRecordValidations.Single();
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, record.Status,
            "The STRUCTURE of clause 5.3 steps 2 a) and 3 a) holds: both chains verify and the data object is carried across the renewal. What this test is about is the temporal half.");
        Assert.AreEqual(BuildingBlockIndication.Passed, record.ArchiveTimestampValidation!.Conclusion.Indication,
            "The record's most recent Archive Timestamp validates through the building block of clause 5.4, so the proof is not withheld for the reason clause 5.3's last sentence names.");

        AlgorithmReliabilityAssessment assessment = record.UnreliableChainAlgorithms.Single();
        Assert.AreEqual(PkiAlgorithmIdentifier.Sha384, assessment.Use.Algorithm,
            "The first chain's own digest algorithm is the one the table stops asserting reliable before the renewal instant.");
        Assert.AreEqual(AlgorithmReliabilityVerdict.NoLongerReliable, assessment.Verdict,
            "Step 2 d): the algorithm has to be secure at the time of the first Archive Timestamp of the following ArchiveTimeStampChain, and the table says it was not.");
        Assert.AreEqual(RenewalTime.AddMinutes(-1), assessment.TrustedUntil,
            "The report carries the time up to which the algorithm was considered secure, which Table 6 of clause 5.1.3 asks a cryptographic-constraints failure to state.");

        Assert.IsFalse(record.EstablishedProofOfExistence,
            "A record whose earlier chain rests on an algorithm the caller's own policy dates as broken by the renewal establishes nothing at the initial archive time.");
        Assert.IsFalse(record.ProtectedObjects.Single().IsProven, "The Signed Data Object is carried by the record's structure but not proven by it under these constraints.");
        Assert.IsEmpty(EvidenceRecordProofs(outcome.LongTermValidation), "No proof of existence at all is attributed to the record.");
        Assert.AreEqual(SignatureValidationIndication.Indeterminate, outcome.Conclusion.Indication,
            $"Without the record's proof the out-of-bounds status of step 7) of clause 5.2.6.4 stands. Sub-indications: {string.Join(", ", outcome.Conclusion.SubIndications.Select(s => s.Value))}.");
    }


    /// <summary>
    /// The same renewed record, the same run, and one date changed: a table asserting the earlier chain's
    /// algorithm reliable up to exactly the renewal instant satisfies step 2 d) — "secure AT the time of the
    /// first Archive Timestamp of the following ArchiveTimeStampChain" includes that instant — and the proof at
    /// the initial archive time is stated, carrying the expired-certificate signature to <c>TOTAL-PASSED</c>.
    /// </summary>
    [TestMethod]
    public async Task TheSameRenewedRecordProvesTheSignatureWhenTheTableReachesTheRenewalInstant()
    {
        using var world = await EvidenceRecordValidationWorld.CreateAsync(
            new EvidenceRecordValidationWorldOptions
            {
                RenewedRecord = true,
                InitialDigestAlgorithm = PkiDigestAlgorithm.Sha384,
                InitialChainAlgorithmTrustedUntil = RenewalTime
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            world.InputsWithEvidenceRecord, world.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        EvidenceRecordValidationResult record = outcome.LongTermValidation!.EvidenceRecordValidations.Single();
        Assert.IsEmpty(record.UnreliableChainAlgorithms, "Every chain's algorithm is asserted reliable at the instant step 2 d) names, the boundary instant included.");
        Assert.IsTrue(record.EstablishedProofOfExistence, "A record whose every link and algorithm held establishes the proof its initial Archive Timestamp states.");
        Assert.AreEqual(ArchiveTime, record.InitialArchiveTime, "The instant is the initial Archive Timestamp's, not the renewal's.");
        Assert.AreEqual(RenewalTime, record.LatestArchiveTime, "The record's most recent Archive Timestamp is the renewal's.");
        Assert.AreEqual(RenewalTime, record.ProtectedObjects.Single().CoveredUntil,
            "The object's own unbroken run of proofs reaches the renewal, which is what makes the token validated at the current time the endpoint of THIS object's coverage.");
        Assert.AreEqual(SignatureValidationIndication.TotalPassed, outcome.Conclusion.Indication,
            $"Sub-indications: {string.Join(", ", outcome.Conclusion.SubIndications.Select(s => s.Value))}.");
        Assert.AreEqual(ArchiveTime, outcome.LongTermValidation.BestSignatureTime, "Step 6): the earliest instant the accumulated proofs prove the signature value existed at.");
    }


    /// <summary>
    /// A run whose validation constraints carry no cryptographic table at all is left exactly where it was: this
    /// library ships no dated algorithm-reliability table and invents none (waveasic contract R-10, "the caller's
    /// dated AlgorithmReliabilityEntry table consulted when supplied"), so the gate of step 2 d) does not run and
    /// the record establishes the proof its structure and its time-stamp support.
    /// </summary>
    [TestMethod]
    public async Task ARunStatingNoCryptographicTableLeavesTheEvidenceRecordStepWhereItWas()
    {
        using var world = await EvidenceRecordValidationWorld.CreateAsync(
            new EvidenceRecordValidationWorldOptions
            {
                RenewedRecord = true,
                InitialDigestAlgorithm = PkiDigestAlgorithm.Sha384,
                SupplyCryptographicTable = false
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            world.InputsWithEvidenceRecord, world.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        EvidenceRecordValidationResult record = outcome.LongTermValidation!.EvidenceRecordValidations.Single();
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, record.Status, "The structural half of clause 5.3 is decided by the record alone and needs no table.");
        Assert.IsEmpty(record.UnreliableChainAlgorithms,
            "An empty list means both 'every algorithm was asserted reliable' and 'no table was supplied'; this run is the second, and the step reports no assessment it did not make.");
        Assert.IsTrue(record.EstablishedProofOfExistence, "The behaviour of a run supplying no table is the behaviour it had before the gate existed.");

        List<ProofOfExistence> signatureProofs = EvidenceRecordProofsAbout(outcome.LongTermValidation, ValidationObjectKind.Signature);
        Assert.IsNotEmpty(signatureProofs, "The record establishes a proof for the CAdES object's octets — the object the caller named and the object the containment rule starts from.");
        Assert.IsTrue(signatureProofs.TrueForAll(static proof => proof.Instant == ArchiveTime && proof.Scope == ProofOfExistenceScope.Object),
            "Every one of them states the initial Archive Timestamp's instant and proves the object itself, exactly as they did before the gate existed.");
    }


    /// <summary>
    /// Clause 5.6.3.4 step 1)c) with NOTE 2 and EXAMPLE 1: a record whose hash tree carries the Signed Data
    /// Object's octets proves those octets and what they CONTAIN, and a detached Signer's Document is not among
    /// them — the Signed Data Object holds a digest of it in the <c>message-digest</c> signed attribute and
    /// nothing else. The proof at the current time step 2) states about the same document is untouched, because
    /// the Driving Application demonstrably holds it now.
    /// </summary>
    [TestMethod]
    public async Task ADetachedSignersDocumentIsNotClaimedAsContainedInTheProvenSignedDataObject()
    {
        using var world = await EvidenceRecordValidationWorld.CreateAsync(
            new EvidenceRecordValidationWorldOptions { DetachedSignature = true },
            TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            world.InputsWithEvidenceRecord, world.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.TotalPassed, outcome.Conclusion.Indication,
            $"The record still proves the octets it carries, so the detached signature over an expired certificate still reaches TOTAL-PASSED. Sub-indications: {string.Join(", ", outcome.Conclusion.SubIndications.Select(s => s.Value))}.");
        Assert.IsTrue(outcome.LongTermValidation!.EvidenceRecordValidations.Single().EstablishedProofOfExistence,
            "The record proves the CAdES object's own octets, which is what its hash tree was built over.");
        List<ProofOfExistence> signatureProofs = EvidenceRecordProofsAbout(outcome.LongTermValidation, ValidationObjectKind.Signature);
        Assert.IsNotEmpty(signatureProofs, "Clause 5.6.3.4 step 1)c): the object the record covers is proven by it.");
        Assert.IsTrue(signatureProofs.TrueForAll(static proof => proof.Instant == ArchiveTime),
            "The instant is the initial Archive Timestamp's, which is what the record states about the octets it carries.");
        Assert.IsNotEmpty(EvidenceRecordProofsAbout(outcome.LongTermValidation, ValidationObjectKind.SignatureValue),
            "The signature value IS contained in the Signed Data Object, so the containment rule of clause 5.6.2.3 step 5) still reaches it — which is what carries the expired certificate.");

        Assert.IsEmpty(EvidenceRecordProofsAbout(outcome.LongTermValidation, ValidationObjectKind.SignedDataObject),
            "The record's group holds the CAdES object alone (RFC 4998 Appendix A's first selection method), so nothing in it proves the Signer's Document existed at the archive time.");

        List<ProofOfExistence> documentProofs =
        [
            .. outcome.LongTermValidation.ProofsOfExistence.Proofs.Where(static proof =>
                proof.ObjectIdentity.Kind == ValidationObjectKind.SignedDataObject
                && string.Equals(proof.ObjectIdentity.Reference, DetachedDocumentIdentifier, StringComparison.Ordinal))
        ];
        Assert.HasCount(1, documentProofs, "Step 2) with NOTE 3 still adds a proof at the current time for the document the Driving Application supplied.");
        Assert.AreEqual(ProofOfExistenceOrigin.DrivingApplicationAssertion, documentProofs[0].Origin, "That proof is the process's own assertion, not the record's.");
        Assert.AreEqual(ValidationTime, documentProofs[0].Instant, "And it states the current time, which is the only instant the run has evidence for.");
    }


    /// <summary>
    /// Lists the proofs of existence one run attributed to an Evidence Record — the proofs whose
    /// <see cref="ProofOfExistence.Origin"/> is <see cref="ProofOfExistenceOrigin.EvidenceRecord"/>.
    /// </summary>
    /// <param name="longTermValidation">What the process of clause 5.6.3 returned.</param>
    /// <returns>The proofs, in the order the process accumulated them.</returns>
    private static List<ProofOfExistence> EvidenceRecordProofs(LongTermValidationResult longTermValidation) =>
        [.. longTermValidation.ProofsOfExistence.Proofs.Where(static proof => proof.Origin == ProofOfExistenceOrigin.EvidenceRecord)];


    /// <summary>
    /// Lists the proofs of existence one run attributed to an Evidence Record about one kind of object.
    /// </summary>
    /// <param name="longTermValidation">What the process of clause 5.6.3 returned.</param>
    /// <param name="kind">The kind of object to select.</param>
    /// <returns>The proofs, in the order the process accumulated them.</returns>
    private static List<ProofOfExistence> EvidenceRecordProofsAbout(LongTermValidationResult longTermValidation, ValidationObjectKind kind) =>
        [.. EvidenceRecordProofs(longTermValidation).Where(proof => proof.ObjectIdentity.Kind == kind)];


    /// <summary>
    /// What one world mints, so that the scenarios of this class differ by a value rather than by a second world
    /// class: the default is the encapsulated, single-chain, fully-trusted world the first tests validate in.
    /// </summary>
    private sealed record EvidenceRecordValidationWorldOptions
    {
        /// <summary>
        /// Whether the CAdES object is minted DETACHED, with the content travelling beside it as the Signer's
        /// Document of Table 8 of clause 5.2.2.2 — the shape every CAdES object inside an Associated Signature
        /// Container has (EN 319 162-1 clause 4.4.4.2 item 3 a).
        /// </summary>
        public bool DetachedSignature { get; init; }

        /// <summary>Whether the Evidence Record is renewed once by the Hash-Tree Renewal of RFC 4998 clause 5.2, which gives the record a second <c>ArchiveTimeStampChain</c> under a new algorithm.</summary>
        public bool RenewedRecord { get; init; }

        /// <summary>
        /// The algorithm the record's INITIAL chain is built under. Deliberately settable, because a scenario
        /// that dates that algorithm has to be able to choose one nothing else in the run uses.
        /// </summary>
        public PkiDigestAlgorithm InitialDigestAlgorithm { get; init; } = PkiDigestAlgorithm.Sha256;

        /// <summary>The instant up to which the cryptographic constraints assert <see cref="InitialDigestAlgorithm"/> reliable; <see langword="null"/> asserts no expiry, which is the table's "if such a time is known" case.</summary>
        public DateTimeOffset? InitialChainAlgorithmTrustedUntil { get; init; }

        /// <summary>
        /// Whether the SIGNATURE validation constraints carry a cryptographic table at all. The time-stamp
        /// constraints always do, so a run stating no table still validates the record's own Archive Timestamp
        /// through the building block of clause 5.4 and the difference is attributable to the table alone.
        /// </summary>
        public bool SupplyCryptographicTable { get; init; } = true;
    }


    /// <summary>
    /// The world every test of this class validates in: a root certification authority, a Time-Stamping
    /// Authority, a signer whose certificate expires before the validation time, the CAdES-B-B signature, and the
    /// Evidence Record taken over that signature's octets while the certificate was still valid.
    /// </summary>
    private sealed class EvidenceRecordValidationWorld: IDisposable
    {
        /// <summary>The carriers this world rented, released in reverse order.</summary>
        private readonly List<IDisposable> owned = [];

        /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
        private bool disposed;


        /// <summary>The inputs of Tables 18, 20 and 27, with no Evidence Record.</summary>
        public SignatureValidationInputs Inputs { get; private set; } = null!;

        /// <summary>The same inputs, with the Evidence Record that proves the Signed Data Object.</summary>
        public SignatureValidationInputs InputsWithEvidenceRecord { get; private set; } = null!;

        /// <summary>The same inputs, with a record taken over octets that are not the Signed Data Object.</summary>
        public SignatureValidationInputs InputsWithForeignEvidenceRecord { get; private set; } = null!;

        /// <summary>The seams the run composes.</summary>
        public SignatureValidationSeams Seams { get; private set; } = null!;


        /// <summary>
        /// Mints the default world: an encapsulated signature and a single-chain Evidence Record under a table
        /// that asserts every algorithm reliable without expiry.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The world, which the caller disposes.</returns>
        public static ValueTask<EvidenceRecordValidationWorld> CreateAsync(CancellationToken cancellationToken) =>
            CreateAsync(new EvidenceRecordValidationWorldOptions(), cancellationToken);


        /// <summary>
        /// Mints the world.
        /// </summary>
        /// <param name="options">What the world mints.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The world, which the caller disposes.</returns>
        public static async ValueTask<EvidenceRecordValidationWorld> CreateAsync(
            EvidenceRecordValidationWorldOptions options,
            CancellationToken cancellationToken)
        {
            var world = new EvidenceRecordValidationWorld();
            try
            {
                await world.BuildAsync(options, cancellationToken).ConfigureAwait(false);

                return world;
            }
            catch
            {
                world.Dispose();

                throw;
            }
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
        /// Mints the certificates, the signature and the Evidence Records, and assembles the inputs and seams.
        /// </summary>
        /// <param name="options">What this world mints.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        private async ValueTask BuildAsync(EvidenceRecordValidationWorldOptions options, CancellationToken cancellationToken)
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            X509ChainTestRingNode root = Own(X509ChainTestRing.CreateRootCa(
                timeProvider, notBefore: SigningTime.AddYears(-1), notAfter: SigningTime.AddYears(9)));
            X509ChainTestRingNode authority = Own(X509ChainTestRing.CreateTimeStampingAuthority(
                root, timeProvider, notBefore: SigningTime.AddYears(-1), notAfter: SigningTime.AddYears(9)));
            X509ChainTestRingNode signer = Own(X509ChainTestRing.CreateLeaf(
                root, SignerDnsName, timeProvider, notBefore: SigningTime.AddYears(-1), notAfter: SignerNotAfter));

            PkiCertificateMemory signerCertificate = Own(OcspTestFixtures.ToCertificateCarrier(signer.Certificate));
            PkiCertificateMemory rootCertificate = Own(OcspTestFixtures.ToCertificateCarrier(root.Certificate));
            PkiCertificateMemory authorityCertificate = Own(OcspTestFixtures.ToCertificateCarrier(authority.Certificate));
            PkiCertificateMemory revocationList = Own(X509ChainTestRingRevocation.MintCertificateRevocationList(
                root, SigningTime.AddMinutes(-5), ValidationTime.AddDays(7), []));

            //The detached world hands the signature a digest of content the caller keeps beside it (§4.5), which
            //is what an Associated Signature Container's CAdES object is; the encapsulated world embeds the
            //content itself. Both digests are computed through the registered seam.
            using DigestValue detachedContentDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                Content, PkiDigestAlgorithm.Sha256.OutputByteLength, PkiDigestAlgorithm.Sha256.DigestTag,
                BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);

            //The nullable is STATED on the null branch of each conditional. Without the cast the conditional has
            //a natural type of ReadOnlyMemory<byte> — the null literal converts to a byte[] and from there
            //through that type's own implicit operator to an EMPTY ReadOnlyMemory — so both arguments would
            //arrive "supplied", which is the one combination clause 4.5 refuses.
            ReadOnlyMemory<byte>? attachedContent = options.DetachedSignature ? (ReadOnlyMemory<byte>?)null : Content;
            ReadOnlyMemory<byte>? suppliedContentDigest = options.DetachedSignature
                ? detachedContentDigest.AsReadOnlyMemory()[..PkiDigestAlgorithm.Sha256.OutputByteLength]
                : (ReadOnlyMemory<byte>?)null;

            using CAdESSignaturePreparation preparation = await CAdESSignatureCreation.PrepareAsync(
                signerCertificate,
                attachedContent,
                suppliedContentDigest,
                PkiDigestAlgorithm.Sha256, SigningTime,
                algorithmConstraints: null, cmsAlgorithmProtectionSignatureAlgorithmOid: null, BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);
            byte[] signatureValueP1363 = signer.SigningKey.SignData(
                preparation.SigningInput.AsReadOnlySpan().ToArray(), HashAlgorithmName.SHA256);
            using IMemoryOwner<byte> signatureValueDer = EcdsaSignatureEncoding.ConvertP1363ToDer(
                signatureValueP1363, BaseMemoryPool.Shared, out int derLength);
            CmsSignedData signedData = Own(CAdESSignatureCreation.Complete(
                preparation, signerCertificate, CryptoAlgorithm.P256, signatureValueDer.Memory[..derLength],
                additionalCertificates: null, BaseMemoryPool.Shared));

            byte[] signedDataObject = signedData.AsReadOnlySpan().ToArray();
            var responder = new MintingTimestampResponder(authority, [authority, root], ArchiveTime);
            EvidenceRecordCreation creation = Own(await EvidenceRecords.CreateInitialAsync(
                new EvidenceRecordCreationContext
                {
                    DataObjectGroups = [new EvidenceRecordDataObjectGroup { DataObjects = [new ReadOnlyMemory<byte>(signedDataObject)] }],
                    DigestAlgorithm = options.InitialDigestAlgorithm,
                    TsaUri = TsaUri,
                    FetchTimestampResponse = responder.FetchAsync
                },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false));
            EvidenceRecord record = creation.EvidenceRecords[0];

            //Leg 3: the independent from-spec-text oracle walks the record's own octets to the root the embedded
            //token binds, before the engine is asked anything about it.
            OracleEvidenceRecord parsedRecord = EvidenceRecordOracle.ParseEvidenceRecord(record.AsReadOnlySpan().ToArray());
            OracleArchiveTimeStamp initial = parsedRecord.Chains[0][0];
            byte[]? independentRoot = EvidenceRecordOracle.RecomputeRoot(
                EvidenceRecordOracle.Hash(signedDataObject, options.InitialDigestAlgorithm), initial.ReducedHashtree, options.InitialDigestAlgorithm);
            Assert.IsNotNull(independentRoot, "The independent walk reaches a root from the record's own reduced hash tree.");
            Assert.IsTrue(independentRoot.AsSpan().SequenceEqual(initial.MessageImprint),
                "The independent Merkle recomputation has to reach the root the record's own time-stamp binds.");

            //The renewed world gives the record a second chain under a new algorithm, so that the first chain's
            //own algorithm has a renewal instant to be assessed at (RFC 4998 clause 5.3 step 2 d).
            if(options.RenewedRecord)
            {
                var renewalResponder = new MintingTimestampResponder(authority, [authority, root], RenewalTime);
                EvidenceRecordRenewal renewal = Own(await EvidenceRecords.RenewHashTreeAsync(
                    new EvidenceRecordHashTreeRenewalContext
                    {
                        DataObjectGroups =
                        [
                            new EvidenceRecordHashTreeRenewalGroup
                            {
                                EvidenceRecord = record,
                                DataObjects = [new ReadOnlyMemory<byte>(signedDataObject)]
                            }
                        ],
                        DigestAlgorithm = PkiDigestAlgorithm.Sha512,
                        TsaUri = TsaUri,
                        FetchTimestampResponse = renewalResponder.FetchAsync
                    },
                    BaseMemoryPool.Shared,
                    cancellationToken).ConfigureAwait(false));
                record = renewal.EvidenceRecords[0];

                OracleEvidenceRecord parsedRenewed = EvidenceRecordOracle.ParseEvidenceRecord(record.AsReadOnlySpan().ToArray());
                Assert.HasCount(2, parsedRenewed.Chains, "The independent reader finds the two chains the renewal wrote.");
                byte[] renewalValue = EvidenceRecordOracle.HashTreeRenewalValue(
                    signedDataObject, [parsedRenewed.ChainEncodings[0]], PkiDigestAlgorithm.Sha512);
                Assert.IsTrue(
                    EvidenceRecordOracle.ContainsValue(parsedRenewed.Chains[1][0].ReducedHashtree[0], renewalValue),
                    "Clause 5.2 step 4: the new chain's first list carries the combination of the data object hash and the hash of the encoded prior sequence.");
            }

            byte[] foreignObject = [.. "an object no signature ever covered"u8];
            EvidenceRecordCreation foreignCreation = Own(await EvidenceRecords.CreateInitialAsync(
                new EvidenceRecordCreationContext
                {
                    DataObjectGroups = [new EvidenceRecordDataObjectGroup { DataObjects = [new ReadOnlyMemory<byte>(foreignObject)] }],
                    DigestAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = TsaUri,
                    FetchTimestampResponse = responder.FetchAsync
                },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false));

            var x509Constraints = new X509ValidationConstraints
            {
                TrustAnchors = [new TrustAnchorConstraint(rootCertificate, SunsetDate: null)],
                MaximumAcceptedRevocationFreshness = TimeSpan.FromDays(365)
            };
            //The initial chain's own algorithm is dated separately from everything else the run uses, so that a
            //scenario dating it as unreliable changes nothing but the question RFC 4998 clause 5.3 step 2 d)
            //asks. SHA-512 is the renewal's algorithm and SHA-256 is the signature's and every token's.
            var cryptographicConstraints = new CryptographicConstraints
            {
                Entries =
                [
                    //First, because a table lookup takes the first row it finds: a world that dates the initial
                    //chain's algorithm states that date even where the algorithm is one of the two below.
                    new AlgorithmReliabilityEntry(
                        options.InitialDigestAlgorithm.Identifier,
                        MinimumKeySizeBits: null,
                        options.InitialChainAlgorithmTrustedUntil),
                    new AlgorithmReliabilityEntry(
                        new PkiAlgorithmIdentifier(X509ChainTestRing.EcdsaWithSha256SignatureOid),
                        MinimumKeySizeBits: X509ChainTestRing.SigningKeySizeBits,
                        TrustedUntil: null),
                    new AlgorithmReliabilityEntry(PkiAlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, TrustedUntil: null),
                    new AlgorithmReliabilityEntry(PkiAlgorithmIdentifier.Sha512, MinimumKeySizeBits: null, TrustedUntil: null)
                ]
            };
            var timestampConstraints = new SignatureValidationConstraints
            {
                Identifier = SignatureValidationPolicyIdentifier.CallerSuppliedConstraints,
                X509 = x509Constraints,
                Cryptographic = cryptographicConstraints,
                SignatureElements = SignatureElementsConstraints.None
            };
            SignatureValidationConstraints constraints = options.SupplyCryptographicTable
                ? timestampConstraints
                : timestampConstraints with { Cryptographic = CryptographicConstraints.Empty };

            var completer = new CertificateChainCompleter([rootCertificate]);
            Seams = new SignatureValidationSeams
            {
                Format = CAdESSignatureFacts.Seam,
                CompleteCertificateChain = completer.CompleteAsync,
                ValidateCertificateChain = IgnoresValidityRangeAsync
            };

            //The Time-Stamping Authority's own certificate needs a revocation status of its own: the Evidence
            //Record's embedded token is validated as a Basic Signature in its own right (clause 5.4.4 step 1)),
            //and a certificate nothing states a status about is not one this engine passes.
            List<RevocationStatusInformation> revocationStatus =
            [
                new()
                {
                    RevocationData = revocationList,
                    SubjectCertificate = signerCertificate,
                    IssuerCertificate = rootCertificate,
                    Status = CertificateRevocationStatus.Good,
                    ThisUpdate = SigningTime.AddMinutes(-5),
                    NextUpdate = ValidationTime.AddDays(7),
                    CoversExpiredCertificates = true
                },
                new()
                {
                    RevocationData = revocationList,
                    SubjectCertificate = authorityCertificate,
                    IssuerCertificate = rootCertificate,
                    Status = CertificateRevocationStatus.Good,
                    ThisUpdate = SigningTime.AddMinutes(-5),
                    NextUpdate = ValidationTime.AddDays(7),
                    CoversExpiredCertificates = true
                }
            ];

            //A detached signature reaches the process only with the Signer's Document beside it (clause 5.2.7.4
            //step 1); the encapsulated world supplies none, exactly as it always did.
            List<SignerDocumentReference> signerDocuments = options.DetachedSignature
                ? [new SignerDocumentReference { Identifier = DetachedDocumentIdentifier, Content = Own(SignedContentMemory.FromBytes(Content.Span, BaseMemoryPool.Shared)) }]
                : [];

            Inputs = new SignatureValidationInputs
            {
                SignedDataObject = signedData,
                SignerDocuments = signerDocuments,
                Constraints = constraints,

                //The time-stamp constraints always carry the table, so that a world stating no signature-side
                //table still validates the record's own Archive Timestamp through the building block of clause
                //5.4 and the difference the test reads is attributable to the table alone.
                TimestampConstraints = timestampConstraints,
                //The certificate revocation list travels as validation data of its own, not only as the source of
                //a status: the validation time sliding process of clause 5.6.2.2 step 2)a) selects revocation
                //data only when the set of proofs of existence holds a proof for the data itself, and step 2) of
                //clause 5.6.3.4 is what puts one there.
                CertificateValidationData = [rootCertificate, revocationList],
                RevocationStatusInformation = revocationStatus
            };

            InputsWithEvidenceRecord = Inputs with
            {
                EvidenceRecords =
                [
                    new EvidenceRecordValidationInput
                    {
                        EvidenceRecord = record,
                        Identifier = "evidencerecord1.ers",
                        ProtectedObjects =
                        [
                            new EvidenceRecordProtectedObject
                            {
                                Object = signedData,
                                Kind = ValidationObjectKind.Signature,
                                Reference = "signature1.p7s"
                            }
                        ]
                    }
                ]
            };

            InputsWithForeignEvidenceRecord = Inputs with
            {
                EvidenceRecords =
                [
                    new EvidenceRecordValidationInput
                    {
                        EvidenceRecord = foreignCreation.EvidenceRecords[0],
                        Identifier = "evidencerecord2.ers",
                        ProtectedObjects =
                        [
                            new EvidenceRecordProtectedObject
                            {
                                Object = signedData,
                                Kind = ValidationObjectKind.Signature,
                                Reference = "signature1.p7s"
                            }
                        ]
                    }
                ]
            };
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


        /// <summary>
        /// A path validation seam that performs the chain's own checks and not the validity-range one, so that
        /// step 7) of clause 5.2.6.4 — the step that reports an expired certificate as out of bounds — is what
        /// decides, rather than the platform seam rejecting the certificate before that step is reached.
        /// </summary>
        /// <param name="chain">The chain the block built.</param>
        /// <param name="trustAnchors">The trust anchors the constraints state.</param>
        /// <param name="validationTime">The instant the chain is validated at.</param>
        /// <param name="pool">The memory pool the returned carrier is rented from.</param>
        /// <param name="checkRevocation">The revocation seam, unused here.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>A placeholder public key; the caller discards it (the shipped block does exactly that).</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "Ownership transfers to the caller: X509CertificateValidation.ValidateAsync consumes the delegate's result through its own 'using PublicKeyMemory _ = await validateCertificateChain(...)' and disposes it there.")]
        private static ValueTask<PublicKeyMemory> IgnoresValidityRangeAsync(
            IReadOnlyList<PkiCertificateMemory> chain,
            IReadOnlyList<PkiCertificateMemory> trustAnchors,
            DateTimeOffset validationTime,
            MemoryPool<byte> pool,
            CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
            CancellationToken cancellationToken)
        {
            IMemoryOwner<byte> owner = pool.Rent(1);

            return ValueTask.FromResult(new PublicKeyMemory(owner, CryptoTags.P256PublicKey));
        }
    }
}
