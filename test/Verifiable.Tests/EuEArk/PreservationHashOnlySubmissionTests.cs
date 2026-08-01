using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the hash-only submission of clause 9.3 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see>: which hash functions a profile accepts (<c>OVR-9.3-06</c>), the two checks a
/// service makes on a submission (<c>OVR-9.3-08</c>) and the per-part goal treatment that follows
/// (<c>OVR-9.3-07</c>).
/// </summary>
/// <remarks>
/// <para>
/// <strong>The hash values are computed, not invented.</strong> Every accepted submission carries digests that
/// came from the registered digest seam over real octets, so a length check that passes has been shown something
/// a real submitter could have sent; the one builder producing a value of the wrong length says so in its name.
/// </para>
/// <para>
/// <strong>Every refusal has its own test.</strong> A guard that only ever saw agreeing input has not been shown
/// to refuse anything, and both checks the requirement states are refusals a service owes its subscribers.
/// </para>
/// </remarks>
[TestClass]
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "A profile built by the capability source carries no extension and owns no pooled carrier; every submission, which does own carriers, is held in a using.")]
internal sealed class PreservationHashOnlySubmissionTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = default!;


    /// <summary>The signed data objects the submissions of these tests withhold and submit hashes of.</summary>
    private static string[] SignedDataObjects { get; } = ["the first signed data object", "the second signed data object"];


    /// <summary>
    /// A profile's accepted hash functions are the submission operation's input formats that name a hash
    /// function, and nothing else it announces is mistaken for one.
    /// </summary>
    [TestMethod]
    public void AProfilesAcceptedHashFunctionsAreItsSubmissionOperationsHashInputFormats()
    {
        using PreservationProfile profile = PreservationCapabilitySource.Profile(
            acceptedHashFunctions: [PkiDigestAlgorithm.Sha256, PkiDigestAlgorithm.Sha512]);

        IReadOnlyList<PkiDigestAlgorithm> accepted = PreservationHashOnlySubmissions.AcceptedHashFunctions(profile);

        Assert.HasCount(2, accepted);
        Assert.AreEqual(PkiDigestAlgorithm.Sha256.Identifier.Oid, accepted[0].Identifier.Oid);
        Assert.AreEqual(PkiDigestAlgorithm.Sha512.Identifier.Oid, accepted[1].Identifier.Oid);

        //The signature format the same operation also accepts is not a hash function.
        using PreservationProfile withoutHashFunctions = PreservationCapabilitySource.Profile();
        Assert.IsEmpty(PreservationHashOnlySubmissions.AcceptedHashFunctions(withoutHashFunctions));
    }


    /// <summary>
    /// An input format naming an algorithm this library cannot compute, and one that is not an object-identifier
    /// name at all, are simply not accepted hash functions — a submission under either could not have its length
    /// checked, which is what the requirement obliges.
    /// </summary>
    [TestMethod]
    public void AnInputFormatThatNamesNoComputableHashFunctionIsNotAnAcceptedOne()
    {
        using PreservationProfile profile = PreservationCapabilitySource.Profile() with
        {
            Operations =
            [
                new PreservationOperationDescriptor
                {
                    Name = PreservationWellKnown.PreservePreservationObjectOperation,
                    InputFormats =
                    [
                        new PreservationFormatDescriptor { FormatId = "urn:oid:1.3.14.3.2.26" },
                        new PreservationFormatDescriptor { FormatId = "http://www.w3.org/2001/04/xmlenc#sha256" },
                        new PreservationFormatDescriptor { FormatId = PreservationDigestMethod.ToUrn(PkiDigestAlgorithm.Sha384) },
                        new PreservationFormatDescriptor { FormatId = PreservationDigestMethod.ToUrn(PkiDigestAlgorithm.Sha384) }
                    ]
                }
            ]
        };

        IReadOnlyList<PkiDigestAlgorithm> accepted = PreservationHashOnlySubmissions.AcceptedHashFunctions(profile);

        //One algorithm, stated twice and listed once.
        Assert.HasCount(1, accepted);
        Assert.AreEqual(PkiDigestAlgorithm.Sha384.Identifier.Oid, accepted[0].Identifier.Oid);
    }


    /// <summary>
    /// A submission under a listed hash function whose values are the right length is accepted, and the goal
    /// treatment it comes back with is the two-treatment one the requirement forces: the signature stays under
    /// the preservation of digital signatures and every bare hash becomes general data.
    /// </summary>
    [TestMethod]
    public async Task AnAcceptedSubmissionCarriesTwoGoalTreatmentsAtOnce()
    {
        using PreservationProfile profile = PreservationCapabilitySource.Profile(
            acceptedHashFunctions: [PkiDigestAlgorithm.Sha256, PkiDigestAlgorithm.Sha512]);

        using PreservationHashOnlySubmission submission = await PreservationCapabilitySource.SubmissionAsync(
            PkiDigestAlgorithm.Sha512,
            SignedDataObjects,
            hashFunctionIdentifier: null,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        PreservationHashOnlySubmissionReport report = PreservationHashOnlySubmissions.StateAcceptance(
            new PreservationHashOnlySubmissionContext { Submission = submission, Profile = profile });

        Assert.AreEqual(PreservationHashOnlySubmissionStatus.Accepted, report.Status);
        Assert.IsTrue(report.IsAccepted);
        Assert.IsNull(report.Reason);
        Assert.AreEqual(PkiDigestAlgorithm.Sha512.Identifier.Oid, report.HashFunction?.Identifier.Oid);

        //One treatment for the signature, one per submitted hash value — three in all for two hashes.
        Assert.HasCount(SignedDataObjects.Length + 1, report.GoalTreatments);
        Assert.AreEqual(PreservationSubmissionPart.DetachedSignature, report.GoalTreatments[0].Part);
        Assert.AreEqual(PreservationWellKnown.DigitalSignatureGoal, report.GoalTreatments[0].Goal);
        Assert.AreEqual("OVR-9.3-03", report.GoalTreatments[0].RequirementIdentifier);

        for(int i = 1; i < report.GoalTreatments.Count; ++i)
        {
            Assert.AreEqual(PreservationSubmissionPart.SubmittedHashValue, report.GoalTreatments[i].Part);
            Assert.AreEqual(i - 1, report.GoalTreatments[i].Index);
            Assert.AreEqual(PreservationWellKnown.GeneralDataGoal, report.GoalTreatments[i].Goal);
            Assert.AreEqual("OVR-9.3-07", report.GoalTreatments[i].RequirementIdentifier);
        }

        //The demotion really is mid-flow: the profile announces the preservation of digital signatures and the
        //submission's own hash values are nonetheless treated as general data.
        Assert.Contains(PreservationWellKnown.DigitalSignatureGoal, profile.PreservationGoals);
        Assert.AreNotEqual(report.GoalTreatments[0].Goal, report.GoalTreatments[1].Goal);
    }


    /// <summary>
    /// A hash function the profile does not list is refused — the first check <c>OVR-9.3-08</c> obliges — and the
    /// report names what the profile does accept so a submitter can correct itself.
    /// </summary>
    [TestMethod]
    public async Task AHashFunctionTheProfileDoesNotListIsRefused()
    {
        using PreservationProfile profile = PreservationCapabilitySource.Profile(acceptedHashFunctions: [PkiDigestAlgorithm.Sha256]);

        using PreservationHashOnlySubmission submission = await PreservationCapabilitySource.SubmissionAsync(
            PkiDigestAlgorithm.Sha512,
            SignedDataObjects,
            hashFunctionIdentifier: null,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        PreservationHashOnlySubmissionReport report = PreservationHashOnlySubmissions.StateAcceptance(
            new PreservationHashOnlySubmissionContext { Submission = submission, Profile = profile });

        Assert.AreEqual(PreservationHashOnlySubmissionStatus.HashFunctionNotAcceptedByProfile, report.Status);
        Assert.IsFalse(report.IsAccepted);
        Assert.IsEmpty(report.GoalTreatments);
        Assert.HasCount(1, report.AcceptedHashFunctions);
        Assert.Contains("OVR-9.3-08", report.Reason!);
    }


    /// <summary>
    /// A hash value that is not as long as the stated hash function produces is refused — the second check
    /// <c>OVR-9.3-08</c> obliges — and the report names which value.
    /// </summary>
    [TestMethod]
    [DataRow(31, DisplayName = "one octet short of the stated function's output")]
    [DataRow(33, DisplayName = "one octet longer than the stated function's output")]
    [DataRow(64, DisplayName = "the length of another function the profile also accepts")]
    public void AHashValueOfTheWrongLengthIsRefused(int valueLength)
    {
        using PreservationProfile profile = PreservationCapabilitySource.Profile(
            acceptedHashFunctions: [PkiDigestAlgorithm.Sha256, PkiDigestAlgorithm.Sha512]);

        using PreservationHashOnlySubmission submission = PreservationCapabilitySource.SubmissionWithValueOfLength(
            PkiDigestAlgorithm.Sha256,
            valueLength,
            BaseMemoryPool.Shared);

        PreservationHashOnlySubmissionReport report = PreservationHashOnlySubmissions.StateAcceptance(
            new PreservationHashOnlySubmissionContext { Submission = submission, Profile = profile });

        Assert.AreEqual(PreservationHashOnlySubmissionStatus.HashValueLengthMismatch, report.Status);
        Assert.AreEqual(0, report.OffendingHashValueIndex);
        Assert.IsEmpty(report.GoalTreatments);
        Assert.Contains("OVR-9.3-08", report.Reason!);
    }


    /// <summary>A value of exactly the stated function's output length passes the same check.</summary>
    [TestMethod]
    public void AHashValueOfExactlyTheStatedLengthPasses()
    {
        using PreservationProfile profile = PreservationCapabilitySource.Profile(acceptedHashFunctions: [PkiDigestAlgorithm.Sha256]);

        using PreservationHashOnlySubmission submission = PreservationCapabilitySource.SubmissionWithValueOfLength(
            PkiDigestAlgorithm.Sha256,
            PkiDigestAlgorithm.Sha256.OutputByteLength,
            BaseMemoryPool.Shared);

        PreservationHashOnlySubmissionReport report = PreservationHashOnlySubmissions.StateAcceptance(
            new PreservationHashOnlySubmissionContext { Submission = submission, Profile = profile });

        Assert.AreEqual(PreservationHashOnlySubmissionStatus.Accepted, report.Status);
        Assert.HasCount(2, report.GoalTreatments);
    }


    /// <summary>
    /// An identifier that is not an object-identifier uniform resource name naming a computable hash function is
    /// refused before anything is compared against the profile's list.
    /// </summary>
    [TestMethod]
    [DataRow("2.16.840.1.101.3.4.2.1", DisplayName = "a bare object identifier is not the required form")]
    [DataRow("urn:oid:1.3.14.3.2.26", DisplayName = "an algorithm this library does not compute")]
    [DataRow("http://www.w3.org/2001/04/xmlenc#sha256", DisplayName = "another identification scheme")]
    [DataRow("", DisplayName = "empty")]
    public async Task AnIdentifierNamingNoComputableHashFunctionIsRefused(string hashFunctionIdentifier)
    {
        using PreservationProfile profile = PreservationCapabilitySource.Profile(acceptedHashFunctions: [PkiDigestAlgorithm.Sha256]);

        using PreservationHashOnlySubmission submission = await PreservationCapabilitySource.SubmissionAsync(
            PkiDigestAlgorithm.Sha256,
            SignedDataObjects,
            hashFunctionIdentifier,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        PreservationHashOnlySubmissionReport report = PreservationHashOnlySubmissions.StateAcceptance(
            new PreservationHashOnlySubmissionContext { Submission = submission, Profile = profile });

        Assert.AreEqual(PreservationHashOnlySubmissionStatus.HashFunctionNotResolvable, report.Status);
        Assert.IsNull(report.HashFunction);
        Assert.IsEmpty(report.GoalTreatments);
    }


    /// <summary>
    /// A profile listing no accepted hash function does not allow hash-only submission at all, which is a
    /// different refusal from one that lists other functions.
    /// </summary>
    [TestMethod]
    public async Task AProfileListingNoAcceptedHashFunctionAllowsNoHashOnlySubmission()
    {
        using PreservationProfile profile = PreservationCapabilitySource.Profile();

        using PreservationHashOnlySubmission submission = await PreservationCapabilitySource.SubmissionAsync(
            PkiDigestAlgorithm.Sha256,
            SignedDataObjects,
            hashFunctionIdentifier: null,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        PreservationHashOnlySubmissionReport report = PreservationHashOnlySubmissions.StateAcceptance(
            new PreservationHashOnlySubmissionContext { Submission = submission, Profile = profile });

        Assert.AreEqual(PreservationHashOnlySubmissionStatus.ProfileStatesNoAcceptedHashFunction, report.Status);
        Assert.IsEmpty(report.AcceptedHashFunctions);
        Assert.Contains("OVR-9.3-06", report.Reason!);
    }


    /// <summary>
    /// A profile announcing no preservation of digital signatures is not the case these requirements govern —
    /// their tags say so — and a submission under it is refused rather than quietly accepted.
    /// </summary>
    [TestMethod]
    public async Task AProfileWithNoDigitalSignatureGoalIsNotTheCaseTheseRequirementsGovern()
    {
        using PreservationProfile profile = PreservationCapabilitySource.Profile(
            goals: [PreservationWellKnown.GeneralDataGoal],
            acceptedHashFunctions: [PkiDigestAlgorithm.Sha256]);

        using PreservationHashOnlySubmission submission = await PreservationCapabilitySource.SubmissionAsync(
            PkiDigestAlgorithm.Sha256,
            SignedDataObjects,
            hashFunctionIdentifier: null,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        PreservationHashOnlySubmissionReport report = PreservationHashOnlySubmissions.StateAcceptance(
            new PreservationHashOnlySubmissionContext { Submission = submission, Profile = profile });

        Assert.AreEqual(PreservationHashOnlySubmissionStatus.ProfileDoesNotPreserveDigitalSignatures, report.Status);
        Assert.IsEmpty(report.GoalTreatments);

        //A profile announcing both goals is governed by them.
        using PreservationProfile bothGoals = PreservationCapabilitySource.Profile(
            goals: [PreservationWellKnown.GeneralDataGoal, PreservationWellKnown.DigitalSignatureGoal],
            acceptedHashFunctions: [PkiDigestAlgorithm.Sha256]);

        Assert.AreEqual(
            PreservationHashOnlySubmissionStatus.Accepted,
            PreservationHashOnlySubmissions.StateAcceptance(
                new PreservationHashOnlySubmissionContext { Submission = submission, Profile = bothGoals }).Status);
    }


    /// <summary>A submission stating no hash value has nothing standing in for the signed data and is refused.</summary>
    [TestMethod]
    public async Task ASubmissionStatingNoHashValueIsRefused()
    {
        using PreservationProfile profile = PreservationCapabilitySource.Profile(acceptedHashFunctions: [PkiDigestAlgorithm.Sha256]);

        using PreservationHashOnlySubmission submission = await PreservationCapabilitySource.SubmissionAsync(
            PkiDigestAlgorithm.Sha256,
            [],
            hashFunctionIdentifier: null,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        PreservationHashOnlySubmissionReport report = PreservationHashOnlySubmissions.StateAcceptance(
            new PreservationHashOnlySubmissionContext { Submission = submission, Profile = profile });

        Assert.AreEqual(PreservationHashOnlySubmissionStatus.NoHashValueStated, report.Status);
        Assert.IsEmpty(report.GoalTreatments);
    }


    /// <summary>
    /// A submission owns every carrier it was built with and returns all of them when it is disposed, which a
    /// counting pool makes an assertion rather than a claim.
    /// </summary>
    [TestMethod]
    public async Task ASubmissionReturnsEveryCarrierItOwns()
    {
        using MeteredHousePool pool = new();

        PreservationHashOnlySubmission submission = await PreservationCapabilitySource.SubmissionAsync(
            PkiDigestAlgorithm.Sha256,
            SignedDataObjects,
            hashFunctionIdentifier: null,
            pool.Pool,
            TestContext.CancellationToken);

        //Two hash values and the detached signature's payload are what the submission holds; whatever the digest
        //seam rented and gave back on the way is already back, which is why the outstanding count is the claim
        //rather than the rented count.
        Assert.AreEqual(SignedDataObjects.Length + 1, pool.OutstandingCount);

        submission.Dispose();

        Assert.AreEqual(0, pool.OutstandingCount);
        Assert.AreEqual(pool.RentedCount, pool.ReturnedCount);
    }


    /// <summary>
    /// Both entry points refuse a null argument, and every enumeration this part of the stage declares puts its
    /// zero on a value that means nothing was computed.
    /// </summary>
    [TestMethod]
    public void TheEntryPointsRefuseNullAndNoZeroValueReadsAsSuccess()
    {
        _ = Assert.ThrowsExactly<ArgumentNullException>(() => PreservationHashOnlySubmissions.AcceptedHashFunctions(null!));
        _ = Assert.ThrowsExactly<ArgumentNullException>(() => PreservationHashOnlySubmissions.StateAcceptance(null!));

        Assert.AreEqual(nameof(PreservationHashOnlySubmissionStatus.NotEvaluated), Enum.GetName(default(PreservationHashOnlySubmissionStatus)));
        Assert.AreEqual(nameof(PreservationSubmissionPart.NotStated), Enum.GetName(default(PreservationSubmissionPart)));
    }
}
