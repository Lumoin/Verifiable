using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the profile-content requirement of clause 6.4 and the evidence self-description
/// requirements of clauses 6.5 and 9.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see>, applied to the profile component and the self-description record this library
/// already ships.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Every item is taken away from a conformant profile one at a time.</strong> The alternative — a
/// hand-built profile per test — would leave every assertion depending on how that profile was built rather than
/// on the item under test, and would let a row quietly stop being checked.
/// </para>
/// <para>
/// <strong>The rows are asserted with their identifiers.</strong> A requirements matrix and the consuming
/// system's graph key on the strings the document itself uses, so the tests check the strings and not only the
/// enumeration members.
/// </para>
/// </remarks>
[TestClass]
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "A profile built by the capability source carries no extension, so it owns no pooled carrier; the ones that do are held in a using.")]
internal sealed class PreservationProfileConformanceTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = default!;


    /// <summary>
    /// The documentation object identifiers are the two clause 4.3.2 states, and the branch that includes Annex A
    /// is told apart from the one that does not.
    /// </summary>
    [TestMethod]
    public void TheDocumentationObjectIdentifiersAreTheTwoTheClauseStates()
    {
        Assert.AreEqual("0.4.0.19511.1.1", PreservationProfileWellKnown.ServicePolicyIdentifier);
        Assert.AreEqual("0.4.0.19511.1.2", PreservationProfileWellKnown.QualifiedServicePolicyIdentifier);

        Assert.IsTrue(PreservationProfileWellKnown.IsServicePolicyIdentifier(PreservationProfileWellKnown.ServicePolicyIdentifier));
        Assert.IsTrue(PreservationProfileWellKnown.IsServicePolicyIdentifier(PreservationProfileWellKnown.QualifiedServicePolicyIdentifier));
        Assert.IsFalse(PreservationProfileWellKnown.IsServicePolicyIdentifier("0.4.0.19511.1.3"));
        Assert.IsFalse(PreservationProfileWellKnown.IsServicePolicyIdentifier(null));
        Assert.IsFalse(PreservationProfileWellKnown.IsServicePolicyIdentifier(" 0.4.0.19511.1.1"));

        Assert.IsTrue(PreservationProfileWellKnown.IsQualifiedServicePolicyIdentifier(PreservationProfileWellKnown.QualifiedServicePolicyIdentifier));
        Assert.IsFalse(PreservationProfileWellKnown.IsQualifiedServicePolicyIdentifier(PreservationProfileWellKnown.ServicePolicyIdentifier));
    }


    /// <summary>
    /// Every item carries the requirement identifier the document itself gives it, in the document's own
    /// sub-item grammar, and no two items share one.
    /// </summary>
    [TestMethod]
    public void EveryItemCarriesTheDocumentsOwnRequirementIdentifier()
    {
        var expected = new Dictionary<PreservationProfileContentItem, string>
        {
            [PreservationProfileContentItem.UniqueIdentification] = "OVR-6.4-03",
            [PreservationProfileContentItem.Identifier] = "OVR-6.4-04 a)",
            [PreservationProfileContentItem.SupportedOperations] = "OVR-6.4-04 b)",
            [PreservationProfileContentItem.SupportedInputFormats] = "OVR-6.4-04 b)-a",
            [PreservationProfileContentItem.AdditionalOutputFormats] = "OVR-6.4-04 b)-b",
            [PreservationProfileContentItem.EvidencePolicyReference] = "OVR-6.4-04 c)-a",
            [PreservationProfileContentItem.SignatureValidationPolicyReference] = "OVR-6.4-04 c)-b",
            [PreservationProfileContentItem.ValidityPeriod] = "OVR-6.4-04 d)",
            [PreservationProfileContentItem.StorageModel] = "OVR-6.4-04 e)",
            [PreservationProfileContentItem.PreservationGoals] = "OVR-6.4-04 f)",
            [PreservationProfileContentItem.EvidenceFormats] = "OVR-6.4-04 g)",
            [PreservationProfileContentItem.Specification] = "OVR-6.4-04 h)",
            [PreservationProfileContentItem.Description] = "OVR-6.4-04 i)",
            [PreservationProfileContentItem.SchemeIdentifier] = "OVR-6.4-04 j)",
            [PreservationProfileContentItem.EvidenceRetentionPeriod] = "OVR-6.4-05",
            [PreservationProfileContentItem.ExpectedEvidenceDuration] = "OVR-6.4-06"
        };

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach(KeyValuePair<PreservationProfileContentItem, string> row in expected)
        {
            Assert.AreEqual(row.Value, PreservationProfileWellKnown.RequirementIdentifierOf(row.Key));
            Assert.IsTrue(seen.Add(row.Value), $"'{row.Value}' is used by more than one item.");
        }

        //Every declared item is covered above — the enumeration carries the sixteen plus its unset value — and
        //the unset value names nothing.
        Assert.HasCount(expected.Count + 1, Enum.GetValues<PreservationProfileContentItem>());
        Assert.AreEqual(string.Empty, PreservationProfileWellKnown.RequirementIdentifierOf(default));
        Assert.AreEqual(PreservationRequirementKeyword.NotStated, PreservationProfileWellKnown.KeywordOf(default));
    }


    /// <summary>
    /// The three items that are not obligations are the three the document states with <em>may</em> and
    /// <em>should</em>, and the two conditional ones are the two sub-items whose sentences carry a condition.
    /// </summary>
    [TestMethod]
    public void OnlyTheItemsTheDocumentSoftensAreSoftened()
    {
        Assert.AreEqual(PreservationRequirementKeyword.May, PreservationProfileWellKnown.KeywordOf(PreservationProfileContentItem.Specification));
        Assert.AreEqual(PreservationRequirementKeyword.May, PreservationProfileWellKnown.KeywordOf(PreservationProfileContentItem.SchemeIdentifier));
        Assert.AreEqual(PreservationRequirementKeyword.Should, PreservationProfileWellKnown.KeywordOf(PreservationProfileContentItem.ExpectedEvidenceDuration));
        Assert.AreEqual(PreservationRequirementKeyword.Shall, PreservationProfileWellKnown.KeywordOf(PreservationProfileContentItem.EvidenceRetentionPeriod));
        Assert.AreEqual(PreservationRequirementKeyword.Shall, PreservationProfileWellKnown.KeywordOf(PreservationProfileContentItem.Identifier));

        Assert.IsTrue(PreservationProfileWellKnown.IsConditional(PreservationProfileContentItem.AdditionalOutputFormats));
        Assert.IsTrue(PreservationProfileWellKnown.IsConditional(PreservationProfileContentItem.SignatureValidationPolicyReference));
        Assert.IsFalse(PreservationProfileWellKnown.IsConditional(PreservationProfileContentItem.Identifier));
    }


    /// <summary>
    /// The two storage-model-tagged items bind exactly the models their tags name, an unrecognised model admits
    /// neither, and every untagged item binds every profile.
    /// </summary>
    [TestMethod]
    [DataRow("WithStorage", false, false, DisplayName = "with storage: neither tagged item binds")]
    [DataRow("WithTemporaryStorage", true, true, DisplayName = "with temporary storage: both tagged items bind")]
    [DataRow("WithoutStorage", false, true, DisplayName = "without storage: only the expected evidence duration binds")]
    [DataRow("SomethingElse", false, false, DisplayName = "an unrecognised model admits neither")]
    public void TheStorageModelTagsBindTheModelsTheyName(string storageModel, bool retentionBinds, bool durationBinds)
    {
        Assert.AreEqual(retentionBinds, PreservationProfileWellKnown.AppliesUnderStorageModel(PreservationProfileContentItem.EvidenceRetentionPeriod, storageModel));
        Assert.AreEqual(durationBinds, PreservationProfileWellKnown.AppliesUnderStorageModel(PreservationProfileContentItem.ExpectedEvidenceDuration, storageModel));
        Assert.IsTrue(PreservationProfileWellKnown.AppliesUnderStorageModel(PreservationProfileContentItem.Identifier, storageModel));
    }


    /// <summary>
    /// A profile stating every item the clause requires of it is conformant, produces one row per item, and
    /// reports the two halves no profile can decide about itself.
    /// </summary>
    [TestMethod]
    public void AProfileStatingEveryItemIsConformant()
    {
        using PreservationProfile profile = PreservationCapabilitySource.Profile(
            goals: [PreservationWellKnown.GeneralDataGoal],
            policies: [new PreservationPolicyReference { PolicyType = PreservationWellKnown.PreservationEvidencePolicyType }]);

        PreservationProfileConformanceReport report = PreservationProfileConformance.State(profile);

        Assert.AreEqual(PreservationProfileConformanceStatus.Conformant, report.Status);
        Assert.HasCount(16, report.Items);

        //Uniqueness across a service's profiles is not decidable from one profile, and the row says so.
        PreservationProfileItemReport? unique = report.FindItem(PreservationProfileContentItem.UniqueIdentification);
        Assert.AreEqual(PreservationProfileItemOutcome.Stated, unique?.Outcome);
        Assert.IsNotNull(unique?.Detail);

        //A profile with no digital-signature goal owes no signature validation policy at all.
        Assert.AreEqual(
            PreservationProfileItemOutcome.NotApplicable,
            report.FindItem(PreservationProfileContentItem.SignatureValidationPolicyReference)?.Outcome);

        //The two storage-model-tagged rows do not bind a with-storage profile.
        Assert.AreEqual(PreservationProfileItemOutcome.NotApplicable, report.FindItem(PreservationProfileContentItem.EvidenceRetentionPeriod)?.Outcome);
        Assert.AreEqual(PreservationProfileItemOutcome.NotApplicable, report.FindItem(PreservationProfileContentItem.ExpectedEvidenceDuration)?.Outcome);

        //Judging the same profile twice answers the same thing: nothing here reads anything but the profile.
        Assert.AreEqual(report.Status, PreservationProfileConformance.State(profile).Status);
    }


    /// <summary>Each obligation taken away in turn makes the profile non-conformant, on that row and no other.</summary>
    [TestMethod]
    public void EveryObligationTakenAwayMakesTheProfileNonConformant()
    {
        //The identifier, which two rows read.
        using(PreservationProfile withoutIdentifier = PreservationCapabilitySource.Profile() with { ProfileIdentifier = string.Empty })
        {
            PreservationProfileConformanceReport report = PreservationProfileConformance.State(withoutIdentifier);
            Assert.AreEqual(PreservationProfileConformanceStatus.RequirementUnmet, report.Status);
            Assert.AreEqual(PreservationProfileItemOutcome.NotStated, report.FindItem(PreservationProfileContentItem.Identifier)?.Outcome);
            Assert.AreEqual(PreservationProfileItemOutcome.NotStated, report.FindItem(PreservationProfileContentItem.UniqueIdentification)?.Outcome);
        }

        //The operations.
        using(PreservationProfile withoutOperations = PreservationCapabilitySource.Profile() with { Operations = [] })
        {
            PreservationProfileConformanceReport report = PreservationProfileConformance.State(withoutOperations);
            Assert.AreEqual(PreservationProfileConformanceStatus.RequirementUnmet, report.Status);
            Assert.AreEqual(PreservationProfileItemOutcome.NotStated, report.FindItem(PreservationProfileContentItem.SupportedOperations)?.Outcome);

            //With no operation at all there is nothing to state an input format for, which is a different answer.
            Assert.AreEqual(PreservationProfileItemOutcome.NotApplicable, report.FindItem(PreservationProfileContentItem.SupportedInputFormats)?.Outcome);
        }

        //The evidence policy reference.
        using(PreservationProfile withoutPolicy = PreservationCapabilitySource.Profile(policies: []))
        {
            PreservationProfileConformanceReport report = PreservationProfileConformance.State(withoutPolicy);
            Assert.AreEqual(PreservationProfileConformanceStatus.RequirementUnmet, report.Status);
            Assert.AreEqual(PreservationProfileItemOutcome.NotStated, report.FindItem(PreservationProfileContentItem.EvidencePolicyReference)?.Outcome);
        }

        //The goals.
        using(PreservationProfile withoutGoals = PreservationCapabilitySource.Profile(goals: []))
        {
            PreservationProfileConformanceReport report = PreservationProfileConformance.State(withoutGoals);
            Assert.AreEqual(PreservationProfileConformanceStatus.RequirementUnmet, report.Status);
            Assert.AreEqual(PreservationProfileItemOutcome.NotStated, report.FindItem(PreservationProfileContentItem.PreservationGoals)?.Outcome);
        }

        //The description.
        using(PreservationProfile withoutDescription = PreservationCapabilitySource.Profile(descriptions: []))
        {
            PreservationProfileConformanceReport report = PreservationProfileConformance.State(withoutDescription);
            Assert.AreEqual(PreservationProfileConformanceStatus.RequirementUnmet, report.Status);
            Assert.AreEqual(PreservationProfileItemOutcome.NotStated, report.FindItem(PreservationProfileContentItem.Description)?.Outcome);
        }

        //The evidence formats.
        using(PreservationProfile withoutFormats = PreservationCapabilitySource.Profile() with { EvidenceFormats = [] })
        {
            PreservationProfileConformanceReport report = PreservationProfileConformance.State(withoutFormats);
            Assert.AreEqual(PreservationProfileConformanceStatus.RequirementUnmet, report.Status);
            Assert.AreEqual(PreservationProfileItemOutcome.NotStated, report.FindItem(PreservationProfileContentItem.EvidenceFormats)?.Outcome);
        }
    }


    /// <summary>A value the vocabulary does not name is unusable rather than merely absent, and says which value.</summary>
    [TestMethod]
    public void AValueTheVocabularyDoesNotNameIsUnusable()
    {
        using(PreservationProfile badModel = PreservationCapabilitySource.Profile(storageModel: "WithSomeStorage"))
        {
            PreservationProfileItemReport? row = PreservationProfileConformance.State(badModel).FindItem(PreservationProfileContentItem.StorageModel);
            Assert.AreEqual(PreservationProfileItemOutcome.Unusable, row?.Outcome);
            Assert.Contains("WithSomeStorage", row!.Detail!);
        }

        using(PreservationProfile badGoal = PreservationCapabilitySource.Profile(goals: ["http://uri.etsi.org/19512/goal/whatever"]))
        {
            PreservationProfileItemReport? row = PreservationProfileConformance.State(badGoal).FindItem(PreservationProfileContentItem.PreservationGoals);
            Assert.AreEqual(PreservationProfileItemOutcome.Unusable, row?.Outcome);
        }

        using(PreservationProfile badOperation = PreservationCapabilitySource.Profile() with
        {
            Operations = [new PreservationOperationDescriptor { Name = "PreserveEverything" }]
        })
        {
            PreservationProfileItemReport? row = PreservationProfileConformance.State(badOperation).FindItem(PreservationProfileContentItem.SupportedOperations);
            Assert.AreEqual(PreservationProfileItemOutcome.Unusable, row?.Outcome);
        }

        using(PreservationProfile blankDescription = PreservationCapabilitySource.Profile(descriptions: [new PreservationLocalizedText { Text = "   " }]))
        {
            PreservationProfileItemReport? row = PreservationProfileConformance.State(blankDescription).FindItem(PreservationProfileContentItem.Description);
            Assert.AreEqual(PreservationProfileItemOutcome.Unusable, row?.Outcome);
        }
    }


    /// <summary>A profile that ceases to be active before it becomes active states a period nothing can use.</summary>
    [TestMethod]
    public void AProfileThatEndsBeforeItBeginsStatesAnUnusablePeriod()
    {
        using PreservationProfile inverted = PreservationCapabilitySource.Profile(validUntil: TestClock.CanonicalEpoch.AddYears(-2));

        PreservationProfileConformanceReport report = PreservationProfileConformance.State(inverted);

        Assert.AreEqual(PreservationProfileConformanceStatus.RequirementUnmet, report.Status);
        Assert.AreEqual(PreservationProfileItemOutcome.Unusable, report.FindItem(PreservationProfileContentItem.ValidityPeriod)?.Outcome);
    }


    /// <summary>
    /// A profile announcing the preservation of digital signatures and referencing no signature validation policy
    /// cannot be judged from the profile alone, and an undecided item is not a pass.
    /// </summary>
    [TestMethod]
    public void APolicyWhoseConditionNoProfileCarriesIsUndecidedRatherThanConformant()
    {
        using PreservationProfile withoutValidationPolicy = PreservationCapabilitySource.Profile(
            goals: [PreservationWellKnown.DigitalSignatureGoal],
            policies: [new PreservationPolicyReference { PolicyType = PreservationWellKnown.PreservationEvidencePolicyType }]);

        PreservationProfileConformanceReport report = PreservationProfileConformance.State(withoutValidationPolicy);

        Assert.AreEqual(PreservationProfileConformanceStatus.Undecided, report.Status);
        PreservationProfileItemReport? row = report.FindItem(PreservationProfileContentItem.SignatureValidationPolicyReference);
        Assert.AreEqual(PreservationProfileItemOutcome.Undecidable, row?.Outcome);
        Assert.AreEqual(PreservationRequirementKeyword.Shall, row?.Keyword);

        //Referencing one settles it.
        using PreservationProfile withValidationPolicy = PreservationCapabilitySource.Profile(
            goals: [PreservationWellKnown.DigitalSignatureGoal],
            policies:
            [
                new PreservationPolicyReference { PolicyType = PreservationWellKnown.PreservationEvidencePolicyType },
                new PreservationPolicyReference { PolicyType = PreservationWellKnown.SignatureValidationPolicyType }
            ]);

        Assert.AreEqual(PreservationProfileConformanceStatus.Conformant, PreservationProfileConformance.State(withValidationPolicy).Status);
    }


    /// <summary>
    /// A temporary-storage profile owes the retention period and is recommended to state the expected evidence
    /// duration, and the two departures reach different conclusions — the difference between an obligation and a
    /// recommendation, on two rows of one clause.
    /// </summary>
    [TestMethod]
    public void ATemporaryStorageProfileOwesTheRetentionPeriodAndIsOnlyRecommendedTheDuration()
    {
        using(PreservationProfile withoutBoth = PreservationCapabilitySource.Profile(
            storageModel: PreservationWellKnown.WithTemporaryStorageModel,
            goals: [PreservationWellKnown.GeneralDataGoal]))
        {
            PreservationProfileConformanceReport report = PreservationProfileConformance.State(withoutBoth);
            Assert.AreEqual(PreservationProfileConformanceStatus.RequirementUnmet, report.Status);
            Assert.AreEqual(PreservationProfileItemOutcome.NotStated, report.FindItem(PreservationProfileContentItem.EvidenceRetentionPeriod)?.Outcome);
        }

        using(PreservationProfile withRetentionOnly = PreservationCapabilitySource.Profile(
            storageModel: PreservationWellKnown.WithTemporaryStorageModel,
            goals: [PreservationWellKnown.GeneralDataGoal],
            retentionPeriod: "P10Y"))
        {
            PreservationProfileConformanceReport report = PreservationProfileConformance.State(withRetentionOnly);
            Assert.AreEqual(PreservationProfileConformanceStatus.RecommendationUnmet, report.Status);
            Assert.AreEqual(PreservationProfileItemOutcome.Stated, report.FindItem(PreservationProfileContentItem.EvidenceRetentionPeriod)?.Outcome);
            Assert.AreEqual(PreservationProfileItemOutcome.NotStated, report.FindItem(PreservationProfileContentItem.ExpectedEvidenceDuration)?.Outcome);
        }

        using(PreservationProfile withBoth = PreservationCapabilitySource.Profile(
            storageModel: PreservationWellKnown.WithTemporaryStorageModel,
            goals: [PreservationWellKnown.GeneralDataGoal],
            retentionPeriod: "P10Y",
            expectedEvidenceDuration: "P30Y"))
        {
            Assert.AreEqual(PreservationProfileConformanceStatus.Conformant, PreservationProfileConformance.State(withBoth).Status);
        }
    }


    /// <summary>
    /// An operation that accepts submitted content and states no input format fails the sub-item, and one that
    /// accepts none is not asked about it.
    /// </summary>
    [TestMethod]
    public void OnlyAnOperationAcceptingSubmittedContentOwesAnInputFormat()
    {
        using(PreservationProfile withoutInputFormats = PreservationCapabilitySource.Profile() with
        {
            Operations = [new PreservationOperationDescriptor { Name = PreservationWellKnown.PreservePreservationObjectOperation }]
        })
        {
            PreservationProfileItemReport? row = PreservationProfileConformance.State(withoutInputFormats).FindItem(PreservationProfileContentItem.SupportedInputFormats);
            Assert.AreEqual(PreservationProfileItemOutcome.NotStated, row?.Outcome);
            Assert.Contains(PreservationWellKnown.PreservePreservationObjectOperation, row!.Detail!);
        }

        using(PreservationProfile retrievalOnly = PreservationCapabilitySource.Profile() with
        {
            Operations = [new PreservationOperationDescriptor { Name = PreservationWellKnown.RetrievePreservationObjectOperation }]
        })
        {
            PreservationProfileConformanceReport report = PreservationProfileConformance.State(retrievalOnly);
            Assert.AreEqual(PreservationProfileItemOutcome.NotApplicable, report.FindItem(PreservationProfileContentItem.SupportedInputFormats)?.Outcome);
            Assert.AreEqual(PreservationProfileItemOutcome.NotApplicable, report.FindItem(PreservationProfileContentItem.AdditionalOutputFormats)?.Outcome);
        }
    }


    /// <summary>
    /// The two permissions are not departures when they are absent, and stating an evidence format or a scheme
    /// outside the registered ones is reported beside the row rather than refused.
    /// </summary>
    [TestMethod]
    public void APermissionIsNotADepartureAndAnUnregisteredValueIsReportedNotRefused()
    {
        using(PreservationProfile withoutPermissions = PreservationCapabilitySource.Profile() with
        {
            Specifications = [],
            SchemeIdentifier = null
        })
        {
            PreservationProfileConformanceReport report = PreservationProfileConformance.State(withoutPermissions);
            Assert.AreEqual(PreservationProfileItemOutcome.NotApplicable, report.FindItem(PreservationProfileContentItem.Specification)?.Outcome);
            Assert.AreEqual(PreservationProfileItemOutcome.NotApplicable, report.FindItem(PreservationProfileContentItem.SchemeIdentifier)?.Outcome);
            Assert.AreEqual(PreservationProfileConformanceStatus.Conformant, report.Status);
        }

        using(PreservationProfile houseFormats = PreservationCapabilitySource.Profile() with
        {
            EvidenceFormats = [new PreservationFormatDescriptor { FormatId = "https://preservation.example.test/format/house" }],
            SchemeIdentifier = "https://preservation.example.test/scheme/house"
        })
        {
            PreservationProfileConformanceReport report = PreservationProfileConformance.State(houseFormats);
            PreservationProfileItemReport? formats = report.FindItem(PreservationProfileContentItem.EvidenceFormats);
            PreservationProfileItemReport? scheme = report.FindItem(PreservationProfileContentItem.SchemeIdentifier);

            Assert.AreEqual(PreservationProfileItemOutcome.Stated, formats?.Outcome);
            Assert.IsNotNull(formats?.Detail);
            Assert.AreEqual(PreservationProfileItemOutcome.Stated, scheme?.Outcome);
            Assert.IsNotNull(scheme?.Detail);
            Assert.AreEqual(PreservationProfileConformanceStatus.Conformant, report.Status);
        }
    }


    /// <summary>
    /// An evidence stating all three items the requirement lists describes itself, and whether a time assertion
    /// covers what it says is answered beside it rather than assumed.
    /// </summary>
    [TestMethod]
    [DataRow(true, DisplayName = "the self-description is covered by a time assertion")]
    [DataRow(false, DisplayName = "the self-description is not covered")]
    public void AnEvidenceStatingAllThreeItemsDescribesItself(bool isProtected)
    {
        using PreservationProfile profile = PreservationCapabilitySource.Profile();

        PreservationEvidenceSelfDescriptionReport report = PreservationProfileConformance.StateSelfDescription(
            PreservationCapabilitySource.ArtifactWithSelfDescription(
                PreservationCapabilitySource.ServiceIdentifier,
                PreservationCapabilitySource.EvidencePolicyLocation,
                PreservationCapabilitySource.ProfileIdentifier,
                isProtected),
            profile);

        Assert.AreEqual(PreservationEvidenceSelfDescriptionStatus.SelfDescribed, report.Status);
        Assert.IsTrue(report.StatesPreservationService);
        Assert.IsTrue(report.StatesEvidencePolicy);
        Assert.IsTrue(report.StatesPreservationProfile);
        Assert.AreEqual(isProtected, report.IsCryptographicallyProtected);
        Assert.IsNull(report.Disagreement);
    }


    /// <summary>An evidence stating some of the three is partly self-described, and which items is readable.</summary>
    [TestMethod]
    public void AnEvidenceStatingSomeItemsIsPartlySelfDescribed()
    {
        using PreservationProfile profile = PreservationCapabilitySource.Profile();

        PreservationEvidenceSelfDescriptionReport report = PreservationProfileConformance.StateSelfDescription(
            PreservationCapabilitySource.ArtifactWithSelfDescription(
                PreservationCapabilitySource.ServiceIdentifier,
                policyIdentifier: null,
                profileIdentifier: null,
                isProtected: false),
            profile);

        Assert.AreEqual(PreservationEvidenceSelfDescriptionStatus.PartlySelfDescribed, report.Status);
        Assert.IsTrue(report.StatesPreservationService);
        Assert.IsFalse(report.StatesEvidencePolicy);
        Assert.IsFalse(report.StatesPreservationProfile);
    }


    /// <summary>
    /// An artifact carrying no self-description at all is a different answer from one carrying an empty one, and
    /// neither reads as an evidence that described itself.
    /// </summary>
    [TestMethod]
    public void CarryingNoSelfDescriptionIsNotTheSameAsCarryingAnEmptyOne()
    {
        PreservationEvidenceSelfDescriptionReport absent = PreservationProfileConformance.StateSelfDescription(
            PreservationCapabilitySource.ArtifactWithoutSelfDescription(),
            profile: null);

        PreservationEvidenceSelfDescriptionReport empty = PreservationProfileConformance.StateSelfDescription(
            PreservationCapabilitySource.ArtifactWithSelfDescription(null, null, null, isProtected: false),
            profile: null);

        Assert.AreEqual(PreservationEvidenceSelfDescriptionStatus.NotSupplied, absent.Status);
        Assert.AreEqual(PreservationEvidenceSelfDescriptionStatus.NotSelfDescribed, empty.Status);
        Assert.IsFalse(absent.StatesPreservationProfile);
        Assert.IsFalse(empty.StatesPreservationProfile);
        Assert.AreEqual(nameof(PreservationEvidenceSelfDescriptionStatus.NotEvaluated), Enum.GetName(default(PreservationEvidenceSelfDescriptionStatus)));
        Assert.AreEqual(nameof(PreservationProfileItemOutcome.NotEvaluated), Enum.GetName(default(PreservationProfileItemOutcome)));
        Assert.AreEqual(nameof(PreservationProfileConformanceStatus.NotEvaluated), Enum.GetName(default(PreservationProfileConformanceStatus)));
    }


    /// <summary>
    /// An evidence naming a profile other than the one it is judged against asserts something that is not so, and
    /// that outranks every other reading of the same self-description.
    /// </summary>
    [TestMethod]
    public void AnEvidenceNamingAnotherProfileDisagreesWithIt()
    {
        using PreservationProfile profile = PreservationCapabilitySource.Profile();

        PreservationEvidenceSelfDescriptionReport report = PreservationProfileConformance.StateSelfDescription(
            PreservationCapabilitySource.ArtifactWithSelfDescription(
                PreservationCapabilitySource.ServiceIdentifier,
                PreservationCapabilitySource.EvidencePolicyLocation,
                "https://preservation.example.test/profile/capability/2",
                isProtected: true),
            profile);

        Assert.AreEqual(PreservationEvidenceSelfDescriptionStatus.DisagreesWithProfile, report.Status);
        Assert.Contains("capability/2", report.Disagreement!);

        //Judged against no profile at all, the same self-description is simply complete.
        Assert.AreEqual(
            PreservationEvidenceSelfDescriptionStatus.SelfDescribed,
            PreservationProfileConformance.StateSelfDescription(
                PreservationCapabilitySource.ArtifactWithSelfDescription(
                    PreservationCapabilitySource.ServiceIdentifier,
                    PreservationCapabilitySource.EvidencePolicyLocation,
                    "https://preservation.example.test/profile/capability/2",
                    isProtected: true),
                profile: null).Status);
    }


    /// <summary>
    /// An evidence naming another evidence policy disagrees, and a profile that references its policy without
    /// saying where it is gives nothing to disagree with — which is reported as agreement rather than as a
    /// finding this library cannot support.
    /// </summary>
    [TestMethod]
    public void APolicyDisagreementNeedsAProfileThatSaysWhereItsPolicyIs()
    {
        using PreservationProfile withLocation = PreservationCapabilitySource.Profile();
        using PreservationProfile withoutLocation = PreservationCapabilitySource.Profile(
            policies: [new PreservationPolicyReference { PolicyType = PreservationWellKnown.PreservationEvidencePolicyType }]);

        EArkEvidenceArtifactFacts artifact = PreservationCapabilitySource.ArtifactWithSelfDescription(
            PreservationCapabilitySource.ServiceIdentifier,
            "https://preservation.example.test/policy/evidence/2",
            PreservationCapabilitySource.ProfileIdentifier,
            isProtected: true);

        Assert.AreEqual(
            PreservationEvidenceSelfDescriptionStatus.DisagreesWithProfile,
            PreservationProfileConformance.StateSelfDescription(artifact, withLocation).Status);

        Assert.AreEqual(
            PreservationEvidenceSelfDescriptionStatus.SelfDescribed,
            PreservationProfileConformance.StateSelfDescription(artifact, withoutLocation).Status);
    }


    /// <summary>Both entry points refuse a null argument rather than answering something about nothing.</summary>
    [TestMethod]
    public void BothEntryPointsRefuseANullArgument()
    {
        _ = Assert.ThrowsExactly<ArgumentNullException>(() => PreservationProfileConformance.State(null!));
        _ = Assert.ThrowsExactly<ArgumentNullException>(() => PreservationProfileConformance.StateSelfDescription(null!, null));
    }
}
