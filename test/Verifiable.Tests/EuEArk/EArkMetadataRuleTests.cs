using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the metadata rule groups: the METS profile catalogue <c>CSIP1</c>…<c>CSIP119</c> of
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see>, and the
/// preservation-metadata catalogue <c>PM1</c>…<c>PM125</c> of
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see>.
/// </summary>
/// <remarks>
/// Each test states one departure from a conformant document and asserts that exactly the rows that departure
/// touches change. The four documented interpretations — the two rows whose keyword is undefined, the two rows
/// with no keyword at all, the transcription defect at the related-event identifier, and the environment rows
/// that bind only an entity describing an environment — each get a test of their own, because an interpretation
/// nobody can see in the claim set is an interpretation nobody can audit.
/// </remarks>
[TestClass]
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "A test states its one departure from a conformant document as a record copy, and a record copy shares every carrier of the instance it was copied from. Exactly one instance of each carrier set is disposed — the copy actually put under test, held in a using — and disposing the instance it was copied from as well would return the same rented memory twice.")]
internal sealed class EArkMetadataRuleTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The identifier the test issuer states as its own.</summary>
    private const string IssuerId = "eark-metadata-validator";

    /// <summary>The correlation identifier the test issuer carries through a run.</summary>
    private const string CorrelationId = "eark-metadata-validation";

    /// <summary>The time provider the issuer stamps its results with.</summary>
    private static FakeTimeProvider IssuerTime { get; } = new(EArkValidationSource.Instant);

    /// <summary>
    /// The content-information-type value a package states when the vocabulary does not name what it holds,
    /// which is what a package that is not <c>MIXED</c> states instead.
    /// </summary>
    private static string OtherInformationType { get; } = MetsWellKnown.OtherContentInformationType;

    /// <summary>The spelled-out form such a package states beside it, which <c>CSIP5</c> then asks for.</summary>
    private static string SpelledOutInformationType { get; } = "an information type specification of the archive's own";


    /// <summary>
    /// A manifest satisfying every MUST and every SHOULD of the METS profile catalogue fails nothing and
    /// leaves nothing undecided: the whole catalogue is answered from the parsed document alone.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    /// <remarks>
    /// Proves <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> CSIP8, CSIP34,
    /// CSIP45, CSIP46, CSIP47, CSIP48, CSIP49, CSIP50, CSIP51, CSIP52, CSIP53, CSIP54, CSIP55, CSIP61, CSIP63,
    /// CSIP73, CSIP74, CSIP75, CSIP91, CSIP92, CSIP96, CSIP116, CSIP100, CSIP118, CSIP104, CSIP119.
    /// </remarks>
    [TestMethod]
    public async Task AConformantManifestFailsNoMetsProfileRequirement()
    {
        using MetsDocument manifest = EArkValidationSource.ConformantManifest();

        ClaimIssueResult result = await RunMetsProfileAsync(ContextFor(manifest)).ConfigureAwait(false);

        Assert.AreEqual(0, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));
        Assert.AreEqual(0, EArkAssessors.CountReason(result, EArkClaimReason.SubjectNotSupplied));
        Assert.AreEqual(0, EArkAssessors.CountReason(result, EArkClaimReason.RecommendedRequirementUnmet));

        //One claim per catalogue row the six groups own, and not one more.
        Assert.HasCount(116, result.Claims);
    }


    /// <summary>
    /// The root-element rows read the four attributes they constrain: the package identifier and the profile
    /// are mandatory, and the two spelled-out forms bind only when the value they qualify says the vocabulary
    /// does not name what the package is.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    /// <remarks>
    /// Proves <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> CSIP1, CSIP2,
    /// CSIP4, CSIP5, CSIP6, csip-principle-2.2. Proves
    /// <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0</see> AIP-IDENTIFIER-ASSIGNED.
    /// </remarks>
    [TestMethod]
    public async Task TheRootElementRowsReadTheAttributesTheyConstrain()
    {
        MetsDocument conformant = EArkValidationSource.ConformantManifest();
        using MetsDocument named = new()
        {
            ObjectIdentifier = conformant.ObjectIdentifier,
            ContentCategory = "records",
            Profile = conformant.Profile,
            Header = conformant.Header,
            OtherContentCategory = null,
            ContentInformationType = "records",
            OtherContentInformationType = null,
            DescriptiveMetadataSections = conformant.DescriptiveMetadataSections,
            AdministrativeMetadata = conformant.AdministrativeMetadata,
            FileSection = conformant.FileSection,
            StructuralMaps = conformant.StructuralMaps,
        };

        ClaimIssueResult result = await RunMetsProfileAsync(ContextFor(named)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip1, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip2, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip3, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip5, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip6, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
    }


    /// <summary>
    /// A package that says the vocabulary does not name its content category, and then does not spell the
    /// category out, departs from the row that asks it to — a departure and not a failure, because the
    /// requirement catalogue of <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP
    /// v2.2.0</see> states <c>CSIP3</c> at <c>REQLEVEL="SHOULD"</c> however emphatically the requirement's
    /// own sentence words its consequent, and this library binds the outcome to the level the catalogue states.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    [TestMethod]
    public async Task AnUnspelledOtherContentCategoryDepartsFromItsOwnRow()
    {
        MetsDocument conformant = EArkValidationSource.ConformantManifest();
        using MetsDocument manifest = new()
        {
            ObjectIdentifier = conformant.ObjectIdentifier,
            ContentCategory = conformant.ContentCategory,
            Profile = conformant.Profile,
            Header = conformant.Header,
            OtherContentCategory = null,
            ContentInformationType = conformant.ContentInformationType,
            OtherContentInformationType = conformant.OtherContentInformationType,
            DescriptiveMetadataSections = conformant.DescriptiveMetadataSections,
            AdministrativeMetadata = conformant.AdministrativeMetadata,
            FileSection = conformant.FileSection,
            StructuralMaps = conformant.StructuralMaps,
        };

        ClaimIssueResult result = await RunMetsProfileAsync(ContextFor(manifest)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip3, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
        Assert.AreEqual(0, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));
    }


    /// <summary>
    /// A package that says the vocabulary does not name its content information type, and then does not spell
    /// that type out, states a permission it did not take rather than a requirement it broke: the catalogue
    /// states <c>CSIP5</c> at <c>REQLEVEL="MAY"</c>, and a package cannot violate a permission. The reason
    /// separates the two roads to <see cref="ClaimOutcome.NotApplicable"/> — a condition that never fired reads
    /// <see cref="EArkClaimReason.ConditionNotTriggered"/>, a permission left untaken reads
    /// <see cref="EArkClaimReason.OptionalSubjectAbsent"/> — so the claim set still says what happened.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    [TestMethod]
    public async Task AnUnspelledOtherContentInformationTypeStatesAPermissionItDidNotTake()
    {
        MetsDocument conformant = EArkValidationSource.ConformantManifest();
        using MetsDocument manifest = new()
        {
            ObjectIdentifier = conformant.ObjectIdentifier,
            ContentCategory = conformant.ContentCategory,
            Profile = conformant.Profile,
            Header = conformant.Header,
            OtherContentCategory = conformant.OtherContentCategory,
            ContentInformationType = MetsWellKnown.OtherContentInformationType,
            OtherContentInformationType = null,
            DescriptiveMetadataSections = conformant.DescriptiveMetadataSections,
            AdministrativeMetadata = conformant.AdministrativeMetadata,
            FileSection = conformant.FileSection,
            StructuralMaps = conformant.StructuralMaps,
        };

        ClaimIssueResult result = await RunMetsProfileAsync(ContextFor(manifest)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip5, ClaimOutcome.NotApplicable, EArkClaimReason.OptionalSubjectAbsent);
        Assert.AreEqual(0, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));
    }


    /// <summary>
    /// The header's creator stamp is judged as the one closed form it is: a manifest naming an agent whose
    /// role, type, other type, name and version note are not all as the catalogue fixes them fails each row
    /// that is wrong and no other.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    /// <remarks>
    /// Proves <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> CSIP117,
    /// CSIP7, CSIP9, CSIP10, CSIP11, CSIP12, CSIP13, CSIP14, CSIP15, CSIP16, csip-principle-2.1.
    /// </remarks>
    [TestMethod]
    public async Task AManifestWithoutTheCreatorStampFailsTheFiveRowsThatFixIt()
    {
        MetsDocument conformant = EArkValidationSource.ConformantManifest();
        using MetsDocument manifest = new()
        {
            ObjectIdentifier = conformant.ObjectIdentifier,
            ContentCategory = conformant.ContentCategory,
            Profile = conformant.Profile,
            Header = new()
            {
                CreateDate = conformant.Header.CreateDate,
                LastModificationDate = conformant.Header.LastModificationDate,
                OaisPackageType = conformant.Header.OaisPackageType,
                Agents = [],
            },
            OtherContentCategory = conformant.OtherContentCategory,
            ContentInformationType = conformant.ContentInformationType,
            OtherContentInformationType = conformant.OtherContentInformationType,
            DescriptiveMetadataSections = conformant.DescriptiveMetadataSections,
            AdministrativeMetadata = conformant.AdministrativeMetadata,
            FileSection = conformant.FileSection,
            StructuralMaps = conformant.StructuralMaps,
        };

        ClaimIssueResult result = await RunMetsProfileAsync(ContextFor(manifest)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip10, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip11, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip12, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip13, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip14, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip15, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip16, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);

        //The header itself and its two datetimes are untouched.
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip117, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip7, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip8, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
    }


    /// <summary>
    /// A manifest carrying no descriptive metadata at all deviates from the one recommendation that asks for
    /// it and leaves the thirteen rows that constrain a section with no subject — not with thirteen failures.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    /// <remarks>
    /// Proves <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> CSIP17,
    /// CSIP19, CSIP20, CSIP21, CSIP22, CSIP23, CSIP24, CSIP25, CSIP26, CSIP27, CSIP28.
    /// </remarks>
    [TestMethod]
    public async Task AManifestWithoutDescriptiveMetadataDeviatesOnceRatherThanFailingThirteenTimes()
    {
        MetsDocument conformant = EArkValidationSource.ConformantManifest();
        using MetsDocument manifest = new()
        {
            ObjectIdentifier = conformant.ObjectIdentifier,
            ContentCategory = conformant.ContentCategory,
            Profile = conformant.Profile,
            Header = conformant.Header,
            OtherContentCategory = conformant.OtherContentCategory,
            ContentInformationType = conformant.ContentInformationType,
            OtherContentInformationType = conformant.OtherContentInformationType,
            DescriptiveMetadataSections = [],
            AdministrativeMetadata = conformant.AdministrativeMetadata,
            FileSection = conformant.FileSection,
            StructuralMaps = conformant.StructuralMaps,
        };

        ClaimIssueResult result = await RunMetsProfileAsync(ContextFor(manifest)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip17, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip18, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip29, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip30, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        Assert.AreEqual(0, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));
    }


    /// <summary>
    /// A section identifier that is not a legal <c>NCName</c> fails its own row — the practical trap the
    /// specification itself calls out, a bare universally-unique identifier beginning with a digit.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    /// <remarks>
    /// Proves <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> CSIP18,
    /// csip-principle-2.5, csip-5.1-ncname.
    /// </remarks>
    [TestMethod]
    public async Task ABareUniversallyUniqueIdentifierIsNotALegalSectionIdentifier()
    {
        MetsDocument conformant = EArkValidationSource.ConformantManifest();
        MetsDescriptiveMetadataSection firstSection = conformant.DescriptiveMetadataSections[0];
        using MetsDocument manifest = new()
        {
            ObjectIdentifier = conformant.ObjectIdentifier,
            ContentCategory = conformant.ContentCategory,
            Profile = conformant.Profile,
            Header = conformant.Header,
            OtherContentCategory = conformant.OtherContentCategory,
            ContentInformationType = conformant.ContentInformationType,
            OtherContentInformationType = conformant.OtherContentInformationType,
            DescriptiveMetadataSections =
            [
                new MetsDescriptiveMetadataSection
                {
                    Id = "2e1f6a52-9f0b-4a34-9d5e-0e2b8f0f1c77",
                    Created = firstSection.Created,
                    Status = firstSection.Status,
                    Reference = firstSection.Reference,
                }
            ],
            AdministrativeMetadata = conformant.AdministrativeMetadata,
            FileSection = conformant.FileSection,
            StructuralMaps = conformant.StructuralMaps,
        };

        ClaimIssueResult result = await RunMetsProfileAsync(ContextFor(manifest)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip18, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
    }


    /// <summary>
    /// A file section missing one of the three mandatory file groups fails exactly that group's row, and the
    /// per-file rows keep answering about the files the other groups carry.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    /// <remarks>
    /// Proves <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> CSIP58,
    /// CSIP59, CSIP60, CSIP113, CSIP64, CSIP65, CSIP66, CSIP67, CSIP68, CSIP69, CSIP70, CSIP76, CSIP77, CSIP78,
    /// csip-filesec-three-groups.
    /// </remarks>
    [TestMethod]
    public async Task AFileSectionMissingOneMandatoryGroupFailsThatGroupsRowAlone()
    {
        MetsDocument conformant = EArkValidationSource.ConformantManifest();
        using MetsDocument manifest = new()
        {
            ObjectIdentifier = conformant.ObjectIdentifier,
            ContentCategory = conformant.ContentCategory,
            Profile = conformant.Profile,
            Header = conformant.Header,
            OtherContentCategory = conformant.OtherContentCategory,
            ContentInformationType = conformant.ContentInformationType,
            OtherContentInformationType = conformant.OtherContentInformationType,
            DescriptiveMetadataSections = conformant.DescriptiveMetadataSections,
            AdministrativeMetadata = conformant.AdministrativeMetadata,
            FileSection = new()
            {
                Id = conformant.FileSection!.Id,
                FileGroups = [conformant.FileSection!.FileGroups[0], conformant.FileSection!.FileGroups[2]],
            },
            StructuralMaps = conformant.StructuralMaps,
        };

        ClaimIssueResult result = await RunMetsProfileAsync(ContextFor(manifest)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip60, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip113, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip114, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip71, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        Assert.AreEqual(1, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));
    }


    /// <summary>
    /// The content-information-type row of a file group binds under the whole antecedent the catalogue states —
    /// the package-level value being <c>MIXED</c> <em>or</em> the file group describing a representation — so a
    /// package that is not mixed and states no value on its representations group departs from the
    /// recommendation instead of reading as a row nothing triggered.
    /// </summary>
    /// <returns>A task that completes when all four shapes have been validated.</returns>
    /// <remarks>
    /// <para>
    /// The catalogue states the antecedent as a disjunction — "when the element 'Content Information Type
    /// Specification' (<c>CSIP4</c>) has the value 'MIXED' or the file group describes a representation, then
    /// this element states the content information type specification used for the file group" — and then
    /// states the second disjunct again, more strongly, in a paragraph of its own: "when … the file group
    /// describes a representation with the <c>mets/fileSec/fileGrp/@USE</c> attribute value is starting with
    /// 'Representations', then this element must state the content information type specification used for the
    /// representation". Its location says the same: the union of the root attribute being <c>MIXED</c> and a
    /// file group whose use begins with the representations label.
    /// </para>
    /// <para>
    /// Reading only the first disjunct answered every non-mixed package carrying a bare representations group
    /// as not applicable, which is the one answer the catalogue does not admit for it. The four shapes below
    /// pin both halves of the disjunction and both ways of leaving it untriggered, so neither disjunct can be
    /// dropped again without a failure naming which.
    /// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0 CSIP62</see>.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async Task TheContentInformationTypeRowBindsOnARepresentationGroupOfAPackageThatIsNotMixed()
    {
        MetsDocument departingSource = EArkValidationSource.ConformantManifest();
        using MetsDocument departing = new()
        {
            ObjectIdentifier = departingSource.ObjectIdentifier,
            ContentCategory = departingSource.ContentCategory,
            Profile = departingSource.Profile,
            Header = departingSource.Header,
            OtherContentCategory = departingSource.OtherContentCategory,
            ContentInformationType = OtherInformationType,
            OtherContentInformationType = SpelledOutInformationType,
            DescriptiveMetadataSections = departingSource.DescriptiveMetadataSections,
            AdministrativeMetadata = departingSource.AdministrativeMetadata,
            FileSection = new()
            {
                Id = departingSource.FileSection!.Id,
                FileGroups = StatingRepresentationInformationType(departingSource.FileSection!.FileGroups, null),
            },
            StructuralMaps = departingSource.StructuralMaps,
        };

        ClaimIssueResult departingResult = await RunMetsProfileAsync(ContextFor(departing)).ConfigureAwait(false);

        //The representations file group the second disjunct is about really is in front of the rules.
        EArkStructuralRuleTests.AssertOutcome(departingResult, EArkClaimIds.Csip114, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(departingResult, EArkClaimIds.Csip62, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);

        MetsDocument statedSource = EArkValidationSource.ConformantManifest();
        using MetsDocument stated = new()
        {
            ObjectIdentifier = statedSource.ObjectIdentifier,
            ContentCategory = statedSource.ContentCategory,
            Profile = statedSource.Profile,
            Header = statedSource.Header,
            OtherContentCategory = statedSource.OtherContentCategory,
            ContentInformationType = OtherInformationType,
            OtherContentInformationType = SpelledOutInformationType,
            DescriptiveMetadataSections = statedSource.DescriptiveMetadataSections,
            AdministrativeMetadata = statedSource.AdministrativeMetadata,
            FileSection = new()
            {
                Id = statedSource.FileSection!.Id,
                FileGroups = StatingRepresentationInformationType(statedSource.FileSection!.FileGroups, "records"),
            },
            StructuralMaps = statedSource.StructuralMaps,
        };

        ClaimIssueResult statedResult = await RunMetsProfileAsync(ContextFor(stated)).ConfigureAwait(false);

        //Widening the antecedent does not turn a package that states the value into a departure.
        EArkStructuralRuleTests.AssertOutcome(statedResult, EArkClaimIds.Csip62, ClaimOutcome.Success, EArkClaimReason.RequirementMet);

        MetsDocument mixedSource = EArkValidationSource.ConformantManifest();
        using MetsDocument mixed = new()
        {
            ObjectIdentifier = mixedSource.ObjectIdentifier,
            ContentCategory = mixedSource.ContentCategory,
            Profile = mixedSource.Profile,
            Header = mixedSource.Header,
            OtherContentCategory = mixedSource.OtherContentCategory,
            ContentInformationType = mixedSource.ContentInformationType,
            OtherContentInformationType = mixedSource.OtherContentInformationType,
            DescriptiveMetadataSections = mixedSource.DescriptiveMetadataSections,
            AdministrativeMetadata = mixedSource.AdministrativeMetadata,
            FileSection = new()
            {
                Id = mixedSource.FileSection!.Id,
                FileGroups = StatingRepresentationInformationType(mixedSource.FileSection!.FileGroups, null),
            },
            StructuralMaps = mixedSource.StructuralMaps,
        };

        ClaimIssueResult mixedResult = await RunMetsProfileAsync(ContextFor(mixed)).ConfigureAwait(false);

        //The first disjunct still binds on its own, which is what the conformant fixture exercises.
        Assert.AreEqual(MetsWellKnown.MixedContentInformationType, mixed.ContentInformationType);
        EArkStructuralRuleTests.AssertOutcome(mixedResult, EArkClaimIds.Csip62, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);

        MetsDocument untriggeredSource = EArkValidationSource.ConformantManifest();
        using MetsDocument untriggered = new()
        {
            ObjectIdentifier = untriggeredSource.ObjectIdentifier,
            ContentCategory = untriggeredSource.ContentCategory,
            Profile = untriggeredSource.Profile,
            Header = untriggeredSource.Header,
            OtherContentCategory = untriggeredSource.OtherContentCategory,
            ContentInformationType = OtherInformationType,
            OtherContentInformationType = SpelledOutInformationType,
            DescriptiveMetadataSections = untriggeredSource.DescriptiveMetadataSections,
            AdministrativeMetadata = untriggeredSource.AdministrativeMetadata,
            FileSection = new()
            {
                Id = untriggeredSource.FileSection!.Id,
                FileGroups = [untriggeredSource.FileSection!.FileGroups[0], untriggeredSource.FileSection!.FileGroups[1]],
            },
            StructuralMaps = untriggeredSource.StructuralMaps,
        };

        ClaimIssueResult untriggeredResult = await RunMetsProfileAsync(ContextFor(untriggered)).ConfigureAwait(false);

        //Neither disjunct holds, and only then is the row one nothing triggered.
        EArkStructuralRuleTests.AssertOutcome(untriggeredResult, EArkClaimIds.Csip114, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(untriggeredResult, EArkClaimIds.Csip62, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);

        //Restates every file group with the representation groups' content-information-type value replaced,
        //which is the one attribute the four shapes differ in besides the package-level one.
        static List<MetsFileGroup> StatingRepresentationInformationType(IReadOnlyList<MetsFileGroup> groups, string? informationType)
        {
            var restated = new List<MetsFileGroup>(groups.Count);
            for(int i = 0; i < groups.Count; ++i)
            {
                MetsFileGroup group = groups[i];
                restated.Add(MetsWellKnown.IsRepresentationLabel(group.Use)
                    ? new MetsFileGroup
                    {
                        Id = group.Id,
                        Use = group.Use,
                        AdministrativeMetadataIds = group.AdministrativeMetadataIds,
                        ContentInformationType = informationType,
                        OtherContentInformationType = group.OtherContentInformationType,
                        Files = group.Files,
                    }
                    : group);
            }

            return restated;
        }
    }


    /// <summary>
    /// A file group that says the vocabulary does not name its content information type, and then does not spell
    /// that type out, states a permission it did not take rather than a requirement it broke: the requirement
    /// catalogue of <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> states
    /// <c>CSIP63</c> at <c>REQLEVEL="MAY"</c>, so a package cannot violate it whatever severity a validator
    /// reports it at, and the sweep disposes exactly these corpus packages on that ground.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    [TestMethod]
    public async Task AFileGroupsUnspelledOtherContentInformationTypeStatesAPermissionItDidNotTake()
    {
        MetsDocument source = EArkValidationSource.ConformantManifest();
        using MetsDocument manifest = new()
        {
            ObjectIdentifier = source.ObjectIdentifier,
            ContentCategory = source.ContentCategory,
            Profile = source.Profile,
            Header = source.Header,
            OtherContentCategory = source.OtherContentCategory,
            ContentInformationType = source.ContentInformationType,
            OtherContentInformationType = source.OtherContentInformationType,
            DescriptiveMetadataSections = source.DescriptiveMetadataSections,
            AdministrativeMetadata = source.AdministrativeMetadata,
            FileSection = new()
            {
                Id = source.FileSection!.Id,
                FileGroups = StatingOtherInformationType(source.FileSection!.FileGroups, spelledOut: null),
            },
            StructuralMaps = source.StructuralMaps,
        };

        ClaimIssueResult result = await RunMetsProfileAsync(ContextFor(manifest)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip63, ClaimOutcome.NotApplicable, EArkClaimReason.OptionalSubjectAbsent);

        MetsDocument spelledSource = EArkValidationSource.ConformantManifest();
        using MetsDocument spelled = new()
        {
            ObjectIdentifier = spelledSource.ObjectIdentifier,
            ContentCategory = spelledSource.ContentCategory,
            Profile = spelledSource.Profile,
            Header = spelledSource.Header,
            OtherContentCategory = spelledSource.OtherContentCategory,
            ContentInformationType = spelledSource.ContentInformationType,
            OtherContentInformationType = spelledSource.OtherContentInformationType,
            DescriptiveMetadataSections = spelledSource.DescriptiveMetadataSections,
            AdministrativeMetadata = spelledSource.AdministrativeMetadata,
            FileSection = new()
            {
                Id = spelledSource.FileSection!.Id,
                FileGroups = StatingOtherInformationType(spelledSource.FileSection!.FileGroups, SpelledOutInformationType),
            },
            StructuralMaps = spelledSource.StructuralMaps,
        };

        ClaimIssueResult spelledResult = await RunMetsProfileAsync(ContextFor(spelled)).ConfigureAwait(false);

        //A group that takes the permission still reads as having met the row, so the change is confined to the
        //one branch where the condition fired and the value is absent.
        EArkStructuralRuleTests.AssertOutcome(spelledResult, EArkClaimIds.Csip63, ClaimOutcome.Success, EArkClaimReason.RequirementMet);

        //Restates every representation file group with the two content-information-type attributes CSIP63's
        //condition and consequent are stated over.
        static List<MetsFileGroup> StatingOtherInformationType(IReadOnlyList<MetsFileGroup> groups, string? spelledOut)
        {
            var restated = new List<MetsFileGroup>(groups.Count);
            for(int i = 0; i < groups.Count; ++i)
            {
                MetsFileGroup group = groups[i];
                restated.Add(MetsWellKnown.IsRepresentationLabel(group.Use)
                    ? new MetsFileGroup
                    {
                        Id = group.Id,
                        Use = group.Use,
                        AdministrativeMetadataIds = group.AdministrativeMetadataIds,
                        ContentInformationType = OtherInformationType,
                        OtherContentInformationType = spelledOut,
                        Files = group.Files,
                    }
                    : group);
            }

            return restated;
        }
    }


    /// <summary>
    /// A manifest carrying no structural map labelled as the catalogue mandates reports the finding twice —
    /// once for the map's type and once for its label — and leaves the thirty-one rows about the map's
    /// contents with no subject rather than failing them all.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    /// <remarks>
    /// Proves <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> CSIP80,
    /// CSIP81, CSIP82, CSIP83, CSIP84, CSIP85, CSIP88, CSIP89, CSIP93, CSIP94, CSIP95, CSIP97, CSIP98, CSIP99,
    /// CSIP101, CSIP102, CSIP103.
    /// </remarks>
    [TestMethod]
    public async Task WithoutTheMandatedStructuralMapTheFindingIsReportedOnceRatherThanThirtyThreeTimes()
    {
        MetsDocument conformant = EArkValidationSource.ConformantManifest();
        using MetsDocument manifest = new()
        {
            ObjectIdentifier = conformant.ObjectIdentifier,
            ContentCategory = conformant.ContentCategory,
            Profile = conformant.Profile,
            Header = conformant.Header,
            OtherContentCategory = conformant.OtherContentCategory,
            ContentInformationType = conformant.ContentInformationType,
            OtherContentInformationType = conformant.OtherContentInformationType,
            DescriptiveMetadataSections = conformant.DescriptiveMetadataSections,
            AdministrativeMetadata = conformant.AdministrativeMetadata,
            FileSection = conformant.FileSection,
            StructuralMaps = [conformant.StructuralMaps[0] with { Label = "an implementer's own map" }],
        };

        ClaimIssueResult result = await RunMetsProfileAsync(ContextFor(manifest)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip80, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip81, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip82, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip83, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip112, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        Assert.AreEqual(2, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));
    }


    /// <summary>
    /// A representation division whose label does not take the form the catalogue fixes fails its own row,
    /// and so do the pointer rows when the pointer it carries is not one link of the package-to-representation
    /// chain.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    /// <remarks>
    /// Proves <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> CSIP106,
    /// CSIP108, CSIP109, CSIP110, CSIP111, CSIP112, csip-filesec-representation-group.
    /// </remarks>
    [TestMethod]
    public async Task ARepresentationDivisionWithoutItsPointerFailsThePointerRows()
    {
        MetsDocument conformant = EArkValidationSource.ConformantManifest();
        MetsDivision root = conformant.StructuralMaps[0].RootDivision;
        MetsDivision fifthDivision = root.Divisions[4];
        using MetsDocument manifest = new()
        {
            ObjectIdentifier = conformant.ObjectIdentifier,
            ContentCategory = conformant.ContentCategory,
            Profile = conformant.Profile,
            Header = conformant.Header,
            OtherContentCategory = conformant.OtherContentCategory,
            ContentInformationType = conformant.ContentInformationType,
            OtherContentInformationType = conformant.OtherContentInformationType,
            DescriptiveMetadataSections = conformant.DescriptiveMetadataSections,
            AdministrativeMetadata = conformant.AdministrativeMetadata,
            FileSection = conformant.FileSection,
            StructuralMaps =
            [
                conformant.StructuralMaps[0] with
                {
                    RootDivision = new()
                    {
                        Id = root.Id,
                        Label = root.Label,
                        AdministrativeMetadataIds = root.AdministrativeMetadataIds,
                        DescriptiveMetadataIds = root.DescriptiveMetadataIds,
                        FilePointers = root.FilePointers,
                        MetsPointers = root.MetsPointers,
                        Divisions =
                        [
                            root.Divisions[0], root.Divisions[1], root.Divisions[2], root.Divisions[3],
                            new()
                            {
                                Id = fifthDivision.Id,
                                Label = fifthDivision.Label,
                                AdministrativeMetadataIds = fifthDivision.AdministrativeMetadataIds,
                                DescriptiveMetadataIds = fifthDivision.DescriptiveMetadataIds,
                                FilePointers = fifthDivision.FilePointers,
                                MetsPointers = [],
                                Divisions = fifthDivision.Divisions,
                            }
                        ],
                    },
                }
            ],
        };

        ClaimIssueResult result = await RunMetsProfileAsync(ContextFor(manifest)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip105, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip107, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip109, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
    }


    /// <summary>
    /// A caller that parsed no manifest gets every one of the catalogue's rows reported as undecided for want
    /// of a subject, and no row reported as a package defect.
    /// </summary>
    /// <returns>A task that completes when the rules have run.</returns>
    [TestMethod]
    public async Task WithoutAManifestEveryMetsProfileRowSaysSoRatherThanFailing()
    {
        var context = new EArkValidationContext
        {
            EntryNames = [],
            CurrentTime = EArkValidationSource.Instant,
        };

        ClaimIssueResult result = await RunMetsProfileAsync(context).ConfigureAwait(false);

        Assert.HasCount(116, result.Claims);
        Assert.AreEqual(116, EArkAssessors.CountReason(result, EArkClaimReason.SubjectNotSupplied));
        Assert.AreEqual(0, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));
    }


    /// <summary>
    /// A preservation-metadata document satisfying every MUST and every SHOULD its entity groups state fails
    /// nothing, and the only rows left undecided are the three the shipped model carries no element for.
    /// </summary>
    /// <returns>A task that completes when the document has been validated.</returns>
    /// <remarks>
    /// Proves <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> PM3, PM4, PM5,
    /// PM15, PM16, PM17, PM18, PM21, PM22, PM23, PM24, PM27, PM29, PM30, PM31, PM32, PM33, PM36, PM37, PM38,
    /// PM40, PM41, PM44, PM45, PM47, PM48, PM49, PM50, PM51, PM52, PM56, PM57, PM58, PM59, PM60, PM63, PM69,
    /// PM70, PM73, PM74, PM75, PM76, PM77, PM81, PM84, PM86, PM93, PM94, PM95, PM102, PM106, PM112, PM116,
    /// PM120, PM122, PM124, PM125, PREMIS-FILE-FORMAT, PREMIS-ORIGINAL-NAME, PREMIS-STORAGE,
    /// PREMIS-RELATIONSHIP, premis-2.2.5-identifiers.
    /// </remarks>
    [TestMethod]
    public async Task AConformantPreservationMetadataDocumentFailsNothing()
    {
        using PremisDocument document = EArkValidationSource.ConformantPreservationMetadata();

        ClaimIssueResult result = await RunPreservationMetadataAsync(ContextFor(document)).ConfigureAwait(false);

        Assert.HasCount(125, result.Claims);
        Assert.AreEqual(0, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));

        //The three rows the model carries no element for, and no others.
        Assert.AreEqual(3, EArkAssessors.CountReason(result, EArkClaimReason.SubjectNotSupplied));
        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm36, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);
        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm49, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);
        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm50, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);
    }


    /// <summary>
    /// An object stating a category the vocabulary does not name fails the three rows that ask for one, at
    /// once — the category is a document-wide fact and the three groups each report it.
    /// </summary>
    /// <returns>A task that completes when the document has been validated.</returns>
    /// <remarks>
    /// Proves <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> PM2, PM14, PM28.
    /// </remarks>
    [TestMethod]
    public async Task AnObjectCategoryTheVocabularyDoesNotNameFailsTheThreeRowsThatAskForOne()
    {
        PremisDocument conformant = EArkValidationSource.ConformantPreservationMetadata();
        PremisObject firstObject = conformant.Objects[0];
        using PremisDocument document = new()
        {
            Version = conformant.Version,
            Objects =
            [
                new PremisObject
                {
                    Category = "a category of this archive's own",
                    Identifiers = firstObject.Identifiers,
                    SignificantProperties = firstObject.SignificantProperties,
                    Characteristics = firstObject.Characteristics,
                    OriginalName = firstObject.OriginalName,
                    Storage = firstObject.Storage,
                    Relationships = firstObject.Relationships,
                    RightsStatementIdentifiers = firstObject.RightsStatementIdentifiers,
                    EnvironmentFunctions = firstObject.EnvironmentFunctions,
                    EnvironmentDesignation = firstObject.EnvironmentDesignation,
                },
                conformant.Objects[1],
                conformant.Objects[2]
            ],
            Events = conformant.Events,
            Agents = conformant.Agents,
            RightsStatements = conformant.RightsStatements,
        };

        ClaimIssueResult result = await RunPreservationMetadataAsync(ContextFor(document)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm2, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm14, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm28, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
    }


    /// <summary>
    /// The two rows whose keyword is <c>COULD</c> — a fifth term the specification's own conformance section
    /// does not define — reach their outcome as a documented interpretation under both readings of the
    /// deviation policy, and never silently.
    /// </summary>
    /// <returns>A task that completes when both readings have run.</returns>
    /// <remarks>
    /// Proves <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> PM53, PM66.
    /// </remarks>
    [TestMethod]
    public async Task TheTwoUndefinedKeywordRowsReachTheirOutcomeAsAStatedInterpretation()
    {
        using PremisDocument document = EArkValidationSource.ConformantPreservationMetadata();

        //The default reading: the keyword is read as MAY, so a document that carries the element succeeds.
        ClaimIssueResult asOptional = await RunPreservationMetadataAsync(ContextFor(document)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(asOptional, PremisClaimIds.Pm53, ClaimOutcome.Success, EArkClaimReason.InterpretationApplied);
        EArkStructuralRuleTests.AssertOutcome(asOptional, PremisClaimIds.Pm66, ClaimOutcome.Success, EArkClaimReason.InterpretationApplied);

        //The stricter reading: the keyword is not read as any defined term, so neither row decides anything.
        ClaimIssueResult asUndefined = await RunPreservationMetadataAsync(ContextFor(document) with
        {
            Deviations = new EArkValidationDeviations { UndefinedKeywordReadsAsOptional = false },
        }).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(asUndefined, PremisClaimIds.Pm53, ClaimOutcome.Inconclusive, EArkClaimReason.InterpretationApplied);
        EArkStructuralRuleTests.AssertOutcome(asUndefined, PremisClaimIds.Pm66, ClaimOutcome.Inconclusive, EArkClaimReason.InterpretationApplied);

        //Neither reading turns an undefined keyword into a package defect.
        Assert.AreEqual(0, EArkAssessors.CountOutcome(asOptional, ClaimOutcome.Failure));
        Assert.AreEqual(0, EArkAssessors.CountOutcome(asUndefined, ClaimOutcome.Failure));
    }


    /// <summary>
    /// The two rows the catalogue states with a cardinality and no keyword at all reach their outcome as a
    /// documented interpretation: the cardinality is <c>0..n</c>, so they are read as optional.
    /// </summary>
    /// <returns>A task that completes when the document has been validated.</returns>
    /// <remarks>
    /// Proves <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> PM80, PM90.
    /// </remarks>
    [TestMethod]
    public async Task TheTwoRowsWithNoKeywordAreReadAtTheLevelTheirCardinalityGives()
    {
        using PremisDocument document = EArkValidationSource.ConformantPreservationMetadata();

        ClaimIssueResult withEvents = await RunPreservationMetadataAsync(ContextFor(document)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(withEvents, PremisClaimIds.Pm80, ClaimOutcome.Success, EArkClaimReason.InterpretationApplied);
        EArkStructuralRuleTests.AssertOutcome(withEvents, PremisClaimIds.Pm90, ClaimOutcome.Success, EArkClaimReason.InterpretationApplied);

        PremisDocument eventlessSource = EArkValidationSource.ConformantPreservationMetadata();
        using PremisDocument withoutEvents = new()
        {
            Version = eventlessSource.Version,
            Objects = eventlessSource.Objects,
            Events = [],
            Agents = eventlessSource.Agents,
            RightsStatements = eventlessSource.RightsStatements,
        };

        ClaimIssueResult none = await RunPreservationMetadataAsync(ContextFor(withoutEvents)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(none, PremisClaimIds.Pm80, ClaimOutcome.NotApplicable, EArkClaimReason.InterpretationApplied);
        EArkStructuralRuleTests.AssertOutcome(none, PremisClaimIds.Pm90, ClaimOutcome.NotApplicable, EArkClaimReason.InterpretationApplied);
        Assert.AreEqual(0, EArkAssessors.CountOutcome(none, ClaimOutcome.Failure));
    }


    /// <summary>
    /// The related-event identifier row carries its resolution of the catalogue's own transcription defect —
    /// the row names the type element with the related-object prefix while its sibling names the value element
    /// with the related-event one — as an interpretation rather than as a plain outcome.
    /// </summary>
    /// <returns>A task that completes when the document has been validated.</returns>
    /// <remarks>
    /// Proves <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> PM64.
    /// </remarks>
    [TestMethod]
    public async Task TheRelatedEventIdentifierRowCarriesItsTranscriptionResolution()
    {
        using PremisDocument document = EArkValidationSource.ConformantPreservationMetadata();

        ClaimIssueResult result = await RunPreservationMetadataAsync(ContextFor(document)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm64, ClaimOutcome.Success, EArkClaimReason.InterpretationApplied);
        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm65, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
    }


    /// <summary>
    /// The environment rows bind an intellectual entity that describes an environment and no other: an entity
    /// describing none leaves them with no subject, which is the reading the catalogue's own group heading
    /// gives and the only one under which an ordinary package is conformant.
    /// </summary>
    /// <returns>A task that completes when the document has been validated.</returns>
    /// <remarks>
    /// Proves <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> PM6, PM7, PM8,
    /// PM11, PM12, PM13.
    /// </remarks>
    [TestMethod]
    public async Task TheEnvironmentRowsBindOnlyAnEntityThatDescribesAnEnvironment()
    {
        PremisDocument conformant = EArkValidationSource.ConformantPreservationMetadata();
        PremisObject firstObject = conformant.Objects[0];
        using PremisDocument document = new()
        {
            Version = conformant.Version,
            Objects =
            [
                new PremisObject
                {
                    Category = firstObject.Category,
                    Identifiers = firstObject.Identifiers,
                    SignificantProperties = firstObject.SignificantProperties,
                    Characteristics = firstObject.Characteristics,
                    OriginalName = firstObject.OriginalName,
                    Storage = firstObject.Storage,
                    Relationships = firstObject.Relationships,
                    RightsStatementIdentifiers = firstObject.RightsStatementIdentifiers,
                    EnvironmentFunctions = [],
                    EnvironmentDesignation = null,
                },
                conformant.Objects[1],
                conformant.Objects[2]
            ],
            Events = conformant.Events,
            Agents = conformant.Agents,
            RightsStatements = conformant.RightsStatements,
        };

        ClaimIssueResult result = await RunPreservationMetadataAsync(ContextFor(document)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm3, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm6, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm9, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm10, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        Assert.AreEqual(0, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));
    }


    /// <summary>
    /// An entity that describes half an environment — a function without a designation — fails the row that
    /// asks for the other half, which is what makes the conditional reading above a rule rather than a
    /// loophole.
    /// </summary>
    /// <returns>A task that completes when the document has been validated.</returns>
    /// <remarks>
    /// Proves <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> PM9, PM10.
    /// </remarks>
    [TestMethod]
    public async Task AnEntityDescribingHalfAnEnvironmentFailsTheRowAskingForTheOtherHalf()
    {
        PremisDocument conformant = EArkValidationSource.ConformantPreservationMetadata();
        PremisObject firstObject = conformant.Objects[0];
        using PremisDocument document = new()
        {
            Version = conformant.Version,
            Objects =
            [
                new PremisObject
                {
                    Category = firstObject.Category,
                    Identifiers = firstObject.Identifiers,
                    SignificantProperties = firstObject.SignificantProperties,
                    Characteristics = firstObject.Characteristics,
                    OriginalName = firstObject.OriginalName,
                    Storage = firstObject.Storage,
                    Relationships = firstObject.Relationships,
                    RightsStatementIdentifiers = firstObject.RightsStatementIdentifiers,
                    EnvironmentFunctions = firstObject.EnvironmentFunctions,
                    EnvironmentDesignation = null,
                },
                conformant.Objects[1],
                conformant.Objects[2]
            ],
            Events = conformant.Events,
            Agents = conformant.Agents,
            RightsStatements = conformant.RightsStatements,
        };

        ClaimIssueResult result = await RunPreservationMetadataAsync(ContextFor(document)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm6, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm9, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
    }


    /// <summary>
    /// The four rights bases are alternatives: a statement resting on one of them leaves the other three's
    /// rows with no subject rather than unmet, which is what the catalogue's own predicate notation says.
    /// </summary>
    /// <returns>A task that completes when the document has been validated.</returns>
    /// <remarks>
    /// Proves <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> PM98, PM99,
    /// PM105, PM109, PM115, PREMIS-RIGHTS.
    /// </remarks>
    [TestMethod]
    public async Task TheFourRightsBasesAreAlternativesRatherThanFourObligations()
    {
        using PremisDocument document = EArkValidationSource.ConformantPreservationMetadata();

        ClaimIssueResult result = await RunPreservationMetadataAsync(ContextFor(document)).ConfigureAwait(false);

        //The statement rests on copyright, so the copyright rows answer and the other three bases do not.
        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm99, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm100, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm105, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm109, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm115, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
    }


    /// <summary>
    /// A document stating a version the vocabulary does not name fails the one row that fixes it, whatever
    /// else it carries.
    /// </summary>
    /// <returns>A task that completes when the document has been validated.</returns>
    /// <remarks>
    /// Proves <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> PM1,
    /// premis-6.1.1-root.
    /// </remarks>
    [TestMethod]
    public async Task ADocumentOfTheWrongVocabularyVersionFailsTheVersionRow()
    {
        PremisDocument conformant = EArkValidationSource.ConformantPreservationMetadata();
        using PremisDocument document = new()
        {
            Version = "2.2",
            Objects = conformant.Objects,
            Events = conformant.Events,
            Agents = conformant.Agents,
            RightsStatements = conformant.RightsStatements,
        };

        ClaimIssueResult result = await RunPreservationMetadataAsync(ContextFor(document)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, PremisClaimIds.Pm1, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
    }


    /// <summary>Builds a validation context over one parsed manifest.</summary>
    /// <param name="manifest">The package's own root manifest.</param>
    /// <returns>The context the rules run over.</returns>
    private static EArkValidationContext ContextFor(MetsDocument manifest) => new()
    {
        EntryNames = [],
        CurrentTime = EArkValidationSource.Instant,
        PackageManifest = manifest,
    };


    /// <summary>Builds a validation context over one parsed preservation-metadata document.</summary>
    /// <param name="document">The preservation-metadata document.</param>
    /// <returns>The context the rules run over.</returns>
    private static EArkValidationContext ContextFor(PremisDocument document) => new()
    {
        EntryNames = [],
        CurrentTime = EArkValidationSource.Instant,
        PreservationMetadata = [document],
    };


    /// <summary>Runs the METS profile rules over one context.</summary>
    /// <param name="context">The package validation is given.</param>
    /// <returns>What the issuer concluded.</returns>
    private Task<ClaimIssueResult> RunMetsProfileAsync(EArkValidationContext context) =>
        RunAsync(context, EArkValidationProfiles.CsipMetsProfileRules());


    /// <summary>Runs the preservation-metadata rules over one context.</summary>
    /// <param name="context">The package validation is given.</param>
    /// <returns>What the issuer concluded.</returns>
    private Task<ClaimIssueResult> RunPreservationMetadataAsync(EArkValidationContext context) =>
        RunAsync(context, EArkValidationProfiles.PreservationMetadataRules());


    /// <summary>Runs one profile over one context.</summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="rules">The rules to run.</param>
    /// <returns>What the issuer concluded.</returns>
    private async Task<ClaimIssueResult> RunAsync(
        EArkValidationContext context,
        IList<ClaimDelegate<EArkValidationContext>> rules)
    {
        var issuer = new ClaimIssuer<EArkValidationContext>(IssuerId, rules, IssuerTime);

        return await issuer.GenerateClaimsAsync(context, CorrelationId, TestContext.CancellationToken).ConfigureAwait(false);
    }
}
