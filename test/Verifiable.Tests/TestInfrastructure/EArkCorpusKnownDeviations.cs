using System;
using System.Collections.Generic;
using Verifiable.Core.Assessment;
using Verifiable.Core.Assessment.EArchiving;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Where the shipped rule lists and the reference corpus answer one requirement differently, and why — the
/// ledger the corpus sweep holds itself to instead of quietly passing or quietly failing those cases.
/// </summary>
/// <remarks>
/// <para>
/// <strong>What a row means.</strong> A row says: for this requirement and this rule of the corpus, the corpus
/// declares a package non-conformant (or conformant) and the shipped claim says something else, and this is the
/// exact something else it says. The sweep asserts that reading letter for letter, so the ledger is a statement
/// about behaviour rather than a licence to differ: a rule that starts answering something new fails the sweep
/// as loudly as a rule that starts answering nothing.
/// </para>
/// <para>
/// <strong>Both directions are enforced.</strong> A row that no longer describes a disagreement is stale and
/// fails the sweep, and a disagreement no row describes fails it too. The ledger can therefore only shrink by
/// someone deepening a rule, and can only grow by someone deciding to add a row.
/// </para>
/// <para>
/// <strong>What the categories are about.</strong> The shipped profiles were written from the requirement
/// catalogue of
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> — one claim per
/// catalogue row, at the level the catalogue states — and they judge a package's STRUCTURE against it. The
/// corpus's rules go further in places: they check that a value belongs to a controlled vocabulary, that a
/// stated size or checksum agrees with the file it describes, that an identifier resolves to the section it
/// names, that an element occurs at most once. Where this library performs the same check under one of its own
/// claims, the row names that claim and the sweep asserts it really failed — the violation is detected, under
/// another requirement's name. Where it performs no such check, the row says so, and the close report carries
/// it as follow-up work rather than as coverage.
/// </para>
/// </remarks>
internal static class EArkCorpusKnownDeviations
{
    /// <summary>
    /// The ledger, one group per kind of difference.
    /// </summary>
    internal static IReadOnlyList<EArkCorpusDeviationGroup> Groups { get; } =
    [
        new EArkCorpusDeviationGroup
        {
            Category = EArkCorpusDeviationCategory.DetectedByAHouseClaimInstead,
            ShippedOutcome = ClaimOutcome.Success,
            ShippedReason = EArkClaimReason.RequirementMet,
            Explanation = "The corpus rule checks a stated value against the file it describes. This library performs the same check, over every reference of the manifest at once, under a claim of its own — so the violation is detected and reported, under this library's own requirement rather than under the catalogue row's.",
            Members =
            [
                new EArkCorpusDeviationMember
                {
                    RequirementId = "CSIP43",
                    RuleId = "2",
                    DetectingClaimCode = 2_900_002,
                    DetectingClaimOutcome = ClaimOutcome.Failure,
                    DetectingClaimReason = EArkClaimReason.FixityMismatch
                },
                new EArkCorpusDeviationMember
                {
                    RequirementId = "CSIP56",
                    RuleId = "2",
                    DetectingClaimCode = 2_900_002,
                    DetectingClaimOutcome = ClaimOutcome.Failure,
                    DetectingClaimReason = EArkClaimReason.FixityMismatch
                },
                new EArkCorpusDeviationMember
                {
                    RequirementId = "CSIP38",
                    RuleId = "2",
                    DetectingClaimCode = 2_900_004,
                    DetectingClaimOutcome = ClaimOutcome.Failure,
                    DetectingClaimReason = EArkClaimReason.ReferenceUnresolved
                },
                new EArkCorpusDeviationMember
                {
                    RequirementId = "CSIP51",
                    RuleId = "2",
                    DetectingClaimCode = 2_900_004,
                    DetectingClaimOutcome = ClaimOutcome.Failure,
                    DetectingClaimReason = EArkClaimReason.ReferenceUnresolved
                }
            ]
        },
        new EArkCorpusDeviationGroup
        {
            Category = EArkCorpusDeviationCategory.FixityUnderAnAlgorithmThisLibraryWillNotCompute,
            ShippedOutcome = ClaimOutcome.Success,
            ShippedReason = EArkClaimReason.RequirementMet,
            Explanation = "The corpus package states the checksum the rule is about under an algorithm ruling R-5 refuses to treat as evidence of authenticity. This library therefore does not recompute it: the strength claim reports the algorithm as flagged and the recomputation claim reports that it was given nothing it could recompute from, so a wrong value under such an algorithm reads as an unusable fixity rather than as a mismatch. That is the secure default working as intended, and it is why the package is not silently passed.",
            Members =
            [
                new EArkCorpusDeviationMember
                {
                    RequirementId = "CSIP29",
                    RuleId = "2",
                    DetectingClaimCode = 2_900_003,
                    DetectingClaimOutcome = ClaimOutcome.Inconclusive,
                    DetectingClaimReason = EArkClaimReason.FixityAlgorithmFlagged
                },
                new EArkCorpusDeviationMember
                {
                    RequirementId = "CSIP71",
                    RuleId = "2",
                    DetectingClaimCode = 2_900_003,
                    DetectingClaimOutcome = ClaimOutcome.Inconclusive,
                    DetectingClaimReason = EArkClaimReason.FixityAlgorithmFlagged
                }
            ]
        },
        new EArkCorpusDeviationGroup
        {
            Category = EArkCorpusDeviationCategory.ValueMembershipNotChecked,
            ShippedOutcome = ClaimOutcome.Success,
            ShippedReason = EArkClaimReason.RequirementMet,
            Explanation = "The requirement obliges a value to be drawn from a controlled vocabulary or an external registry. The shipped rule states that the value is there and says nothing about which member it is, because the vocabularies are maintained documents this repository does not hold and a media-type registry is not a specification this wave transcribes.",
            Members =
            [
                new EArkCorpusDeviationMember { RequirementId = "CSIP2", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP4", RuleId = "3" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP20", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP26", RuleId = "3" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP34", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP40", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP47", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP53", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP62", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP64", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP68", RuleId = "2" }
            ]
        },
        new EArkCorpusDeviationGroup
        {
            Category = EArkCorpusDeviationCategory.ValueShapeNotChecked,
            ShippedOutcome = ClaimOutcome.Success,
            ShippedReason = EArkClaimReason.RequirementMet,
            Explanation = "The corpus rule constrains the shape of a value the shipped rule only requires to be present: a size in octets that has to agree with the file, a text content that has to be non-empty, a media type that has to stay under a length bound.",
            Members =
            [
                new EArkCorpusDeviationMember { RequirementId = "CSIP15", RuleId = "3" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP27", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP40", RuleId = "3" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP41", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP53", RuleId = "3" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP54", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP68", RuleId = "3" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP69", RuleId = "2" }
            ]
        },
        new EArkCorpusDeviationGroup
        {
            Category = EArkCorpusDeviationCategory.CardinalityNotChecked,
            ShippedOutcome = ClaimOutcome.Success,
            ShippedReason = EArkClaimReason.RequirementMet,
            Explanation = "The corpus rule turns the catalogue's cardinality into a check that an element occurs at most once. The shipped rule reads the catalogue row as a question about presence, so a document stating the particle twice satisfies it.",
            Members =
            [
                new EArkCorpusDeviationMember { RequirementId = "CSIP15", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP76", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP80", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP88", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP90", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP93", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP97", RuleId = "2" }
            ]
        },
        new EArkCorpusDeviationGroup
        {
            Category = EArkCorpusDeviationCategory.CrossReferenceNotResolved,
            ShippedOutcome = ClaimOutcome.Success,
            ShippedReason = EArkClaimReason.RequirementMet,
            Explanation = "The corpus rule follows an identifier from one section of the manifest to another — a file pointer to the file group it names, an administrative identifier list to the sections it lists, a file group's use to the folder it stands for. The shipped rule states that the pointer is there; this library resolves references to package entries under its own claim, and inside the document only where a rule of its own says so.",
            Members =
            [
                new EArkCorpusDeviationMember { RequirementId = "CSIP64", RuleId = "3" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP91", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP116", RuleId = "1" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP118", RuleId = "1" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP119", RuleId = "1" }
            ]
        },
        new EArkCorpusDeviationGroup
        {
            Category = EArkCorpusDeviationCategory.FolderContentNotCrossChecked,
            ShippedOutcome = ClaimOutcome.Success,
            ShippedReason = EArkClaimReason.RequirementMet,
            Explanation = "The corpus rule reads a section of the manifest as an obligation on the package tree: an administrative section present means there ought to be files in the preservation metadata folder. The shipped rule judges the manifest section itself, and the folder rows of the structural catalogue judge the tree, so neither states the implication between them.",
            Members =
            [
                new EArkCorpusDeviationMember { RequirementId = "CSIP31", RuleId = "2" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP32", RuleId = "2" }
            ]
        },
        new EArkCorpusDeviationGroup
        {
            Category = EArkCorpusDeviationCategory.ConditionalCompanionNotChecked,
            ShippedOutcome = ClaimOutcome.Success,
            ShippedReason = EArkClaimReason.RequirementMet,
            Explanation = "The corpus states, as a rule of the first requirement, an obligation the catalogue gives a requirement of its own: that the spelled-out form must exist and carry a value when the value says the vocabulary does not name what the package is. The shipped profile issues that obligation under its own catalogue row, so the first requirement's claim is met while its sibling's carries the finding.",
            Members =
            [
                new EArkCorpusDeviationMember { RequirementId = "CSIP2", RuleId = "3" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP2", RuleId = "4" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP4", RuleId = "4" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP4", RuleId = "5" }
            ]
        },
        new EArkCorpusDeviationGroup
        {
            Category = EArkCorpusDeviationCategory.ViolationInARepresentationManifest,
            ShippedOutcome = ClaimOutcome.Success,
            ShippedReason = EArkClaimReason.RequirementMet,
            Explanation = "The corpus package carries the violation in a representation's own manifest, and the requirement is conditional on which manifest is being read. The sweep hands the rules the package's root manifest, which satisfies the requirement, and the requirement's other branch is about a document the sweep did not put in front of them.",
            Members =
            [
                new EArkCorpusDeviationMember { RequirementId = "CSIP1", RuleId = "4" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP4", RuleId = "2" }
            ]
        },
        new EArkCorpusDeviationGroup
        {
            Category = EArkCorpusDeviationCategory.IdentifierNotComparedWithTheFolderName,
            ShippedOutcome = ClaimOutcome.Success,
            ShippedReason = EArkClaimReason.RequirementMet,
            Explanation = "The corpus rule compares the package identifier with the name of the folder the package sits in. The shipped rule judges the identifier itself; the folder-naming recommendation is a row of the structural catalogue, which the shipped structural profile issues from the snapshot's root-folder fact rather than from the manifest.",
            Members =
            [
                new EArkCorpusDeviationMember { RequirementId = "CSIP1", RuleId = "3" }
            ]
        },
        new EArkCorpusDeviationGroup
        {
            Category = EArkCorpusDeviationCategory.ConditionReadDiffers,
            ShippedOutcome = ClaimOutcome.NotApplicable,
            ShippedReason = EArkClaimReason.ConditionNotTriggered,
            Explanation = "The requirement binds under a condition, and the corpus package removes the very thing the condition is about — the division the label belongs to. The shipped rule then reports the condition as untriggered while the corpus expects the absent subject to be the violation. Which reading is right depends on whether the catalogue's condition is read over the document as a whole or over each occurrence, and the specification does not say.",
            Members =
            [
                new EArkCorpusDeviationMember { RequirementId = "CSIP90", RuleId = "1" }
            ]
        },
        new EArkCorpusDeviationGroup
        {
            Category = EArkCorpusDeviationCategory.CorpusPackageContradictsItsOwnDescription,
            ShippedOutcome = ClaimOutcome.Inconclusive,
            ShippedReason = EArkClaimReason.RecommendedRequirementUnmet,
            Explanation = "The corpus declares the package conformant to a rule its own package description says the package violates — a package built to have no descriptive metadata section at all, and one built to have that section with no reference in it, both flagged conformant to the rules that ask for exactly those. The shipped rule reports the departure, and the package really does carry the absence, which the sweep proves from the parsed manifest rather than from the description's wording.",
            Members =
            [
                new EArkCorpusDeviationMember { RequirementId = "CSIP17", RuleId = "1" },
                new EArkCorpusDeviationMember { RequirementId = "CSIP21", RuleId = "2" }
            ]
        }
    ];


    /// <summary>
    /// Finds the ledger group that covers one requirement's rule.
    /// </summary>
    /// <param name="requirementId">The requirement identifier the corpus case is keyed by.</param>
    /// <param name="ruleId">The rule's own identifier within its case.</param>
    /// <returns>The group and the member, or <see langword="null"/> when the ledger states nothing.</returns>
    internal static (EArkCorpusDeviationGroup Group, EArkCorpusDeviationMember Member)? Find(string requirementId, string ruleId)
    {
        for(int i = 0; i < Groups.Count; ++i)
        {
            IReadOnlyList<EArkCorpusDeviationMember> members = Groups[i].Members;
            for(int j = 0; j < members.Count; ++j)
            {
                if(string.Equals(members[j].RequirementId, requirementId, StringComparison.Ordinal)
                    && string.Equals(members[j].RuleId, ruleId, StringComparison.Ordinal))
                {
                    return (Groups[i], members[j]);
                }
            }
        }

        return null;
    }
}


/// <summary>
/// What kind of difference one ledger group states between the corpus's reading of a requirement and the
/// shipped rule's.
/// </summary>
/// <remarks>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised category never reads as a difference
/// somebody accounted for.
/// </remarks>
internal enum EArkCorpusDeviationCategory
{
    /// <summary>No category stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>This library performs the same check under a claim of its own, which the sweep asserts failed.</summary>
    DetectedByAHouseClaimInstead = 1,

    /// <summary>The value's membership in a controlled vocabulary or an external registry is not checked.</summary>
    ValueMembershipNotChecked = 2,

    /// <summary>The value's shape — its length, its emptiness, its agreement with a file — is not checked.</summary>
    ValueShapeNotChecked = 3,

    /// <summary>The catalogue's cardinality is read as a question about presence rather than about repetition.</summary>
    CardinalityNotChecked = 4,

    /// <summary>An identifier is not followed from one section of the manifest to another.</summary>
    CrossReferenceNotResolved = 5,

    /// <summary>A manifest section is not read as an obligation on the package tree.</summary>
    FolderContentNotCrossChecked = 6,

    /// <summary>The obligation the corpus states as a rule of this requirement is a catalogue row of its own.</summary>
    ConditionalCompanionNotChecked = 7,

    /// <summary>The corpus package carries the violation in a representation's own manifest.</summary>
    ViolationInARepresentationManifest = 8,

    /// <summary>The package identifier is not compared with the name of the folder the package sits in.</summary>
    IdentifierNotComparedWithTheFolderName = 9,

    /// <summary>The requirement's condition is read over the document where the corpus reads it over an occurrence.</summary>
    ConditionReadDiffers = 10,

    /// <summary>The corpus declares a package conformant to a rule its own description says it violates.</summary>
    CorpusPackageContradictsItsOwnDescription = 11,

    /// <summary>
    /// The stated fixity is under an algorithm this library refuses to compute, so a wrong value under it reads
    /// as an unusable fixity rather than as a mismatch.
    /// </summary>
    FixityUnderAnAlgorithmThisLibraryWillNotCompute = 12
}


/// <summary>
/// One kind of difference, with the reading the shipped rules give and the rules it covers.
/// </summary>
internal sealed record EArkCorpusDeviationGroup
{
    /// <summary>Gets what kind of difference the group states.</summary>
    public required EArkCorpusDeviationCategory Category { get; init; }

    /// <summary>Gets the outcome every covered case's claim really carries.</summary>
    public required ClaimOutcome ShippedOutcome { get; init; }

    /// <summary>Gets the reason every covered case's claim really carries.</summary>
    public required EArkClaimReason ShippedReason { get; init; }

    /// <summary>Gets why the two readings differ, in the specification's own terms.</summary>
    public required string Explanation { get; init; }

    /// <summary>Gets the corpus rules the group covers.</summary>
    public required IReadOnlyList<EArkCorpusDeviationMember> Members { get; init; }
}


/// <summary>
/// One corpus rule a ledger group covers.
/// </summary>
internal sealed record EArkCorpusDeviationMember
{
    /// <summary>Gets the requirement identifier the corpus case is keyed by.</summary>
    public required string RequirementId { get; init; }

    /// <summary>Gets the rule's own identifier within its case.</summary>
    public required string RuleId { get; init; }

    /// <summary>
    /// Gets the code of the claim under which this library detects the same violation, or zero when it detects
    /// it under none.
    /// </summary>
    /// <remarks>
    /// The codes are the ones <see cref="EArkClaimIds"/> allocates and documents as stable, written out here so
    /// the ledger reads as data rather than as a reference into a class it is asserted against.
    /// </remarks>
    public int DetectingClaimCode { get; init; }

    /// <summary>Gets the outcome that claim really carries, when the row names one.</summary>
    public ClaimOutcome? DetectingClaimOutcome { get; init; }

    /// <summary>Gets the reason that claim really carries, when the row names one.</summary>
    public EArkClaimReason? DetectingClaimReason { get; init; }
}
