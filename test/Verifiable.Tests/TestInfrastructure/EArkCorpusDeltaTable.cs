using System;
using System.Collections.Generic;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// What changed between the edition of the Common Specification the reference corpus states its cases against
/// and the edition this library's rules are written against — the table the corpus sweep cites whenever the two
/// readings of one requirement differ.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why a table is needed at all.</strong> Every corpus case carries the specification version it was
/// written for, and those versions run from a draft of edition 2.0 to edition 2.2.0, while every rule this
/// library ships reads
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see>. A case whose
/// requirement was softened, retired or restated between the two therefore states an expected outcome that the
/// shipped rules cannot reach, and calling such a case green or red without saying why would make the whole
/// sweep unreadable.
/// </para>
/// <para>
/// <strong>Every row is verified against the specification family's OWN published catalogues, not against
/// prose.</strong> The reference material ships each published edition of the METS profile as its own document,
/// so <see cref="EArkProfileCatalogueSource"/> reads both editions and
/// <c>EArkCorpusDeltaTableTests</c> asserts each row below against them: a stated level change must really be
/// the two editions' two levels, a stated retirement must really be an identifier the later edition dropped, and
/// — the direction that keeps the table honest — the editions must carry no difference this table does not
/// state. The prose of this file is therefore a description of a machine-checked fact rather than an assertion
/// of one.
/// </para>
/// <para>
/// <strong>Numbering.</strong> Rows are named <c>D-1</c>… in the order they are stated, and a swept case that a
/// row affects cites the row by that name. The names are this table's own; the requirement identifiers are the
/// specification's.
/// </para>
/// </remarks>
internal static class EArkCorpusDeltaTable
{
    /// <summary>
    /// The edition the delta is measured from — the latest edition any corpus case states, and the one whose
    /// requirement levels the corpus's rule severities were written against.
    /// </summary>
    internal static string BaselineVersion { get; } = "2.1.0";

    /// <summary>The edition every rule this library ships reads.</summary>
    internal static string RuleVersion { get; } = "2.2.0";


    /// <summary>
    /// The delta rows, in the order they were established.
    /// </summary>
    internal static IReadOnlyList<EArkCorpusDeltaRow> Rows { get; } =
    [
        new EArkCorpusDeltaRow
        {
            Id = "D-1",
            RequirementId = "CSIP96",
            Kind = EArkCorpusDeltaKind.RequirementLevelSoftened,
            BaselineReading = "MUST",
            RuleReading = "SHOULD",
            Effect = "A package that does not satisfy it departs from a recommendation, so the shipped rule reaches Inconclusive where a rule reading the earlier edition would reach Failure. The corpus states the rule at ERROR severity while its own case cites edition 2.2.0, so the corpus severity was not carried through the change.",
            Evidence = "The two published catalogues state REQLEVEL MUST and REQLEVEL SHOULD for this identifier."
        },
        new EArkCorpusDeltaRow
        {
            Id = "D-2",
            RequirementId = "CSIP100",
            Kind = EArkCorpusDeltaKind.RequirementLevelSoftened,
            BaselineReading = "MUST",
            RuleReading = "SHOULD",
            Effect = "As D-1. The corpus case cites edition 2.0.4 and states the rule at ERROR severity.",
            Evidence = "The two published catalogues state REQLEVEL MUST and REQLEVEL SHOULD for this identifier."
        },
        new EArkCorpusDeltaRow
        {
            Id = "D-3",
            RequirementId = "CSIP104",
            Kind = EArkCorpusDeltaKind.RequirementLevelSoftened,
            BaselineReading = "MUST",
            RuleReading = "SHOULD",
            Effect = "As D-1. The corpus case cites edition 2.2.0 and states the rule at ERROR severity.",
            Evidence = "The two published catalogues state REQLEVEL MUST and REQLEVEL SHOULD for this identifier."
        },
        new EArkCorpusDeltaRow
        {
            Id = "D-4",
            RequirementId = "CSIP86",
            Kind = EArkCorpusDeltaKind.RequirementRetired,
            BaselineReading = "stated by neither published catalogue, and carried by the corpus as a requirement directory",
            RuleReading = "no requirement, and no claim identifier: this repository leaves the number permanently unallocated",
            Effect = "Every case of the directory is skipped as a retired requirement. Nothing this library ships can answer it, and answering it from a neighbouring rule would invent a requirement.",
            Evidence = "Neither published catalogue states the identifier; the corpus carries a directory for it."
        },
        new EArkCorpusDeltaRow
        {
            Id = "D-5",
            RequirementId = "CSIP87",
            Kind = EArkCorpusDeltaKind.RequirementRetired,
            BaselineReading = "stated by neither published catalogue, and carried by the corpus as a requirement directory",
            RuleReading = "no requirement, and no claim identifier: this repository leaves the number permanently unallocated",
            Effect = "As D-4.",
            Evidence = "Neither published catalogue states the identifier; the corpus carries a directory for it."
        },
        new EArkCorpusDeltaRow
        {
            Id = "D-6",
            RequirementId = "CSIP31",
            Kind = EArkCorpusDeltaKind.RequirementTextDiverged,
            BaselineReading = "the corpus case, which cites a draft of edition 2.0, states cardinality 0..n",
            RuleReading = "both published catalogues state cardinality 0..1",
            Effect = "The shipped rule reads the catalogue's cardinality. No case of the directory turns on the difference, because the packages it names exercise the presence of the section rather than its multiplicity.",
            Evidence = "The published catalogues agree with each other and disagree with the corpus case's own requirement text."
        },
        new EArkCorpusDeltaRow
        {
            Id = "D-7",
            RequirementId = "CSIP62",
            Kind = EArkCorpusDeltaKind.RequirementTextDiverged,
            BaselineReading = "the corpus case, which cites edition 2.0.4, states one element location",
            RuleReading = "both published catalogues state a wider location, admitting the value on the root element and a file group whose use merely begins with the representations label",
            Effect = "The shipped rule reads the catalogue's location — the union of the root element carrying the mixed value and a file group whose use begins with the representations label — and both disjuncts of the condition it states. The directory's rule 1 turns on the second disjunct: its package is not mixed and carries a bare representations group, so only that disjunct reaches it, and the rule reports the departure the corpus states rather than a condition nothing triggered.",
            Evidence = "The published catalogues agree with each other and disagree with the corpus case's own requirement text."
        },
        new EArkCorpusDeltaRow
        {
            Id = "D-8",
            RequirementId = "CSIPSTR2",
            Kind = EArkCorpusDeltaKind.RequirementWithoutCorpusCase,
            BaselineReading = "the folder-structure catalogue states it, and this repository allocates a claim identifier for it",
            RuleReading = "the shipped structural profile issues it like every other folder row",
            Effect = "Nothing to sweep: the corpus carries no requirement directory for this identifier. Recorded so the absence reads as a gap in the corpus rather than as a rule this library never wrote.",
            Evidence = "The corpus's structural directories run 1 and 3 to 16."
        },
        new EArkCorpusDeltaRow
        {
            Id = "D-9",
            RequirementId = "CSIP115",
            Kind = EArkCorpusDeltaKind.RequirementNumberNeverAllocated,
            BaselineReading = "stated by neither published catalogue",
            RuleReading = "no requirement, and no claim identifier",
            Effect = "Nothing to sweep, and nothing missing: the number was never allocated by any edition. Recorded so the gap in the numbering does not read as a transcription loss.",
            Evidence = "Neither published catalogue states the identifier, and the corpus carries no directory for it."
        }
    ];


    /// <summary>
    /// Finds the delta row that governs one requirement identifier.
    /// </summary>
    /// <param name="requirementId">The requirement identifier, as the specification spells it.</param>
    /// <returns>The row, or <see langword="null"/> when the two editions read the requirement alike.</returns>
    internal static EArkCorpusDeltaRow? Find(string requirementId)
    {
        for(int i = 0; i < Rows.Count; ++i)
        {
            if(string.Equals(Rows[i].RequirementId, requirementId, StringComparison.Ordinal))
            {
                return Rows[i];
            }
        }

        return null;
    }
}


/// <summary>
/// What kind of difference one delta row states between the corpus's edition of a requirement and the edition
/// the shipped rules read.
/// </summary>
/// <remarks>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised kind never reads as a difference that was
/// established.
/// </remarks>
internal enum EArkCorpusDeltaKind
{
    /// <summary>No difference stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The later edition states a weaker requirement level than the earlier one.</summary>
    RequirementLevelSoftened = 1,

    /// <summary>The later edition states no such requirement at all, and the corpus still carries cases for it.</summary>
    RequirementRetired = 2,

    /// <summary>
    /// The corpus case's own requirement text disagrees with what both published editions state — a location or
    /// a cardinality the corpus never carried through an earlier change.
    /// </summary>
    RequirementTextDiverged = 3,

    /// <summary>The specification states the requirement and the corpus carries no case for it.</summary>
    RequirementWithoutCorpusCase = 4,

    /// <summary>The number sits inside the numbering and was never allocated by any edition.</summary>
    RequirementNumberNeverAllocated = 5
}


/// <summary>
/// One row of the edition-delta table: which requirement it is about, how the two editions read it, and what
/// that does to a swept case.
/// </summary>
internal sealed record EArkCorpusDeltaRow
{
    /// <summary>Gets this table's own name for the row, which a swept case cites.</summary>
    public required string Id { get; init; }

    /// <summary>Gets the requirement identifier the row is about, as the specification spells it.</summary>
    public required string RequirementId { get; init; }

    /// <summary>Gets what kind of difference the row states.</summary>
    public required EArkCorpusDeltaKind Kind { get; init; }

    /// <summary>Gets how the edition the corpus states its cases against reads the requirement.</summary>
    public required string BaselineReading { get; init; }

    /// <summary>Gets how the edition the shipped rules read reads it.</summary>
    public required string RuleReading { get; init; }

    /// <summary>Gets what the difference does to a case the corpus states for this requirement.</summary>
    public required string Effect { get; init; }

    /// <summary>Gets what makes the row true, stated so a reader can check it against the material.</summary>
    public required string Evidence { get; init; }
}
