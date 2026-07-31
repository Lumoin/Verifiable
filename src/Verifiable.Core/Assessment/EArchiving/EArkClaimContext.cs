using System;
using System.Diagnostics;

namespace Verifiable.Core.Assessment.EArchiving;

/// <summary>
/// Why one E-ARK requirement's claim reached the outcome it did.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This is not a second conclusion vocabulary.</strong> The conclusion is
/// <see cref="ClaimOutcome"/>, unchanged and shared with every other claim this repository issues; the values
/// below say which of the several roads to an outcome a rule took. Two of them matter enough on their own to
/// be the reason this type exists: <see cref="ClaimOutcome.Inconclusive"/> is reached both by a package that
/// declined a SHOULD and by a rule that was never given the document it judges, and those are opposite
/// findings — the first is about the package, the second about the caller. Without the distinction a claim set
/// cannot be read; with it, the outcome stays the shipped enum and the distinction sits beside it.
/// </para>
/// <para>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised reason never reads as a requirement that
/// was met.
/// </para>
/// </remarks>
public enum EArkClaimReason
{
    /// <summary>No reason stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The requirement holds of the subject the rule was given.</summary>
    RequirementMet = 1,

    /// <summary>A MUST-level requirement does not hold. Reached with <see cref="ClaimOutcome.Failure"/>.</summary>
    MandatoryRequirementUnmet = 2,

    /// <summary>
    /// A SHOULD-level requirement does not hold. Reached with <see cref="ClaimOutcome.Inconclusive"/>: the
    /// specification permits the deviation, so the claim states what happened and leaves the decision to
    /// whoever assesses the claim set.
    /// </summary>
    RecommendedRequirementUnmet = 3,

    /// <summary>
    /// A MAY-level requirement's subject is absent, so the rule had nothing to judge. Reached with
    /// <see cref="ClaimOutcome.NotApplicable"/>.
    /// </summary>
    OptionalSubjectAbsent = 4,

    /// <summary>
    /// A conditional requirement's condition does not hold, so the requirement does not bind this package.
    /// Reached with <see cref="ClaimOutcome.NotApplicable"/>.
    /// </summary>
    ConditionNotTriggered = 5,

    /// <summary>
    /// The caller did not supply the document or the facts the rule judges, so nothing was decided. Reached
    /// with <see cref="ClaimOutcome.Inconclusive"/> — never with success, which would report a conformance the
    /// rule never established, and never with failure, which would report a package defect where the caller
    /// merely declined to parse something.
    /// </summary>
    SubjectNotSupplied = 6,

    /// <summary>
    /// The rule applied a documented interpretation of a defect in the source specification — a keyword outside
    /// the five the specification's own conformance section defines, or a requirement whose transcription
    /// contradicts its siblings. The interpretation is stated at the rule.
    /// </summary>
    InterpretationApplied = 7,

    /// <summary>
    /// A fixity value is stated under an algorithm this library will not treat as evidence of authenticity, and
    /// the deviation policy in force flags it rather than failing the package. Reached with
    /// <see cref="ClaimOutcome.Inconclusive"/> under the secure default, and with
    /// <see cref="ClaimOutcome.Failure"/> when the caller raised the floor.
    /// </summary>
    FixityAlgorithmFlagged = 8,

    /// <summary>A fixity value was recomputed and does not equal what the document states.</summary>
    FixityMismatch = 9,

    /// <summary>A reference names a resource the package does not hold, so it resolves to nothing.</summary>
    ReferenceUnresolved = 10,

    /// <summary>
    /// The requirement binds a repository or a service rather than a document, so a single package can never
    /// answer it. Reached with <see cref="ClaimOutcome.NotApplicable"/>, and allocated so that a matrix and a
    /// consuming graph can name the row rather than leave it silent.
    /// </summary>
    ServiceOperational = 11
}


/// <summary>
/// What one E-ARK requirement's claim says beyond its outcome: why the rule concluded, and what it concluded
/// about.
/// </summary>
/// <remarks>
/// <para>
/// Every claim <see cref="EArkValidationChecks"/> issues carries one of these. The claim identifier names the
/// requirement, the outcome names the conclusion, and this names the road between them — which is what lets a
/// consumer tell a package that declined a recommendation from a validation that was never given the document
/// to judge, without a second outcome enumeration.
/// </para>
/// <para>
/// <see cref="Subject"/> is a short, human-readable phrase naming what the rule looked at, in the
/// specification's own words where the specification has words for it — an element path, a folder name, a
/// representation label. It is diagnostic text and never a value a caller parses.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EArkClaimContext: ClaimContext
{
    /// <summary>
    /// Initialises a claim context.
    /// </summary>
    /// <param name="reason">Why the rule concluded as it did.</param>
    /// <param name="subject">A short phrase naming what the rule looked at.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="subject"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When <paramref name="reason"/> is <see cref="EArkClaimReason.NotEvaluated"/>, which is the value of an
    /// unset field and never a conclusion a rule reached.
    /// </exception>
    public EArkClaimContext(EArkClaimReason reason, string subject)
    {
        ArgumentNullException.ThrowIfNull(subject);

        if(reason == EArkClaimReason.NotEvaluated)
        {
            throw new ArgumentException(
                "A claim context states why a rule concluded, and a rule that concluded has a reason other than the unset one.",
                nameof(reason));
        }

        Reason = reason;
        Subject = subject;
    }


    /// <summary>Gets why the rule concluded as it did.</summary>
    public EArkClaimReason Reason { get; }

    /// <summary>Gets a short phrase naming what the rule looked at.</summary>
    public string Subject { get; }


    /// <summary>A short debugger string showing the reason and the subject.</summary>
    private string DebuggerDisplay => $"EArkClaimContext({Reason}, {Subject})";
}
