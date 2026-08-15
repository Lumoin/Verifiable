using System;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Which presence/cardinality outcome a hoisted row check reports — the arms
/// <see cref="XAdESRuleViolation"/>'s own <c>XAdESRowPresenceViolation</c>/<c>XAdESRowCardinalityViolation</c>
/// already distinguish, now format-neutral.
/// </summary>
public enum AdESRowCheckKind
{
    /// <summary>A row whose presence at the level is <see cref="AdESPresence.ShallBePresent"/> had zero occurrences.</summary>
    MissingRequired,

    /// <summary>A row whose presence at the level is <see cref="AdESPresence.ShallNotBePresent"/> had at least one occurrence.</summary>
    PresentButForbidden,

    /// <summary>One <see cref="AdESCardinality"/> statement for the row at the level was unsatisfied (cardinality checks only).</summary>
    CardinalityMismatch
}


/// <summary>
/// Projects a violated row to the caller's own closed-sum violation instance. Keyed, when a format needs it, off
/// <see cref="AdESTableRow.RequirementId"/> — the row's CANONICAL id, never a violation's own self-reported id
/// (which may legitimately differ; a pre-existing JAdES Service drift is one such case).
/// </summary>
/// <typeparam name="TViolation">The caller's own closed-sum violation type.</typeparam>
/// <param name="row">The row the finding is reported against.</param>
/// <param name="level">The baseline level the finding was evaluated at.</param>
/// <param name="kind">Which presence/cardinality outcome fired.</param>
/// <param name="cardinalityExpected">The unsatisfied cardinality statement, for <see cref="AdESRowCheckKind.CardinalityMismatch"/>; <see langword="null"/> for the two presence arms.</param>
/// <param name="actualCount">The wire occurrence count observed.</param>
/// <returns>The caller's own violation instance for this finding.</returns>
public delegate TViolation AdESRowFinding<out TViolation>(
    AdESTableRow row, AdESBaselineLevel level, AdESRowCheckKind kind, AdESCardinality? cardinalityExpected, int actualCount);


/// <summary>
/// The one presence/cardinality check every AdES baseline level table's rows are evaluated by — the
/// walk-collect-violations logic hoisted out of <c>XAdESLevelRules.CheckPresenceAndCardinality</c> so XAdES,
/// JAdES and CBAdES share exactly one definition of "how a row's presence/cardinality is judged at a level",
/// including the XA-6.3-t44 tolerant-floor carve-out. Per-row (the caller owns iteration and emission order): a
/// caller walks its own table in its own order, calling <see cref="CheckRow{TViolation}"/> once per row with
/// that row's own wire occurrence count — the caller's own sequence of calls IS the emission order, so the
/// engine itself never sorts or re-orders anything.
/// </summary>
public static class AdESLevelRuleEngine
{
    /// <summary>
    /// Evaluates <paramref name="row"/>'s presence, and (when <paramref name="includeCardinality"/>) cardinality,
    /// against <paramref name="occurrenceCount"/> at <paramref name="level"/>, appending one
    /// <typeparamref name="TViolation"/> — built by <paramref name="labelFinding"/> — per violation found to
    /// <paramref name="violations"/>.
    /// </summary>
    /// <typeparam name="TViolation">The caller's own closed-sum violation type.</typeparam>
    /// <param name="row">The table row to evaluate.</param>
    /// <param name="occurrenceCount">The row's wire occurrence count at this signature.</param>
    /// <param name="level">The baseline level to evaluate against.</param>
    /// <param name="includeCardinality">
    /// Whether an unsatisfied cardinality statement is also reported. XAdES-only today — neither
    /// <c>JAdESRuleViolation</c> nor <c>CBAdESRuleViolation</c> declares a cardinality violation type, so JAdES
    /// and CBAdES always pass <see langword="false"/> here, structurally forced rather than a policy choice.
    /// </param>
    /// <param name="labelFinding">Projects a fired check to the caller's own violation instance.</param>
    /// <param name="violations">The list findings are appended to, in the order this method discovers them.</param>
    /// <exception cref="ArgumentNullException"><paramref name="row"/>, <paramref name="labelFinding"/>, or <paramref name="violations"/> is <see langword="null"/>.</exception>
    public static void CheckRow<TViolation>(
        AdESTableRow row,
        int occurrenceCount,
        AdESBaselineLevel level,
        bool includeCardinality,
        AdESRowFinding<TViolation> labelFinding,
        List<TViolation> violations)
    {
        ArgumentNullException.ThrowIfNull(row);
        ArgumentNullException.ThrowIfNull(labelFinding);
        ArgumentNullException.ThrowIfNull(violations);

        AdESPresence presence = row.Presence.At(level);
        bool isPresenceViolated = presence switch
        {
            AdESPresence.ShallBePresent when occurrenceCount == 0 =>
                AddFinding(violations, labelFinding, row, level, AdESRowCheckKind.MissingRequired, occurrenceCount),
            AdESPresence.ShallNotBePresent when occurrenceCount > 0 =>
                AddFinding(violations, labelFinding, row, level, AdESRowCheckKind.PresentButForbidden, occurrenceCount),
            _ => false
        };

        if(isPresenceViolated || row.Cardinality is null || occurrenceCount == 0)
        {
            //A missing-mandatory row is already reported above; re-reporting it as a cardinality mismatch too
            //(count 0 against e.g. ExactlyOne) would state the same defect twice. A zero count otherwise
            //reaches this branch only on a row whose presence cell at this level does NOT require presence
            //(ShallNotBePresent or the "*" soft-negative) -- every row pairing a >=1 cardinality token
            //(ExactlyOne/OneOrMore/AtLeastTwo) with a level is ALSO ShallBePresent at that same level
            //throughout every source table, with exactly ONE documented exception: XA-6.3-t44 (ArchiveTimeStamp)
            //states cardinality OneOrMore level-invariant against a "*" soft-negative presence at B-B/B-T/B-LT --
            //Table 2's own design tolerates zero there (the floor only truly binds once B-LTA's ShallBePresent
            //applies), and THIS early return is what implements that tolerance. A registry-invariant test pins
            //this exact, single carve-out so a future row cannot introduce a second one silently.
            return;
        }

        if(!includeCardinality)
        {
            return;
        }

        IReadOnlyList<AdESCardinality> applicable = row.Cardinality.ValuesAt(level);
        for(int i = 0; i < applicable.Count; ++i)
        {
            if(!IsCardinalitySatisfied(applicable[i], occurrenceCount))
            {
                violations.Add(labelFinding(row, level, AdESRowCheckKind.CardinalityMismatch, applicable[i], occurrenceCount));
            }
        }
    }


    private static bool AddFinding<TViolation>(
        List<TViolation> violations,
        AdESRowFinding<TViolation> labelFinding,
        AdESTableRow row,
        AdESBaselineLevel level,
        AdESRowCheckKind kind,
        int actualCount)
    {
        violations.Add(labelFinding(row, level, kind, null, actualCount));

        return true;
    }


    private static bool IsCardinalitySatisfied(AdESCardinality cardinality, int count) => cardinality switch
    {
        AdESCardinality.ExactlyZero => count == 0,
        AdESCardinality.ExactlyOne => count == 1,
        AdESCardinality.ZeroOrOne => count <= 1,
        AdESCardinality.ZeroOrMore => true,
        AdESCardinality.OneOrMore => count >= 1,
        AdESCardinality.AtLeastTwo => count >= 2,
        _ => true
    };
}
