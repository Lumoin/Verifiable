using System.Collections.Generic;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Proofs of <see cref="AdESLevelRuleEngine.CheckRow{TViolation}"/> — the shared presence/cardinality/XA-6.3-t44
/// carve-out skeleton XAdES, JAdES and CBAdES level rules all evaluate a row through,
/// exercised directly against real <see cref="AdESTableRow"/> fixtures drawn from
/// <see cref="XAdESBaselineLevelTable"/> rather than an invented parallel row shape.
/// </summary>
[TestClass]
internal sealed class AdESLevelRuleEngineTests
{
    /// <summary>One <see cref="AdESLevelRuleEngine.CheckRow{TViolation}"/> finding, captured verbatim for assertion.</summary>
    private sealed record CapturedRowFinding(AdESTableRow Row, AdESBaselineLevel Level, AdESRowCheckKind Kind, AdESCardinality? CardinalityExpected, int ActualCount);


    private static CapturedRowFinding Capture(AdESTableRow row, AdESBaselineLevel level, AdESRowCheckKind kind, AdESCardinality? cardinalityExpected, int actualCount) =>
        new(row, level, kind, cardinalityExpected, actualCount);


    /// <summary>A <see cref="AdESPresence.ShallBePresent"/> row with zero occurrences reports exactly one <see cref="AdESRowCheckKind.MissingRequired"/> finding.</summary>
    /// <remarks><see cref="XAdESBaselineLevelTable.SigningTime"/> (XA-6.3-t05) is uniformly <see cref="AdESPresence.ShallBePresent"/>.</remarks>
    [TestMethod]
    public void ShallBePresentRowWithZeroOccurrencesReportsMissingRequired()
    {
        var violations = new List<CapturedRowFinding>();

        AdESLevelRuleEngine.CheckRow(XAdESBaselineLevelTable.SigningTime, occurrenceCount: 0, AdESBaselineLevel.BB, includeCardinality: true, Capture, violations);

        Assert.HasCount(1, violations, "A ShallBePresent row with zero occurrences reports exactly one finding.");
        Assert.Contains(f => f.Kind == AdESRowCheckKind.MissingRequired
            && ReferenceEquals(f.Row, XAdESBaselineLevelTable.SigningTime)
            && f.Level == AdESBaselineLevel.BB
            && f.ActualCount == 0
            && f.CardinalityExpected is null, violations);
    }


    /// <summary>A <see cref="AdESPresence.ShallNotBePresent"/> row with at least one occurrence reports exactly one <see cref="AdESRowCheckKind.PresentButForbidden"/> finding.</summary>
    /// <remarks><see cref="XAdESBaselineLevelTable.SigningCertificate"/> (XA-6.3-t07, the deprecated V1 row) is uniformly <see cref="AdESPresence.ShallNotBePresent"/>.</remarks>
    [TestMethod]
    public void ShallNotBePresentRowWithAnOccurrenceReportsPresentButForbidden()
    {
        var violations = new List<CapturedRowFinding>();

        AdESLevelRuleEngine.CheckRow(XAdESBaselineLevelTable.SigningCertificate, occurrenceCount: 1, AdESBaselineLevel.BLTA, includeCardinality: true, Capture, violations);

        Assert.HasCount(1, violations, "A ShallNotBePresent row with an occurrence reports exactly one finding.");
        Assert.Contains(f => f.Kind == AdESRowCheckKind.PresentButForbidden
            && ReferenceEquals(f.Row, XAdESBaselineLevelTable.SigningCertificate)
            && f.Level == AdESBaselineLevel.BLTA
            && f.ActualCount == 1, violations);
    }


    /// <summary>
    /// The XA-6.3-t44 carve-out: <see cref="XAdESBaselineLevelTable.ArchiveTimeStamp"/> states cardinality
    /// <see cref="AdESCardinality.OneOrMore"/> (a floor above zero) level-invariant, paired with a "*"
    /// soft-negative (non-<see cref="AdESPresence.ShallBePresent"/>) presence at B-B/B-T/B-LT. A zero occurrence
    /// count at one of those levels must report NO cardinality violation — the tolerant-floor early return.
    /// </summary>
    [TestMethod]
    public void ArchiveTimeStampCarveOutEmitsNoCardinalityViolationAtZeroCountBelowBLTA()
    {
        var violations = new List<CapturedRowFinding>();

        AdESLevelRuleEngine.CheckRow(XAdESBaselineLevelTable.ArchiveTimeStamp, occurrenceCount: 0, AdESBaselineLevel.BLT, includeCardinality: true, Capture, violations);

        Assert.IsEmpty(violations, "The t44 carve-out tolerates a zero count against the OneOrMore floor while presence is still the soft-negative '*' at B-LT.");
    }


    /// <summary><c>includeCardinality: false</c> suppresses every cardinality finding, even when a genuine mismatch is present.</summary>
    /// <remarks><see cref="XAdESBaselineLevelTable.SigningCertificateV2"/> (XA-6.3-t06) states <see cref="AdESCardinality.ExactlyOne"/>; two occurrences would fire a cardinality mismatch were cardinality checked.</remarks>
    [TestMethod]
    public void IncludeCardinalityFalseEmitsNoCardinalityFindings()
    {
        var violations = new List<CapturedRowFinding>();

        AdESLevelRuleEngine.CheckRow(XAdESBaselineLevelTable.SigningCertificateV2, occurrenceCount: 2, AdESBaselineLevel.BB, includeCardinality: false, Capture, violations);

        Assert.IsEmpty(violations, "SigningCertificateV2's ExactlyOne cardinality is violated by a count of 2, but includeCardinality: false must suppress the finding.");
    }


    /// <summary>
    /// A <c>labelFinding</c> delegate with no arm for the row it is given throws, and that exception propagates
    /// out of <see cref="AdESLevelRuleEngine.CheckRow{TViolation}"/> uncaught — the same throwing-default posture
    /// <c>JAdESLevelRules</c>' and <c>CBAdESLevelRules</c>' own row-keyed delegates use for an unrecognized
    /// <see cref="AdESTableRow.RequirementId"/>.
    /// </summary>
    [TestMethod]
    public void LabelFindingThrowingDefaultPropagatesOutOfCheckRow()
    {
        var violations = new List<string>();
        AdESRowFinding<string> throwingDefault = (row, level, kind, cardinalityExpected, actualCount) => row.RequirementId switch
        {
            "XA-6.3-t05" => "SigningTime",
            _ => throw new InvalidOperationException($"Unrecognized row '{row.RequirementId}'.")
        };

        Assert.ThrowsExactly<InvalidOperationException>(() =>
            AdESLevelRuleEngine.CheckRow(XAdESBaselineLevelTable.SigningCertificateV2, occurrenceCount: 0, AdESBaselineLevel.BB, includeCardinality: true, throwingDefault, violations));
    }
}
