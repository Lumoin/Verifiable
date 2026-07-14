using Verifiable.Core.Assessment;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="Fido2ValidationProfiles.RegistrationRules"/> and
/// <see cref="Fido2ValidationProfiles.AssertionRules"/>: asserts the complete <em>set</em> of
/// <see cref="ClaimId"/> codes each profile produces, independent of any ceremony input's validity.
/// </summary>
/// <remarks>
/// <para>
/// Every other rule-level test in this suite (<c>Fido2RegistrationRulesTests</c>,
/// <c>Fido2AssertionRulesTests</c>, <c>Fido2AssertionAtFlagTests</c>, and
/// <c>Fido2RegistrationVerifierTests</c>'s <c>AssertOnlyClaimFails</c>) walks
/// <see cref="ClaimIssueResult.Claims"/> and asserts the outcome of whichever claims are
/// <em>present</em>. None of them assert that a given claim is present at all: if a
/// <see cref="ClaimDelegate{TInput}"/> entry were deleted outright from
/// <see cref="Fido2ValidationProfiles.RegistrationRules"/> or
/// <see cref="Fido2ValidationProfiles.AssertionRules"/> — silently dropping an entire ceremony
/// check, including a security-relevant gate such as the cross-origin check or either user-presence
/// check — every existing outcome-shaped test would keep passing, because the deleted claim simply
/// never appears in <see cref="ClaimIssueResult.Claims"/> for the <c>foreach</c> to visit. This file
/// closes that gap directly: it inspects <see cref="ClaimDelegate{TInput}.ExpectedClaimIds"/> on the
/// rule lists themselves, with no ceremony input involved at all.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Fido2ValidationProfileCompletenessTests
{
    /// <summary>
    /// <see cref="Fido2ValidationProfiles.RegistrationRules"/> produces exactly the documented
    /// registration claim set: every <see cref="Fido2ClaimIds"/> member in the 1200-1219 registration
    /// sub-range that a static rule (as opposed to <see cref="Fido2RegistrationVerifier"/> itself, for
    /// <see cref="Fido2ClaimIds.Fido2RegistrationCredentialIdUnique"/> and
    /// <see cref="Fido2ClaimIds.Fido2RegistrationAttestationDowngraded"/>) is responsible for — plus
    /// the shared extension-outputs claim. Deleting any one rule from the list, or adding an
    /// undocumented one, fails this test with no ceremony input required.
    /// </summary>
    [TestMethod]
    public void RegistrationRulesProduceExactlyTheDocumentedClaimIdSet()
    {
        HashSet<int> expected =
        [
            Fido2ClaimIds.Fido2RegistrationClientDataType.Code,
            Fido2ClaimIds.Fido2RegistrationChallenge.Code,
            Fido2ClaimIds.Fido2RegistrationOrigin.Code,
            Fido2ClaimIds.Fido2RegistrationCrossOrigin.Code,
            Fido2ClaimIds.Fido2RegistrationTopOrigin.Code,
            Fido2ClaimIds.Fido2RegistrationRpIdHash.Code,
            Fido2ClaimIds.Fido2RegistrationUserPresent.Code,
            Fido2ClaimIds.Fido2RegistrationUserVerified.Code,
            Fido2ClaimIds.Fido2RegistrationBackupFlagsInvariant.Code,
            Fido2ClaimIds.Fido2RegistrationCredentialAlgorithm.Code,
            Fido2ClaimIds.Fido2RegistrationCredentialIdLength.Code,
            Fido2ClaimIds.Fido2RegistrationAttestationTrustworthy.Code,
            Fido2ClaimIds.Fido2RegistrationExtensionOutputs.Code
        ];

        IList<ClaimDelegate<RegistrationCeremonyInput>> rules = Fido2ValidationProfiles.RegistrationRules();
        HashSet<int> produced = [.. rules.SelectMany(rule => rule.ExpectedClaimIds).Select(id => id.Code)];

        Assert.HasCount(expected.Count, rules, "Every registration rule contributes exactly one claim ID in the current profile; a mismatch here means a rule declares more or fewer than one, or the profile carries an undetected duplicate.");
        Assert.IsTrue(expected.SetEquals(produced), $"Expected claim set {{{string.Join(", ", expected.Order())}}}, got {{{string.Join(", ", produced.Order())}}}.");
    }


    /// <summary>
    /// <see cref="Fido2ValidationProfiles.AssertionRules"/> produces exactly the documented assertion
    /// claim set: every <see cref="Fido2ClaimIds"/> member in the 1220-1239 assertion sub-range — all
    /// fifteen are owned by a static rule, unlike the registration side — plus the shared
    /// extension-outputs claim. Deleting any one rule from the list, or adding an undocumented one,
    /// fails this test with no ceremony input required.
    /// </summary>
    [TestMethod]
    public void AssertionRulesProduceExactlyTheDocumentedClaimIdSet()
    {
        HashSet<int> expected =
        [
            Fido2ClaimIds.Fido2AssertionClientDataType.Code,
            Fido2ClaimIds.Fido2AssertionChallenge.Code,
            Fido2ClaimIds.Fido2AssertionOrigin.Code,
            Fido2ClaimIds.Fido2AssertionCrossOrigin.Code,
            Fido2ClaimIds.Fido2AssertionTopOrigin.Code,
            Fido2ClaimIds.Fido2AssertionRpIdHash.Code,
            Fido2ClaimIds.Fido2AssertionUserPresent.Code,
            Fido2ClaimIds.Fido2AssertionUserVerified.Code,
            Fido2ClaimIds.Fido2AssertionBackupFlagsInvariant.Code,
            Fido2ClaimIds.Fido2AssertionNoAttestedCredentialData.Code,
            Fido2ClaimIds.Fido2AssertionAllowedCredentials.Code,
            Fido2ClaimIds.Fido2AssertionSignCountRegression.Code,
            Fido2ClaimIds.Fido2AssertionUvInitializedUpgrade.Code,
            Fido2ClaimIds.Fido2AssertionBackupStateConsistency.Code,
            Fido2ClaimIds.Fido2AssertionUserHandle.Code,
            Fido2ClaimIds.Fido2AssertionExtensionOutputs.Code
        ];

        IList<ClaimDelegate<AssertionCeremonyInput>> rules = Fido2ValidationProfiles.AssertionRules();
        HashSet<int> produced = [.. rules.SelectMany(rule => rule.ExpectedClaimIds).Select(id => id.Code)];

        Assert.HasCount(expected.Count, rules, "Every assertion rule contributes exactly one claim ID in the current profile; a mismatch here means a rule declares more or fewer than one, or the profile carries an undetected duplicate.");
        Assert.IsTrue(expected.SetEquals(produced), $"Expected claim set {{{string.Join(", ", expected.Order())}}}, got {{{string.Join(", ", produced.Order())}}}.");
    }
}
