using Verifiable.Core.Assessment;
using Verifiable.Fido2;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="Fido2RegistrationChecks.CheckRegistrationTopOrigin"/>'s member-mismatch
/// branch: a present <c>topOrigin</c> that does not belong to a non-null
/// <see cref="RegistrationCeremonyInput.ExpectedTopOrigins"/> set.
/// </summary>
/// <remarks>
/// <see cref="Fido2RegistrationRulesTests"/> covers this rule's other two branches — a present
/// <c>topOrigin</c> with <see cref="RegistrationCeremonyInput.ExpectedTopOrigins"/> null (fails), and
/// a present <c>topOrigin</c> that is a member of the expected set (succeeds) — but never a present
/// <c>topOrigin</c> against a non-null expected set that does not contain it. Without this case, the
/// <c>ContainsOrdinal(...) ? Success : Failure</c> ternary could be replaced with a bare
/// <see cref="ClaimOutcome.Success"/> and every registration test would still pass. The assertion
/// side's structurally identical three-branch check already has a test for exactly this case
/// (<see cref="Fido2OriginPolicyTests.MismatchedTopOriginFails"/>), confirming the check itself is
/// sound and it is specifically the registration copy's coverage that was thin.
/// </remarks>
[TestClass]
internal sealed class Fido2RegistrationTopOriginRuleTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A present <c>topOrigin</c> that is not a member of a non-null, non-empty
    /// <see cref="RegistrationCeremonyInput.ExpectedTopOrigins"/> set fails
    /// <see cref="Fido2ClaimIds.Fido2RegistrationTopOrigin"/>.
    /// </summary>
    [TestMethod]
    public async Task TopOriginPresentAndAbsentFromNonEmptyExpectedSetFailsTopOriginClaim()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataTopOrigin: Fido2CeremonyInputFactory.ValidTopOrigin,
            expectedTopOrigins: new HashSet<string> { "https://a-different-embedder.example" });

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationTopOrigin, ClaimOutcome.Failure));
    }


    /// <summary>Runs <see cref="Fido2ValidationProfiles.RegistrationRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    /// <param name="input">The ceremony input to validate.</param>
    /// <returns>The generated <see cref="ClaimIssueResult"/>.</returns>
    private Task<ClaimIssueResult> IssueClaimsAsync(RegistrationCeremonyInput input)
    {
        var issuer = new ClaimIssuer<RegistrationCeremonyInput>("fido2-registration-top-origin-rule-test", Fido2ValidationProfiles.RegistrationRules());

        return issuer.GenerateClaimsAsync(input, "fido2-registration-top-origin-rule-test-correlation", TestContext.CancellationToken).AsTask();
    }


    /// <summary>
    /// Asserts that every claim in <paramref name="result"/> matching one of <paramref name="expectedOverrides"/>
    /// carries its given outcome, and every other claim is <see cref="ClaimOutcome.Success"/> (or
    /// <see cref="ClaimOutcome.NotApplicable"/> for the extension-outputs claim, which this file's
    /// inputs never populate) — the fail-closed idiom: flipping one axis must not silently let an
    /// unrelated claim also fail.
    /// </summary>
    /// <param name="result">The generated claim result to inspect.</param>
    /// <param name="expectedOverrides">The claim identifiers whose outcome differs from the acceptable default.</param>
    private static void AssertClaimOutcomes(ClaimIssueResult result, params (ClaimId ClaimId, ClaimOutcome Outcome)[] expectedOverrides)
    {
        foreach(Claim claim in result.Claims)
        {
            ClaimOutcome expected = claim.Id.Code == Fido2ClaimIds.Fido2RegistrationExtensionOutputs.Code
                ? ClaimOutcome.NotApplicable
                : ClaimOutcome.Success;

            foreach((ClaimId claimId, ClaimOutcome outcome) in expectedOverrides)
            {
                if(claim.Id.Code == claimId.Code)
                {
                    expected = outcome;

                    break;
                }
            }

            Assert.AreEqual(expected, claim.Outcome, $"Claim '{claim.Id}' outcome mismatch.");
        }
    }
}
