using Verifiable.Core.Assessment;
using Verifiable.Fido2;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="Fido2AssertionChecks.CheckAssertionUserHandle"/>'s exact length boundary:
/// the 1-byte and 64-byte extremes WebAuthn L3 section 5.4.3 declares valid.
/// </summary>
/// <remarks>
/// <see cref="Fido2UserHandleRuleTests"/> covers the "one past the fence" rejections — an empty
/// (0-byte) and a 65-byte <c>response.userHandle</c> — but never the exact valid extremes of 1 byte
/// and 64 bytes. <see cref="UserHandle.Create"/> performs no length validation of its own by design,
/// so <see cref="Fido2AssertionChecks.CheckAssertionUserHandle"/> is the sole enforcement point for
/// this bound; an off-by-one mutation narrowing the accepted range (<c>&lt; 2 or &gt; 64</c>,
/// rejecting a valid 1-byte handle, or <c>&lt; 1 or &gt; 63</c>, rejecting a valid 64-byte handle)
/// would pass every existing test undetected.
/// </remarks>
[TestClass]
internal sealed class Fido2UserHandleBoundaryTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>A 1-byte <c>response.userHandle</c> — the minimum valid length — succeeds the user-handle claim when it matches the stored handle.</summary>
    [TestMethod]
    public async Task OneByteResponseUserHandleSucceeds()
    {
        byte[] oneByteHandle = [0x2a];

        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            responseUserHandle: oneByteHandle,
            storedUserHandle: oneByteHandle);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A 64-byte <c>response.userHandle</c> — the maximum valid length — succeeds the user-handle claim when it matches the stored handle.</summary>
    [TestMethod]
    public async Task SixtyFourByteResponseUserHandleSucceeds()
    {
        byte[] sixtyFourByteHandle = new byte[UserHandle.MaxLength];
        Array.Fill(sixtyFourByteHandle, (byte)0x2a);

        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            responseUserHandle: sixtyFourByteHandle,
            storedUserHandle: sixtyFourByteHandle);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>Runs <see cref="Fido2ValidationProfiles.AssertionRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    /// <param name="input">The ceremony input to validate.</param>
    /// <returns>The generated <see cref="ClaimIssueResult"/>.</returns>
    private Task<ClaimIssueResult> IssueClaimsAsync(AssertionCeremonyInput input)
    {
        var issuer = new ClaimIssuer<AssertionCeremonyInput>("fido2-user-handle-boundary-test", Fido2ValidationProfiles.AssertionRules());

        return issuer.GenerateClaimsAsync(input, "fido2-user-handle-boundary-test-correlation", TestContext.CancellationToken).AsTask();
    }


    /// <summary>
    /// Asserts that every claim in <paramref name="result"/> matching one of <paramref name="expectedOverrides"/>
    /// carries its given outcome, and every other claim is <see cref="ClaimOutcome.Success"/> — the fail-closed
    /// idiom: flipping one axis must not silently let an unrelated claim also fail.
    /// </summary>
    /// <param name="result">The generated claim result to inspect.</param>
    /// <param name="expectedOverrides">The claim identifiers whose outcome differs from <see cref="ClaimOutcome.Success"/>.</param>
    private static void AssertClaimOutcomes(ClaimIssueResult result, params (ClaimId ClaimId, ClaimOutcome Outcome)[] expectedOverrides)
    {
        foreach(Claim claim in result.Claims)
        {
            ClaimOutcome expected = claim.Id.Code == Fido2ClaimIds.Fido2AssertionExtensionOutputs.Code
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
