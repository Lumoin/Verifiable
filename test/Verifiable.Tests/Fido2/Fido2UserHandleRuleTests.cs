using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Assessment;
using Verifiable.Fido2;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="Fido2AssertionChecks.CheckAssertionUserHandle"/>: drives the WebAuthn L3
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">section 7.2</see>, step 6
/// user-handle ownership check through a real <see cref="ClaimIssuer{TInput}"/>, on inputs built by
/// <see cref="Fido2CeremonyInputFactory.CreateValidAssertionInput"/>.
/// </summary>
[TestClass]
internal sealed class Fido2UserHandleRuleTests
{
    /// <summary>A user handle distinct from <see cref="Fido2CeremonyInputFactory.ValidUserHandle"/>, for the mismatch axis.</summary>
    private static byte[] OtherUserHandle { get; } = [0x01, 0x02, 0x03, 0x04, 0x05];

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>A present <c>response.userHandle</c> equal to the stored user handle succeeds the user-handle claim.</summary>
    [TestMethod]
    public async Task PresentAndMatchingSucceeds()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput();

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A present <c>response.userHandle</c> that does not equal the stored user handle fails the user-handle claim.</summary>
    [TestMethod]
    public async Task PresentAndMismatchedFailsUserHandleClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            storedUserHandle: OtherUserHandle);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionUserHandle, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A present <c>response.userHandle</c> with no stored user handle to compare against fails the user-handle claim: ownership cannot be confirmed.</summary>
    [TestMethod]
    public async Task PresentWithNoStoredHandleFailsUserHandleClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            omitStoredUserHandle: true);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionUserHandle, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>An empty <c>response.userHandle</c> fails the user-handle claim: WebAuthn L3 section 5.4.3 forbids an empty user handle.</summary>
    [TestMethod]
    public async Task EmptyResponseUserHandleFailsUserHandleClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            responseUserHandle: []);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionUserHandle, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A 65-byte <c>response.userHandle</c> fails the user-handle claim: WebAuthn L3 section 5.4.3 bounds a user handle to a maximum of 64 bytes.</summary>
    [TestMethod]
    public async Task SixtyFiveByteResponseUserHandleFailsUserHandleClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            responseUserHandle: new byte[UserHandle.MaxLength + 1]);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionUserHandle, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>
    /// An absent <c>response.userHandle</c> on the discoverable-credential path — no allowlist
    /// supplied — fails the user-handle claim: WebAuthn L3 section 7.2 step 6's second case
    /// requires a <c>userHandle</c> there.
    /// </summary>
    [TestMethod]
    public async Task AbsentResponseUserHandleOnDiscoverablePathFailsUserHandleClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            omitResponseUserHandle: true);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionUserHandle, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>
    /// An absent <c>response.userHandle</c> with an allowlist supplied does not apply the
    /// user-handle claim: WebAuthn L3 section 7.2 step 6's first case makes a <c>userHandle</c>
    /// optional once the relying party already identified the user via the allowlist.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId instances transfers to the ceremony input, which the using declaration disposes.")]
    public async Task AbsentResponseUserHandleWithAllowlistIsNotApplicable()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            omitResponseUserHandle: true,
            allowedCredentialIds: [CredentialId.Create(Fido2CeremonyInputFactory.ValidCredentialId, BaseMemoryPool.Shared)],
            credentialId: CredentialId.Create(Fido2CeremonyInputFactory.ValidCredentialId, BaseMemoryPool.Shared));

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionUserHandle, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>Runs <see cref="Fido2ValidationProfiles.AssertionRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    /// <param name="input">The ceremony input to validate.</param>
    /// <returns>The generated <see cref="ClaimIssueResult"/>.</returns>
    private Task<ClaimIssueResult> IssueClaimsAsync(AssertionCeremonyInput input)
    {
        var issuer = new ClaimIssuer<AssertionCeremonyInput>("fido2-user-handle-rule-test", Fido2ValidationProfiles.AssertionRules());

        return issuer.GenerateClaimsAsync(input, "fido2-user-handle-rule-test-correlation", TestContext.CancellationToken).AsTask();
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
            //Fido2AssertionExtensionOutputs is always NotApplicable for this file's inputs: none
            //of them populate ClientExtensionOutputs/AuthenticatorExtensionOutputs, so this claim
            //would otherwise mismatch the Success default at every call site.
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
