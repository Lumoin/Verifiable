using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="Fido2AssertionChecks.CheckAssertionNoAttestedCredentialData"/>: drives the
/// WebAuthn L3 <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">section
/// 6.1</see> assertion-side prohibition on the <c>AT</c> flag and attested credential data through
/// a real <see cref="ClaimIssuer{TInput}"/> running <see cref="Fido2ValidationProfiles.AssertionRules"/>.
/// </summary>
[TestClass]
internal sealed class Fido2AssertionAtFlagTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Assertion <c>authData</c> carrying the <c>AT</c> flag and an attested credential data block
    /// — a <c>makeCredential</c>-shaped structure replayed into a <c>getAssertion</c> response —
    /// fails <see cref="Fido2ClaimIds.Fido2AssertionNoAttestedCredentialData"/> exactly, with every
    /// other applicable claim still succeeding.
    /// </summary>
    [TestMethod]
    public async Task AssertionAuthDataWithAttestedCredentialDataFailsNoAttestedCredentialDataClaim()
    {
        using AssertionCeremonyInput input = CreateAssertionInputWithAttestedCredentialData();

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2AssertionNoAttestedCredentialData, ClaimOutcome.Failure));
    }


    /// <summary>
    /// A normal assertion <c>authData</c> — <c>AT</c> clear, no attested credential data block —
    /// succeeds <see cref="Fido2ClaimIds.Fido2AssertionNoAttestedCredentialData"/>.
    /// </summary>
    [TestMethod]
    public async Task NormalAssertionAuthDataSucceedsNoAttestedCredentialDataClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput();

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result);
    }


    /// <summary>
    /// Builds an otherwise-valid <see cref="AssertionCeremonyInput"/> whose <c>authData</c> carries
    /// the <c>AT</c> flag set and a full attested credential data block — the shape a registration
    /// ceremony produces, not an assertion.
    /// </summary>
    /// <returns>The ceremony input under test, owned by the caller.</returns>
    private static AssertionCeremonyInput CreateAssertionInputWithAttestedCredentialData()
    {
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();
        byte[] credentialId = [0x01, 0x02, 0x03, 0x04];
        byte[] attestedCredentialData = Fido2TestVectors.BuildAttestedCredentialData(
            Guid.NewGuid(), credentialId, Fido2TestVectors.EncodeP256CoseKey());

        byte flags = (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit | AuthenticatorDataFlags.AttestedCredentialDataIncludedBit);
        byte[] authenticatorDataBytes = Fido2TestVectors.BuildAuthenticatorData(
            rpIdHash, flags, signCount: 1, attestedCredentialData: attestedCredentialData);

        AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(
            authenticatorDataBytes, Fido2TestVectors.TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        UserHandle responseUserHandle = UserHandle.Create(Fido2CeremonyInputFactory.ValidUserHandle, BaseMemoryPool.Shared);
        UserHandle storedUserHandle = UserHandle.Create(Fido2CeremonyInputFactory.ValidUserHandle, BaseMemoryPool.Shared);

        return new AssertionCeremonyInput
        {
            ClientData = new ClientData(WellKnownClientDataTypes.Get, Fido2CeremonyInputFactory.ValidChallenge, Fido2CeremonyInputFactory.ValidOrigin),
            AuthenticatorData = authenticatorData,
            ExpectedChallenge = Fido2CeremonyInputFactory.ValidChallenge,
            ExpectedOrigins = new HashSet<string> { Fido2CeremonyInputFactory.ValidOrigin },
            ExpectedRpIdHash = Fido2TestVectors.WrapRpIdHash(rpIdHash, BaseMemoryPool.Shared),
            UserVerification = UserVerificationRequirement.Required,
            StoredSignCount = 0,
            StoredUvInitialized = true,
            ResponseUserHandle = responseUserHandle,
            StoredUserHandle = storedUserHandle
        };
    }


    /// <summary>Runs <see cref="Fido2ValidationProfiles.AssertionRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    /// <param name="input">The ceremony input to validate.</param>
    /// <returns>The generated <see cref="ClaimIssueResult"/>.</returns>
    private Task<ClaimIssueResult> IssueClaimsAsync(AssertionCeremonyInput input)
    {
        var issuer = new ClaimIssuer<AssertionCeremonyInput>("fido2-assertion-at-flag-test", Fido2ValidationProfiles.AssertionRules());

        return issuer.GenerateClaimsAsync(input, "fido2-assertion-at-flag-test-correlation", TestContext.CancellationToken).AsTask();
    }


    /// <summary>
    /// Asserts that every claim in <paramref name="result"/> matching one of <paramref name="expectedOverrides"/>
    /// carries its given outcome, and every other applicable claim is <see cref="ClaimOutcome.Success"/> or
    /// <see cref="ClaimOutcome.NotApplicable"/> — the fail-closed idiom: flipping one axis must not silently
    /// let an unrelated claim also fail.
    /// </summary>
    /// <param name="result">The generated claim result to inspect.</param>
    /// <param name="expectedOverrides">The claim identifiers whose outcome differs from the acceptable default.</param>
    private static void AssertClaimOutcomes(ClaimIssueResult result, params (ClaimId ClaimId, ClaimOutcome Outcome)[] expectedOverrides)
    {
        foreach(Claim claim in result.Claims)
        {
            bool overridden = false;
            foreach((ClaimId claimId, ClaimOutcome outcome) in expectedOverrides)
            {
                if(claim.Id.Code == claimId.Code)
                {
                    Assert.AreEqual(outcome, claim.Outcome, $"Claim '{claim.Id}' outcome mismatch.");
                    overridden = true;

                    break;
                }
            }

            if(!overridden)
            {
                Assert.IsTrue(
                    claim.Outcome is ClaimOutcome.Success or ClaimOutcome.NotApplicable,
                    $"Claim '{claim.Id}' unexpectedly reported {claim.Outcome}.");
            }
        }
    }
}
