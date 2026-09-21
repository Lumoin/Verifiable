using CsCheck;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.Fido2;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Property-based tests (CsCheck) for the WebAuthn L3
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">section 7.1</see>
/// registration ceremony rules in <see cref="Fido2ValidationProfiles.RegistrationRules"/>: invariants that
/// must hold for every input in a class, not just the hand-picked vectors in
/// <see cref="Fido2RegistrationRulesTests"/>.
/// </summary>
[TestClass]
internal sealed class Fido2RulePropertyTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Any single-character corruption of the client-reported challenge fails the challenge claim: the ordinal
    /// string comparison in
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">WebAuthn L3 section
    /// 7.1</see>, step 8 rejects any difference from the expected challenge, however small.
    /// </summary>
    [TestMethod]
    public async Task AnySingleCharacterChallengeCorruptionFailsChallengeClaim()
    {
        string challenge = Fido2CeremonyInputFactory.ValidChallenge;

        await (from index in Gen.Int[0, challenge.Length - 1]
               from replacement in Gen.Char.AlphaNumeric.Where(c => c != challenge[index])
               select (index, replacement))
        .SampleAsync(async sample =>
        {
            char[] corrupted = challenge.ToCharArray();
            corrupted[sample.index] = sample.replacement;

            using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
                clientDataChallenge: new string(corrupted));

            ClaimIssueResult result = await IssueRegistrationClaimsAsync(input);

            Claim claim = FindClaim(result, Fido2ClaimIds.Fido2RegistrationChallenge);
            Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        }, threads: CsCheckSampling.Threads);
    }


    /// <summary>
    /// Any single-bit flip anywhere in the expected RP ID hash fails the rpIdHash claim: the fixed-time
    /// comparison in
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">WebAuthn L3 section
    /// 7.1</see>, step 14 rejects any difference from <c>authData.rpIdHash</c>.
    /// </summary>
    [TestMethod]
    public async Task AnyBitFlipInExpectedRpIdHashFailsRpIdHashClaim()
    {
        await (from index in Gen.Int[0, 31]
               from bit in Gen.Int[0, 7]
               select (index, bit))
        .SampleAsync(async sample =>
        {
            byte[] corrupted = Fido2TestVectors.CreateRpIdHash();
            corrupted[sample.index] ^= (byte)(1 << sample.bit);

            using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
                expectedRpIdHash: corrupted);

            ClaimIssueResult result = await IssueRegistrationClaimsAsync(input);

            Claim claim = FindClaim(result, Fido2ClaimIds.Fido2RegistrationRpIdHash);
            Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        }, threads: CsCheckSampling.Threads);
    }


    /// <summary>
    /// For any authenticator data flags byte, the backup-flags-invariant claim fails exactly when the <c>BS</c>
    /// bit is set while the <c>BE</c> bit is clear — the only combination
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">WebAuthn L3 section
    /// 7.1</see>, step 17 forbids. The user-presence/verification requirements are relaxed so the random byte's
    /// unrelated bits cannot make an unrelated claim fail.
    /// </summary>
    [TestMethod]
    public async Task BackupFlagsInvariantFailsExactlyWhenBackupStateSetWithoutBackupEligible()
    {
        await Gen.Byte.SampleAsync(async flagsByte =>
        {
            bool userPresent = (flagsByte & AuthenticatorDataFlags.UserPresentBit) != 0;
            bool userVerified = (flagsByte & AuthenticatorDataFlags.UserVerifiedBit) != 0;
            bool backupEligible = (flagsByte & AuthenticatorDataFlags.BackupEligibleBit) != 0;
            bool backupState = (flagsByte & AuthenticatorDataFlags.BackupStateBit) != 0;

            using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
                userPresent: userPresent,
                userVerified: userVerified,
                backupEligible: backupEligible,
                backupState: backupState,
                userVerification: UserVerificationRequirement.Discouraged,
                allowUserPresenceAbsent: true);

            ClaimIssueResult result = await IssueRegistrationClaimsAsync(input);

            Claim claim = FindClaim(result, Fido2ClaimIds.Fido2RegistrationBackupFlagsInvariant);
            bool expectedFailure = backupState && !backupEligible;

            Assert.AreEqual(expectedFailure ? ClaimOutcome.Failure : ClaimOutcome.Success, claim.Outcome);
        }, threads: CsCheckSampling.Threads);
    }


    /// <summary>Runs <see cref="Fido2ValidationProfiles.RegistrationRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    /// <param name="input">The ceremony input to validate.</param>
    /// <returns>The generated <see cref="ClaimIssueResult"/>.</returns>
    private Task<ClaimIssueResult> IssueRegistrationClaimsAsync(RegistrationCeremonyInput input)
    {
        var issuer = new ClaimIssuer<RegistrationCeremonyInput>("fido2-registration-property-test", Fido2ValidationProfiles.RegistrationRules(), new FakeTimeProvider(TestClock.CanonicalEpoch));

        return issuer.GenerateClaimsAsync(input, "fido2-registration-property-test-correlation", TestContext.CancellationToken).AsTask();
    }


    /// <summary>Finds the claim carrying <paramref name="claimId"/> in <paramref name="result"/>.</summary>
    /// <param name="result">The claim result to search.</param>
    /// <param name="claimId">The claim identifier to find.</param>
    /// <returns>The matching claim.</returns>
    /// <exception cref="InvalidOperationException"><paramref name="claimId"/> is not present in <paramref name="result"/>.</exception>
    private static Claim FindClaim(ClaimIssueResult result, ClaimId claimId)
    {
        foreach(Claim claim in result.Claims)
        {
            if(claim.Id.Code == claimId.Code)
            {
                return claim;
            }
        }

        throw new InvalidOperationException($"Claim '{claimId}' was not present in the result.");
    }
}
