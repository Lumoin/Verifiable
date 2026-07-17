using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Assessment;
using Verifiable.Fido2;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="Fido2ValidationProfiles.AssertionRules"/>: drives the WebAuthn L3
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">section 7.2</see>
/// authentication ceremony rules through a real <see cref="ClaimIssuer{TInput}"/>, on inputs built by
/// <see cref="Fido2CeremonyInputFactory.CreateValidAssertionInput"/>.
/// </summary>
[TestClass]
internal sealed class Fido2AssertionRulesTests
{
    /// <summary>A credential identifier distinct from <see cref="Fido2CeremonyInputFactory.ValidCredentialId"/>, for the allowlist-mismatch axis.</summary>
    private static byte[] OtherCredentialId { get; } = [0xAA, 0xBB, 0xCC];

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A fully-valid assertion ceremony input yields <see cref="ClaimOutcome.Success"/> for every applicable
    /// rule, and <see cref="ClaimOutcome.NotApplicable"/> for the two claims whose valid default is "not
    /// tracked" — no allowlist was supplied, and no stored backup record exists.
    /// </summary>
    [TestMethod]
    public async Task FullyValidInputYieldsExpectedClaimOutcomes()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput();
        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A client data <c>type</c> of <c>webauthn.create</c> on an assertion ceremony fails step 10's type check.</summary>
    [TestMethod]
    public async Task WrongClientDataTypeFailsClientDataTypeClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientDataType: WellKnownClientDataTypes.Create);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionClientDataType, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A client-reported challenge that does not match the expected challenge fails step 11's challenge check.</summary>
    [TestMethod]
    public async Task ChallengeMismatchFailsChallengeClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientDataChallenge: "a-completely-different-challenge");

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionChallenge, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A client-reported origin absent from the expected origin set fails step 12's origin check.</summary>
    [TestMethod]
    public async Task OriginNotInExpectedSetFailsOriginClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientDataOrigin: "https://attacker.example");

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionOrigin, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A cross-origin ceremony the relying party does not allow fails step 13's crossOrigin check.</summary>
    [TestMethod]
    public async Task CrossOriginTrueWithoutAllowFailsCrossOriginClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientDataCrossOrigin: true,
            allowCrossOrigin: false);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionCrossOrigin, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A cross-origin ceremony the relying party allows succeeds every applicable rule.</summary>
    [TestMethod]
    public async Task CrossOriginTrueWithAllowSucceeds()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientDataCrossOrigin: true,
            allowCrossOrigin: true);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A present <c>topOrigin</c> with no expected top origins configured fails step 14's topOrigin check.</summary>
    [TestMethod]
    public async Task TopOriginPresentWithNullExpectedTopOriginsFailsTopOriginClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientDataTopOrigin: Fido2CeremonyInputFactory.ValidTopOrigin,
            expectedTopOrigins: null);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionTopOrigin, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A present <c>topOrigin</c> matching an expected top origin succeeds every applicable rule.</summary>
    [TestMethod]
    public async Task TopOriginPresentAndMatchingSucceeds()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientDataTopOrigin: Fido2CeremonyInputFactory.ValidTopOrigin,
            expectedTopOrigins: new HashSet<string> { Fido2CeremonyInputFactory.ValidTopOrigin });

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A single flipped bit anywhere in <c>authData.rpIdHash</c> fails step 15's rpIdHash check.</summary>
    [TestMethod]
    public async Task RpIdHashOneBitFlippedFailsRpIdHashClaim()
    {
        byte[] flipped = Fido2TestVectors.CreateRpIdHash();
        flipped[0] ^= 0x01;

        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(authDataRpIdHash: flipped);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionRpIdHash, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>An expected RP ID hash of a different length than <c>authData.rpIdHash</c> fails step 15's rpIdHash check.</summary>
    [TestMethod]
    public async Task RpIdHashWrongLengthFailsRpIdHashClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(expectedRpIdHash: new byte[16]);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionRpIdHash, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>
    /// A clear <c>UP</c> bit fails step 16's user-present check unconditionally: unlike registration's step 15,
    /// the assertion step carries no conditional-mediation exception.
    /// </summary>
    [TestMethod]
    public async Task UserPresentClearFailsUserPresentClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(userPresent: false);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionUserPresent, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A clear <c>UV</c> bit fails step 17's user-verified check under <see cref="UserVerificationRequirement.Required"/>.</summary>
    [TestMethod]
    public async Task UserVerifiedClearWithRequiredFailsUserVerifiedClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            userVerified: false,
            userVerification: UserVerificationRequirement.Required);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionUserVerified, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A set <c>UV</c> bit succeeds under <see cref="UserVerificationRequirement.Required"/>, with no <see cref="Claim.Context"/> attached.</summary>
    [TestMethod]
    public async Task UserVerifiedSetWithRequiredSucceedsWithNoContext()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            userVerified: true,
            userVerification: UserVerificationRequirement.Required);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
        Claim claim = FindClaim(result, Fido2ClaimIds.Fido2AssertionUserVerified);
        Assert.AreSame(ClaimContext.None, claim.Context);
    }


    /// <summary>
    /// A clear <c>UV</c> bit succeeds every applicable rule under <see cref="UserVerificationRequirement.Discouraged"/>,
    /// recording the observed (clear) state in the claim's <see cref="Claim.Context"/>.
    /// </summary>
    [TestMethod]
    public async Task UserVerifiedClearWithDiscouragedSucceedsAndRecordsObservedState()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            userVerified: false,
            userVerification: UserVerificationRequirement.Discouraged);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
        Claim claim = FindClaim(result, Fido2ClaimIds.Fido2AssertionUserVerified);
        var context = Assert.IsInstanceOfType<UserVerificationClaimContext>(claim.Context);
        Assert.IsFalse(context.UserVerified);
    }


    /// <summary>
    /// A clear <c>UV</c> bit succeeds every applicable rule under <see cref="UserVerificationRequirement.Preferred"/>,
    /// recording the observed (clear) state in the claim's <see cref="Claim.Context"/>.
    /// </summary>
    [TestMethod]
    public async Task UserVerifiedClearWithPreferredSucceedsAndRecordsObservedState()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            userVerified: false,
            userVerification: UserVerificationRequirement.Preferred);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
        Claim claim = FindClaim(result, Fido2ClaimIds.Fido2AssertionUserVerified);
        var context = Assert.IsInstanceOfType<UserVerificationClaimContext>(claim.Context);
        Assert.IsFalse(context.UserVerified);
    }


    /// <summary>
    /// A set <c>UV</c> bit succeeds every applicable rule under <see cref="UserVerificationRequirement.Preferred"/>,
    /// recording the observed (set) state in the claim's <see cref="Claim.Context"/>.
    /// </summary>
    [TestMethod]
    public async Task UserVerifiedSetWithPreferredSucceedsAndRecordsObservedState()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            userVerified: true,
            userVerification: UserVerificationRequirement.Preferred);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
        Claim claim = FindClaim(result, Fido2ClaimIds.Fido2AssertionUserVerified);
        var context = Assert.IsInstanceOfType<UserVerificationClaimContext>(claim.Context);
        Assert.IsTrue(context.UserVerified);
    }


    /// <summary>
    /// The stored credential record's <c>uvInitialized</c> is <see langword="false"/> and the assertion's
    /// <c>UV</c> flag is <see langword="true"/> — the step-up transition — yielding exactly
    /// <see cref="ClaimOutcome.Inconclusive"/> for <see cref="Fido2ClaimIds.Fido2AssertionUvInitializedUpgrade"/>,
    /// while the overall outcome is unaffected (a signal, not a failure).
    /// </summary>
    [TestMethod]
    public async Task UvInitializedStoredFalseCurrentTrueYieldsInconclusive()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            userVerified: true,
            storedUvInitialized: false);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionUvInitializedUpgrade, ClaimOutcome.Inconclusive),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>The stored <c>uvInitialized</c> is <see langword="false"/> and the current <c>UV</c> flag is also clear: nothing to upgrade, succeeds.</summary>
    [TestMethod]
    public async Task UvInitializedStoredFalseCurrentFalseSucceeds()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            userVerified: false,
            userVerification: UserVerificationRequirement.Discouraged,
            storedUvInitialized: false);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>The stored <c>uvInitialized</c> is already <see langword="true"/> and the current <c>UV</c> flag is set: no transition, succeeds.</summary>
    [TestMethod]
    public async Task UvInitializedStoredTrueCurrentTrueSucceeds()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            userVerified: true,
            storedUvInitialized: true);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>The stored <c>uvInitialized</c> is already <see langword="true"/> and the current <c>UV</c> flag is clear: no upgrade rule applies (uvInitialized never regresses), succeeds.</summary>
    [TestMethod]
    public async Task UvInitializedStoredTrueCurrentFalseSucceeds()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            userVerified: false,
            userVerification: UserVerificationRequirement.Discouraged,
            storedUvInitialized: true);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A set <c>BS</c> bit with a clear <c>BE</c> bit fails step 18's backup-flags invariant.</summary>
    [TestMethod]
    public async Task BackupStateSetWithBackupEligibleClearFailsBackupFlagsInvariantClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            backupEligible: false,
            backupState: true);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionBackupFlagsInvariant, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>An asserted credential identifier present in the relying party's allowlist succeeds step 5's allowed-credentials check.</summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId instances transfers to the ceremony input, which the using declaration disposes.")]
    public async Task AllowedCredentialsContainingAssertedIdSucceeds()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            allowedCredentialIds: [CredentialId.Create(Fido2CeremonyInputFactory.ValidCredentialId, BaseMemoryPool.Shared)],
            credentialId: CredentialId.Create(Fido2CeremonyInputFactory.ValidCredentialId, BaseMemoryPool.Shared));

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>An asserted credential identifier absent from the relying party's allowlist fails step 5's allowed-credentials check.</summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId instances transfers to the ceremony input, which the using declaration disposes.")]
    public async Task AllowedCredentialsNotContainingAssertedIdFailsAllowedCredentialsClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            allowedCredentialIds: [CredentialId.Create(OtherCredentialId, BaseMemoryPool.Shared)],
            credentialId: CredentialId.Create(Fido2CeremonyInputFactory.ValidCredentialId, BaseMemoryPool.Shared));

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>An allowlist configured with no asserted credential identifier fails step 5's allowed-credentials check.</summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId instance transfers to the ceremony input, which the using declaration disposes.")]
    public async Task AllowedCredentialsPresentWithNullCredentialIdFailsAllowedCredentialsClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            allowedCredentialIds: [CredentialId.Create(Fido2CeremonyInputFactory.ValidCredentialId, BaseMemoryPool.Shared)]);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A strictly increasing signature counter succeeds step 22's signCount-regression check.</summary>
    [TestMethod]
    public async Task SignCountIncreasingSucceeds()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(signCount: 5, storedSignCount: 1);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A zero signature counter against a zero stored counter succeeds step 22's check: the authenticator does not implement the counter.</summary>
    [TestMethod]
    public async Task SignCountBothZeroSucceeds()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(signCount: 0, storedSignCount: 0);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>
    /// An asserted counter equal to a nonzero stored counter yields exactly
    /// <see cref="ClaimOutcome.Inconclusive"/> for step 22's check — a possible-clone signal, not a hard failure.
    /// </summary>
    [TestMethod]
    public async Task SignCountEqualNonzeroYieldsInconclusive()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(signCount: 5, storedSignCount: 5);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionSignCountRegression, ClaimOutcome.Inconclusive),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>
    /// An asserted counter lower than the stored counter yields exactly <see cref="ClaimOutcome.Inconclusive"/>
    /// for step 22's check, never <see cref="ClaimOutcome.Failure"/>.
    /// </summary>
    [TestMethod]
    public async Task SignCountDecreasingYieldsInconclusive()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(signCount: 3, storedSignCount: 5);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionSignCountRegression, ClaimOutcome.Inconclusive),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable),
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.NotApplicable));
    }


    /// <summary>A current backup eligibility differing from the stored record fails step 19's backup-state-consistency check.</summary>
    [TestMethod]
    public async Task BackupStateConsistencyBackupEligibleMismatchFailsClaim()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            backupEligible: false,
            storedBackupEligible: true);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable));
    }


    /// <summary>
    /// A current backup state differing from a tracked stored backup state yields
    /// <see cref="ClaimOutcome.Inconclusive"/> for step 19's check — the specification leaves the response to
    /// relying party policy rather than mandating success or failure.
    /// </summary>
    [TestMethod]
    public async Task BackupStateConsistencyBackupStateChangedWithStoredValueYieldsInconclusive()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            backupEligible: false,
            backupState: false,
            storedBackupEligible: false,
            storedBackupState: true);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2AssertionBackupStateConsistency, ClaimOutcome.Inconclusive),
            (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable));
    }


    /// <summary>Current backup eligibility and state consistent with a tracked stored record succeeds step 19's check.</summary>
    [TestMethod]
    public async Task BackupStateConsistencyConsistentSucceeds()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            backupEligible: false,
            backupState: false,
            storedBackupEligible: false,
            storedBackupState: false);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2AssertionAllowedCredentials, ClaimOutcome.NotApplicable));
    }


    /// <summary>Finds the claim carrying <paramref name="claimId"/> in <paramref name="result"/>.</summary>
    /// <param name="result">The claim result to search.</param>
    /// <param name="claimId">The claim identifier to find.</param>
    /// <returns>The matching claim.</returns>
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


    /// <summary>Runs <see cref="Fido2ValidationProfiles.AssertionRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    /// <param name="input">The ceremony input to validate.</param>
    /// <returns>The generated <see cref="ClaimIssueResult"/>.</returns>
    private Task<ClaimIssueResult> IssueClaimsAsync(AssertionCeremonyInput input)
    {
        var issuer = new ClaimIssuer<AssertionCeremonyInput>("fido2-assertion-rules-test", Fido2ValidationProfiles.AssertionRules());

        return issuer.GenerateClaimsAsync(input, "fido2-assertion-rules-test-correlation", TestContext.CancellationToken).AsTask();
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
