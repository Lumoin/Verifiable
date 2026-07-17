using Verifiable.Core.Assessment;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="Fido2ValidationProfiles.RegistrationRules"/>: drives the WebAuthn L3
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">section 7.1</see>
/// registration ceremony rules through a real <see cref="ClaimIssuer{TInput}"/>, on inputs built by
/// <see cref="Fido2CeremonyInputFactory.CreateValidRegistrationInput"/>.
/// </summary>
[TestClass]
internal sealed class Fido2RegistrationRulesTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>A fully-valid registration ceremony input yields <see cref="ClaimOutcome.Success"/> for every rule.</summary>
    [TestMethod]
    public async Task FullyValidInputYieldsAllClaimsSuccess()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput();
        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result);
    }


    /// <summary>A client data <c>type</c> of <c>webauthn.get</c> on a registration ceremony fails step 7's type check.</summary>
    [TestMethod]
    public async Task WrongClientDataTypeFailsClientDataTypeClaim()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataType: WellKnownClientDataTypes.Get);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationClientDataType, ClaimOutcome.Failure));
    }


    /// <summary>A client-reported challenge that does not match the expected challenge fails step 8's challenge check.</summary>
    [TestMethod]
    public async Task ChallengeMismatchFailsChallengeClaim()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataChallenge: "a-completely-different-challenge");

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationChallenge, ClaimOutcome.Failure));
    }


    /// <summary>A client-reported origin absent from the expected origin set fails step 9's origin check.</summary>
    [TestMethod]
    public async Task OriginNotInExpectedSetFailsOriginClaim()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOrigin: "https://attacker.example");

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationOrigin, ClaimOutcome.Failure));
    }


    /// <summary>A cross-origin ceremony the relying party does not allow fails step 10's crossOrigin check.</summary>
    [TestMethod]
    public async Task CrossOriginTrueWithoutAllowFailsCrossOriginClaim()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataCrossOrigin: true,
            allowCrossOrigin: false);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationCrossOrigin, ClaimOutcome.Failure));
    }


    /// <summary>A cross-origin ceremony the relying party allows succeeds every rule.</summary>
    [TestMethod]
    public async Task CrossOriginTrueWithAllowSucceeds()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataCrossOrigin: true,
            allowCrossOrigin: true);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result);
    }


    /// <summary>A present <c>topOrigin</c> with no expected top origins configured fails step 11's topOrigin check.</summary>
    [TestMethod]
    public async Task TopOriginPresentWithNullExpectedTopOriginsFailsTopOriginClaim()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataTopOrigin: Fido2CeremonyInputFactory.ValidTopOrigin,
            expectedTopOrigins: null);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationTopOrigin, ClaimOutcome.Failure));
    }


    /// <summary>A present <c>topOrigin</c> matching an expected top origin succeeds every rule.</summary>
    [TestMethod]
    public async Task TopOriginPresentAndMatchingSucceeds()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataTopOrigin: Fido2CeremonyInputFactory.ValidTopOrigin,
            expectedTopOrigins: new HashSet<string> { Fido2CeremonyInputFactory.ValidTopOrigin });

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result);
    }


    /// <summary>A single flipped bit anywhere in <c>authData.rpIdHash</c> fails step 14's rpIdHash check.</summary>
    [TestMethod]
    public async Task RpIdHashOneBitFlippedFailsRpIdHashClaim()
    {
        byte[] flipped = Fido2TestVectors.CreateRpIdHash();
        flipped[0] ^= 0x01;

        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(authDataRpIdHash: flipped);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationRpIdHash, ClaimOutcome.Failure));
    }


    /// <summary>An expected RP ID hash of a different length than <c>authData.rpIdHash</c> fails step 14's rpIdHash check.</summary>
    [TestMethod]
    public async Task RpIdHashWrongLengthFailsRpIdHashClaim()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(expectedRpIdHash: new byte[16]);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationRpIdHash, ClaimOutcome.Failure));
    }


    /// <summary>A clear <c>UP</c> bit fails step 15's user-present check.</summary>
    [TestMethod]
    public async Task UserPresentClearFailsUserPresentClaim()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(userPresent: false);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationUserPresent, ClaimOutcome.Failure));
    }


    /// <summary>A clear <c>UP</c> bit succeeds every rule when the relying party opts into the conditional-create exception.</summary>
    [TestMethod]
    public async Task UserPresentClearWithAllowUserPresenceAbsentSucceeds()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            userPresent: false,
            allowUserPresenceAbsent: true);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result);
    }


    /// <summary>A clear <c>UV</c> bit fails step 16's user-verified check under <see cref="UserVerificationRequirement.Required"/>.</summary>
    [TestMethod]
    public async Task UserVerifiedClearWithRequiredFailsUserVerifiedClaim()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            userVerified: false,
            userVerification: UserVerificationRequirement.Required);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationUserVerified, ClaimOutcome.Failure));
    }


    /// <summary>A set <c>UV</c> bit succeeds under <see cref="UserVerificationRequirement.Required"/>, with no <see cref="Claim.Context"/> attached.</summary>
    [TestMethod]
    public async Task UserVerifiedSetWithRequiredSucceedsWithNoContext()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            userVerified: true,
            userVerification: UserVerificationRequirement.Required);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result);
        Claim claim = FindClaim(result, Fido2ClaimIds.Fido2RegistrationUserVerified);
        Assert.AreSame(ClaimContext.None, claim.Context);
    }


    /// <summary>
    /// A clear <c>UV</c> bit succeeds every rule under <see cref="UserVerificationRequirement.Discouraged"/>,
    /// recording the observed (clear) state in the claim's <see cref="Claim.Context"/>.
    /// </summary>
    [TestMethod]
    public async Task UserVerifiedClearWithDiscouragedSucceedsAndRecordsObservedState()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            userVerified: false,
            userVerification: UserVerificationRequirement.Discouraged);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result);
        Claim claim = FindClaim(result, Fido2ClaimIds.Fido2RegistrationUserVerified);
        var context = Assert.IsInstanceOfType<UserVerificationClaimContext>(claim.Context);
        Assert.IsFalse(context.UserVerified);
    }


    /// <summary>
    /// A clear <c>UV</c> bit succeeds every rule under <see cref="UserVerificationRequirement.Preferred"/>,
    /// recording the observed (clear) state in the claim's <see cref="Claim.Context"/>.
    /// </summary>
    [TestMethod]
    public async Task UserVerifiedClearWithPreferredSucceedsAndRecordsObservedState()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            userVerified: false,
            userVerification: UserVerificationRequirement.Preferred);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result);
        Claim claim = FindClaim(result, Fido2ClaimIds.Fido2RegistrationUserVerified);
        var context = Assert.IsInstanceOfType<UserVerificationClaimContext>(claim.Context);
        Assert.IsFalse(context.UserVerified);
    }


    /// <summary>
    /// A set <c>UV</c> bit succeeds every rule under <see cref="UserVerificationRequirement.Preferred"/>,
    /// recording the observed (set) state in the claim's <see cref="Claim.Context"/>.
    /// </summary>
    [TestMethod]
    public async Task UserVerifiedSetWithPreferredSucceedsAndRecordsObservedState()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            userVerified: true,
            userVerification: UserVerificationRequirement.Preferred);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result);
        Claim claim = FindClaim(result, Fido2ClaimIds.Fido2RegistrationUserVerified);
        var context = Assert.IsInstanceOfType<UserVerificationClaimContext>(claim.Context);
        Assert.IsTrue(context.UserVerified);
    }


    /// <summary>A set <c>BS</c> bit with a clear <c>BE</c> bit fails step 17's backup-flags invariant.</summary>
    [TestMethod]
    public async Task BackupStateSetWithBackupEligibleClearFailsBackupFlagsInvariantClaim()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            backupEligible: false,
            backupState: true);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationBackupFlagsInvariant, ClaimOutcome.Failure));
    }


    /// <summary>An attested algorithm absent from the relying party's accepted list fails step 20's algorithm check.</summary>
    [TestMethod]
    public async Task AlgorithmNotInAllowedListFailsCredentialAlgorithmClaim()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            allowedAlgorithms: [WellKnownCoseAlgorithms.Es384]);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationCredentialAlgorithm, ClaimOutcome.Failure));
    }


    /// <summary>
    /// A credential public key with no <c>alg</c> parameter never reaches step 20's algorithm check: the
    /// WebAuthn L3
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">section 6.5.1</see>
    /// parse-boundary conformance check — "the COSE_Key-encoded credential public key MUST contain the
    /// 'alg' parameter" — rejects it while the authenticator data is being read, before a
    /// <see cref="RegistrationCeremonyInput"/> can even be constructed.
    /// </summary>
    [TestMethod]
    public void NullCredentialAlgorithmIsRejectedAtTheParseBoundary()
    {
        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => Fido2CeremonyInputFactory.CreateValidRegistrationInput(credentialAlgorithm: null));

        Assert.IsTrue(exception.Message.Contains($"required label {CoseKeyParameters.Alg}", StringComparison.Ordinal), $"The message must name the missing alg label; was: {exception.Message}");
    }


    /// <summary>Missing attested credential data fails both the algorithm check and the credential-id-length check.</summary>
    [TestMethod]
    public async Task MissingAttestedCredentialDataFailsCredentialAlgorithmAndCredentialIdLengthClaims()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(includeAttestedCredentialData: false);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(
            result,
            (Fido2ClaimIds.Fido2RegistrationCredentialAlgorithm, ClaimOutcome.Failure),
            (Fido2ClaimIds.Fido2RegistrationCredentialIdLength, ClaimOutcome.Failure));
    }


    /// <summary>No attestation result at all fails step 24's attestation trustworthiness gate.</summary>
    [TestMethod]
    public async Task NullAttestationResultFailsAttestationTrustworthyClaim()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(omitAttestationResult: true);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationAttestationTrustworthy, ClaimOutcome.Failure));
    }


    /// <summary><see cref="NoneAttestationResult"/> succeeds step 24's gate when the relying party's policy accepts it.</summary>
    [TestMethod]
    public async Task NoneAttestationAcceptedByPolicySucceeds()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            attestationResult: new NoneAttestationResult(),
            acceptNoneAttestation: true);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result);
    }


    /// <summary><see cref="NoneAttestationResult"/> fails step 24's gate when the relying party's policy rejects it.</summary>
    [TestMethod]
    public async Task NoneAttestationRejectedByPolicyFailsAttestationTrustworthyClaim()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            attestationResult: new NoneAttestationResult(),
            acceptNoneAttestation: false);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationAttestationTrustworthy, ClaimOutcome.Failure));
    }


    /// <summary><see cref="SelfAttestationResult"/> succeeds step 24's gate when the relying party's policy accepts it.</summary>
    [TestMethod]
    public async Task SelfAttestationAcceptedByPolicySucceeds()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            attestationResult: new SelfAttestationResult(),
            acceptSelfAttestation: true);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result);
    }


    /// <summary><see cref="SelfAttestationResult"/> fails step 24's gate when the relying party's policy rejects it.</summary>
    [TestMethod]
    public async Task SelfAttestationRejectedByPolicyFailsAttestationTrustworthyClaim()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            attestationResult: new SelfAttestationResult(),
            acceptSelfAttestation: false);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationAttestationTrustworthy, ClaimOutcome.Failure));
    }


    /// <summary>
    /// A <see cref="CertifiedAttestationResult"/> always succeeds step 24's gate: its certificate chain has
    /// already validated by the time this rule runs.
    /// </summary>
    [TestMethod]
    public async Task CertifiedAttestationAlwaysSucceeds()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            attestationResult: new CertifiedAttestationResult(AttestationType.Unknown, Array.Empty<PkiCertificateMemory>()));

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result);
    }


    /// <summary>A <see cref="RejectedAttestationResult"/> always fails step 24's gate.</summary>
    [TestMethod]
    public async Task RejectedAttestationResultFailsAttestationTrustworthyClaim()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            attestationResult: new RejectedAttestationResult(Fido2AttestationErrors.ChainValidationFailed));

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationAttestationTrustworthy, ClaimOutcome.Failure));
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


    /// <summary>Runs <see cref="Fido2ValidationProfiles.RegistrationRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    /// <param name="input">The ceremony input to validate.</param>
    /// <returns>The generated <see cref="ClaimIssueResult"/>.</returns>
    private Task<ClaimIssueResult> IssueClaimsAsync(RegistrationCeremonyInput input)
    {
        var issuer = new ClaimIssuer<RegistrationCeremonyInput>("fido2-registration-rules-test", Fido2ValidationProfiles.RegistrationRules());

        return issuer.GenerateClaimsAsync(input, "fido2-registration-rules-test-correlation", TestContext.CancellationToken).AsTask();
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
            //Fido2RegistrationExtensionOutputs is always NotApplicable for this file's inputs: none
            //of them populate ClientExtensionOutputs/AuthenticatorExtensionOutputs, so this claim
            //would otherwise mismatch the Success default at every call site.
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
