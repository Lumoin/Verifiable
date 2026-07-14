using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="Fido2AssertionChecks.CheckAssertionNoAttestedCredentialData"/>'s two-operand
/// boolean, exercised with the <c>AT</c> flag and the attested credential data block deliberately
/// disagreeing — the case <see cref="Fido2AssertionAtFlagTests"/> does not cover, since both of its
/// inputs keep the two operands in agreement (flag clear/data absent, or flag set/data present).
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication
/// Level 3, section 6.1: Authenticator Data</see> requires both the <c>AT</c> flag clear AND no
/// attested credential data block for an assertion; either condition alone must fail the claim, so
/// the check's implementation ORs the two failure conditions together
/// (<c>Flags.AttestedCredentialDataIncluded || AttestedCredentialData is not null</c>). Only an input
/// where the two operands disagree can distinguish that <c>||</c> from a mistaken <c>&amp;&amp;</c>:
/// under matched operands (both true or both false) the two forms compute the same result.
/// <see cref="AuthenticatorData"/>'s public constructor performs no cross-validation between its
/// <c>flags</c> and <c>attestedCredentialData</c> parameters, so — exactly as
/// <c>Fido2RegistrationVerifierTests.BuildRegistrationAuthenticatorData</c> already does on the
/// registration side — a mismatched instance is directly constructible without going through
/// <see cref="AuthenticatorDataReader.Read"/> at all.
/// </remarks>
[TestClass]
internal sealed class Fido2AssertionAttestedCredentialDataMismatchTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The <c>AT</c> flag clear with a non-null attested credential data block. The correct
    /// <c>||</c> evaluates <c>false || true</c> to <see langword="true"/>, so this mismatched
    /// authenticator correctly fails the claim; a mistaken <c>&amp;&amp;</c> would instead evaluate
    /// <c>false &amp;&amp; true</c> to <see langword="false"/> and let it slip through as
    /// <see cref="ClaimOutcome.Success"/>.
    /// </summary>
    [TestMethod]
    public async Task AtFlagClearWithAttestedCredentialDataPresentFailsNoAttestedCredentialDataClaim()
    {
        using AssertionCeremonyInput input = CreateAssertionInputWithMismatchedAuthenticatorData(
            attestedCredentialDataIncludedFlagSet: false,
            includeAttestedCredentialData: true);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2AssertionNoAttestedCredentialData, ClaimOutcome.Failure));
    }


    /// <summary>
    /// The <c>AT</c> flag set with no attested credential data block — the mirror-image mismatch,
    /// which a mistaken <c>&amp;&amp;</c> would also report as <see cref="ClaimOutcome.Success"/>
    /// (<c>true &amp;&amp; false</c> is <see langword="false"/>). Correctly fails.
    /// </summary>
    [TestMethod]
    public async Task AtFlagSetWithNoAttestedCredentialDataFailsNoAttestedCredentialDataClaim()
    {
        using AssertionCeremonyInput input = CreateAssertionInputWithMismatchedAuthenticatorData(
            attestedCredentialDataIncludedFlagSet: true,
            includeAttestedCredentialData: false);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2AssertionNoAttestedCredentialData, ClaimOutcome.Failure));
    }


    /// <summary>
    /// Builds an otherwise-valid <see cref="AssertionCeremonyInput"/> whose <see cref="AuthenticatorData"/>
    /// is constructed directly (bypassing <see cref="AuthenticatorDataReader.Read"/>) so its <c>AT</c>
    /// flag bit and its <see cref="AuthenticatorData.AttestedCredentialData"/> presence can be set
    /// independently of one another.
    /// </summary>
    /// <param name="attestedCredentialDataIncludedFlagSet">Whether the <c>AT</c> flag bit (<c>0x40</c>) is set.</param>
    /// <param name="includeAttestedCredentialData">Whether a non-null attested credential data block is attached.</param>
    /// <returns>The ceremony input under test, owned by the caller.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the DigestValue/UserHandle/AttestedCredentialData carriers transfers to the returned AssertionCeremonyInput, which the caller disposes via a using declaration.")]
    private static AssertionCeremonyInput CreateAssertionInputWithMismatchedAuthenticatorData(
        bool attestedCredentialDataIncludedFlagSet,
        bool includeAttestedCredentialData)
    {
        byte flags = (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit | (attestedCredentialDataIncludedFlagSet ? AuthenticatorDataFlags.AttestedCredentialDataIncludedBit : 0));

        byte[] rpIdHashBytes = Fido2TestVectors.CreateRpIdHash();
        DigestValue authDataRpIdHash = Fido2TestVectors.WrapRpIdHash(rpIdHashBytes, BaseMemoryPool.Shared);
        DigestValue expectedRpIdHash = Fido2TestVectors.WrapRpIdHash(rpIdHashBytes, BaseMemoryPool.Shared);

        AttestedCredentialData? attestedCredentialData = includeAttestedCredentialData
            ? BuildAttestedCredentialData()
            : null;

        var authenticatorData = new AuthenticatorData(authDataRpIdHash, new AuthenticatorDataFlags(flags), signCount: 1, attestedCredentialData, ReadOnlyMemory<byte>.Empty);

        UserHandle responseUserHandle = UserHandle.Create(Fido2CeremonyInputFactory.ValidUserHandle, BaseMemoryPool.Shared);
        UserHandle storedUserHandle = UserHandle.Create(Fido2CeremonyInputFactory.ValidUserHandle, BaseMemoryPool.Shared);

        return new AssertionCeremonyInput
        {
            ClientData = new ClientData(WellKnownClientDataTypes.Get, Fido2CeremonyInputFactory.ValidChallenge, Fido2CeremonyInputFactory.ValidOrigin),
            AuthenticatorData = authenticatorData,
            ExpectedChallenge = Fido2CeremonyInputFactory.ValidChallenge,
            ExpectedOrigins = new HashSet<string> { Fido2CeremonyInputFactory.ValidOrigin },
            ExpectedRpIdHash = expectedRpIdHash,
            UserVerification = UserVerificationRequirement.Required,
            StoredSignCount = 0,
            StoredUvInitialized = true,
            ResponseUserHandle = responseUserHandle,
            StoredUserHandle = storedUserHandle
        };
    }


    /// <summary>Builds a fresh, independently-owned <see cref="AttestedCredentialData"/> for the "present" axis.</summary>
    /// <returns>A new <see cref="AttestedCredentialData"/> instance, owned by the caller.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId carrier transfers to the returned AttestedCredentialData, itself owned transitively by the caller's AuthenticatorData/AssertionCeremonyInput.")]
    private static AttestedCredentialData BuildAttestedCredentialData()
    {
        CoseKey credentialPublicKey = Fido2TestVectors.TestCredentialPublicKeyReader(Fido2TestVectors.EncodeP256CoseKey()).CoseKey;
        CredentialId credentialId = CredentialId.Create(Fido2CeremonyInputFactory.ValidCredentialId, BaseMemoryPool.Shared);

        return new AttestedCredentialData(Guid.NewGuid(), credentialId, credentialPublicKey);
    }


    /// <summary>Runs <see cref="Fido2ValidationProfiles.AssertionRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    /// <param name="input">The ceremony input to validate.</param>
    /// <returns>The generated <see cref="ClaimIssueResult"/>.</returns>
    private Task<ClaimIssueResult> IssueClaimsAsync(AssertionCeremonyInput input)
    {
        var issuer = new ClaimIssuer<AssertionCeremonyInput>("fido2-assertion-attested-credential-data-mismatch-test", Fido2ValidationProfiles.AssertionRules());

        return issuer.GenerateClaimsAsync(input, "fido2-assertion-attested-credential-data-mismatch-test-correlation", TestContext.CancellationToken).AsTask();
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
