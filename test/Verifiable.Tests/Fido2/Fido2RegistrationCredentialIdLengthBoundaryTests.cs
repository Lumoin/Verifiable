using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Boundary tests for <see cref="Fido2RegistrationChecks.CheckRegistrationCredentialIdLength"/>'s
/// <c>&gt;= 1 and &lt;= 1023</c> bound (WebAuthn L3 <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">section
/// 7.1</see>, step 25), driven through the real <see cref="ClaimIssuer{TInput}"/> pipeline built from
/// <see cref="Fido2ValidationProfiles.RegistrationRules"/>, mirroring <see cref="Fido2RegistrationRulesTests"/>'s
/// own shape.
/// </summary>
/// <remarks>
/// <see cref="AttestedCredentialData"/>'s public constructor performs no length validation of its own
/// — <see cref="Fido2RegistrationChecks.CheckRegistrationCredentialIdLength"/> is the sole enforcement
/// point for this bound against a directly-constructed input, the same pattern
/// <see cref="Fido2RegistrationVerifierTests"/> already uses elsewhere. Every existing test in
/// <see cref="Fido2RegistrationRulesTests"/> exercises only "attested credential data missing
/// entirely" and a fixed 4-byte credential ID; this file supplies the length axis itself, including
/// both exact valid extremes (1 and 1023 bytes) that
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">section 6.5.1</see>'s
/// wire-parse boundary (<see cref="AuthenticatorDataReader.ReadAttestedCredentialData"/>) never lets
/// through a real <c>authData</c> parse in the first place, since this rule is what a relying party
/// that builds <see cref="RegistrationCeremonyInput"/> from a non-wire source (or a future format
/// whose parser is laxer) would still depend on.
/// </remarks>
[TestClass]
internal sealed class Fido2RegistrationCredentialIdLengthBoundaryTests
{
    /// <summary>The base64url-encoded challenge a valid ceremony embeds and expects.</summary>
    private const string ValidChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";

    /// <summary>The relying party origin a valid ceremony embeds and expects.</summary>
    private const string ValidOrigin = "https://relyingparty.example";

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>A 0-byte credential ID fails <see cref="Fido2ClaimIds.Fido2RegistrationCredentialIdLength"/> — below the lower bound.</summary>
    [TestMethod]
    public async Task ZeroByteCredentialIdFailsCredentialIdLengthClaim()
    {
        using RegistrationCeremonyInput input = BuildInputWithCredentialIdLength(0);
        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationCredentialIdLength, ClaimOutcome.Failure));
    }


    /// <summary>A 1-byte credential ID succeeds — the exact lower valid extreme, never exercised by the fixed 4-byte default.</summary>
    [TestMethod]
    public async Task OneByteCredentialIdSucceedsCredentialIdLengthClaim()
    {
        using RegistrationCeremonyInput input = BuildInputWithCredentialIdLength(1);
        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result);
    }


    /// <summary>A 1023-byte credential ID succeeds — the exact upper valid extreme.</summary>
    [TestMethod]
    public async Task OneThousandTwentyThreeByteCredentialIdSucceedsCredentialIdLengthClaim()
    {
        using RegistrationCeremonyInput input = BuildInputWithCredentialIdLength(CredentialId.MaxLength);
        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result);
    }


    /// <summary>A 1024-byte credential ID fails — one byte past the upper bound.</summary>
    [TestMethod]
    public async Task OneThousandTwentyFourByteCredentialIdFailsCredentialIdLengthClaim()
    {
        using RegistrationCeremonyInput input = BuildInputWithCredentialIdLength(CredentialId.MaxLength + 1);
        ClaimIssueResult result = await IssueClaimsAsync(input);

        AssertClaimOutcomes(result, (Fido2ClaimIds.Fido2RegistrationCredentialIdLength, ClaimOutcome.Failure));
    }


    /// <summary>
    /// Builds a <see cref="RegistrationCeremonyInput"/> valid against every rule in
    /// <see cref="Fido2ValidationProfiles.RegistrationRules"/> except for the credential-ID-length
    /// axis under test, constructing <see cref="AttestedCredentialData"/> directly (bypassing the
    /// wire-parse boundary) so a length outside 1-1023 can be constructed at all.
    /// </summary>
    /// <param name="credentialIdLength">The exact byte length the constructed credential ID carries.</param>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId/DigestValue carriers transfers to the returned RegistrationCeremonyInput (via AttestedCredentialData/AuthenticatorData), which the caller disposes via a using declaration.")]
    private static RegistrationCeremonyInput BuildInputWithCredentialIdLength(int credentialIdLength)
    {
        byte[] credentialId = new byte[credentialIdLength];
        for(int i = 0; i < credentialId.Length; i++)
        {
            credentialId[i] = (byte)(i + 1);
        }

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);

        CredentialId credentialIdCarrier = CredentialId.Create(credentialId, BaseMemoryPool.Shared);

        var attestedCredentialData = new AttestedCredentialData(Guid.NewGuid(), credentialIdCarrier, credentialPublicKey);

        const byte Flags = (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit | AuthenticatorDataFlags.AttestedCredentialDataIncludedBit);
        var authenticatorData = new AuthenticatorData(
            Fido2TestVectors.WrapRpIdHash(Fido2TestVectors.CreateRpIdHash(), BaseMemoryPool.Shared),
            new AuthenticatorDataFlags(Flags),
            signCount: 0,
            attestedCredentialData,
            ReadOnlyMemory<byte>.Empty);

        return new RegistrationCeremonyInput
        {
            ClientData = new ClientData(WellKnownClientDataTypes.Create, ValidChallenge, ValidOrigin),
            AuthenticatorData = authenticatorData,
            ExpectedChallenge = ValidChallenge,
            ExpectedOrigins = new HashSet<string> { ValidOrigin },
            ExpectedRpIdHash = Fido2TestVectors.WrapRpIdHash(Fido2TestVectors.CreateRpIdHash(), BaseMemoryPool.Shared),
            UserVerification = UserVerificationRequirement.Required,
            AllowedAlgorithms = [WellKnownCoseAlgorithms.Es256],
            AttestationResult = new NoneAttestationResult(),
            AcceptNoneAttestation = true
        };
    }


    /// <summary>Runs <see cref="Fido2ValidationProfiles.RegistrationRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    private Task<ClaimIssueResult> IssueClaimsAsync(RegistrationCeremonyInput input)
    {
        var issuer = new ClaimIssuer<RegistrationCeremonyInput>(
            "fido2-registration-credential-id-length-boundary-test", Fido2ValidationProfiles.RegistrationRules());

        return issuer.GenerateClaimsAsync(input, "fido2-registration-credential-id-length-boundary-test-correlation", TestContext.CancellationToken).AsTask();
    }


    /// <summary>
    /// Asserts that every claim in <paramref name="result"/> matching one of <paramref name="expectedOverrides"/>
    /// carries its given outcome, and every other claim is <see cref="ClaimOutcome.Success"/> (or
    /// <see cref="ClaimOutcome.NotApplicable"/> for the extension-outputs claim, which no input built
    /// by this file populates) — the fail-closed idiom: flipping the length axis must not silently let
    /// an unrelated claim also fail, mirroring <see cref="Fido2RegistrationRulesTests"/>'s own helper
    /// of the same shape.
    /// </summary>
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
