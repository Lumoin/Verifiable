using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Firewalled end-to-end tests for <see cref="Fido2AssertionVerifier"/>: the WebAuthn L3
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">section 7.2</see>
/// authentication assertion signature verification, composed with the surface-field ceremony
/// rules in <see cref="Fido2ValidationProfiles.AssertionRules"/>.
/// </summary>
/// <remarks>
/// Every test reconstructs the ceremony input from the wire bytes <see cref="Fido2AssertionOracle"/>
/// mints — parsing <c>clientDataJSON</c> via <see cref="ClientDataJsonReader"/> and <c>authData</c>
/// via <see cref="AuthenticatorDataReader"/> — and hands the verifier only the stored credential
/// <see cref="CoseKey"/> plus wire bytes, never the oracle's private key or any in-memory object.
/// This mirrors the issuer/holder/verifier firewall this codebase requires of every ceremony test.
/// </remarks>
[TestClass]
internal sealed class Fido2AssertionVerifierTests
{
    /// <summary>The base64url-encoded challenge a valid ceremony embeds and expects.</summary>
    private const string ValidChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";

    /// <summary>The relying party origin a valid ceremony embeds and expects.</summary>
    internal const string ValidOrigin = "https://relyingparty.example";

    /// <summary>
    /// A default user handle this class's ceremony inputs use for both <c>response.userHandle</c>
    /// and the relying party's stored record, so <see cref="Fido2AssertionChecks.CheckAssertionUserHandle"/>
    /// succeeds and every test here stays focused on its own claim.
    /// </summary>
    private static byte[] DefaultUserHandleBytes { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The algorithm-matrix oracle factories under test, named for <see cref="DynamicDataAttribute"/> display.</summary>
    public static IEnumerable<object[]> AssertionAlgorithms =>
    [
        [nameof(Fido2AssertionOracle.CreateEs256)],
        [nameof(Fido2AssertionOracle.CreateEs384)],
        [nameof(Fido2AssertionOracle.CreateEs512)],
        [nameof(Fido2AssertionOracle.CreateEs256K)],
        [nameof(Fido2AssertionOracle.CreateRs256)],
        [nameof(Fido2AssertionOracle.CreateRs384)],
        [nameof(Fido2AssertionOracle.CreateRs512)],
        [nameof(Fido2AssertionOracle.CreatePs256)],
        [nameof(Fido2AssertionOracle.CreatePs384)],
        [nameof(Fido2AssertionOracle.CreatePs512)],
        [nameof(Fido2AssertionOracle.CreateEdDsa)]
    ];


    /// <summary>
    /// A validly minted assertion verifies and is acceptable across every algorithm the oracle
    /// supports (ES256, ES384, ES512, ES256K, RS256, RS384, RS512, PS256, PS384, PS512, EdDSA) —
    /// the verifier reconstructs entirely from wire bytes plus the stored credential public key.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(AssertionAlgorithms))]
    public async Task ValidAssertionAcrossAlgorithmMatrixIsAcceptable(string oracleFactoryName)
    {
        using Fido2AssertionOracle oracle = CreateOracle(oracleFactoryName);
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyMintedAssertionAsync(oracle.CredentialPublicKey, minted);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsTrue(outcome.IsAcceptable);
        Assert.IsFalse(HasFailureClaim(outcome));
    }


    /// <summary>
    /// A single flipped bit in the wire signature is rejected: <see cref="Fido2AssertionOutcome.SignatureValid"/>
    /// is <see langword="false"/> and the outcome is unacceptable, even though every surface-field
    /// rule still succeeds against the (unmodified) authData/clientData.
    /// </summary>
    [TestMethod]
    public async Task TamperedSignatureIsRejectedWithSignatureInvalid()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        byte[] tamperedSignature = minted.Signature.AsReadOnlySpan().ToArray();
        tamperedSignature[0] ^= 0xFF;

        Fido2AssertionOutcome outcome = await VerifyMintedAssertionAsync(oracle.CredentialPublicKey, minted, signatureOverride: tamperedSignature);

        Assert.IsFalse(outcome.SignatureValid);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.IsFalse(HasFailureClaim(outcome));
    }


    /// <summary>
    /// A tampered <c>authData</c> byte (inside <c>signCount</c>, so no surface-field rule reacts to
    /// it) invalidates the signature: the transcript the signature covers no longer matches what was
    /// signed.
    /// </summary>
    [TestMethod]
    public async Task TamperedAuthenticatorDataIsRejectedWithSignatureInvalid()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, signCount: 5, cancellationToken: TestContext.CancellationToken);

        byte[] tamperedAuthenticatorData = [.. minted.AuthenticatorData];
        //Offset 34 lies inside the big-endian signCount field (bytes 33-36): flipping it changes
        //the signed transcript without touching rpIdHash or flags, isolating the failure to the
        //signature check.
        tamperedAuthenticatorData[34] ^= 0xFF;

        Fido2AssertionOutcome outcome = await VerifyMintedAssertionAsync(
            oracle.CredentialPublicKey, minted, authenticatorDataOverride: tamperedAuthenticatorData);

        Assert.IsFalse(outcome.SignatureValid);
        Assert.IsFalse(outcome.IsAcceptable);
    }


    /// <summary>
    /// A relying party challenge that does not match the one embedded in <c>clientDataJSON</c>
    /// fails <see cref="Fido2ClaimIds.Fido2AssertionChallenge"/>, while the signature — which
    /// covers the actual embedded challenge, correctly — remains valid.
    /// </summary>
    [TestMethod]
    public async Task WrongExpectedChallengeFailsChallengeClaimWithSignatureStillValid()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyMintedAssertionAsync(
            oracle.CredentialPublicKey, minted, expectedChallenge: "a-completely-different-challenge");

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.AreEqual(ClaimOutcome.Failure, GetClaimOutcome(outcome, Fido2ClaimIds.Fido2AssertionChallenge));
    }


    /// <summary>
    /// A relying party ID hash that does not match <c>authData.rpIdHash</c> fails
    /// <see cref="Fido2ClaimIds.Fido2AssertionRpIdHash"/>, while the signature remains valid.
    /// </summary>
    [TestMethod]
    public async Task WrongExpectedRpIdHashFailsRpIdHashClaimWithSignatureStillValid()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        byte[] wrongRpIdHash = Fido2TestVectors.CreateRpIdHash();
        wrongRpIdHash[0] ^= 0x01;

        Fido2AssertionOutcome outcome = await VerifyMintedAssertionAsync(
            oracle.CredentialPublicKey, minted, expectedRpIdHash: wrongRpIdHash);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.AreEqual(ClaimOutcome.Failure, GetClaimOutcome(outcome, Fido2ClaimIds.Fido2AssertionRpIdHash));
    }


    /// <summary>
    /// A relying party origin set that does not contain the ceremony's actual origin fails
    /// <see cref="Fido2ClaimIds.Fido2AssertionOrigin"/>, while the signature remains valid.
    /// </summary>
    [TestMethod]
    public async Task WrongExpectedOriginFailsOriginClaimWithSignatureStillValid()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(ValidChallenge, ValidOrigin, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyMintedAssertionAsync(
            oracle.CredentialPublicKey, minted, expectedOrigins: new HashSet<string> { "https://attacker.example" });

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.AreEqual(ClaimOutcome.Failure, GetClaimOutcome(outcome, Fido2ClaimIds.Fido2AssertionOrigin));
    }


    /// <summary>
    /// A cross-origin ceremony the relying party does not allow fails
    /// <see cref="Fido2ClaimIds.Fido2AssertionCrossOrigin"/>, while the signature remains valid.
    /// </summary>
    [TestMethod]
    public async Task CrossOriginNotAllowedFailsCrossOriginClaimWithSignatureStillValid()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(
            ValidChallenge, ValidOrigin, crossOrigin: true, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyMintedAssertionAsync(oracle.CredentialPublicKey, minted, allowCrossOrigin: false);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.AreEqual(ClaimOutcome.Failure, GetClaimOutcome(outcome, Fido2ClaimIds.Fido2AssertionCrossOrigin));
    }


    /// <summary>
    /// A signature counter equal to the stored value (neither increasing nor implementing the
    /// counter) is a possible-clone signal, not a failure: the claim is
    /// <see cref="ClaimOutcome.Inconclusive"/> and the overall outcome stays acceptable — relying
    /// party policy, not this verifier, decides how to react.
    /// </summary>
    [TestMethod]
    public async Task NonIncreasingSignCountYieldsInconclusiveButStaysAcceptable()
    {
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(
            ValidChallenge, ValidOrigin, signCount: 5, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyMintedAssertionAsync(oracle.CredentialPublicKey, minted, storedSignCount: 5);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsTrue(outcome.IsAcceptable);
        Assert.AreEqual(ClaimOutcome.Inconclusive, GetClaimOutcome(outcome, Fido2ClaimIds.Fido2AssertionSignCountRegression));
    }


    /// <summary>Maps an oracle factory name (from <see cref="AssertionAlgorithms"/>) to the oracle it builds.</summary>
    private static Fido2AssertionOracle CreateOracle(string oracleFactoryName) => oracleFactoryName switch
    {
        nameof(Fido2AssertionOracle.CreateEs256) => Fido2AssertionOracle.CreateEs256(),
        nameof(Fido2AssertionOracle.CreateEs384) => Fido2AssertionOracle.CreateEs384(),
        nameof(Fido2AssertionOracle.CreateEs512) => Fido2AssertionOracle.CreateEs512(),
        nameof(Fido2AssertionOracle.CreateEs256K) => Fido2AssertionOracle.CreateEs256K(),
        nameof(Fido2AssertionOracle.CreateRs256) => Fido2AssertionOracle.CreateRs256(),
        nameof(Fido2AssertionOracle.CreateRs384) => Fido2AssertionOracle.CreateRs384(),
        nameof(Fido2AssertionOracle.CreateRs512) => Fido2AssertionOracle.CreateRs512(),
        nameof(Fido2AssertionOracle.CreatePs256) => Fido2AssertionOracle.CreatePs256(),
        nameof(Fido2AssertionOracle.CreatePs384) => Fido2AssertionOracle.CreatePs384(),
        nameof(Fido2AssertionOracle.CreatePs512) => Fido2AssertionOracle.CreatePs512(),
        nameof(Fido2AssertionOracle.CreateEdDsa) => Fido2AssertionOracle.CreateEdDsa(),
        _ => throw new ArgumentException($"Unknown oracle factory '{oracleFactoryName}'.", nameof(oracleFactoryName))
    };


    /// <summary>
    /// Reconstructs an <see cref="AssertionCeremonyInput"/> from <paramref name="minted"/>'s wire
    /// bytes ONLY — via <see cref="ClientDataJsonReader"/> and <see cref="AuthenticatorDataReader"/>,
    /// never from the oracle's in-memory state — and runs <see cref="Fido2AssertionVerifier"/>
    /// against it. Every parameter overrides one relying-party expectation so a single test can
    /// isolate one failure axis.
    /// </summary>
    internal async Task<Fido2AssertionOutcome> VerifyMintedAssertionAsync(
        CoseKey credentialPublicKey,
        MintedAssertion minted,
        byte[]? signatureOverride = null,
        byte[]? authenticatorDataOverride = null,
        string expectedChallenge = ValidChallenge,
        IReadOnlySet<string>? expectedOrigins = null,
        byte[]? expectedRpIdHash = null,
        bool allowCrossOrigin = false,
        UserVerificationRequirement userVerification = UserVerificationRequirement.Required,
        uint storedSignCount = 0)
    {
        byte[] authenticatorDataBytes = authenticatorDataOverride ?? minted.AuthenticatorData;
        ReadOnlyMemory<byte> signature = signatureOverride is not null
            ? signatureOverride
            : minted.Signature.AsReadOnlyMemory();

        ClientData clientData = ClientDataJsonReader.Read(minted.ClientDataJson);
        AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(authenticatorDataBytes, Fido2TestVectors.TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        //WebAuthn L3 section 7.2 step 6 requires a response user handle identifying the account on
        //the discoverable-credential path this helper exercises (no allowlist is supplied below);
        //every call site here gets a matching response/stored pair so the algorithm- and policy-axis
        //tests this helper serves stay focused on their own claim, per Fido2AssertionChecks.CheckAssertionUserHandle.
        UserHandle responseUserHandle = UserHandle.Create(DefaultUserHandleBytes, BaseMemoryPool.Shared);
        UserHandle storedUserHandle = UserHandle.Create(DefaultUserHandleBytes, BaseMemoryPool.Shared);

        using var ceremonyInput = new AssertionCeremonyInput
        {
            ClientData = clientData,
            AuthenticatorData = authenticatorData,
            ExpectedChallenge = expectedChallenge,
            ExpectedOrigins = expectedOrigins ?? new HashSet<string> { ValidOrigin },
            ExpectedRpIdHash = Fido2TestVectors.WrapRpIdHash(expectedRpIdHash ?? Fido2TestVectors.CreateRpIdHash(), BaseMemoryPool.Shared),
            AllowCrossOrigin = allowCrossOrigin,
            UserVerification = userVerification,
            StoredSignCount = storedSignCount,
            StoredUvInitialized = true,
            ResponseUserHandle = responseUserHandle,
            StoredUserHandle = storedUserHandle
        };

        return await Fido2AssertionVerifier.VerifyAsync(
            credentialPublicKey,
            signature,
            authenticatorDataBytes,
            minted.ClientDataJson,
            ceremonyInput,
            correlationId: "fido2-assertion-verifier-test-correlation",
            pool: BaseMemoryPool.Shared,
            timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Finds the outcome of the claim carrying <paramref name="claimId"/> in <paramref name="outcome"/>.</summary>
    private static ClaimOutcome GetClaimOutcome(Fido2AssertionOutcome outcome, ClaimId claimId)
    {
        foreach(Claim claim in outcome.Claims.Claims)
        {
            if(claim.Id.Code == claimId.Code)
            {
                return claim.Outcome;
            }
        }

        throw new InvalidOperationException($"Claim '{claimId}' was not present in the result.");
    }


    /// <summary>Determines whether any claim in <paramref name="outcome"/> carries <see cref="ClaimOutcome.Failure"/>.</summary>
    private static bool HasFailureClaim(Fido2AssertionOutcome outcome)
    {
        foreach(Claim claim in outcome.Claims.Claims)
        {
            if(claim.Outcome == ClaimOutcome.Failure)
            {
                return true;
            }
        }

        return false;
    }
}
