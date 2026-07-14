using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Firewalled end-to-end tests for the <c>appid</c> extension's rpIdHash special logic in
/// <see cref="Fido2AssertionChecks.CheckAssertionRpIdHash"/>, driven through the real
/// <see cref="Fido2AssertionVerifier.VerifyAsync(CoseKey,ReadOnlyMemory{byte},ReadOnlyMemory{byte},ReadOnlyMemory{byte},AssertionCeremonyInput,string,System.Buffers.MemoryPool{byte},TimeProvider,CancellationToken)"/>
/// path and <see cref="Fido2AssertionOracle"/>.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-appid-extension">W3C Web Authentication Level
/// 3, section 10.1.1: FIDO AppID Extension (appid)</see>: "If true, the AppID was used and thus,
/// when verifying the assertion, the Relying Party MUST expect the rpIdHash to be the hash of the
/// AppID, not the RP ID." Every test reconstructs the ceremony input from
/// <see cref="Fido2AssertionOracle"/>'s wire bytes only, mirroring
/// <see cref="Fido2AssertionVerifierTests"/>'s firewall discipline; the oracle's existing
/// <c>rpIdHash</c> mint parameter already expresses the AppID-hash case, so no oracle change is
/// needed.
/// </remarks>
[TestClass]
internal sealed class Fido2AppIdRpIdHashTests
{
    /// <summary>The base64url-encoded challenge a valid ceremony embeds and expects.</summary>
    private const string ValidChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";

    /// <summary>The relying party origin a valid ceremony embeds and expects.</summary>
    private const string ValidOrigin = "https://relyingparty.example";

    /// <summary>The legacy FIDO AppID the relying party previously used with the U2F JavaScript API.</summary>
    private const string LegacyAppId = "https://legacy.example.com";

    /// <summary>A default user handle every ceremony input here uses for both sides, so <see cref="Fido2ClaimIds.Fido2AssertionUserHandle"/> succeeds and each test stays focused on the rpIdHash claim.</summary>
    private static byte[] DefaultUserHandleBytes { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// An assertion minted with <c>authData.rpIdHash</c> equal to the SHA-256 of the relying
    /// party's legacy AppID, and a client extension output <c>{"appid":true}</c> — decoded via the
    /// real <see cref="ClientExtensionOutputsJsonReader"/> — succeeds
    /// <see cref="Fido2ClaimIds.Fido2AssertionRpIdHash"/> and the outcome is acceptable.
    /// </summary>
    [TestMethod]
    public async Task AppIdTrueWithMatchingAppIdHashSucceedsAndIsAcceptable()
    {
        byte[] appIdHash = ComputeAppIdHash();
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(
            ValidChallenge, ValidOrigin, rpIdHash: appIdHash, cancellationToken: TestContext.CancellationToken);

        IReadOnlyList<Fido2ExtensionOutput> clientExtensionOutputs = ClientExtensionOutputsJsonReader.Read(BuildAppIdClientExtensionResultsJson(appid: true));
        bool appIdExtensionOutput = DecodeBooleanExtensionOutput(clientExtensionOutputs, "appid");

        Fido2AssertionOutcome outcome = await VerifyMintedAssertionAsync(
            oracle.CredentialPublicKey, minted, appIdExtensionOutput, expectedAppIdHash: appIdHash);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsTrue(outcome.IsAcceptable);
        Assert.AreEqual(ClaimOutcome.Success, GetClaimOutcome(outcome, Fido2ClaimIds.Fido2AssertionRpIdHash));
    }


    /// <summary>
    /// <c>appid</c> reported <see langword="true"/>, but <c>authData.rpIdHash</c> carries the RP ID
    /// hash rather than the AppID hash, fails <see cref="Fido2ClaimIds.Fido2AssertionRpIdHash"/>:
    /// once <c>appid</c> is asserted, the RP ID hash is no longer an acceptable comparand.
    /// </summary>
    [TestMethod]
    public async Task AppIdTrueButAuthDataCarriesRpIdHashFailsRpIdHashClaim()
    {
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(
            ValidChallenge, ValidOrigin, rpIdHash: rpIdHash, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyMintedAssertionAsync(
            oracle.CredentialPublicKey, minted, appIdExtensionOutput: true, expectedAppIdHash: ComputeAppIdHash(), expectedRpIdHash: rpIdHash);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.AreEqual(ClaimOutcome.Failure, GetClaimOutcome(outcome, Fido2ClaimIds.Fido2AssertionRpIdHash));
    }


    /// <summary>
    /// <c>appid</c> reported <see langword="true"/> with no <see cref="AssertionCeremonyInput.ExpectedAppIdHash"/>
    /// configured fails closed: the relying party asserted an AppID output it never configured a
    /// hash for, so there is nothing safe to compare against.
    /// </summary>
    [TestMethod]
    public async Task AppIdTrueWithNoConfiguredExpectedAppIdHashFailsClosed()
    {
        byte[] appIdHash = ComputeAppIdHash();
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(
            ValidChallenge, ValidOrigin, rpIdHash: appIdHash, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyMintedAssertionAsync(
            oracle.CredentialPublicKey, minted, appIdExtensionOutput: true, expectedAppIdHash: null);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.AreEqual(ClaimOutcome.Failure, GetClaimOutcome(outcome, Fido2ClaimIds.Fido2AssertionRpIdHash));
    }


    /// <summary>
    /// No <c>appid</c> output at all, with <c>authData.rpIdHash</c> equal to the expected RP ID
    /// hash, is the unchanged happy path: <see cref="Fido2ClaimIds.Fido2AssertionRpIdHash"/>
    /// succeeds exactly as it did before this wave.
    /// </summary>
    [TestMethod]
    public async Task AppIdAbsentWithMatchingRpIdHashIsUnchangedHappyPath()
    {
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();
        using Fido2AssertionOracle oracle = Fido2AssertionOracle.CreateEs256();
        using MintedAssertion minted = await oracle.MintAsync(
            ValidChallenge, ValidOrigin, rpIdHash: rpIdHash, cancellationToken: TestContext.CancellationToken);

        Fido2AssertionOutcome outcome = await VerifyMintedAssertionAsync(
            oracle.CredentialPublicKey, minted, appIdExtensionOutput: false, expectedAppIdHash: null, expectedRpIdHash: rpIdHash);

        Assert.IsTrue(outcome.SignatureValid);
        Assert.IsTrue(outcome.IsAcceptable);
        Assert.AreEqual(ClaimOutcome.Success, GetClaimOutcome(outcome, Fido2ClaimIds.Fido2AssertionRpIdHash));
    }


    /// <summary>Computes the SHA-256 hash of <see cref="LegacyAppId"/>, the value <c>authData.rpIdHash</c> carries when a legacy U2F credential asserted via <c>appid</c>.</summary>
    private static byte[] ComputeAppIdHash() => SHA256.HashData(Encoding.UTF8.GetBytes(LegacyAppId));


    /// <summary>Builds a minimal <c>clientExtensionResults</c> JSON object carrying only the <c>appid</c> boolean.</summary>
    private static ReadOnlyMemory<byte> BuildAppIdClientExtensionResultsJson(bool appid) =>
        Encoding.UTF8.GetBytes($$"""{"appid":{{(appid ? "true" : "false")}}}""");


    /// <summary>Decodes the still-encoded JSON boolean value of the entry carrying <paramref name="identifier"/> in <paramref name="outputs"/>.</summary>
    private static bool DecodeBooleanExtensionOutput(IReadOnlyList<Fido2ExtensionOutput> outputs, string identifier)
    {
        foreach(Fido2ExtensionOutput output in outputs)
        {
            if(string.Equals(output.Identifier, identifier, StringComparison.Ordinal))
            {
                Utf8JsonReader reader = new(output.Value.Span);
                reader.Read();

                return reader.GetBoolean();
            }
        }

        throw new InvalidOperationException($"Extension output '{identifier}' was not present.");
    }


    /// <summary>
    /// Reconstructs an <see cref="AssertionCeremonyInput"/> from <paramref name="minted"/>'s wire
    /// bytes only — via <see cref="ClientDataJsonReader"/> and <see cref="AuthenticatorDataReader"/>
    /// — and runs <see cref="Fido2AssertionVerifier"/> against it.
    /// </summary>
    /// <param name="credentialPublicKey">The oracle's stored credential public key.</param>
    /// <param name="minted">The minted wire-shaped assertion.</param>
    /// <param name="appIdExtensionOutput">The decoded <c>appid</c> client extension output boolean.</param>
    /// <param name="expectedAppIdHash">The relying party's configured AppID hash, or <see langword="null"/>.</param>
    /// <param name="expectedRpIdHash">The relying party's expected RP ID hash. Defaults to a fresh valid hash unrelated to any AppID hash.</param>
    private async Task<Fido2AssertionOutcome> VerifyMintedAssertionAsync(
        CoseKey credentialPublicKey,
        MintedAssertion minted,
        bool appIdExtensionOutput,
        byte[]? expectedAppIdHash,
        byte[]? expectedRpIdHash = null)
    {
        ClientData clientData = ClientDataJsonReader.Read(minted.ClientDataJson);
        AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(
            minted.AuthenticatorData, Fido2TestVectors.TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        UserHandle responseUserHandle = UserHandle.Create(DefaultUserHandleBytes, BaseMemoryPool.Shared);
        UserHandle storedUserHandle = UserHandle.Create(DefaultUserHandleBytes, BaseMemoryPool.Shared);

        using var ceremonyInput = new AssertionCeremonyInput
        {
            ClientData = clientData,
            AuthenticatorData = authenticatorData,
            ExpectedChallenge = ValidChallenge,
            ExpectedOrigins = new HashSet<string> { ValidOrigin },
            ExpectedRpIdHash = Fido2TestVectors.WrapRpIdHash(expectedRpIdHash ?? Fido2TestVectors.CreateRpIdHash(), BaseMemoryPool.Shared),
            UserVerification = UserVerificationRequirement.Required,
            StoredSignCount = 0,
            StoredUvInitialized = true,
            ResponseUserHandle = responseUserHandle,
            StoredUserHandle = storedUserHandle,
            AppIdExtensionOutput = appIdExtensionOutput,
            ExpectedAppIdHash = expectedAppIdHash is null ? null : Fido2TestVectors.WrapRpIdHash(expectedAppIdHash, BaseMemoryPool.Shared)
        };

        return await Fido2AssertionVerifier.VerifyAsync(
            credentialPublicKey,
            minted.Signature.AsReadOnlyMemory(),
            minted.AuthenticatorData,
            minted.ClientDataJson,
            ceremonyInput,
            correlationId: "fido2-appid-rpidhash-test-correlation",
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
}
