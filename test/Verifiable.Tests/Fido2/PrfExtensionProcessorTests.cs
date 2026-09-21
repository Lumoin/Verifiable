using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.Fido2;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="PrfExtensionProcessor"/>: the <c>prf</c> extension's RP-side output
/// processing, which reports only whether the passkey supports <c>prf</c> and whether a result was
/// present, never the secret bytes underneath <c>results</c>.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-prf-extension">W3C Web Authentication Level 3,
/// section 10.1.4: Pseudo-random function extension (prf)</see>. Mirrors
/// <see cref="LargeBlobExtensionProcessorTests"/>'s style: the unit-level tests construct a
/// <see cref="Fido2ExtensionOutput"/> directly; the firewalled tests decode real
/// <c>clientExtensionResults</c> wire bytes through the actual
/// <see cref="ClientExtensionOutputsJsonReader"/> and run the registered processor through a real
/// <see cref="ClaimIssuer{TInput}"/> executing <see cref="Fido2ValidationProfiles.RegistrationRules"/>
/// / <see cref="Fido2ValidationProfiles.AssertionRules"/>.
/// </remarks>
[TestClass]
internal sealed class PrfExtensionProcessorTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A registration ceremony whose <c>prf</c> output carries <c>{"enabled":true}</c> reports
    /// <see cref="Fido2ClaimIds.Fido2RegistrationPrfEnabled"/> as <see cref="ClaimOutcome.Success"/>
    /// with <see cref="PrfEnabledContext.Enabled"/> <see langword="true"/>, and
    /// <see cref="Fido2ClaimIds.Fido2RegistrationPrfResultsPresent"/> as
    /// <see cref="ClaimOutcome.NotApplicable"/> — section 10.1.4's own "outputs may not be
    /// available during registration".
    /// </summary>
    [TestMethod]
    public async Task RegistrationEnabledTrueWithNoResultsReportsEnabledAndResultsNotApplicable()
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(Fido2TestVectors.Encode("""{"enabled":true}"""));

        Claim enabledClaim = GetClaim(result, Fido2ClaimIds.Fido2RegistrationPrfEnabled);
        Assert.AreEqual(ClaimOutcome.Success, enabledClaim.Outcome);
        Assert.IsTrue(((PrfEnabledContext)enabledClaim.Context).Enabled);

        Assert.AreEqual(ClaimOutcome.NotApplicable, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationPrfResultsPresent));
    }


    /// <summary>
    /// A registration ceremony whose <c>prf</c> output carries
    /// <c>{"enabled":true,"results":{"first":"..."}}</c> reports both
    /// <see cref="Fido2ClaimIds.Fido2RegistrationPrfEnabled"/> and
    /// <see cref="Fido2ClaimIds.Fido2RegistrationPrfResultsPresent"/> as
    /// <see cref="ClaimOutcome.Success"/>.
    /// </summary>
    [TestMethod]
    public async Task RegistrationEnabledTrueWithResultsReportsBothSuccess()
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(
            Fido2TestVectors.Encode("""{"enabled":true,"results":{"first":"AQIDBA"}}"""));

        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationPrfEnabled));

        Claim resultsClaim = GetClaim(result, Fido2ClaimIds.Fido2RegistrationPrfResultsPresent);
        Assert.AreEqual(ClaimOutcome.Success, resultsClaim.Outcome);
        Assert.IsTrue(((PrfResultsPresentContext)resultsClaim.Context).HasResults);
    }


    /// <summary>
    /// A registration ceremony whose <c>prf</c> output carries <c>{"enabled":false}</c> still
    /// reports <see cref="ClaimOutcome.Success"/> — <see langword="false"/> is a legitimate
    /// authenticator state, not a protocol violation — with the decoded value recorded.
    /// </summary>
    [TestMethod]
    public async Task RegistrationEnabledFalseSucceedsAndRecordsValue()
    {
        Claim claim = await IssueSingleRegistrationExtensionClaimAsync(
            Fido2ClaimIds.Fido2RegistrationPrfEnabled,
            Fido2TestVectors.Encode("""{"enabled":false}"""));

        Assert.AreEqual(ClaimOutcome.Success, claim.Outcome);
        Assert.IsFalse(((PrfEnabledContext)claim.Context).Enabled);
    }


    /// <summary>
    /// An assertion ceremony whose <c>prf</c> output carries <c>{"results":{"first":"..."}}</c>
    /// reports <see cref="Fido2ClaimIds.Fido2AssertionPrfResultsPresent"/> as
    /// <see cref="ClaimOutcome.Success"/> with <see cref="PrfResultsPresentContext.HasResults"/>
    /// <see langword="true"/>.
    /// </summary>
    [TestMethod]
    public async Task AssertionWithResultsReportsResultsPresentSuccess()
    {
        Claim claim = await IssueSingleAssertionExtensionClaimAsync(
            Fido2ClaimIds.Fido2AssertionPrfResultsPresent,
            Fido2TestVectors.Encode("""{"results":{"first":"AQIDBA"}}"""));

        Assert.AreEqual(ClaimOutcome.Success, claim.Outcome);
        Assert.IsTrue(((PrfResultsPresentContext)claim.Context).HasResults);
    }


    /// <summary>
    /// An assertion ceremony whose <c>prf</c> output is an empty object — the specification's own
    /// "no applicable PRF input" shape — reports
    /// <see cref="Fido2ClaimIds.Fido2AssertionPrfResultsPresent"/> as
    /// <see cref="ClaimOutcome.NotApplicable"/>, never <see cref="ClaimOutcome.Failure"/>.
    /// </summary>
    [TestMethod]
    public async Task AssertionWithoutResultsReportsResultsNotApplicable()
    {
        Claim claim = await IssueSingleAssertionExtensionClaimAsync(Fido2ClaimIds.Fido2AssertionPrfResultsPresent, Fido2TestVectors.Encode("{}"));

        Assert.AreEqual(ClaimOutcome.NotApplicable, claim.Outcome);
    }


    /// <summary>
    /// A results-bearing <c>prf</c> output yields a claim whose context states, in a single boolean,
    /// that a result was present — <see cref="PrfResultsPresentContext"/> declares no member a
    /// caller could read for the secret bytes, so there is nothing further to assert here beyond the
    /// one predicate this test reads through the claim's public members.
    /// </summary>
    [TestMethod]
    public async Task ResultsPresentClaimCarriesThePresenceBooleanAndNoBytePayload()
    {
        Claim claim = await IssueSingleAssertionExtensionClaimAsync(
            Fido2ClaimIds.Fido2AssertionPrfResultsPresent,
            Fido2TestVectors.Encode("""{"results":{"first":"AQIDBA","second":"BQYHCA"}}"""));

        PrfResultsPresentContext context = (PrfResultsPresentContext)claim.Context;
        Assert.IsTrue(context.HasResults);
    }


    /// <summary>A registration <c>prf</c> output missing the required <c>enabled</c> member fails closed.</summary>
    [TestMethod]
    public async Task RegistrationMissingEnabledMemberFailsCeremonyClaimClosed()
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(Fido2TestVectors.Encode("{}"));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>A registration <c>prf</c> output that is not a JSON object at all fails closed.</summary>
    [TestMethod]
    public async Task RegistrationNonObjectOutputFailsCeremonyClaimClosed()
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(Fido2TestVectors.Encode("true"));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>A non-boolean <c>enabled</c> member fails closed.</summary>
    [TestMethod]
    public async Task RegistrationEnabledNotBooleanFailsCeremonyClaimClosed()
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(Fido2TestVectors.Encode("""{"enabled":"yes"}"""));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>A repeated <c>enabled</c> member is rejected as malformed — no single unambiguous value.</summary>
    [TestMethod]
    public async Task RegistrationRepeatedEnabledMemberFailsCeremonyClaimClosed()
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(Fido2TestVectors.Encode("""{"enabled":true,"enabled":false}"""));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>A <c>results</c> member that is not a JSON object fails closed.</summary>
    [TestMethod]
    public async Task RegistrationResultsNotObjectFailsCeremonyClaimClosed()
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(Fido2TestVectors.Encode("""{"enabled":true,"results":"nope"}"""));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>A <c>results</c> object missing its required <c>first</c> member fails closed.</summary>
    [TestMethod]
    public async Task RegistrationResultsMissingFirstFailsCeremonyClaimClosed()
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(Fido2TestVectors.Encode("""{"enabled":true,"results":{}}"""));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>A <c>results.first</c> member that is not a string fails closed.</summary>
    [TestMethod]
    public async Task RegistrationResultsFirstNotStringFailsCeremonyClaimClosed()
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(Fido2TestVectors.Encode("""{"enabled":true,"results":{"first":123}}"""));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>An assertion <c>results</c> member that is not a JSON object fails closed.</summary>
    [TestMethod]
    public async Task AssertionResultsNotObjectFailsCeremonyClaimClosed()
    {
        ClaimIssueResult result = await IssueAssertionClaimsAsync(Fido2TestVectors.Encode("""{"results":"nope"}"""));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2AssertionExtensionOutputs));
    }


    /// <summary>An assertion <c>results</c> object missing its required <c>first</c> member fails closed.</summary>
    [TestMethod]
    public async Task AssertionResultsMissingFirstFailsCeremonyClaimClosed()
    {
        ClaimIssueResult result = await IssueAssertionClaimsAsync(Fido2TestVectors.Encode("""{"results":{}}"""));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2AssertionExtensionOutputs));
    }


    /// <summary>A cancelled token stops <see cref="PrfExtensionProcessor.ProcessRegistrationOutput"/> before it decodes anything.</summary>
    [TestMethod]
    public async Task ProcessRegistrationOutputHonoursAnAlreadyCancelledToken()
    {
        ExtensionOutputProcessingRequest request = new(
            WellKnownWebAuthnExtensionIdentifiers.Prf,
            Fido2TestVectors.Encode("""{"enabled":true}"""),
            authenticatorOutputCbor: null,
            BaseMemoryPool.Shared);

        _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(() =>
            PrfExtensionProcessor.ProcessRegistrationOutput(request, new CancellationToken(true)).AsTask());
    }


    /// <summary>A cancelled token stops <see cref="PrfExtensionProcessor.ProcessAssertionOutput"/> before it decodes anything.</summary>
    [TestMethod]
    public async Task ProcessAssertionOutputHonoursAnAlreadyCancelledToken()
    {
        ExtensionOutputProcessingRequest request = new(
            WellKnownWebAuthnExtensionIdentifiers.Prf,
            Fido2TestVectors.Encode("""{"results":{"first":"AQIDBA"}}"""),
            authenticatorOutputCbor: null,
            BaseMemoryPool.Shared);

        _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(() =>
            PrfExtensionProcessor.ProcessAssertionOutput(request, new CancellationToken(true)).AsTask());
    }


    /// <summary>
    /// Firewalled: a real <c>clientExtensionResults</c> JSON document carrying
    /// <c>{"prf":{"enabled":true,"results":{"first":"..."}}}</c>, decoded through the actual
    /// <see cref="ClientExtensionOutputsJsonReader"/>, run through the real
    /// <see cref="Fido2ValidationProfiles.RegistrationRules"/>, reports
    /// <see cref="Fido2ClaimIds.Fido2RegistrationPrfEnabled"/>,
    /// <see cref="Fido2ClaimIds.Fido2RegistrationPrfResultsPresent"/> and the unconditional
    /// <see cref="Fido2ClaimIds.Fido2RegistrationExtensionOutputs"/> ceremony claim as
    /// <see cref="ClaimOutcome.Success"/>.
    /// </summary>
    [TestMethod]
    public async Task FirewalledRegistrationWireJsonThroughRealReaderSucceeds()
    {
        IReadOnlyList<Fido2ExtensionOutput> outputs = ClientExtensionOutputsJsonReader.Read(
            Fido2TestVectors.Encode("""{"prf":{"enabled":true,"results":{"first":"AQIDBA"}}}"""));

        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            (WellKnownWebAuthnExtensionIdentifiers.Prf, PrfExtensionProcessor.ProcessRegistrationOutput));

        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientExtensionOutputs: outputs,
            extensionOutputProcessor: selector);

        ClaimIssueResult result = await IssueRegistrationClaimsAsync(input);

        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationPrfEnabled));
        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationPrfResultsPresent));
        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>
    /// Firewalled: a real <c>clientExtensionResults</c> JSON document carrying
    /// <c>{"prf":{"results":{"first":"..."}}}</c>, decoded through the actual
    /// <see cref="ClientExtensionOutputsJsonReader"/>, reports
    /// <see cref="Fido2ClaimIds.Fido2AssertionPrfResultsPresent"/> and the unconditional
    /// <see cref="Fido2ClaimIds.Fido2AssertionExtensionOutputs"/> ceremony claim as
    /// <see cref="ClaimOutcome.Success"/>.
    /// </summary>
    [TestMethod]
    public async Task FirewalledAssertionWireJsonThroughRealReaderSucceeds()
    {
        IReadOnlyList<Fido2ExtensionOutput> outputs = ClientExtensionOutputsJsonReader.Read(
            Fido2TestVectors.Encode("""{"prf":{"results":{"first":"AQIDBA"}}}"""));

        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            (WellKnownWebAuthnExtensionIdentifiers.Prf, PrfExtensionProcessor.ProcessAssertionOutput));

        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientExtensionOutputs: outputs,
            extensionOutputProcessor: selector);

        ClaimIssueResult result = await IssueAssertionClaimsAsync(input);

        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2AssertionPrfResultsPresent));
        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2AssertionExtensionOutputs));
    }


    /// <summary>
    /// Issues registration claims for a ceremony carrying a single <c>prf</c> client extension
    /// output built directly from <paramref name="prfOutputJson"/>, and returns the claim matching
    /// <paramref name="claimId"/>.
    /// </summary>
    private async Task<Claim> IssueSingleRegistrationExtensionClaimAsync(ClaimId claimId, ReadOnlyMemory<byte> prfOutputJson)
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(prfOutputJson);

        return GetClaim(result, claimId);
    }


    /// <summary>
    /// Runs <see cref="Fido2ValidationProfiles.RegistrationRules"/> through a real
    /// <see cref="ClaimIssuer{TInput}"/> against a ceremony carrying a single <c>prf</c> client
    /// extension output built directly from <paramref name="prfOutputJson"/>, with
    /// <see cref="PrfExtensionProcessor.ProcessRegistrationOutput"/> registered.
    /// </summary>
    private async Task<ClaimIssueResult> IssueRegistrationClaimsAsync(ReadOnlyMemory<byte> prfOutputJson)
    {
        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            (WellKnownWebAuthnExtensionIdentifiers.Prf, PrfExtensionProcessor.ProcessRegistrationOutput));

        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientExtensionOutputs: [new Fido2ExtensionOutput(WellKnownWebAuthnExtensionIdentifiers.Prf, prfOutputJson)],
            extensionOutputProcessor: selector);

        //Awaited (not returned directly) so the `using` above does not dispose the pooled ceremony
        //input's carriers before the ceremony's own claim-generation task has finished reading them.
        return await IssueRegistrationClaimsAsync(input);
    }


    /// <summary>Runs <see cref="Fido2ValidationProfiles.RegistrationRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    private Task<ClaimIssueResult> IssueRegistrationClaimsAsync(RegistrationCeremonyInput input)
    {
        var issuer = new ClaimIssuer<RegistrationCeremonyInput>("prf-extension-processor-test", Fido2ValidationProfiles.RegistrationRules(), new FakeTimeProvider(TestClock.CanonicalEpoch));

        return issuer.GenerateClaimsAsync(input, "prf-extension-processor-test-correlation", TestContext.CancellationToken).AsTask();
    }


    /// <summary>
    /// Issues assertion claims for a ceremony carrying a single <c>prf</c> client extension output
    /// built directly from <paramref name="prfOutputJson"/>, and returns the claim matching
    /// <paramref name="claimId"/>.
    /// </summary>
    private async Task<Claim> IssueSingleAssertionExtensionClaimAsync(ClaimId claimId, ReadOnlyMemory<byte> prfOutputJson)
    {
        ClaimIssueResult result = await IssueAssertionClaimsAsync(prfOutputJson);

        return GetClaim(result, claimId);
    }


    /// <summary>
    /// Runs <see cref="Fido2ValidationProfiles.AssertionRules"/> through a real
    /// <see cref="ClaimIssuer{TInput}"/> against a ceremony carrying a single <c>prf</c> client
    /// extension output built directly from <paramref name="prfOutputJson"/>, with
    /// <see cref="PrfExtensionProcessor.ProcessAssertionOutput"/> registered.
    /// </summary>
    private async Task<ClaimIssueResult> IssueAssertionClaimsAsync(ReadOnlyMemory<byte> prfOutputJson)
    {
        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            (WellKnownWebAuthnExtensionIdentifiers.Prf, PrfExtensionProcessor.ProcessAssertionOutput));

        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientExtensionOutputs: [new Fido2ExtensionOutput(WellKnownWebAuthnExtensionIdentifiers.Prf, prfOutputJson)],
            extensionOutputProcessor: selector);

        //Awaited (not returned directly) so the `using` above does not dispose the pooled ceremony
        //input's carriers before the ceremony's own claim-generation task has finished reading them.
        return await IssueAssertionClaimsAsync(input);
    }


    /// <summary>Runs <see cref="Fido2ValidationProfiles.AssertionRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    private Task<ClaimIssueResult> IssueAssertionClaimsAsync(AssertionCeremonyInput input)
    {
        var issuer = new ClaimIssuer<AssertionCeremonyInput>("prf-extension-processor-test", Fido2ValidationProfiles.AssertionRules(), new FakeTimeProvider(TestClock.CanonicalEpoch));

        return issuer.GenerateClaimsAsync(input, "prf-extension-processor-test-correlation", TestContext.CancellationToken).AsTask();
    }


    /// <summary>Finds the claim carrying <paramref name="claimId"/> in <paramref name="result"/>.</summary>
    private static Claim GetClaim(ClaimIssueResult result, ClaimId claimId)
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


    /// <summary>Finds the outcome of the claim carrying <paramref name="claimId"/> in <paramref name="result"/>.</summary>
    private static ClaimOutcome GetOutcome(ClaimIssueResult result, ClaimId claimId) => GetClaim(result, claimId).Outcome;
}
