using Verifiable.Core.Assessment;
using Verifiable.Fido2;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="AppIdExcludeExtensionProcessor"/>: the <c>appidExclude</c> extension's
/// registration-side output processing.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-appid-exclude-extension">W3C Web
/// Authentication Level 3, section 10.1.2: FIDO AppID Exclusion Extension (appidExclude)</see>. The
/// unit-level tests construct a <see cref="Fido2ExtensionOutput"/> directly, mirroring
/// <see cref="Fido2ExtensionProcessingTests"/>'s style; the firewalled test decodes real
/// <c>clientExtensionResults</c> wire bytes through the actual
/// <see cref="ClientExtensionOutputsJsonReader"/> and runs the registered processor through a real
/// <see cref="ClaimIssuer{TInput}"/> executing <see cref="Fido2ValidationProfiles.RegistrationRules"/>.
/// </remarks>
[TestClass]
internal sealed class AppIdExcludeExtensionProcessorTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A registration ceremony whose <c>appidExclude</c> output is <see langword="true"/> — the
    /// only value the specification defines — reports
    /// <see cref="Fido2ClaimIds.Fido2RegistrationAppIdExclude"/> as <see cref="ClaimOutcome.Success"/>.
    /// </summary>
    [TestMethod]
    public async Task AppIdExcludeTrueSucceeds()
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(Encode("true"));

        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationAppIdExclude));
        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>
    /// A registration ceremony whose <c>appidExclude</c> output decodes cleanly but is
    /// <see langword="false"/> — a value the specification never defines — fails
    /// <see cref="Fido2ClaimIds.Fido2RegistrationAppIdExclude"/>, a defensive check against a
    /// non-conformant or adversarial client.
    /// </summary>
    [TestMethod]
    public async Task AppIdExcludeFalseFails()
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(Encode("false"));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationAppIdExclude));
    }


    /// <summary>
    /// A registration ceremony whose <c>appidExclude</c> output is not a boolean at all fails
    /// closed: the ceremony-level extension-processing claim reports
    /// <see cref="ClaimOutcome.Failure"/> because the processor throws.
    /// </summary>
    [TestMethod]
    public async Task AppIdExcludeNonBooleanFailsCeremonyClaimClosed()
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(Encode("\"true\""));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>
    /// A registration ceremony whose <c>appidExclude</c> output carries content trailing its
    /// boolean value fails closed.
    /// </summary>
    [TestMethod]
    public async Task AppIdExcludeTrailingContentFailsCeremonyClaimClosed()
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(Encode("true true"));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>
    /// Firewalled: a real <c>clientExtensionResults</c> JSON document carrying
    /// <c>{"appidExclude":true}</c>, decoded through the actual
    /// <see cref="ClientExtensionOutputsJsonReader"/>, run through the real
    /// <see cref="Fido2ValidationProfiles.RegistrationRules"/>, reports
    /// <see cref="Fido2ClaimIds.Fido2RegistrationAppIdExclude"/> and the unconditional
    /// <see cref="Fido2ClaimIds.Fido2RegistrationExtensionOutputs"/> ceremony claim as
    /// <see cref="ClaimOutcome.Success"/>.
    /// </summary>
    [TestMethod]
    public async Task FirewalledWireJsonThroughRealReaderSucceeds()
    {
        IReadOnlyList<Fido2ExtensionOutput> outputs = ClientExtensionOutputsJsonReader.Read(
            Encode("""{"appidExclude":true}"""));

        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            (WellKnownWebAuthnExtensionIdentifiers.AppIdExclude, AppIdExcludeExtensionProcessor.ProcessRegistrationOutput));

        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientExtensionOutputs: outputs,
            extensionOutputProcessor: selector);

        ClaimIssueResult result = await IssueRegistrationClaimsAsync(input);

        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationAppIdExclude));
        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>
    /// Runs <see cref="Fido2ValidationProfiles.RegistrationRules"/> through a real
    /// <see cref="ClaimIssuer{TInput}"/> against a ceremony carrying a single <c>appidExclude</c>
    /// client extension output built directly from <paramref name="appIdExcludeOutputJson"/>, with
    /// <see cref="AppIdExcludeExtensionProcessor.ProcessRegistrationOutput"/> registered.
    /// </summary>
    private async Task<ClaimIssueResult> IssueRegistrationClaimsAsync(ReadOnlyMemory<byte> appIdExcludeOutputJson)
    {
        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            (WellKnownWebAuthnExtensionIdentifiers.AppIdExclude, AppIdExcludeExtensionProcessor.ProcessRegistrationOutput));

        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientExtensionOutputs: [new Fido2ExtensionOutput(WellKnownWebAuthnExtensionIdentifiers.AppIdExclude, appIdExcludeOutputJson)],
            extensionOutputProcessor: selector);

        //Awaited (not returned directly) so the `using` above does not dispose the pooled ceremony
        //input's carriers before the ceremony's own claim-generation task has finished reading them.
        return await IssueRegistrationClaimsAsync(input);
    }


    /// <summary>Runs <see cref="Fido2ValidationProfiles.RegistrationRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    private Task<ClaimIssueResult> IssueRegistrationClaimsAsync(RegistrationCeremonyInput input)
    {
        var issuer = new ClaimIssuer<RegistrationCeremonyInput>("appidexclude-extension-processor-test", Fido2ValidationProfiles.RegistrationRules());

        return issuer.GenerateClaimsAsync(input, "appidexclude-extension-processor-test-correlation", TestContext.CancellationToken).AsTask();
    }


    /// <summary>Finds the outcome of the claim carrying <paramref name="claimId"/> in <paramref name="result"/>.</summary>
    private static ClaimOutcome GetOutcome(ClaimIssueResult result, ClaimId claimId)
    {
        foreach(Claim claim in result.Claims)
        {
            if(claim.Id.Code == claimId.Code)
            {
                return claim.Outcome;
            }
        }

        throw new InvalidOperationException($"Claim '{claimId}' was not present in the result.");
    }
}
