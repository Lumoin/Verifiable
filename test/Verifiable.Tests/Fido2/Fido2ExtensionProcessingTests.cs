using Verifiable.Core.Assessment;
using Verifiable.Fido2;
using Verifiable.Tests.TestInfrastructure;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="Fido2ExtensionChecks"/> and <see cref="Fido2ExtensionSelectors"/>: the
/// WebAuthn L3 <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">section 9</see>
/// extension-output processing rule shared by both ceremonies, driven through a real
/// <see cref="ClaimIssuer{TInput}"/> running <see cref="Fido2ValidationProfiles.AssertionRules"/> /
/// <see cref="Fido2ValidationProfiles.RegistrationRules"/> on inputs built by
/// <see cref="Fido2CeremonyInputFactory"/>.
/// </summary>
[TestClass]
internal sealed class Fido2ExtensionProcessingTests
{
    /// <summary>The claim identifier <see cref="StubProcessorAsync"/> reports, distinct from every production claim range.</summary>
    private static ClaimId StubProcessorClaimId { get; } = ClaimId.Create(9200, "Fido2ExtensionProcessingTestStubProcessor");

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// An assertion ceremony carrying no extension outputs at all reports
    /// <see cref="Fido2ClaimIds.Fido2AssertionExtensionOutputs"/> as
    /// <see cref="ClaimOutcome.NotApplicable"/> and every other claim still succeeds — the section
    /// 9 "works with nothing" posture: adding this rule does not regress any pre-existing ceremony.
    /// </summary>
    [TestMethod]
    public async Task AssertionWithNoExtensionOutputsReportsNotApplicableAndNothingElseRegresses()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput();

        ClaimIssueResult result = await IssueAssertionClaimsAsync(input);

        Assert.AreEqual(ClaimOutcome.NotApplicable, GetOutcome(result, Fido2ClaimIds.Fido2AssertionExtensionOutputs));
        Assert.IsFalse(HasFailure(result));
    }


    /// <summary>
    /// A registration ceremony carrying no extension outputs at all reports
    /// <see cref="Fido2ClaimIds.Fido2RegistrationExtensionOutputs"/> as
    /// <see cref="ClaimOutcome.NotApplicable"/> and every other claim still succeeds.
    /// </summary>
    [TestMethod]
    public async Task RegistrationWithNoExtensionOutputsReportsNotApplicableAndNothingElseRegresses()
    {
        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput();

        ClaimIssueResult result = await IssueRegistrationClaimsAsync(input);

        Assert.AreEqual(ClaimOutcome.NotApplicable, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
        Assert.IsFalse(HasFailure(result));
    }


    /// <summary>
    /// An extension output present on the wire with no registered processor is ignored by default:
    /// <see cref="Fido2ClaimIds.Fido2AssertionExtensionOutputs"/> succeeds and no claim in the
    /// result fails — section 9's "Relying Parties MUST be prepared to handle cases where some or
    /// all of those extensions are ignored".
    /// </summary>
    [TestMethod]
    public async Task UnregisteredExtensionOutputIsIgnoredByDefaultAndSucceeds()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientExtensionOutputs: [new Fido2ExtensionOutput("credProps", Fido2TestVectors.Encode("true"))]);

        ClaimIssueResult result = await IssueAssertionClaimsAsync(input);

        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2AssertionExtensionOutputs));
        Assert.IsFalse(HasFailure(result));
    }


    /// <summary>
    /// The same unregistered extension output fails
    /// <see cref="Fido2ClaimIds.Fido2AssertionExtensionOutputs"/> exactly when the relying party
    /// opts into <see cref="AssertionCeremonyInput.RejectUnregisteredExtensionOutputs"/>.
    /// </summary>
    [TestMethod]
    public async Task UnregisteredExtensionOutputFailsWhenRejectUnregisteredIsRequested()
    {
        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientExtensionOutputs: [new Fido2ExtensionOutput("credProps", Fido2TestVectors.Encode("true"))],
            rejectUnregisteredExtensionOutputs: true);

        ClaimIssueResult result = await IssueAssertionClaimsAsync(input);

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2AssertionExtensionOutputs));
    }


    /// <summary>
    /// A registered processor's own claims appear in the result alongside the ceremony-level claim,
    /// which succeeds when the processor itself does not throw.
    /// </summary>
    [TestMethod]
    public async Task RegisteredProcessorsClaimsAppearInTheResult()
    {
        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            ("credProps", StubProcessorAsync));

        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientExtensionOutputs: [new Fido2ExtensionOutput("credProps", Fido2TestVectors.Encode("true"))],
            extensionOutputProcessor: selector);

        ClaimIssueResult result = await IssueAssertionClaimsAsync(input);

        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2AssertionExtensionOutputs));
        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, StubProcessorClaimId));
    }


    /// <summary>
    /// A registered processor that throws (a genuine defect, not cancellation) fails exactly the
    /// ceremony-level claim, fail-closed, without the exception escaping the rule pipeline.
    /// </summary>
    [TestMethod]
    public async Task ThrowingProcessorFailsExactlyTheCeremonyExtensionClaim()
    {
        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            ("credProps", ThrowingProcessorAsync));

        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientExtensionOutputs: [new Fido2ExtensionOutput("credProps", Fido2TestVectors.Encode("true"))],
            extensionOutputProcessor: selector);

        ClaimIssueResult result = await IssueAssertionClaimsAsync(input);

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2AssertionExtensionOutputs));
    }


    /// <summary>
    /// <see cref="Fido2ExtensionSelectors.FromIdentifiers"/> rejects two registrations sharing the
    /// same identifier, per the 7037 case-sensitive-match MUST's structural twin,
    /// <see cref="Fido2AttestationSelectors.FromFormats"/>.
    /// </summary>
    [TestMethod]
    public void FromIdentifiersDuplicateIdentifierThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => Fido2ExtensionSelectors.FromIdentifiers(
            ("credProps", StubProcessorAsync),
            ("credProps", StubProcessorAsync)));
    }


    /// <summary>
    /// <see cref="Fido2ExtensionSelectors.FromIdentifiers"/> dispatches by an ordinal
    /// (case-sensitive) match: a registration for <c>credProps</c> does not resolve a lookup for
    /// <c>CredProps</c>.
    /// </summary>
    [TestMethod]
    public void IdentifierLookupIsCaseSensitive()
    {
        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            ("credProps", StubProcessorAsync));

        Assert.IsNotNull(selector("credProps"));
        Assert.IsNull(selector("CredProps"));
    }


    /// <summary>
    /// Two registrations differing only by case coexist as distinct identifiers — the ordinal
    /// dictionary never collapses them.
    /// </summary>
    [TestMethod]
    public void TwoCaseDifferingRegistrationsCoexist()
    {
        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            ("credProps", StubProcessorAsync),
            ("CredProps", StubProcessorAsync));

        Assert.IsNotNull(selector("credProps"));
        Assert.IsNotNull(selector("CredProps"));
    }


    /// <summary>
    /// A processor registered for <c>credProps</c> never dispatches for a wire identifier that
    /// differs only by case (<c>CredProps</c>): the ceremony treats it as unregistered — ignored by
    /// default — rather than case-insensitively matching it to the registered processor.
    /// </summary>
    [TestMethod]
    public async Task DifferentlyCasedWireIdentifierTakesTheUnregisteredPath()
    {
        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            ("credProps", StubProcessorAsync));

        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientExtensionOutputs: [new Fido2ExtensionOutput("CredProps", Fido2TestVectors.Encode("true"))],
            extensionOutputProcessor: selector);

        ClaimIssueResult result = await IssueAssertionClaimsAsync(input);

        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2AssertionExtensionOutputs));
        Assert.IsFalse(ContainsClaim(result, StubProcessorClaimId));
    }


    /// <summary>A processor matching <see cref="ExtensionOutputProcessDelegate"/> that reports one fixed success claim.</summary>
    private static ValueTask<List<Claim>> StubProcessorAsync(ExtensionOutputProcessingRequest request, CancellationToken cancellationToken) =>
        ValueTask.FromResult<List<Claim>>([new Claim(StubProcessorClaimId, ClaimOutcome.Success)]);


    /// <summary>A processor matching <see cref="ExtensionOutputProcessDelegate"/> that always throws, simulating a defective extension implementation.</summary>
    private static ValueTask<List<Claim>> ThrowingProcessorAsync(ExtensionOutputProcessingRequest request, CancellationToken cancellationToken) =>
        throw new InvalidOperationException("The extension processing test's throwing processor always fails, by design.");


    /// <summary>Runs <see cref="Fido2ValidationProfiles.AssertionRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    private Task<ClaimIssueResult> IssueAssertionClaimsAsync(AssertionCeremonyInput input)
    {
        var issuer = new ClaimIssuer<AssertionCeremonyInput>("fido2-extension-processing-test", Fido2ValidationProfiles.AssertionRules());

        return issuer.GenerateClaimsAsync(input, "fido2-extension-processing-test-correlation", TestContext.CancellationToken).AsTask();
    }


    /// <summary>Runs <see cref="Fido2ValidationProfiles.RegistrationRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    private Task<ClaimIssueResult> IssueRegistrationClaimsAsync(RegistrationCeremonyInput input)
    {
        var issuer = new ClaimIssuer<RegistrationCeremonyInput>("fido2-extension-processing-test", Fido2ValidationProfiles.RegistrationRules());

        return issuer.GenerateClaimsAsync(input, "fido2-extension-processing-test-correlation", TestContext.CancellationToken).AsTask();
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


    /// <summary>Determines whether <paramref name="result"/> carries any claim with <paramref name="claimId"/>.</summary>
    private static bool ContainsClaim(ClaimIssueResult result, ClaimId claimId)
    {
        foreach(Claim claim in result.Claims)
        {
            if(claim.Id.Code == claimId.Code)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>Determines whether any claim in <paramref name="result"/> carries <see cref="ClaimOutcome.Failure"/>.</summary>
    private static bool HasFailure(ClaimIssueResult result)
    {
        foreach(Claim claim in result.Claims)
        {
            if(claim.Outcome == ClaimOutcome.Failure)
            {
                return true;
            }
        }

        return false;
    }
}
