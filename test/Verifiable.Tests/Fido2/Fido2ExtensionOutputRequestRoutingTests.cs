using Verifiable.Core.Assessment;
using Verifiable.Fido2;
using Verifiable.Tests.TestInfrastructure;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests that a registered <see cref="ExtensionOutputProcessDelegate"/> observes the correct,
/// side-specific payload on its <see cref="ExtensionOutputProcessingRequest"/>: the client extension
/// output routed into <see cref="ExtensionOutputProcessingRequest.ClientOutputJson"/>, and the
/// authenticator extension output routed into <see cref="ExtensionOutputProcessingRequest.AuthenticatorOutputCbor"/>.
/// </summary>
/// <remarks>
/// Every processor <see cref="Fido2ExtensionProcessingTests"/> registers ignores its
/// <see cref="ExtensionOutputProcessingRequest"/> parameter entirely — none of them inspect
/// <see cref="ExtensionOutputProcessingRequest.ClientOutputJson"/> or
/// <see cref="ExtensionOutputProcessingRequest.AuthenticatorOutputCbor"/> content. That leaves the
/// two <c>FindValue(...)</c> calls building the request
/// (<c>Fido2ExtensionChecks.ProcessExtensionOutputsAsync</c>) unexercised: swapping which side's
/// lookup feeds which request property would route the client's value into
/// <see cref="ExtensionOutputProcessingRequest.AuthenticatorOutputCbor"/> and vice versa, and no
/// existing test would notice. This file registers a processor that actively compares each request
/// property's bytes against distinguishable, side-specific values.
/// </remarks>
[TestClass]
internal sealed class Fido2ExtensionOutputRequestRoutingTests
{
    /// <summary>The extension identifier this file's client and authenticator outputs share.</summary>
    private const string ExtensionIdentifier = "credProps";

    /// <summary>The claim identifier reporting whether <see cref="ExtensionOutputProcessingRequest.ClientOutputJson"/> carried the expected client-side bytes.</summary>
    private static ClaimId ClientRoutingClaimId { get; } = ClaimId.Create(9220, "Fido2ExtensionOutputRequestRoutingTestClientRouting");

    /// <summary>The claim identifier reporting whether <see cref="ExtensionOutputProcessingRequest.AuthenticatorOutputCbor"/> carried the expected authenticator-side bytes.</summary>
    private static ClaimId AuthenticatorRoutingClaimId { get; } = ClaimId.Create(9221, "Fido2ExtensionOutputRequestRoutingTestAuthenticatorRouting");

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A processor registered for one identifier present on both the client and authenticator side,
    /// with distinguishable values on each side, observes the client's value on
    /// <see cref="ExtensionOutputProcessingRequest.ClientOutputJson"/> and the authenticator's value
    /// on <see cref="ExtensionOutputProcessingRequest.AuthenticatorOutputCbor"/> — never swapped.
    /// </summary>
    [TestMethod]
    public async Task ProcessorObservesEachSidesOwnValueOnItsOwnRequestProperty()
    {
        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            (ExtensionIdentifier, RoutingCheckProcessorAsync));

        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientExtensionOutputs: [new Fido2ExtensionOutput(ExtensionIdentifier, Fido2TestVectors.Encode("client-value"))],
            authenticatorExtensionOutputs: [new Fido2ExtensionOutput(ExtensionIdentifier, Fido2TestVectors.Encode("authenticator-value"))],
            extensionOutputProcessor: selector);

        ClaimIssueResult result = await IssueClaimsAsync(input);

        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, ClientRoutingClaimId), "The client extension output must be routed into ClientOutputJson.");
        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, AuthenticatorRoutingClaimId), "The authenticator extension output must be routed into AuthenticatorOutputCbor.");
        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2AssertionExtensionOutputs));
    }


    /// <summary>
    /// A processor matching <see cref="ExtensionOutputProcessDelegate"/> that compares each request
    /// property's bytes against the fixed, side-specific expected values this test file uses.
    /// </summary>
    /// <param name="request">The request under inspection.</param>
    /// <param name="cancellationToken">A cancellation token, unused by this stub.</param>
    /// <returns>Two claims, one per side, each reporting whether that side's value was routed correctly.</returns>
    private static ValueTask<List<Claim>> RoutingCheckProcessorAsync(ExtensionOutputProcessingRequest request, CancellationToken cancellationToken)
    {
        bool clientRoutedCorrectly = request.ClientOutputJson is ReadOnlyMemory<byte> clientBytes
            && clientBytes.Span.SequenceEqual(Fido2TestVectors.Encode("client-value").Span);
        bool authenticatorRoutedCorrectly = request.AuthenticatorOutputCbor is ReadOnlyMemory<byte> authenticatorBytes
            && authenticatorBytes.Span.SequenceEqual(Fido2TestVectors.Encode("authenticator-value").Span);

        return ValueTask.FromResult<List<Claim>>(
        [
            new Claim(ClientRoutingClaimId, clientRoutedCorrectly ? ClaimOutcome.Success : ClaimOutcome.Failure),
            new Claim(AuthenticatorRoutingClaimId, authenticatorRoutedCorrectly ? ClaimOutcome.Success : ClaimOutcome.Failure)
        ]);
    }


    /// <summary>Runs <see cref="Fido2ValidationProfiles.AssertionRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    /// <param name="input">The ceremony input to validate.</param>
    /// <returns>The generated <see cref="ClaimIssueResult"/>.</returns>
    private Task<ClaimIssueResult> IssueClaimsAsync(AssertionCeremonyInput input)
    {
        var issuer = new ClaimIssuer<AssertionCeremonyInput>("fido2-extension-output-request-routing-test", Fido2ValidationProfiles.AssertionRules());

        return issuer.GenerateClaimsAsync(input, "fido2-extension-output-request-routing-test-correlation", TestContext.CancellationToken).AsTask();
    }


    /// <summary>Finds the outcome of the claim carrying <paramref name="claimId"/> in <paramref name="result"/>.</summary>
    /// <param name="result">The claim result to search.</param>
    /// <param name="claimId">The claim identifier to find.</param>
    /// <returns>The matching claim's outcome.</returns>
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
