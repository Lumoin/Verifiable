using System.Buffers.Text;
using Verifiable.Core.Assessment;
using Verifiable.Fido2;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="LargeBlobExtensionProcessor"/>: the <c>largeBlob</c> extension's RP-side
/// output processing — the <see cref="Fido2ExtensionSelectors"/> registry's first production
/// tenant.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">W3C Web Authentication
/// Level 3, section 10.1.5: Large blob storage extension (largeBlob)</see>. The unit-level tests
/// construct a <see cref="Fido2ExtensionOutput"/> directly, mirroring
/// <see cref="Fido2ExtensionProcessingTests"/>'s style; the firewalled tests decode real
/// <c>clientExtensionResults</c> wire bytes through the actual
/// <see cref="ClientExtensionOutputsJsonReader"/> and run the registered processor through a real
/// <see cref="ClaimIssuer{TInput}"/> executing <see cref="Fido2ValidationProfiles.RegistrationRules"/>
/// / <see cref="Fido2ValidationProfiles.AssertionRules"/>.
/// </remarks>
[TestClass]
internal sealed class LargeBlobExtensionProcessorTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A registration ceremony whose <c>largeBlob</c> output carries <c>{"supported":true}</c>
    /// reports <see cref="Fido2ClaimIds.Fido2RegistrationLargeBlobSupported"/> as
    /// <see cref="ClaimOutcome.Success"/>, with the decoded value recorded in
    /// <see cref="LargeBlobSupportedContext.Supported"/>.
    /// </summary>
    [TestMethod]
    public async Task RegistrationSupportedTrueSucceedsAndRecordsValue()
    {
        Claim claim = await IssueSingleRegistrationExtensionClaimAsync(
            Fido2ClaimIds.Fido2RegistrationLargeBlobSupported,
            Fido2TestVectors.Encode("""{"supported":true}"""));

        Assert.AreEqual(ClaimOutcome.Success, claim.Outcome);
        var context = (LargeBlobSupportedContext)claim.Context;
        Assert.IsTrue(context.Supported);
    }


    /// <summary>
    /// A registration ceremony whose <c>largeBlob</c> output carries <c>{"supported":false}</c>
    /// still reports <see cref="ClaimOutcome.Success"/> — <see langword="false"/> is a legitimate
    /// authenticator state, not a protocol violation — with the decoded value recorded.
    /// </summary>
    [TestMethod]
    public async Task RegistrationSupportedFalseSucceedsAndRecordsValue()
    {
        Claim claim = await IssueSingleRegistrationExtensionClaimAsync(
            Fido2ClaimIds.Fido2RegistrationLargeBlobSupported,
            Fido2TestVectors.Encode("""{"supported":false}"""));

        Assert.AreEqual(ClaimOutcome.Success, claim.Outcome);
        var context = (LargeBlobSupportedContext)claim.Context;
        Assert.IsFalse(context.Supported);
    }


    /// <summary>
    /// A registration ceremony whose <c>largeBlob</c> output omits the required <c>supported</c>
    /// member fails closed: <see cref="Fido2ClaimIds.Fido2RegistrationExtensionOutputs"/> reports
    /// <see cref="ClaimOutcome.Failure"/> because the processor throws.
    /// </summary>
    [TestMethod]
    public async Task RegistrationMissingSupportedMemberFailsCeremonyClaimClosed()
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(Fido2TestVectors.Encode("{}"));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>
    /// A registration ceremony whose <c>largeBlob</c> output is not a JSON object at all fails
    /// closed the same way as a missing member.
    /// </summary>
    [TestMethod]
    public async Task RegistrationNonObjectOutputFailsCeremonyClaimClosed()
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(Fido2TestVectors.Encode("true"));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>
    /// A repeated <c>supported</c> member in the <c>largeBlob</c> output is rejected as malformed —
    /// no single unambiguous value — and fails the ceremony claim closed.
    /// </summary>
    [TestMethod]
    public async Task RegistrationRepeatedMemberFailsCeremonyClaimClosed()
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(Fido2TestVectors.Encode("""{"supported":true,"supported":false}"""));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>
    /// Firewalled: a real <c>clientExtensionResults</c> JSON document carrying
    /// <c>{"largeBlob":{"supported":true}}</c>, decoded through the actual
    /// <see cref="ClientExtensionOutputsJsonReader"/>, run through the real
    /// <see cref="Fido2ValidationProfiles.RegistrationRules"/>, reports both
    /// <see cref="Fido2ClaimIds.Fido2RegistrationLargeBlobSupported"/> and the unconditional
    /// <see cref="Fido2ClaimIds.Fido2RegistrationExtensionOutputs"/> ceremony claim as
    /// <see cref="ClaimOutcome.Success"/>.
    /// </summary>
    [TestMethod]
    public async Task FirewalledRegistrationWireJsonThroughRealReaderSucceeds()
    {
        IReadOnlyList<Fido2ExtensionOutput> outputs = ClientExtensionOutputsJsonReader.Read(
            Fido2TestVectors.Encode("""{"largeBlob":{"supported":true}}"""));

        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            (WellKnownWebAuthnExtensionIdentifiers.LargeBlob, LargeBlobExtensionProcessor.ProcessRegistrationOutput));

        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientExtensionOutputs: outputs,
            extensionOutputProcessor: selector);

        ClaimIssueResult result = await IssueRegistrationClaimsAsync(input);

        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationLargeBlobSupported));
        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>
    /// An assertion ceremony whose <c>largeBlob</c> output carries only <c>{"blob":"..."}</c>
    /// reports <see cref="Fido2ClaimIds.Fido2AssertionLargeBlobRead"/> as
    /// <see cref="ClaimOutcome.Success"/> with the exact decoded bytes carried in
    /// <see cref="LargeBlobReadContext.Blob"/>, tagged <see cref="Fido2BufferTags.LargeBlob"/>, and
    /// <see cref="Fido2ClaimIds.Fido2AssertionLargeBlobWritten"/> as
    /// <see cref="ClaimOutcome.NotApplicable"/> since <c>written</c> was absent.
    /// </summary>
    [TestMethod]
    public async Task AssertionBlobPresentSucceedsAndCarriesDecodedBytesTagged()
    {
        byte[] blobBytes = [0x01, 0x02, 0x03, 0x04, 0x05];
        string base64Url = Base64Url.EncodeToString(blobBytes);

        ClaimIssueResult result = await IssueAssertionClaimsAsync(
            Fido2TestVectors.Encode($$"""{"blob":"{{base64Url}}"}"""));

        Claim readClaim = GetClaim(result, Fido2ClaimIds.Fido2AssertionLargeBlobRead);
        Assert.AreEqual(ClaimOutcome.Success, readClaim.Outcome);
        var readContext = (LargeBlobReadContext)readClaim.Context;
        CollectionAssert.AreEqual(blobBytes, readContext.Blob.Span.ToArray());
        Assert.AreEqual(Fido2BufferTags.LargeBlob, readContext.Blob.Tag);

        Assert.AreEqual(ClaimOutcome.NotApplicable, GetOutcome(result, Fido2ClaimIds.Fido2AssertionLargeBlobWritten));
    }


    /// <summary>
    /// An assertion ceremony whose <c>largeBlob</c> output carries only <c>{"written":true}</c>
    /// reports <see cref="Fido2ClaimIds.Fido2AssertionLargeBlobWritten"/> as
    /// <see cref="ClaimOutcome.Success"/> with the decoded value recorded, and
    /// <see cref="Fido2ClaimIds.Fido2AssertionLargeBlobRead"/> as
    /// <see cref="ClaimOutcome.NotApplicable"/> since <c>blob</c> was absent.
    /// </summary>
    [TestMethod]
    public async Task AssertionWrittenPresentSucceedsAndRecordsValue()
    {
        ClaimIssueResult result = await IssueAssertionClaimsAsync(Fido2TestVectors.Encode("""{"written":true}"""));

        Claim writtenClaim = GetClaim(result, Fido2ClaimIds.Fido2AssertionLargeBlobWritten);
        Assert.AreEqual(ClaimOutcome.Success, writtenClaim.Outcome);
        Assert.IsTrue(((LargeBlobWrittenContext)writtenClaim.Context).Written);

        Assert.AreEqual(ClaimOutcome.NotApplicable, GetOutcome(result, Fido2ClaimIds.Fido2AssertionLargeBlobRead));
    }


    /// <summary>
    /// An assertion ceremony whose <c>largeBlob</c> output is an empty object — the specification's
    /// own "read failed, no write attempted" shape — reports both
    /// <see cref="Fido2ClaimIds.Fido2AssertionLargeBlobRead"/> and
    /// <see cref="Fido2ClaimIds.Fido2AssertionLargeBlobWritten"/> as
    /// <see cref="ClaimOutcome.NotApplicable"/>, never <see cref="ClaimOutcome.Failure"/>.
    /// </summary>
    [TestMethod]
    public async Task AssertionEmptyOutputReportsBothClaimsNotApplicable()
    {
        ClaimIssueResult result = await IssueAssertionClaimsAsync(Fido2TestVectors.Encode("{}"));

        Assert.AreEqual(ClaimOutcome.NotApplicable, GetOutcome(result, Fido2ClaimIds.Fido2AssertionLargeBlobRead));
        Assert.AreEqual(ClaimOutcome.NotApplicable, GetOutcome(result, Fido2ClaimIds.Fido2AssertionLargeBlobWritten));
        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2AssertionExtensionOutputs));
    }


    /// <summary>
    /// An assertion ceremony whose <c>blob</c> member is not valid base64url fails the ceremony
    /// claim closed — a genuinely malformed shape, distinct from the documented "read failed" case.
    /// </summary>
    [TestMethod]
    public async Task AssertionMalformedBase64UrlBlobFailsCeremonyClaimClosed()
    {
        ClaimIssueResult result = await IssueAssertionClaimsAsync(Fido2TestVectors.Encode("""{"blob":"not-valid-base64url!!!"}"""));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2AssertionExtensionOutputs));
    }


    /// <summary>
    /// An assertion ceremony whose <c>written</c> member is not boolean-shaped fails the ceremony
    /// claim closed.
    /// </summary>
    [TestMethod]
    public async Task AssertionNonBooleanWrittenFailsCeremonyClaimClosed()
    {
        ClaimIssueResult result = await IssueAssertionClaimsAsync(Fido2TestVectors.Encode("""{"written":"yes"}"""));

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2AssertionExtensionOutputs));
    }


    /// <summary>
    /// Firewalled: a real <c>clientExtensionResults</c> JSON document carrying
    /// <c>{"largeBlob":{"blob":"..."}}</c>, decoded through the actual
    /// <see cref="ClientExtensionOutputsJsonReader"/>, reports
    /// <see cref="Fido2ClaimIds.Fido2AssertionLargeBlobRead"/> and the unconditional
    /// <see cref="Fido2ClaimIds.Fido2AssertionExtensionOutputs"/> ceremony claim as
    /// <see cref="ClaimOutcome.Success"/>.
    /// </summary>
    [TestMethod]
    public async Task FirewalledAssertionWireJsonThroughRealReaderSucceedsForBlob()
    {
        byte[] blobBytes = [0xAA, 0xBB, 0xCC];
        string base64Url = Base64Url.EncodeToString(blobBytes);

        IReadOnlyList<Fido2ExtensionOutput> outputs = ClientExtensionOutputsJsonReader.Read(
            Fido2TestVectors.Encode($$$"""{"largeBlob":{"blob":"{{{base64Url}}}"}}"""));

        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            (WellKnownWebAuthnExtensionIdentifiers.LargeBlob, LargeBlobExtensionProcessor.ProcessAssertionOutput));

        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientExtensionOutputs: outputs,
            extensionOutputProcessor: selector);

        ClaimIssueResult result = await IssueAssertionClaimsAsync(input);

        Claim readClaim = GetClaim(result, Fido2ClaimIds.Fido2AssertionLargeBlobRead);
        Assert.AreEqual(ClaimOutcome.Success, readClaim.Outcome);
        CollectionAssert.AreEqual(blobBytes, ((LargeBlobReadContext)readClaim.Context).Blob.Span.ToArray());
        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2AssertionExtensionOutputs));
    }


    /// <summary>
    /// Firewalled: a real <c>clientExtensionResults</c> JSON document carrying
    /// <c>{"largeBlob":{"written":true}}</c>, decoded through the actual
    /// <see cref="ClientExtensionOutputsJsonReader"/>, reports
    /// <see cref="Fido2ClaimIds.Fido2AssertionLargeBlobWritten"/> as <see cref="ClaimOutcome.Success"/>.
    /// </summary>
    [TestMethod]
    public async Task FirewalledAssertionWireJsonThroughRealReaderSucceedsForWritten()
    {
        IReadOnlyList<Fido2ExtensionOutput> outputs = ClientExtensionOutputsJsonReader.Read(
            Fido2TestVectors.Encode("""{"largeBlob":{"written":true}}"""));

        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            (WellKnownWebAuthnExtensionIdentifiers.LargeBlob, LargeBlobExtensionProcessor.ProcessAssertionOutput));

        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientExtensionOutputs: outputs,
            extensionOutputProcessor: selector);

        ClaimIssueResult result = await IssueAssertionClaimsAsync(input);

        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2AssertionLargeBlobWritten));
    }


    /// <summary>
    /// Issues registration claims for a ceremony carrying a single <c>largeBlob</c> client
    /// extension output built directly from <paramref name="largeBlobOutputJson"/>, and returns the
    /// claim matching <paramref name="claimId"/>.
    /// </summary>
    private async Task<Claim> IssueSingleRegistrationExtensionClaimAsync(ClaimId claimId, ReadOnlyMemory<byte> largeBlobOutputJson)
    {
        ClaimIssueResult result = await IssueRegistrationClaimsAsync(largeBlobOutputJson);

        return GetClaim(result, claimId);
    }


    /// <summary>
    /// Runs <see cref="Fido2ValidationProfiles.RegistrationRules"/> through a real
    /// <see cref="ClaimIssuer{TInput}"/> against a ceremony carrying a single <c>largeBlob</c>
    /// client extension output built directly from <paramref name="largeBlobOutputJson"/>, with
    /// <see cref="LargeBlobExtensionProcessor.ProcessRegistrationOutput"/> registered.
    /// </summary>
    private async Task<ClaimIssueResult> IssueRegistrationClaimsAsync(ReadOnlyMemory<byte> largeBlobOutputJson)
    {
        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            (WellKnownWebAuthnExtensionIdentifiers.LargeBlob, LargeBlobExtensionProcessor.ProcessRegistrationOutput));

        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientExtensionOutputs: [new Fido2ExtensionOutput(WellKnownWebAuthnExtensionIdentifiers.LargeBlob, largeBlobOutputJson)],
            extensionOutputProcessor: selector);

        //Awaited (not returned directly) so the `using` above does not dispose the pooled ceremony
        //input's carriers before the ceremony's own claim-generation task has finished reading them.
        return await IssueRegistrationClaimsAsync(input);
    }


    /// <summary>Runs <see cref="Fido2ValidationProfiles.RegistrationRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    private Task<ClaimIssueResult> IssueRegistrationClaimsAsync(RegistrationCeremonyInput input)
    {
        var issuer = new ClaimIssuer<RegistrationCeremonyInput>("largeblob-extension-processor-test", Fido2ValidationProfiles.RegistrationRules());

        return issuer.GenerateClaimsAsync(input, "largeblob-extension-processor-test-correlation", TestContext.CancellationToken).AsTask();
    }


    /// <summary>
    /// Runs <see cref="Fido2ValidationProfiles.AssertionRules"/> through a real
    /// <see cref="ClaimIssuer{TInput}"/> against a ceremony carrying a single <c>largeBlob</c>
    /// client extension output built directly from <paramref name="largeBlobOutputJson"/>, with
    /// <see cref="LargeBlobExtensionProcessor.ProcessAssertionOutput"/> registered.
    /// </summary>
    private async Task<ClaimIssueResult> IssueAssertionClaimsAsync(ReadOnlyMemory<byte> largeBlobOutputJson)
    {
        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            (WellKnownWebAuthnExtensionIdentifiers.LargeBlob, LargeBlobExtensionProcessor.ProcessAssertionOutput));

        using AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput(
            clientExtensionOutputs: [new Fido2ExtensionOutput(WellKnownWebAuthnExtensionIdentifiers.LargeBlob, largeBlobOutputJson)],
            extensionOutputProcessor: selector);

        //Awaited (not returned directly) so the `using` above does not dispose the pooled ceremony
        //input's carriers before the ceremony's own claim-generation task has finished reading them.
        return await IssueAssertionClaimsAsync(input);
    }


    /// <summary>Runs <see cref="Fido2ValidationProfiles.AssertionRules"/> through a real <see cref="ClaimIssuer{TInput}"/>.</summary>
    private Task<ClaimIssueResult> IssueAssertionClaimsAsync(AssertionCeremonyInput input)
    {
        var issuer = new ClaimIssuer<AssertionCeremonyInput>("largeblob-extension-processor-test", Fido2ValidationProfiles.AssertionRules());

        return issuer.GenerateClaimsAsync(input, "largeblob-extension-processor-test-correlation", TestContext.CancellationToken).AsTask();
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
