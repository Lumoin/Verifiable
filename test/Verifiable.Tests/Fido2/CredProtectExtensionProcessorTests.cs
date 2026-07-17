using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Core.Assessment;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CredProtectExtensionProcessor"/>: the <c>credProtect</c> extension's RP-side
/// authenticator-output claim processing (CTAP 2.3 waveext R13).
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credProtect-extension">
/// CTAP 2.3, section 12.1: Credential Protection (credProtect)</see>. Every success-path assertion
/// decodes a REAL authData <c>extensions</c> map minted by <see cref="CtapAuthenticatorSimulator"/>'s
/// real <c>authenticatorMakeCredential</c> pipeline, through the actual
/// <see cref="AuthenticatorExtensionOutputsCborReader"/> — never fixture-forged CBOR. The two
/// out-of-set/malformed tests are the sole exception: R13's own defensive branches guard against a
/// non-conformant or adversarial authenticator, a wire shape the real, conformant mc pipeline
/// structurally cannot produce (mc itself rejects an illegal credProtect request before any credential
/// is minted), mirroring <see cref="AppIdExcludeExtensionProcessorTests"/>'s own unreachable-via-
/// conformant-flow "false" case.
/// </remarks>
[TestClass]
internal sealed class CredProtectExtensionProcessorTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A registration ceremony whose real, simulator-minted <c>credProtect</c> authenticator extension
    /// output decodes to one of the three registered wire values reports
    /// <see cref="Fido2ClaimIds.Fido2RegistrationCredProtect"/> as <see cref="ClaimOutcome.Success"/>,
    /// with the level recorded in <see cref="CredProtectLevelContext.Level"/>.
    /// </summary>
    [TestMethod]
    [DataRow(1, DisplayName = "userVerificationOptional")]
    [DataRow(2, DisplayName = "userVerificationOptionalWithCredentialIDList")]
    [DataRow(3, DisplayName = "userVerificationRequired")]
    public async Task RealAuthDataCredProtectLevelReportsSuccessWithLevel(int level)
    {
        byte[] authenticatorOutputCbor = await MintCredProtectAuthenticatorOutputBytesAsync(level, TestContext.CancellationToken);

        var request = new ExtensionOutputProcessingRequest(
            WellKnownWebAuthnExtensionIdentifiers.CredProtect, clientOutputJson: null, authenticatorOutputCbor, BaseMemoryPool.Shared);
        List<Claim> claims = await CredProtectExtensionProcessor.ProcessRegistrationOutput(request, TestContext.CancellationToken);

        Claim claim = Assert.ContainsSingle(claims);
        Assert.AreEqual(ClaimOutcome.Success, claim.Outcome);
        Assert.AreEqual(level, ((CredProtectLevelContext)claim.Context).Level);
    }


    /// <summary>
    /// A well-formed CBOR unsigned integer outside the three registered wire values fails
    /// <see cref="Fido2ClaimIds.Fido2RegistrationCredProtect"/> with no context — a defensive check
    /// against a non-conformant or adversarial authenticator, not a pass-through of an untrusted value.
    /// </summary>
    [TestMethod]
    [DataRow(0, DisplayName = "zero")]
    [DataRow(4, DisplayName = "one-past-range")]
    public async Task OutOfSetLevelFailsWithNoContext(int illegalLevel)
    {
        byte[] authenticatorOutputCbor = EncodeCborUnsignedInteger(illegalLevel);

        var request = new ExtensionOutputProcessingRequest(
            WellKnownWebAuthnExtensionIdentifiers.CredProtect, clientOutputJson: null, authenticatorOutputCbor, BaseMemoryPool.Shared);
        List<Claim> claims = await CredProtectExtensionProcessor.ProcessRegistrationOutput(request, TestContext.CancellationToken);

        Claim claim = Assert.ContainsSingle(claims);
        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        Assert.AreEqual(ClaimContext.None, claim.Context);
    }


    /// <summary>
    /// A registration ceremony whose <c>credProtect</c> output is not a CBOR unsigned integer at all
    /// fails closed: the ceremony-level extension-processing claim reports
    /// <see cref="ClaimOutcome.Failure"/> because the processor throws.
    /// </summary>
    [TestMethod]
    public async Task NonIntegerValueFailsCeremonyClaimClosed()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteTextString("not-an-integer");
        byte[] authenticatorOutputCbor = writer.Encode();

        ClaimIssueResult result = await IssueRegistrationClaimsAsync(authenticatorOutputCbor);

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>
    /// Firewalled: a real authData <c>extensions</c> map minted by <see cref="CtapAuthenticatorSimulator"/>,
    /// decoded through the actual <see cref="AuthenticatorExtensionOutputsCborReader"/>, run through
    /// the real <see cref="Fido2ValidationProfiles.RegistrationRules"/>, reports
    /// <see cref="Fido2ClaimIds.Fido2RegistrationCredProtect"/> and the unconditional
    /// <see cref="Fido2ClaimIds.Fido2RegistrationExtensionOutputs"/> ceremony claim as
    /// <see cref="ClaimOutcome.Success"/>.
    /// </summary>
    [TestMethod]
    public async Task FirewalledRealAuthDataThroughRealReaderSucceeds()
    {
        byte[] authenticatorOutputCbor = await MintCredProtectAuthenticatorOutputBytesAsync(2, TestContext.CancellationToken);

        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            (WellKnownWebAuthnExtensionIdentifiers.CredProtect, CredProtectExtensionProcessor.ProcessRegistrationOutput));

        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            authenticatorExtensionOutputs: [new Fido2ExtensionOutput(WellKnownWebAuthnExtensionIdentifiers.CredProtect, authenticatorOutputCbor)],
            extensionOutputProcessor: selector);

        var issuer = new ClaimIssuer<RegistrationCeremonyInput>("credprotect-extension-processor-firewalled-test", Fido2ValidationProfiles.RegistrationRules());
        ClaimIssueResult result = await issuer.GenerateClaimsAsync(input, "credprotect-extension-processor-firewalled-test-correlation", TestContext.CancellationToken);

        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationCredProtect));
        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>
    /// Mints a credential requesting <paramref name="credProtect"/> through
    /// <see cref="CtapAuthenticatorSimulator"/>'s real, in-process <c>authenticatorMakeCredential</c>
    /// pipeline, decodes its authData through <see cref="AuthenticatorDataReader"/>/
    /// <see cref="AuthenticatorExtensionOutputsCborReader"/>, and returns a private copy of the
    /// <c>credProtect</c> authenticator extension output's own encoded value bytes (independent of the
    /// pooled response buffer this method's own <see langword="using"/> declarations release).
    /// </summary>
    private static async Task<byte[]> MintCredProtectAuthenticatorOutputBytesAsync(int credProtect, CancellationToken cancellationToken)
    {
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator($"credprotect-processor-{credProtect}");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ReadOnlyMemory<byte> extensions = CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput(credProtect: credProtect);
        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(pool, extensions: extensions);
        using PooledMemory response = await CtapWave2AuthenticatorFixtures.SendMakeCredentialAsync(simulator, request, pool, cancellationToken);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        IReadOnlyList<Fido2ExtensionOutput> outputs = AuthenticatorExtensionOutputsCborReader.Read(authenticatorData.Extensions);

        foreach(Fido2ExtensionOutput output in outputs)
        {
            if(output.Identifier == WellKnownWebAuthnExtensionIdentifiers.CredProtect)
            {
                return output.Value.ToArray();
            }
        }

        throw new InvalidOperationException("The minted authData carried no credProtect extension output.");
    }


    /// <summary>Encodes <paramref name="value"/> as a single CTAP2 canonical CBOR unsigned integer.</summary>
    private static byte[] EncodeCborUnsignedInteger(int value)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteInt32(value);

        return writer.Encode();
    }


    /// <summary>
    /// Runs <see cref="Fido2ValidationProfiles.RegistrationRules"/> through a real
    /// <see cref="ClaimIssuer{TInput}"/> against a ceremony carrying a single <c>credProtect</c>
    /// authenticator extension output built directly from <paramref name="authenticatorOutputCbor"/>,
    /// with <see cref="CredProtectExtensionProcessor.ProcessRegistrationOutput"/> registered.
    /// </summary>
    private async Task<ClaimIssueResult> IssueRegistrationClaimsAsync(ReadOnlyMemory<byte> authenticatorOutputCbor)
    {
        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            (WellKnownWebAuthnExtensionIdentifiers.CredProtect, CredProtectExtensionProcessor.ProcessRegistrationOutput));

        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            authenticatorExtensionOutputs: [new Fido2ExtensionOutput(WellKnownWebAuthnExtensionIdentifiers.CredProtect, authenticatorOutputCbor)],
            extensionOutputProcessor: selector);

        var issuer = new ClaimIssuer<RegistrationCeremonyInput>("credprotect-extension-processor-test", Fido2ValidationProfiles.RegistrationRules());

        return await issuer.GenerateClaimsAsync(input, "credprotect-extension-processor-test-correlation", TestContext.CancellationToken);
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
