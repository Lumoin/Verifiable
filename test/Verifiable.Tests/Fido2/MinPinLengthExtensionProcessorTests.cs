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
/// Tests for <see cref="MinPinLengthExtensionProcessor"/>: the <c>minPinLength</c> extension's RP-side
/// authenticator-output claim processing (CTAP 2.3 waveext R13).
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-minpinlength-extension">
/// CTAP 2.3, section 12.5: Minimum PIN Length Extension (minPinLength)</see>. Every success-path
/// assertion decodes a REAL authData <c>extensions</c> map minted by an RP-authorized
/// <see cref="CtapAuthenticatorSimulator"/> <c>authenticatorMakeCredential</c> call, through the actual
/// <see cref="AuthenticatorExtensionOutputsCborReader"/> — never fixture-forged CBOR. The malformed-CBOR
/// test is the sole exception: minPinLength carries no restricted value set, so the only defensive
/// branch this processor has is malformed wire bytes, a shape the real, conformant pipeline cannot
/// produce.
/// </remarks>
[TestClass]
internal sealed class MinPinLengthExtensionProcessorTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The plaintext PIN <see cref="AuthorizeRpAndMintMinPinLengthAuthenticatorOutputBytesAsync"/> establishes to authorize its RP.</summary>
    private const string DefaultPin = "1234";


    /// <summary>
    /// A registration ceremony whose real, simulator-minted <c>minPinLength</c> authenticator
    /// extension output decodes cleanly reports <see cref="Fido2ClaimIds.Fido2RegistrationMinPinLength"/>
    /// as <see cref="ClaimOutcome.Success"/>, with the length recorded in
    /// <see cref="MinPinLengthContext.Length"/>.
    /// </summary>
    [TestMethod]
    public async Task RealAuthDataMinPinLengthReportsSuccessWithLength()
    {
        byte[] authenticatorOutputCbor = await AuthorizeRpAndMintMinPinLengthAuthenticatorOutputBytesAsync(TestContext.CancellationToken);

        var request = new ExtensionOutputProcessingRequest(
            WellKnownWebAuthnExtensionIdentifiers.MinPinLength, clientOutputJson: null, authenticatorOutputCbor, BaseMemoryPool.Shared);
        List<Claim> claims = await MinPinLengthExtensionProcessor.ProcessRegistrationOutput(request, TestContext.CancellationToken);

        Claim claim = Assert.ContainsSingle(claims);
        Assert.AreEqual(ClaimOutcome.Success, claim.Outcome);
        Assert.AreEqual(CtapAuthenticatorState.DefaultMinPinCodePointLength, ((MinPinLengthContext)claim.Context).Length);
    }


    /// <summary>
    /// A registration ceremony whose <c>minPinLength</c> output is not a CBOR unsigned integer at all
    /// fails closed: the ceremony-level extension-processing claim reports
    /// <see cref="ClaimOutcome.Failure"/> because the processor throws.
    /// </summary>
    [TestMethod]
    public async Task NonIntegerValueFailsCeremonyClaimClosed()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteTextString("not-an-integer");
        byte[] authenticatorOutputCbor = writer.Encode();

        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            (WellKnownWebAuthnExtensionIdentifiers.MinPinLength, MinPinLengthExtensionProcessor.ProcessRegistrationOutput));

        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            authenticatorExtensionOutputs: [new Fido2ExtensionOutput(WellKnownWebAuthnExtensionIdentifiers.MinPinLength, authenticatorOutputCbor)],
            extensionOutputProcessor: selector);

        var issuer = new ClaimIssuer<RegistrationCeremonyInput>("minpinlength-extension-processor-test", Fido2ValidationProfiles.RegistrationRules());
        ClaimIssueResult result = await issuer.GenerateClaimsAsync(input, "minpinlength-extension-processor-test-correlation", TestContext.CancellationToken);

        Assert.AreEqual(ClaimOutcome.Failure, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>
    /// Firewalled: a real authData <c>extensions</c> map minted by an RP-authorized
    /// <see cref="CtapAuthenticatorSimulator"/> call, decoded through the actual
    /// <see cref="AuthenticatorExtensionOutputsCborReader"/>, run through the real
    /// <see cref="Fido2ValidationProfiles.RegistrationRules"/>, reports
    /// <see cref="Fido2ClaimIds.Fido2RegistrationMinPinLength"/> and the unconditional
    /// <see cref="Fido2ClaimIds.Fido2RegistrationExtensionOutputs"/> ceremony claim as
    /// <see cref="ClaimOutcome.Success"/>.
    /// </summary>
    [TestMethod]
    public async Task FirewalledRealAuthDataThroughRealReaderSucceeds()
    {
        byte[] authenticatorOutputCbor = await AuthorizeRpAndMintMinPinLengthAuthenticatorOutputBytesAsync(TestContext.CancellationToken);

        SelectExtensionOutputProcessorDelegate selector = Fido2ExtensionSelectors.FromIdentifiers(
            (WellKnownWebAuthnExtensionIdentifiers.MinPinLength, MinPinLengthExtensionProcessor.ProcessRegistrationOutput));

        using RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            authenticatorExtensionOutputs: [new Fido2ExtensionOutput(WellKnownWebAuthnExtensionIdentifiers.MinPinLength, authenticatorOutputCbor)],
            extensionOutputProcessor: selector);

        var issuer = new ClaimIssuer<RegistrationCeremonyInput>("minpinlength-extension-processor-firewalled-test", Fido2ValidationProfiles.RegistrationRules());
        ClaimIssueResult result = await issuer.GenerateClaimsAsync(input, "minpinlength-extension-processor-firewalled-test-correlation", TestContext.CancellationToken);

        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationMinPinLength));
        Assert.AreEqual(ClaimOutcome.Success, GetOutcome(result, Fido2ClaimIds.Fido2RegistrationExtensionOutputs));
    }


    /// <summary>
    /// Establishes a PIN, authorizes <see cref="CtapWave2AuthenticatorFixtures.DefaultRpId"/> for the
    /// <c>minPinLength</c> extension via <c>setMinPINLength</c>'s <c>minPinLengthRPIDs</c> parameter,
    /// mints a credential requesting <c>minPinLength</c> through <see cref="CtapAuthenticatorSimulator"/>'s
    /// real, in-process <c>authenticatorMakeCredential</c> pipeline, decodes its authData through
    /// <see cref="AuthenticatorDataReader"/>/<see cref="AuthenticatorExtensionOutputsCborReader"/>, and
    /// returns a private copy of the <c>minPinLength</c> authenticator extension output's own encoded
    /// value bytes (independent of the pooled response buffer this method's own <see langword="using"/>
    /// declarations release).
    /// </summary>
    private static async Task<byte[]> AuthorizeRpAndMintMinPinLengthAuthenticatorOutputBytesAsync(CancellationToken cancellationToken)
    {
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("minpinlength-processor");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, cancellationToken);
        byte[] token = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, cancellationToken);

        byte[] subCommandParams = CtapWaveConfigFixtures.BuildSubCommandParams(minPinLengthRpIds: [CtapWave2AuthenticatorFixtures.DefaultRpId]);
        byte[] message = CtapWaveConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, subCommandParams);
        byte[] param = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, cancellationToken);

        var configRequest = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength,
            MinPinLengthRpIds: [CtapWave2AuthenticatorFixtures.DefaultRpId],
            PinUvAuthProtocol: (int)protocolId,
            PinUvAuthParam: param);
        using(PooledMemory configResponse = await CtapWaveConfigFixtures.SendAuthenticatorConfigAsync(simulator, configRequest, pool, cancellationToken))
        {
            if(!WellKnownCtapStatusCodes.IsOk(configResponse.AsReadOnlySpan()[0]))
            {
                throw new Fido2FormatException($"Fixture setMinPINLength authorization failed with CTAP2 status 0x{configResponse.AsReadOnlySpan()[0]:X2}.");
            }
        }

        ReadOnlyMemory<byte> extensions = CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput(minPinLength: true);
        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(pool, extensions: extensions);
        using PooledMemory response = await CtapWave2AuthenticatorFixtures.SendMakeCredentialAsync(simulator, request, pool, cancellationToken);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        IReadOnlyList<Fido2ExtensionOutput> outputs = AuthenticatorExtensionOutputsCborReader.Read(authenticatorData.Extensions);

        foreach(Fido2ExtensionOutput output in outputs)
        {
            if(output.Identifier == WellKnownWebAuthnExtensionIdentifiers.MinPinLength)
            {
                return output.Value.ToArray();
            }
        }

        throw new InvalidOperationException("The minted authData carried no minPinLength extension output.");
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
