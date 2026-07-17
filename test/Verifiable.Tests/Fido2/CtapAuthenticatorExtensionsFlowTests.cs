using System;
using System.Buffers;
using System.Collections.Generic;
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
/// The waveext real-wire capstones for the <c>credProtect</c> (CTAP 2.3 §12.1) and <c>minPinLength</c>
/// (§12.5) extensions, joined by the waveclose mc-side <c>hmac-secret</c> annotation capstone (§12.7):
/// the same real, unmodified APDU transport stack (<see cref="CtapWave2TransportHarness"/>)
/// the waveconfig/wavecm/wavereset capstones use, driving the full happy path (both extensions live end
/// to end through the RP-side processors), the credProtect enforcement asymmetries, minPinLength's
/// RP-ID authorization, <c>authenticatorReset</c>'s <c>minPinLengthRPIDs</c> clearing, and the
/// <c>"hmac-secret"</c> annotation's true/false/absent trichotomy. Every
/// assertion reads a wire-visible fact only — <see cref="AuthenticatorDataReader"/> flags,
/// <see cref="CtapCommandException.StatusCode"/>, or a decoded <c>authenticatorMakeCredential</c>/
/// <c>authenticatorGetAssertion</c> response — never internal simulator state; every
/// <c>pinUvAuthParam</c> is computed with the real <see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/>
/// over wire-received bytes, via <see cref="CtapWaveConfigFixtures"/>'s shared message-assembly helpers.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorExtensionsFlowTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The plaintext PIN every UV-collecting capstone in this file establishes.</summary>
    private const string Pin = "1234";

    /// <summary>The single PIN/UV auth protocol every capstone in this file drives.</summary>
    private static CtapPinUvAuthProtocolId ProtocolId => CtapPinUvAuthProtocolId.Two;


    /// <summary>
    /// Capstone (1): the full happy path over the real APDU transport — <c>setMinPINLength</c> stores
    /// <c>minPinLengthRPIDs</c> naming this RP, an <c>authenticatorMakeCredential</c> requesting BOTH
    /// extensions carries both outputs in its authData on the wire, and the RP-side
    /// <see cref="CredProtectExtensionProcessor"/>/<see cref="MinPinLengthExtensionProcessor"/> each
    /// yield a real claim from the decoded bytes.
    /// </summary>
    [TestMethod]
    public async Task FullHappyPathBothExtensionsOverRealApduTransport()
    {
        const string RpId = "waveext-capstone-happy.example";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveext-capstone-happy");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        await EstablishPinAsync(harness, pool, cancellationToken).ConfigureAwait(false);
        byte[] acfgToken = await IssueTokenAsync(harness, pool, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, cancellationToken).ConfigureAwait(false);
        await SendSetMinPinLengthRpIdsAsync(harness, pool, acfgToken, [RpId], cancellationToken).ConfigureAwait(false);

        ReadOnlyMemory<byte> extensions = CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput(credProtect: 2, minPinLength: true);
        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(pool, rpId: RpId, extensions: extensions);
        CtapMakeCredentialResponse response = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(request);

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsTrue(authenticatorData.Flags.ExtensionDataIncluded, "both extensions authorized -- the ED bit must be set on the wire.");

        IReadOnlyList<Fido2ExtensionOutput> outputs = AuthenticatorExtensionOutputsCborReader.Read(authenticatorData.Extensions);
        Assert.HasCount(2, outputs);

        ReadOnlyMemory<byte> credProtectOutputCbor = FindOutput(outputs, WellKnownWebAuthnExtensionIdentifiers.CredProtect);
        var credProtectRequest = new ExtensionOutputProcessingRequest(WellKnownWebAuthnExtensionIdentifiers.CredProtect, null, credProtectOutputCbor, pool);
        List<Claim> credProtectClaims = await CredProtectExtensionProcessor.ProcessRegistrationOutput(credProtectRequest, cancellationToken).ConfigureAwait(false);
        Claim credProtectClaim = Assert.ContainsSingle(credProtectClaims);
        Assert.AreEqual(ClaimOutcome.Success, credProtectClaim.Outcome);
        Assert.AreEqual(2, ((CredProtectLevelContext)credProtectClaim.Context).Level);

        ReadOnlyMemory<byte> minPinLengthOutputCbor = FindOutput(outputs, WellKnownWebAuthnExtensionIdentifiers.MinPinLength);
        var minPinLengthRequest = new ExtensionOutputProcessingRequest(WellKnownWebAuthnExtensionIdentifiers.MinPinLength, null, minPinLengthOutputCbor, pool);
        List<Claim> minPinLengthClaims = await MinPinLengthExtensionProcessor.ProcessRegistrationOutput(minPinLengthRequest, cancellationToken).ConfigureAwait(false);
        Claim minPinLengthClaim = Assert.ContainsSingle(minPinLengthClaims);
        Assert.AreEqual(ClaimOutcome.Success, minPinLengthClaim.Outcome);
        Assert.AreEqual(CtapAuthenticatorState.DefaultMinPinCodePointLength, ((MinPinLengthContext)minPinLengthClaim.Context).Length);
    }


    /// <summary>
    /// Capstone (2): credProtect enforcement over the real APDU transport — a level-3 discoverable
    /// credential is invisible to a UV-less <c>authenticatorGetAssertion</c> (<c>NoCredentials</c>) and
    /// assertable once UV is collected; a level-2 discoverable credential is invisible to the UV-less
    /// discoverable scan yet assertable via an <c>allowList</c> without UV (the allowList bypass); a
    /// level-3 <c>excludeList</c> match with no UV collected in the same call is silently exempted, so
    /// the <c>authenticatorMakeCredential</c> SUCCEEDS despite the match (R9's inversion).
    /// </summary>
    [TestMethod]
    public async Task CredProtectEnforcementAcrossExcludeListAndGetAssertionOverRealApduTransport()
    {
        const string Level3RpId = "waveext-capstone-l3.example";
        const string Level2RpId = "waveext-capstone-l2.example";
        const string ExcludeRpId = "waveext-capstone-excl.example";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveext-capstone-enforcement");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        byte[] level3CredentialIdBytes = await RegisterCredentialOverRealTransportAsync(
            harness, pool, Level3RpId, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xE0), credProtect: 3, cancellationToken).ConfigureAwait(false);
        byte[] level2CredentialIdBytes = await RegisterCredentialOverRealTransportAsync(
            harness, pool, Level2RpId, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xE2), credProtect: 2, cancellationToken).ConfigureAwait(false);
        byte[] excludeCredentialIdBytes = await RegisterCredentialOverRealTransportAsync(
            harness, pool, ExcludeRpId, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xE4), credProtect: 3, cancellationToken).ConfigureAwait(false);

        //Level-3, uv-less ga -> NoCredentials, ON THE WIRE.
        CtapGetAssertionRequest level3NoUvRequest = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(pool, rpId: Level3RpId);
        CtapCommandException level3NoUvException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
                harness.Transceive, CtapGetAssertionRequestCborWriter.Write, level3NoUvRequest, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
                .AsTask());
        Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, level3NoUvException.StatusCode, "a level-3 discoverable credential must be invisible to a UV-less ga, on the wire.");
        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(level3NoUvRequest);

        //Level-2 allowList bypass: the uv-less discoverable scan hides it, the uv-less allowList request sees it.
        CtapGetAssertionRequest level2DiscoverableRequest = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(pool, rpId: Level2RpId);
        CtapCommandException level2DiscoverableException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
                harness.Transceive, CtapGetAssertionRequestCborWriter.Write, level2DiscoverableRequest, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
                .AsTask());
        Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, level2DiscoverableException.StatusCode, "level 2 is filtered from the uv-less discoverable scan, on the wire.");
        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(level2DiscoverableRequest);

        CtapGetAssertionRequest level2AllowListRequest = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(
            pool, rpId: Level2RpId,
            allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(level2CredentialIdBytes, pool) }]);
        CtapGetAssertionResponse level2AllowListResponse = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            harness.Transceive, CtapGetAssertionRequestCborWriter.Write, level2AllowListRequest, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(level2AllowListRequest);
        level2AllowListResponse.Credential.Id.Dispose();
        level2AllowListResponse.User?.Id.Dispose();
        //Reaching here IS the wire proof: the allowList branch never applies the level-2 filter.

        //ExcludeList level-3 exemption: no UV collected -> mc SUCCEEDS (R9's inversion).
        CtapMakeCredentialRequest excludeAttemptRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: ExcludeRpId, userId: CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xE6),
            excludeList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(excludeCredentialIdBytes, pool) }]);
        CtapMakeCredentialResponse excludeAttemptResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, excludeAttemptRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(excludeAttemptRequest);
        _ = excludeAttemptResponse;
        //Reaching here IS the wire proof: mc succeeded despite the excludeList match.

        //Level-3, WITH UV -> ga succeeds, on the wire.
        await EstablishPinAsync(harness, pool, cancellationToken).ConfigureAwait(false);
        byte[] gaToken = await IssueTokenAsync(harness, pool, WellKnownCtapPinUvAuthTokenPermissions.Ga, Level3RpId, cancellationToken).ConfigureAwait(false);
        byte[] gaMessage = CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x20);
        byte[] gaParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(gaToken, ProtocolId, gaMessage, pool, cancellationToken).ConfigureAwait(false);
        CtapGetAssertionRequest level3WithUvRequest = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(
            pool, rpId: Level3RpId,
            allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(level3CredentialIdBytes, pool) }],
            pinUvAuthParam: gaParam, pinUvAuthProtocol: (int)ProtocolId);
        CtapGetAssertionResponse level3WithUvResponse = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            harness.Transceive, CtapGetAssertionRequestCborWriter.Write, level3WithUvRequest, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(level3WithUvRequest);
        using(AuthenticatorData level3WithUvAuthenticatorData = AuthenticatorDataReader.Read(level3WithUvResponse.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            Assert.IsTrue(level3WithUvAuthenticatorData.Flags.UserVerified, "with a valid pinUvAuthToken, ga must succeed with uv=1 for the level-3 credential.");
        }
        level3WithUvResponse.Credential.Id.Dispose();
        level3WithUvResponse.User?.Id.Dispose();
    }


    /// <summary>
    /// Capstone (3): an unauthorized RP's <c>minPinLength</c> request completes with <c>CTAP2_OK</c> and
    /// NO <c>minPinLength</c> key in the decoded authData, on the real wire — §12.5 defines no error
    /// path for this case.
    /// </summary>
    [TestMethod]
    public async Task UnauthorizedRpMinPinLengthRequestGetsOkWithNoExtensionsOutputOverRealApduTransport()
    {
        const string RpId = "waveext-capstone-unauthorized.example";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveext-capstone-unauthorized");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        ReadOnlyMemory<byte> extensions = CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput(minPinLength: true);
        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(pool, rpId: RpId, extensions: extensions);
        CtapMakeCredentialResponse response = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(request);
        //Reaching here IS the wire proof of CTAP2_OK.

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsFalse(authenticatorData.Flags.ExtensionDataIncluded, "an unauthorized RP's minPinLength request must complete with no extensions output on the wire.");
    }


    /// <summary>
    /// Capstone (4): <c>authenticatorReset</c> clears <c>minPinLengthRPIDs</c>, proven wire-visibly — a
    /// post-reset <c>authenticatorMakeCredential</c> from a previously-authorized RP gets no
    /// <c>minPinLength</c> output.
    /// </summary>
    [TestMethod]
    public async Task ResetClearsMinPinLengthRpIdsOverRealApduTransport()
    {
        const string RpId = "waveext-capstone-reset.example";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveext-capstone-reset");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        await EstablishPinAsync(harness, pool, cancellationToken).ConfigureAwait(false);
        byte[] acfgToken = await IssueTokenAsync(harness, pool, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, cancellationToken).ConfigureAwait(false);
        await SendSetMinPinLengthRpIdsAsync(harness, pool, acfgToken, [RpId], cancellationToken).ConfigureAwait(false);

        ReadOnlyMemory<byte> extensions = CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput(minPinLength: true);

        CtapMakeCredentialRequest beforeRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(pool, rpId: RpId, extensions: extensions);
        CtapMakeCredentialResponse beforeResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, beforeRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(beforeRequest);
        using(AuthenticatorData beforeAuthenticatorData = AuthenticatorDataReader.Read(beforeResponse.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            Assert.IsTrue(beforeAuthenticatorData.Flags.ExtensionDataIncluded, "the RP must be authorized before reset.");
        }

        byte[] resetRequest = [WellKnownCtapCommands.Reset];
        using(PooledMemory resetResponse = await harness.Transceive(resetRequest, pool, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0], "authenticatorReset must succeed on the wire.");
        }

        CtapMakeCredentialRequest afterRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: RpId, userId: CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xF0), extensions: extensions);
        CtapMakeCredentialResponse afterResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, afterRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(afterRequest);
        using AuthenticatorData afterAuthenticatorData = AuthenticatorDataReader.Read(afterResponse.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsFalse(
            afterAuthenticatorData.Flags.ExtensionDataIncluded,
            "authenticatorReset must clear minPinLengthRPIDs on the wire -- the previously-authorized RP gets no output.");
    }


    /// <summary>
    /// The mc-side <c>hmac-secret</c> annotation (CTAP 2.3 §12.7, snapshot lines 13198-13201) over the
    /// real APDU transport: a literal <c>hmac-secret: true</c> request carries <c>"hmac-secret": true</c>
    /// in the mc authData extensions map on the wire (ED flag set); a literal <c>hmac-secret: false</c>
    /// request and an absent request both carry NO <c>"hmac-secret"</c> key at all — contract R3's ruled
    /// reading of snapshot line 13194's "has sent" gate as "sent with the value true", and trap 10's
    /// "the authenticator never emits false" made observable on the wire (the ED flag itself stays clear
    /// for both negative cases, since no other extension is requested in this test).
    /// </summary>
    [TestMethod]
    public async Task HmacSecretMcAnnotationOverRealApduTransport()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-hmac-secret-mc-annotation");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        await AssertHmacSecretAnnotationAsync(harness, pool, "waveclose-mc-true.example", hmacSecret: true, expectAnnotation: true, cancellationToken).ConfigureAwait(false);
        await AssertHmacSecretAnnotationAsync(harness, pool, "waveclose-mc-false.example", hmacSecret: false, expectAnnotation: false, cancellationToken).ConfigureAwait(false);
        await AssertHmacSecretAnnotationAsync(harness, pool, "waveclose-mc-absent.example", hmacSecret: null, expectAnnotation: false, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives one <c>authenticatorMakeCredential</c> requesting only the <c>hmac-secret</c> extension
    /// (value <paramref name="hmacSecret"/>) over <paramref name="harness"/>'s real transport, and asserts
    /// whether the <c>"hmac-secret"</c> authData annotation appears, per <paramref name="expectAnnotation"/>.
    /// </summary>
    private static async Task AssertHmacSecretAnnotationAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, string rpId, bool? hmacSecret, bool expectAnnotation, CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> extensions = CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput(hmacSecret: hmacSecret);
        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(pool, rpId: rpId, extensions: extensions);
        CtapMakeCredentialResponse response = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(request);

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool);

        if(expectAnnotation)
        {
            Assert.IsTrue(authenticatorData.Flags.ExtensionDataIncluded, $"rp '{rpId}': a granted hmac-secret request must set the ED flag.");

            IReadOnlyList<Fido2ExtensionOutput> outputs = AuthenticatorExtensionOutputsCborReader.Read(authenticatorData.Extensions);
            ReadOnlyMemory<byte> hmacSecretOutput = FindOutput(outputs, WellKnownWebAuthnExtensionIdentifiers.HmacSecret);
            Assert.IsTrue(hmacSecretOutput.Span.SequenceEqual(new byte[] { 0xF5 }), $"rp '{rpId}': the hmac-secret annotation must be the literal CBOR true.");
        }
        else
        {
            Assert.IsFalse(
                authenticatorData.Flags.ExtensionDataIncluded,
                $"rp '{rpId}': hmac-secret false/absent with no other extension requested must leave the ED flag clear -- no annotation, not even a false one.");
        }
    }


    /// <summary>
    /// Registers a resident credential for <paramref name="rpId"/>/<paramref name="userId"/> over
    /// <paramref name="harness"/>'s real transport, optionally requesting <paramref name="credProtect"/>,
    /// and returns the minted credential ID's own bytes.
    /// </summary>
    private static async Task<byte[]> RegisterCredentialOverRealTransportAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, string rpId, byte[] userId, int? credProtect, CancellationToken cancellationToken)
    {
        //Explicit if/else, not a ternary: CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput
        //returns a non-nullable ReadOnlyMemory<byte>, so a ternary against the null literal infers the
        //wrong Nullable<ReadOnlyMemory<byte>> shape for the absent branch (documented at
        //CtapWave2AuthenticatorFixtures.RegisterCredentialAsync's own identical construction).
        ReadOnlyMemory<byte>? extensions;
        if(credProtect is int requestedCredProtect)
        {
            extensions = CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput(credProtect: requestedCredProtect);
        }
        else
        {
            extensions = null;
        }

        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: rpId, userId: userId, options: new CtapCommandOptions(ResidentKey: true), extensions: extensions);
        CtapMakeCredentialResponse response = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(request);

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool);

        return authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
    }


    /// <summary>Finds the ordinal-matching output's still-encoded CBOR value in <paramref name="outputs"/>.</summary>
    private static ReadOnlyMemory<byte> FindOutput(IReadOnlyList<Fido2ExtensionOutput> outputs, string identifier)
    {
        foreach(Fido2ExtensionOutput output in outputs)
        {
            if(output.Identifier == identifier)
            {
                return output.Value;
            }
        }

        throw new InvalidOperationException($"No extension output named '{identifier}' was present.");
    }


    /// <summary>Establishes <see cref="Pin"/> as the authenticator's PIN over <paramref name="harness"/>'s real transport.</summary>
    private static async Task EstablishPinAsync(CtapWave2TransportHarness harness, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(harness.Transceive, ProtocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(Pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)ProtocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            harness.Transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Issues a <c>pinUvAuthToken</c> via <c>getPinUvAuthTokenUsingPinWithPermissions</c> (<c>0x09</c>)
    /// carrying <paramref name="permissions"/>, optionally bound to <paramref name="rpId"/>, decrypting
    /// it from wire bytes only, over <paramref name="harness"/>'s real transport.
    /// </summary>
    private static async Task<byte[]> IssueTokenAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, int permissions, string? rpId, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(harness.Transceive, ProtocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync(Pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)ProtocolId, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: permissions, RpId: rpId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            harness.Transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);

        return await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Sends <c>setMinPINLength</c> naming <paramref name="rpIds"/> as the <c>minPinLengthRPIDs</c>
    /// parameter over <paramref name="harness"/>'s real transport, throwing
    /// <see cref="CtapCommandException"/> for a non-success status.
    /// </summary>
    private static async Task SendSetMinPinLengthRpIdsAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, byte[] token, IReadOnlyList<string> rpIds, CancellationToken cancellationToken)
    {
        byte[] subCommandParams = CtapWaveConfigFixtures.BuildSubCommandParams(minPinLengthRpIds: rpIds);
        byte[] message = CtapWaveConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, subCommandParams);
        byte[] param = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, ProtocolId, message, pool, cancellationToken).ConfigureAwait(false);

        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, MinPinLengthRpIds: rpIds,
            PinUvAuthProtocol: (int)ProtocolId, PinUvAuthParam: param);

        byte[] envelope = CtapWaveConfigFixtures.BuildAuthenticatorConfigEnvelope(request);
        using PooledMemory response = await harness.Transceive(envelope, pool, cancellationToken).ConfigureAwait(false);
        if(!WellKnownCtapStatusCodes.IsOk(response.AsReadOnlySpan()[0]))
        {
            throw new CtapCommandException(response.AsReadOnlySpan()[0]);
        }
    }
}
