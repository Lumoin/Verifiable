using System;
using System.Buffers;
using System.Collections;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// PKG-E: the CTAP 2.3 §9-close real-wire capstones for <c>hmac-secret</c> (§12.7) and
/// <c>hmac-secret-mc</c> (§12.8) — reconstructing the FULL R14 property set, the R13 platform-actor
/// obligations, and the R2 credential lifecycle purely from wire bytes, over the UNCHANGED
/// <see cref="CtapWave2TransportHarness"/>. Where PKG-B/PKG-C's own flow tests
/// (<see cref="CtapAuthenticatorHmacSecretGetAssertionFlowTests"/>,
/// <see cref="CtapAuthenticatorHmacSecretMcFlowTests"/>) drive
/// <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> in process, every test here drives
/// <see cref="CtapWave2TransportHarness.Transceive"/> — the real, unmodified APDU/NFC transport stack —
/// so every assertion is observable by a genuine platform, never by a test holding a reference to the
/// simulator's internal state.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorHmacSecretCapstoneTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The plaintext PIN every UV-collecting scenario in this file establishes.</summary>
    private const string Pin = "1234";


    /// <summary>
    /// The §9-close capstone: ONE device, ONE wire session. <c>getInfo</c> advertises the real 5-element
    /// <c>extensions</c> array; a PIN is established and a protocol-two <c>pinUvAuthToken</c> is issued
    /// over the wire; an <c>authenticatorMakeCredential</c> requesting <c>hmac-secret: true</c> carries
    /// the annotation in its authData on the wire; a one-salt protocol-one <c>authenticatorGetAssertion</c>
    /// OMITS the extension's own <c>pinUvAuthProtocol</c> member (snapshot line 13279's defaulting, live);
    /// a two-salt protocol-two <c>authenticatorGetAssertion</c> INCLUDES it (snapshot line 13246,
    /// contract R13); the full R14 property set — determinism (a), uv-separation (b, trap 4), linkage
    /// (c), credential isolation (d, trap 21), protocol-two IV freshness (e, trap 6) — is proven from
    /// wire bytes only; and three wire negatives close: a tampered <c>saltAuth</c> (0x33, trap 2), a
    /// 48-byte decrypted plaintext (0x02, trap 3), and an unpaired <c>hmac-secret-mc</c> (0x14, trap 8).
    /// </summary>
    /// <remarks>
    /// The protocol-two <c>pinUvAuthToken</c> this test issues right after establishing the PIN carries
    /// <c>mc</c> permission and authorizes the resident-key mc mint that follows it (a PIN-protected
    /// authenticator's own "resident key requires a pinUvAuthToken" gate). CTAP 2.3's permission-stripping
    /// rule (line 5828, applied at both <c>authenticatorMakeCredential</c> step 14.4 and
    /// <c>authenticatorGetAssertion</c> step 9.4: "when a pinUvAuthToken is used with an operation that
    /// tests user presence, it is updated to remove all permissions except lbw") means that token is spent
    /// by the mc mint itself — so the R14(b) uv-separation step issues its OWN fresh <c>ga</c>-permission
    /// token immediately before the one ga call that needs <c>uv: 1</c>, mirroring
    /// <see cref="CtapAuthenticatorHmacSecretGetAssertionFlowTests.HmacSecretOutputDiffersBetweenUvAndNonUvForTheSameCredentialAndSalt"/>'s
    /// own documented ordering constraint (issue-then-immediately-consume, no intervening 'up' gesture).
    /// </remarks>
    [TestMethod]
    public async Task SectionNineCloseCapstoneOverRealApduTransport()
    {
        const string RpId = "waveclose-capstone-s9.example";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-capstone-s9");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        CtapGetInfoResponse getInfoResponse = await CtapAuthenticatorGetInfoClient.GetInfoAsync(
            harness.Transceive, CtapGetInfoResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreSequenceEqual(
            new[]
            {
                WellKnownWebAuthnExtensionIdentifiers.CredProtect,
                WellKnownWebAuthnExtensionIdentifiers.HmacSecret,
                WellKnownWebAuthnExtensionIdentifiers.HmacSecretMc,
                WellKnownWebAuthnExtensionIdentifiers.LargeBlobKey,
                WellKnownWebAuthnExtensionIdentifiers.MinPinLength
            },
            (ICollection)new List<string>(getInfoResponse.Extensions!),
            "getInfo must advertise exactly the 5-element extensions array, decoded from the wire.");

        await EstablishPinAsync(harness, pool, CtapPinUvAuthProtocolId.Two, cancellationToken).ConfigureAwait(false);
        byte[] mcToken = await IssueTokenAsync(harness, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Mc, RpId, cancellationToken).ConfigureAwait(false);
        Assert.HasCount(32, mcToken, "getPinUvAuthTokenUsingPinWithPermissions under protocol two must decrypt to a 32-byte token, on the wire.");
        byte[] mcMessage = CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x10);
        byte[] mcParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(mcToken, CtapPinUvAuthProtocolId.Two, mcMessage, pool, cancellationToken).ConfigureAwait(false);

        //A resident-key mc request on a PIN-protected authenticator MUST carry a valid mc-permission
        //pinUvAuthParam (CtapAuthenticatorTransitions' own "ResidentKeyRequiresPinUvAuthToken" gate) --
        //this IS the "PIN + protocol-2 token session" step's token, consumed here rather than left idle.
        ReadOnlyMemory<byte> mcExtensions = CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput(hmacSecret: true);
        CtapMakeCredentialRequest mcRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: RpId, options: new CtapCommandOptions(ResidentKey: true), extensions: mcExtensions,
            pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        CtapMakeCredentialResponse mcResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, mcRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(mcRequest);

        byte[] credentialIdBytes;
        using(AuthenticatorData mcAuthenticatorData = AuthenticatorDataReader.Read(mcResponse.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            Assert.IsTrue(mcAuthenticatorData.Flags.ExtensionDataIncluded, "a granted hmac-secret mc request must set the ED flag, on the wire.");
            IReadOnlyList<Fido2ExtensionOutput> mcOutputs = AuthenticatorExtensionOutputsCborReader.Read(mcAuthenticatorData.Extensions);
            Assert.IsTrue(
                DecodeCborBoolean(FindOutput(mcOutputs, WellKnownWebAuthnExtensionIdentifiers.HmacSecret)),
                "the mc authData must carry \"hmac-secret\": true, on the wire.");
            credentialIdBytes = mcAuthenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        }

        byte[] salt1 = CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x80);

        using CtapWave5bPlatformPinSession protocolOneSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        (byte[] oneSaltEnc, byte[] oneSaltAuth) = await protocolOneSession.BuildHmacSecretSaltsAsync(salt1, null, cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> oneSaltExtensions = CtapWave2AuthenticatorFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            protocolOneSession.PlatformPublicKeyCose, oneSaltEnc, oneSaltAuth, pinUvAuthProtocol: null);
        (byte[] nonUvOutput, _) = await SendHmacSecretGetAssertionAsync(
            harness, pool, RpId, credentialIdBytes, oneSaltExtensions, protocolOneSession, cancellationToken).ConfigureAwait(false);
        Assert.HasCount(32, nonUvOutput, "a one-salt hmac-secret output decrypts to exactly 32 bytes, on the wire.");

        byte[] salt2 = CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x81);
        using CtapWave5bPlatformPinSession protocolTwoSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.Two, pool, cancellationToken).ConfigureAwait(false);
        (byte[] twoSaltEnc, byte[] twoSaltAuth) = await protocolTwoSession.BuildHmacSecretSaltsAsync(salt1, salt2, cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> twoSaltExtensions = CtapWave2AuthenticatorFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            protocolTwoSession.PlatformPublicKeyCose, twoSaltEnc, twoSaltAuth, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        AssertHmacSecretPinUvAuthProtocolMemberIsPresentOnTheWire(twoSaltExtensions, (int)CtapPinUvAuthProtocolId.Two);
        (byte[] twoSaltOutput, _) = await SendHmacSecretGetAssertionAsync(
            harness, pool, RpId, credentialIdBytes, twoSaltExtensions, protocolTwoSession, cancellationToken).ConfigureAwait(false);
        Assert.HasCount(64, twoSaltOutput, "a two-salt hmac-secret output decrypts to exactly 64 bytes, on the wire.");
        Assert.AreSequenceEqual(
            nonUvOutput, twoSaltOutput[..32],
            "R14(c) linkage: a two-salt output's first 32 bytes must equal the one-salt output for the same salt1.");

        using CtapWave5bPlatformPinSession determinismSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        (byte[] determinismSaltEnc, byte[] determinismSaltAuth) = await determinismSession.BuildHmacSecretSaltsAsync(salt1, null, cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> determinismExtensions = CtapWave2AuthenticatorFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            determinismSession.PlatformPublicKeyCose, determinismSaltEnc, determinismSaltAuth, pinUvAuthProtocol: null);
        (byte[] determinismOutput, _) = await SendHmacSecretGetAssertionAsync(
            harness, pool, RpId, credentialIdBytes, determinismExtensions, determinismSession, cancellationToken).ConfigureAwait(false);
        Assert.AreSequenceEqual(
            nonUvOutput, determinismOutput, "R14(a) determinism: the same salt and uv posture must decrypt to the identical output every time.");

        byte[] uvToken = await IssueTokenAsync(harness, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Ga, RpId, cancellationToken).ConfigureAwait(false);
        byte[] gaMessage = CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x20);
        byte[] gaParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(uvToken, CtapPinUvAuthProtocolId.Two, gaMessage, pool, cancellationToken).ConfigureAwait(false);
        using CtapWave5bPlatformPinSession uvSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        (byte[] uvSaltEnc, byte[] uvSaltAuth) = await uvSession.BuildHmacSecretSaltsAsync(salt1, null, cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> uvExtensions = CtapWave2AuthenticatorFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            uvSession.PlatformPublicKeyCose, uvSaltEnc, uvSaltAuth, pinUvAuthProtocol: null);
        (byte[] uvOutput, _) = await SendHmacSecretGetAssertionAsync(
            harness, pool, RpId, credentialIdBytes, uvExtensions, uvSession, cancellationToken,
            gaParam: gaParam, gaProtocolId: CtapPinUvAuthProtocolId.Two).ConfigureAwait(false);
        Assert.AreNotSequenceEqual(
            nonUvOutput, uvOutput, "R14(b) uv-separation (trap 4): uv=0 and uv=1 must select different CredRandom values for the same salt.");

        byte[] secondCredentialIdBytes = await RegisterHmacSecretCredentialAsync(
            harness, pool, RpId, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0x91), cancellationToken).ConfigureAwait(false);
        using CtapWave5bPlatformPinSession isolationSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        (byte[] isolationSaltEnc, byte[] isolationSaltAuth) = await isolationSession.BuildHmacSecretSaltsAsync(salt1, null, cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> isolationExtensions = CtapWave2AuthenticatorFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            isolationSession.PlatformPublicKeyCose, isolationSaltEnc, isolationSaltAuth, pinUvAuthProtocol: null);
        (byte[] isolationOutput, _) = await SendHmacSecretGetAssertionAsync(
            harness, pool, RpId, secondCredentialIdBytes, isolationExtensions, isolationSession, cancellationToken).ConfigureAwait(false);
        Assert.AreNotSequenceEqual(
            nonUvOutput, isolationOutput,
            "R14(d) credential isolation (trap 21): the same salt against two different credentials must decrypt to different outputs.");

        using CtapWave5bPlatformPinSession ivSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.Two, pool, cancellationToken).ConfigureAwait(false);
        (byte[] ivSaltEnc, byte[] ivSaltAuth) = await ivSession.BuildHmacSecretSaltsAsync(salt1, null, cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> ivExtensions = CtapWave2AuthenticatorFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            ivSession.PlatformPublicKeyCose, ivSaltEnc, ivSaltAuth, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        (byte[] firstIvDecrypted, byte[] firstIvCiphertext) = await SendHmacSecretGetAssertionAsync(
            harness, pool, RpId, credentialIdBytes, ivExtensions, ivSession, cancellationToken).ConfigureAwait(false);
        (byte[] secondIvDecrypted, byte[] secondIvCiphertext) = await SendHmacSecretGetAssertionAsync(
            harness, pool, RpId, credentialIdBytes, ivExtensions, ivSession, cancellationToken).ConfigureAwait(false);
        Assert.AreNotSequenceEqual(
            firstIvCiphertext, secondIvCiphertext,
            "R14(e) protocol-two IV freshness (trap 6): two identical protocol-two requests must produce different wire ciphertext bytes.");
        Assert.AreSequenceEqual(
            firstIvDecrypted, secondIvDecrypted, "R14(e): both requests must decrypt to the identical output despite the different ciphertext.");

        using CtapWave5bPlatformPinSession tamperedSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        (byte[] tamperedSaltEnc, byte[] tamperedSaltAuth) = await tamperedSession.BuildHmacSecretSaltsAsync(salt1, null, cancellationToken).ConfigureAwait(false);
        tamperedSaltAuth[0] ^= 0xFF;
        ReadOnlyMemory<byte> tamperedExtensions = CtapWave2AuthenticatorFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            tamperedSession.PlatformPublicKeyCose, tamperedSaltEnc, tamperedSaltAuth, pinUvAuthProtocol: null);
        CtapGetAssertionRequest tamperedRequest = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(
            pool, rpId: RpId, allowList: CtapWave5AuthenticatorFixtures.BuildAllowList(credentialIdBytes, pool), extensions: tamperedExtensions);
        CtapCommandException tamperedException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            SendGetAssertionOverWireAsync(harness, tamperedRequest, pool, cancellationToken).AsTask());
        Assert.AreEqual(
            WellKnownCtapStatusCodes.PinAuthInvalid, tamperedException.StatusCode,
            "a tampered saltAuth must reject with CTAP2_ERR_PIN_AUTH_INVALID (trap 2), on the wire.");

        using CtapWave5bPlatformPinSession wrongLengthSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        (byte[] wrongLengthSaltEnc, byte[] wrongLengthSaltAuth) = await wrongLengthSession.BuildHmacSecretSaltsAsync(
            CtapWave2AuthenticatorFixtures.BuildFixedBytes(48, 0x82), null, cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> wrongLengthExtensions = CtapWave2AuthenticatorFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            wrongLengthSession.PlatformPublicKeyCose, wrongLengthSaltEnc, wrongLengthSaltAuth, pinUvAuthProtocol: null);
        CtapGetAssertionRequest wrongLengthRequest = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(
            pool, rpId: RpId, allowList: CtapWave5AuthenticatorFixtures.BuildAllowList(credentialIdBytes, pool), extensions: wrongLengthExtensions);
        CtapCommandException wrongLengthException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            SendGetAssertionOverWireAsync(harness, wrongLengthRequest, pool, cancellationToken).AsTask());
        Assert.AreEqual(
            WellKnownCtapStatusCodes.InvalidParameter, wrongLengthException.StatusCode,
            "a 48-byte decrypted plaintext must reject with CTAP1_ERR_INVALID_PARAMETER (trap 3), on the wire.");

        using CtapWave5bPlatformPinSession unpairedSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> unpairedExtensions = CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput(
            hmacSecret: null,
            hmacSecretMc: new CtapGetAssertionHmacSecretInput(
                unpairedSession.PlatformPublicKeyCose,
                CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x83),
                CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0x84),
                PinUvAuthProtocol: null));
        CtapMakeCredentialRequest unpairedRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: RpId, userId: CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0x85), extensions: unpairedExtensions);
        CtapCommandException unpairedException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            SendMakeCredentialOverWireAsync(harness, unpairedRequest, pool, cancellationToken).AsTask());
        Assert.AreEqual(
            WellKnownCtapStatusCodes.MissingParameter, unpairedException.StatusCode,
            "hmac-secret-mc present without a paired hmac-secret: true must reject with CTAP2_ERR_MISSING_PARAMETER (trap 8), on the wire.");
    }


    /// <summary>
    /// The <c>hmac-secret-mc</c> wire flow (CTAP 2.3 §12.8): an <c>authenticatorMakeCredential</c>
    /// carrying BOTH extensions decrypts, on the platform side, to the SAME <c>HMAC-SHA-256(CredRandomWithoutUV,
    /// salt1)</c> value a LATER <c>authenticatorGetAssertion</c> <c>hmac-secret</c> call against the SAME
    /// credential and salt produces — the linkage property (contract R6) tying mc-time delegation to
    /// ga's own algorithm, proven from wire bytes on both sides, never by echoing authenticator state.
    /// </summary>
    [TestMethod]
    public async Task HmacSecretMcWireFlowLinksToALaterGetAssertionHmacSecretOverRealApduTransport()
    {
        const string RpId = "waveclose-capstone-mc.example";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        byte[] salt1 = CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x86);

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-capstone-mc");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        using CtapWave5bPlatformPinSession mcSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        (byte[] mcSaltEnc, byte[] mcSaltAuth) = await mcSession.BuildHmacSecretSaltsAsync(salt1, null, cancellationToken).ConfigureAwait(false);

        ReadOnlyMemory<byte> mcExtensions = CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput(
            hmacSecret: true,
            hmacSecretMc: new CtapGetAssertionHmacSecretInput(mcSession.PlatformPublicKeyCose, mcSaltEnc, mcSaltAuth, PinUvAuthProtocol: null));
        CtapMakeCredentialRequest mcRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: RpId, options: new CtapCommandOptions(ResidentKey: true), extensions: mcExtensions);
        CtapMakeCredentialResponse mcResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, mcRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(mcRequest);

        byte[] mcDecrypted;
        byte[] credentialIdBytes;
        using(AuthenticatorData mcAuthenticatorData = AuthenticatorDataReader.Read(mcResponse.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            Assert.IsTrue(mcAuthenticatorData.Flags.ExtensionDataIncluded, "a paired hmac-secret-mc mint must set the ED flag, on the wire.");
            IReadOnlyList<Fido2ExtensionOutput> mcOutputs = AuthenticatorExtensionOutputsCborReader.Read(mcAuthenticatorData.Extensions);
            Assert.IsTrue(
                DecodeCborBoolean(FindOutput(mcOutputs, WellKnownWebAuthnExtensionIdentifiers.HmacSecret)),
                "the mc authData must also carry \"hmac-secret\": true alongside its own \"hmac-secret-mc\" output, on the wire.");

            byte[] mcCiphertext = DecodeCborByteString(FindOutput(mcOutputs, WellKnownWebAuthnExtensionIdentifiers.HmacSecretMc));
            mcDecrypted = await mcSession.DecryptHmacSecretOutputAsync(mcCiphertext, cancellationToken).ConfigureAwait(false);
            credentialIdBytes = mcAuthenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        }
        Assert.HasCount(32, mcDecrypted, "a one-salt hmac-secret-mc output decrypts to exactly 32 bytes, on the wire.");

        using CtapWave5bPlatformPinSession gaSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        (byte[] gaSaltEnc, byte[] gaSaltAuth) = await gaSession.BuildHmacSecretSaltsAsync(salt1, null, cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> gaExtensions = CtapWave2AuthenticatorFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            gaSession.PlatformPublicKeyCose, gaSaltEnc, gaSaltAuth, pinUvAuthProtocol: null);
        (byte[] gaDecrypted, _) = await SendHmacSecretGetAssertionAsync(
            harness, pool, RpId, credentialIdBytes, gaExtensions, gaSession, cancellationToken).ConfigureAwait(false);

        Assert.AreSequenceEqual(
            mcDecrypted, gaDecrypted,
            "the mc-time hmac-secret-mc output and a later ga hmac-secret call for the same salt and (non-uv) posture must decrypt to the identical output, on the wire.");
    }


    /// <summary>
    /// The R2 credential lifecycle, proven on the wire: a credential minted WITHOUT the <c>hmac-secret</c>
    /// extension still mints its <see cref="CtapCredentialRecord.CredRandomWithUV"/>/
    /// <see cref="CtapCredentialRecord.CredRandomWithoutUV"/> pair unconditionally (snapshot line 13192's
    /// SHOULD, adopted); the pair survives <see cref="CtapAuthenticatorSimulator.PowerCycle"/> — a LATER
    /// <c>authenticatorGetAssertion</c> WITH the extension still succeeds; an <c>authenticatorReset</c>
    /// then erases the credential entirely, so no CredRandom survives its own record.
    /// </summary>
    [TestMethod]
    public async Task CredentialMintedWithoutHmacSecretSurvivesPowerCycleThenIsErasedByFactoryResetOverRealApduTransport()
    {
        const string RpId = "waveclose-capstone-lifecycle.example";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-capstone-lifecycle");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        CtapMakeCredentialRequest mcRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: RpId, options: new CtapCommandOptions(ResidentKey: true));
        CtapMakeCredentialResponse mcResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, mcRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(mcRequest);

        byte[] credentialIdBytes;
        using(AuthenticatorData mcAuthenticatorData = AuthenticatorDataReader.Read(mcResponse.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            Assert.IsFalse(mcAuthenticatorData.Flags.ExtensionDataIncluded, "a mint that never mentions hmac-secret must carry no extensions output, on the wire.");
            credentialIdBytes = mcAuthenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        }

        simulator.PowerCycle();

        byte[] salt1 = CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x87);
        using CtapWave5bPlatformPinSession gaSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        (byte[] saltEnc, byte[] saltAuth) = await gaSession.BuildHmacSecretSaltsAsync(salt1, null, cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> gaExtensions = CtapWave2AuthenticatorFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            gaSession.PlatformPublicKeyCose, saltEnc, saltAuth, pinUvAuthProtocol: null);
        (byte[] decrypted, _) = await SendHmacSecretGetAssertionAsync(
            harness, pool, RpId, credentialIdBytes, gaExtensions, gaSession, cancellationToken).ConfigureAwait(false);
        Assert.HasCount(
            32, decrypted, "a credential minted without the extension, surviving a power cycle, must still serve a later hmac-secret assertion, on the wire.");

        byte[] resetRequest = [WellKnownCtapCommands.Reset];
        using(PooledMemory resetResponse = await harness.Transceive(resetRequest, pool, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0], "authenticatorReset must return CTAP2_OK, on the wire.");
        }

        CtapGetAssertionRequest postResetRequest = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(
            pool, rpId: RpId, allowList: CtapWave5AuthenticatorFixtures.BuildAllowList(credentialIdBytes, pool));
        CtapCommandException postResetException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            SendGetAssertionOverWireAsync(harness, postResetRequest, pool, cancellationToken).AsTask());
        Assert.AreEqual(
            WellKnownCtapStatusCodes.NoCredentials, postResetException.StatusCode,
            "a FactoryReset must erase the credential -- and with it its CredRandom pair -- on the wire.");
    }


    /// <summary>Establishes <see cref="Pin"/> as the authenticator's PIN under <paramref name="protocolId"/>, over <paramref name="harness"/>'s real transport.</summary>
    private static async Task EstablishPinAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, protocolId, pool, cancellationToken).ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(Pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            harness.Transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Issues a <paramref name="permissions"/>-scoped <c>pinUvAuthToken</c> bound to <paramref name="rpId"/>
    /// via <c>getPinUvAuthTokenUsingPinWithPermissions</c> under <paramref name="protocolId"/>, decrypted
    /// from wire bytes only, over <paramref name="harness"/>'s real transport.
    /// </summary>
    private static async Task<byte[]> IssueTokenAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, int permissions, string rpId,
        CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, protocolId, pool, cancellationToken).ConfigureAwait(false);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync(Pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: pinHashEnc, Permissions: permissions, RpId: rpId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            harness.Transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);

        return await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Registers a non-resident credential for <paramref name="rpId"/>/<paramref name="userId"/>
    /// requesting <c>hmac-secret: true</c>, over <paramref name="harness"/>'s real transport, and returns
    /// the minted credential ID's own bytes. Non-resident (rather than <c>rk: true</c>) so this mint needs
    /// no <c>pinUvAuthToken</c> even once the caller's PIN is set — CtapAuthenticatorTransitions' own
    /// "resident key requires a pinUvAuthToken" gate is <c>residentKey</c>-scoped, and allowList-addressed
    /// resolution (the only resolution path this capstone's isolation property needs) does not require
    /// residency.
    /// </summary>
    private static async Task<byte[]> RegisterHmacSecretCredentialAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, string rpId, byte[] userId, CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> extensions = CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput(hmacSecret: true);
        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: rpId, userId: userId, extensions: extensions);
        CtapMakeCredentialResponse response = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(request);

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool);

        return authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// Builds a fresh <c>allowList</c> citing <paramref name="credentialIdBytes"/>, sends ONE
    /// <c>authenticatorGetAssertion</c> carrying <paramref name="extensions"/> and, when supplied,
    /// <paramref name="gaParam"/>/<paramref name="gaProtocolId"/>'s top-level <c>pinUvAuthParam</c>/
    /// <c>pinUvAuthProtocol</c> (a SEPARATE mechanism from the extension's own inner
    /// <c>pinUvAuthProtocol</c> member), over <paramref name="harness"/>'s real transport, and returns
    /// both the decrypted <c>hmac-secret</c> output and its still-encrypted wire ciphertext.
    /// </summary>
    private static async Task<(byte[] Decrypted, byte[] Ciphertext)> SendHmacSecretGetAssertionAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, string rpId, byte[] credentialIdBytes,
        ReadOnlyMemory<byte> extensions, CtapWave5bPlatformPinSession session, CancellationToken cancellationToken,
        byte[]? gaParam = null, CtapPinUvAuthProtocolId? gaProtocolId = null)
    {
        //Explicit if/else, not a direct byte[]?-to-ReadOnlyMemory<byte>?-argument pass: a null byte[]
        //implicitly converts to a non-null (empty, zero-length) ReadOnlyMemory<byte>, which would make
        //BuildGetAssertionRequest see a present-but-empty pinUvAuthParam instead of an absent one.
        ReadOnlyMemory<byte>? resolvedGaParam;
        if(gaParam is byte[] gaParamBytes)
        {
            resolvedGaParam = gaParamBytes;
        }
        else
        {
            resolvedGaParam = null;
        }

        CtapGetAssertionRequest request = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(
            pool, rpId: rpId, allowList: CtapWave5AuthenticatorFixtures.BuildAllowList(credentialIdBytes, pool), extensions: extensions,
            pinUvAuthParam: resolvedGaParam, pinUvAuthProtocol: gaProtocolId is CtapPinUvAuthProtocolId protocolId ? (int)protocolId : null);

        CtapGetAssertionResponse response = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            harness.Transceive, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(request);
        response.Credential.Id.Dispose();
        response.User?.Id.Dispose();

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool);
        IReadOnlyList<Fido2ExtensionOutput> outputs = AuthenticatorExtensionOutputsCborReader.Read(authenticatorData.Extensions);
        byte[] ciphertext = DecodeCborByteString(FindOutput(outputs, WellKnownWebAuthnExtensionIdentifiers.HmacSecret));
        byte[] decrypted = await session.DecryptHmacSecretOutputAsync(ciphertext, cancellationToken).ConfigureAwait(false);

        return (decrypted, ciphertext);
    }


    /// <summary>Sends <paramref name="request"/> through <see cref="CtapAuthenticatorGetAssertionClient.GetAssertionAsync"/> over <paramref name="harness"/>'s real transport, disposing the request either way.</summary>
    private static ValueTask<CtapGetAssertionResponse> SendGetAssertionOverWireAsync(
        CtapWave2TransportHarness harness, CtapGetAssertionRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        try
        {
            return CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
                harness.Transceive, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken);
        }
        finally
        {
            CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(request);
        }
    }


    /// <summary>Sends <paramref name="request"/> through <see cref="CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync"/> over <paramref name="harness"/>'s real transport, disposing the request either way.</summary>
    private static ValueTask<CtapMakeCredentialResponse> SendMakeCredentialOverWireAsync(
        CtapWave2TransportHarness harness, CtapMakeCredentialRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        try
        {
            return CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
                harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken);
        }
        finally
        {
            CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(request);
        }
    }


    /// <summary>
    /// Decodes the raw <c>hmac-secret</c> ga extension input bytes about to go over the wire and confirms
    /// they carry the <c>pinUvAuthProtocol</c> member (<c>0x04</c>) with the value
    /// <paramref name="expectedProtocol"/> (CTAP 2.3 snapshot line 13246, contract R13) — read directly
    /// off <paramref name="extensionsCbor"/> with a fresh <see cref="CborReader"/>, not trusted from the
    /// builder call that produced the bytes.
    /// </summary>
    private static void AssertHmacSecretPinUvAuthProtocolMemberIsPresentOnTheWire(ReadOnlyMemory<byte> extensionsCbor, int expectedProtocol)
    {
        var reader = new CborReader(extensionsCbor, CborConformanceMode.Ctap2Canonical);
        int outerCount = reader.ReadStartMap()!.Value;
        for(int i = 0; i < outerCount; i++)
        {
            string key = reader.ReadTextString();
            if(!WellKnownWebAuthnExtensionIdentifiers.IsHmacSecret(key))
            {
                reader.SkipValue();
                continue;
            }

            int innerCount = reader.ReadStartMap()!.Value;
            int? foundProtocol = null;
            for(int j = 0; j < innerCount; j++)
            {
                int memberKey = reader.ReadInt32();
                if(memberKey == WellKnownCtapHmacSecretExtensionKeys.PinUvAuthProtocol)
                {
                    foundProtocol = reader.ReadInt32();
                }
                else
                {
                    reader.SkipValue();
                }
            }
            reader.ReadEndMap();

            Assert.AreEqual(
                expectedProtocol, foundProtocol,
                "the hmac-secret extension input must carry pinUvAuthProtocol on the wire when the session protocol is not protocol one (snapshot line 13246).");

            return;
        }

        Assert.Fail("no 'hmac-secret' extension entry was present in the encoded extensions map.");
    }


    /// <summary>Locates <paramref name="identifier"/>'s still-CBOR-encoded value in a decoded authData extensions map.</summary>
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


    /// <summary>Decodes a CBOR boolean item's value (the wire form <see cref="AuthenticatorExtensionOutputsCborReader"/> hands back, still type-prefixed).</summary>
    private static bool DecodeCborBoolean(ReadOnlyMemory<byte> encoded) =>
        new CborReader(encoded, CborConformanceMode.Ctap2Canonical).ReadBoolean();


    /// <summary>Decodes a CBOR byte-string item's raw content bytes (the wire form <see cref="AuthenticatorExtensionOutputsCborReader"/> hands back, still type/length-prefixed).</summary>
    private static byte[] DecodeCborByteString(ReadOnlyMemory<byte> encoded) =>
        new CborReader(encoded, CborConformanceMode.Ctap2Canonical).ReadByteString();
}
