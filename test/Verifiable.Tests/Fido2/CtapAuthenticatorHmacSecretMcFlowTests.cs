using System;
using System.Buffers;
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
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// PKG-C: the <c>authenticatorMakeCredential</c> <c>hmac-secret-mc</c> pipeline (CTAP 2.3 §12.8)
/// exercised in process — the compound-map reader, the R6 pairing gate (BOTH negative shapes, trap 8),
/// and the delegated crypto processing that reuses PKG-B's <c>hmac-secret</c> routine at mc time (uv
/// bit from the mc response) — driven directly against
/// <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> (no APDU transport; the R14 wire-only
/// capstones land in PKG-E). Platform-side crypto goes through
/// <see cref="CtapWave5bPinCryptoFixtures"/>'s hmac-secret session helpers — the SAME
/// <see cref="CtapPinUvAuthProtocol"/> operations the authenticator itself uses (contract R13), reused
/// unchanged since the mc-time compound input is byte-for-byte the same shape ga's own <c>hmac-secret</c>
/// input uses.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorHmacSecretMcFlowTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Trap 8, first negative shape: <c>hmac-secret-mc</c> present while <c>hmac-secret</c> is entirely
    /// absent from the same request rejects with exactly <see cref="WellKnownCtapStatusCodes.MissingParameter"/>
    /// (CTAP 2.3 §12.8, snapshot lines 13369-13370) — the pairing gate runs BEFORE any crypto, so the
    /// compound input's own saltEnc/saltAuth bytes need not be valid ciphertext for this rejection to
    /// fire (a crypto-derived status code here would prove the gate ran too late).
    /// </summary>
    [TestMethod]
    public async Task HmacSecretMcWithoutHmacSecretReturnsMissingParameter()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-hmac-secret-mc-unpaired-absent");
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);

        ReadOnlyMemory<byte> extensions = CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput(
            hmacSecret: null,
            hmacSecretMc: new CtapGetAssertionHmacSecretInput(
                session.PlatformPublicKeyCose,
                CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x71),
                CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0x72),
                PinUvAuthProtocol: null));

        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(pool, extensions: extensions);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            SendMakeCredentialAsync(simulator, request, pool, cancellationToken).AsTask());
        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, exception.StatusCode);
    }


    /// <summary>
    /// Trap 8, second negative shape: <c>hmac-secret-mc</c> present while <c>hmac-secret</c> IS present
    /// but carries the literal <see langword="false"/> rejects with exactly
    /// <see cref="WellKnownCtapStatusCodes.MissingParameter"/> — snapshot line 13369's "MUST also be
    /// present with the value... set to true" makes a present-but-false <c>hmac-secret</c> an unpaired
    /// request exactly as an absent one is, distinct from the first negative shape above (a present key
    /// with the wrong value, not a missing key).
    /// </summary>
    [TestMethod]
    public async Task HmacSecretMcWithHmacSecretFalseReturnsMissingParameter()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-hmac-secret-mc-unpaired-false");
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);

        ReadOnlyMemory<byte> extensions = CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput(
            hmacSecret: false,
            hmacSecretMc: new CtapGetAssertionHmacSecretInput(
                session.PlatformPublicKeyCose,
                CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x73),
                CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0x74),
                PinUvAuthProtocol: null));

        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(pool, extensions: extensions);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            SendMakeCredentialAsync(simulator, request, pool, cancellationToken).AsTask());
        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, exception.StatusCode);
    }


    /// <summary>
    /// The positive pairing flow (contract R6): an <c>authenticatorMakeCredential</c> request carrying
    /// BOTH <c>hmac-secret: true</c> and a paired <c>hmac-secret-mc</c> compound input succeeds, and its
    /// authData extensions map carries BOTH the <c>"hmac-secret": true</c> annotation AND its OWN
    /// encrypted <c>"hmac-secret-mc"</c> output. The platform-side decrypt is verified against a REAL
    /// property, not an echo of authenticator state: a LATER <c>authenticatorGetAssertion</c>
    /// <c>hmac-secret</c> call against the SAME credential, the SAME salt, and the SAME (non-uv)
    /// posture must decrypt to the IDENTICAL HMAC output — both sides independently reconstruct
    /// <c>HMAC-SHA-256(CredRandomWithoutUV, salt1)</c> from wire bytes only, so equality proves the
    /// mc-time delegation (snapshot line 13402) actually ran the SAME routine ga's own effect runs.
    /// </summary>
    [TestMethod]
    public async Task HmacSecretMcPositiveFlowLinksToALaterGetAssertionHmacSecretOutput()
    {
        const string RpId = "waveclose-hmac-secret-mc.example";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        byte[] salt1 = CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x75);

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-hmac-secret-mc-positive");

        using CtapWave5bPlatformPinSession mcSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        (byte[] mcSaltEnc, byte[] mcSaltAuth) = await mcSession.BuildHmacSecretSaltsAsync(salt1, null, cancellationToken).ConfigureAwait(false);

        ReadOnlyMemory<byte> mcExtensions = CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput(
            hmacSecret: true,
            hmacSecretMc: new CtapGetAssertionHmacSecretInput(mcSession.PlatformPublicKeyCose, mcSaltEnc, mcSaltAuth, PinUvAuthProtocol: null));

        CtapMakeCredentialRequest mcRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: RpId, options: new CtapCommandOptions(ResidentKey: true), extensions: mcExtensions);

        CtapMakeCredentialResponse mcResponse = await SendMakeCredentialAsync(simulator, mcRequest, pool, cancellationToken).ConfigureAwait(false);

        using AuthenticatorData mcAuthenticatorData = AuthenticatorDataReader.Read(mcResponse.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsTrue(mcAuthenticatorData.Flags.ExtensionDataIncluded, "a paired hmac-secret-mc mint must set the ED flag.");

        IReadOnlyList<Fido2ExtensionOutput> mcOutputs = AuthenticatorExtensionOutputsCborReader.Read(mcAuthenticatorData.Extensions);
        bool hmacSecretAnnotation = DecodeCborBoolean(FindExtensionOutput(mcOutputs, WellKnownWebAuthnExtensionIdentifiers.HmacSecret));
        Assert.IsTrue(hmacSecretAnnotation, "the mc response must carry \"hmac-secret\": true alongside its own \"hmac-secret-mc\" output.");

        byte[] mcCiphertext = DecodeCborByteString(FindExtensionOutput(mcOutputs, WellKnownWebAuthnExtensionIdentifiers.HmacSecretMc));
        byte[] mcDecrypted = await mcSession.DecryptHmacSecretOutputAsync(mcCiphertext, cancellationToken).ConfigureAwait(false);
        Assert.HasCount(32, mcDecrypted, "a one-salt hmac-secret-mc output must decrypt to exactly 32 bytes.");

        byte[] credentialIdBytes = mcAuthenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();

        using CtapWave5bPlatformPinSession gaSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        (byte[] gaSaltEnc, byte[] gaSaltAuth) = await gaSession.BuildHmacSecretSaltsAsync(salt1, null, cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> gaExtensions = CtapWave2AuthenticatorFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            gaSession.PlatformPublicKeyCose, gaSaltEnc, gaSaltAuth);

        List<PublicKeyCredentialDescriptor> allowList = [new PublicKeyCredentialDescriptor
        {
            Type = WellKnownPublicKeyCredentialTypes.PublicKey,
            Id = CredentialId.Create(credentialIdBytes, pool)
        }];
        CtapGetAssertionRequest gaRequest = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(
            pool, rpId: RpId, allowList: allowList, extensions: gaExtensions);

        CtapGetAssertionResponse gaResponse = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            simulator.TransceiveAsync, CtapGetAssertionRequestCborWriter.Write, gaRequest, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(gaRequest);
        gaResponse.Credential.Id.Dispose();
        gaResponse.User?.Id.Dispose();

        using AuthenticatorData gaAuthenticatorData = AuthenticatorDataReader.Read(gaResponse.AuthData, CredentialPublicKeyCborReader.Read, pool);
        IReadOnlyList<Fido2ExtensionOutput> gaOutputs = AuthenticatorExtensionOutputsCborReader.Read(gaAuthenticatorData.Extensions);
        byte[] gaCiphertext = DecodeCborByteString(FindExtensionOutput(gaOutputs, WellKnownWebAuthnExtensionIdentifiers.HmacSecret));
        byte[] gaDecrypted = await gaSession.DecryptHmacSecretOutputAsync(gaCiphertext, cancellationToken).ConfigureAwait(false);

        Assert.AreSequenceEqual(mcDecrypted, gaDecrypted,
            "the mc-time hmac-secret-mc output and a later ga hmac-secret call for the same salt and (non-uv) posture must decrypt to the identical HMAC output.");
    }


    /// <summary>Sends <paramref name="request"/> through <see cref="CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync"/>, disposing the request either way.</summary>
    private static ValueTask<CtapMakeCredentialResponse> SendMakeCredentialAsync(
        CtapAuthenticatorSimulator simulator, CtapMakeCredentialRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        try
        {
            return CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
                simulator.TransceiveAsync, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken);
        }
        finally
        {
            CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(request);
        }
    }


    /// <summary>Locates <paramref name="identifier"/>'s still-CBOR-encoded value in a decoded authData extensions map.</summary>
    private static ReadOnlyMemory<byte> FindExtensionOutput(IReadOnlyList<Fido2ExtensionOutput> outputs, string identifier)
    {
        foreach(Fido2ExtensionOutput output in outputs)
        {
            if(output.Identifier == identifier)
            {
                return output.Value;
            }
        }

        throw new InvalidOperationException($"No '{identifier}' extension output was present in the decoded authData extensions map.");
    }


    /// <summary>Decodes a CBOR boolean item's value (the wire form <see cref="AuthenticatorExtensionOutputsCborReader"/> hands back, still type-prefixed).</summary>
    private static bool DecodeCborBoolean(ReadOnlyMemory<byte> encoded) =>
        new CborReader(encoded, CborConformanceMode.Ctap2Canonical).ReadBoolean();


    /// <summary>Decodes a CBOR byte-string item's raw content bytes (the wire form <see cref="AuthenticatorExtensionOutputsCborReader"/> hands back, still type/length-prefixed).</summary>
    private static byte[] DecodeCborByteString(ReadOnlyMemory<byte> encoded) =>
        new CborReader(encoded, CborConformanceMode.Ctap2Canonical).ReadByteString();
}
