using System;
using System.Buffers;
using System.Collections.Generic;
using Lumoin.Veritas.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor;
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
/// The <c>authenticatorGetAssertion</c> <c>hmac-secret</c> pipeline (CTAP 2.3 §12.7) exercised
/// in process — the compound-map reader, the processing algorithm (protocol defaulting, up/uv
/// gating, decapsulate/verify/decrypt, CredRandom selection, HMAC, encrypt), and the new ga
/// authData-extensions output pipeline — driven directly against
/// <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> (no APDU transport; the wire-only
/// capstones land elsewhere). Every platform-side crypto operation goes through
/// <see cref="CtapPinCryptoFixtures"/>'s hmac-secret session helpers, the same
/// <see cref="CtapPinUvAuthProtocol"/> operations the authenticator itself uses.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorHmacSecretGetAssertionFlowTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The relying party identifier every test in this file registers credentials under.</summary>
    private const string RpId = "hmac-secret.example";

    /// <summary>The plaintext PIN every uv-collecting scenario in this file establishes.</summary>
    private const string Pin = "1234";


    /// <summary>
    /// The full processing algorithm succeeds across every combination of salt count, PIN/UV auth
    /// protocol, and uv posture — the "one-salt/two-salt × protocol 1/protocol 2 × uv/non-uv"
    /// matrix. Protocol-one rows OMIT the request's own <c>pinUvAuthProtocol</c> member, exercising
    /// snapshot line 13279's default-to-protocol-one; protocol-two rows INCLUDE it (value <c>2</c>),
    /// satisfying snapshot line 13246's platform obligation — both readings share this one
    /// matrix rather than needing a separate defaulting test. The decrypted output's length (32 for one
    /// salt, 64 for two) is the row's own success proof; byte-content correctness across calls is proven
    /// by the dedicated determinism/uv-separation/linkage/isolation properties below, never by
    /// echoing the authenticator's own CredRandom.
    /// </summary>
    [TestMethod]
    [DataRow(1, false, false, DisplayName = "one salt, protocol 1, non-uv")]
    [DataRow(1, false, true, DisplayName = "one salt, protocol 1, uv")]
    [DataRow(1, true, false, DisplayName = "one salt, protocol 2, non-uv")]
    [DataRow(1, true, true, DisplayName = "one salt, protocol 2, uv")]
    [DataRow(2, false, false, DisplayName = "two salt, protocol 1, non-uv")]
    [DataRow(2, false, true, DisplayName = "two salt, protocol 1, uv")]
    [DataRow(2, true, false, DisplayName = "two salt, protocol 2, non-uv")]
    [DataRow(2, true, true, DisplayName = "two salt, protocol 2, uv")]
    public async Task HmacSecretGetAssertionSucceedsAcrossSaltCountProtocolAndUvPosture(int saltCount, bool isProtocolTwo, bool userVerified)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = isProtocolTwo ? CtapPinUvAuthProtocolId.Two : CtapPinUvAuthProtocolId.One;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator(
            $"hmac-secret-matrix-{saltCount}-{isProtocolTwo}-{userVerified}",
            BaseMemoryPool.Shared);

        byte[] credentialIdBytes = await CtapMakeCredentialGetAssertionFixtures.RegisterAndCaptureCredentialIdBytesAsync(
            simulator, pool, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x50), cancellationToken, RpId).ConfigureAwait(false);

        byte[]? gaParam = null;
        if(userVerified)
        {
            byte[] token = await EstablishPinAndIssueGaTokenAsync(simulator, pool, protocolId, RpId, cancellationToken).ConfigureAwait(false);
            gaParam = await CtapConfigFixtures.ComputeSignatureAsync(
                token, protocolId, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(32, 0x20), pool, cancellationToken).ConfigureAwait(false);
        }

        using CtapPlatformPinSession hmacSecretSession = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, cancellationToken).ConfigureAwait(false);

        byte[] salt1 = CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(32, 0x60);
        byte[]? salt2 = saltCount == 2 ? CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(32, 0x70) : null;
        (byte[] saltEnc, byte[] saltAuth) = await hmacSecretSession.BuildHmacSecretSaltsAsync(salt1, salt2, cancellationToken).ConfigureAwait(false);

        int? requestProtocol = isProtocolTwo ? (int)protocolId : null;
        ReadOnlyMemory<byte> extensions = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            hmacSecretSession.PlatformPublicKeyCose, saltEnc, saltAuth, requestProtocol);

        //Explicit if/else, not a ternary or a direct byte[]?-to-ReadOnlyMemory<byte>?-argument pass:
        //gaParam's own implicit array-to-ReadOnlyMemory<byte> conversion turns even a null array into a
        //non-null (empty, zero-length) ReadOnlyMemory<byte>, so BuildGetAssertionRequest's own
        //zero-length probe (WellKnownCtapStatusCodes.PinNotSet) would fire for every non-uv row unless
        //this is resolved explicitly first (CtapMakeCredentialRequestCborReader's own documented reason
        //for this shape).
        ReadOnlyMemory<byte>? resolvedGaParam;
        if(gaParam is byte[] gaParamBytes)
        {
            resolvedGaParam = gaParamBytes;
        }
        else
        {
            resolvedGaParam = null;
        }

        CtapGetAssertionRequest request = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(
            pool, rpId: RpId, allowList: CtapClientPinFixtures.BuildAllowList(credentialIdBytes, pool), extensions: extensions,
            pinUvAuthParam: resolvedGaParam, pinUvAuthProtocol: userVerified ? (int)protocolId : null);

        CtapGetAssertionResponse response = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            simulator.TransceiveAsync, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(request);
        DisposeResponse(response);

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.AreEqual(userVerified, authenticatorData.Flags.UserVerified, "the response's own uv bit must match the resolved posture.");
        Assert.IsTrue(authenticatorData.Flags.ExtensionDataIncluded, "a granted hmac-secret request must set the ED flag.");

        byte[] decryptedOutput = await DecryptHmacSecretOutputAsync(hmacSecretSession, authenticatorData, cancellationToken).ConfigureAwait(false);
        Assert.HasCount(saltCount * 32, decryptedOutput, "the decrypted hmac-secret output must be exactly 32 (one salt) or 64 (two salt) bytes.");
    }


    /// <summary>
    /// A present-but-unsupported <c>pinUvAuthProtocol</c> (e.g. <c>3</c>) rejects with exactly
    /// <see cref="WellKnownCtapStatusCodes.InvalidParameter"/> (step 1, the clientPIN §6.5.5
    /// analog) — the crypto never runs, so any salts suffice.
    /// </summary>
    [TestMethod]
    public async Task HmacSecretUnsupportedProtocolReturnsInvalidParameter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("hmac-secret-unsupported-protocol",BaseMemoryPool.Shared);
        byte[] credentialIdBytes = await CtapMakeCredentialGetAssertionFixtures.RegisterAndCaptureCredentialIdBytesAsync(
            simulator, pool, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x51), cancellationToken, RpId).ConfigureAwait(false);

        using CtapPlatformPinSession session = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        (byte[] saltEnc, byte[] saltAuth) = await session.BuildHmacSecretSaltsAsync(
            CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(32, 0x61), null, cancellationToken).ConfigureAwait(false);

        ReadOnlyMemory<byte> extensions = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            session.PlatformPublicKeyCose, saltEnc, saltAuth, pinUvAuthProtocol: 3);
        CtapGetAssertionRequest request = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(
            pool, rpId: RpId, allowList: CtapClientPinFixtures.BuildAllowList(credentialIdBytes, pool), extensions: extensions);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            SendGetAssertionAsync(simulator, request, pool, cancellationToken).AsTask());
        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, exception.StatusCode);
    }


    /// <summary>
    /// <c>up: false</c> with the <c>hmac-secret</c> extension present rejects with exactly
    /// <see cref="WellKnownCtapStatusCodes.UnsupportedOption"/> (snapshot line 13283) — this
    /// authenticator's own general <c>up</c> handling does not already produce this code for a bare
    /// <c>up: false</c> ga request, so hmac-secret's own check is the only source of it.
    /// </summary>
    [TestMethod]
    public async Task HmacSecretUpFalseReturnsUnsupportedOption()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("hmac-secret-up-false",BaseMemoryPool.Shared);
        byte[] credentialIdBytes = await CtapMakeCredentialGetAssertionFixtures.RegisterAndCaptureCredentialIdBytesAsync(
            simulator, pool, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x52), cancellationToken, RpId).ConfigureAwait(false);

        using CtapPlatformPinSession session = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        (byte[] saltEnc, byte[] saltAuth) = await session.BuildHmacSecretSaltsAsync(
            CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(32, 0x62), null, cancellationToken).ConfigureAwait(false);

        ReadOnlyMemory<byte> extensions = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            session.PlatformPublicKeyCose, saltEnc, saltAuth);
        CtapGetAssertionRequest request = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(
            pool, rpId: RpId, allowList: CtapClientPinFixtures.BuildAllowList(credentialIdBytes, pool), extensions: extensions,
            options: new CtapCommandOptions(UserPresence: false));

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            SendGetAssertionAsync(simulator, request, pool, cancellationToken).AsTask());
        Assert.AreEqual(WellKnownCtapStatusCodes.UnsupportedOption, exception.StatusCode);
    }


    /// <summary>
    /// A <c>saltAuth</c> that fails <c>verify(sharedSecret, saltEnc, saltAuth)</c> rejects with exactly
    /// <see cref="WellKnownCtapStatusCodes.PinAuthInvalid"/> (snapshot line 13304) — checked
    /// BEFORE any decrypt is attempted.
    /// </summary>
    [TestMethod]
    public async Task HmacSecretTamperedSaltAuthReturnsPinAuthInvalid()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("hmac-secret-tampered-auth",BaseMemoryPool.Shared);
        byte[] credentialIdBytes = await CtapMakeCredentialGetAssertionFixtures.RegisterAndCaptureCredentialIdBytesAsync(
            simulator, pool, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x53), cancellationToken, RpId).ConfigureAwait(false);

        using CtapPlatformPinSession session = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        (byte[] saltEnc, byte[] saltAuth) = await session.BuildHmacSecretSaltsAsync(
            CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(32, 0x63), null, cancellationToken).ConfigureAwait(false);
        saltAuth[0] ^= 0xFF;

        ReadOnlyMemory<byte> extensions = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            session.PlatformPublicKeyCose, saltEnc, saltAuth);
        CtapGetAssertionRequest request = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(
            pool, rpId: RpId, allowList: CtapClientPinFixtures.BuildAllowList(credentialIdBytes, pool), extensions: extensions);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            SendGetAssertionAsync(simulator, request, pool, cancellationToken).AsTask());
        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, exception.StatusCode);
    }


    /// <summary>
    /// A <c>saltEnc</c> that fails to DECRYPT outright (too short for protocol two's 16-byte IV prefix)
    /// but still carries a verifying <c>saltAuth</c> rejects with exactly
    /// <see cref="WellKnownCtapStatusCodes.InvalidParameter"/> (snapshot line 13307) — the OTHER
    /// trigger of <see cref="CtapGetAssertionHmacSecretOutcomeKind.DecryptFailed"/>, distinct from the
    /// decrypts-to-the-wrong-length trigger below.
    /// </summary>
    [TestMethod]
    public async Task HmacSecretDecryptFailureReturnsInvalidParameter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("hmac-secret-decrypt-failure",BaseMemoryPool.Shared);
        byte[] credentialIdBytes = await CtapMakeCredentialGetAssertionFixtures.RegisterAndCaptureCredentialIdBytesAsync(
            simulator, pool, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x5D), cancellationToken, RpId).ConfigureAwait(false);

        using CtapPlatformPinSession session = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, cancellationToken).ConfigureAwait(false);
        (byte[] saltEnc, byte[] saltAuth) = await session.BuildMalformedHmacSecretSaltsAsync(cancellationToken).ConfigureAwait(false);

        ReadOnlyMemory<byte> extensions = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            session.PlatformPublicKeyCose, saltEnc, saltAuth, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        CtapGetAssertionRequest request = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(
            pool, rpId: RpId, allowList: CtapClientPinFixtures.BuildAllowList(credentialIdBytes, pool), extensions: extensions);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            SendGetAssertionAsync(simulator, request, pool, cancellationToken).AsTask());
        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, exception.StatusCode);
    }


    /// <summary>
    /// A correctly-verified <c>saltEnc</c> that decrypts to exactly 48 bytes (neither 32 nor 64) rejects
    /// with exactly <see cref="WellKnownCtapStatusCodes.InvalidParameter"/> (snapshot line 13307) —
    /// the gate is on the DECRYPTED plaintext length, distinct from the verify-failure branch above.
    /// </summary>
    [TestMethod]
    public async Task HmacSecretDecryptedPlaintextWrongLengthReturnsInvalidParameter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("hmac-secret-wrong-length",BaseMemoryPool.Shared);
        byte[] credentialIdBytes = await CtapMakeCredentialGetAssertionFixtures.RegisterAndCaptureCredentialIdBytesAsync(
            simulator, pool, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x54), cancellationToken, RpId).ConfigureAwait(false);

        using CtapPlatformPinSession session = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, cancellationToken).ConfigureAwait(false);
        //salt2 is null, so BuildHmacSecretSaltsAsync encrypts salt1 verbatim -- a 48-byte, block-aligned
        //plaintext, neither the 32- nor 64-byte shape §12.7 requires.
        (byte[] saltEnc, byte[] saltAuth) = await session.BuildHmacSecretSaltsAsync(
            CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(48, 0x64), null, cancellationToken).ConfigureAwait(false);

        ReadOnlyMemory<byte> extensions = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            session.PlatformPublicKeyCose, saltEnc, saltAuth, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        CtapGetAssertionRequest request = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(
            pool, rpId: RpId, allowList: CtapClientPinFixtures.BuildAllowList(credentialIdBytes, pool), extensions: extensions);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            SendGetAssertionAsync(simulator, request, pool, cancellationToken).AsTask());
        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, exception.StatusCode);
    }


    /// <summary>
    /// hmac-secret runs identically for a discoverable (resident, <c>allowList</c>-absent) credential and
    /// an <c>allowList</c>-addressed one (CTAP 2.3 §12.7 snapshot line 13087's MUST — "both discoverable
    /// and non-discoverable credentials") — both calls against the SAME resident credential succeed and
    /// each yields a 32-byte decrypted output.
    /// </summary>
    [TestMethod]
    public async Task HmacSecretServesBothDiscoverableAndAllowListResolution()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("hmac-secret-13087",BaseMemoryPool.Shared);
        byte[] credentialIdBytes = await CtapMakeCredentialGetAssertionFixtures.RegisterAndCaptureCredentialIdBytesAsync(
            simulator, pool, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x55), cancellationToken, RpId, resident: true).ConfigureAwait(false);

        byte[] discoverableOutput = await RunOneSaltHmacSecretAsync(simulator, pool, RpId, allowList: null, cancellationToken).ConfigureAwait(false);
        byte[] allowListOutput = await RunOneSaltHmacSecretAsync(
            simulator, pool, RpId, CtapClientPinFixtures.BuildAllowList(credentialIdBytes, pool), cancellationToken).ConfigureAwait(false);

        Assert.HasCount(32, discoverableOutput, "the discoverable-scan call must produce a 32-byte output.");
        Assert.HasCount(32, allowListOutput, "the allowList call must produce a 32-byte output.");
    }


    /// <summary>
    /// A credential minted with NO <c>hmac-secret</c> extension in its <c>authenticatorMakeCredential</c>
    /// request still serves a later <c>authenticatorGetAssertion</c>'s <c>hmac-secret</c> extension
    /// (snapshot line 13192's SHOULD, adopted): CredRandom generation is unconditional.
    /// </summary>
    [TestMethod]
    public async Task HmacSecretServesAssertionForCredentialMintedWithoutTheExtension()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("hmac-secret-r2c",BaseMemoryPool.Shared);

        //RegisterAndCaptureCredentialIdBytesAsync's own mc request carries no extensions member at all --
        //the credential is minted with hmac-secret entirely unmentioned.
        byte[] credentialIdBytes = await CtapMakeCredentialGetAssertionFixtures.RegisterAndCaptureCredentialIdBytesAsync(
            simulator, pool, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x56), cancellationToken, RpId).ConfigureAwait(false);

        byte[] decryptedOutput = await RunOneSaltHmacSecretAsync(
            simulator, pool, RpId, CtapClientPinFixtures.BuildAllowList(credentialIdBytes, pool), cancellationToken).ConfigureAwait(false);

        Assert.HasCount(32, decryptedOutput, "a credential minted without the extension must still serve a later hmac-secret assertion.");
    }


    /// <summary>
    /// Determinism: the SAME credential, salt, and uv posture, called twice, decrypts to the IDENTICAL
    /// output both times (in-process; the wire-only version lands elsewhere).
    /// </summary>
    [TestMethod]
    public async Task HmacSecretOutputIsDeterministicForTheSameSaltAndUvPosture()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("hmac-secret-determinism",BaseMemoryPool.Shared);
        byte[] credentialIdBytes = await CtapMakeCredentialGetAssertionFixtures.RegisterAndCaptureCredentialIdBytesAsync(
            simulator, pool, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x57), cancellationToken, RpId).ConfigureAwait(false);

        byte[] firstOutput = await RunOneSaltHmacSecretAsync(
            simulator, pool, RpId, CtapClientPinFixtures.BuildAllowList(credentialIdBytes, pool), cancellationToken).ConfigureAwait(false);
        byte[] secondOutput = await RunOneSaltHmacSecretAsync(
            simulator, pool, RpId, CtapClientPinFixtures.BuildAllowList(credentialIdBytes, pool), cancellationToken).ConfigureAwait(false);

        Assert.AreSequenceEqual(firstOutput, secondOutput, "the same credential, salt, and uv posture must decrypt to the identical output every time.");
    }


    /// <summary>
    /// uv-separation: the SAME credential and salt, called once with <c>uv:0</c> and once with <c>uv:1</c>,
    /// decrypts to DIFFERENT outputs — <see cref="CtapCredentialRecord.CredRandomWithUV"/> and
    /// <see cref="CtapCredentialRecord.CredRandomWithoutUV"/> are observably distinct (property (b)).
    /// A PIN-protected authenticator still answers a token-less ga with <c>uv:0</c> (the "protected but
    /// neither param nor uv present" fallback), so both calls target the SAME credential on the SAME
    /// simulator instance.
    /// </summary>
    [TestMethod]
    public async Task HmacSecretOutputDiffersBetweenUvAndNonUvForTheSameCredentialAndSalt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        const CtapPinUvAuthProtocolId ProtocolId = CtapPinUvAuthProtocolId.Two;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("hmac-secret-uv-separation",BaseMemoryPool.Shared);
        byte[] credentialIdBytes = await CtapMakeCredentialGetAssertionFixtures.RegisterAndCaptureCredentialIdBytesAsync(
            simulator, pool, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x58), cancellationToken, RpId).ConfigureAwait(false);
        byte[] token = await EstablishPinAndIssueGaTokenAsync(simulator, pool, ProtocolId, RpId, cancellationToken).ConfigureAwait(false);
        byte[] gaParam = await CtapConfigFixtures.ComputeSignatureAsync(
            token, ProtocolId, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(32, 0x20), pool, cancellationToken).ConfigureAwait(false);

        //The uv:1 call runs FIRST: CTAP 2.3 §6.2.2 step 9 clears every pinUvAuthToken's permissions
        //(except lbw) once a "up" gesture is confirmed, which every successful ga call performs
        //regardless of whether IT used a token — a token-less uv:0 call run first would strip the
        //just-issued token's ga permission before this method ever presents it.
        byte[] uvOutput = await RunOneSaltHmacSecretAsync(
            simulator, pool, RpId, CtapClientPinFixtures.BuildAllowList(credentialIdBytes, pool), cancellationToken,
            gaParam: gaParam, gaProtocolId: ProtocolId).ConfigureAwait(false);

        byte[] nonUvOutput = await RunOneSaltHmacSecretAsync(
            simulator, pool, RpId, CtapClientPinFixtures.BuildAllowList(credentialIdBytes, pool), cancellationToken).ConfigureAwait(false);

        Assert.AreNotSequenceEqual(nonUvOutput, uvOutput, "uv=0 and uv=1 must select different CredRandom values, producing different outputs.");
    }


    /// <summary>
    /// Linkage: a two-salt request's decrypted output's first 32 bytes equal a one-salt request's whole
    /// output, for the SAME credential and salt1 (property (c)) — both derive
    /// <c>HMAC-SHA-256(CredRandom, salt1)</c> from the identical CredRandom.
    /// </summary>
    [TestMethod]
    public async Task TwoSaltOutputsFirstHalfLinksToTheOneSaltOutputForTheSameSalt1()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("hmac-secret-linkage",BaseMemoryPool.Shared);
        byte[] credentialIdBytes = await CtapMakeCredentialGetAssertionFixtures.RegisterAndCaptureCredentialIdBytesAsync(
            simulator, pool, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x59), cancellationToken, RpId).ConfigureAwait(false);

        byte[] salt1 = CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(32, 0x65);

        using CtapPlatformPinSession oneSaltSession = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        byte[] oneSaltOutput = await SendHmacSecretRequestAsync(
            simulator, pool, RpId, CtapClientPinFixtures.BuildAllowList(credentialIdBytes, pool), oneSaltSession, salt1, salt2: null, cancellationToken).ConfigureAwait(false);

        using CtapPlatformPinSession twoSaltSession = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);
        byte[] twoSaltOutput = await SendHmacSecretRequestAsync(
            simulator, pool, RpId, CtapClientPinFixtures.BuildAllowList(credentialIdBytes, pool), twoSaltSession, salt1,
            CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(32, 0x66), cancellationToken).ConfigureAwait(false);

        byte[] twoSaltFirstHalf = twoSaltOutput[..32];
        Assert.AreSequenceEqual(oneSaltOutput, twoSaltFirstHalf, "a two-salt output's first 32 bytes must equal the one-salt output for the same salt1.");
    }


    /// <summary>
    /// Credential isolation (also grounds the 12827 evidence rewrite): the SAME salt against TWO
    /// DIFFERENT credentials decrypts to DIFFERENT outputs — each credential's own independently random
    /// CredRandom pair is never shared or derivable across credentials.
    /// </summary>
    [TestMethod]
    public async Task HmacSecretOutputDiffersAcrossTwoDifferentCredentialsForTheSameSalt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("hmac-secret-isolation",BaseMemoryPool.Shared);
        byte[] firstCredentialIdBytes = await CtapMakeCredentialGetAssertionFixtures.RegisterAndCaptureCredentialIdBytesAsync(
            simulator, pool, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x5A), cancellationToken, RpId).ConfigureAwait(false);
        byte[] secondCredentialIdBytes = await CtapMakeCredentialGetAssertionFixtures.RegisterAndCaptureCredentialIdBytesAsync(
            simulator, pool, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x5B), cancellationToken, RpId).ConfigureAwait(false);

        byte[] firstOutput = await RunOneSaltHmacSecretAsync(
            simulator, pool, RpId, CtapClientPinFixtures.BuildAllowList(firstCredentialIdBytes, pool), cancellationToken).ConfigureAwait(false);
        byte[] secondOutput = await RunOneSaltHmacSecretAsync(
            simulator, pool, RpId, CtapClientPinFixtures.BuildAllowList(secondCredentialIdBytes, pool), cancellationToken).ConfigureAwait(false);

        Assert.AreNotSequenceEqual(firstOutput, secondOutput, "the same salt against two different credentials must decrypt to different outputs.");
    }


    /// <summary>
    /// Protocol-two IV freshness: two byte-identical protocol-two ga requests produce DIFFERENT
    /// raw <c>hmac-secret</c> ciphertext bytes on the wire (a fresh random IV per <c>encrypt</c> call),
    /// yet decrypt to the IDENTICAL output.
    /// </summary>
    [TestMethod]
    public async Task ProtocolTwoCiphertextIsFreshPerRequestButDecryptsIdentically()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("hmac-secret-iv-freshness",BaseMemoryPool.Shared);
        byte[] credentialIdBytes = await CtapMakeCredentialGetAssertionFixtures.RegisterAndCaptureCredentialIdBytesAsync(
            simulator, pool, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x5C), cancellationToken, RpId).ConfigureAwait(false);

        using CtapPlatformPinSession session = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, cancellationToken).ConfigureAwait(false);
        byte[] salt1 = CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(32, 0x67);
        (byte[] saltEnc, byte[] saltAuth) = await session.BuildHmacSecretSaltsAsync(salt1, null, cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> extensions = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            session.PlatformPublicKeyCose, saltEnc, saltAuth, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);

        (byte[] firstCiphertext, byte[] firstDecrypted) = await SendAndCaptureCiphertextAsync(
            simulator, pool, RpId, CtapClientPinFixtures.BuildAllowList(credentialIdBytes, pool), extensions, session, cancellationToken).ConfigureAwait(false);
        (byte[] secondCiphertext, byte[] secondDecrypted) = await SendAndCaptureCiphertextAsync(
            simulator, pool, RpId, CtapClientPinFixtures.BuildAllowList(credentialIdBytes, pool), extensions, session, cancellationToken).ConfigureAwait(false);

        Assert.AreNotSequenceEqual(firstCiphertext, secondCiphertext, "two identical protocol-two requests must produce different wire ciphertext (fresh IV per call).");
        Assert.AreSequenceEqual(firstDecrypted, secondDecrypted, "both requests must decrypt to the identical output despite the different ciphertext.");
    }


    /// <summary>
    /// Establishes <paramref name="pin"/> as the authenticator's PIN and issues a <c>ga</c>-permission
    /// <c>pinUvAuthToken</c> under <paramref name="protocolId"/>, decrypted from wire bytes only.
    /// </summary>
    private static async Task<byte[]> EstablishPinAndIssueGaTokenAsync(
        CtapAuthenticatorSimulator simulator, BaseMemoryPool pool, CtapPinUvAuthProtocolId protocolId, string? rpId, CancellationToken cancellationToken)
    {
        using CtapPlatformPinSession setPinSession = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, cancellationToken).ConfigureAwait(false);
        (byte[] newPinEnc, byte[] setPinParam) = await setPinSession.BuildSetPinMessagesAsync(Pin, cancellationToken).ConfigureAwait(false);

        var setPinRequest = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: setPinSession.PlatformPublicKeyCose, PinUvAuthParam: setPinParam, NewPinEnc: newPinEnc);
        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, setPinRequest, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);

        using CtapPlatformPinSession tokenSession = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, cancellationToken).ConfigureAwait(false);
        byte[] pinHashEnc = await tokenSession.BuildPinHashEncAsync(Pin, cancellationToken).ConfigureAwait(false);

        var tokenRequest = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: tokenSession.PlatformPublicKeyCose, PinHashEnc: pinHashEnc, Permissions: WellKnownCtapPinUvAuthTokenPermissions.Ga, RpId: rpId);
        CtapClientPinResponse tokenResponse = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, tokenRequest, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);

        return await tokenSession.DecryptTokenAsync(tokenResponse.PinUvAuthToken!.Value, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds a fresh protocol-one hmac-secret session, sends ONE ga request carrying a one-salt
    /// hmac-secret extension against <paramref name="allowList"/> (or a discoverable scan when
    /// <see langword="null"/>), and returns the decrypted 32-byte output — the shared shape most of this
    /// file's property tests compose from.
    /// </summary>
    private static async Task<byte[]> RunOneSaltHmacSecretAsync(
        CtapAuthenticatorSimulator simulator, BaseMemoryPool pool, string rpId, IReadOnlyList<PublicKeyCredentialDescriptor>? allowList,
        CancellationToken cancellationToken, byte[]? gaParam = null, CtapPinUvAuthProtocolId? gaProtocolId = null)
    {
        using CtapPlatformPinSession session = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.One, pool, cancellationToken).ConfigureAwait(false);

        return await SendHmacSecretRequestAsync(
            simulator, pool, rpId, allowList, session, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(32, 0x60), salt2: null, cancellationToken,
            gaParam, gaProtocolId).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds <paramref name="session"/>'s salt(s), sends ONE ga request carrying them against
    /// <paramref name="allowList"/>, and returns the decrypted output.
    /// </summary>
    private static async Task<byte[]> SendHmacSecretRequestAsync(
        CtapAuthenticatorSimulator simulator, BaseMemoryPool pool, string rpId, IReadOnlyList<PublicKeyCredentialDescriptor>? allowList,
        CtapPlatformPinSession session, byte[] salt1, byte[]? salt2, CancellationToken cancellationToken,
        byte[]? gaParam = null, CtapPinUvAuthProtocolId? gaProtocolId = null)
    {
        (byte[] saltEnc, byte[] saltAuth) = await session.BuildHmacSecretSaltsAsync(salt1, salt2, cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> extensions = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionHmacSecretExtensionsInput(
            session.PlatformPublicKeyCose, saltEnc, saltAuth);

        //Explicit if/else, not a direct byte[]?-to-ReadOnlyMemory<byte>?-argument pass -- see the
        //identical resolvedGaParam remark in HmacSecretGetAssertionSucceedsAcrossSaltCountProtocolAndUvPosture.
        ReadOnlyMemory<byte>? resolvedGaParam;
        if(gaParam is byte[] gaParamBytes)
        {
            resolvedGaParam = gaParamBytes;
        }
        else
        {
            resolvedGaParam = null;
        }

        CtapGetAssertionRequest request = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(
            pool, rpId: rpId, allowList: allowList, extensions: extensions, pinUvAuthParam: resolvedGaParam,
            pinUvAuthProtocol: gaProtocolId is CtapPinUvAuthProtocolId protocolId ? (int)protocolId : null);

        CtapGetAssertionResponse response = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            simulator.TransceiveAsync, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(request);
        DisposeResponse(response);

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool);

        return await DecryptHmacSecretOutputAsync(session, authenticatorData, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Sends ONE ga request carrying <paramref name="extensions"/> and returns both the raw, still-encrypted
    /// wire ciphertext and its decrypted content — the shape the IV-freshness property needs,
    /// distinct from every other helper here that returns only the decrypted content.
    /// </summary>
    private static async Task<(byte[] Ciphertext, byte[] Decrypted)> SendAndCaptureCiphertextAsync(
        CtapAuthenticatorSimulator simulator, BaseMemoryPool pool, string rpId, IReadOnlyList<PublicKeyCredentialDescriptor> allowList,
        ReadOnlyMemory<byte> extensions, CtapPlatformPinSession session, CancellationToken cancellationToken)
    {
        CtapGetAssertionRequest request = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(pool, rpId: rpId, allowList: allowList, extensions: extensions);

        CtapGetAssertionResponse response = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            simulator.TransceiveAsync, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(request);
        DisposeResponse(response);

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool);
        byte[] ciphertext = DecodeCborByteString(FindHmacSecretOutput(authenticatorData.Extensions));
        byte[] decrypted = await session.DecryptHmacSecretOutputAsync(ciphertext, cancellationToken).ConfigureAwait(false);

        return (ciphertext, decrypted);
    }


    /// <summary>Decrypts the decoded <paramref name="authenticatorData"/>'s <c>hmac-secret</c> authData output under <paramref name="session"/>'s shared secret.</summary>
    private static async Task<byte[]> DecryptHmacSecretOutputAsync(CtapPlatformPinSession session, AuthenticatorData authenticatorData, CancellationToken cancellationToken)
    {
        byte[] encryptedOutput = DecodeCborByteString(FindHmacSecretOutput(authenticatorData.Extensions));

        return await session.DecryptHmacSecretOutputAsync(encryptedOutput, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Locates the <c>"hmac-secret"</c> entry's still-CBOR-encoded value in a decoded ga authData extensions map.</summary>
    private static ReadOnlyMemory<byte> FindHmacSecretOutput(ReadOnlyMemory<byte> extensionsCbor)
    {
        IReadOnlyList<Fido2ExtensionOutput> outputs = AuthenticatorExtensionOutputsCborReader.Read(extensionsCbor);
        foreach(Fido2ExtensionOutput output in outputs)
        {
            if(output.Identifier == WellKnownWebAuthnExtensionIdentifiers.HmacSecret)
            {
                return output.Value;
            }
        }

        throw new InvalidOperationException("No 'hmac-secret' extension output was present in the decoded authData extensions map.");
    }


    /// <summary>Decodes a CBOR byte-string item's raw content bytes (the wire form <see cref="AuthenticatorExtensionOutputsCborReader"/> hands back, still type/length-prefixed).</summary>
    private static byte[] DecodeCborByteString(ReadOnlyMemory<byte> encoded) =>
        new CborReader(encoded, CborOptions.Ctap2Canonical).ReadByteString();


    /// <summary>Sends <paramref name="request"/> through <see cref="CtapAuthenticatorGetAssertionClient.GetAssertionAsync"/>, disposing the request either way.</summary>
    private static ValueTask<CtapGetAssertionResponse> SendGetAssertionAsync(
        CtapAuthenticatorSimulator simulator, CtapGetAssertionRequest request, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        try
        {
            return CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
                simulator.TransceiveAsync, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken);
        }
        finally
        {
            CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(request);
        }
    }


    /// <summary>Disposes a decoded ga response's own SensitiveMemory carriers (the credential descriptor and, when present, the response user handle).</summary>
    private static void DisposeResponse(CtapGetAssertionResponse response)
    {
        response.Credential.Id.Dispose();
        response.User?.Id.Dispose();
    }
}
