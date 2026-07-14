using System;
using System.Buffers;
using System.Formats.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wave PKG-B unit-test matrix for the <c>credProtect</c> (CTAP 2.3 §12.1) and <c>minPinLength</c>
/// (§12.5) extensions end to end: <c>authenticatorMakeCredential</c>'s extension processing (R6,
/// including the equal-or-subset pair rows 3557/4110 proven non-vacuously both directions), the
/// excludeList credProtect-aware branch (R9), and <c>authenticatorGetAssertion</c>'s two asymmetric
/// credProtect filters (R10). Driven in-process through <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/>
/// (real-wire capstones are a later package), with platform-side <c>pinUvAuthParam</c> computed the same
/// way the wave-5c fixtures compute mc/ga's own — through <see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/>
/// over the actual token bytes, never a test-only crypto reimplementation. Every assertion decodes REAL
/// wire bytes (the response's own <c>authData</c>/extensions), never back-channel simulator state.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorExtensionsTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The plaintext PIN every UV-collecting test in this file establishes.</summary>
    private const string DefaultPin = "1234";

    /// <summary>The fixed <c>clientDataHash</c> bytes <see cref="CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest"/> always embeds — the mc verify message <see cref="ComputeMcSignatureAsync"/> signs.</summary>
    private static byte[] McClientDataHash => BuildFixedBytes(32, 0x10);

    /// <summary>The fixed <c>clientDataHash</c> bytes <see cref="CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest"/> always embeds — the ga verify message <see cref="ComputeGaSignatureAsync"/> signs.</summary>
    private static byte[] GaClientDataHash => BuildFixedBytes(32, 0x20);


    /// <summary>
    /// A solicited, legal <c>credProtect</c> value (R6/line 12632's MUST: the output value equals the
    /// level "the authenticator set for the created credential", here the requested level) is the ONLY
    /// key the authData extensions map carries — the equal-or-subset MUST's forward direction (row
    /// 3557/4110): a request naming only <c>credProtect</c> never yields a <c>minPinLength</c> key.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialWithCredProtectAloneEmitsOnlyCredProtectKeyWithRequestedLevel()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ext-mc-credprotect-alone");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ReadOnlyMemory<byte> extensions = BuildMakeCredentialExtensionsInput(credProtect: 2);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, extensions: extensions);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);

        Assert.IsTrue(authenticatorData.Flags.ExtensionDataIncluded);
        var outputs = AuthenticatorExtensionOutputsCborReader.Read(authenticatorData.Extensions);
        Assert.HasCount(1, outputs);
        Assert.AreEqual(WellKnownWebAuthnExtensionIdentifiers.CredProtect, outputs[0].Identifier);
        Assert.AreEqual(2, ReadCborInt32(outputs[0].Value));
    }


    /// <summary>
    /// An authorized <c>minPinLength</c> request with NO <c>credProtect</c> entry emits only the
    /// <c>minPinLength</c> key, with the current minimum PIN length as its value — the equal-or-subset
    /// MUST's reverse direction, AND line 12648's MUST NOT (no unsolicited <c>credProtect</c> output)
    /// proven non-vacuously: the extensions map genuinely exists (carrying <c>minPinLength</c>) yet
    /// still carries no <c>credProtect</c> key.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialWithMinPinLengthAloneForAuthorizedRpEmitsOnlyMinPinLengthKeyAndNeverCredProtect()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ext-mc-minpinlength-alone");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        await AuthorizeRpForMinPinLengthAsync(simulator, pool, protocolId, [DefaultRpId], TestContext.CancellationToken);

        ReadOnlyMemory<byte> extensions = BuildMakeCredentialExtensionsInput(minPinLength: true);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, extensions: extensions);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);

        Assert.IsTrue(authenticatorData.Flags.ExtensionDataIncluded);
        var outputs = AuthenticatorExtensionOutputsCborReader.Read(authenticatorData.Extensions);
        Assert.HasCount(1, outputs);
        Assert.AreEqual(WellKnownWebAuthnExtensionIdentifiers.MinPinLength, outputs[0].Identifier);
        Assert.AreEqual(CtapAuthenticatorState.DefaultMinPinCodePointLength, ReadCborInt32(outputs[0].Value));
    }


    /// <summary>
    /// An unauthorized RP's <c>minPinLength</c> request completes with <c>CTAP2_OK</c> and NO extensions
    /// output whatsoever — §12.5 defines no error path for this case (extraction trap 8): the RP simply
    /// never learns the current minimum PIN length.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialWithMinPinLengthForUnauthorizedRpReturnsOkWithNoExtensionsOutput()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ext-mc-minpinlength-unauthorized");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ReadOnlyMemory<byte> extensions = BuildMakeCredentialExtensionsInput(minPinLength: true);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, extensions: extensions);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);

        Assert.IsFalse(authenticatorData.Flags.ExtensionDataIncluded, "no key was resolved on either extension, so the whole extensions map — and the ED bit — must be absent.");
    }


    /// <summary>Both extensions requested and both authorized: the authData extensions map carries both keys, canonical-ordered (<c>credProtect</c> before <c>minPinLength</c>).</summary>
    [TestMethod]
    public async Task MakeCredentialWithBothExtensionsRequestedAndAuthorizedEmitsBothKeysInCanonicalOrder()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ext-mc-both-extensions");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        await AuthorizeRpForMinPinLengthAsync(simulator, pool, protocolId, [DefaultRpId], TestContext.CancellationToken);

        ReadOnlyMemory<byte> extensions = BuildMakeCredentialExtensionsInput(credProtect: 3, minPinLength: true);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, extensions: extensions);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);

        var outputs = AuthenticatorExtensionOutputsCborReader.Read(authenticatorData.Extensions);
        Assert.HasCount(2, outputs);
        Assert.AreEqual(WellKnownWebAuthnExtensionIdentifiers.CredProtect, outputs[0].Identifier, "credProtect (11 chars) sorts before minPinLength (12 chars) under CTAP2 canonical ordering.");
        Assert.AreEqual(3, ReadCborInt32(outputs[0].Value));
        Assert.AreEqual(WellKnownWebAuthnExtensionIdentifiers.MinPinLength, outputs[1].Identifier);
        Assert.AreEqual(CtapAuthenticatorState.DefaultMinPinCodePointLength, ReadCborInt32(outputs[1].Value));
    }


    /// <summary>A <c>credProtect</c> value outside the three legal wire values {1, 2, 3} rejects with <c>CTAP2_ERR_INVALID_PARAMETER</c> (R6, a documented deviation — §12.1 defines no error path of its own).</summary>
    [TestMethod]
    [DataRow(0, DisplayName = "zero")]
    [DataRow(4, DisplayName = "one-past-range")]
    public async Task MakeCredentialWithInvalidCredProtectValueReturnsInvalidParameter(int illegalCredProtect)
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator($"ext-mc-credprotect-invalid-{illegalCredProtect}");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ReadOnlyMemory<byte> extensions = BuildMakeCredentialExtensionsInput(credProtect: illegalCredProtect);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, extensions: extensions);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A request with no recognized extension input produces authData with no extensions section at all — byte-identical in shape to every pre-wave mc response.</summary>
    [TestMethod]
    public async Task MakeCredentialWithNoExtensionsRequestedProducesNoExtensionDataFlag()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ext-mc-no-extensions");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);

        Assert.IsFalse(authenticatorData.Flags.ExtensionDataIncluded);
        Assert.AreEqual(0, authenticatorData.Extensions.Length);
    }


    /// <summary>An excludeList match at the default level (<c>userVerificationOptional</c>, 1) is excluded unconditionally, with no UV involved — the pre-existing regression shape, re-derived non-vacuously against the new credProtect-aware branch.</summary>
    [TestMethod]
    public async Task MakeCredentialExcludeListMatchAtDefaultLevelIsExcludedUnconditionally()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ext-mc-exclude-level1");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapWave2RegisteredCredential registered = await RegisterCredentialAsync(simulator, pool, BuildFixedBytes(16, 0xC0), TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, userId: BuildFixedBytes(16, 0xC1),
            excludeList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = registered.CredentialId }]);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.CredentialExcluded, response.AsReadOnlySpan()[0]);
        registered.CredentialId.Dispose();
    }


    /// <summary>An excludeList match at level <c>userVerificationOptionalWithCredentialIDList</c> (2) is excluded unconditionally, exactly like level 1 — R9's exemption is level-3-only.</summary>
    [TestMethod]
    public async Task MakeCredentialExcludeListMatchAtLevelTwoIsExcludedUnconditionally()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ext-mc-exclude-level2");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapWave2RegisteredCredential registered = await RegisterCredentialAsync(
            simulator, pool, BuildFixedBytes(16, 0xC2), TestContext.CancellationToken, credProtect: 2);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, userId: BuildFixedBytes(16, 0xC3),
            excludeList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = registered.CredentialId }]);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.CredentialExcluded, response.AsReadOnlySpan()[0]);
        registered.CredentialId.Dispose();
    }


    /// <summary>An excludeList match at level <c>userVerificationRequired</c> (3) WITH <c>uv</c> already collected in the same call is excluded, exactly like levels 1/2.</summary>
    [TestMethod]
    public async Task MakeCredentialExcludeListMatchAtLevelThreeWithUvCollectedIsExcluded()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ext-mc-exclude-level3-uv");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        CtapWave2RegisteredCredential registered = await RegisterCredentialAsync(
            simulator, pool, BuildFixedBytes(16, 0xC4), TestContext.CancellationToken, credProtect: 3);

        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Mc, rpId: DefaultRpId, TestContext.CancellationToken);
        byte[] param = await ComputeMcSignatureAsync(token, protocolId, pool, TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, userId: BuildFixedBytes(16, 0xC5), pinUvAuthParam: param, pinUvAuthProtocol: (int)protocolId,
            excludeList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = registered.CredentialId }]);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.CredentialExcluded, response.AsReadOnlySpan()[0]);
        registered.CredentialId.Dispose();
    }


    /// <summary>
    /// R9's inversion (trap 2): an excludeList match at level <c>userVerificationRequired</c> (3) with
    /// NO <c>uv</c> collected in this same call is silently dropped from consideration — the mc request
    /// SUCCEEDS exactly as if the excludeList had never matched.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialExcludeListMatchAtLevelThreeWithoutUvSucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ext-mc-exclude-level3-no-uv");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapWave2RegisteredCredential registered = await RegisterCredentialAsync(
            simulator, pool, BuildFixedBytes(16, 0xC6), TestContext.CancellationToken, credProtect: 3);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, userId: BuildFixedBytes(16, 0xC7),
            excludeList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = registered.CredentialId }]);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0], "a level-3 excludeList match with no UV collected must be silently dropped, letting mc proceed to success.");
        registered.CredentialId.Dispose();
    }


    /// <summary>
    /// R9's continue-parsing rule (CTAP 2.3 lines 3497-3498: "remove the credential from the excludeList
    /// and continue parsing the rest of the list"): the exemption is per-ENTRY, not a whole-list
    /// short-circuit. An excludeList naming the exempted level-3 credential FIRST and a level-1
    /// credential for the SAME rp.id SECOND still excludes — the scan must not stop at the first
    /// (exempted) match.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialExcludeListExemptedLevelThreeFirstThenLevelOneSecondStillExcludes()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ext-mc-exclude-level3-then-level1");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapWave2RegisteredCredential levelThree = await RegisterCredentialAsync(
            simulator, pool, BuildFixedBytes(16, 0xC8), TestContext.CancellationToken, credProtect: 3);
        CtapWave2RegisteredCredential levelOne = await RegisterCredentialAsync(
            simulator, pool, BuildFixedBytes(16, 0xC9), TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, userId: BuildFixedBytes(16, 0xCA),
            excludeList:
            [
                new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = levelThree.CredentialId },
                new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = levelOne.CredentialId }
            ]);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.CredentialExcluded, response.AsReadOnlySpan()[0], "a later, non-exempt list entry must still exclude even though the first entry was exempted.");
        levelThree.CredentialId.Dispose();
        levelOne.CredentialId.Dispose();
    }


    /// <summary>R10: a level-2 (<c>userVerificationOptionalWithCredentialIDList</c>) discoverable credential is invisible to a UV-less discoverable scan, but the SAME credential is assertable via an <c>allowList</c> request without UV — the allowList branch never applies the level-2 filter.</summary>
    [TestMethod]
    public async Task GetAssertionDiscoverableScanHidesLevelTwoCredentialWithoutUvButAllowListSeesIt()
    {
        const string rpId = "ext-ga-level2.example";
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ext-ga-level2");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapWave2RegisteredCredential registered = await RegisterCredentialAsync(
            simulator, pool, BuildFixedBytes(16, 0xD0), TestContext.CancellationToken, rpId: rpId, credProtect: 2);

        using(PooledMemory discoverableResponse = await SendGetAssertionAsync(simulator, BuildGetAssertionRequest(pool, rpId: rpId), pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, discoverableResponse.AsReadOnlySpan()[0], "level 2 IS filtered from the discoverable (no-allowList) scan when uv=false.");
        }

        CtapGetAssertionRequest allowListRequest = BuildGetAssertionRequest(
            pool, rpId: rpId, allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = registered.CredentialId }]);
        using(PooledMemory allowListResponse = await SendGetAssertionAsync(simulator, allowListRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, allowListResponse.AsReadOnlySpan()[0], "level 2 is NEVER filtered from the allowList branch — knowledge of the credential ID exempts it.");
        }

        registered.CredentialId.Dispose();
    }


    /// <summary>R10: a level-3 (<c>userVerificationRequired</c>) credential is invisible to BOTH the discoverable scan and the allowList branch without UV, and visible to both once UV is collected — the ONE filter shared across both branches.</summary>
    [TestMethod]
    public async Task GetAssertionLevelThreeCredentialInvisibleWithoutUvVisibleWithUv()
    {
        const string rpId = "ext-ga-level3.example";
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ext-ga-level3");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        CtapWave2RegisteredCredential registered = await RegisterCredentialAsync(
            simulator, pool, BuildFixedBytes(16, 0xD2), TestContext.CancellationToken, rpId: rpId, credProtect: 3);
        byte[] credentialIdBytes = registered.CredentialId.AsReadOnlySpan().ToArray();
        registered.CredentialId.Dispose();

        using(PooledMemory discoverableNoUv = await SendGetAssertionAsync(simulator, BuildGetAssertionRequest(pool, rpId: rpId), pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, discoverableNoUv.AsReadOnlySpan()[0]);
        }

        //Each SendGetAssertionAsync call disposes its own request's allowList credential IDs
        //(DisposeGetAssertionRequest) once sent, so a FRESH CredentialId copy is built for each of the
        //two allowList uses below rather than reusing one instance across both calls.
        using(PooledMemory allowListNoUv = await SendGetAssertionAsync(
            simulator,
            BuildGetAssertionRequest(pool, rpId: rpId, allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(credentialIdBytes, pool) }]),
            pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, allowListNoUv.AsReadOnlySpan()[0]);
        }

        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);

        //A fresh token per successful ga call: every ga success whose "up" is true strips the token used
        //down to lbw permissions (CTAP 2.3 line 5828/4098, ApplyPinUvAuthTokenFlagClearingIfUserPresent)
        //— unrelated to credProtect filtering, so reissuing is the correct fixture shape.
        byte[] discoverableToken = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Ga, rpId: rpId, TestContext.CancellationToken);
        byte[] discoverableParam = await ComputeGaSignatureAsync(discoverableToken, protocolId, pool, TestContext.CancellationToken);
        using(PooledMemory discoverableWithUv = await SendGetAssertionAsync(
            simulator, BuildGetAssertionRequest(pool, rpId: rpId, pinUvAuthParam: discoverableParam, pinUvAuthProtocol: (int)protocolId), pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, discoverableWithUv.AsReadOnlySpan()[0]);
        }

        byte[] allowListToken = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Ga, rpId: rpId, TestContext.CancellationToken);
        byte[] allowListParam = await ComputeGaSignatureAsync(allowListToken, protocolId, pool, TestContext.CancellationToken);
        using(PooledMemory allowListWithUv = await SendGetAssertionAsync(
            simulator,
            BuildGetAssertionRequest(
                pool, rpId: rpId,
                allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(credentialIdBytes, pool) }],
                pinUvAuthParam: allowListParam, pinUvAuthProtocol: (int)protocolId),
            pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, allowListWithUv.AsReadOnlySpan()[0]);
        }
    }


    /// <summary>R10: a level-1 (<c>userVerificationOptional</c>) credential is never filtered by either credProtect check, even without UV.</summary>
    [TestMethod]
    public async Task GetAssertionLevelOneCredentialNeverFilteredEvenWithoutUv()
    {
        const string rpId = "ext-ga-level1.example";
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ext-ga-level1");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xD4), TestContext.CancellationToken, rpId: rpId);

        using PooledMemory response = await SendGetAssertionAsync(simulator, BuildGetAssertionRequest(pool, rpId: rpId), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A previously-authorized RP loses its <c>minPinLength</c> authorization after
    /// <c>authenticatorReset</c> (R7 §7.4.3 line 8424): a post-reset mc request from the same RP gets no
    /// <c>minPinLength</c> output, proven from real decoded authData bytes, never internal state.
    /// </summary>
    [TestMethod]
    public async Task SetMinPinLengthAuthorizedRpLosesAuthorizationAfterReset()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ext-minpinlength-reset-clears");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        await AuthorizeRpForMinPinLengthAsync(simulator, pool, protocolId, [DefaultRpId], TestContext.CancellationToken);

        ReadOnlyMemory<byte> extensions = BuildMakeCredentialExtensionsInput(minPinLength: true);
        using(PooledMemory beforeResponse = await SendMakeCredentialAsync(
            simulator, BuildMakeCredentialRequest(pool, extensions: extensions), pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, beforeResponse.AsReadOnlySpan()[0]);
            CtapMakeCredentialResponse beforeDecoded = CtapMakeCredentialResponseCborReader.Read(beforeResponse.AsReadOnlyMemory()[1..]);
            using AuthenticatorData beforeAuthenticatorData = AuthenticatorDataReader.Read(beforeDecoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
            Assert.IsTrue(beforeAuthenticatorData.Flags.ExtensionDataIncluded, "the RP must be authorized before reset.");
        }

        byte[] resetRequest = [WellKnownCtapCommands.Reset];
        using(PooledMemory resetResponse = await simulator.TransceiveAsync(resetRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0]);
        }

        using PooledMemory afterResponse = await SendMakeCredentialAsync(
            simulator, BuildMakeCredentialRequest(pool, userId: BuildFixedBytes(16, 0xD8), extensions: extensions), pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, afterResponse.AsReadOnlySpan()[0]);
        CtapMakeCredentialResponse afterDecoded = CtapMakeCredentialResponseCborReader.Read(afterResponse.AsReadOnlyMemory()[1..]);
        using AuthenticatorData afterAuthenticatorData = AuthenticatorDataReader.Read(afterDecoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsFalse(afterAuthenticatorData.Flags.ExtensionDataIncluded, "authenticatorReset clears minPinLengthRPIDs (§7.4.3 line 8424) — the same RP is unauthorized again.");
    }


    /// <summary>Establishes a PIN, issues an <c>acfg</c>-permission token, and calls <c>setMinPINLength</c> naming <paramref name="rpIds"/> as the authorized <c>minPinLengthRPIDs</c> list.</summary>
    private static async Task AuthorizeRpForMinPinLengthAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string[] rpIds, CancellationToken cancellationToken)
    {
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, cancellationToken);
        byte[] token = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, cancellationToken);

        byte[] subCommandParams = CtapWaveConfigFixtures.BuildSubCommandParams(minPinLengthRpIds: rpIds);
        byte[] message = CtapWaveConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, subCommandParams);
        byte[] param = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, cancellationToken);

        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength,
            MinPinLengthRpIds: rpIds,
            PinUvAuthProtocol: (int)protocolId,
            PinUvAuthParam: param);
        using PooledMemory response = await CtapWaveConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, cancellationToken);
        if(!WellKnownCtapStatusCodes.IsOk(response.AsReadOnlySpan()[0]))
        {
            throw new Fido2FormatException($"Fixture setMinPINLength authorization failed with CTAP2 status 0x{response.AsReadOnlySpan()[0]:X2}.");
        }
    }


    /// <summary>Computes the platform-side mc <c>pinUvAuthParam</c>: <c>authenticate(token, clientDataHash)</c>, mirroring the wave-5c binding tests' own helper.</summary>
    private static async Task<byte[]> ComputeMcSignatureAsync(byte[] token, CtapPinUvAuthProtocolId protocolId, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
        await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, McClientDataHash, pool, cancellationToken);


    /// <summary>Computes the platform-side ga <c>pinUvAuthParam</c>: <c>authenticate(token, clientDataHash)</c>, mirroring the wave-5c binding tests' own helper.</summary>
    private static async Task<byte[]> ComputeGaSignatureAsync(byte[] token, CtapPinUvAuthProtocolId protocolId, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
        await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, GaClientDataHash, pool, cancellationToken);


    /// <summary>Decodes a single CTAP2-canonical CBOR unsigned/negative integer from an authenticator extension output's raw encoded value.</summary>
    private static int ReadCborInt32(ReadOnlyMemory<byte> encodedValue) =>
        checked((int)new CborReader(encodedValue, CborConformanceMode.Ctap2Canonical).ReadInt64());
}
