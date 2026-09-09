using System;
using System.Buffers;
using System.Collections.Generic;
using Lumoin.Veritas.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapMakeCredentialGetAssertionFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The unit-test matrix for <c>authenticatorConfig</c> (<c>0x0D</c>): the shared prologue
/// (subCommand/subcommand-support/token-gate steps 1-4), the <c>toggleAlwaysUv</c> step-3 bypass
/// conjunction, the <c>acfg</c> permission check's non-mc/ga-ness (no RP-ID binding, no flag/permission
/// stripping), the <c>toggleAlwaysUv</c>/<c>setMinPINLength</c> subcommand bodies including the
/// <c>forcePINChange</c> gates threaded into <c>getPinToken</c>/
/// <c>getPinUvAuthTokenUsingPinWithPermissions</c>/<c>changePIN</c>, and the
/// capability-gated <c>enableEnterpriseAttestation</c> subcommand: idempotent enable, ignored
/// <c>subCommandParams</c>, the protected-path trio, the fresh-device tokenless path, and the
/// getInfo-flip observable proof. Driven in-process through
/// <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> (real-wire capstones are a later package),
/// with platform-side <c>pinUvAuthParam</c> computed the same way the shared fixtures compute mc/ga's
/// own — through <see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/> over the actual token bytes,
/// never a test-only crypto reimplementation.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorConfigTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The plaintext PIN most tests establish, matching this profile's default 4-code-point minimum.</summary>
    private const string DefaultPin = "1234";


    /// <summary>Step 1: an absent <c>subCommand</c> maps to <c>MissingParameter</c> at the decode boundary.</summary>
    [TestMethod]
    public async Task SubCommandAbsentReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-subcommand-absent",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.Ctap2Canonical);

        writer.WriteStartMap(0);
        writer.WriteEndMap();
        byte[] parameters = writerBuffer.WrittenSpan.ToArray();
        int envelopeLength = parameters.Length + 1;
        using IMemoryOwner<byte> envelopeOwner = pool.Rent(envelopeLength);
        Span<byte> envelope = envelopeOwner.Memory.Span[..envelopeLength];
        envelope[0] = WellKnownCtapCommands.AuthenticatorConfig;
        parameters.CopyTo(envelope[1..]);

        using PooledMemory response = await simulator.TransceiveAsync(envelopeOwner.Memory[..envelopeLength], pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// Step 2: every subCommand this DEFAULT (non-enterprise-attestation-capable) authenticator does not
    /// support — including out-of-table values — returns <c>InvalidSubcommand</c>. The <c>0x01</c>
    /// row is RE-SCOPED, not removed: <c>enableEnterpriseAttestation</c>
    /// is now conditionally supported (see <see cref="TokenWithAcfgPermissionEnablesEnterpriseAttestationWithExactVerifyMessage"/>
    /// and its siblings for the CAPABLE-authenticator positive path), but this DEFAULT simulator (no
    /// <see cref="CtapEnterpriseAttestationProvisioning"/> seeded) stays non-capable, so <c>0x01</c>
    /// against it is unchanged behavior.
    /// </summary>
    [TestMethod]
    [DataRow(0x01, DisplayName = "enableEnterpriseAttestation (non-capable default)")]
    [DataRow(0x04, DisplayName = "enableLongTouchForReset")]
    [DataRow(0xFF, DisplayName = "vendorPrototype")]
    [DataRow(0x99, DisplayName = "out-of-table")]
    public async Task UnsupportedSubCommandReturnsInvalidSubcommand(int subCommand)
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator($"config-unsupported-{subCommand:X2}",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        var request = new CtapAuthenticatorConfigRequest(SubCommand: subCommand);
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidSubcommand, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// Fresh-device (no PIN set, <c>alwaysUv</c> off) tokenless <c>enableEnterpriseAttestation</c> against
    /// a CAPABLE authenticator SUCCEEDS (line 7992's own no-PIN-set skip-auth path): the step-4
    /// token gate never applies, since neither "protected by user verification" nor <c>alwaysUv</c> holds
    /// — <c>enableEnterpriseAttestation</c> is just another <c>authenticatorConfig</c> subcommand at the
    /// token-gate level, mirroring <see cref="UnprotectedAlwaysUvOffSetMinPinLengthSucceedsWithJunkParamIgnored"/>'s
    /// own fresh-device precedent. Also proves the capability-gated third disjunct itself passes step 2:
    /// a non-capable authenticator's identical request is rejected (<see cref="UnsupportedSubCommandReturnsInvalidSubcommand"/>'s
    /// re-scoped <c>0x01</c> row), so this success is the capability gate's own live positive half.
    /// </summary>
    [TestMethod]
    public async Task FreshDeviceTokenlessEnableEnterpriseAttestationSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = CtapEnterpriseAttestationFixtures.CreateCapableSimulator("config-ep-fresh-tokenless", pool);

        var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation);
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// The getInfo-flip observable proof (line 8000's own note): a freshly built capable authenticator
    /// reports <c>ep:false</c>; the very next <c>authenticatorGetInfo</c> after a successful
    /// <c>enableEnterpriseAttestation</c> reports <c>ep:true</c> — proven end to end through the full
    /// <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> loop, never asserted on in-process state.
    /// </summary>
    [TestMethod]
    public async Task EnableEnterpriseAttestationFlipsGetInfoEpToTrue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = CtapEnterpriseAttestationFixtures.CreateCapableSimulator("config-ep-getinfo-flip", pool);

        CtapGetInfoResponse before = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsFalse(before.Options!.Ep!.Value, "a freshly built capable authenticator starts disabled.");

        var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation);
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapGetInfoResponse after = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsTrue(after.Options!.Ep!.Value, "the very next getInfo after a successful enable must report ep:true (line 8000's note).");
    }


    /// <summary>
    /// A second <c>enableEnterpriseAttestation</c> call against an already-enabled authenticator is a
    /// no-op success (line 8002), never a toggle back to disabled: the same idempotent handler
    /// that re-enables a disabled feature also re-affirms an already-enabled one.
    /// </summary>
    [TestMethod]
    public async Task EnableEnterpriseAttestationCalledTwiceStaysEnabledBothTimes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = CtapEnterpriseAttestationFixtures.CreateCapableSimulator("config-ep-idempotent", pool);
        var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation);

        using PooledMemory firstResponse = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstResponse.AsReadOnlySpan()[0]);

        using PooledMemory secondResponse = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, secondResponse.AsReadOnlySpan()[0]);

        CtapGetInfoResponse info = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsTrue(info.Options!.Ep!.Value, "a second enable call must leave the feature enabled -- never toggle it back off.");
    }


    /// <summary>
    /// <c>subCommandParams</c> is spec-defined as ignored for <c>enableEnterpriseAttestation</c> (line
    /// 7994): smuggling a <c>setMinPINLength</c>-shaped <c>newMinPINLength</c> value into the
    /// SAME request's <c>subCommandParams</c> map (genuinely decoded onto <see cref="CtapAuthenticatorConfigRequest.NewMinPinLength"/>
    /// by the shared reader, since it cannot know ahead of time which subcommand will consult it) has NO
    /// effect: the handler dispatched for <c>0x01</c> takes no <see cref="CtapAuthenticatorConfigRequest"/>
    /// parameter at all, so it structurally cannot read it — the feature enables and the <c>minPINLength</c>
    /// getInfo member is untouched.
    /// </summary>
    [TestMethod]
    public async Task EnableEnterpriseAttestationIgnoresSubCommandParams()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = CtapEnterpriseAttestationFixtures.CreateCapableSimulator("config-ep-params-ignored", pool);

        CtapGetInfoResponse before = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        int minPinLengthBefore = before.MinPinLength!.Value;

        var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation, NewMinPinLength: 30);
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapGetInfoResponse after = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsTrue(after.Options!.Ep!.Value);
        Assert.AreEqual(minPinLengthBefore, after.MinPinLength, "a NewMinPinLength value smuggled into enableEnterpriseAttestation's subCommandParams must have zero effect -- the handler never reads it.");
    }


    /// <summary>Protected (a PIN is set), tokenless <c>enableEnterpriseAttestation</c> against a capable authenticator: step 4.1 rejects with <c>PuatRequired</c>.</summary>
    [TestMethod]
    public async Task ProtectedTokenlessEnableEnterpriseAttestationReturnsPuatRequired()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = CtapEnterpriseAttestationFixtures.CreateCapableSimulator("config-ep-protected-no-token", pool);
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, DefaultPin, TestContext.CancellationToken);

        var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation);
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A token carrying the <c>acfg</c> permission enables enterprise attestation on a protected, capable
    /// authenticator; the exact platform-computed verify message is <c>32×0xff ‖ 0x0D ‖ 0x01</c> with NO
    /// <c>subCommandParams</c> segment appended (<see cref="CtapConfigFixtures.BuildMessage"/>
    /// elides an absent segment entirely).
    /// </summary>
    [TestMethod]
    public async Task TokenWithAcfgPermissionEnablesEnterpriseAttestationWithExactVerifyMessage()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = CtapEnterpriseAttestationFixtures.CreateCapableSimulator("config-ep-acfg-success", pool);
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        byte[] message = CtapConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation, ReadOnlyMemory<byte>.Empty);
        byte[] expectedMessage = new byte[34];
        Array.Fill(expectedMessage, (byte)0xff, 0, 32);
        expectedMessage[32] = WellKnownCtapCommands.AuthenticatorConfig;
        expectedMessage[33] = (byte)WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation;
        Assert.AreSequenceEqual(expectedMessage, message, "the verify message must be exactly 32x0xff || 0x0D || 0x01 with no subCommandParams segment.");

        byte[] param = await CtapConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, TestContext.CancellationToken);
        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation, PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: param);
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapGetInfoResponse info = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsTrue(info.Options!.Ep!.Value);
    }


    /// <summary>A token lacking the <c>acfg</c> permission fails <c>enableEnterpriseAttestation</c>'s step 4.5 with <c>PinAuthInvalid</c>.</summary>
    [TestMethod]
    public async Task TokenWithoutAcfgPermissionEnableEnterpriseAttestationReturnsPinAuthInvalid()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = CtapEnterpriseAttestationFixtures.CreateCapableSimulator("config-ep-no-acfg", pool);
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin,
            WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga, DefaultRpId, TestContext.CancellationToken);

        byte[] message = CtapConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation, ReadOnlyMemory<byte>.Empty);
        byte[] param = await CtapConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, TestContext.CancellationToken);
        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation, PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: param);
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Not protected, <c>alwaysUv</c> off: no gate at all — <c>toggleAlwaysUv</c> succeeds tokenless and flips both getInfo members.</summary>
    [TestMethod]
    public async Task UnprotectedAlwaysUvOffToggleAlwaysUvSucceedsWithoutTokenAndFlipsGetInfo()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-toggle-unprotected",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        CtapGetInfoResponse before = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsFalse(before.Options!.AlwaysUv!.Value);
        Assert.IsTrue(before.Options!.MakeCredUvNotRqd!.Value);

        var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv);
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapGetInfoResponse after = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsTrue(after.Options!.AlwaysUv!.Value);
        Assert.IsFalse(after.Options!.MakeCredUvNotRqd!.Value);
    }


    /// <summary>Not protected, <c>alwaysUv</c> off: <c>setMinPINLength</c> also has no gate — a junk presented <c>pinUvAuthParam</c> is ignored.</summary>
    [TestMethod]
    public async Task UnprotectedAlwaysUvOffSetMinPinLengthSucceedsWithJunkParamIgnored()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-setmin-unprotected-junk",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength,
            PinUvAuthParam: new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Protected, no <c>pinUvAuthParam</c> presented: step 4.1 rejects with <c>PuatRequired</c>.</summary>
    [TestMethod]
    public async Task ProtectedNoTokenPresentedReturnsPuatRequired()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-protected-no-token",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, DefaultPin, TestContext.CancellationToken);

        var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength);
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Protected, <c>pinUvAuthParam</c> present but <c>pinUvAuthProtocol</c> absent: step 4.2 rejects with <c>MissingParameter</c>.</summary>
    [TestMethod]
    public async Task ProtectedPinUvAuthProtocolAbsentReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-protected-protocol-absent",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, DefaultPin, TestContext.CancellationToken);

        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength,
            PinUvAuthParam: new byte[] { 0x01 });
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Protected, an unsupported <c>pinUvAuthProtocol</c> value (3): step 4.3 rejects with <c>InvalidParameter</c>.</summary>
    [TestMethod]
    public async Task ProtectedPinUvAuthProtocolUnsupportedReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-protected-protocol-unsupported",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, DefaultPin, TestContext.CancellationToken);

        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength,
            PinUvAuthProtocol: 3,
            PinUvAuthParam: new byte[] { 0x01 });
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A bad HMAC fails with <c>PinAuthInvalid</c> and mutates NO state: the same token remains usable afterward.</summary>
    [TestMethod]
    public async Task ProtectedBadHmacReturnsPinAuthInvalidAndTokenRemainsUsable()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-bad-hmac",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        var badRequest = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv,
            PinUvAuthProtocol: (int)protocolId,
            PinUvAuthParam: new byte[32]);
        using PooledMemory badResponse = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, badRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, badResponse.AsReadOnlySpan()[0]);

        byte[] message = CtapConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, ReadOnlyMemory<byte>.Empty);
        byte[] validParam = await CtapConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, TestContext.CancellationToken);
        var goodRequest = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv,
            PinUvAuthProtocol: (int)protocolId,
            PinUvAuthParam: validParam);
        using PooledMemory goodResponse = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, goodRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(
            WellKnownCtapStatusCodes.Ok, goodResponse.AsReadOnlySpan()[0],
            "the token must remain usable after a failed verify attempt: no retries decrement, no state mutation on a bad HMAC.");
    }


    /// <summary>A token without the <c>acfg</c> permission fails step 4.5 with <c>PinAuthInvalid</c>.</summary>
    [TestMethod]
    public async Task TokenWithoutAcfgPermissionReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-no-acfg-permission",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin,
            WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga, DefaultRpId, TestContext.CancellationToken);

        byte[] message = CtapConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, ReadOnlyMemory<byte>.Empty);
        byte[] param = await CtapConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, TestContext.CancellationToken);
        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: param);
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A token carrying <c>acfg</c> passes the prologue and the subcommand executes.</summary>
    [TestMethod]
    public async Task TokenWithAcfgPermissionSucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-with-acfg-permission",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        byte[] message = CtapConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, ReadOnlyMemory<byte>.Empty);
        byte[] param = await CtapConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, TestContext.CancellationToken);
        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: param);
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A token used successfully for <c>authenticatorConfig</c> retains every OTHER permission afterward
    /// (no flag/permission clearing): the SAME token then completes an <c>authenticatorMakeCredential</c>
    /// with <c>uv=1</c>.
    /// </summary>
    [TestMethod]
    public async Task ConfigSuccessDoesNotStripPermissionsSameTokenCompletesMakeCredentialWithUvOne()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-no-strip",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);

        int permissions = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga | WellKnownCtapPinUvAuthTokenPermissions.Acfg;
        byte[] token = await CtapConfigFixtures.IssueTokenAsync(simulator, pool, protocolId, DefaultPin, permissions, DefaultRpId, TestContext.CancellationToken);

        byte[] configMessage = CtapConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, ReadOnlyMemory<byte>.Empty);
        byte[] configParam = await CtapConfigFixtures.ComputeSignatureAsync(token, protocolId, configMessage, pool, TestContext.CancellationToken);
        var configRequest = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: configParam);
        using PooledMemory configResponse = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, configRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, configResponse.AsReadOnlySpan()[0]);

        byte[] mcParam = await CtapConfigFixtures.ComputeSignatureAsync(token, protocolId, BuildFixedBytes(32, 0x10), pool, TestContext.CancellationToken);
        CtapMakeCredentialRequest mcRequest = BuildMakeCredentialRequest(pool, pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)protocolId);
        using PooledMemory mcResponse = await SendMakeCredentialAsync(simulator, mcRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, mcResponse.AsReadOnlySpan()[0]);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(mcResponse.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsTrue(authenticatorData.Flags.UserVerified, "the config-consuming token must still authenticate a subsequent mc call with uv=1 -- no permission/flag stripping.");
    }


    /// <summary>An <c>acfg</c> token bound to ANY <c>rpId</c> still passes <c>authenticatorConfig</c> (<c>acfg</c>'s own RP ID column is "Ignored").</summary>
    [TestMethod]
    public async Task RpIdBoundAcfgTokenPassesConfig()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-rpid-bound-acfg",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);

        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, "some-other-rp.example", TestContext.CancellationToken);

        byte[] message = CtapConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, ReadOnlyMemory<byte>.Empty);
        byte[] param = await CtapConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, TestContext.CancellationToken);
        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: param);
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(
            WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0],
            "acfg's own RP ID is Ignored -- a token bound to ANY rpId must still pass authenticatorConfig's permission gate.");
    }


    /// <summary>A token past its usage-timer expiry fails <c>verify</c> — the expiry fold runs before trust, exactly like mc/ga.</summary>
    [TestMethod]
    public async Task ExpiredTokenReturnsPinAuthInvalid()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-expired-token", BaseMemoryPool.Shared, timeProvider: timeProvider);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);

        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        timeProvider.Advance(CtapPinUvAuthTokenState.InitialUsageTimeLimit);

        byte[] message = CtapConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, ReadOnlyMemory<byte>.Empty);
        byte[] param = await CtapConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, TestContext.CancellationToken);
        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: param);
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A token issued for one protocol never authenticates a request declaring the OTHER protocol.</summary>
    [TestMethod]
    public async Task CrossProtocolTokenReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-cross-protocol",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, DefaultPin, TestContext.CancellationToken);

        byte[] protocolTwoToken = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        byte[] message = CtapConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, ReadOnlyMemory<byte>.Empty);
        byte[] protocolOneComputedParam = await CtapConfigFixtures.ComputeSignatureAsync(
            protocolTwoToken, CtapPinUvAuthProtocolId.One, message, pool, TestContext.CancellationToken);

        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.One,
            PinUvAuthParam: protocolOneComputedParam);
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Bypass conjunction: enabling <c>alwaysUv</c> unprotected, then disabling it — still unprotected — succeeds tokenless both times (the step-3 bypass proper on the second call).</summary>
    [TestMethod]
    public async Task UnprotectedAlwaysUvOnToggleAlwaysUvTokenlessSucceedsDisabling()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-bypass-unprotected-disable",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        var enableRequest = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv);
        using PooledMemory enableResponse = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, enableRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, enableResponse.AsReadOnlySpan()[0]);

        CtapGetInfoResponse afterEnable = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsTrue(afterEnable.Options!.AlwaysUv!.Value);

        var disableRequest = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv);
        using PooledMemory disableResponse = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, disableRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, disableResponse.AsReadOnlySpan()[0]);

        CtapGetInfoResponse afterDisable = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsFalse(afterDisable.Options!.AlwaysUv!.Value);
    }


    /// <summary>Bypass conjunction: once protected, <c>toggleAlwaysUv</c> tokenless falls through to the ordinary step-4 gate, even with <c>alwaysUv</c> already true.</summary>
    [TestMethod]
    public async Task ProtectedAlwaysUvOnToggleAlwaysUvTokenlessReturnsPuatRequired()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-bypass-protected-blocked",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        var enableRequest = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv);
        using PooledMemory enableResponse = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, enableRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, enableResponse.AsReadOnlySpan()[0]);

        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, DefaultPin, TestContext.CancellationToken);

        var disableRequest = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv);
        using PooledMemory disableResponse = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, disableRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, disableResponse.AsReadOnlySpan()[0]);
    }


    /// <summary>The step-3 bypass is <c>toggleAlwaysUv</c>-ONLY: <c>setMinPINLength</c> tokenless still hits the ordinary step-4 gate even with <c>alwaysUv</c> true and not protected.</summary>
    [TestMethod]
    public async Task UnprotectedAlwaysUvOnSetMinPinLengthTokenlessReturnsPuatRequired()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-bypass-setmin-not-covered",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        var enableRequest = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv);
        using PooledMemory enableResponse = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, enableRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, enableResponse.AsReadOnlySpan()[0]);

        var setMinRequest = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength);
        using PooledMemory setMinResponse = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, setMinRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, setMinResponse.AsReadOnlySpan()[0]);
    }


    /// <summary>Raising the minimum with a PIN already long enough succeeds, reports the new minimum, and does not force a change.</summary>
    [TestMethod]
    public async Task SetMinPinLengthRaiseSucceedsAndUpdatesGetInfo()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-setmin-raise",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        const string longPin = "123456789";
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, longPin, TestContext.CancellationToken);
        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, longPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        using PooledMemory response = await SendSetMinPinLengthAsync(simulator, pool, protocolId, token, newMinPinLength: 6, cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapGetInfoResponse info = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(6, info.MinPinLength);
        Assert.IsFalse(info.ForcePinChange ?? false, "the PIN already satisfies the raised minimum -- no change should be forced.");
    }


    /// <summary>A decrease is rejected with <c>PinPolicyViolation</c> -- minimum PIN lengths may only be increased.</summary>
    [TestMethod]
    public async Task SetMinPinLengthLowerReturnsPinPolicyViolation()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-setmin-lower-rejected",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        const string longPin = "123456789";
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, longPin, TestContext.CancellationToken);
        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, longPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        using PooledMemory raiseResponse = await SendSetMinPinLengthAsync(simulator, pool, protocolId, token, newMinPinLength: 6, cancellationToken: TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, raiseResponse.AsReadOnlySpan()[0]);

        using PooledMemory lowerResponse = await SendSetMinPinLengthAsync(simulator, pool, protocolId, token, newMinPinLength: 5, cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinPolicyViolation, lowerResponse.AsReadOnlySpan()[0]);
    }


    /// <summary>Setting the minimum equal to the current value is a no-op success (not a "decrease").</summary>
    [TestMethod]
    public async Task SetMinPinLengthEqualSucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-setmin-equal",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        using PooledMemory response = await SendSetMinPinLengthAsync(simulator, pool, protocolId, token, newMinPinLength: 4, cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapGetInfoResponse info = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(4, info.MinPinLength);
        Assert.IsFalse(info.ForcePinChange ?? false);
    }


    /// <summary>An absent <c>newMinPINLength</c> defaults to the current minimum (step 1) — a true no-op.</summary>
    [TestMethod]
    public async Task SetMinPinLengthAbsentNewValueIsNoOp()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-setmin-absent-noop",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        using PooledMemory response = await SendSetMinPinLengthAsync(simulator, pool, protocolId, token, cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapGetInfoResponse info = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(4, info.MinPinLength);
    }


    /// <summary><c>forceChangePin:true</c> with no PIN set returns <c>PinNotSet</c> (step 4).</summary>
    [TestMethod]
    public async Task SetMinPinLengthForceChangePinNoPinReturnsPinNotSet()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-setmin-force-no-pin",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, ForceChangePin: true);
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinNotSet, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// <c>minPinLengthRPIDs</c> present is now ACCEPTED and STORED (line 8105/8136's disjunctive
    /// gate, read under De Morgan, is satisfied once <c>minPinLength</c> alone is supported; the flip
    /// from the superseded <c>SetMinPinLengthMinPinLengthRpIdsReturnsInvalidParameter</c> unconditional-
    /// rejection test): a subsequent mc <c>minPinLength</c> request from the newly authorized RP is
    /// granted the current minimum PIN length, proven from real decoded authData bytes.
    /// </summary>
    [TestMethod]
    public async Task SetMinPinLengthMinPinLengthRpIdsAcceptsAndStoresTheAuthorizedList()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-setmin-rpids-accepted",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        using PooledMemory response = await SendSetMinPinLengthAsync(
            simulator, pool, protocolId, token, minPinLengthRpIds: ["authorized.example"], cancellationToken: TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        Assert.IsTrue(await IsAuthorizedForMinPinLengthAsync(simulator, pool, "authorized.example", TestContext.CancellationToken));
    }


    /// <summary>
    /// A second <c>minPinLengthRPIDs</c> call REPLACES the stored list wholesale (line 8184's posture —
    /// no pre-configured list exists in this profile): an RP authorized by the first call loses
    /// authorization once a second call names a disjoint list. A fresh token is issued before each
    /// <c>setMinPINLength</c> call: the intervening mc authorization probe itself tests user presence,
    /// which strips the previous token's permissions down to <c>lbw</c> (CTAP 2.3 line 5828/3545) —
    /// unrelated to <c>minPinLengthRPIDs</c> storage, so re-issuing is the correct fixture shape, not a
    /// workaround for anything under test.
    /// </summary>
    [TestMethod]
    public async Task SetMinPinLengthMinPinLengthRpIdsOverwritesPreviouslyStoredListWholesale()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-setmin-rpids-overwrite",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);

        byte[] firstToken = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);
        using(PooledMemory firstResponse = await SendSetMinPinLengthAsync(
            simulator, pool, protocolId, firstToken, minPinLengthRpIds: ["first.example"], cancellationToken: TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstResponse.AsReadOnlySpan()[0]);
        }
        Assert.IsTrue(await IsAuthorizedForMinPinLengthAsync(simulator, pool, "first.example", TestContext.CancellationToken));

        byte[] secondToken = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);
        using(PooledMemory secondResponse = await SendSetMinPinLengthAsync(
            simulator, pool, protocolId, secondToken, minPinLengthRpIds: ["second.example"], cancellationToken: TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, secondResponse.AsReadOnlySpan()[0]);
        }

        Assert.IsFalse(await IsAuthorizedForMinPinLengthAsync(simulator, pool, "first.example", TestContext.CancellationToken), "the second call must REPLACE, not merge with, the first.");
        Assert.IsTrue(await IsAuthorizedForMinPinLengthAsync(simulator, pool, "second.example", TestContext.CancellationToken));
    }


    /// <summary>An EMPTY supplied <c>minPinLengthRPIDs</c> array is a no-op: step 8's own guard is "present and contains at least one string" (line 8179), so the previously stored list survives unchanged.</summary>
    [TestMethod]
    public async Task SetMinPinLengthMinPinLengthRpIdsEmptyArrayIsNoOp()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-setmin-rpids-empty-noop",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        using(PooledMemory firstResponse = await SendSetMinPinLengthAsync(
            simulator, pool, protocolId, token, minPinLengthRpIds: ["kept.example"], cancellationToken: TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstResponse.AsReadOnlySpan()[0]);
        }

        using(PooledMemory emptyResponse = await SendSetMinPinLengthAsync(
            simulator, pool, protocolId, token, minPinLengthRpIds: [], cancellationToken: TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, emptyResponse.AsReadOnlySpan()[0], "an empty array is a no-op, never a rejection.");
        }

        Assert.IsTrue(await IsAuthorizedForMinPinLengthAsync(simulator, pool, "kept.example", TestContext.CancellationToken), "an empty supplied array must leave the previously stored list unchanged.");
    }


    /// <summary>A supplied <c>minPinLengthRPIDs</c> list larger than <c>maxRPIDsForSetMinPINLength</c> (8) rejects with <c>CTAP2_ERR_KEY_STORE_FULL</c> (line 8182's unnamed bound check + line 8189's named storage-failure code, a documented two-anchor reading).</summary>
    [TestMethod]
    public async Task SetMinPinLengthMinPinLengthRpIdsExceedingCapacityReturnsKeyStoreFull()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-setmin-rpids-over-capacity",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        using PooledMemory response = await SendSetMinPinLengthAsync(
            simulator, pool, protocolId, token, minPinLengthRpIds: BuildRpIdList(CtapAuthenticatorState.MaxRpIdsForSetMinPinLengthCapacity + 1),
            cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.KeyStoreFull, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A supplied <c>minPinLengthRPIDs</c> list EXACTLY at the <c>maxRPIDsForSetMinPINLength</c> capacity (8) is accepted — the bound is inclusive.</summary>
    [TestMethod]
    public async Task SetMinPinLengthMinPinLengthRpIdsAtCapacityBoundarySucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-setmin-rpids-at-capacity",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        using PooledMemory response = await SendSetMinPinLengthAsync(
            simulator, pool, protocolId, token, minPinLengthRpIds: BuildRpIdList(CtapAuthenticatorState.MaxRpIdsForSetMinPinLengthCapacity),
            cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Builds <paramref name="count"/> distinct RP ID strings, for the capacity-bound tests.</summary>
    private static List<string> BuildRpIdList(int count)
    {
        var rpIds = new List<string>(count);
        for(int i = 0; i < count; i++)
        {
            rpIds.Add($"rp-{i}.example");
        }

        return rpIds;
    }


    /// <summary>Sends an mc <c>minPinLength:true</c> request for <paramref name="rpId"/> and reports whether the response's real decoded authData carries the <c>minPinLength</c> output — the ONLY observable proof of <c>minPinLengthRPIDs</c> storage.</summary>
    private static async Task<bool> IsAuthorizedForMinPinLengthAsync(CtapAuthenticatorSimulator simulator, BaseMemoryPool pool, string rpId, CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> extensions = BuildMakeCredentialExtensionsInput(minPinLength: true);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, rpId: rpId, userId: BuildFixedBytes(16, unchecked((byte)rpId.Length)), extensions: extensions);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, cancellationToken);
        if(!WellKnownCtapStatusCodes.IsOk(response.AsReadOnlySpan()[0]))
        {
            throw new Fido2FormatException($"minPinLength authorization probe mc failed with CTAP2 status 0x{response.AsReadOnlySpan()[0]:X2}.");
        }

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);

        return authenticatorData.Flags.ExtensionDataIncluded;
    }


    /// <summary><c>pinComplexityPolicy</c> is decoded but ignored (line 8442) -- it must not itself cause a rejection.</summary>
    [TestMethod]
    public async Task SetMinPinLengthPinComplexityPolicyIgnoredSucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-setmin-complexity-ignored",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, PinComplexityPolicy: true);
        using PooledMemory response = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Positive case: raising the minimum above an existing, now-too-short PIN forces a change AND kills every token — including the one that authenticated the raising call itself.</summary>
    [TestMethod]
    public async Task SetMinPinLengthRaiseAboveExistingPinForcesChangeAndKillsTokens()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-setmin-force-raise",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        using PooledMemory response = await SendSetMinPinLengthAsync(simulator, pool, protocolId, token, newMinPinLength: 6, cancellationToken: TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapGetInfoResponse info = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(6, info.MinPinLength);
        Assert.IsTrue(info.ForcePinChange!.Value, "raising the minimum above an existing, now-too-short PIN must force a change.");

        byte[] message = CtapConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, ReadOnlyMemory<byte>.Empty);
        byte[] staleParam = await CtapConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, TestContext.CancellationToken);
        var staleRequest = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: staleParam);
        using PooledMemory staleResponse = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, staleRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(
            WellKnownCtapStatusCodes.PinAuthInvalid, staleResponse.AsReadOnlySpan()[0],
            "step 7 must reset the SAME token that authenticated the raising call -- it must not remain usable.");
    }


    /// <summary>Negative case: raising the minimum to AT MOST the existing PIN's own length does NOT force a change, and the authenticating token survives.</summary>
    [TestMethod]
    public async Task SetMinPinLengthRaiseToExactExistingPinLengthDoesNotForceChange()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-setmin-no-force-exact",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        const string sixCharPin = "123456";
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, sixCharPin, TestContext.CancellationToken);
        byte[] token = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, sixCharPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        using PooledMemory response = await SendSetMinPinLengthAsync(simulator, pool, protocolId, token, newMinPinLength: 6, cancellationToken: TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapGetInfoResponse info = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(6, info.MinPinLength);
        Assert.IsFalse(info.ForcePinChange ?? false, "raising the minimum to AT MOST the existing PIN's own length must NOT force a change.");

        byte[] message = CtapConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, ReadOnlyMemory<byte>.Empty);
        byte[] param = await CtapConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, TestContext.CancellationToken);
        var secondRequest = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: param);
        using PooledMemory secondResponse = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, secondRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, secondResponse.AsReadOnlySpan()[0], "the token must survive since no reset was triggered.");
    }


    /// <summary><c>getPinToken</c>'s back-compat gate: <c>forcePINChange:true</c> answers <c>PinInvalid</c> (line 5904).</summary>
    [TestMethod]
    public async Task ForcePinChangeGetPinTokenReturnsPinInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-force-getpintoken",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] acfgToken = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        using PooledMemory forceResponse = await SendSetMinPinLengthAsync(
            simulator, pool, protocolId, acfgToken, forceChangePin: true, cancellationToken: TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, forceResponse.AsReadOnlySpan()[0]);

        using CtapPlatformPinSession session = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync(DefaultPin, TestContext.CancellationToken);

        var getPinTokenRequest = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: pinHashEnc);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorClientPinClient.ClientPinAsync(
                simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, getPinTokenRequest, CtapClientPinResponseCborReader.Read, pool,
                TestContext.CancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, exception.StatusCode);
    }


    /// <summary><c>getPinUvAuthTokenUsingPinWithPermissions</c>'s CTAP2.1-correct gate: <c>forcePINChange:true</c> answers <c>PinPolicyViolation</c> (line 6006).</summary>
    [TestMethod]
    public async Task ForcePinChangePermissionsGateReturnsPinPolicyViolation()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-force-permissions-gate",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] acfgToken = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        using PooledMemory forceResponse = await SendSetMinPinLengthAsync(
            simulator, pool, protocolId, acfgToken, forceChangePin: true, cancellationToken: TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, forceResponse.AsReadOnlySpan()[0]);

        using CtapPlatformPinSession session = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync(DefaultPin, TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: pinHashEnc, Permissions: WellKnownCtapPinUvAuthTokenPermissions.Mc, RpId: DefaultRpId);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorClientPinClient.ClientPinAsync(
                simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool,
                TestContext.CancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.PinPolicyViolation, exception.StatusCode);
    }


    /// <summary><c>changePIN</c> to the SAME PIN under a pending force rejects with <c>PinPolicyViolation</c> (line 5700, <c>FixedTimeEquals</c>).</summary>
    [TestMethod]
    public async Task ForcePinChangeChangePinToSameReturnsPinPolicyViolation()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-force-changepin-same",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] acfgToken = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        using PooledMemory forceResponse = await SendSetMinPinLengthAsync(
            simulator, pool, protocolId, acfgToken, forceChangePin: true, cancellationToken: TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, forceResponse.AsReadOnlySpan()[0]);

        using CtapPlatformPinSession session = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) = await session.BuildChangePinMessagesAsync(DefaultPin, DefaultPin, TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.ChangePin, PinUvAuthProtocol: (int)protocolId, KeyAgreement: session.PlatformPublicKeyCose,
            PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc, PinHashEnc: pinHashEnc);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorClientPinClient.ClientPinAsync(
                simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool,
                TestContext.CancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.PinPolicyViolation, exception.StatusCode);
    }


    /// <summary>A successful <c>changePIN</c> to a genuinely new PIN clears <c>forcePINChange</c> and a fresh token becomes issuable.</summary>
    [TestMethod]
    public async Task ForcePinChangeChangePinToNewCompliantClearsFlagAndAllowsFreshToken()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-force-changepin-clears",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] acfgToken = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        using PooledMemory forceResponse = await SendSetMinPinLengthAsync(
            simulator, pool, protocolId, acfgToken, forceChangePin: true, cancellationToken: TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, forceResponse.AsReadOnlySpan()[0]);

        CtapGetInfoResponse forcedInfo = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsTrue(forcedInfo.ForcePinChange!.Value);

        using CtapPlatformPinSession session = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) = await session.BuildChangePinMessagesAsync("5678", DefaultPin, TestContext.CancellationToken);

        var changePinRequest = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.ChangePin, PinUvAuthProtocol: (int)protocolId, KeyAgreement: session.PlatformPublicKeyCose,
            PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc, PinHashEnc: pinHashEnc);
        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, changePinRequest, CtapClientPinResponseCborReader.Read, pool, TestContext.CancellationToken);

        CtapGetInfoResponse clearedInfo = await CtapConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsFalse(clearedInfo.ForcePinChange ?? false);

        byte[] freshToken = await CtapConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, "5678", WellKnownCtapPinUvAuthTokenPermissions.Ga, DefaultRpId, TestContext.CancellationToken);
        Assert.IsNotNull(freshToken);
    }


    /// <summary>Once the minimum is raised, <c>setPIN</c> for a PIN shorter than it fails with <c>PinPolicyViolation</c>.</summary>
    [TestMethod]
    public async Task SetPinBelowRaisedMinimumReturnsPinPolicyViolation()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("config-setpin-below-raised-min",BaseMemoryPool.Shared);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        var raiseRequest = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, NewMinPinLength: 6);
        using PooledMemory raiseResponse = await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, raiseRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, raiseResponse.AsReadOnlySpan()[0]);

        using CtapPlatformPinSession session = await CtapPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(DefaultPin, TestContext.CancellationToken);

        var setPinRequest = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorClientPinClient.ClientPinAsync(
                simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, setPinRequest, CtapClientPinResponseCborReader.Read, pool,
                TestContext.CancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.PinPolicyViolation, exception.StatusCode);
    }


    /// <summary>
    /// Builds and sends a <c>setMinPINLength</c> request, computing the platform-side <c>pinUvAuthParam</c>
    /// over the SAME <c>subCommandParams</c> bytes the request will carry.
    /// </summary>
    private static async Task<PooledMemory> SendSetMinPinLengthAsync(
        CtapAuthenticatorSimulator simulator, BaseMemoryPool pool, CtapPinUvAuthProtocolId protocolId, byte[] token,
        int? newMinPinLength = null, bool? forceChangePin = null, IReadOnlyList<string>? minPinLengthRpIds = null, bool? pinComplexityPolicy = null,
        CancellationToken cancellationToken = default)
    {
        bool hasSubCommandParams = newMinPinLength is not null || minPinLengthRpIds is not null || forceChangePin is not null || pinComplexityPolicy is not null;
        ReadOnlyMemory<byte> subCommandParams = hasSubCommandParams
            ? CtapConfigFixtures.BuildSubCommandParams(newMinPinLength, minPinLengthRpIds, forceChangePin, pinComplexityPolicy)
            : ReadOnlyMemory<byte>.Empty;
        byte[] message = CtapConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, subCommandParams);
        byte[] param = await CtapConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, cancellationToken);

        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength,
            NewMinPinLength: newMinPinLength,
            MinPinLengthRpIds: minPinLengthRpIds,
            ForceChangePin: forceChangePin,
            PinComplexityPolicy: pinComplexityPolicy,
            PinUvAuthProtocol: (int)protocolId,
            PinUvAuthParam: param);

        return await CtapConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, cancellationToken);
    }
}
