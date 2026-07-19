using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;
using static Verifiable.Tests.TestInfrastructure.CtapWaveCmFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wave PKG-B unit-test matrix for <c>authenticatorCredentialManagement</c> (<c>0x0A</c>): the
/// shared prologue (R2 — subCommand/subcommand-support/token-gate steps 1-4, the UNCONDITIONAL gate with
/// no protected-check and no tokenless fallback), the Optional-RP-ID split (R3, C1 inverted polarity and
/// C2's existence-and-match conjunction), all seven subcommand bodies (R7), enumeration determinism (R9),
/// and the two new stateful sequences' discard/timer/expiry matrix (R10). Driven in-process through
/// <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> (real-wire capstones are a later package),
/// with platform-side <c>pinUvAuthParam</c> computed the same way the wave-5c/waveconfig fixtures compute
/// mc/ga/acfg's own — through <see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/> over the actual token
/// bytes, never a test-only crypto reimplementation. <c>updateUserInformation</c>'s <c>KeyStoreFull</c>
/// disposition (documented-unreachable) has no test here by design — see
/// <c>CtapAuthenticatorTransitions.OnUpdateUserInformationRequested</c>'s own doc comment.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorCredentialManagementTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The plaintext PIN most tests establish, matching this profile's default 4-code-point minimum.</summary>
    private const string DefaultPin = "1234";


    /// <summary>Step 1's equivalent: an absent <c>subCommand</c> maps to <c>MissingParameter</c> at the decode boundary.</summary>
    [TestMethod]
    public async Task SubCommandAbsentReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-subcommand-absent");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        byte[] parameters = writer.Encode();
        int envelopeLength = parameters.Length + 1;
        using IMemoryOwner<byte> envelopeOwner = pool.Rent(envelopeLength);
        Span<byte> envelope = envelopeOwner.Memory.Span[..envelopeLength];
        envelope[0] = WellKnownCtapCommands.CredentialManagement;
        parameters.CopyTo(envelope[1..]);

        using PooledMemory response = await simulator.TransceiveAsync(envelopeOwner.Memory[..envelopeLength], pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Every <c>subCommand</c> value outside {0x01..0x07} rejects with <c>InvalidSubcommand</c> — the sole source (line 8810), no gate at all.</summary>
    [TestMethod]
    [DataRow(0x00, DisplayName = "below-range")]
    [DataRow(0x08, DisplayName = "one-past-range")]
    [DataRow(0x99, DisplayName = "far-out-of-range")]
    public async Task UnsupportedSubCommandReturnsInvalidSubcommand(int subCommand)
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator($"cm-unsupported-{subCommand:X2}");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapCredentialManagementRequest(SubCommand: subCommand);
        using PooledMemory response = await SendCredentialManagementAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidSubcommand, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// Every one of the five verifying subcommands rejects a missing <c>pinUvAuthParam</c> with
    /// <c>PuatRequired</c> UNCONDITIONALLY — even when no PIN is set and the store is empty (the gate
    /// precedes any no-credentials check).
    /// </summary>
    [TestMethod]
    [DataRow(WellKnownCredentialManagementSubCommandGetCredsMetadata, DisplayName = "getCredsMetadata")]
    [DataRow(WellKnownCredentialManagementSubCommandEnumerateRpsBegin, DisplayName = "enumerateRPsBegin")]
    [DataRow(WellKnownCredentialManagementSubCommandEnumerateCredentialsBegin, DisplayName = "enumerateCredentialsBegin")]
    [DataRow(WellKnownCredentialManagementSubCommandDeleteCredential, DisplayName = "deleteCredential")]
    [DataRow(WellKnownCredentialManagementSubCommandUpdateUserInformation, DisplayName = "updateUserInformation")]
    public async Task NoPinSetAndEmptyStoreNoParamReturnsPuatRequired(int subCommand)
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator($"cm-no-pin-no-param-{subCommand:X2}");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapCredentialManagementRequest(SubCommand: subCommand);
        using PooledMemory response = await SendCredentialManagementAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>enumerateCredentialsBegin</c> with no <c>rpIDHash</c> member rejects with <c>MissingParameter</c>.</summary>
    [TestMethod]
    public async Task EnumerateCredentialsBeginNoRpIdHashReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-enum-creds-no-rpidhash");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapCredentialManagementRequest(
            SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            PinUvAuthParam: new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
        using PooledMemory response = await SendCredentialManagementAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>deleteCredential</c> with no <c>credentialID</c> member rejects with <c>MissingParameter</c>.</summary>
    [TestMethod]
    public async Task DeleteCredentialNoCredentialIdReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-delete-no-credid");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapCredentialManagementRequest(
            SubCommand: WellKnownCtapCredentialManagementSubCommands.DeleteCredential,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            PinUvAuthParam: new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
        using PooledMemory response = await SendCredentialManagementAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>updateUserInformation</c> with <c>credentialID</c> present but <c>user</c> absent rejects with <c>MissingParameter</c>.</summary>
    [TestMethod]
    public async Task UpdateUserInformationCredentialIdWithoutUserReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-update-no-user");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using CredentialId fakeId = CredentialId.Create(BuildFixedBytes(32, 0x50), pool);
        var request = new CtapCredentialManagementRequest(
            SubCommand: WellKnownCtapCredentialManagementSubCommands.UpdateUserInformation,
            CredentialId: new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = fakeId },
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            PinUvAuthParam: new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
        using PooledMemory response = await SendCredentialManagementAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>updateUserInformation</c> with <c>user</c> present but <c>credentialID</c> absent rejects with <c>MissingParameter</c>.</summary>
    [TestMethod]
    public async Task UpdateUserInformationUserWithoutCredentialIdReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-update-no-credid");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using UserHandle fakeUserId = UserHandle.Create(BuildFixedBytes(16, 0x60), pool);
        var request = new CtapCredentialManagementRequest(
            SubCommand: WellKnownCtapCredentialManagementSubCommands.UpdateUserInformation,
            User: new CtapPublicKeyCredentialUserEntity(fakeUserId, "alice"),
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            PinUvAuthParam: new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
        using PooledMemory response = await SendCredentialManagementAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>pinUvAuthProtocol</c> absent (mandatory params otherwise present) rejects with <c>MissingParameter</c>.</summary>
    [TestMethod]
    public async Task PinUvAuthProtocolAbsentReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-protocol-absent");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapCredentialManagementRequest(
            SubCommand: WellKnownCtapCredentialManagementSubCommands.GetCredsMetadata,
            PinUvAuthParam: new byte[] { 0x01 });
        using PooledMemory response = await SendCredentialManagementAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>An unsupported <c>pinUvAuthProtocol</c> value (3) rejects with <c>InvalidParameter</c>.</summary>
    [TestMethod]
    public async Task PinUvAuthProtocolUnsupportedReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-protocol-unsupported");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapCredentialManagementRequest(
            SubCommand: WellKnownCtapCredentialManagementSubCommands.GetCredsMetadata,
            PinUvAuthProtocol: 3,
            PinUvAuthParam: new byte[] { 0x01 });
        using PooledMemory response = await SendCredentialManagementAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A bad HMAC fails with <c>PinAuthInvalid</c> and mutates NO state: the same token remains usable afterward.</summary>
    [TestMethod]
    public async Task BadHmacReturnsPinAuthInvalidAndTokenRemainsUsable()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-bad-hmac");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        var badRequest = new CtapCredentialManagementRequest(
            SubCommand: WellKnownCtapCredentialManagementSubCommands.GetCredsMetadata,
            PinUvAuthProtocol: (int)protocolId,
            PinUvAuthParam: new byte[32]);
        using(PooledMemory badResponse = await SendCredentialManagementAsync(simulator, badRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, badResponse.AsReadOnlySpan()[0]);
        }

        using PooledMemory goodResponse = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.GetCredsMetadata, null, null, null, pool, TestContext.CancellationToken);
        Assert.AreEqual(
            WellKnownCtapStatusCodes.Ok, goodResponse.AsReadOnlySpan()[0],
            "the token must remain usable after a failed verify attempt: no state mutation on a bad HMAC.");
    }


    /// <summary>A token without the <c>cm</c> permission fails with <c>PinAuthInvalid</c>.</summary>
    [TestMethod]
    public async Task TokenWithoutCmPermissionReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-no-cm-permission");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin,
            WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga, DefaultRpId, TestContext.CancellationToken);

        using PooledMemory response = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.GetCredsMetadata, null, null, null, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A <c>enumerateRPsGetNextRP</c>/<c>enumerateCredentialsGetNextCredential</c> succeeds despite a
    /// junk presented <c>pinUvAuthParam</c>/<c>pinUvAuthProtocol</c>: the two continuations decode and
    /// IGNORE both — no gate exists for them at all.
    /// </summary>
    [TestMethod]
    public async Task GetNextRpWithJunkParamStillSucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-getnextrp-junk-param");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x70), TestContext.CancellationToken, rpId: "rpa.example");
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x71), TestContext.CancellationToken, rpId: "rpb.example");
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using(PooledMemory begin = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateRpsBegin, null, null, null, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, begin.AsReadOnlySpan()[0]);
        }

        var junkRequest = new CtapCredentialManagementRequest(
            SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateRpsGetNextRp,
            PinUvAuthProtocol: 99,
            PinUvAuthParam: new byte[] { 0xFF, 0xFF });
        using PooledMemory response = await SendCredentialManagementAsync(simulator, junkRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>C1 rejects a BOUND token for <c>getCredsMetadata</c>/<c>enumerateRPsBegin</c> — INVERTED polarity from mc/ga.</summary>
    [TestMethod]
    [DataRow(WellKnownCredentialManagementSubCommandGetCredsMetadata, DisplayName = "getCredsMetadata")]
    [DataRow(WellKnownCredentialManagementSubCommandEnumerateRpsBegin, DisplayName = "enumerateRPsBegin")]
    public async Task C1RejectsBoundTokenForMetadataAndRpEnumeration(int subCommand)
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator($"cm-c1-bound-{subCommand:X2}");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: DefaultRpId, TestContext.CancellationToken);

        using PooledMemory response = await SendGatedRequestAsync(simulator, token, protocolId, subCommand, null, null, null, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// C1 rejects a BOUND token for <c>enumerateCredentialsBegin</c> even when it is bound to the VERY RP
    /// being enumerated — the two RP-ID notions (token permission scoping vs. the request's own
    /// <c>rpIDHash</c> parameter) are independent.
    /// </summary>
    [TestMethod]
    public async Task C1RejectsTokenBoundToTheVeryRpBeingEnumerated()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-c1-bound-own-rp");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x72), TestContext.CancellationToken, rpId: DefaultRpId);
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: DefaultRpId, TestContext.CancellationToken);

        ReadOnlyMemory<byte> rpIdHash = ComputeRpIdHashOracle(DefaultRpId);
        using PooledMemory response = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, rpIdHash, null, null, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// C2's REQUIRED negative triple for <c>deleteCredential</c>: a token bound to a DIFFERENT RP than
    /// the addressed (existing) credential rejects with <c>PinAuthInvalid</c> — no existence oracle.
    /// </summary>
    [TestMethod]
    public async Task DeleteCredentialBoundTokenMismatchedExistingCredentialReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-delete-bound-mismatch");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        const string otherRpId = "other.example";
        byte[] otherCredentialId = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x73), TestContext.CancellationToken, rpId: otherRpId);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: DefaultRpId, TestContext.CancellationToken);

        using CredentialId addressedId = CredentialId.Create(otherCredentialId, pool);
        var descriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = addressedId };
        using PooledMemory response = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.DeleteCredential, null, descriptor, null, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>C2's REQUIRED negative triple for <c>deleteCredential</c>: a BOUND token addressing a nonexistent credential also rejects with <c>PinAuthInvalid</c> — no existence oracle.</summary>
    [TestMethod]
    public async Task DeleteCredentialBoundTokenNonexistentCredentialReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-delete-bound-nonexistent");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: DefaultRpId, TestContext.CancellationToken);

        using CredentialId bogusId = CredentialId.Create(BuildFixedBytes(32, 0x80), pool);
        var descriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = bogusId };
        using PooledMemory response = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.DeleteCredential, null, descriptor, null, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>C2's REQUIRED negative triple for <c>deleteCredential</c>: an UNBOUND token addressing a nonexistent credential reaches step 7 and rejects with <c>NoCredentials</c>.</summary>
    [TestMethod]
    public async Task DeleteCredentialUnboundTokenNonexistentCredentialReturnsNoCredentials()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-delete-unbound-nonexistent");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using CredentialId bogusId = CredentialId.Create(BuildFixedBytes(32, 0x81), pool);
        var descriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = bogusId };
        using PooledMemory response = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.DeleteCredential, null, descriptor, null, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, response.AsReadOnlySpan()[0]);
    }


    /// <summary>C2 for <c>updateUserInformation</c>: a bound-mismatched token rejects with <c>PinAuthInvalid</c>.</summary>
    [TestMethod]
    public async Task UpdateUserInformationBoundTokenMismatchedExistingCredentialReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-update-bound-mismatch");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        const string otherRpId = "other2.example";
        byte[] userId = BuildFixedBytes(16, 0x74);
        byte[] otherCredentialId = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, userId, TestContext.CancellationToken, rpId: otherRpId);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: DefaultRpId, TestContext.CancellationToken);

        using CredentialId addressedId = CredentialId.Create(otherCredentialId, pool);
        var descriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = addressedId };
        using UserHandle suppliedUserId = UserHandle.Create(userId, pool);
        var user = new CtapPublicKeyCredentialUserEntity(suppliedUserId, "renamed");
        using PooledMemory response = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.UpdateUserInformation, null, descriptor, user, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>C2's REQUIRED negative triple for <c>updateUserInformation</c>: a BOUND token addressing a nonexistent credential also rejects with <c>PinAuthInvalid</c> — no existence oracle, the same conjunction <see cref="DeleteCredentialBoundTokenNonexistentCredentialReturnsPinAuthInvalid"/> proves for the sibling subcommand.</summary>
    [TestMethod]
    public async Task UpdateUserInformationBoundTokenNonexistentCredentialReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-update-bound-nonexistent");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: DefaultRpId, TestContext.CancellationToken);

        using CredentialId bogusId = CredentialId.Create(BuildFixedBytes(32, 0x84), pool);
        var descriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = bogusId };
        using UserHandle suppliedUserId = UserHandle.Create(BuildFixedBytes(16, 0x85), pool);
        var user = new CtapPublicKeyCredentialUserEntity(suppliedUserId, "nobody");
        using PooledMemory response = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.UpdateUserInformation, null, descriptor, user, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>C2 for <c>updateUserInformation</c>: an unbound token addressing a nonexistent credential reaches step 7 and rejects with <c>NoCredentials</c>.</summary>
    [TestMethod]
    public async Task UpdateUserInformationUnboundTokenNonexistentCredentialReturnsNoCredentials()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-update-unbound-nonexistent");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using CredentialId bogusId = CredentialId.Create(BuildFixedBytes(32, 0x82), pool);
        var descriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = bogusId };
        using UserHandle suppliedUserId = UserHandle.Create(BuildFixedBytes(16, 0x83), pool);
        var user = new CtapPublicKeyCredentialUserEntity(suppliedUserId, "nobody");
        using PooledMemory response = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.UpdateUserInformation, null, descriptor, user, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A cm-permissioned token retains every OTHER permission afterward (no flag/permission clearing in
    /// the cm path): a token bound to <see cref="DefaultRpId"/> (matching <c>deleteCredential</c>'s own
    /// C2 "bound-and-matching" allowance) completes <c>deleteCredential</c>, then the SAME token
    /// completes an <c>authenticatorMakeCredential</c> for that same RP with <c>uv=1</c>.
    /// </summary>
    [TestMethod]
    public async Task TokenSucceedsAndDoesNotStripPermissionsSameTokenCompletesMakeCredentialWithUvOne()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-no-strip");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] credentialIdBytes = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xDA), TestContext.CancellationToken);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        int permissions = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Cm;
        byte[] token = await CtapWaveConfigFixtures.IssueTokenAsync(simulator, pool, protocolId, DefaultPin, permissions, DefaultRpId, TestContext.CancellationToken);

        using CredentialId deleteId = CredentialId.Create(credentialIdBytes, pool);
        var descriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = deleteId };
        using(PooledMemory cmResponse = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.DeleteCredential, null, descriptor, null, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, cmResponse.AsReadOnlySpan()[0]);
        }

        byte[] mcParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, BuildFixedBytes(32, 0x10), pool, TestContext.CancellationToken);
        CtapMakeCredentialRequest mcRequest = BuildMakeCredentialRequest(pool, pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)protocolId);
        using PooledMemory mcResponse = await SendMakeCredentialAsync(simulator, mcRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, mcResponse.AsReadOnlySpan()[0], "the cm token must retain mc afterward: no permission clearing in the cm path.");
    }


    /// <summary><c>getCredsMetadata</c> succeeds on an EMPTY store with <c>{0, capacity}</c> — no no-credentials rejection exists for it.</summary>
    [TestMethod]
    public async Task GetCredsMetadataEmptyStoreSucceedsWithZeroAndCapacity()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-metadata-empty", residentCredentialCapacity: 5);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using PooledMemory response = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.GetCredsMetadata, null, null, null, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapCredentialManagementResponse decoded = CtapCredentialManagementResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);
        Assert.AreEqual(0, decoded.ExistingResidentCredentialsCount);
        Assert.AreEqual(5, decoded.MaxPossibleRemainingResidentCredentialsCount);
    }


    /// <summary><c>getCredsMetadata</c> on a populated store reports <c>{n, capacity-n}</c>, matching getInfo's own <c>remainingDiscoverableCredentials</c>.</summary>
    [TestMethod]
    public async Task GetCredsMetadataPopulatedStoreReportsCountAndRemainingMatchingGetInfo()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-metadata-populated", residentCredentialCapacity: 5);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x90), TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x91), TestContext.CancellationToken, rpId: "second.example");

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using PooledMemory response = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.GetCredsMetadata, null, null, null, pool, TestContext.CancellationToken);
        CtapCredentialManagementResponse decoded = CtapCredentialManagementResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);
        Assert.AreEqual(2, decoded.ExistingResidentCredentialsCount);
        Assert.AreEqual(3, decoded.MaxPossibleRemainingResidentCredentialsCount);

        CtapGetInfoResponse infoResponse = await CtapWaveConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(decoded.MaxPossibleRemainingResidentCredentialsCount, infoResponse.RemainingDiscoverableCredentials, "R9: both numbers derive from the same single source.");
    }


    /// <summary>
    /// <c>enumerateRPsBegin</c>/<c>enumerateRPsGetNextRP</c> walk every RP holding a discoverable
    /// credential in <c>CreationSequence</c>-ascending order BY EACH RP's FIRST-created credential (R9)
    /// — not by each RP's most-recently-created one, which this fixture setup deliberately distinguishes:
    /// rpB's own first credential precedes rpA's, even though rpA also gets a SECOND (later) credential.
    /// <c>totalRPs</c> appears only on the Begin response; <c>rpIDHash</c> matches an independently
    /// computed SHA-256 on both responses.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRpsWalksInFirstCreatedOrderWithRpIdHashAndTotalRpsOnlyOnBegin()
    {
        const string rpA = "rpa-order.example";
        const string rpB = "rpb-order.example";
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-enum-rps-order", residentCredentialCapacity: 4);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xA0), TestContext.CancellationToken, rpId: rpB);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xA1), TestContext.CancellationToken, rpId: rpA);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xA2), TestContext.CancellationToken, rpId: rpB);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using PooledMemory beginResponse = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateRpsBegin, null, null, null, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, beginResponse.AsReadOnlySpan()[0]);
        CtapCredentialManagementResponse begin = CtapCredentialManagementResponseCborReader.Read(beginResponse.AsReadOnlyMemory()[1..], pool);
        Assert.AreEqual(rpB, begin.Rp!.Id);
        Assert.AreEqual(2, begin.TotalRps);
        Assert.AreSequenceEqual(ComputeRpIdHashOracle(rpB).ToArray(), begin.RpIdHash!.Value.ToArray());

        var nextRequest = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateRpsGetNextRp);
        using PooledMemory nextResponse = await SendCredentialManagementAsync(simulator, nextRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, nextResponse.AsReadOnlySpan()[0]);
        CtapCredentialManagementResponse next = CtapCredentialManagementResponseCborReader.Read(nextResponse.AsReadOnlyMemory()[1..], pool);
        Assert.AreEqual(rpA, next.Rp!.Id);
        Assert.IsNull(next.TotalRps, "enumerateRPsGetNextRP never reports totalRPs.");
        Assert.AreSequenceEqual(ComputeRpIdHashOracle(rpA).ToArray(), next.RpIdHash!.Value.ToArray());
    }


    /// <summary><c>enumerateRPsBegin</c> with no discoverable credentials at all rejects with <c>NoCredentials</c>.</summary>
    [TestMethod]
    public async Task EnumerateRpsBeginNoDiscoverableCredentialsReturnsNoCredentials()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-enum-rps-empty");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using PooledMemory response = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateRpsBegin, null, null, null, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>enumerateRPsGetNextRP</c> with no live sequence (never begun) rejects with <c>NotAllowed</c>.</summary>
    [TestMethod]
    public async Task EnumerateRpsGetNextRpWithoutBeginReturnsNotAllowed()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-enum-rps-no-begin");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateRpsGetNextRp);
        using PooledMemory response = await SendCredentialManagementAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// <c>enumerateCredentialsBegin</c>/<c>enumerateCredentialsGetNextCredential</c> walk every resident
    /// credential for the matched RP in <c>CreationSequence</c>-ascending order, filtering out a
    /// different RP's own credential; <c>totalCredentials</c> appears only on the Begin response;
    /// <c>publicKey</c> is byte-round-trippable against the registered COSE key.
    /// </summary>
    [TestMethod]
    public async Task EnumerateCredentialsWalksMatchedRpInCreationOrderWithTotalOnlyOnBeginAndPublicKeyRoundTrips()
    {
        const string rpId = "enum-creds.example";
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-enum-creds-order", residentCredentialCapacity: 4);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] firstUserId = BuildFixedBytes(16, 0xB0);
        byte[] secondUserId = BuildFixedBytes(16, 0xB1);
        CtapWave2RegisteredCredential first = await RegisterCredentialAsync(simulator, pool, firstUserId, TestContext.CancellationToken, rpId: rpId);
        CtapWave2RegisteredCredential second = await RegisterCredentialAsync(simulator, pool, secondUserId, TestContext.CancellationToken, rpId: rpId);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xB2), TestContext.CancellationToken, rpId: "other-enum.example");

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        ReadOnlyMemory<byte> rpIdHash = ComputeRpIdHashOracle(rpId);
        using PooledMemory beginResponse = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, rpIdHash, null, null, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, beginResponse.AsReadOnlySpan()[0]);
        CtapCredentialManagementResponse begin = CtapCredentialManagementResponseCborReader.Read(beginResponse.AsReadOnlyMemory()[1..], pool);
        Assert.AreEqual(2, begin.TotalCredentials);
        Assert.AreSequenceEqual(firstUserId, begin.User!.Id.AsReadOnlySpan().ToArray());
        Assert.AreSequenceEqual(first.CredentialId.AsReadOnlySpan().ToArray(), begin.CredentialId!.Id.AsReadOnlySpan().ToArray());
        Assert.AreEqual(first.PublicKey, begin.PublicKey);
        begin.CredentialId.Id.Dispose();
        begin.User.Id.Dispose();

        var nextRequest = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsGetNextCredential);
        using PooledMemory nextResponse = await SendCredentialManagementAsync(simulator, nextRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, nextResponse.AsReadOnlySpan()[0]);
        CtapCredentialManagementResponse next = CtapCredentialManagementResponseCborReader.Read(nextResponse.AsReadOnlyMemory()[1..], pool);
        Assert.IsNull(next.TotalCredentials, "enumerateCredentialsGetNextCredential never reports totalCredentials.");
        Assert.AreSequenceEqual(secondUserId, next.User!.Id.AsReadOnlySpan().ToArray());
        Assert.AreEqual(second.PublicKey, next.PublicKey);
        next.CredentialId!.Id.Dispose();
        next.User.Id.Dispose();

        first.CredentialId.Dispose();
        second.CredentialId.Dispose();
    }


    /// <summary>
    /// No response of any credMgmt subcommand ever carries <c>thirdPartyPayment</c> — a byte-level
    /// top-level-key scan (R8; this authenticator models no third-party payment extension). Renamed from
    /// its wave-B name (<c>...NeverEmitsLargeBlobKeyOrThirdPartyPayment</c>): the <c>largeBlobKey</c> half
    /// SPLIT to <see cref="EnumerateCredentialsResponseEmitsLargeBlobKeyWithAMintedKey"/>, a positive
    /// assertion against a REAL minted key, once wavelb modeled the extension (R8, the waveext-R11
    /// rename maneuver). <c>credProtect</c>'s own coverage lives in
    /// <see cref="EnumerateCredentialsResponseEmitsCredProtectWithThePersistedLevel"/>.
    /// </summary>
    [TestMethod]
    public async Task EnumerateCredentialsResponseNeverEmitsThirdPartyPayment()
    {
        const string rpId = "no-forbidden-keys.example";
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-no-forbidden-keys", residentCredentialCapacity: 2);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] credentialIdBytes = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xB9), TestContext.CancellationToken, rpId: rpId);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        ReadOnlyMemory<byte> rpIdHash = ComputeRpIdHashOracle(rpId);
        using PooledMemory beginResponse = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, rpIdHash, null, null, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, beginResponse.AsReadOnlySpan()[0]);

        List<int> keys = ReadTopLevelIntegerKeys(beginResponse.AsReadOnlyMemory()[1..]);
        Assert.DoesNotContain(WellKnownCtapCredentialManagementResponseKeys.ThirdPartyPayment, keys);

        using CredentialId disposeId = CredentialId.Create(credentialIdBytes, pool);
    }


    /// <summary>
    /// <c>enumerateCredentialsBegin</c> emits <c>largeBlobKey</c> (<c>0x0B</c>) carrying the credential's
    /// REAL minted key (wavelb R8) — the credential is registered with the <c>largeBlobKey</c> extension
    /// requested (mc mints and returns it at <c>0x05</c>), so the enumerate response's <c>0x0B</c> bytes
    /// are asserted byte-equal to that SAME minted key, never a hardcoded or back-channel value. The
    /// SPLIT half of <see cref="EnumerateCredentialsResponseNeverEmitsThirdPartyPayment"/> (R8).
    /// </summary>
    [TestMethod]
    public async Task EnumerateCredentialsResponseEmitsLargeBlobKeyWithAMintedKey()
    {
        const string rpId = "cm-largeblobkey-emitted.example";
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-largeblobkey-emitted", residentCredentialCapacity: 2);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ReadOnlyMemory<byte> extensions = BuildMakeCredentialExtensionsInput(largeBlobKey: true);
        CtapMakeCredentialRequest mcRequest = BuildMakeCredentialRequest(
            pool, rpId: rpId, userId: BuildFixedBytes(16, 0xBB), options: new CtapCommandOptions(ResidentKey: true), extensions: extensions);
        using PooledMemory mcResponse = await SendMakeCredentialAsync(simulator, mcRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, mcResponse.AsReadOnlySpan()[0]);
        CtapMakeCredentialResponse mcDecoded = CtapMakeCredentialResponseCborReader.Read(mcResponse.AsReadOnlyMemory()[1..]);
        byte[] mintedKey = mcDecoded.LargeBlobKey!.Value.ToArray();

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        ReadOnlyMemory<byte> rpIdHash = ComputeRpIdHashOracle(rpId);
        using PooledMemory beginResponse = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, rpIdHash, null, null, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, beginResponse.AsReadOnlySpan()[0]);

        CtapCredentialManagementResponse decoded = CtapCredentialManagementResponseCborReader.Read(beginResponse.AsReadOnlyMemory()[1..], pool);
        decoded.User!.Id.Dispose();
        decoded.CredentialId!.Id.Dispose();

        Assert.IsNotNull(decoded.LargeBlobKey);
        Assert.IsTrue(decoded.LargeBlobKey!.Value.Span.SequenceEqual(mintedKey));
    }


    /// <summary>
    /// <c>enumerateCredentialsBegin</c> emits <c>credProtect</c> (<c>0x0A</c>) carrying the credential's
    /// REAL persisted level (R11) — minted at level 2, never the default 1, so the assertion cannot be
    /// satisfied by a hardcoded constant.
    /// </summary>
    [TestMethod]
    public async Task EnumerateCredentialsResponseEmitsCredProtectWithThePersistedLevel()
    {
        const string rpId = "credprotect-emitted.example";
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-credprotect-emitted", residentCredentialCapacity: 2);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] credentialIdBytes = await RegisterAndCaptureCredentialIdBytesAsync(
            simulator, pool, BuildFixedBytes(16, 0xBA), TestContext.CancellationToken, rpId: rpId, credProtect: 2);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        ReadOnlyMemory<byte> rpIdHash = ComputeRpIdHashOracle(rpId);
        using PooledMemory beginResponse = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, rpIdHash, null, null, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, beginResponse.AsReadOnlySpan()[0]);

        CtapCredentialManagementResponse decoded = CtapCredentialManagementResponseCborReader.Read(beginResponse.AsReadOnlyMemory()[1..], pool);
        Assert.AreEqual(2, decoded.CredProtect);
        decoded.CredentialId!.Id.Dispose();
        decoded.User!.Id.Dispose();

        using CredentialId disposeId = CredentialId.Create(credentialIdBytes, pool);
    }


    /// <summary><c>enumerateCredentialsBegin</c> with an <c>rpIDHash</c> matching no stored credential rejects with <c>NoCredentials</c>.</summary>
    [TestMethod]
    public async Task EnumerateCredentialsBeginNoMatchReturnsNoCredentials()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-enum-creds-nomatch");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xB3), TestContext.CancellationToken);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        ReadOnlyMemory<byte> rpIdHash = ComputeRpIdHashOracle("nomatch.example");
        using PooledMemory response = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, rpIdHash, null, null, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>enumerateCredentialsGetNextCredential</c> with no live sequence rejects with <c>NotAllowed</c>.</summary>
    [TestMethod]
    public async Task EnumerateCredentialsGetNextWithoutBeginReturnsNotAllowed()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-enum-creds-no-begin");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsGetNextCredential);
        using PooledMemory response = await SendCredentialManagementAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>enumerateRPsGetNextRP</c> issued more than 30 seconds after the last stateful step rejects with <c>NotAllowed</c> and discards the sequence.</summary>
    [TestMethod]
    public async Task EnumerateRpsGetNextRpAfterTimerExpiryReturnsNotAllowedAndDiscardsState()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-rps-timer-expired", timeProvider: timeProvider, residentCredentialCapacity: 2);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xC0), TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xC1), TestContext.CancellationToken, rpId: "second-timer.example");

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using(PooledMemory begin = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateRpsBegin, null, null, null, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, begin.AsReadOnlySpan()[0]);
        }

        timeProvider.Advance(TimeSpan.FromSeconds(31));

        var nextRequest = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateRpsGetNextRp);
        using(PooledMemory expired = await SendCredentialManagementAsync(simulator, nextRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, expired.AsReadOnlySpan()[0]);
        }

        using PooledMemory second = await SendCredentialManagementAsync(simulator, nextRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, second.AsReadOnlySpan()[0], "the sequence must have been discarded by the timer expiry.");
    }


    /// <summary><c>enumerateCredentialsGetNextCredential</c> issued more than 30 seconds after the last stateful step rejects with <c>NotAllowed</c> and discards the sequence.</summary>
    [TestMethod]
    public async Task EnumerateCredentialsGetNextAfterTimerExpiryReturnsNotAllowedAndDiscardsState()
    {
        const string rpId = "cred-timer.example";
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-creds-timer-expired", timeProvider: timeProvider, residentCredentialCapacity: 2);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xC2), TestContext.CancellationToken, rpId: rpId);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xC3), TestContext.CancellationToken, rpId: rpId);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        ReadOnlyMemory<byte> rpIdHash = ComputeRpIdHashOracle(rpId);
        using(PooledMemory begin = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, rpIdHash, null, null, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, begin.AsReadOnlySpan()[0]);
        }

        timeProvider.Advance(TimeSpan.FromSeconds(31));

        var nextRequest = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsGetNextCredential);
        using(PooledMemory expired = await SendCredentialManagementAsync(simulator, nextRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, expired.AsReadOnlySpan()[0]);
        }

        using PooledMemory second = await SendCredentialManagementAsync(simulator, nextRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, second.AsReadOnlySpan()[0]);
    }


    /// <summary><c>enumerateRPsGetNextRP</c> issued after the AUTHENTICATING TOKEN itself expires rejects with <c>NotAllowed</c> and discards the sequence (CTAP 2.3, line 2873).</summary>
    [TestMethod]
    public async Task EnumerateRpsGetNextRpAfterAuthenticatingTokenExpiryReturnsNotAllowed()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-rps-token-expired", timeProvider: timeProvider, residentCredentialCapacity: 2);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xC4), TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xC5), TestContext.CancellationToken, rpId: "second-tokexp.example");

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using(PooledMemory begin = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateRpsBegin, null, null, null, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, begin.AsReadOnlySpan()[0]);
        }

        //The Begin call's own successful verify already stamped LastUsedAt, so only the token's own
        //10-minute MAX usage time period (unconditional, independent of LastUsedAt) can still expire it;
        //this exercises this handler's own token-expiry-folded-first branch (CTAP 2.3, line 2873) —
        //distinct from EnumerateRpsGetNextRpAfterTimerExpiryReturnsNotAllowedAndDiscardsState's own
        //30-second enumeration-timer branch, even though both observably return the same status.
        timeProvider.Advance(TimeSpan.FromMinutes(10) + TimeSpan.FromSeconds(1));

        var nextRequest = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateRpsGetNextRp);
        using PooledMemory response = await SendCredentialManagementAsync(simulator, nextRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>enumerateCredentialsGetNextCredential</c> issued after the AUTHENTICATING TOKEN itself expires rejects with <c>NotAllowed</c>.</summary>
    [TestMethod]
    public async Task EnumerateCredentialsGetNextAfterAuthenticatingTokenExpiryReturnsNotAllowed()
    {
        const string rpId = "cred-tokexp.example";
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-creds-token-expired", timeProvider: timeProvider, residentCredentialCapacity: 2);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xC6), TestContext.CancellationToken, rpId: rpId);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xC7), TestContext.CancellationToken, rpId: rpId);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        ReadOnlyMemory<byte> rpIdHash = ComputeRpIdHashOracle(rpId);
        using(PooledMemory begin = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, rpIdHash, null, null, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, begin.AsReadOnlySpan()[0]);
        }

        //Same rationale as EnumerateRpsGetNextRpAfterAuthenticatingTokenExpiryReturnsNotAllowed's own
        //remark: the token's 10-minute MAX usage time period is the only branch that can still expire it
        //once Begin's own verify has stamped LastUsedAt.
        timeProvider.Advance(TimeSpan.FromMinutes(10) + TimeSpan.FromSeconds(1));

        var nextRequest = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsGetNextCredential);
        using PooledMemory response = await SendCredentialManagementAsync(simulator, nextRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, response.AsReadOnlySpan()[0]);
    }


    /// <summary>An intervening <c>authenticatorGetInfo</c> between <c>enumerateRPsBegin</c> and <c>enumerateRPsGetNextRP</c> discards the remembered sequence (R10's global discard rule).</summary>
    [TestMethod]
    public async Task InterveningGetInfoDiscardsRpEnumerationSequence()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-rps-intervening-getinfo", residentCredentialCapacity: 2);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xC8), TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xC9), TestContext.CancellationToken, rpId: "second-getinfo.example");

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using(PooledMemory begin = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateRpsBegin, null, null, null, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, begin.AsReadOnlySpan()[0]);
        }

        using IMemoryOwner<byte> getInfoRequestOwner = pool.Rent(1);
        getInfoRequestOwner.Memory.Span[0] = WellKnownCtapCommands.GetInfo;
        using(PooledMemory getInfoResponse = await simulator.TransceiveAsync(getInfoRequestOwner.Memory[..1], pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, getInfoResponse.AsReadOnlySpan()[0]);
        }

        var nextRequest = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateRpsGetNextRp);
        using PooledMemory response = await SendCredentialManagementAsync(simulator, nextRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, response.AsReadOnlySpan()[0]);
    }


    /// <summary>An intervening <c>authenticatorMakeCredential</c> discards a remembered credential-enumeration sequence.</summary>
    [TestMethod]
    public async Task InterveningMakeCredentialDiscardsCredentialEnumerationSequence()
    {
        const string rpId = "cred-intervening-mc.example";
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-creds-intervening-mc", residentCredentialCapacity: 3);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xCA), TestContext.CancellationToken, rpId: rpId);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xCB), TestContext.CancellationToken, rpId: rpId);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        ReadOnlyMemory<byte> rpIdHash = ComputeRpIdHashOracle(rpId);
        using(PooledMemory begin = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, rpIdHash, null, null, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, begin.AsReadOnlySpan()[0]);
        }

        //Non-resident: once a PIN is set, a resident mc registration requires a token (step 7), but this
        //intervening registration only needs to be SOME mc call, proving the discard is unconditional.
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xCC), TestContext.CancellationToken, rpId: "third.example", resident: false);

        var nextRequest = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsGetNextCredential);
        using PooledMemory response = await SendCredentialManagementAsync(simulator, nextRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// An intervening <c>deleteCredential</c> discards BOTH remembered enumeration sequences at once
    /// (extraction Q5, line 2871's own "MAY assume this globally" license) — a live RP-enumeration
    /// sequence dies even though only the credential store, not the RP list, was touched.
    /// </summary>
    [TestMethod]
    public async Task InterveningDeleteCredentialDiscardsBothEnumerationSequences()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-rps-intervening-delete", residentCredentialCapacity: 3);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] firstCredentialId = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xCD), TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xCE), TestContext.CancellationToken, rpId: "second-delete.example");

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using(PooledMemory begin = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateRpsBegin, null, null, null, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, begin.AsReadOnlySpan()[0]);
        }

        using CredentialId deleteId = CredentialId.Create(firstCredentialId, pool);
        var descriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = deleteId };
        using(PooledMemory deleteResponse = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.DeleteCredential, null, descriptor, null, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, deleteResponse.AsReadOnlySpan()[0]);
        }

        var nextRequest = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateRpsGetNextRp);
        using PooledMemory response = await SendCredentialManagementAsync(simulator, nextRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>deleteCredential</c> removes the credential, returns a bare <c>CTAP2_OK</c>, and shrinks the store — reflected in a following <c>getCredsMetadata</c>.</summary>
    [TestMethod]
    public async Task DeleteCredentialSucceedsBareOkAndStoreShrinks()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-delete-shrinks", residentCredentialCapacity: 3);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] credentialIdBytes = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xD0), TestContext.CancellationToken);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using CredentialId deleteId = CredentialId.Create(credentialIdBytes, pool);
        var descriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = deleteId };
        using(PooledMemory deleteResponse = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.DeleteCredential, null, descriptor, null, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, deleteResponse.AsReadOnlySpan()[0]);
            Assert.AreEqual(1, deleteResponse.Length, "deleteCredential returns no CBOR body.");
        }

        using PooledMemory metadataResponse = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.GetCredsMetadata, null, null, null, pool, TestContext.CancellationToken);
        CtapCredentialManagementResponse metadata = CtapCredentialManagementResponseCborReader.Read(metadataResponse.AsReadOnlyMemory()[1..], pool);
        Assert.AreEqual(0, metadata.ExistingResidentCredentialsCount);
    }


    /// <summary>Re-deleting an already-deleted credential rejects with <c>NoCredentials</c>.</summary>
    [TestMethod]
    public async Task ReDeleteCredentialReturnsNoCredentials()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-redelete");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] credentialIdBytes = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xD1), TestContext.CancellationToken);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using CredentialId deleteId = CredentialId.Create(credentialIdBytes, pool);
        var descriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = deleteId };
        using(PooledMemory firstDelete = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.DeleteCredential, null, descriptor, null, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstDelete.AsReadOnlySpan()[0]);
        }

        using PooledMemory secondDelete = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.DeleteCredential, null, descriptor, null, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, secondDelete.AsReadOnlySpan()[0]);
    }


    /// <summary><c>updateUserInformation</c> replaces both <c>name</c> and <c>displayName</c> when both are supplied non-empty.</summary>
    [TestMethod]
    public async Task UpdateUserInformationRenamesBothFields()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-update-rename");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] userId = BuildFixedBytes(16, 0xD2);
        byte[] credentialIdBytes = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, userId, TestContext.CancellationToken);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using(PooledMemory response = await SendUpdateAsync(
            simulator, token, protocolId, credentialIdBytes, userId, "renamed-name", "Renamed Display", pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        }

        (string? name, string? displayName) = await EnumerateSingleCredentialFieldsAsync(simulator, token, protocolId, DefaultRpId, pool, TestContext.CancellationToken);
        Assert.AreEqual("renamed-name", name);
        Assert.AreEqual("Renamed Display", displayName);
    }


    /// <summary>An absent <c>name</c> in the supplied <c>user</c> removes the stored <c>name</c> (the three-way mapping's absent leg).</summary>
    [TestMethod]
    public async Task UpdateUserInformationNameAbsentRemovesName()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-update-name-absent");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] userId = BuildFixedBytes(16, 0xD3);
        byte[] credentialIdBytes = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, userId, TestContext.CancellationToken);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using(PooledMemory response = await SendUpdateAsync(
            simulator, token, protocolId, credentialIdBytes, userId, name: null, displayName: "Kept Display", pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        }

        (string? name, string? displayName) = await EnumerateSingleCredentialFieldsAsync(simulator, token, protocolId, DefaultRpId, pool, TestContext.CancellationToken);
        Assert.IsNull(name, "an absent name member removes the stored name.");
        Assert.AreEqual("Kept Display", displayName);
    }


    /// <summary>A present-but-EMPTY <c>name</c> also removes the stored <c>name</c> (the three-way mapping's present-and-empty leg — REQUIRED negative distinct from absent).</summary>
    [TestMethod]
    public async Task UpdateUserInformationNameEmptyRemovesName()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-update-name-empty");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] userId = BuildFixedBytes(16, 0xD4);
        byte[] credentialIdBytes = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, userId, TestContext.CancellationToken);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using(PooledMemory response = await SendUpdateAsync(
            simulator, token, protocolId, credentialIdBytes, userId, name: string.Empty, displayName: "Kept Display Two", pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        }

        (string? name, string? displayName) = await EnumerateSingleCredentialFieldsAsync(simulator, token, protocolId, DefaultRpId, pool, TestContext.CancellationToken);
        Assert.IsNull(name, "a present-but-empty name member removes the stored name, the same as absent.");
        Assert.AreEqual("Kept Display Two", displayName);
    }


    /// <summary>A present-but-EMPTY <c>displayName</c> removes the stored <c>displayName</c>.</summary>
    [TestMethod]
    public async Task UpdateUserInformationDisplayNameEmptyRemovesDisplayName()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-update-displayname-empty");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] userId = BuildFixedBytes(16, 0xD5);
        byte[] credentialIdBytes = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, userId, TestContext.CancellationToken);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using(PooledMemory response = await SendUpdateAsync(
            simulator, token, protocolId, credentialIdBytes, userId, name: "Kept Name", displayName: string.Empty, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        }

        (string? name, string? displayName) = await EnumerateSingleCredentialFieldsAsync(simulator, token, protocolId, DefaultRpId, pool, TestContext.CancellationToken);
        Assert.AreEqual("Kept Name", name);
        Assert.IsNull(displayName, "a present-but-empty displayName member removes the stored displayName.");
    }


    /// <summary>A supplied <c>user.id</c> that does not match the addressed credential's own stored user ID rejects with <c>InvalidParameter</c> (plain ordinal compare).</summary>
    [TestMethod]
    public async Task UpdateUserInformationUserIdMismatchReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-update-userid-mismatch");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] userId = BuildFixedBytes(16, 0xD6);
        byte[] credentialIdBytes = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, userId, TestContext.CancellationToken);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        byte[] wrongUserId = BuildFixedBytes(16, 0xD7);
        using PooledMemory response = await SendUpdateAsync(
            simulator, token, protocolId, credentialIdBytes, wrongUserId, name: "irrelevant", displayName: null, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>An update that succeeds is visible in a subsequent enumeration — proven separately by every rename test's own <see cref="EnumerateSingleCredentialFieldsAsync"/> read-back, restated here as its own dedicated assertion.</summary>
    [TestMethod]
    public async Task UpdatedEntityIsVisibleInSubsequentEnumeration()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-update-visible-enum");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] userId = BuildFixedBytes(16, 0xD8);
        byte[] credentialIdBytes = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, userId, TestContext.CancellationToken);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        byte[] token = await EstablishPinAndIssueCmTokenAsync(simulator, pool, protocolId, rpId: null, TestContext.CancellationToken);

        using(PooledMemory response = await SendUpdateAsync(
            simulator, token, protocolId, credentialIdBytes, userId, "visible-name", "Visible Display", pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        }

        (string? name, string? displayName) = await EnumerateSingleCredentialFieldsAsync(simulator, token, protocolId, DefaultRpId, pool, TestContext.CancellationToken);
        Assert.AreEqual("visible-name", name);
        Assert.AreEqual("Visible Display", displayName);
    }


    /// <summary>The <c>getCredsMetadata</c> subCommand ID (<c>0x01</c>), used as a <c>DataRow</c> constant.</summary>
    private const int WellKnownCredentialManagementSubCommandGetCredsMetadata = 0x01;

    /// <summary>The <c>enumerateRPsBegin</c> subCommand ID (<c>0x02</c>), used as a <c>DataRow</c> constant.</summary>
    private const int WellKnownCredentialManagementSubCommandEnumerateRpsBegin = 0x02;

    /// <summary>The <c>enumerateCredentialsBegin</c> subCommand ID (<c>0x04</c>), used as a <c>DataRow</c> constant.</summary>
    private const int WellKnownCredentialManagementSubCommandEnumerateCredentialsBegin = 0x04;

    /// <summary>The <c>deleteCredential</c> subCommand ID (<c>0x06</c>), used as a <c>DataRow</c> constant.</summary>
    private const int WellKnownCredentialManagementSubCommandDeleteCredential = 0x06;

    /// <summary>The <c>updateUserInformation</c> subCommand ID (<c>0x07</c>), used as a <c>DataRow</c> constant.</summary>
    private const int WellKnownCredentialManagementSubCommandUpdateUserInformation = 0x07;


    /// <summary>Establishes a PIN and issues a cm-permissioned token, optionally bound to <paramref name="rpId"/>.</summary>
    private static async Task<byte[]> EstablishPinAndIssueCmTokenAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string? rpId, CancellationToken cancellationToken)
    {
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, cancellationToken);

        return await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Cm, rpId, cancellationToken);
    }


    /// <summary>Computes the platform-side <c>pinUvAuthParam</c> over the R4 message shape and sends one gated credMgmt subcommand.</summary>
    private static async Task<PooledMemory> SendGatedRequestAsync(
        CtapAuthenticatorSimulator simulator, byte[] token, CtapPinUvAuthProtocolId protocolId, int subCommand,
        ReadOnlyMemory<byte>? rpIdHash, PublicKeyCredentialDescriptor? credentialId, CtapPublicKeyCredentialUserEntity? user,
        MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        bool hasSubCommandParams = rpIdHash is not null || credentialId is not null || user is not null;
        byte[] subCommandParams = hasSubCommandParams ? BuildSubCommandParams(rpIdHash, credentialId, user) : [];
        byte[] message = BuildMessage(subCommand, hasSubCommandParams ? subCommandParams : ReadOnlyMemory<byte>.Empty);
        byte[] param = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, cancellationToken);

        var request = new CtapCredentialManagementRequest(
            SubCommand: subCommand,
            RpIdHash: rpIdHash,
            CredentialId: credentialId,
            User: user,
            PinUvAuthProtocol: (int)protocolId,
            PinUvAuthParam: param);

        return await SendCredentialManagementAsync(simulator, request, pool, cancellationToken);
    }


    /// <summary>Builds and sends an <c>updateUserInformation</c> request for <paramref name="credentialIdBytes"/> with the supplied user fields.</summary>
    private static async Task<PooledMemory> SendUpdateAsync(
        CtapAuthenticatorSimulator simulator, byte[] token, CtapPinUvAuthProtocolId protocolId, byte[] credentialIdBytes, byte[] suppliedUserId,
        string? name, string? displayName, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using CredentialId credentialId = CredentialId.Create(credentialIdBytes, pool);
        var descriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = credentialId };
        using UserHandle userHandle = UserHandle.Create(suppliedUserId, pool);
        var user = new CtapPublicKeyCredentialUserEntity(userHandle, name, displayName);

        return await SendGatedRequestAsync(simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.UpdateUserInformation, null, descriptor, user, pool, cancellationToken);
    }


    /// <summary>Enumerates the single resident credential for <paramref name="rpId"/> and returns its current <c>name</c>/<c>displayName</c>, disposing every decoded carrier.</summary>
    private static async Task<(string? Name, string? DisplayName)> EnumerateSingleCredentialFieldsAsync(
        CtapAuthenticatorSimulator simulator, byte[] token, CtapPinUvAuthProtocolId protocolId, string rpId, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> rpIdHash = ComputeRpIdHashOracle(rpId);
        using PooledMemory response = await SendGatedRequestAsync(
            simulator, token, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, rpIdHash, null, null, pool, cancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapCredentialManagementResponse decoded = CtapCredentialManagementResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);
        (string? name, string? displayName) = (decoded.User!.Name, decoded.User.DisplayName);
        decoded.User.Id.Dispose();
        decoded.CredentialId!.Id.Dispose();

        return (name, displayName);
    }


    /// <summary>Computes SHA-256(UTF8(<paramref name="rpId"/>)) as an independent oracle for <c>rpIDHash</c> byte-exactness assertions.</summary>
    private static ReadOnlyMemory<byte> ComputeRpIdHashOracle(string rpId) => SHA256.HashData(Encoding.UTF8.GetBytes(rpId));


    /// <summary>Reads every top-level integer key of a CBOR map payload, without interpreting the values — for byte-level "forbidden key absent" assertions.</summary>
    private static List<int> ReadTopLevelIntegerKeys(ReadOnlyMemory<byte> payload)
    {
        var reader = new CborReader(payload, CborConformanceMode.Ctap2Canonical);
        int? count = reader.ReadStartMap();
        var keys = new List<int>();

        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
        {
            keys.Add(checked((int)reader.ReadInt64()));
            read++;
            reader.SkipValue();
        }

        reader.ReadEndMap();

        return keys;
    }
}
