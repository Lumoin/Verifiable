using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wavecm real-wire capstones for <c>authenticatorCredentialManagement</c> (<c>0x0A</c>): the same
/// real, unmodified APDU transport stack (<see cref="CtapWave2TransportHarness"/>) the waveconfig
/// capstones in <see cref="CtapAuthenticatorConfigFlowTests"/> use, driving the full seven-subcommand
/// management lifecycle (Capstone A) and the permission/RP-ID/statefulness semantics (Capstone B) end to
/// end. Every assertion reads a wire-visible fact only -- a raw response status byte,
/// <see cref="CtapCommandException.StatusCode"/>, a decoded <c>authenticatorCredentialManagement</c>/
/// <c>authenticatorGetInfo</c> response, or an independently recomputed SHA-256 digest -- never internal
/// simulator state. Every <c>pinUvAuthParam</c> is computed with the real
/// <see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/> over wire-received bytes, via
/// <see cref="CtapWaveCmFixtures"/>'s R4 message-assembly helpers.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorCredentialManagementFlowTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The plaintext PIN both capstones establish, matching this profile's default 4-code-point minimum.</summary>
    private const string Pin = "1234";

    /// <summary>The single PIN/UV auth protocol both capstones drive.</summary>
    private static CtapPinUvAuthProtocolId ProtocolId => CtapPinUvAuthProtocolId.Two;


    /// <summary>
    /// Capstone A: the full <c>authenticatorCredentialManagement</c> lifecycle over the real APDU
    /// transport -- register three discoverable credentials across two RPs, observe
    /// <c>remainingDiscoverableCredentials</c> drop on the wire, walk both the RP and per-RP credential
    /// enumerations with an independently verified <c>rpIDHash</c>, delete one credential and observe its
    /// downstream <c>authenticatorGetAssertion</c> effect, then rename the survivor via
    /// <c>updateUserInformation</c> and observe the rename through re-enumeration.
    /// </summary>
    [TestMethod]
    public async Task FullManagementLifecycleOverRealApduTransport()
    {
        const string RpA = "wavecm-capstone-a-rpa.example";
        const string RpB = "wavecm-capstone-a-rpb.example";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("wavecm-capstone-a");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        await EstablishPinAsync(harness, pool, cancellationToken).ConfigureAwait(false);

        CtapGetInfoResponse infoBeforeRegistration = await GetInfoAsync(harness, pool, cancellationToken).ConfigureAwait(false);
        int remainingBeforeRegistration = infoBeforeRegistration.RemainingDiscoverableCredentials!.Value;

        CtapWaveCmRegisteredCredential rpaUser1 = await RegisterResidentCredentialAsync(
            harness, pool, RpA, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xA0), cancellationToken).ConfigureAwait(false);
        CtapWaveCmRegisteredCredential rpaUser2 = await RegisterResidentCredentialAsync(
            harness, pool, RpA, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xA1), cancellationToken).ConfigureAwait(false);
        _ = await RegisterResidentCredentialAsync(harness, pool, RpB, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xB0), cancellationToken)
            .ConfigureAwait(false);

        CtapGetInfoResponse infoAfterRegistration = await GetInfoAsync(harness, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            remainingBeforeRegistration - 3, infoAfterRegistration.RemainingDiscoverableCredentials!.Value,
            "registering three discoverable credentials must drop remainingDiscoverableCredentials by exactly three, on the wire.");

        byte[] cmToken = await IssueCmTokenAsync(harness, pool, rpId: null, cancellationToken).ConfigureAwait(false);

        CtapCredentialManagementResponse metadataAfterRegistration = (await AssertGatedCmStatusAsync(
            harness, pool, cmToken, WellKnownCtapCredentialManagementSubCommands.GetCredsMetadata, null, null, null,
            WellKnownCtapStatusCodes.Ok, cancellationToken).ConfigureAwait(false))!;
        Assert.AreEqual(3, metadataAfterRegistration.ExistingResidentCredentialsCount, "three discoverable credentials must be reported after registration.");
        Assert.AreEqual(remainingBeforeRegistration - 3, metadataAfterRegistration.MaxPossibleRemainingResidentCredentialsCount);

        CtapCredentialManagementResponse rpsBegin = (await AssertGatedCmStatusAsync(
            harness, pool, cmToken, WellKnownCtapCredentialManagementSubCommands.EnumerateRpsBegin, null, null, null,
            WellKnownCtapStatusCodes.Ok, cancellationToken).ConfigureAwait(false))!;
        Assert.AreEqual(2, rpsBegin.TotalRps, "two distinct RPs must hold discoverable credentials.");
        string firstRpId = rpsBegin.Rp!.Id;
        AssertRpIdHashMatches(firstRpId, rpsBegin.RpIdHash!.Value);

        var rpsGetNextRequest = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateRpsGetNextRp);
        (byte rpsNextStatus, CtapCredentialManagementResponse? rpsNext) = await SendCredentialManagementAsync(harness.Transceive, rpsGetNextRequest, pool, cancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, rpsNextStatus);
        string secondRpId = rpsNext!.Rp!.Id;
        AssertRpIdHashMatches(secondRpId, rpsNext.RpIdHash!.Value);

        Assert.IsTrue(
            new HashSet<string>(StringComparer.Ordinal) { firstRpId, secondRpId }.SetEquals([RpA, RpB]),
            "the enumerateRPsBegin/GetNextRP walk must visit exactly rpA and rpB, in some order.");

        byte[] rpaHash = ComputeRpIdHash(RpA);
        CtapCredentialManagementResponse credsBegin = (await AssertGatedCmStatusAsync(
            harness, pool, cmToken, WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, rpaHash, null, null,
            WellKnownCtapStatusCodes.Ok, cancellationToken).ConfigureAwait(false))!;
        Assert.AreEqual(2, credsBegin.TotalCredentials, "rpA must report two discoverable credentials.");
        AssertUserIdMatches(rpaUser1, credsBegin.User!);
        Assert.IsTrue(rpaUser1.CredentialIdBytes.AsSpan().SequenceEqual(credsBegin.CredentialId!.Id.AsReadOnlySpan()));
        Assert.AreEqual(rpaUser1.PublicKey, credsBegin.PublicKey, "the enumerated publicKey must byte-round-trip the registered COSE key.");
        credsBegin.User!.Id.Dispose();
        credsBegin.CredentialId!.Id.Dispose();

        var credsGetNextRequest = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsGetNextCredential);
        (byte credsNextStatus, CtapCredentialManagementResponse? credsNext) = await SendCredentialManagementAsync(harness.Transceive, credsGetNextRequest, pool, cancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, credsNextStatus);
        Assert.IsNull(credsNext!.TotalCredentials, "enumerateCredentialsGetNextCredential must omit totalCredentials.");
        AssertUserIdMatches(rpaUser2, credsNext.User!);
        Assert.IsTrue(rpaUser2.CredentialIdBytes.AsSpan().SequenceEqual(credsNext.CredentialId!.Id.AsReadOnlySpan()));
        Assert.AreEqual(rpaUser2.PublicKey, credsNext.PublicKey);
        credsNext.User!.Id.Dispose();
        credsNext.CredentialId!.Id.Dispose();

        using(CredentialId deleteCarrier = CredentialId.Create(rpaUser1.CredentialIdBytes, pool))
        {
            var deleteDescriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = deleteCarrier };
            await AssertGatedCmStatusAsync(
                harness, pool, cmToken, WellKnownCtapCredentialManagementSubCommands.DeleteCredential, null, deleteDescriptor, null,
                WellKnownCtapStatusCodes.Ok, cancellationToken).ConfigureAwait(false);
        }

        using(CredentialId allowListId = CredentialId.Create(rpaUser1.CredentialIdBytes, pool))
        {
            CtapGetAssertionRequest gaRequest = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(
                pool, rpId: RpA, allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = allowListId }]);
            byte[] gaEnvelope = CtapWave2RequestEnvelopes.BuildGetAssertionEnvelope(gaRequest);
            CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(gaRequest);
            using PooledMemory gaResponse = await harness.Transceive(gaEnvelope, pool, cancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                WellKnownCtapStatusCodes.NoCredentials, gaResponse.AsReadOnlySpan()[0],
                "a ga allowList naming a cm-deleted credential must fail with NoCredentials, on the wire.");
        }

        CtapCredentialManagementResponse metadataAfterDelete = (await AssertGatedCmStatusAsync(
            harness, pool, cmToken, WellKnownCtapCredentialManagementSubCommands.GetCredsMetadata, null, null, null,
            WellKnownCtapStatusCodes.Ok, cancellationToken).ConfigureAwait(false))!;
        Assert.AreEqual(2, metadataAfterDelete.ExistingResidentCredentialsCount);
        Assert.AreEqual(remainingBeforeRegistration - 2, metadataAfterDelete.MaxPossibleRemainingResidentCredentialsCount);

        const string RenamedName = "wavecm-renamed-user";
        const string RenamedDisplayName = "Wavecm Renamed User";
        using(CredentialId renameCredentialCarrier = CredentialId.Create(rpaUser2.CredentialIdBytes, pool))
        using(UserHandle renameUserId = UserHandle.Create(rpaUser2.UserId, pool))
        {
            var renameDescriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = renameCredentialCarrier };
            var renameUser = new CtapPublicKeyCredentialUserEntity(renameUserId, RenamedName, RenamedDisplayName);
            await AssertGatedCmStatusAsync(
                harness, pool, cmToken, WellKnownCtapCredentialManagementSubCommands.UpdateUserInformation, null, renameDescriptor, renameUser,
                WellKnownCtapStatusCodes.Ok, cancellationToken).ConfigureAwait(false);
        }

        CtapCredentialManagementResponse credsAfterRename = (await AssertGatedCmStatusAsync(
            harness, pool, cmToken, WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, rpaHash, null, null,
            WellKnownCtapStatusCodes.Ok, cancellationToken).ConfigureAwait(false))!;
        Assert.AreEqual(1, credsAfterRename.TotalCredentials, "only rpaUser2 must remain for rpA after the deletion.");
        Assert.AreEqual(RenamedName, credsAfterRename.User!.Name);
        Assert.AreEqual(RenamedDisplayName, credsAfterRename.User.DisplayName);
        credsAfterRename.User!.Id.Dispose();
        credsAfterRename.CredentialId!.Id.Dispose();
    }


    /// <summary>
    /// Capstone B: the <c>cm</c> permission's Optional-RP-ID semantics (C1's inverted polarity, C2's
    /// unbound-or-matching conjunction) and the stateful enumeration sequences' discard rules, over the
    /// real APDU transport. A bound token rejects every C1 subcommand and the RP-mismatched C2 deletion
    /// while accepting the RP-matched one; an unbound token passes all three C1 subcommands; a live
    /// enumeration sequence is discarded by ANY intervening command -- <c>authenticatorGetInfo</c> and a
    /// fresh <c>pinUvAuthToken</c> issuance (itself an <c>authenticatorClientPIN</c> call) alike -- and a
    /// bare continuation with no prior Begin fails cold.
    /// </summary>
    [TestMethod]
    public async Task PermissionRpIdAndStatefulnessSemanticsOverRealApduTransport()
    {
        const string RpA = "wavecm-capstone-b-rpa.example";
        const string RpB = "wavecm-capstone-b-rpb.example";
        const string RpC = "wavecm-capstone-b-rpc.example";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("wavecm-capstone-b");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        var coldGetNextRequest = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateRpsGetNextRp);
        (byte coldStatus, _) = await SendCredentialManagementAsync(harness.Transceive, coldGetNextRequest, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            WellKnownCtapStatusCodes.NotAllowed, coldStatus, "a bare GetNext with no prior Begin, on a fresh authenticator, must fail with NotAllowed.");

        await EstablishPinAsync(harness, pool, cancellationToken).ConfigureAwait(false);

        CtapWaveCmRegisteredCredential credentialA = await RegisterResidentCredentialAsync(
            harness, pool, RpA, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xD0), cancellationToken).ConfigureAwait(false);
        CtapWaveCmRegisteredCredential credentialB = await RegisterResidentCredentialAsync(
            harness, pool, RpB, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xD1), cancellationToken).ConfigureAwait(false);
        _ = await RegisterResidentCredentialAsync(harness, pool, RpC, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xD2), cancellationToken).ConfigureAwait(false);
        _ = await RegisterResidentCredentialAsync(harness, pool, RpC, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xD3), cancellationToken).ConfigureAwait(false);
        _ = await RegisterResidentCredentialAsync(harness, pool, RpC, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xD4), cancellationToken).ConfigureAwait(false);

        byte[] rpaHash = ComputeRpIdHash(RpA);
        byte[] boundToken = await IssueCmTokenAsync(harness, pool, RpA, cancellationToken).ConfigureAwait(false);

        await AssertGatedCmStatusAsync(
            harness, pool, boundToken, WellKnownCtapCredentialManagementSubCommands.GetCredsMetadata, null, null, null,
            WellKnownCtapStatusCodes.PinAuthInvalid, cancellationToken).ConfigureAwait(false);
        await AssertGatedCmStatusAsync(
            harness, pool, boundToken, WellKnownCtapCredentialManagementSubCommands.EnumerateRpsBegin, null, null, null,
            WellKnownCtapStatusCodes.PinAuthInvalid, cancellationToken).ConfigureAwait(false);
        await AssertGatedCmStatusAsync(
            harness, pool, boundToken, WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, rpaHash, null, null,
            WellKnownCtapStatusCodes.PinAuthInvalid, cancellationToken).ConfigureAwait(false);

        using(CredentialId deleteACarrier = CredentialId.Create(credentialA.CredentialIdBytes, pool))
        {
            var deleteADescriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = deleteACarrier };
            await AssertGatedCmStatusAsync(
                harness, pool, boundToken, WellKnownCtapCredentialManagementSubCommands.DeleteCredential, null, deleteADescriptor, null,
                WellKnownCtapStatusCodes.Ok, cancellationToken).ConfigureAwait(false);
        }

        using(CredentialId deleteBCarrier = CredentialId.Create(credentialB.CredentialIdBytes, pool))
        {
            var deleteBDescriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = deleteBCarrier };
            await AssertGatedCmStatusAsync(
                harness, pool, boundToken, WellKnownCtapCredentialManagementSubCommands.DeleteCredential, null, deleteBDescriptor, null,
                WellKnownCtapStatusCodes.PinAuthInvalid, cancellationToken).ConfigureAwait(false);
        }

        byte[] unboundToken = await IssueCmTokenAsync(harness, pool, rpId: null, cancellationToken).ConfigureAwait(false);

        CtapCredentialManagementResponse metadataUnbound = (await AssertGatedCmStatusAsync(
            harness, pool, unboundToken, WellKnownCtapCredentialManagementSubCommands.GetCredsMetadata, null, null, null,
            WellKnownCtapStatusCodes.Ok, cancellationToken).ConfigureAwait(false))!;
        Assert.AreEqual(4, metadataUnbound.ExistingResidentCredentialsCount, "credentialB and the three rpC credentials must remain.");

        CtapCredentialManagementResponse rpsBeginUnbound = (await AssertGatedCmStatusAsync(
            harness, pool, unboundToken, WellKnownCtapCredentialManagementSubCommands.EnumerateRpsBegin, null, null, null,
            WellKnownCtapStatusCodes.Ok, cancellationToken).ConfigureAwait(false))!;
        Assert.AreEqual(2, rpsBeginUnbound.TotalRps, "rpB and rpC must remain after rpA's sole credential was deleted.");

        byte[] rpbHash = ComputeRpIdHash(RpB);
        CtapCredentialManagementResponse credsBeginUnbound = (await AssertGatedCmStatusAsync(
            harness, pool, unboundToken, WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, rpbHash, null, null,
            WellKnownCtapStatusCodes.Ok, cancellationToken).ConfigureAwait(false))!;
        Assert.AreEqual(1, credsBeginUnbound.TotalCredentials);
        credsBeginUnbound.User!.Id.Dispose();
        credsBeginUnbound.CredentialId!.Id.Dispose();

        byte[] rpcHash = ComputeRpIdHash(RpC);
        var getNextRequest = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsGetNextCredential);

        CtapCredentialManagementResponse credsBeginC = (await AssertGatedCmStatusAsync(
            harness, pool, unboundToken, WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, rpcHash, null, null,
            WellKnownCtapStatusCodes.Ok, cancellationToken).ConfigureAwait(false))!;
        Assert.AreEqual(3, credsBeginC.TotalCredentials, "rpC must report three discoverable credentials for the statefulness leg.");
        credsBeginC.User!.Id.Dispose();
        credsBeginC.CredentialId!.Id.Dispose();

        (byte firstNextStatus, CtapCredentialManagementResponse? firstNext) = await SendCredentialManagementAsync(harness.Transceive, getNextRequest, pool, cancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstNextStatus, "the first GetNext, immediately after Begin, must succeed.");
        firstNext!.User!.Id.Dispose();
        firstNext.CredentialId!.Id.Dispose();

        _ = await GetInfoAsync(harness, pool, cancellationToken).ConfigureAwait(false);

        (byte discardedByGetInfoStatus, _) = await SendCredentialManagementAsync(harness.Transceive, getNextRequest, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            WellKnownCtapStatusCodes.NotAllowed, discardedByGetInfoStatus,
            "an intervening authenticatorGetInfo must discard the remembered enumeration sequence, on the wire.");

        CtapCredentialManagementResponse credsBeginC2 = (await AssertGatedCmStatusAsync(
            harness, pool, unboundToken, WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, rpcHash, null, null,
            WellKnownCtapStatusCodes.Ok, cancellationToken).ConfigureAwait(false))!;
        credsBeginC2.User!.Id.Dispose();
        credsBeginC2.CredentialId!.Id.Dispose();

        _ = await IssueCmTokenAsync(harness, pool, rpId: null, cancellationToken).ConfigureAwait(false);

        (byte discardedByReissueStatus, _) = await SendCredentialManagementAsync(harness.Transceive, getNextRequest, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            WellKnownCtapStatusCodes.NotAllowed, discardedByReissueStatus,
            "issuing a fresh pinUvAuthToken via authenticatorClientPIN must discard the remembered enumeration sequence, on the wire.");
    }


    /// <summary>Sends an <c>authenticatorGetInfo</c> request over <paramref name="harness"/>'s real transport and decodes the response.</summary>
    private static async Task<CtapGetInfoResponse> GetInfoAsync(CtapWave2TransportHarness harness, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] request = [WellKnownCtapCommands.GetInfo];
        using PooledMemory response = await harness.Transceive(request, pool, cancellationToken).ConfigureAwait(false);

        return CtapGetInfoResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
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
    /// Issues an <c>mc|ga</c>-permissioned token via <see cref="IssueTokenAsync"/>, bound to
    /// <paramref name="rpId"/> -- mc/ga's own "Required" RP-ID column (unlike <c>cm</c>'s Optional one)
    /// makes <paramref name="rpId"/> a mandatory issuance parameter, not just a first-use binding; one
    /// registration's worth per issuance, since a successful <c>mc</c> strips the token's other
    /// permissions.
    /// </summary>
    private static Task<byte[]> IssueMcGaTokenAsync(CtapWave2TransportHarness harness, MemoryPool<byte> pool, string rpId, CancellationToken cancellationToken) =>
        IssueTokenAsync(harness, pool, WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga, rpId, cancellationToken);


    /// <summary>Issues a <c>cm</c>-permissioned token via <see cref="IssueTokenAsync"/>, bound to <paramref name="rpId"/> or unbound when <see langword="null"/>.</summary>
    private static Task<byte[]> IssueCmTokenAsync(CtapWave2TransportHarness harness, MemoryPool<byte> pool, string? rpId, CancellationToken cancellationToken) =>
        IssueTokenAsync(harness, pool, WellKnownCtapPinUvAuthTokenPermissions.Cm, rpId, cancellationToken);


    /// <summary>
    /// Registers one discoverable (<c>rk</c>) credential for <paramref name="userId"/> at
    /// <paramref name="rpId"/> over <paramref name="harness"/>'s real transport, driven by a fresh
    /// <c>mc|ga</c> token (a successful <c>mc</c> strips a token's other permissions, so a token is
    /// never reused across registrations).
    /// </summary>
    private static async Task<CtapWaveCmRegisteredCredential> RegisterResidentCredentialAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, string rpId, byte[] userId, CancellationToken cancellationToken)
    {
        byte[] token = await IssueMcGaTokenAsync(harness, pool, rpId, cancellationToken).ConfigureAwait(false);
        byte[] message = CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x10);
        byte[] param = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, ProtocolId, message, pool, cancellationToken).ConfigureAwait(false);

        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: rpId, userId: userId, options: new CtapCommandOptions(ResidentKey: true),
            pinUvAuthParam: param, pinUvAuthProtocol: (int)ProtocolId);
        CtapMakeCredentialResponse response = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(request);

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool);
        byte[] credentialIdBytes = authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();

        return new CtapWaveCmRegisteredCredential(rpId, userId, credentialIdBytes, authenticatorData.AttestedCredentialData.CredentialPublicKey);
    }


    /// <summary>
    /// Builds and sends one gated <c>authenticatorCredentialManagement</c> subcommand over
    /// <paramref name="harness"/>'s real transport, computing <c>pinUvAuthParam</c> platform-side over
    /// the R4 message shape, and asserts the returned status equals <paramref name="expectedStatus"/>.
    /// </summary>
    /// <returns>The decoded response, or <see langword="null"/> when <paramref name="expectedStatus"/> is not <see cref="WellKnownCtapStatusCodes.Ok"/>.</returns>
    private static async Task<CtapCredentialManagementResponse?> AssertGatedCmStatusAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, byte[] token, int subCommand,
        ReadOnlyMemory<byte>? rpIdHash, PublicKeyCredentialDescriptor? credentialId, CtapPublicKeyCredentialUserEntity? user,
        byte expectedStatus, CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> subCommandParams = (rpIdHash is null && credentialId is null && user is null)
            ? ReadOnlyMemory<byte>.Empty
            : CtapWaveCmFixtures.BuildSubCommandParams(rpIdHash, credentialId, user);
        byte[] message = CtapWaveCmFixtures.BuildMessage(subCommand, subCommandParams);
        byte[] param = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, ProtocolId, message, pool, cancellationToken).ConfigureAwait(false);

        var request = new CtapCredentialManagementRequest(
            SubCommand: subCommand, RpIdHash: rpIdHash, CredentialId: credentialId, User: user,
            PinUvAuthProtocol: (int)ProtocolId, PinUvAuthParam: param);

        (byte status, CtapCredentialManagementResponse? response) = await SendCredentialManagementAsync(harness.Transceive, request, pool, cancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(expectedStatus, status, $"authenticatorCredentialManagement subCommand 0x{subCommand:X2} returned an unexpected status.");

        return response;
    }


    /// <summary>
    /// Encodes, sends, and decodes one <c>authenticatorCredentialManagement</c> request over
    /// <paramref name="transceive"/>, returning both the raw status byte and (when it is
    /// <see cref="WellKnownCtapStatusCodes.Ok"/> and the response carries a body) the decoded response.
    /// </summary>
    private static async Task<(byte StatusCode, CtapCredentialManagementResponse? Response)> SendCredentialManagementAsync(
        Ctap2TransceiveDelegate transceive, CtapCredentialManagementRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] envelope = CtapWaveCmFixtures.BuildCredentialManagementEnvelope(request);
        using PooledMemory response = await transceive(envelope, pool, cancellationToken).ConfigureAwait(false);
        byte statusCode = response.AsReadOnlySpan()[0];
        if(!WellKnownCtapStatusCodes.IsOk(statusCode))
        {
            return (statusCode, null);
        }

        ReadOnlyMemory<byte> body = response.AsReadOnlyMemory()[1..];

        return (statusCode, body.Length > 0 ? CtapCredentialManagementResponseCborReader.Read(body, pool) : null);
    }


    /// <summary>Independently computes <paramref name="rpId"/>'s SHA-256 digest -- an oracle wholly separate from the authenticator's own <c>ComputeRpIdHash</c> seam.</summary>
    private static byte[] ComputeRpIdHash(string rpId) => SHA256.HashData(Encoding.UTF8.GetBytes(rpId));


    /// <summary>Asserts that <paramref name="rpIdHash"/> equals the independently computed SHA-256 digest of <paramref name="rpId"/>.</summary>
    private static void AssertRpIdHashMatches(string rpId, ReadOnlyMemory<byte> rpIdHash)
    {
        byte[] expected = ComputeRpIdHash(rpId);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(rpIdHash.Span), $"the rpIDHash reported for '{rpId}' must equal an independently computed SHA-256 digest.");
    }


    /// <summary>Asserts that <paramref name="actual"/>'s user id bytes match <paramref name="expected"/>'s registration-time user handle.</summary>
    private static void AssertUserIdMatches(CtapWaveCmRegisteredCredential expected, CtapPublicKeyCredentialUserEntity actual)
    {
        Assert.IsTrue(
            expected.UserId.AsSpan().SequenceEqual(actual.Id.AsReadOnlySpan()),
            "the enumerated user id must match the credential's registration-time user handle.");
    }


    /// <summary>
    /// A discoverable credential registered by <see cref="RegisterResidentCredentialAsync"/>, carrying
    /// everything a later credential-management assertion needs to independently verify enumeration,
    /// deletion, and rename results.
    /// </summary>
    /// <param name="RpId">The relying party identifier the credential was registered under.</param>
    /// <param name="UserId">The plaintext user handle bytes the credential was registered with.</param>
    /// <param name="CredentialIdBytes">The minted credential identifier's raw bytes.</param>
    /// <param name="PublicKey">The minted credential's public key, parsed from the registration response's <c>attestedCredentialData</c>.</param>
    private sealed record CtapWaveCmRegisteredCredential(string RpId, byte[] UserId, byte[] CredentialIdBytes, CoseKey PublicKey);
}
