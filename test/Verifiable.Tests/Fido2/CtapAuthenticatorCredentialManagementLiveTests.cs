using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;
using static Verifiable.Tests.TestInfrastructure.CtapWaveCmFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Cross-command <c>authenticatorCredentialManagement</c> store-effect tests: <c>deleteCredential</c>'s
/// downstream effect on <c>authenticatorGetAssertion</c> (no secondary index — the very next <c>ga</c>
/// observes the deletion through the ordinary path), and the R10 global-discard rule's cross-FAMILY
/// reach (a credMgmt <c>Begin</c> from the OTHER sequence discards a live sibling sequence, exactly as
/// mc/ga/getInfo/clientPin/config already do). Driven in-process through
/// <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/>, mirroring
/// <c>CtapAuthenticatorAlwaysUvLiveTests</c>'s role for the waveconfig wave.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorCredentialManagementLiveTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The plaintext PIN this file establishes, matching this profile's default 4-code-point minimum.</summary>
    private const string DefaultPin = "1234";


    /// <summary>
    /// <c>deleteCredential</c> has no secondary index to keep in sync: the very next
    /// <c>authenticatorGetAssertion</c> naming the just-deleted credential via <c>allowList</c> finds it
    /// gone and returns <c>CTAP2_ERR_NO_CREDENTIALS</c> through the ordinary locate-credentials path.
    /// </summary>
    [TestMethod]
    public async Task DeleteCredentialCausesSubsequentGetAssertionAllowListToReturnNoCredentials()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-live-delete-then-ga");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] credentialIdBytes = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xE0), TestContext.CancellationToken);

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Cm, rpId: null, TestContext.CancellationToken);

        using(CredentialId deleteId = CredentialId.Create(credentialIdBytes, pool))
        {
            var descriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = deleteId };
            byte[] subCommandParams = BuildSubCommandParams(credentialId: descriptor);
            byte[] message = BuildMessage(WellKnownCtapCredentialManagementSubCommands.DeleteCredential, subCommandParams);
            byte[] param = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, TestContext.CancellationToken);

            var deleteRequest = new CtapCredentialManagementRequest(
                SubCommand: WellKnownCtapCredentialManagementSubCommands.DeleteCredential,
                CredentialId: descriptor,
                PinUvAuthProtocol: (int)protocolId,
                PinUvAuthParam: param);
            using PooledMemory deleteResponse = await SendCredentialManagementAsync(simulator, deleteRequest, pool, TestContext.CancellationToken);
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, deleteResponse.AsReadOnlySpan()[0]);
        }

        using CredentialId allowListId = CredentialId.Create(credentialIdBytes, pool);
        CtapGetAssertionRequest gaRequest = BuildGetAssertionRequest(
            pool, allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = allowListId }]);
        using PooledMemory gaResponse = await SendGetAssertionAsync(simulator, gaRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, gaResponse.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// The R10 global-discard rule reaches ACROSS the two credMgmt enumeration families: beginning a
    /// fresh <c>enumerateCredentialsBegin</c> discards a live <c>enumerateRPsBegin</c> sequence, even
    /// though the credential store itself was not mutated — mirroring how <c>enumerateRPsGetNextRP</c>
    /// discards <c>RememberedEnumerateCredentials</c> and vice versa.
    /// </summary>
    [TestMethod]
    public async Task EnumerateCredentialsBeginDiscardsLiveRpEnumerationSequence()
    {
        const string rpId = "live-cross-family.example";
        using CtapAuthenticatorSimulator simulator = CreateSimulator("cm-live-cross-family", residentCredentialCapacity: 3);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xE1), TestContext.CancellationToken, rpId: rpId);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xE2), TestContext.CancellationToken, rpId: "second-cross-family.example");

        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Cm, rpId: null, TestContext.CancellationToken);

        byte[] rpsBeginMessage = BuildMessage(WellKnownCtapCredentialManagementSubCommands.EnumerateRpsBegin, ReadOnlyMemory<byte>.Empty);
        byte[] rpsBeginParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, rpsBeginMessage, pool, TestContext.CancellationToken);
        var rpsBeginRequest = new CtapCredentialManagementRequest(
            SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateRpsBegin, PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: rpsBeginParam);
        using(PooledMemory rpsBeginResponse = await SendCredentialManagementAsync(simulator, rpsBeginRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, rpsBeginResponse.AsReadOnlySpan()[0]);
        }

        byte[] rpIdHash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(rpId));
        byte[] credsSubCommandParams = BuildSubCommandParams(rpIdHash: rpIdHash);
        byte[] credsBeginMessage = BuildMessage(WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, credsSubCommandParams);
        byte[] credsBeginParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, credsBeginMessage, pool, TestContext.CancellationToken);
        var credsBeginRequest = new CtapCredentialManagementRequest(
            SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin,
            RpIdHash: rpIdHash,
            PinUvAuthProtocol: (int)protocolId,
            PinUvAuthParam: credsBeginParam);
        using(PooledMemory credsBeginResponse = await SendCredentialManagementAsync(simulator, credsBeginRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, credsBeginResponse.AsReadOnlySpan()[0]);
        }

        var rpsNextRequest = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateRpsGetNextRp);
        using PooledMemory rpsNextResponse = await SendCredentialManagementAsync(simulator, rpsNextRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(
            WellKnownCtapStatusCodes.NotAllowed, rpsNextResponse.AsReadOnlySpan()[0],
            "enumerateCredentialsBegin must discard the sibling enumerateRPsBegin sequence it did not itself initialize.");
    }
}
