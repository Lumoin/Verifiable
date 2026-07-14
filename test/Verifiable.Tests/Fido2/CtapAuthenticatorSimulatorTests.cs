using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Foundation.Automata;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapAuthenticatorSimulator"/>'s <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/>,
/// exercised directly (no APDU transport) with the shipped CBOR writer as the encode seam.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorSimulatorTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed 16-byte fill pattern, distinguishable byte-by-byte, standing in for the entropy provider.</summary>
    private static void FillFixedPattern(Span<byte> destination)
    {
        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)(0x20 + i);
        }
    }


    /// <summary>
    /// An <c>authenticatorGetInfo</c> request returns a CTAP2_OK status byte followed by a decodable
    /// response reporting FIDO_2_3, the simulator's own AAGUID, and <c>options.rk = true</c> (wave 2:
    /// this authenticator can create discoverable credentials).
    /// </summary>
    [TestMethod]
    public async Task GetInfoRequestReturnsOkStatusAndDecodableResponse()
    {
        using var simulator = new CtapAuthenticatorSimulator(
            "sim-1",
            CtapGetInfoResponseCborWriter.Write,
            CtapMakeCredentialRequestCborReader.Read,
            CtapMakeCredentialResponseCborWriter.Write,
            CtapGetAssertionRequestCborReader.Read,
            CtapGetAssertionResponseCborWriter.Write,
            CredentialPublicKeyCborWriter.Write,
            PackedAttestationStatementCborWriter.Write,
            CtapClientPinRequestCborReader.Read,
            CtapClientPinResponseCborWriter.Write,
            CtapAuthenticatorConfigRequestCborReader.Read,
            CtapCredentialManagementRequestCborReader.Read,
            CtapCredentialManagementResponseCborWriter.Write,
            CtapBioEnrollmentRequestCborReader.Read,
            CtapBioEnrollmentResponseCborWriter.Write,
            CtapLargeBlobsRequestCborReader.Read,
            CtapLargeBlobsResponseCborWriter.Write,
            CtapMakeCredentialExtensionOutputsCborWriter.Write,
            CtapGetAssertionExtensionOutputsCborWriter.Write,
            rng: FillFixedPattern);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //Independent oracle: computed from the same fixed fill pattern handed to the simulator,
        //not read back from the simulator's own state.
        Span<byte> expectedAaguidBytes = stackalloc byte[16];
        FillFixedPattern(expectedAaguidBytes);
        Guid expectedAaguid = new(expectedAaguidBytes, bigEndian: true);

        byte[] request = [WellKnownCtapCommands.GetInfo];
        using PooledMemory response = await simulator.TransceiveAsync(request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapGetInfoResponse decoded = CtapGetInfoResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        CollectionAssert.Contains(new List<string>(decoded.Versions), WellKnownCtapVersions.Fido23);
        Assert.AreEqual(expectedAaguid, decoded.Aaguid);
        Assert.IsNotNull(decoded.Options);
        Assert.IsTrue(decoded.Options!.ResidentKey);
    }


    /// <summary>An unrecognized command byte returns a bare CTAP1_ERR_INVALID_COMMAND status, no CBOR body.</summary>
    [TestMethod]
    public async Task UnrecognizedCommandReturnsInvalidCommandStatusWithNoBody()
    {
        using var simulator = new CtapAuthenticatorSimulator(
            "sim-2",
            CtapGetInfoResponseCborWriter.Write,
            CtapMakeCredentialRequestCborReader.Read,
            CtapMakeCredentialResponseCborWriter.Write,
            CtapGetAssertionRequestCborReader.Read,
            CtapGetAssertionResponseCborWriter.Write,
            CredentialPublicKeyCborWriter.Write,
            PackedAttestationStatementCborWriter.Write,
            CtapClientPinRequestCborReader.Read,
            CtapClientPinResponseCborWriter.Write,
            CtapAuthenticatorConfigRequestCborReader.Read,
            CtapCredentialManagementRequestCborReader.Read,
            CtapCredentialManagementResponseCborWriter.Write,
            CtapBioEnrollmentRequestCborReader.Read,
            CtapBioEnrollmentResponseCborWriter.Write,
            CtapLargeBlobsRequestCborReader.Read,
            CtapLargeBlobsResponseCborWriter.Write,
            CtapMakeCredentialExtensionOutputsCborWriter.Write,
            CtapGetAssertionExtensionOutputsCborWriter.Write);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //0xFE: unrecognized, unlike WellKnownCtapCommands.GetInfo (0x04) or any other registered command byte.
        byte[] request = [0xFE];
        using PooledMemory response = await simulator.TransceiveAsync(request, pool, TestContext.CancellationToken);

        Assert.AreEqual(1, response.Length);
        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidCommand, response.AsReadOnlySpan()[0]);
    }


    /// <summary>An empty request envelope (no command byte at all) is answered the same way as an unrecognized command.</summary>
    [TestMethod]
    public async Task EmptyRequestReturnsInvalidCommandStatus()
    {
        using var simulator = new CtapAuthenticatorSimulator(
            "sim-3",
            CtapGetInfoResponseCborWriter.Write,
            CtapMakeCredentialRequestCborReader.Read,
            CtapMakeCredentialResponseCborWriter.Write,
            CtapGetAssertionRequestCborReader.Read,
            CtapGetAssertionResponseCborWriter.Write,
            CredentialPublicKeyCborWriter.Write,
            PackedAttestationStatementCborWriter.Write,
            CtapClientPinRequestCborReader.Read,
            CtapClientPinResponseCborWriter.Write,
            CtapAuthenticatorConfigRequestCborReader.Read,
            CtapCredentialManagementRequestCborReader.Read,
            CtapCredentialManagementResponseCborWriter.Write,
            CtapBioEnrollmentRequestCborReader.Read,
            CtapBioEnrollmentResponseCborWriter.Write,
            CtapLargeBlobsRequestCborReader.Read,
            CtapLargeBlobsResponseCborWriter.Write,
            CtapMakeCredentialExtensionOutputsCborWriter.Write,
            CtapGetAssertionExtensionOutputsCborWriter.Write);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using PooledMemory response = await simulator.TransceiveAsync(ReadOnlyMemory<byte>.Empty, pool, TestContext.CancellationToken);

        Assert.AreEqual(1, response.Length);
        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidCommand, response.AsReadOnlySpan()[0]);
    }


    /// <summary>The AAGUID reported across repeated <c>authenticatorGetInfo</c> calls on the same instance never changes.</summary>
    [TestMethod]
    public async Task AaguidIsStableAcrossRepeatedCalls()
    {
        using var simulator = new CtapAuthenticatorSimulator(
            "sim-4",
            CtapGetInfoResponseCborWriter.Write,
            CtapMakeCredentialRequestCborReader.Read,
            CtapMakeCredentialResponseCborWriter.Write,
            CtapGetAssertionRequestCborReader.Read,
            CtapGetAssertionResponseCborWriter.Write,
            CredentialPublicKeyCborWriter.Write,
            PackedAttestationStatementCborWriter.Write,
            CtapClientPinRequestCborReader.Read,
            CtapClientPinResponseCborWriter.Write,
            CtapAuthenticatorConfigRequestCborReader.Read,
            CtapCredentialManagementRequestCborReader.Read,
            CtapCredentialManagementResponseCborWriter.Write,
            CtapBioEnrollmentRequestCborReader.Read,
            CtapBioEnrollmentResponseCborWriter.Write,
            CtapLargeBlobsRequestCborReader.Read,
            CtapLargeBlobsResponseCborWriter.Write,
            CtapMakeCredentialExtensionOutputsCborWriter.Write,
            CtapGetAssertionExtensionOutputsCborWriter.Write,
            rng: FillFixedPattern);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] request = [WellKnownCtapCommands.GetInfo];

        using PooledMemory first = await simulator.TransceiveAsync(request, pool, TestContext.CancellationToken);
        using PooledMemory second = await simulator.TransceiveAsync(request, pool, TestContext.CancellationToken);

        Guid firstAaguid = CtapGetInfoResponseCborReader.Read(first.AsReadOnlyMemory()[1..]).Aaguid;
        Guid secondAaguid = CtapGetInfoResponseCborReader.Read(second.AsReadOnlyMemory()[1..]).Aaguid;

        Assert.AreEqual(firstAaguid, secondAaguid);
        Assert.AreEqual(firstAaguid, simulator.Aaguid);
    }


    /// <summary>
    /// An <c>authenticatorMakeCredential</c> request naming a user associates that account's user name
    /// and display name with the stored credential record verbatim — CTAP 2.3 section 6.1, snapshot line
    /// 2924's "MAY also associate any or all of the user name, and user display name": the fixture's own
    /// "alice"/"Alice Example" defaults are already threaded through <see cref="CtapAuthenticatorState.CredentialsByCredentialId"/>
    /// by every mc test in this suite, but no prior test directly asserts the fidelity of that pass-through
    /// against the resulting <see cref="CtapCredentialRecord"/> until now.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialAssociatesUserNameAndDisplayNameWithTheStoredRecord()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-user-name-fidelity");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var trace = new TestObserver<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>>();
        byte[] credentialIdBytes;
        using(simulator.Subscribe(trace))
        {
            CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(pool);
            using PooledMemory response = await CtapWave2AuthenticatorFixtures.SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
            CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
            using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
            credentialIdBytes = authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        }

        string credentialIdHex = Convert.ToHexStringLower(credentialIdBytes);
        CtapCredentialRecord record = trace.Received[^1].StateAfter.CredentialsByCredentialId[credentialIdHex];

        Assert.AreEqual("alice", record.UserName);
        Assert.AreEqual("Alice Example", record.UserDisplayName);
    }
}
