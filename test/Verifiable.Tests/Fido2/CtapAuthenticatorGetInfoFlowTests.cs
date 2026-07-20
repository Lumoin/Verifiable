using System;
using System.Buffers;
using System.Collections;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Ctap;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wave's capstone firewalled flow test: the RP-side <see cref="CtapAuthenticatorGetInfoClient"/>
/// drives a <see cref="CtapAuthenticatorSimulator"/> over the real, unmodified
/// <see cref="ApduExecutor"/>/<see cref="ApduDevice"/> stack via <see cref="CtapNfcTransport"/> and
/// <see cref="CtapNfcResponder"/> — the two projects' own transport seam, with no shared type and no
/// glue assembly. This test <em>is</em> the composition site: both method-group conversions
/// (<c>transport.TransceiveAsync</c> to <see cref="Ctap2TransceiveDelegate"/>, and
/// <c>simulator.TransceiveAsync</c> to <see cref="CtapPayloadTransceiveDelegate"/>) happen here.
/// </summary>
/// <remarks>
/// Firewalled: the asserting side reconstructs the AAGUID from the same fixed entropy pattern it
/// handed the simulator at construction, independently of anything the simulator's own state exposes
/// — the assertion never reads <see cref="CtapAuthenticatorSimulator.Aaguid"/> back out of the
/// instance under test.
/// </remarks>
[TestClass]
internal sealed class CtapAuthenticatorGetInfoFlowTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed 16-byte fill pattern, independently reconstructible by the asserting side.</summary>
    private static void FillFixedAaguidPattern(Span<byte> destination)
    {
        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)(0xA0 + i);
        }
    }


    /// <summary>
    /// The RP client's <c>authenticatorGetInfo</c> call reaches the simulator over the real APDU
    /// transport: SELECT never carries FIDO_2_3, the decoded getInfo response does, and a response
    /// large enough to exceed a short-form frame's 256-byte ceiling proves the round trip genuinely
    /// used extended-length APDU framing rather than trivially fitting in a small buffer. TORN row
    /// 4620 (snapshot line 4620: <c>"FIDO_2_2"</c> MUST NOT be present in <c>versions</c>) closes here
    /// by an EXACT-ARRAY assertion on <see cref="CtapGetInfoResponse.Versions"/> — proving both that
    /// <c>FIDO_2_3</c> is present AND that nothing else, including a hypothetical <c>FIDO_2_2</c>, is.
    /// </summary>
    [TestMethod]
    public async Task RpClientDrivesSimulatorOverRealApduTransportAndDecodesGetInfo()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //A padded, but semantically legitimate, "supported extensions" personalization — this
        //simulator model advertises many extension identifiers, pushing the getInfo response past
        //256 bytes so the round trip cannot accidentally succeed via a short-form-sized coincidence.
        var supportedExtensions = new List<string>();
        for(int i = 0; i < 25; i++)
        {
            supportedExtensions.Add($"ext-identifier-{i:D3}");
        }

        using var simulator = new CtapAuthenticatorSimulator(
            "flow-test-authenticator",
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
            supportedExtensions: supportedExtensions,
            rng: FillFixedAaguidPattern);

        using CtapNfcResponder responder = CtapNfcResponder.Create(simulator.TransceiveAsync);
        using ApduDevice device = ApduDevice.Create(responder.TransceiveAsync);

        ApduResult<SelectResponse> selectResult = await device.SelectAsync(
            WellKnownAid.Fido, pool, TestContext.CancellationToken);
        Assert.IsTrue(selectResult.IsSuccess);
        using(SelectResponse selectResponse = selectResult.Value)
        {
            //CTAP 2.3 section 11.3.3: the NFC Select response is one of the legacy version strings
            //only — FIDO_2_3 appears solely inside authenticatorGetInfo, never here.
            Assert.IsLessThan(0, selectResponse.FileControlInformation.IndexOf("FIDO_2_3"u8));
        }

        CtapNfcTransport transport = CtapNfcTransport.OverApdu(device);
        Ctap2TransceiveDelegate transceive = transport.TransceiveAsync;

        CtapGetInfoResponse response = await CtapAuthenticatorGetInfoClient.GetInfoAsync(
            transceive, CtapGetInfoResponseCborReader.Read, pool, TestContext.CancellationToken);

        //Independent oracle: the expected AAGUID is derived here from the same fixed fill pattern
        //the simulator was constructed with, not read back from the simulator's own state.
        Span<byte> expectedAaguidBytes = stackalloc byte[16];
        FillFixedAaguidPattern(expectedAaguidBytes);
        Guid expectedAaguid = new(expectedAaguidBytes, bigEndian: true);

        Assert.AreEqual(expectedAaguid, response.Aaguid);
        Assert.AreSequenceEqual(new[] { WellKnownCtapVersions.Fido23 }, (ICollection)new List<string>(response.Versions));
        Assert.IsNotNull(response.Extensions);
        Assert.HasCount(supportedExtensions.Count, response.Extensions!);
        Assert.AreSequenceEqual(supportedExtensions, new List<string>(response.Extensions!));
        Assert.IsNotNull(response.Options);
        Assert.IsTrue(response.Options!.ResidentKey);

        //R5/R6/R7 over the real wire: maxCredentialCountInList (0x07) is always present and matches
        //the same fixed capacity mc/ga's own excludeList/allowList bound check enforces; algorithms
        //(0x0A) is OMITTED entirely since this simulator was constructed with no credentialSigningBackend
        //(a genuinely backendless authenticator, not merely an ES256-only one); firmwareVersion (0x0E)
        //reports the CtapAuthenticatorState.Initial seed default.
        Assert.AreEqual(CtapAuthenticatorState.MaxCredentialCountInListCapacity, response.MaxCredentialCountInList);
        Assert.IsNull(response.Algorithms);
        Assert.AreEqual(1, response.FirmwareVersion);
    }
}
