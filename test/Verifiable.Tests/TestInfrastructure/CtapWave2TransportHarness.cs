using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Ctap;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Composes the real, unmodified <see cref="ApduExecutor"/>/<see cref="ApduDevice"/> stack over a
/// <see cref="CtapAuthenticatorSimulator"/> through <see cref="CtapNfcResponder"/> and
/// <see cref="CtapNfcTransport"/> — the wave-1 transport composition
/// (<c>CtapAuthenticatorGetInfoFlowTests.RpClientDrivesSimulatorOverRealApduTransportAndDecodesGetInfo</c>)
/// factored once here so every wave-2 capstone test shares one composition site instead of
/// reimplementing it per test method.
/// </summary>
/// <remarks>
/// The transport needs zero changes for <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>:
/// <see cref="CtapNfcTransport.TransceiveAsync"/> already carries an arbitrary-length CBOR request body
/// verbatim, so this harness's only job is the wave-1 composition wiring plus the one-time
/// <c>SELECT</c> the FIDO applet needs before any CTAP2 command can be exchanged.
/// </remarks>
internal sealed class CtapWave2TransportHarness: IDisposable
{
    /// <summary>The NFC responder bridging the simulator's transceive method to the APDU device.</summary>
    private CtapNfcResponder Responder { get; }

    /// <summary>The real, unmodified APDU device the FIDO applet is selected on.</summary>
    private ApduDevice Device { get; }

    /// <summary>Guards against redundant disposal.</summary>
    private bool disposed;

    /// <summary>
    /// The transport-neutral CTAP2 request/response exchange, ready for a <see cref="CtapAuthenticatorGetInfoClient"/>,
    /// <see cref="CtapAuthenticatorMakeCredentialClient"/>, or <see cref="CtapAuthenticatorGetAssertionClient"/> call.
    /// </summary>
    public Ctap2TransceiveDelegate Transceive { get; }


    /// <summary>
    /// Initializes a harness already wired over <paramref name="responder"/>/<paramref name="device"/>.
    /// </summary>
    private CtapWave2TransportHarness(CtapNfcResponder responder, ApduDevice device, Ctap2TransceiveDelegate transceive)
    {
        Responder = responder;
        Device = device;
        Transceive = transceive;
    }


    /// <summary>
    /// Builds a harness for <paramref name="simulator"/>: creates the responder and device, selects the
    /// FIDO applet, and exposes the resulting <see cref="Ctap2TransceiveDelegate"/>.
    /// </summary>
    /// <param name="simulator">The authenticator simulator to drive over the real transport.</param>
    /// <param name="pool">The memory pool the <c>SELECT</c> exchange rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The composed harness. The caller owns it and must dispose it.</returns>
    public static async Task<CtapWave2TransportHarness> CreateAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        CtapNfcResponder responder = CtapNfcResponder.Create(simulator.TransceiveAsync);
        ApduDevice device = ApduDevice.Create(responder.TransceiveAsync);

        ApduResult<SelectResponse> selectResult = await device.SelectAsync(WellKnownAid.Fido, pool, cancellationToken).ConfigureAwait(false);
        selectResult.Value.Dispose();

        CtapNfcTransport transport = CtapNfcTransport.OverApdu(device);

        return new CtapWave2TransportHarness(responder, device, transport.TransceiveAsync);
    }


    /// <summary>
    /// Releases the underlying <see cref="ApduDevice"/> and <see cref="CtapNfcResponder"/>. Idempotent.
    /// </summary>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;

        Device.Dispose();
        Responder.Dispose();
    }
}
