using JCoseEncodedCoseMac0 = Verifiable.JCose.EncodedCoseMac0;
using JCoseEncodedCoseSign1 = Verifiable.JCose.EncodedCoseSign1;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// The <c>DeviceAuth</c> structure per ISO/IEC 18013-5 §9.1.3.4 — a CBOR
/// map carrying exactly one of <see cref="DeviceSignature"/> (a COSE_Sign1
/// over the <c>DeviceAuthentication</c> structure) or
/// <see cref="DeviceMac"/> (a COSE_Mac0 derived via ECDH between the
/// device key and the reader's ephemeral key).
/// </summary>
/// <remarks>
/// <para>
/// The two paths are mutually exclusive — the spec wire shape forbids both
/// keys appearing in the same map. The data model represents that with two
/// nullable slots and a constructor that enforces "exactly one." Callers
/// pick the path based on the session binding the transport supplies: HTTP-
/// shaped flows (OID4VP) typically use the signature path; proximity flows
/// with an established reader key can use the MAC path for performance.
/// </para>
/// <para>
/// Disposal cascades into whichever of <see cref="DeviceSignature"/> /
/// <see cref="DeviceMac"/> is populated, releasing the pool-routed wire
/// bytes carried inside.
/// </para>
/// </remarks>
public sealed class MdocDeviceAuth: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a <c>DeviceAuth</c> with a signature. Mutually exclusive
    /// with the MAC path. Ownership of <paramref name="signature"/>
    /// transfers to the new instance.
    /// </summary>
    public MdocDeviceAuth(MdocDeviceSignature signature)
    {
        ArgumentNullException.ThrowIfNull(signature);

        DeviceSignature = signature;
    }


    /// <summary>
    /// Initializes a <c>DeviceAuth</c> with a MAC. Mutually exclusive with
    /// the signature path. Ownership of <paramref name="mac"/> transfers
    /// to the new instance.
    /// </summary>
    public MdocDeviceAuth(MdocDeviceMac mac)
    {
        ArgumentNullException.ThrowIfNull(mac);

        DeviceMac = mac;
    }


    /// <summary>
    /// The COSE_Sign1-carrier when this <c>DeviceAuth</c> uses the
    /// signature path; <see langword="null"/> when it uses the MAC path.
    /// </summary>
    public MdocDeviceSignature? DeviceSignature { get; }

    /// <summary>
    /// The COSE_Mac0-carrier when this <c>DeviceAuth</c> uses the MAC path;
    /// <see langword="null"/> when it uses the signature path.
    /// </summary>
    public MdocDeviceMac? DeviceMac { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        DeviceSignature?.Dispose();
        DeviceMac?.Dispose();
        disposed = true;
    }
}


/// <summary>
/// Semantic carrier for the <c>deviceSignature</c> slot — a COSE_Sign1
/// over the <c>DeviceAuthentication</c> structure per RFC 9052.
/// </summary>
/// <remarks>
/// <para>
/// COSE_Sign1's payload field is <c>nil</c> on the wire (the
/// <c>DeviceAuthentication</c> bytes are not transmitted — the verifier
/// reconstructs them from the session-transcript context plus the
/// <c>DeviceNameSpacesBytes</c> already in <see cref="MdocDeviceSigned"/>).
/// The <c>Sig_structure</c> the signature is over is built per
/// RFC 9052 §4.4 with the reconstructed <c>DeviceAuthenticationBytes</c>
/// as the payload field.
/// </para>
/// <para>
/// Owns <see cref="EncodedCoseSign1"/>; disposing releases the pool memory.
/// </para>
/// </remarks>
public sealed class MdocDeviceSignature: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a <c>DeviceSignature</c> from the pool-routed COSE_Sign1
    /// wire-bytes carrier. Ownership transfers to the new instance.
    /// </summary>
    public MdocDeviceSignature(JCoseEncodedCoseSign1 encodedCoseSign1)
    {
        ArgumentNullException.ThrowIfNull(encodedCoseSign1);

        EncodedCoseSign1 = encodedCoseSign1;
    }


    /// <summary>
    /// The original COSE_Sign1 wire-bytes carrier (Tag 18 included), with
    /// a nil payload field. Pool-routed, CBOM-tagged; owned by this
    /// <see cref="MdocDeviceSignature"/>.
    /// </summary>
    public JCoseEncodedCoseSign1 EncodedCoseSign1 { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        EncodedCoseSign1.Dispose();
        disposed = true;
    }
}


/// <summary>
/// Semantic carrier for the <c>deviceMac</c> slot — a COSE_Mac0 derived
/// via ECDH-based key agreement between the device key and a session-
/// established reader key.
/// </summary>
/// <remarks>
/// <para>
/// Models the MAC path so wire round-trips preserve it; the COSE_Mac0
/// signer/verifier lands when a transport binding (typically a proximity
/// flow with established reader ephemeral key) requires it. The OID4VP
/// flows the toy-wallet drives use the
/// <see cref="MdocDeviceSignature"/> path.
/// </para>
/// </remarks>
public sealed class MdocDeviceMac: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a <c>DeviceMac</c> from the pool-routed COSE_Mac0
    /// wire-bytes carrier. Ownership transfers to the new instance.
    /// </summary>
    public MdocDeviceMac(JCoseEncodedCoseMac0 encodedCoseMac0)
    {
        ArgumentNullException.ThrowIfNull(encodedCoseMac0);

        EncodedCoseMac0 = encodedCoseMac0;
    }


    /// <summary>
    /// The original COSE_Mac0 wire-bytes carrier (Tag 17 included).
    /// Pool-routed, CBOM-tagged; owned by this <see cref="MdocDeviceMac"/>.
    /// </summary>
    public JCoseEncodedCoseMac0 EncodedCoseMac0 { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        EncodedCoseMac0.Dispose();
        disposed = true;
    }
}
