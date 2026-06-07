namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// The semantic carrier for the <c>deviceSigned</c> slot in
/// <see cref="MdocDocument"/> per ISO/IEC 18013-5 §8.3.2.1.2.3 — graduates
/// <c>EncodedDeviceSigned: ReadOnlyMemory&lt;byte&gt;?</c> to a typed view
/// per the project's semantic-types-over-raw-bytes direction.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="NameSpaces"/> is the device's own claim assertions (often
/// empty). <see cref="DeviceAuth"/> carries either a COSE_Sign1
/// (<see cref="MdocDeviceSignature"/>) or a COSE_Mac0
/// (<see cref="MdocDeviceMac"/>) over the <c>DeviceAuthentication</c>
/// structure that binds this presentation to the session.
/// </para>
/// <para>
/// <see cref="EncodedDeviceNameSpacesBytes"/> is the original Tag 24
/// wrapper around the <c>DeviceNameSpaces</c> map — the byte form the
/// <c>DeviceAuthentication</c> array commits to as its
/// <c>DeviceNameSpacesBytes</c> field. Preserving the original bytes
/// matters for the same reason it matters for <c>IssuerSignedItem</c>: the
/// signature commitment hashes them, and re-encoding could shift bytes.
/// </para>
/// </remarks>
public sealed class MdocDeviceSigned: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a <c>DeviceSigned</c> from caller-supplied parts.
    /// Ownership of <paramref name="deviceAuth"/> transfers to the new
    /// instance; disposing cascades to release the COSE wire-bytes
    /// carrier inside.
    /// </summary>
    /// <param name="nameSpaces">The parsed <c>DeviceNameSpaces</c>.</param>
    /// <param name="encodedDeviceNameSpacesBytes">
    /// The Tag-24-wrapped wire form of <paramref name="nameSpaces"/> the
    /// device side authored. Reused as the <c>DeviceNameSpacesBytes</c>
    /// field of the <c>DeviceAuthentication</c> array during signature
    /// verification.
    /// </param>
    /// <param name="deviceAuth">The COSE_Sign1 or COSE_Mac0 over <c>DeviceAuthentication</c>.</param>
    public MdocDeviceSigned(
        MdocDeviceNameSpaces nameSpaces,
        ReadOnlyMemory<byte> encodedDeviceNameSpacesBytes,
        MdocDeviceAuth deviceAuth)
    {
        ArgumentNullException.ThrowIfNull(nameSpaces);
        ArgumentNullException.ThrowIfNull(deviceAuth);

        NameSpaces = nameSpaces;
        EncodedDeviceNameSpacesBytes = encodedDeviceNameSpacesBytes;
        DeviceAuth = deviceAuth;
    }


    /// <summary>The device-side claim assertions (often empty).</summary>
    public MdocDeviceNameSpaces NameSpaces { get; }

    /// <summary>
    /// The original Tag-24-wrapped wire bytes for the
    /// <c>DeviceNameSpaces</c> map. Verifier reconstructs the
    /// <c>DeviceAuthenticationBytes</c> using exactly these bytes; the
    /// device signature was computed over the same bytes the issuer
    /// originally emitted.
    /// </summary>
    public ReadOnlyMemory<byte> EncodedDeviceNameSpacesBytes { get; }

    /// <summary>The COSE_Sign1 or COSE_Mac0 over <c>DeviceAuthentication</c>.</summary>
    public MdocDeviceAuth DeviceAuth { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        DeviceAuth.Dispose();
        disposed = true;
    }
}
