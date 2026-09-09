using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_ECDH_ZGen command (CC = 0x00000154).
/// </summary>
/// <remarks>
/// <para>
/// Performs EC Diffie-Hellman point multiplication: outPoint = inPoint * privateKey.
/// The key referenced by <see cref="KeyHandle"/> must be an ECC key with the
/// <c>decrypt</c> attribute set and the ECDH scheme (TPM_ALG_ECDH).
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 14.5):
/// </para>
/// <list type="bullet">
///   <item><description>keyHandle (TPMI_DH_OBJECT): Handle of the ECC key. Requires authorization.</description></item>
///   <item><description>inPoint (TPM2B_ECC_POINT, TPM 2.0 Library Part 2, clause 11.2.5.3, Table 199): the input public key point, framed through <see cref="Tpm2bEccPoint"/>.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class EcdhZGenInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    /// <summary>The framed <c>inPoint</c> (TPM2B_ECC_POINT) this command carries.</summary>
    private Tpm2bEccPoint InPoint { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_ECDH_ZGen;

    /// <summary>
    /// Gets the handle of the ECC key.
    /// </summary>
    public TpmiDhObject KeyHandle { get; }

    /// <summary>
    /// Creates a TPM2_ECDH_ZGen input from separate x and y coordinate spans.
    /// </summary>
    /// <param name="keyHandle">The handle of the ECC key.</param>
    /// <param name="xCoord">The x coordinate of the input point.</param>
    /// <param name="yCoord">The y coordinate of the input point.</param>
    /// <param name="pool">The memory pool for coordinate buffer allocation.</param>
    /// <returns>A new <see cref="EcdhZGenInput"/>.</returns>
    public static EcdhZGenInput Create(
        TpmiDhObject keyHandle,
        ReadOnlySpan<byte> xCoord,
        ReadOnlySpan<byte> yCoord,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return new EcdhZGenInput(keyHandle, Tpm2bEccPoint.Create(xCoord, yCoord, pool));
    }


    /// <summary>
    /// Creates a TPM2_ECDH_ZGen input from an uncompressed EC point (0x04 || X || Y).
    /// </summary>
    /// <param name="keyHandle">The handle of the ECC key.</param>
    /// <param name="uncompressedPoint">The uncompressed point encoding.</param>
    /// <param name="pool">The memory pool for coordinate buffer allocation.</param>
    /// <returns>A new <see cref="EcdhZGenInput"/>.</returns>
    public static EcdhZGenInput FromUncompressedPoint(
        TpmiDhObject keyHandle,
        ReadOnlySpan<byte> uncompressedPoint,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return Create(
            keyHandle,
            EllipticCurveUtilities.SliceXCoordinate(uncompressedPoint),
            EllipticCurveUtilities.SliceYCoordinate(uncompressedPoint),
            pool);
    }


    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +       //keyHandle (TPMI_DH_OBJECT)
               InPoint.SerializedSize;   //TPM2B_ECC_POINT inPoint (outer size ‖ TPMS_ECC_POINT)
    }


    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        KeyHandle.WriteTo(ref writer);
    }


    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        InPoint.WriteTo(ref writer);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            InPoint.Dispose();
            Disposed = true;
        }
    }


    private EcdhZGenInput(TpmiDhObject keyHandle, Tpm2bEccPoint inPoint)
    {
        KeyHandle = keyHandle;
        InPoint = inPoint;
    }


    private string DebuggerDisplay => $"EcdhZGenInput(Key={KeyHandle}, X={InPoint.Point.X.Length} bytes, Y={InPoint.Point.Y.Length} bytes)";
}
