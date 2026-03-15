using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

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
/// Command structure (TPM 2.0 Part 3, Section 14.5):
/// </para>
/// <list type="bullet">
///   <item><description>keyHandle (TPMI_DH_OBJECT): Handle of the ECC key. Requires authorization.</description></item>
///   <item><description>inPoint (TPM2B_ECC_POINT): The input public key point as a sized buffer containing two TPM2B_ECC_PARAMETER values (x, y).</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class EcdhZGenInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    private Tpm2bEccParameter X { get; }

    private Tpm2bEccParameter Y { get; }

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
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return new EcdhZGenInput(keyHandle, Tpm2bEccParameter.Create(xCoord, pool), Tpm2bEccParameter.Create(yCoord, pool));
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
        MemoryPool<byte> pool)
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
               sizeof(ushort) +     //TPM2B_ECC_POINT outer size field
               X.SerializedSize +   //TPM2B_ECC_PARAMETER x
               Y.SerializedSize;    //TPM2B_ECC_PARAMETER y
    }


    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        KeyHandle.WriteTo(ref writer);
    }


    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2B_ECC_POINT outer size: the total byte count of the TPMS_ECC_POINT that follows.
        writer.WriteUInt16((ushort)(X.SerializedSize + Y.SerializedSize));
        X.WriteTo(ref writer);
        Y.WriteTo(ref writer);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            X.Dispose();
            Y.Dispose();
            Disposed = true;
        }
    }


    private EcdhZGenInput(TpmiDhObject keyHandle, Tpm2bEccParameter x, Tpm2bEccParameter y)
    {
        KeyHandle = keyHandle;
        X = x;
        Y = y;
    }


    private string DebuggerDisplay => $"EcdhZGenInput(Key={KeyHandle}, X={X.Length} bytes, Y={Y.Length} bytes)";
}
