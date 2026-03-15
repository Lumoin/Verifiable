using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_ECDH_ZGen command.
/// </summary>
/// <remarks>
/// <para>
/// Contains the output EC point Z = privateKey * inPoint as a TPMS_ECC_POINT.
/// </para>
/// <para>
/// Response structure (TPM 2.0 Part 3, Section 14.5):
/// </para>
/// <list type="bullet">
///   <item><description>outPoint (TPMS_ECC_POINT): The output point as two TPM2B_ECC_PARAMETER values (x, y).</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class EcdhZGenResponse: IDisposable, ITpmWireType
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the x coordinate of the output point.
    /// </summary>
    public Tpm2bEccParameter OutPointX { get; }

    /// <summary>
    /// Gets the y coordinate of the output point.
    /// </summary>
    public Tpm2bEccParameter OutPointY { get; }

    private EcdhZGenResponse(Tpm2bEccParameter outPointX, Tpm2bEccParameter outPointY)
    {
        OutPointX = outPointX;
        OutPointY = outPointY;
    }

    /// <summary>
    /// Parses an EcdhZGen response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for coordinate buffer allocation.</param>
    /// <returns>The parsed response.</returns>
    public static EcdhZGenResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        //outPoint is TPM2B_ECC_POINT: consume the outer size field before parsing the coordinates.
        _ = reader.ReadUInt16();
        Tpm2bEccParameter x = Tpm2bEccParameter.Parse(ref reader, pool);
        Tpm2bEccParameter y = Tpm2bEccParameter.Parse(ref reader, pool);
        return new EcdhZGenResponse(x, y);
    }

    /// <summary>
    /// Reconstructs the uncompressed point encoding
    /// (<see cref="EllipticCurveUtilities.UncompressedCoordinateFormat"/> || X || Y).
    /// </summary>
    /// <returns>The uncompressed point bytes.</returns>
    public byte[] ToUncompressedPoint()
    {
        ReadOnlySpan<byte> xSpan = OutPointX.AsReadOnlySpan();
        ReadOnlySpan<byte> ySpan = OutPointY.AsReadOnlySpan();

        byte[] result = new byte[1 + xSpan.Length + ySpan.Length];
        result[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
        xSpan.CopyTo(result.AsSpan(1));
        ySpan.CopyTo(result.AsSpan(1 + xSpan.Length));
        return result;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            OutPointX.Dispose();
            OutPointY.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay =>
        $"EcdhZGenResponse(X={OutPointX.Length} bytes, Y={OutPointY.Length} bytes)";
}
