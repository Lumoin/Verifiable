using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_ECDH_ZGen command.
/// </summary>
/// <remarks>
/// <para>
/// Contains the output EC point Z = privateKey * inPoint, framed as a TPM2B_ECC_POINT (TPM 2.0 Library Part 2,
/// clause 11.2.5.3, Table 199) through <see cref="Tpm2bEccPoint"/>.
/// </para>
/// <para>
/// Response structure (TPM 2.0 Library Part 3, clause 14.5):
/// </para>
/// <list type="bullet">
///   <item><description>outPoint (TPM2B_ECC_POINT): the output point, two TPM2B_ECC_PARAMETER coordinates (x, y) wrapped in the outer sized parameter.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class EcdhZGenResponse: IDisposable, ITpmWireType
{
    private bool Disposed { get; set; }

    /// <summary>The framed <c>outPoint</c> (TPM2B_ECC_POINT) this response carries.</summary>
    private Tpm2bEccPoint OutPoint { get; }

    /// <summary>
    /// Gets the x coordinate of the output point — a BORROWED view over the <see cref="Tpm2bEccPoint"/> this
    /// response owns; never dispose it directly, <see cref="Dispose"/> releases both coordinates.
    /// </summary>
    public Tpm2bEccParameter OutPointX => OutPoint.Point.X;

    /// <summary>
    /// Gets the y coordinate of the output point — a BORROWED view over the <see cref="Tpm2bEccPoint"/> this
    /// response owns; never dispose it directly, <see cref="Dispose"/> releases both coordinates.
    /// </summary>
    public Tpm2bEccParameter OutPointY => OutPoint.Point.Y;

    /// <summary>
    /// Initializes the response over the parsed <c>outPoint</c>, whose ownership (the two coordinate rentals)
    /// transfers to this instance and is released by <see cref="Dispose"/>.
    /// </summary>
    /// <param name="outPoint">The framed output point; ownership transfers to the response.</param>
    private EcdhZGenResponse(Tpm2bEccPoint outPoint)
    {
        OutPoint = outPoint;
    }

    /// <summary>
    /// Parses an EcdhZGen response from a TPM reader through <see cref="Tpm2bEccPoint.Parse"/>, which refuses a
    /// zero outer size and cross-checks the declared size against the octets the inner <c>TPMS_ECC_POINT</c>
    /// actually consumed (Part 4's <c>TPM2B_ECC_POINT_Unmarshal</c> consistency check).
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for coordinate buffer allocation.</param>
    /// <returns>The parsed response.</returns>
    public static EcdhZGenResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return new EcdhZGenResponse(Tpm2bEccPoint.Parse(ref reader, pool));
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            OutPoint.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay =>
        $"EcdhZGenResponse(X={OutPointX.Length} bytes, Y={OutPointY.Length} bytes)";
}
