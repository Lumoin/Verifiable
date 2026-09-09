using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// ECC public point (TPMS_ECC_POINT).
/// </summary>
/// <remarks>
/// <para>
/// This structure contains the X and Y coordinates of an ECC public key point.
/// For key creation templates, both coordinates can be empty (the TPM generates them).
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM2B_ECC_PARAMETER x;                   // X coordinate.
///     TPM2B_ECC_PARAMETER y;                   // Y coordinate.
/// } TPMS_ECC_POINT;
/// </code>
/// <para>
/// Each coordinate is a TPM2B with a 2-byte size prefix followed by the coordinate bytes.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 11.2.5.2.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmsEccPoint: IDisposable
{
    private static TpmsEccPoint EmptyInstance { get; } = new(Tpm2bEccParameter.Empty, Tpm2bEccParameter.Empty);

    private bool disposed;

    /// <summary>
    /// Initializes a new ECC point with the specified coordinates.
    /// </summary>
    /// <param name="x">The X coordinate.</param>
    /// <param name="y">The Y coordinate.</param>
    private TpmsEccPoint(Tpm2bEccParameter x, Tpm2bEccParameter y)
    {
        X = x;
        Y = y;
    }

    /// <summary>
    /// Gets an empty ECC point (for templates).
    /// </summary>
    public static TpmsEccPoint Empty => EmptyInstance;

    /// <summary>
    /// Gets the X coordinate.
    /// </summary>
    public Tpm2bEccParameter X { get; }

    /// <summary>
    /// Gets the Y coordinate.
    /// </summary>
    public Tpm2bEccParameter Y { get; }

    /// <summary>
    /// Gets whether this point is empty (both coordinates zero-length).
    /// </summary>
    public bool IsEmpty => X.IsEmpty && Y.IsEmpty;

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return X.SerializedSize + Y.SerializedSize;
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        X.WriteTo(ref writer);
        Y.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses an ECC point from a TPM reader. The X coordinate's rental is disposed and the exception rethrown
    /// if the Y coordinate's parse then throws (a truncated or over-long Y), so a refused frame never orphans
    /// the already-rented X.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed ECC point.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the parsed x and y coordinates transfers to the returned TpmsEccPoint, or to the shared Empty singleton when both are empty; the dispose-on-throw guard around y's parse releases x if y's parse fails, so no path loses the rental.")]
    public static TpmsEccPoint Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        Tpm2bEccParameter x = Tpm2bEccParameter.Parse(ref reader, pool);
        Tpm2bEccParameter y;
        try
        {
            y = Tpm2bEccParameter.Parse(ref reader, pool);
        }
        catch
        {
            x.Dispose();
            throw;
        }

        if(x.IsEmpty && y.IsEmpty)
        {
            return Empty;
        }

        return new TpmsEccPoint(x, y);
    }

    /// <summary>
    /// Creates an ECC point from the specified coordinates. The X rental is disposed and the exception rethrown
    /// if the Y coordinate's creation then throws (Y wider than <see cref="Tpm2bEccParameter"/>'s maximum), so a
    /// caller error on Y never orphans the already-rented X.
    /// </summary>
    /// <param name="x">The X coordinate bytes.</param>
    /// <param name="y">The Y coordinate bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created ECC point.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the created xParam and yParam coordinates transfers to the returned TpmsEccPoint, or to the shared Empty singleton when both spans are empty; the dispose-on-throw guard around y's creation releases xParam if y's creation fails, so no path loses the rental.")]
    public static TpmsEccPoint Create(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, BaseMemoryPool pool)
    {
        if(x.IsEmpty && y.IsEmpty)
        {
            return Empty;
        }

        Tpm2bEccParameter xParam = Tpm2bEccParameter.Create(x, pool);
        Tpm2bEccParameter yParam;
        try
        {
            yParam = Tpm2bEccParameter.Create(y, pool);
        }
        catch
        {
            xParam.Dispose();
            throw;
        }

        return new TpmsEccPoint(xParam, yParam);
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed && this != EmptyInstance)
        {
            X.Dispose();
            Y.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay
    {
        get
        {
            if(IsEmpty)
            {
                return "TPMS_ECC_POINT(empty)";
            }

            return $"TPMS_ECC_POINT(x={X.Length}, y={Y.Length})";
        }
    }
}