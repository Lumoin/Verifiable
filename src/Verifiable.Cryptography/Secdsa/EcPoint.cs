using System.Diagnostics;
using System.Numerics;

namespace Verifiable.Cryptography.Secdsa;

/// <summary>
/// Represents a point on an elliptic curve as affine (X, Y) coordinates.
/// </summary>
/// <param name="X">The x-coordinate.</param>
/// <param name="Y">The y-coordinate.</param>
[DebuggerDisplay("EcPoint(X={X}, Y={Y})")]
public sealed record EcPoint(BigInteger X, BigInteger Y)
{
    /// <summary>
    /// Gets the point at infinity (the group identity element).
    /// </summary>
    public static EcPoint Infinity { get; } = new EcPoint(BigInteger.Zero, BigInteger.Zero);

    /// <summary>
    /// Gets whether this point is the point at infinity.
    /// </summary>
    public bool IsInfinity => X.IsZero && Y.IsZero;
}
