using System.Diagnostics;
using System.Numerics;

namespace Verifiable.Cryptography.Secdsa;

/// <summary>
/// Represents a standard ECDSA signature as (r, s) scalars.
/// </summary>
/// <param name="R">The r component: x-coordinate of k*G reduced modulo q.</param>
/// <param name="S">The s component.</param>
[DebuggerDisplay("EcdsaSignature(R={R}, S={S})")]
public sealed record EcdsaSignature(BigInteger R, BigInteger S);
