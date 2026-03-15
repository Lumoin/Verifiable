using System.Diagnostics;
using System.Numerics;

namespace Verifiable.Cryptography.Secdsa;

/// <summary>
/// Represents an ECDSA signature in full format (R point, s scalar) as used
/// in Algorithm 3 of the SECDSA specification.
/// </summary>
/// <remarks>
/// The full format stores the complete nonce point R rather than just its
/// x-coordinate r. This is required in Algorithm 3 for computing
/// G'' = s^(-1)*G' and Y'' = s^(-1)*Y' as part of the blinded instruction.
/// </remarks>
/// <param name="RPoint">The nonce point R = k*G.</param>
/// <param name="S">The s scalar.</param>
[DebuggerDisplay("FullEcdsaSignature(S={S})")]
public sealed record FullEcdsaSignature(EcPoint RPoint, BigInteger S);