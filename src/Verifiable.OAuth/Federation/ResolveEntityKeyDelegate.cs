using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Resolves the verification key for an Entity Statement against the
/// declared <c>jwks</c> of its issuer. The orchestrator calls this once
/// per chain link before invoking <see cref="Jws.VerifyAsync"/>; the
/// result is fed into
/// <see cref="TrustChainValidationContext.LinkSignaturesVerified"/>
/// indirectly via the verify call.
/// </summary>
/// <param name="statementToVerify">
/// The statement whose signature is about to be verified.
/// </param>
/// <param name="headerOfStatementToVerify">
/// The JWS protected header of <paramref name="statementToVerify"/>; the
/// resolver consults <c>kid</c> and <c>alg</c> from this header when
/// selecting among the candidate keys.
/// </param>
/// <param name="issuerStatement">
/// The statement whose <c>jwks</c> claim carries the candidate keys.
/// Equals <paramref name="statementToVerify"/> when the statement is
/// self-signed (an Entity Configuration); otherwise equals the next
/// higher position in the trust chain.
/// </param>
/// <param name="cancellationToken">
/// Token to monitor for cancellation requests.
/// </param>
/// <returns>
/// The resolved <see cref="PublicKeyMemory"/> the caller owns and must
/// dispose, or <see langword="null"/> when no candidate key matched the
/// header.
/// </returns>
/// <remarks>
/// Implementations MUST NOT verify the signature themselves — the
/// signature verify call (via <see cref="Jws.VerifyAsync"/>) lives in the
/// orchestrator and consumes the returned key. Splitting key resolution
/// from verification keeps deployment-overridable policy (kid matching,
/// algorithm hinting, key set caching) separate from the cryptographic
/// primitive.
/// </remarks>
public delegate ValueTask<PublicKeyMemory?> ResolveEntityKeyDelegate(
    EntityStatement statementToVerify,
    UnverifiedJwtHeader headerOfStatementToVerify,
    EntityStatement issuerStatement,
    CancellationToken cancellationToken);
