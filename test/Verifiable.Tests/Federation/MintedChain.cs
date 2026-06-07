using Verifiable.JCose;
using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Output of <see cref="FederationTestRing.BuildDirectChainAsync"/> — the
/// parsed <see cref="TrustChain"/>, the parallel list of compact JWS
/// strings (positionally aligned with
/// <see cref="TrustChain.Statements"/>), and the parallel list of
/// unverified headers.
/// </summary>
internal sealed record MintedChain(
    TrustChain Chain,
    IReadOnlyList<string> CompactJwsByPosition,
    IReadOnlyList<UnverifiedJwtHeader> HeadersByPosition);
