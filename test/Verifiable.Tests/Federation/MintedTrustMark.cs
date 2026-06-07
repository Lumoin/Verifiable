using Verifiable.JCose;
using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Output of <see cref="FederationTestRing.MintTrustMarkAsync"/> — the
/// parsed <see cref="TrustMark"/>, the unverified header, and the raw
/// compact JWS.
/// </summary>
internal sealed record MintedTrustMark(
    TrustMark Mark,
    UnverifiedJwtHeader Header,
    string CompactJws);
