using Verifiable.JCose;
using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Output of <see cref="FederationTestRing.MintTrustMarkDelegationAsync"/>
/// — the parsed <see cref="TrustMarkDelegation"/>, the unverified header,
/// and the raw compact JWS.
/// </summary>
internal sealed record MintedTrustMarkDelegation(
    TrustMarkDelegation Delegation,
    UnverifiedJwtHeader Header,
    string CompactJws);
