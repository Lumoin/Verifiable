using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.OAuth;

/// <summary>
/// <see cref="ClaimContext"/> subtype carrying a single contributed
/// claim as a (claim-name, claim-value) pair. Each <see cref="Claim"/>
/// emitted by an OAuth claim-contribution rule carries an instance of
/// this type as its <see cref="Claim.Context"/>; walking sites read
/// <see cref="ClaimName"/> and <see cref="ClaimValue"/> from
/// <see cref="ClaimOutcome.Success"/>-status claims to merge the
/// contribution into the response payload.
/// </summary>
/// <param name="ClaimName">
/// The wire-format JWT claim name (e.g. <c>"email"</c>, <c>"acr"</c>) the
/// contribution applies to. One of <see cref="WellKnownJwtClaimNames"/>.
/// </param>
/// <param name="ClaimValue">
/// The claim value to emit. String, number, boolean, array, or nested
/// object — whatever the JWT serializer accepts for that claim shape.
/// </param>
[DebuggerDisplay("ClaimContributionContext Name={ClaimName,nq}")]
public sealed record ClaimContributionContext(string ClaimName, object ClaimValue): ClaimContext;
