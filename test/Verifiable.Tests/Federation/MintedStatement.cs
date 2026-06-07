using Verifiable.JCose;
using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Output of <see cref="FederationTestRing.MintEntityConfigurationAsync"/>
/// and <see cref="FederationTestRing.MintSubordinateStatementAsync"/> —
/// the parsed <see cref="EntityStatement"/>, the unverified header used
/// during signing (for feeding into
/// <see cref="EntityStatementValidationContext"/>), and the raw compact
/// JWS string the orchestrator's <see cref="Jws.VerifyAsync"/> call
/// consumes.
/// </summary>
internal sealed record MintedStatement(
    EntityStatement Statement,
    UnverifiedJwtHeader Header,
    string CompactJws);
