using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Input to <see cref="EntityStatementValidator"/> and the
/// <see cref="ClaimDelegateAsync{TInput}"/>-shaped checks on
/// <see cref="FederationValidationChecks"/>. Carries the parsed header /
/// statement plus pre-computed signature outcome and time-of-evaluation
/// snapshot so individual check methods stay synchronous and side-effect-
/// free.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors the
/// <see cref="Verifiable.OAuth.Validation.ValidationContext"/> precedent:
/// async work that depends on policy hooks (key resolution + JWS signature
/// verification) is performed by the validator's orchestrator before the
/// claim chain runs, and the boolean outcome is fed into
/// <see cref="SignatureVerified"/>. Each
/// <see cref="FederationValidationChecks"/> method then reads what it needs
/// and emits its <see cref="Verifiable.Core.Assessment.Claim"/>.
/// </para>
/// <para>
/// "Unverified" in <see cref="EntityStatement.Payload"/> remains accurate
/// even after the validator runs: the payload itself is never replaced;
/// the validator stamps the verification result onto this context
/// alongside the statement.
/// </para>
/// </remarks>
[DebuggerDisplay("EntityStatementValidationContext Iss={Statement.Issuer,nq} SigOk={SignatureVerified}")]
public sealed record EntityStatementValidationContext
{
    /// <summary>The JWS protected header. Carries <c>typ</c>, <c>alg</c>, <c>kid</c>.</summary>
    public required UnverifiedJwtHeader Header { get; init; }

    /// <summary>The structurally classified statement (chunk 2 output).</summary>
    public required EntityStatement Statement { get; init; }

    /// <summary>
    /// Outcome of the JWS signature verification step performed by the
    /// validator before the claim chain runs. <see langword="true"/> when the
    /// signature verified against the key resolved for this statement.
    /// </summary>
    public required bool SignatureVerified { get; init; }

    /// <summary>
    /// The instant against which <c>iat</c> and <c>exp</c> are compared, from
    /// the validator's injected <see cref="TimeProvider"/>.
    /// </summary>
    public required DateTimeOffset Now { get; init; }

    /// <summary>
    /// Maximum acceptable clock skew for the <c>iat</c> / <c>exp</c> checks.
    /// Application code should pass
    /// <see cref="Verifiable.OAuth.Server.TimingPolicy.ClockSkewTolerance"/>
    /// for a single deployment-wide source of truth.
    /// </summary>
    public required TimeSpan ClockSkew { get; init; }
}
