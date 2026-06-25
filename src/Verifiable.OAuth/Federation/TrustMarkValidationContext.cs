using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Input to <see cref="TrustMarkValidator"/> and the trust-mark-shaped
/// checks on <see cref="FederationValidationChecks"/>. Carries the parsed
/// header / mark plus pre-computed signature outcome and time-of-evaluation
/// snapshot so individual check methods stay synchronous and side-effect-
/// free.
/// </summary>
/// <remarks>
/// Mirrors <see cref="EntityStatementValidationContext"/> in shape. Async
/// work (key resolution + JWS signature verification) is performed by the
/// orchestrator before the claim chain runs; the validator surfaces the
/// pre-computed outcome via <see cref="SignatureVerified"/>.
/// </remarks>
[DebuggerDisplay("TrustMarkValidationContext Iss={Mark.Issuer,nq} Sub={Mark.Subject,nq} SigOk={SignatureVerified}")]
public sealed record TrustMarkValidationContext
{
    /// <summary>The JWS protected header of the trust mark.</summary>
    public required UnverifiedJwtHeader Header { get; init; }

    /// <summary>The structurally classified trust mark from the parser.</summary>
    public required TrustMark Mark { get; init; }

    /// <summary>
    /// Outcome of the JWS signature verification step performed before the
    /// claim chain runs. <see langword="true"/> when the signature
    /// verified against the issuer's resolved key.
    /// </summary>
    public required bool SignatureVerified { get; init; }

    /// <summary>
    /// The instant against which <c>exp</c> is compared, from the
    /// validator's injected <see cref="TimeProvider"/>.
    /// </summary>
    public required DateTimeOffset Now { get; init; }

    /// <summary>Maximum acceptable clock skew for the <c>exp</c> check.</summary>
    public required TimeSpan ClockSkew { get; init; }
}
