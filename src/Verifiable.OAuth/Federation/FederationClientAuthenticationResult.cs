using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Outcome of validating a Federation §8.8 client-authentication JWT (the
/// default <c>private_key_jwt</c> method) presented to a federation endpoint.
/// Carries the authenticated requester identity and replay token on success,
/// or a typed failure reason on rejection.
/// </summary>
/// <remarks>
/// Same sealed-record-with-nullable-fields shape as the other Federation
/// result types (<see cref="TrustChainValidationOutcome"/>,
/// <see cref="EntityStatementParseResult"/>); the federation endpoint maps a
/// rejection onto an HTTP 401 <c>invalid_client</c> response.
/// </remarks>
[DebuggerDisplay("FederationClientAuthenticationResult Valid={IsValid} Reason={FailureReason,nq}")]
public sealed record FederationClientAuthenticationResult
{
    /// <summary>
    /// The authenticated requester's Entity Identifier (the assertion's
    /// <c>iss</c> == <c>sub</c> == <c>client_id</c>); <see langword="null"/> on
    /// failure.
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// The assertion's <c>jti</c>, surfaced so the endpoint can apply its own
    /// replay defense; <see langword="null"/> on failure.
    /// </summary>
    public string? Jti { get; init; }

    /// <summary>The assertion's expiry; <see langword="null"/> on failure.</summary>
    public DateTimeOffset? Expiration { get; init; }

    /// <summary>The reason validation failed; <see langword="null"/> on success.</summary>
    public string? FailureReason { get; init; }

    /// <summary><see langword="true"/> when the client authentication validated.</summary>
    public bool IsValid => FailureReason is null;


    /// <summary>Builds a success result.</summary>
    public static FederationClientAuthenticationResult Authenticated(
        string clientId, string jti, DateTimeOffset expiration)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(jti);
        return new FederationClientAuthenticationResult
        {
            ClientId = clientId,
            Jti = jti,
            Expiration = expiration,
        };
    }


    /// <summary>Builds a failure result.</summary>
    public static FederationClientAuthenticationResult Rejected(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return new FederationClientAuthenticationResult { FailureReason = reason };
    }
}
