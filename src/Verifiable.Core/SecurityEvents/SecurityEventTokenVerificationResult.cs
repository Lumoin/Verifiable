using System;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The outcome of verifying a Security Event Token: the extracted, typed token on
/// success, or a typed failure reason. Mirrors the success/failure shape of the
/// claims-JWT validator family (for example
/// <see cref="Verifiable.OAuth.JwsAccessTokenValidator"/>'s result) — verification
/// reports outcomes a receiver dispatches on rather than throwing.
/// </summary>
/// <remarks>
/// On failure, <see cref="Token"/> is <see langword="null"/> and <see cref="Error"/>
/// carries the cause — a firewalled receiver must not act on claims whose signature
/// or validity did not hold. The verified value is the strongly-typed
/// <see cref="SecurityEventToken"/>, never a loose claim dictionary.
/// </remarks>
public sealed record SecurityEventTokenVerificationResult
{
    /// <summary>The extracted, validated token when verification succeeded; otherwise <see langword="null"/>.</summary>
    public SecurityEventToken? Token { get; init; }

    /// <summary>The failure reason when verification failed; otherwise <see langword="null"/>.</summary>
    public SecurityEventTokenValidationError? Error { get; init; }

    /// <summary><see langword="true"/> when verification and all SET-level checks succeeded.</summary>
    public bool IsValid => Error is null;


    /// <summary>Builds a success result carrying the extracted <paramref name="token"/>.</summary>
    public static SecurityEventTokenVerificationResult Success(SecurityEventToken token)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new SecurityEventTokenVerificationResult { Token = token };
    }


    /// <summary>Builds a failure result carrying <paramref name="error"/>.</summary>
    public static SecurityEventTokenVerificationResult Failed(SecurityEventTokenValidationError error) =>
        new() { Error = error };
}
