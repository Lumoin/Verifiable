namespace Verifiable.OAuth.Federation;

/// <summary>
/// The application's answer to
/// <see cref="Server.AuthorizationServerIntegration.ResolveSubjectTrustChainAsync"/>: either the
/// resolved <see cref="Contribution"/>, or the <see cref="FederationResolveError"/> naming why
/// resolution failed, which the library maps to the
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.9">Federation §8.9</see>
/// error code the <c>federation_resolve_endpoint</c>
/// (<see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3">§8.3</see>) reports.
/// </summary>
public sealed record FederationResolveOutcome
{
    /// <summary>
    /// The resolved contribution, or <see langword="null"/> when <see cref="Error"/> names the
    /// failure instead.
    /// </summary>
    public ResolveResponseContribution? Contribution { get; init; }

    /// <summary>
    /// The reason resolution failed, or <see langword="null"/> when <see cref="Contribution"/> is
    /// set. An outcome with neither set is answered the same as a <see langword="null"/> delegate
    /// return — <see cref="FederationResolveError.InvalidSubject"/>.
    /// </summary>
    public FederationResolveError? Error { get; init; }

    /// <summary>Creates a successful outcome carrying the resolved <paramref name="contribution"/>.</summary>
    /// <param name="contribution">The resolved metadata, trust chain, and trust marks.</param>
    /// <returns>A <see cref="FederationResolveOutcome"/> carrying <paramref name="contribution"/>.</returns>
    public static FederationResolveOutcome Resolved(ResolveResponseContribution contribution) =>
        new() { Contribution = contribution };

    /// <summary>Creates a failed outcome naming the <paramref name="error"/>.</summary>
    /// <param name="error">The reason resolution failed.</param>
    /// <returns>A <see cref="FederationResolveOutcome"/> naming <paramref name="error"/>.</returns>
    public static FederationResolveOutcome Failed(FederationResolveError error) =>
        new() { Error = error };
}
