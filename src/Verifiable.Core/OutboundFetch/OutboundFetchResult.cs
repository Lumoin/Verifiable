using System;

namespace Verifiable.Core.OutboundFetch;

/// <summary>
/// Why a guarded <see cref="OutboundFetch"/> ended.
/// </summary>
public enum OutboundFetchOutcome
{
    /// <summary>A terminal (non-redirect) response was obtained. <see cref="OutboundFetchResult.Response"/> is set.</summary>
    Fetched = 0,

    /// <summary>A URL (the target or a redirect hop) was denied by the policy.</summary>
    DeniedByPolicy,

    /// <summary>A redirect was returned but the policy's <see cref="RedirectMode"/> is <see cref="RedirectMode.None"/>.</summary>
    RedirectNotFollowed,

    /// <summary>The redirect chain exceeded <see cref="OutboundFetchPolicy.MaxRedirects"/>.</summary>
    TooManyRedirects
}


/// <summary>
/// The outcome of a guarded <see cref="OutboundFetch"/>. Fail-closed by return,
/// not by exception: a denied or over-long fetch yields a non-<see cref="OutboundFetchOutcome.Fetched"/>
/// outcome with a diagnostic <see cref="DenyReason"/>, never a thrown policy
/// error. Carries provenance (requested vs final URL, hop count) suitable for an
/// audit/trust log.
/// </summary>
public sealed record OutboundFetchResult
{
    /// <summary>Why the fetch ended.</summary>
    public required OutboundFetchOutcome Outcome { get; init; }

    /// <summary>
    /// The terminal response when <see cref="Outcome"/> is
    /// <see cref="OutboundFetchOutcome.Fetched"/>; otherwise <see langword="null"/>.
    /// </summary>
    public OutboundResponse? Response { get; init; }

    /// <summary>A diagnostic reason for a non-fetched outcome. Do not surface verbatim to untrusted callers.</summary>
    public string? DenyReason { get; init; }

    /// <summary>The URL originally requested.</summary>
    public required Uri RequestedUri { get; init; }

    /// <summary>The URL at which the fetch ended (after any redirects).</summary>
    public required Uri FinalUri { get; init; }

    /// <summary>The number of redirect hops followed.</summary>
    public int RedirectCount { get; init; }


    /// <summary>Whether a terminal response was obtained.</summary>
    public bool IsFetched => Outcome == OutboundFetchOutcome.Fetched;
}
