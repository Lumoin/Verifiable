using Verifiable.Core.Outbound;

namespace Verifiable.Core.StatusLists;

/// <summary>A verified Status List Token or a typed failure to fetch it.</summary>
public abstract class StatusListTokenResolution
{
    /// <summary>Restricts derivation to this assembly's resolution outcomes.</summary>
    private protected StatusListTokenResolution()
    {
    }
}


/// <summary>Why a Status List Token could not be fetched for resolution.</summary>
public enum StatusListTokenResolutionFailureKind
{
    /// <summary>The transport failed, including a timeout while the caller's token was live.</summary>
    Unreachable,

    /// <summary>The guarded reader refused a declared or observed response length.</summary>
    TooLarge,

    /// <summary>The outbound policy denied the target or a redirect hop.</summary>
    PolicyDenied,

    /// <summary>A redirect was not followed or the redirect chain exceeded its bound.</summary>
    RedirectNotFollowed,

    /// <summary>The response status was outside the successful range.</summary>
    UnsuccessfulStatus,

    /// <summary>The response did not carry the requested token media type.</summary>
    ContentTypeMismatch
}


/// <summary>A failed fetch with its evidence, never a usable or partial Status List Token.</summary>
public sealed class StatusListTokenResolutionFailure: StatusListTokenResolution
{
    /// <summary>The resolution's own classification of the failed fetch.</summary>
    public required StatusListTokenResolutionFailureKind Kind { get; init; }

    /// <summary>The Status List Token location requested by the caller.</summary>
    public required Uri RequestedUri { get; init; }

    /// <summary>The location at which the fetch ended.</summary>
    public required Uri FinalUri { get; init; }

    /// <summary>The number of redirect hops followed.</summary>
    public int RedirectCount { get; init; }

    /// <summary>The guarded fetch's failure kind; own-budget cancellation is TimeoutException.</summary>
    public Type? FailureKind { get; init; }

    /// <summary>The original guarded reader's size evidence when Kind is TooLarge.</summary>
    public OutboundResponseTooLarge? TooLarge { get; init; }

    /// <summary>The terminal HTTP status, or zero when no terminal response was reached.</summary>
    public int StatusCode { get; init; }

    /// <summary>The received media type when the content-type check failed.</summary>
    public string? ContentType { get; init; }

    /// <summary>An internal diagnostic; never surface verbatim to untrusted callers.</summary>
    public string? DenyReason { get; init; }
}
