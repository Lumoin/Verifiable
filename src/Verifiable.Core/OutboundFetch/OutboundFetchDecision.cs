using System;

namespace Verifiable.Core.OutboundFetch;

/// <summary>
/// The result of classifying a single URL against an
/// <see cref="OutboundFetchPolicy"/>: either allowed, or denied with a
/// human-readable reason. A neutral primitive — it carries no policy decision
/// of its own beyond the verdict, and never throws.
/// </summary>
[System.Diagnostics.DebuggerDisplay("{IsAllowed ? \"Allow\" : \"Deny: \" + DenyReason,nq}")]
public readonly record struct OutboundFetchDecision
{
    private OutboundFetchDecision(bool isAllowed, string? denyReason)
    {
        IsAllowed = isAllowed;
        DenyReason = denyReason;
    }


    /// <summary>Whether the URL is permitted by the policy.</summary>
    public bool IsAllowed { get; }

    /// <summary>
    /// The reason the URL was denied, or <see langword="null"/> when
    /// <see cref="IsAllowed"/> is <see langword="true"/>. Intended for logs and
    /// diagnostics; do not surface verbatim to untrusted callers.
    /// </summary>
    public string? DenyReason { get; }


    /// <summary>The allow verdict.</summary>
    public static OutboundFetchDecision Allowed { get; } = new(true, null);

    /// <summary>Builds a deny verdict carrying <paramref name="reason"/>.</summary>
    /// <param name="reason">Why the URL was denied.</param>
    public static OutboundFetchDecision Denied(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return new OutboundFetchDecision(false, reason);
    }
}
