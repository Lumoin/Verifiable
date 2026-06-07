using System.Diagnostics;

namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// Application-supplied additions to the OpenID AuthZEN Authorization API 1.0
/// Policy Decision Point metadata document (§9.1) — values the library cannot
/// derive from the endpoint chain. Returned from the
/// <see cref="Server.ContributeAuthZenMetadataDelegate"/> seam.
/// </summary>
[DebuggerDisplay("AuthZenMetadataContribution Capabilities={Capabilities?.Count}")]
public sealed record AuthZenMetadataContribution
{
    /// <summary>The empty contribution — no additional metadata.</summary>
    public static AuthZenMetadataContribution Empty { get; } = new();

    /// <summary>
    /// The §9.1 <c>capabilities</c> value — a list of registered IANA URNs
    /// referencing PDP-specific capabilities. Omitted from the document when
    /// <see langword="null"/> or empty.
    /// </summary>
    public IReadOnlyList<string>? Capabilities { get; init; }
}
