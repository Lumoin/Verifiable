using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// A §3.4.4 Authorization Capability Request query entry, asking for authorization capabilities
/// ("zcaps") in the verifiable presentation.
/// </summary>
/// <remarks>
/// The §3.4.4 query type is editor-flagged ("Authorization Capability queries and responses might
/// not be standardized at this time."). It is modeled here so the request parses and round-trips,
/// but it is never a conformance gate and <see cref="VprEvaluator"/> does not attempt to satisfy it
/// from held verifiable credentials.
/// </remarks>
[DebuggerDisplay("AuthorizationCapabilityRequest Capabilities={CapabilityQuery.Length} Group={Group}")]
public sealed record AuthorizationCapabilityRequestQuery: VcalmPresentationQuery
{
    /// <summary>The §3.4.4 <c>capabilityQuery</c> array of requested capabilities.</summary>
    public ImmutableArray<CapabilityQueryItem> CapabilityQuery { get; init; } =
        ImmutableArray<CapabilityQueryItem>.Empty;
}


/// <summary>
/// A single §3.4.4 <c>capabilityQuery</c> item: a requested authorization capability.
/// </summary>
[DebuggerDisplay("CapabilityQueryItem ReferenceId={ReferenceId} Controller={Controller}")]
public sealed record CapabilityQueryItem
{
    /// <summary>The §3.4.4 <c>referenceId</c> — a memorable correlation name.</summary>
    public string? ReferenceId { get; init; }

    /// <summary>
    /// The §3.4.4 <c>allowedAction</c> — the requested action(s). The wire allows a single string or
    /// an array; both normalize to this list.
    /// </summary>
    public ImmutableArray<string> AllowedAction { get; init; } = ImmutableArray<string>.Empty;

    /// <summary>The §3.4.4 <c>controller</c> — the controller identifier (a DID).</summary>
    public string? Controller { get; init; }

    /// <summary>
    /// The §3.4.4 <c>invocationTarget</c> — the opaque target object the capability is invoked
    /// against, preserved as its verbatim JSON. <see langword="null"/> when absent.
    /// </summary>
    public string? InvocationTargetJson { get; init; }
}
