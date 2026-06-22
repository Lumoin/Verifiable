using System.Collections.Generic;

namespace Verifiable.DidComm;

/// <summary>
/// A single disclosure descriptor in a Discover Features disclose: one feature the agent reveals it supports
/// (DIDComm v2.1 §disclose Message Type).
/// </summary>
public sealed record FeatureDisclosure
{
    /// <summary>REQUIRED. The feature type disclosed — <see cref="WellKnownDiscoverFeaturesNames.Protocol"/>, <c>goal-code</c>, <c>header</c>, or another value.</summary>
    public required string FeatureType { get; init; }

    /// <summary>REQUIRED. The identifier that unambiguously names the disclosed feature — a PIURI for a protocol, a goal code, a header name (DIDComm v2.1 §disclose Message Type).</summary>
    public required string Id { get; init; }

    /// <summary>
    /// OPTIONAL, protocol-only. The roles the agent can play in the protocol. A <see langword="null"/> roles is
    /// NOT "no roles" — it discloses the protocol without detailing roles (DIDComm v2.1 §Sparse Responses).
    /// </summary>
    public IReadOnlyList<string>? Roles { get; init; }

    /// <summary>
    /// OPTIONAL. Additional descriptor members beyond <c>feature-type</c>/<c>id</c>/<c>roles</c>, preserved
    /// verbatim — e.g. the §Agent Constraint Disclosure descriptor's own constraint value (<c>max_receive_bytes</c>).
    /// The spec permits future feature types to add optional fields (DIDComm v2.1 §disclose Message Type); this
    /// carries them losslessly. MUST NOT contain the reserved <c>feature-type</c>/<c>id</c>/<c>roles</c> keys.
    /// </summary>
    public IReadOnlyDictionary<string, object>? AdditionalFields { get; init; }
}


/// <summary>
/// A Discover Features <c>disclose</c> message body — the features an agent discloses in answer to a query, or
/// proactively (DIDComm v2.1 §disclose Message Type). An empty <see cref="Disclosures"/> is NOT "I support no
/// matching features" (DIDComm v2.1 §Sparse Responses). Build and interpret via
/// <see cref="DiscoverFeaturesExtensions"/>.
/// </summary>
public sealed record DiscoverFeaturesDisclose
{
    /// <summary>REQUIRED. The disclosure descriptors — zero or more (DIDComm v2.1 §disclose Message Type).</summary>
    public required IReadOnlyList<FeatureDisclosure> Disclosures { get; init; }
}
