using System.Collections.Generic;

namespace Verifiable.DidComm;

/// <summary>
/// A single query descriptor in a Discover Features query: a request to disclose features of a given type whose
/// identifier matches a pattern (DIDComm v2.1 §query Message Type).
/// </summary>
public sealed record FeatureQuery
{
    /// <summary>REQUIRED. The feature type queried — <see cref="WellKnownDiscoverFeaturesNames.Protocol"/>, <c>goal-code</c>, <c>header</c>, or another value.</summary>
    public required string FeatureType { get; init; }

    /// <summary>
    /// REQUIRED. The identifier to match — an exact value, or a prefix ending in a <c>*</c> wildcard (a bare
    /// <c>*</c> matches anything), e.g. <c>https://didcomm.org/tictactoe/1.*</c> (DIDComm v2.1 §query Message Type).
    /// </summary>
    public required string Match { get; init; }
}


/// <summary>
/// A Discover Features <c>query</c> message body — one or more <see cref="FeatureQuery"/> descriptors asking a
/// responder which features it supports (DIDComm v2.1 §Discover Features Protocol 2.0). Build and interpret via
/// <see cref="DiscoverFeaturesExtensions"/>.
/// </summary>
public sealed record DiscoverFeaturesQuery
{
    /// <summary>REQUIRED. The query descriptors — at least one (DIDComm v2.1 §query Message Type).</summary>
    public required IReadOnlyList<FeatureQuery> Queries { get; init; }
}
