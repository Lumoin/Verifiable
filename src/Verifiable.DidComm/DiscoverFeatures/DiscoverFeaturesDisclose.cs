using System;
using System.Collections.Generic;
using Verifiable.Foundation;

namespace Verifiable.DidComm.DiscoverFeatures;

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


    /// <summary>
    /// Determines whether this disclosure equals <paramref name="other"/> by value: <see cref="FeatureType"/> and
    /// <see cref="Id"/> by ordinal comparison, <see cref="Roles"/> element-wise in order, and the arbitrary-JSON
    /// <see cref="AdditionalFields"/> by deep structural comparison (<see cref="StructuralEquality.JsonEqual"/>).
    /// </summary>
    /// <param name="other">The disclosure to compare with, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the two disclosures are value-equal.</returns>
    public bool Equals(FeatureDisclosure? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(FeatureType, other.FeatureType, StringComparison.Ordinal)
            && string.Equals(Id, other.Id, StringComparison.Ordinal)
            && StructuralEquality.SequenceEqual(Roles, other.Roles)
            && StructuralEquality.JsonEqual(AdditionalFields, other.AdditionalFields);
    }


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(FeatureType, StringComparer.Ordinal);
        hash.Add(Id, StringComparer.Ordinal);
        hash.Add(StructuralEquality.SequenceHashCode(Roles));
        hash.Add(StructuralEquality.JsonHashCode(AdditionalFields));

        return hash.ToHashCode();
    }
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


    /// <summary>Determines whether this disclose equals <paramref name="other"/> by its <see cref="Disclosures"/> element-wise in order.</summary>
    /// <param name="other">The disclose to compare with, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the two are value-equal.</returns>
    public bool Equals(DiscoverFeaturesDisclose? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return StructuralEquality.SequenceEqual(Disclosures, other.Disclosures);
    }


    /// <inheritdoc/>
    public override int GetHashCode() => StructuralEquality.SequenceHashCode(Disclosures);
}
