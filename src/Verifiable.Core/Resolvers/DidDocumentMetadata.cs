using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Metadata about the resolved DID document. This metadata typically does not change
/// between invocations unless the DID document itself changes.
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://w3c.github.io/did-resolution/#document-metadata">W3C DID Resolution section 7.1 Document Metadata</see>.
/// </para>
/// <para>
/// The DID Resolution document metadata is an open structure. Method-specific and registered properties are
/// carried in the <see cref="AdditionalData"/> open-world bucket (flattened to the metadata root on the wire),
/// so they serialize as plain top-level properties without a type discriminator and any property a peer or
/// future resolver emits round-trips rather than being dropped. The type stays inheritable for callers who
/// prefer a strongly-typed subtype; its equality is type-aware (a base instance and a derived instance are
/// never equal) so a derived type only adds its own fields to equality.
/// </para>
/// </remarks>
[DebuggerDisplay("Deactivated={Deactivated} VersionId={VersionId,nq} Created={Created} Updated={Updated}")]
public class DidDocumentMetadata: IEquatable<DidDocumentMetadata>
{
    /// <summary>
    /// Empty metadata instance for convenience.
    /// </summary>
    public static DidDocumentMetadata Empty { get; } = new();

    /// <summary>
    /// Timestamp of the Create operation.
    /// </summary>
    public DateTimeOffset? Created { get; init; }

    /// <summary>
    /// Timestamp of the last Update operation for the resolved document version.
    /// </summary>
    public DateTimeOffset? Updated { get; init; }

    /// <summary>
    /// Whether the DID has been deactivated.
    /// </summary>
    public bool Deactivated { get; init; }

    /// <summary>
    /// Timestamp of the next Update operation if the resolved version is not the latest.
    /// </summary>
    public DateTimeOffset? NextUpdate { get; init; }

    /// <summary>
    /// Version identifier for the resolved document version.
    /// </summary>
    public string? VersionId { get; init; }

    /// <summary>
    /// Version identifier for the next document version, if the resolved version is not the latest.
    /// </summary>
    public string? NextVersionId { get; init; }

    /// <summary>
    /// Equivalent identifiers for this DID.
    /// </summary>
    public IReadOnlyList<string>? EquivalentId { get; init; }

    /// <summary>
    /// The canonical identifier for this DID.
    /// </summary>
    public string? CanonicalId { get; init; }

    /// <summary>
    /// The open-world bucket for DID Resolution document-metadata properties the typed model does not name —
    /// registered or method-specific properties (for example did:webvh's <c>witness</c>, <c>watchers</c>,
    /// <c>scid</c>, <c>portable</c>, <c>ttl</c>).
    /// </summary>
    /// <remarks>
    /// The DID Resolution document metadata is an open structure, so a method's properties are carried here
    /// rather than via a polymorphic subtype: they are flattened to the metadata object's root on the wire
    /// (each key is a top-level property, never a nested <c>additionalData</c> object), and any property a
    /// future or peer resolver emits round-trips through this bucket instead of being dropped. Consistent with
    /// <see cref="Verifiable.Core.Model.Credentials.CredentialSubject.AdditionalData"/> and the other open-world
    /// POCOs, this is not part of equality.
    /// </remarks>
    public IDictionary<string, object>? AdditionalData { get; init; }

    /// <inheritdoc />
    public virtual bool Equals(DidDocumentMetadata? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        //A base instance is never equal to a derived (method-specific) one, so a derived type's equality only
        //has to add its own fields on top of this comparison.
        if(GetType() != other.GetType())
        {
            return false;
        }

        return Created == other.Created
            && Updated == other.Updated
            && Deactivated == other.Deactivated
            && NextUpdate == other.NextUpdate
            && string.Equals(VersionId, other.VersionId, StringComparison.Ordinal)
            && string.Equals(NextVersionId, other.NextVersionId, StringComparison.Ordinal)
            && string.Equals(CanonicalId, other.CanonicalId, StringComparison.Ordinal);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is DidDocumentMetadata other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Created);
        hash.Add(Updated);
        hash.Add(Deactivated);
        hash.Add(VersionId, StringComparer.Ordinal);
        return hash.ToHashCode();
    }

    public static bool operator ==(DidDocumentMetadata? left, DidDocumentMetadata? right) =>
        left is null ? right is null : left.Equals(right);

    public static bool operator !=(DidDocumentMetadata? left, DidDocumentMetadata? right) => !(left == right);
}
