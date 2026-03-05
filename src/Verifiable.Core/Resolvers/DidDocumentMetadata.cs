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
/// </remarks>
[DebuggerDisplay("Deactivated={Deactivated} VersionId={VersionId,nq} Created={Created} Updated={Updated}")]
public sealed class DidDocumentMetadata: IEquatable<DidDocumentMetadata>
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

    /// <inheritdoc />
    public bool Equals(DidDocumentMetadata? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
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