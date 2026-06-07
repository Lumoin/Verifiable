using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Result of <see cref="MetadataPolicyMerger.Merge(EntityTypeMetadataPolicy, EntityTypeMetadataPolicy)"/>
/// and its sibling snapshot-level overload. Either carries the merged
/// policy (success) or a structured-failure reason (conflict). Mirrors the
/// <see cref="EntityStatementParseResult"/> / <see cref="MetadataPolicyParseResult"/>
/// shape: single sealed record with nullable fields + static factories.
/// </summary>
[DebuggerDisplay("MetadataPolicyMergeResult Success={IsSuccess} Reason={FailureReason,nq}")]
public sealed record MetadataPolicyMergeResult
{
    /// <summary>The merged per-entity-type block when success; otherwise <see langword="null"/>.</summary>
    public EntityTypeMetadataPolicy? MergedBlock { get; init; }

    /// <summary>The merged snapshot when success; otherwise <see langword="null"/>.</summary>
    public MetadataPolicySnapshot? MergedSnapshot { get; init; }

    /// <summary>The reason merging failed; <see langword="null"/> on success.</summary>
    public string? FailureReason { get; init; }

    /// <summary><see langword="true"/> when merging succeeded.</summary>
    public bool IsSuccess => FailureReason is null;


    /// <summary>Builds a success result for the block-level merge.</summary>
    public static MetadataPolicyMergeResult MergedFromBlock(EntityTypeMetadataPolicy block)
    {
        ArgumentNullException.ThrowIfNull(block);
        return new MetadataPolicyMergeResult { MergedBlock = block };
    }


    /// <summary>Builds a success result for the snapshot-level merge.</summary>
    public static MetadataPolicyMergeResult MergedFromSnapshot(MetadataPolicySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        return new MetadataPolicyMergeResult { MergedSnapshot = snapshot };
    }


    /// <summary>Builds a failure result with the given reason.</summary>
    public static MetadataPolicyMergeResult Failed(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return new MetadataPolicyMergeResult { FailureReason = reason };
    }
}
