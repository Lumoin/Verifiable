using System.Diagnostics;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Enumerates the reasons one item's digest commitment can fail to match
/// the MSO. Used by <see cref="MdocDigestBindingItemResult.FailureReason"/>.
/// </summary>
public enum MdocDigestBindingItemFailureReason
{
    /// <summary>No failure; the item's digest matched the MSO commitment.</summary>
    None = 0,

    /// <summary>
    /// The item's enclosing namespace is not present in the MSO's
    /// <c>valueDigests</c> map at all — the issuer did not commit to any
    /// items under this namespace.
    /// </summary>
    NamespaceNotCommittedInMso,

    /// <summary>
    /// The item's namespace is committed but its specific <c>digestID</c>
    /// is not in the corresponding inner map.
    /// </summary>
    DigestIdNotCommittedInMso,

    /// <summary>
    /// The MSO commits to a digest for this item, but
    /// <c>hash(item.WireBytes)</c> under the MSO's declared digest
    /// algorithm does not match it. This is the tampering signal —
    /// either the item bytes or the MSO commitment was modified after
    /// signing.
    /// </summary>
    DigestMismatch
}


/// <summary>
/// Enumerates the overall-level reasons MSO digest binding validation can
/// fail. Used by <see cref="MdocDigestBindingResult.FailureReason"/>.
/// </summary>
public enum MdocDigestBindingFailureReason
{
    /// <summary>No failure; the binding validated successfully.</summary>
    None = 0,

    /// <summary>
    /// The MSO declares a digest algorithm not in the ISO/IEC 18013-5
    /// §9.1.2.5 set (SHA-256 / SHA-384 / SHA-512), so the validator
    /// cannot compute the expected digests.
    /// </summary>
    UnsupportedDigestAlgorithm,

    /// <summary>
    /// One or more items failed per-item digest binding. Inspect
    /// <see cref="MdocDigestBindingResult.ItemResults"/> for the per-item
    /// failure reasons.
    /// </summary>
    ItemBindingFailed
}


/// <summary>
/// Per-item result from <see cref="MdocMsoDigestBindingValidator.Validate"/>.
/// Mirrors the shape of <see cref="Verifiable.Core.SelectiveDisclosure.SdClaimVerificationResult"/>
/// — verifier-side callers iterate per-item to see which items proved out and
/// which did not.
/// </summary>
[DebuggerDisplay("{NameSpace}/{ElementIdentifier} (digestID {DigestId}): {IsValid ? \"Valid\" : FailureReason}")]
public readonly record struct MdocDigestBindingItemResult
{
    /// <summary>The namespace under which this item lives.</summary>
    public string NameSpace { get; init; }

    /// <summary>The digest identifier as carried on the item and committed in the MSO.</summary>
    public uint DigestId { get; init; }

    /// <summary>The element identifier (claim name) within the namespace.</summary>
    public string ElementIdentifier { get; init; }

    /// <summary>
    /// Whether the item's digest matched the MSO commitment.
    /// </summary>
    public bool IsValid { get; init; }

    /// <summary>Reason for failure, if any.</summary>
    public MdocDigestBindingItemFailureReason FailureReason { get; init; }


    /// <summary>Creates a passing per-item result for the supplied item.</summary>
    public static MdocDigestBindingItemResult Success(MdocIssuerSignedItem item, string nameSpace)
    {
        ArgumentNullException.ThrowIfNull(item);
        ArgumentException.ThrowIfNullOrEmpty(nameSpace);

        return new()
        {
            NameSpace = nameSpace,
            DigestId = item.DigestId,
            ElementIdentifier = item.ElementIdentifier,
            IsValid = true,
            FailureReason = MdocDigestBindingItemFailureReason.None
        };
    }


    /// <summary>Creates a failed per-item result for the supplied item.</summary>
    public static MdocDigestBindingItemResult Failed(
        MdocIssuerSignedItem item,
        string nameSpace,
        MdocDigestBindingItemFailureReason reason)
    {
        ArgumentNullException.ThrowIfNull(item);
        ArgumentException.ThrowIfNullOrEmpty(nameSpace);

        return new()
        {
            NameSpace = nameSpace,
            DigestId = item.DigestId,
            ElementIdentifier = item.ElementIdentifier,
            IsValid = false,
            FailureReason = reason
        };
    }
}


/// <summary>
/// Overall result of MSO digest binding validation. Carries the per-item
/// outcomes plus a top-level success/failure summary so callers can act on
/// the result without enumerating every item.
/// </summary>
[DebuggerDisplay("{ToString()}")]
public readonly record struct MdocDigestBindingResult
{
    /// <summary>
    /// Whether every item's digest matched the MSO commitment AND the
    /// MSO's declared digest algorithm was in the supported set.
    /// </summary>
    public bool IsValid { get; init; }

    /// <summary>The top-level failure reason; <see cref="MdocDigestBindingFailureReason.None"/> on success.</summary>
    public MdocDigestBindingFailureReason FailureReason { get; init; }

    /// <summary>The per-item results, in iteration order of the namespaces map.</summary>
    public IReadOnlyList<MdocDigestBindingItemResult> ItemResults { get; init; }


    /// <summary>Creates a successful overall result with the per-item outcomes.</summary>
    public static MdocDigestBindingResult Success(IReadOnlyList<MdocDigestBindingItemResult> itemResults) => new()
    {
        IsValid = true,
        FailureReason = MdocDigestBindingFailureReason.None,
        ItemResults = itemResults
    };


    /// <summary>Creates a failed overall result with an optional per-item breakdown.</summary>
    public static MdocDigestBindingResult Failed(
        MdocDigestBindingFailureReason reason,
        IReadOnlyList<MdocDigestBindingItemResult>? itemResults = null) => new()
        {
            IsValid = false,
            FailureReason = reason,
            ItemResults = itemResults ?? []
        };


    /// <inheritdoc/>
    public override string ToString()
    {
        if(IsValid)
        {
            return $"Valid ({ItemResults.Count} items bound)";
        }

        int failed = 0;
        foreach(MdocDigestBindingItemResult itemResult in ItemResults)
        {
            if(!itemResult.IsValid)
            {
                failed++;
            }
        }

        return failed > 0
            ? $"Invalid ({FailureReason}, {failed} items failed)"
            : $"Invalid ({FailureReason})";
    }
}
