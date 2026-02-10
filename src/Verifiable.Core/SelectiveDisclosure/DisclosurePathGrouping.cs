using System;
using System.Collections.Generic;
using Verifiable.JsonPointer;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Groups disclosable <see cref="CredentialPath"/> values by their parent path, producing
/// a lookup from parent container path to the set of leaf claim names at that level.
/// </summary>
/// <remarks>
/// <para>
/// This is the first phase of the selective disclosure issuance pipeline, shared across
/// all formats (SD-JWT, SD-CWT). It performs pure <see cref="CredentialPath"/> manipulation
/// with no format-specific dependencies.
/// </para>
/// <para>
/// Per <see href="https://datatracker.ietf.org/doc/rfc9901/#section-5.1">RFC 9901 Section 5.1</see>,
/// the <c>_sd</c> digest array is a sibling of the claims it replaces. For a disclosable
/// path like <c>/credentialSubject/degree</c>, the parent is <c>/credentialSubject</c> and
/// the leaf name is <c>degree</c>. The digest for <c>degree</c> must appear in the <c>_sd</c>
/// array inside the <c>credentialSubject</c> object. This grouping enables the format-specific
/// redaction phase to place digests at the correct nesting level.
/// </para>
/// <code>
/// Input paths:
///   /credentialSubject/degree
///   /credentialSubject/id
///   /validFrom
///
/// Grouped output:
///   /credentialSubject  ->  { "degree", "id" }
///   (root)              ->  { "validFrom" }
/// </code>
/// </remarks>
public static class DisclosurePathGrouping
{
    /// <summary>
    /// Groups disclosable paths by their parent container path.
    /// </summary>
    /// <param name="disclosablePaths">
    /// Paths to claims that should become selectively disclosable.
    /// Each path must have at least one segment (the leaf claim name).
    /// </param>
    /// <returns>
    /// A dictionary mapping each parent <see cref="CredentialPath"/> to the set of
    /// leaf property names that are disclosable at that level. The root path
    /// (<see cref="CredentialPath.Root"/>) is used for top-level claims.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown when a disclosable path is the root path (cannot redact the entire document)
    /// or when the last segment is not a property name.
    /// </exception>
    public static IReadOnlyDictionary<CredentialPath, IReadOnlySet<string>> GroupByParent(
        IReadOnlySet<CredentialPath> disclosablePaths)
    {
        ArgumentNullException.ThrowIfNull(disclosablePaths);

        var grouped = new Dictionary<CredentialPath, HashSet<string>>();

        foreach(CredentialPath path in disclosablePaths)
        {
            if(!path.IsJsonPath)
            {
                continue;
            }

            CredentialPath? parent = path.Parent;
            if(parent is null)
            {
                throw new ArgumentException(
                    "Cannot redact the root path. Each disclosable path must identify a specific claim.",
                    nameof(disclosablePaths));
            }

            //The leaf name is the last segment's raw token value.
            JsonPointer.JsonPointerSegment? lastSegment = path.JsonPointer.LastSegment;
            if(lastSegment is null)
            {
                continue;
            }

            string leafName = lastSegment.Value.Value;

            if(!grouped.TryGetValue(parent.Value, out HashSet<string>? leaves))
            {
                leaves = new HashSet<string>(StringComparer.Ordinal);
                grouped[parent.Value] = leaves;
            }

            leaves.Add(leafName);
        }

        //Convert to read-only interface.
        var result = new Dictionary<CredentialPath, IReadOnlySet<string>>(grouped.Count);
        foreach(KeyValuePair<CredentialPath, HashSet<string>> entry in grouped)
        {
            result[entry.Key] = entry.Value;
        }

        return result;
    }


    /// <summary>
    /// Determines whether a given path has any disclosable descendants in the grouping.
    /// </summary>
    /// <param name="path">The path to check.</param>
    /// <param name="groupedPaths">The grouped disclosable paths from <see cref="GroupByParent"/>.</param>
    /// <returns>
    /// <see langword="true"/> if <paramref name="path"/> is a parent in the grouping
    /// or if any parent in the grouping is a descendant of <paramref name="path"/>.
    /// </returns>
    public static bool HasDisclosableDescendants(
        CredentialPath path,
        IReadOnlyDictionary<CredentialPath, IReadOnlySet<string>> groupedPaths)
    {
        ArgumentNullException.ThrowIfNull(groupedPaths);

        //Direct match: this path itself has disclosable children.
        if(groupedPaths.ContainsKey(path))
        {
            return true;
        }

        //Check if any parent path in the grouping is a descendant of the given path.
        foreach(CredentialPath parentPath in groupedPaths.Keys)
        {
            if(parentPath.IsDescendantOf(path))
            {
                return true;
            }
        }

        return false;
    }
}