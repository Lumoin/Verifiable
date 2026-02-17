using System;
using System.Collections.Generic;
using Verifiable.JCose.Sd;
using Verifiable.JsonPointer;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Places <c>_sd</c> digest arrays at the correct locations within a claims dictionary tree.
/// </summary>
/// <remarks>
/// <para>
/// This is the final phase of the selective disclosure issuance pipeline. After the
/// format-specific redaction phase has created disclosures and computed digests grouped
/// by parent <see cref="CredentialPath"/>, this class navigates the mandatory claims
/// dictionary tree and inserts the <c>_sd</c> arrays at each parent location.
/// </para>
/// <para>
/// Per <see href="https://datatracker.ietf.org/doc/rfc9901/#section-5.1">RFC 9901 Section 5.1</see>,
/// the <c>_sd</c> claim is an array of digests that is a sibling of the claims it replaces.
/// For nested structures, multiple <c>_sd</c> arrays may exist at different nesting levels.
/// The <c>_sd_alg</c> claim is always placed at the root per
/// <see href="https://datatracker.ietf.org/doc/rfc9901/#section-5.1.1">RFC 9901 Section 5.1.1</see>.
/// </para>
/// <code>
/// Input:
///   claims = { "credentialSubject": { }, "@context": [...], ... }
///   digestsByParent = {
///     /credentialSubject -> ["digest1", "digest2"]
///   }
///
/// Output (claims modified in place):
///   { "credentialSubject": { "_sd": ["digest1", "digest2"] }, "@context": [...], ..., "_sd_alg": "sha-256" }
/// </code>
/// <para>
/// This class operates on <see cref="Dictionary{TKey, TValue}"/> trees, which is the
/// common representation for both <c>JwtPayload</c> (SD-JWT) and CBOR claim maps (SD-CWT).
/// </para>
/// </remarks>
public static class DigestPlacement
{
    /// <summary>
    /// Inserts <c>_sd</c> digest arrays at the correct locations in the claims tree
    /// and adds <c>_sd_alg</c> at the root.
    /// </summary>
    /// <param name="claims">
    /// The mandatory claims dictionary tree. Modified in place to include <c>_sd</c>
    /// arrays at each parent location and <c>_sd_alg</c> at the root.
    /// </param>
    /// <param name="digestsByParent">
    /// A mapping from parent <see cref="CredentialPath"/> to the list of Base64Url-encoded
    /// digests that belong in the <c>_sd</c> array at that location.
    /// </param>
    /// <param name="hashAlgorithm">
    /// The hash algorithm identifier in IANA format (e.g., <c>"sha-256"</c>).
    /// </param>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a parent path does not resolve to a dictionary in the claims tree.
    /// </exception>
    public static void PlaceDigests(
        Dictionary<string, object> claims,
        IReadOnlyDictionary<CredentialPath, List<string>> digestsByParent,
        string hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(digestsByParent);
        ArgumentException.ThrowIfNullOrWhiteSpace(hashAlgorithm);

        foreach(KeyValuePair<CredentialPath, List<string>> entry in digestsByParent)
        {
            CredentialPath parentPath = entry.Key;
            List<string> digests = entry.Value;

            //Sort digests alphabetically per RFC 9901 Section 5.2.4.2 recommendation.
            digests.Sort(StringComparer.Ordinal);

            //Navigate to the parent dictionary in the claims tree.
            Dictionary<string, object> target = ResolveParent(claims, parentPath);
            target[SdConstants.SdClaimName] = new List<string>(digests);
        }

        //Add _sd_alg at root only when digests were placed.
        if(digestsByParent.Count > 0)
        {
            claims[SdConstants.SdAlgorithmClaimName] = hashAlgorithm;
        }
    }


    /// <summary>
    /// Navigates the claims dictionary tree to find the dictionary at the given path.
    /// </summary>
    private static Dictionary<string, object> ResolveParent(
        Dictionary<string, object> root,
        CredentialPath path)
    {
        //Root path means the top-level claims dictionary.
        if(path.Equals(CredentialPath.Root))
        {
            return root;
        }

        Dictionary<string, object> current = root;

        foreach(JsonPointerSegment segment in path.JsonPointer.Segments)
        {
            string key = segment.Value;

            if(!current.TryGetValue(key, out object? child))
            {
                throw new InvalidOperationException(
                    $"Cannot place _sd array: path segment '{key}' not found in claims tree.");
            }

            current = child switch
            {
                Dictionary<string, object> dict => dict,
                _ => throw new InvalidOperationException(
                    $"Cannot place _sd array: path segment '{key}' resolved to {child.GetType().Name}, expected Dictionary<string, object>.")
            };
        }

        return current;
    }
}