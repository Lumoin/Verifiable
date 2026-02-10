using System;
using System.Collections.Generic;
using Verifiable.JCose;
using Verifiable.JCose.Sd;
using Verifiable.JsonPointer;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Places blinded claim hash arrays at the correct locations within a CWT claims dictionary tree.
/// </summary>
/// <remarks>
/// <para>
/// This is the SD-CWT counterpart of <see cref="DigestPlacement"/>. Where SD-JWT places
/// Base64Url-encoded string digests in <c>_sd</c> arrays keyed by a string claim name,
/// SD-CWT places raw <c>byte[]</c> digests in arrays keyed by CBOR <c>simple(59)</c> at
/// the same level of hierarchy as the redacted claims.
/// </para>
/// <para>
/// Per <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt</see>, the <c>sd_alg</c> parameter goes into the COSE
/// protected header (not the payload), so this class does not place it.
/// </para>
/// <code>
/// Input:
///   claims = { 1: "https://issuer.example", 503: { "country": "us" } }
///   digestsByParent = {
///     / root -> [digest1, digest2]
///     /503   -> [digest3]
///   }
///
/// Output (claims modified in place):
///   {
///     1: "https://issuer.example",
///     503: { "country": "us", simple(59): [digest3] },
///     simple(59): [digest1, digest2]
///   }
/// </code>
/// </remarks>
public static class CwtDigestPlacement
{
    /// <summary>
    /// The dictionary key representing CBOR <c>simple(59)</c> used for <c>redacted_claim_keys</c>.
    /// </summary>
    /// <remarks>
    /// CWT payload uses <see cref="Dictionary{Int32, Object}"/>, but the
    /// <c>redacted_claim_keys</c> key is a CBOR simple value, not an integer. To represent
    /// it in the integer-keyed dictionary, we use <see cref="int.MinValue"/> as a sentinel.
    /// The CBOR serializer must map this sentinel back to <c>simple(59)</c> on the wire.
    /// </remarks>
    public const int RedactedClaimKeysSentinel = int.MinValue;


    /// <summary>
    /// Inserts <c>redacted_claim_keys</c> arrays at the correct locations in the CWT claims tree.
    /// </summary>
    /// <param name="claims">
    /// The mandatory claims dictionary tree. Modified in place to include
    /// <c>redacted_claim_keys</c> arrays at each parent location.
    /// </param>
    /// <param name="digestsByParent">
    /// A mapping from parent <see cref="CredentialPath"/> to the list of raw digest bytes
    /// that belong in the <c>redacted_claim_keys</c> array at that location.
    /// </param>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a parent path does not resolve to a dictionary in the claims tree.
    /// </exception>
    public static void PlaceDigests(
        Dictionary<int, object> claims,
        IReadOnlyDictionary<CredentialPath, List<byte[]>> digestsByParent)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(digestsByParent);

        foreach(KeyValuePair<CredentialPath, List<byte[]>> entry in digestsByParent)
        {
            CredentialPath parentPath = entry.Key;
            List<byte[]> digests = entry.Value;

            //Sort digests by byte value for deterministic encoding.
            digests.Sort(CompareByteArrays);

            //Navigate to the parent dictionary in the claims tree.
            Dictionary<int, object> target = ResolveParent(claims, parentPath);
            target[RedactedClaimKeysSentinel] = new List<byte[]>(digests);
        }
    }


    /// <summary>
    /// Navigates the CWT claims dictionary tree to find the dictionary at the given path.
    /// </summary>
    private static Dictionary<int, object> ResolveParent(
        Dictionary<int, object> root,
        CredentialPath path)
    {
        if(path.Equals(CredentialPath.Root))
        {
            return root;
        }

        Dictionary<int, object> current = root;

        foreach(JsonPointerSegment segment in path.JsonPointer.Segments)
        {
            //CWT uses integer keys, so parse the segment as int.
            if(!int.TryParse(segment.Value, out int key))
            {
                throw new InvalidOperationException(
                    $"Cannot place redacted_claim_keys: path segment '{segment.Value}' is not a valid integer key.");
            }

            if(!current.TryGetValue(key, out object? child))
            {
                throw new InvalidOperationException(
                    $"Cannot place redacted_claim_keys: key {key} not found in claims tree.");
            }

            current = child switch
            {
                Dictionary<int, object> dict => dict,
                _ => throw new InvalidOperationException(
                    $"Cannot place redacted_claim_keys: key {key} resolved to {child.GetType().Name}, expected Dictionary<int, object>.")
            };
        }

        return current;
    }


    /// <summary>
    /// Compares two byte arrays lexicographically for deterministic digest ordering.
    /// </summary>
    private static int CompareByteArrays(byte[] left, byte[] right)
    {
        int minLength = Math.Min(left.Length, right.Length);
        for(int i = 0; i < minLength; i++)
        {
            int comparison = left[i].CompareTo(right[i]);
            if(comparison != 0)
            {
                return comparison;
            }
        }

        return left.Length.CompareTo(right.Length);
    }
}