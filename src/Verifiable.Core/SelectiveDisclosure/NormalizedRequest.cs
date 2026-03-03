using System.Collections.Generic;

namespace Verifiable.Core.SelectiveDisclosure;


/// <summary>
/// Result of normalizing an external request against a disclosure lattice.
/// </summary>
/// <typeparam name="TClaim">The type representing individual claims.</typeparam>
/// <param name="SelectableClaims">Claims from the request that are selectable (need selection decision).</param>
/// <param name="MandatoryClaims">Claims from the request that are already mandatory (always disclosed).</param>
/// <param name="UnavailableClaims">Claims from the request that are not in the credential.</param>
public readonly record struct NormalizedRequest<TClaim>(
    IReadOnlySet<TClaim> SelectableClaims,
    IReadOnlySet<TClaim> MandatoryClaims,
    IReadOnlySet<TClaim> UnavailableClaims)
{
    /// <summary>
    /// Gets whether all requested claims can be satisfied (none are unavailable).
    /// </summary>
    public bool CanSatisfy => UnavailableClaims.Count == 0;

    /// <summary>
    /// Gets the total claims that will be disclosed if this request is granted.
    /// </summary>
    /// <remarks>
    /// This is SelectableClaims ∪ MandatoryClaims. Note that additional mandatory
    /// claims not in the original request will also be disclosed.
    /// </remarks>
    public IReadOnlySet<TClaim> EffectiveClaims
    {
        get
        {
            var result = new HashSet<TClaim>(SelectableClaims);
            result.UnionWith(MandatoryClaims);
            return result;
        }
    }
}
