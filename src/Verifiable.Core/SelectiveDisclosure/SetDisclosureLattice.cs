using System;
using System.Collections.Generic;

namespace Verifiable.Core.SelectiveDisclosure;


/// <summary>
/// A bounded lattice implementation using set operations.
/// </summary>
/// <typeparam name="TClaim">The type representing individual claims.</typeparam>
/// <remarks>
/// <para>
/// This implementation uses standard set operations (union, intersection, subset)
/// for lattice operations. The lattice is bounded by:
/// </para>
/// <list type="bullet">
/// <item><description>Top: All available claims in the credential.</description></item>
/// <item><description>Bottom: Mandatory claims that must always be disclosed.</description></item>
/// <item><description>Selectable: Claims that can be optionally disclosed (Top - Bottom).</description></item>
/// </list>
/// </remarks>
public sealed class SetDisclosureLattice<TClaim>
{
    /// <summary>
    /// The top element (all available claims, both mandatory and selectable).
    /// </summary>
    public IReadOnlySet<TClaim> Top { get; }

    /// <summary>
    /// The bottom element (mandatory claims only).
    /// </summary>
    public IReadOnlySet<TClaim> Bottom { get; }

    /// <summary>
    /// The selectable claims (Top minus Bottom).
    /// </summary>
    public IReadOnlySet<TClaim> Selectable { get; }

    private IEqualityComparer<TClaim> Comparer { get; }


    /// <summary>
    /// Creates a new set-based disclosure lattice.
    /// </summary>
    /// <param name="allClaims">All available claims (top element).</param>
    /// <param name="mandatoryClaims">Mandatory claims (bottom element).</param>
    /// <param name="comparer">Optional equality comparer for claims.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when mandatory claims are not a subset of all claims.
    /// </exception>
    public SetDisclosureLattice(
        IEnumerable<TClaim> allClaims,
        IEnumerable<TClaim> mandatoryClaims,
        IEqualityComparer<TClaim>? comparer = null)
    {
        ArgumentNullException.ThrowIfNull(allClaims);
        ArgumentNullException.ThrowIfNull(mandatoryClaims);

        Comparer = comparer ?? EqualityComparer<TClaim>.Default;

        var top = new HashSet<TClaim>(allClaims, Comparer);
        var bottom = new HashSet<TClaim>(mandatoryClaims, Comparer);

        //Validate that bottom ⊆ top.
        if(!bottom.IsSubsetOf(top))
        {
            throw new ArgumentException(
                "Mandatory claims must be a subset of all available claims.",
                nameof(mandatoryClaims));
        }

        //Compute selectable = top - bottom.
        var selectable = new HashSet<TClaim>(top, Comparer);
        selectable.ExceptWith(bottom);

        Top = top;
        Bottom = bottom;
        Selectable = selectable;
    }


    /// <summary>
    /// Computes the join (least upper bound) of two disclosure sets via set union.
    /// </summary>
    public IReadOnlySet<TClaim> Join(IReadOnlySet<TClaim> a, IReadOnlySet<TClaim> b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        var result = new HashSet<TClaim>(a, Comparer);
        result.UnionWith(b);
        return result;
    }


    /// <summary>
    /// Computes the meet (greatest lower bound) of two disclosure sets via set intersection.
    /// </summary>
    public IReadOnlySet<TClaim> Meet(IReadOnlySet<TClaim> a, IReadOnlySet<TClaim> b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        var result = new HashSet<TClaim>(a, Comparer);
        result.IntersectWith(b);
        return result;
    }


    /// <summary>
    /// Determines if one disclosure set is a subset of another in the lattice order.
    /// </summary>
    public bool LessOrEqual(IReadOnlySet<TClaim> a, IReadOnlySet<TClaim> b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        return a.IsSubsetOf(b);
    }


    /// <summary>
    /// Determines if a disclosure set is valid within the lattice bounds (Bottom is a subset of disclosures which is a subset of Top).
    /// </summary>
    public bool IsValid(IReadOnlySet<TClaim> disclosures)
    {
        ArgumentNullException.ThrowIfNull(disclosures);

        //Valid if Bottom ⊆ disclosures ⊆ Top.
        return Bottom.IsSubsetOf(disclosures) && disclosures.IsSubsetOf(Top);
    }


    /// <summary>
    /// Normalizes an external request by separating claims into selectable, already mandatory, and unavailable.
    /// </summary>
    public NormalizedRequest<TClaim> NormalizeRequest(IReadOnlySet<TClaim>? requested)
    {
        if(requested is null || requested.Count == 0)
        {
            return new NormalizedRequest<TClaim>(
                SelectableClaims: new HashSet<TClaim>(Comparer),
                MandatoryClaims: new HashSet<TClaim>(Comparer),
                UnavailableClaims: new HashSet<TClaim>(Comparer));
        }

        var selectable = new HashSet<TClaim>(Comparer);
        var mandatory = new HashSet<TClaim>(Comparer);
        var unavailable = new HashSet<TClaim>(Comparer);

        foreach(var claim in requested)
        {
            if(Bottom.Contains(claim))
            {
                //Claim is mandatory, always disclosed.
                mandatory.Add(claim);
            }
            else if(Selectable.Contains(claim))
            {
                //Claim is selectable, needs selection decision.
                selectable.Add(claim);
            }
            else
            {
                //Claim is not in the credential.
                unavailable.Add(claim);
            }
        }

        return new NormalizedRequest<TClaim>(
            SelectableClaims: selectable,
            MandatoryClaims: mandatory,
            UnavailableClaims: unavailable);
    }
}