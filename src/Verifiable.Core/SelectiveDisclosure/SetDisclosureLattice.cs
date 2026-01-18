using System;
using System.Collections.Generic;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Represents a bounded lattice over disclosure sets.
/// </summary>
/// <typeparam name="TClaim">The type representing individual claims.</typeparam>
/// <remarks>
/// <para>
/// A bounded lattice is a partially ordered set with:
/// </para>
/// <list type="bullet">
/// <item><description><see cref="Top"/>: The greatest element (all available claims).</description></item>
/// <item><description><see cref="Bottom"/>: The least element (mandatory claims only).</description></item>
/// <item><description><see cref="Join"/>: Least upper bound (union of disclosures).</description></item>
/// <item><description><see cref="Meet"/>: Greatest lower bound (intersection of disclosures).</description></item>
/// </list>
/// <para>
/// This structure enables principled reasoning about selective disclosure:
/// </para>
/// <list type="bullet">
/// <item><description>Minimum disclosure: Join of all requirements.</description></item>
/// <item><description>Maximum disclosure: Top minus user exclusions.</description></item>
/// <item><description>Valid disclosure: Any set where Bottom ⊆ S ⊆ Top.</description></item>
/// </list>
/// </remarks>
public interface IBoundedDisclosureLattice<TClaim>
{
    /// <summary>
    /// Gets the top element (all available claims, both mandatory and selectable).
    /// </summary>
    IReadOnlySet<TClaim> Top { get; }

    /// <summary>
    /// Gets the bottom element (mandatory claims only).
    /// </summary>
    IReadOnlySet<TClaim> Bottom { get; }

    /// <summary>
    /// Gets the selectable claims (Top minus Bottom).
    /// </summary>
    /// <remarks>
    /// These are claims that can be optionally disclosed. Mandatory claims
    /// are always disclosed and don't need to be selected.
    /// </remarks>
    IReadOnlySet<TClaim> Selectable { get; }

    /// <summary>
    /// Computes the join (least upper bound) of two disclosure sets.
    /// </summary>
    /// <param name="a">First disclosure set.</param>
    /// <param name="b">Second disclosure set.</param>
    /// <returns>The smallest set containing both a and b.</returns>
    /// <remarks>
    /// For set-based lattices, this is set union: Join(A, B) = A ∪ B.
    /// </remarks>
    IReadOnlySet<TClaim> Join(IReadOnlySet<TClaim> a, IReadOnlySet<TClaim> b);

    /// <summary>
    /// Computes the meet (greatest lower bound) of two disclosure sets.
    /// </summary>
    /// <param name="a">First disclosure set.</param>
    /// <param name="b">Second disclosure set.</param>
    /// <returns>The largest set contained in both a and b.</returns>
    /// <remarks>
    /// For set-based lattices, this is set intersection: Meet(A, B) = A ∩ B.
    /// </remarks>
    IReadOnlySet<TClaim> Meet(IReadOnlySet<TClaim> a, IReadOnlySet<TClaim> b);

    /// <summary>
    /// Determines if one disclosure set is less than or equal to another in the lattice order.
    /// </summary>
    /// <param name="a">First disclosure set.</param>
    /// <param name="b">Second disclosure set.</param>
    /// <returns><see langword="true"/> if a ⊆ b; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// For set-based lattices, this is subset relation: a ≤ b iff a ⊆ b.
    /// </remarks>
    bool LessOrEqual(IReadOnlySet<TClaim> a, IReadOnlySet<TClaim> b);

    /// <summary>
    /// Determines if a disclosure set is valid within the lattice bounds.
    /// </summary>
    /// <param name="disclosures">The disclosure set to validate.</param>
    /// <returns><see langword="true"/> if Bottom ⊆ disclosures ⊆ Top; otherwise <see langword="false"/>.</returns>
    bool IsValid(IReadOnlySet<TClaim> disclosures);

    /// <summary>
    /// Normalizes an external request by filtering to only selectable claims.
    /// </summary>
    /// <param name="requested">The externally requested claims.</param>
    /// <returns>
    /// A tuple containing the normalized request (intersection with Selectable)
    /// and claims that were already mandatory (intersection with Bottom).
    /// </returns>
    /// <remarks>
    /// <para>
    /// External requests (e.g., from verifiers) may contain claims that are:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Already mandatory: These are always disclosed, no selection needed.</description></item>
    /// <item><description>Not in the credential: These cannot be satisfied.</description></item>
    /// <item><description>Selectable: These need to be included in the selection.</description></item>
    /// </list>
    /// <para>
    /// This method separates these cases so callers can handle them appropriately.
    /// </para>
    /// </remarks>
    NormalizedRequest<TClaim> NormalizeRequest(IReadOnlySet<TClaim>? requested);
}


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
public sealed class SetDisclosureLattice<TClaim>: IBoundedDisclosureLattice<TClaim>
{
    /// <inheritdoc/>
    public IReadOnlySet<TClaim> Top { get; }

    /// <inheritdoc/>
    public IReadOnlySet<TClaim> Bottom { get; }

    /// <inheritdoc/>
    public IReadOnlySet<TClaim> Selectable { get; }

    private readonly IEqualityComparer<TClaim> _comparer;


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

        _comparer = comparer ?? EqualityComparer<TClaim>.Default;

        var top = new HashSet<TClaim>(allClaims, _comparer);
        var bottom = new HashSet<TClaim>(mandatoryClaims, _comparer);

        //Validate that bottom ⊆ top.
        if(!bottom.IsSubsetOf(top))
        {
            throw new ArgumentException(
                "Mandatory claims must be a subset of all available claims.",
                nameof(mandatoryClaims));
        }

        //Compute selectable = top - bottom.
        var selectable = new HashSet<TClaim>(top, _comparer);
        selectable.ExceptWith(bottom);

        Top = top;
        Bottom = bottom;
        Selectable = selectable;
    }


    /// <inheritdoc/>
    public IReadOnlySet<TClaim> Join(IReadOnlySet<TClaim> a, IReadOnlySet<TClaim> b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        var result = new HashSet<TClaim>(a, _comparer);
        result.UnionWith(b);
        return result;
    }


    /// <inheritdoc/>
    public IReadOnlySet<TClaim> Meet(IReadOnlySet<TClaim> a, IReadOnlySet<TClaim> b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        var result = new HashSet<TClaim>(a, _comparer);
        result.IntersectWith(b);
        return result;
    }


    /// <inheritdoc/>
    public bool LessOrEqual(IReadOnlySet<TClaim> a, IReadOnlySet<TClaim> b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        return a.IsSubsetOf(b);
    }


    /// <inheritdoc/>
    public bool IsValid(IReadOnlySet<TClaim> disclosures)
    {
        ArgumentNullException.ThrowIfNull(disclosures);

        //Valid if Bottom ⊆ disclosures ⊆ Top.
        return Bottom.IsSubsetOf(disclosures) && disclosures.IsSubsetOf(Top);
    }


    /// <inheritdoc/>
    public NormalizedRequest<TClaim> NormalizeRequest(IReadOnlySet<TClaim>? requested)
    {
        if(requested is null || requested.Count == 0)
        {
            return new NormalizedRequest<TClaim>(
                SelectableClaims: new HashSet<TClaim>(_comparer),
                MandatoryClaims: new HashSet<TClaim>(_comparer),
                UnavailableClaims: new HashSet<TClaim>(_comparer));
        }

        var selectable = new HashSet<TClaim>(_comparer);
        var mandatory = new HashSet<TClaim>(_comparer);
        var unavailable = new HashSet<TClaim>(_comparer);

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