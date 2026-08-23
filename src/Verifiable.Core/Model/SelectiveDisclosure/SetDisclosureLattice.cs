using System;
using System.Collections.Generic;

namespace Verifiable.Core.Model.SelectiveDisclosure;


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
/// <para>
/// <strong>Structure:</strong> claims may carry a hierarchy — a JSON Pointer path has
/// ancestors, an N-Quad statement index does not — so the lattice takes it as the
/// <see cref="ClaimAncestorsDelegate{TClaim}"/> seam instead of assuming one. With the seam
/// wired, <see cref="ComputeClosure"/> and <see cref="IsValid"/> enforce upward closure:
/// a disclosed claim drags its ancestors along, because a nested element cannot be read
/// without the elements that contain it. Without the seam every claim is unrelated, so
/// closure is the mandatory floor and validity is the bounds check alone.
/// </para>
/// <para>
/// <strong>Enforcement:</strong> <see cref="Clamp"/> is the operation that turns the bounds
/// from a documented expectation into an enforced one. It maps any proposed set — including
/// one produced outside the lattice, by a policy assessor or a cross-credential optimizer —
/// onto the nearest set the lattice admits, and reports which bound the proposal crossed.
/// </para>
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
    /// The claim hierarchy this lattice closes over, or <see langword="null"/> when the claim
    /// type is flat and upward closure is the identity.
    /// </summary>
    private ClaimAncestorsDelegate<TClaim>? Ancestors { get; }


    /// <summary>
    /// Creates a new set-based disclosure lattice.
    /// </summary>
    /// <param name="allClaims">All available claims (top element).</param>
    /// <param name="mandatoryClaims">Mandatory claims (bottom element).</param>
    /// <param name="comparer">Optional equality comparer for claims.</param>
    /// <param name="ancestors">
    /// The claim hierarchy, which makes <see cref="ComputeClosure"/> and <see cref="IsValid"/>
    /// enforce upward closure. Pass <see cref="CredentialPath.Ancestry"/> for credential paths.
    /// When <see langword="null"/>, claims are treated as unrelated to one another.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when mandatory claims are not a subset of all claims.
    /// </exception>
    public SetDisclosureLattice(
        IEnumerable<TClaim> allClaims,
        IEnumerable<TClaim> mandatoryClaims,
        IEqualityComparer<TClaim>? comparer = null,
        ClaimAncestorsDelegate<TClaim>? ancestors = null)
    {
        ArgumentNullException.ThrowIfNull(allClaims);
        ArgumentNullException.ThrowIfNull(mandatoryClaims);

        Comparer = comparer ?? EqualityComparer<TClaim>.Default;
        Ancestors = ancestors;

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
    /// Computes the upward closure of the requested claims within this lattice.
    /// </summary>
    /// <param name="requestedClaims">The claims explicitly requested for disclosure.</param>
    /// <returns>
    /// The mandatory claims, the requested claims that exist in the lattice, and every ancestor
    /// of those claims that exists in the lattice. Requested claims outside
    /// <see cref="Top"/> are not in the credential and are skipped.
    /// </returns>
    /// <remarks>
    /// <para>
    /// Closure is what makes a disclosure set structurally usable: a verifier that receives
    /// a nested element without the elements containing it cannot place the value. The
    /// mandatory floor is closed as well, so the result satisfies <see cref="IsValid"/> for
    /// any input.
    /// </para>
    /// </remarks>
    public IReadOnlySet<TClaim> ComputeClosure(IEnumerable<TClaim> requestedClaims)
    {
        ArgumentNullException.ThrowIfNull(requestedClaims);

        var seeds = new HashSet<TClaim>(Bottom, Comparer);
        foreach(var claim in requestedClaims)
        {
            if(Top.Contains(claim))
            {
                seeds.Add(claim);
            }
        }

        var ancestors = Ancestors;
        if(ancestors is null)
        {
            return seeds;
        }

        var result = new HashSet<TClaim>(seeds, Comparer);
        foreach(var seed in seeds)
        {
            foreach(var ancestor in ancestors(seed))
            {
                if(Top.Contains(ancestor))
                {
                    result.Add(ancestor);
                }
            }
        }

        return result;
    }


    /// <summary>
    /// Maps a proposed disclosure set onto the nearest set this lattice admits, and reports
    /// how the proposal left the lattice.
    /// </summary>
    /// <param name="proposedClaims">The proposed disclosure set, from any source.</param>
    /// <returns>
    /// The clamped set together with the claims that had to be dropped or restored to produce it.
    /// </returns>
    /// <remarks>
    /// <para>
    /// The clamp is (proposal ∩ <see cref="Top"/>) ∪ <see cref="Bottom"/> followed by
    /// <see cref="ComputeClosure"/>, so the result always satisfies <see cref="IsValid"/>.
    /// It exists because a proposal can arrive from a component the lattice does not control —
    /// a policy assessor, a cross-credential optimizer, a model-driven reasoner — and a
    /// component that returns a set outside the bounds must not be able to widen the
    /// disclosure by doing so. The correction is not silent: the three reported sets keep the
    /// attempt in the caller's audit trail.
    /// </para>
    /// </remarks>
    public DisclosureClampResult<TClaim> Clamp(IReadOnlySet<TClaim> proposedClaims)
    {
        ArgumentNullException.ThrowIfNull(proposedClaims);

        var outOfBounds = new HashSet<TClaim>(proposedClaims, Comparer);
        outOfBounds.ExceptWith(Top);

        var restoredMandatory = new HashSet<TClaim>(Bottom, Comparer);
        restoredMandatory.ExceptWith(proposedClaims);

        var clamped = ComputeClosure(proposedClaims);

        //Whatever the closure added beyond the proposal and the mandatory floor is an ancestor
        //it pulled in, which keeps the three reported sets disjoint.
        var restoredAncestors = new HashSet<TClaim>(clamped, Comparer);
        restoredAncestors.ExceptWith(proposedClaims);
        restoredAncestors.ExceptWith(Bottom);

        return new DisclosureClampResult<TClaim>
        {
            ClampedClaims = clamped,
            OutOfBoundsClaims = outOfBounds.Count > 0 ? outOfBounds : null,
            RestoredMandatoryClaims = restoredMandatory.Count > 0 ? restoredMandatory : null,
            RestoredAncestorClaims = restoredAncestors.Count > 0 ? restoredAncestors : null
        };
    }


    /// <summary>
    /// Determines whether a disclosure set is structurally valid in this lattice: it lies within
    /// the bounds (Bottom is a subset of disclosures which is a subset of Top) and it is upward-closed.
    /// </summary>
    /// <param name="disclosures">The disclosure set to check.</param>
    /// <returns><see langword="true"/> when the set is one the lattice admits.</returns>
    /// <remarks>
    /// <para>
    /// This is the structural oracle for a disclosure set: it holds the mandatory floor, stays
    /// under the available ceiling, and carries the ancestors of everything it names. Upward
    /// closure is checked only against ancestors the lattice knows, since an ancestor absent
    /// from <see cref="Top"/> is not disclosable at all. Every set <see cref="Clamp"/> and
    /// <see cref="ComputeClosure"/> produce satisfies this predicate.
    /// </para>
    /// </remarks>
    public bool IsValid(IReadOnlySet<TClaim> disclosures)
    {
        ArgumentNullException.ThrowIfNull(disclosures);

        //Valid if Bottom ⊆ disclosures ⊆ Top.
        if(!Bottom.IsSubsetOf(disclosures) || !disclosures.IsSubsetOf(Top))
        {
            return false;
        }

        var ancestors = Ancestors;
        if(ancestors is null)
        {
            return true;
        }

        foreach(var claim in disclosures)
        {
            foreach(var ancestor in ancestors(claim))
            {
                if(Top.Contains(ancestor) && !disclosures.Contains(ancestor))
                {
                    return false;
                }
            }
        }

        return true;
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
