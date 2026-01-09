using System;
using System.Collections.Generic;
using System.Linq;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Lattice operations on credential paths for selective disclosure decisions.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Mathematical Foundation:</strong>
/// </para>
/// <para>
/// Valid disclosure path sets form a bounded lattice under the subset ordering:
/// </para>
/// <code>
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                         Path Lattice Structure                          │
/// ├─────────────────────────────────────────────────────────────────────────┤
/// │                                                                         │
/// │                           ┌─────────┐                                   │
/// │                           │   All   │  ⊤ (top) - all paths disclosed    │
/// │                           └────┬────┘                                   │
/// │                                │                                        │
/// │              ┌─────────────────┼─────────────────┐                      │
/// │              │                 │                 │                      │
/// │         ┌────┴────┐       ┌────┴────┐       ┌────┴────┐                 │
/// │         │  Set A  │       │  Set B  │       │  Set C  │                 │
/// │         └────┬────┘       └────┬────┘       └────┬────┘                 │
/// │              │                 │                 │                      │
/// │              └─────────────────┼─────────────────┘                      │
/// │                                │                                        │
/// │                           ┌────┴────┐                                   │
/// │                           │Mandatory│  ⊥ (bottom) - minimum valid set  │
/// │                           └─────────┘                                   │
/// │                                                                         │
/// └─────────────────────────────────────────────────────────────────────────┘
/// </code>
/// <para>
/// <strong>Lattice Operations:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Join (∨):</strong> Least upper bound. Union of paths plus closure.
/// Use when combining requirements from multiple verifiers.
/// </description></item>
/// <item><description>
/// <strong>Meet (∧):</strong> Greatest lower bound. Intersection of paths plus mandatory.
/// Use when computing what user is willing to share vs. what verifier requests.
/// </description></item>
/// </list>
/// <para>
/// <strong>Wallet System Applications:</strong>
/// </para>
/// <code>
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                    Wallet Disclosure Workflow                           │
/// ├─────────────────────────────────────────────────────────────────────────┤
/// │                                                                         │
/// │   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐     │
/// │   │ Verifier Request│    │ User Preferences│    │ Mandatory Paths │     │
/// │   │ {name, email}   │    │ {name, phone}   │    │ {iss, type}     │     │
/// │   └────────┬────────┘    └────────┬────────┘    └────────┬────────┘     │
/// │            │                      │                      │              │
/// │            └──────────┬───────────┘                      │              │
/// │                       │                                  │              │
/// │                       ▼                                  │              │
/// │               ┌───────────────┐                          │              │
/// │               │ Meet (∧)      │                          │              │
/// │               │ {name}        │◄─────────────────────────┘              │
/// │               └───────┬───────┘                                         │
/// │                       │                                                 │
/// │                       ▼                                                 │
/// │               ┌───────────────┐                                         │
/// │               │ ComputeClosure│                                         │
/// │               │ + ancestors   │                                         │
/// │               └───────┬───────┘                                         │
/// │                       │                                                 │
/// │                       ▼                                                 │
/// │               ┌───────────────┐                                         │
/// │               │ Final Result  │                                         │
/// │               │ {iss,type,    │                                         │
/// │               │  credSubj,    │                                         │
/// │               │  name}        │                                         │
/// │               └───────────────┘                                         │
/// │                                                                         │
/// └─────────────────────────────────────────────────────────────────────────┘
/// </code>
/// <para>
/// <strong>Structural Constraints:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Upward Closure:</strong> Disclosing a nested path requires all ancestors
/// to be visible. E.g., disclosing /a/b/c requires /a/b, /a, and root to be disclosed.
/// </description></item>
/// <item><description>
/// <strong>Mandatory Inclusion:</strong> Certain paths must always be disclosed
/// (e.g., issuer, credential type).
/// </description></item>
/// </list>
/// <para>
/// <strong>Thread Safety:</strong> This class is immutable and thread-safe.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// //Create a lattice with known paths and mandatory set.
/// var allPaths = new HashSet&lt;CredentialPath&gt;
/// {
///     CredentialPath.Root,
///     CredentialPath.FromJsonPointer("/iss"),
///     CredentialPath.FromJsonPointer("/type"),
///     CredentialPath.FromJsonPointer("/credentialSubject"),
///     CredentialPath.FromJsonPointer("/credentialSubject/name"),
///     CredentialPath.FromJsonPointer("/credentialSubject/email")
/// };
///
/// var mandatory = new HashSet&lt;CredentialPath&gt;
/// {
///     CredentialPath.Root,
///     CredentialPath.FromJsonPointer("/iss"),
///     CredentialPath.FromJsonPointer("/type")
/// };
///
/// var lattice = new PathLattice(allPaths, mandatory);
///
/// //Compute what to disclose for a verifier request.
/// var request = new[] { CredentialPath.FromJsonPointer("/credentialSubject/name") };
/// var toDisclose = lattice.ComputeClosure(request);
/// //Result includes: /, /iss, /type, /credentialSubject, /credentialSubject/name
/// </code>
/// </example>
public sealed class PathLattice
{
    private readonly IReadOnlySet<CredentialPath> _allPaths;
    private readonly IReadOnlySet<CredentialPath> _mandatoryPaths;

    /// <summary>
    /// All paths known to this lattice.
    /// </summary>
    public IReadOnlySet<CredentialPath> AllPaths => _allPaths;

    /// <summary>
    /// Paths that must always be disclosed.
    /// </summary>
    public IReadOnlySet<CredentialPath> MandatoryPaths => _mandatoryPaths;


    /// <summary>
    /// Creates a new path lattice.
    /// </summary>
    /// <param name="allPaths">All paths in the credential.</param>
    /// <param name="mandatoryPaths">Paths that must always be disclosed.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when mandatory paths are not a subset of all paths.
    /// </exception>
    public PathLattice(IReadOnlySet<CredentialPath> allPaths, IReadOnlySet<CredentialPath> mandatoryPaths)
    {
        ArgumentNullException.ThrowIfNull(allPaths);
        ArgumentNullException.ThrowIfNull(mandatoryPaths);

        foreach(CredentialPath mandatory in mandatoryPaths)
        {
            if(!allPaths.Contains(mandatory))
            {
                throw new ArgumentException(
                    $"Mandatory path '{mandatory}' is not in the set of all paths.",
                    nameof(mandatoryPaths));
            }
        }

        _allPaths = allPaths;
        _mandatoryPaths = mandatoryPaths;
    }


    /// <summary>
    /// Computes the upward closure of the requested paths.
    /// </summary>
    /// <param name="requestedPaths">The paths explicitly requested for disclosure.</param>
    /// <returns>
    /// A set containing the requested paths, their ancestors, and all mandatory paths.
    /// </returns>
    /// <remarks>
    /// <para>
    /// Upward closure ensures structural validity: to disclose a nested element,
    /// all ancestor elements must also be disclosed.
    /// </para>
    /// </remarks>
    public IReadOnlySet<CredentialPath> ComputeClosure(IEnumerable<CredentialPath> requestedPaths)
    {
        ArgumentNullException.ThrowIfNull(requestedPaths);

        var result = new HashSet<CredentialPath>(_mandatoryPaths);

        foreach(CredentialPath path in requestedPaths)
        {
            if(!_allPaths.Contains(path))
            {
                continue;
            }

            //Add the path and all its ancestors.
            foreach(CredentialPath ancestor in path.SelfAndAncestors())
            {
                if(_allPaths.Contains(ancestor))
                {
                    result.Add(ancestor);
                }
            }
        }

        return result;
    }


    /// <summary>
    /// Computes the join (least upper bound) of two path sets.
    /// </summary>
    /// <param name="a">First path set.</param>
    /// <param name="b">Second path set.</param>
    /// <returns>The smallest valid set containing both inputs.</returns>
    /// <remarks>
    /// <para>
    /// Use Join when combining requirements from multiple verifiers:
    /// "Verifier A needs {name, email}, Verifier B needs {name, phone}"
    /// → Join produces {name, email, phone} (plus closure).
    /// </para>
    /// <para>
    /// Lattice properties:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Commutative: Join(a, b) = Join(b, a)</description></item>
    /// <item><description>Associative: Join(Join(a, b), c) = Join(a, Join(b, c))</description></item>
    /// <item><description>Idempotent: Join(a, a) = a</description></item>
    /// </list>
    /// </remarks>
    public IReadOnlySet<CredentialPath> Join(
        IReadOnlySet<CredentialPath> a,
        IReadOnlySet<CredentialPath> b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        var union = new HashSet<CredentialPath>(a);
        union.UnionWith(b);

        return ComputeClosure(union);
    }


    /// <summary>
    /// Computes the meet (greatest lower bound) of two path sets.
    /// </summary>
    /// <param name="a">First path set.</param>
    /// <param name="b">Second path set.</param>
    /// <returns>The largest valid set contained in both inputs.</returns>
    /// <remarks>
    /// <para>
    /// Use Meet when computing the intersection of what a verifier wants
    /// and what the user is willing to share:
    /// "Verifier wants {name, email, ssn}, User allows {name, email}"
    /// → Meet produces {name, email} (plus mandatory).
    /// </para>
    /// <para>
    /// Lattice properties:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Commutative: Meet(a, b) = Meet(b, a)</description></item>
    /// <item><description>Associative: Meet(Meet(a, b), c) = Meet(a, Meet(b, c))</description></item>
    /// <item><description>Idempotent: Meet(a, a) = a</description></item>
    /// </list>
    /// </remarks>
    public IReadOnlySet<CredentialPath> Meet(
        IReadOnlySet<CredentialPath> a,
        IReadOnlySet<CredentialPath> b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        var intersection = new HashSet<CredentialPath>(a);
        intersection.IntersectWith(b);

        //Always include mandatory paths.
        intersection.UnionWith(_mandatoryPaths);

        //Ensure closure.
        return ComputeClosure(intersection);
    }


    /// <summary>
    /// Computes the difference between two path sets.
    /// </summary>
    /// <param name="minuend">The set to subtract from.</param>
    /// <param name="subtrahend">The set to subtract.</param>
    /// <returns>Paths in minuend but not in subtrahend, plus mandatory.</returns>
    /// <remarks>
    /// Use Difference to find what additional disclosures one verifier needs
    /// compared to another.
    /// </remarks>
    public IReadOnlySet<CredentialPath> Difference(
        IReadOnlySet<CredentialPath> minuend,
        IReadOnlySet<CredentialPath> subtrahend)
    {
        ArgumentNullException.ThrowIfNull(minuend);
        ArgumentNullException.ThrowIfNull(subtrahend);

        var result = new HashSet<CredentialPath>(minuend);
        result.ExceptWith(subtrahend);
        result.UnionWith(_mandatoryPaths);

        return result;
    }


    /// <summary>
    /// Checks if one path set is a subset of another.
    /// </summary>
    /// <param name="subset">The potential subset.</param>
    /// <param name="superset">The potential superset.</param>
    /// <returns><c>true</c> if subset ⊆ superset.</returns>
    public static bool IsSubsetOf(IReadOnlySet<CredentialPath> subset, IReadOnlySet<CredentialPath> superset)
    {
        ArgumentNullException.ThrowIfNull(subset);
        ArgumentNullException.ThrowIfNull(superset);

        foreach(CredentialPath path in subset)
        {
            if(!superset.Contains(path))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Validates that a path set satisfies all structural constraints.
    /// </summary>
    /// <param name="paths">The path set to validate.</param>
    /// <returns><c>true</c> if the path set is valid.</returns>
    /// <remarks>
    /// A valid path set must:
    /// <list type="bullet">
    /// <item><description>Contain all mandatory paths.</description></item>
    /// <item><description>Contain only known paths.</description></item>
    /// <item><description>Be upward-closed (include all ancestors of included paths).</description></item>
    /// </list>
    /// </remarks>
    public bool IsValidPathSet(IReadOnlySet<CredentialPath> paths)
    {
        ArgumentNullException.ThrowIfNull(paths);

        //Check mandatory inclusion.
        foreach(CredentialPath mandatory in _mandatoryPaths)
        {
            if(!paths.Contains(mandatory))
            {
                return false;
            }
        }

        //Check known paths and upward closure.
        foreach(CredentialPath path in paths)
        {
            if(!_allPaths.Contains(path))
            {
                return false;
            }

            //Check ancestors are included.
            foreach(CredentialPath ancestor in path.Ancestors())
            {
                if(_allPaths.Contains(ancestor) && !paths.Contains(ancestor))
                {
                    return false;
                }
            }
        }

        return true;
    }


    /// <summary>
    /// Gets all paths at a specific depth.
    /// </summary>
    /// <param name="depth">The depth (0 = root).</param>
    /// <returns>Paths at the specified depth.</returns>
    public IEnumerable<CredentialPath> GetPathsAtDepth(int depth)
    {
        return _allPaths.Where(p => p.Depth == depth);
    }


    /// <summary>
    /// Gets all descendant paths of a given path.
    /// </summary>
    /// <param name="ancestor">The ancestor path.</param>
    /// <returns>All paths that are descendants of the ancestor.</returns>
    public IEnumerable<CredentialPath> GetDescendants(CredentialPath ancestor)
    {
        return _allPaths.Where(p => ancestor.IsAncestorOf(p));
    }
}