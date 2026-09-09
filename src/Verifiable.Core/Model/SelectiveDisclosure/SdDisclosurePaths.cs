using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// The concrete <see cref="CredentialPath"/> each <see cref="SdDisclosure"/> in a parsed
/// <see cref="SdToken{TEnvelope}"/> occupies in the issuer-signed structure.
/// </summary>
/// <remarks>
/// <para>
/// A disclosure's position is not a property of the disclosure itself — the same
/// <c>(salt, name, value)</c> triple carries no information about where its digest sits in
/// the issuer-signed payload, and per
/// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901</see> §9.3 the same claim name
/// legitimately recurs at different depths with independent salts. Position is a product of
/// walking the digest tree of a specific signed payload, so it is computed once, at parse time,
/// by the format-specific leaf (<c>Verifiable.Json.SdJwtPathExtraction</c> for SD-JWT,
/// <c>Verifiable.Cbor.SdCwtPathExtraction</c> for SD-CWT) and carried on the token as this type.
/// </para>
/// <para>
/// Identity here is REFERENCE identity: the map is snapshotted into a dictionary built with
/// <see cref="ReferenceEqualityComparer"/>, so a disclosure resolves to the position the walk
/// gave THAT instance. <see cref="SdDisclosure"/>'s own equality is its salt bytes, which is a
/// cryptographic-commitment notion rather than a positional one: two distinct disclosures that
/// carry the same salt would otherwise collapse into one key, and a lookup for either would
/// answer with the other's position. Because the map's keys are instances, this type carries no
/// content equality of its own — it is a plain class, deliberately not a record, so no generated
/// member can present a reference comparison as a value comparison.
/// </para>
/// </remarks>
public sealed class SdDisclosurePaths
{
    /// <summary>The snapshot the constructor took, keyed by disclosure instance.</summary>
    private Dictionary<SdDisclosure, CredentialPath> DisclosureToPath { get; }

    /// <summary>The inverse of <see cref="DisclosureToPath"/>, keyed by position.</summary>
    private Dictionary<CredentialPath, SdDisclosure> PathToDisclosure { get; }

    /// <summary>
    /// The single, shared empty instance — the default for a token that has no parsed
    /// payload to walk (an issuance-side token constructed before it has ever been signed
    /// and parsed back).
    /// </summary>
    public static SdDisclosurePaths Empty { get; } = new(new Dictionary<SdDisclosure, CredentialPath>());

    /// <summary>Every concrete path a disclosure in this map resolves to.</summary>
    public IReadOnlySet<CredentialPath> Paths { get; }

    /// <summary>The number of disclosure/path pairs this map carries.</summary>
    public int Count => DisclosureToPath.Count;


    /// <summary>
    /// Creates a disclosure/path map from the walker's digest-to-position resolution, taking a
    /// complete snapshot of <paramref name="disclosureToPath"/> into instance-keyed storage so
    /// neither later mutation of the caller's dictionary nor the comparer it was built with can
    /// change what this map answers.
    /// </summary>
    /// <param name="disclosureToPath">
    /// Each disclosure's resolved path, as produced by the format-specific path walker.
    /// </param>
    public SdDisclosurePaths(IReadOnlyDictionary<SdDisclosure, CredentialPath> disclosureToPath)
    {
        ArgumentNullException.ThrowIfNull(disclosureToPath);

        var byDisclosure = new Dictionary<SdDisclosure, CredentialPath>(ReferenceEqualityComparer.Instance);
        var pathToDisclosure = new Dictionary<CredentialPath, SdDisclosure>();
        var paths = new HashSet<CredentialPath>();
        foreach((SdDisclosure disclosure, CredentialPath path) in disclosureToPath)
        {
            byDisclosure[disclosure] = path;
            pathToDisclosure[path] = disclosure;
            paths.Add(path);
        }

        DisclosureToPath = byDisclosure;
        PathToDisclosure = pathToDisclosure;
        Paths = paths;
    }


    /// <summary>
    /// Looks up the path a disclosure resolved to, by the instance the walk placed.
    /// </summary>
    /// <param name="disclosure">The disclosure to look up.</param>
    /// <param name="path">The disclosure's path, when found.</param>
    /// <returns><see langword="true"/> when the disclosure is in this map.</returns>
    public bool TryGetPath(SdDisclosure disclosure, out CredentialPath path)
    {
        ArgumentNullException.ThrowIfNull(disclosure);

        return DisclosureToPath.TryGetValue(disclosure, out path);
    }


    /// <summary>
    /// Looks up the disclosure that resolved to a path.
    /// </summary>
    /// <param name="path">The path to look up.</param>
    /// <param name="disclosure">The disclosure at that path, when found.</param>
    /// <returns><see langword="true"/> when a disclosure resolved to that path.</returns>
    public bool TryGetDisclosure(CredentialPath path, [NotNullWhen(true)] out SdDisclosure? disclosure) =>
        PathToDisclosure.TryGetValue(path, out disclosure);


    /// <summary>
    /// Finds the disclosure position that directly encloses <paramref name="path"/> — the nearest
    /// ancestor of it that is itself a disclosure position in this map — so a node that exists only
    /// inside a disclosure's value resolves to the disclosure whose release reveals it (RFC 9901
    /// §7.2 step 2b, the disclosable ancestor a selection must carry along).
    /// </summary>
    /// <remarks>
    /// The walk is nearest-first over <see cref="CredentialPath.Parent"/>, so the position returned
    /// is the innermost enclosing disclosure — never a farther ancestor whose release would disclose
    /// more than the path requires. It is a pure query over <see cref="Paths"/>: the caller decides
    /// whether <paramref name="path"/> is a node the credential actually carries (a bare descendant
    /// of a disclosure that the credential does not carry must not resolve to its ancestor, or it
    /// would release a disclosure to pay for a claim that does not exist).
    /// </remarks>
    /// <param name="path">The path whose enclosing disclosure position is sought.</param>
    /// <param name="enclosingDisclosurePath">The nearest ancestor of <paramref name="path"/> that is a disclosure position, when one exists.</param>
    /// <returns><see langword="true"/> when a disclosure position encloses <paramref name="path"/>.</returns>
    public bool TryFindEnclosingDisclosurePath(CredentialPath path, out CredentialPath enclosingDisclosurePath)
    {
        CredentialPath? candidate = path.Parent;
        while(candidate is CredentialPath ancestor)
        {
            if(Paths.Contains(ancestor))
            {
                enclosingDisclosurePath = ancestor;

                return true;
            }

            candidate = ancestor.Parent;
        }

        enclosingDisclosurePath = CredentialPath.Root;

        return false;
    }
}
