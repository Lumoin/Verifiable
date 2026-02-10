using System;
using System.Collections.Generic;
using Verifiable.JCose.Sd;
using JsonPointerType = Verifiable.JsonPointer.JsonPointer;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Bridges SD-JWT and SD-CWT disclosure types to the <see cref="CredentialPath"/>-based
/// lattice operations for selective disclosure computation.
/// </summary>
/// <remarks>
/// <para>
/// SD-JWT and SD-CWT disclosures are <c>(salt, claim_name, value)</c> triples.
/// Each disclosure maps to a <see cref="CredentialPath"/> via its claim name or
/// JSON Pointer location. This class performs that mapping and provides convenience
/// methods for lattice construction, optimal selection, and digest validation.
/// </para>
/// <para>
/// <strong>Claim name mapping:</strong> A disclosure with claim name <c>"given_name"</c>
/// maps to <c>CredentialPath.FromJsonPointer("/given_name")</c>. For nested disclosures
/// accessed via JSON Pointers, the pointer maps directly (e.g., <c>"/address/city"</c>).
/// For array element disclosures that have no claim name, a synthetic pointer is
/// generated from the array index.
/// </para>
/// </remarks>
public static class SdDisclosureSelection
{
    /// <summary>
    /// Creates a disclosure lattice from a set of available disclosures.
    /// </summary>
    /// <param name="allDisclosures">All disclosures available from the issuer.</param>
    /// <param name="mandatoryPaths">Paths to claims that must always be disclosed.</param>
    /// <returns>A bounded lattice for disclosure selection.</returns>
    public static SetDisclosureLattice<CredentialPath> CreateLattice(
        IReadOnlyList<SdDisclosure> allDisclosures,
        IEnumerable<CredentialPath>? mandatoryPaths = null)
    {
        ArgumentNullException.ThrowIfNull(allDisclosures);

        var allPaths = new HashSet<CredentialPath>();
        for(int i = 0; i < allDisclosures.Count; i++)
        {
            allPaths.Add(DisclosureToPath(allDisclosures[i], i));
        }

        var mandatory = mandatoryPaths is not null
            ? new HashSet<CredentialPath>(mandatoryPaths)
            : [];

        return new SetDisclosureLattice<CredentialPath>(allPaths, mandatory);
    }


    /// <summary>
    /// Creates a disclosure lattice from disclosures keyed by JSON Pointer paths.
    /// </summary>
    /// <param name="allDisclosures">All disclosures with their JSON Pointer paths.</param>
    /// <param name="mandatoryPaths">Paths to claims that must always be disclosed.</param>
    /// <returns>A bounded lattice for disclosure selection.</returns>
    public static SetDisclosureLattice<CredentialPath> CreateLatticeWithPointers(
        IReadOnlyDictionary<string, SdDisclosure> allDisclosures,
        IEnumerable<CredentialPath>? mandatoryPaths = null)
    {
        ArgumentNullException.ThrowIfNull(allDisclosures);

        var allPaths = new HashSet<CredentialPath>();
        foreach(var pointer in allDisclosures.Keys)
        {
            allPaths.Add(CredentialPath.FromJsonPointer(pointer));
        }

        var mandatory = mandatoryPaths is not null
            ? new HashSet<CredentialPath>(mandatoryPaths)
            : [];

        return new SetDisclosureLattice<CredentialPath>(allPaths, mandatory);
    }


    /// <summary>
    /// Selects disclosures based on the selected <see cref="CredentialPath"/> set
    /// from the lattice computation.
    /// </summary>
    /// <param name="allDisclosures">All available disclosures.</param>
    /// <param name="selectedPaths">Paths selected by the lattice operation.</param>
    /// <returns>The filtered list of disclosures to include in the presentation.</returns>
    public static IReadOnlyList<SdDisclosure> SelectDisclosures(
        IReadOnlyList<SdDisclosure> allDisclosures,
        IReadOnlySet<CredentialPath> selectedPaths)
    {
        ArgumentNullException.ThrowIfNull(allDisclosures);
        ArgumentNullException.ThrowIfNull(selectedPaths);

        var result = new List<SdDisclosure>();
        for(int i = 0; i < allDisclosures.Count; i++)
        {
            var path = DisclosureToPath(allDisclosures[i], i);
            if(selectedPaths.Contains(path))
            {
                result.Add(allDisclosures[i]);
            }
        }

        return result;
    }


    /// <summary>
    /// Selects disclosures from a pointer-keyed dictionary based on the selected path set.
    /// </summary>
    /// <param name="allDisclosures">All disclosures with their JSON Pointer paths.</param>
    /// <param name="selectedPaths">Paths selected by the lattice operation.</param>
    /// <returns>The filtered list of disclosures to include in the presentation.</returns>
    public static IReadOnlyList<SdDisclosure> SelectDisclosuresByPointer(
        IReadOnlyDictionary<string, SdDisclosure> allDisclosures,
        IReadOnlySet<CredentialPath> selectedPaths)
    {
        ArgumentNullException.ThrowIfNull(allDisclosures);
        ArgumentNullException.ThrowIfNull(selectedPaths);

        var result = new List<SdDisclosure>();
        foreach(var (pointer, disclosure) in allDisclosures)
        {
            var path = CredentialPath.FromJsonPointer(pointer);
            if(selectedPaths.Contains(path))
            {
                result.Add(disclosure);
            }
        }

        return result;
    }


    /// <summary>
    /// Computes the optimal disclosure selection for a presentation.
    /// </summary>
    /// <param name="allDisclosures">All available disclosures.</param>
    /// <param name="verifierRequestedPaths">Paths requested by the verifier.</param>
    /// <param name="userExcludedPaths">Paths the user wants to exclude.</param>
    /// <param name="mandatoryPaths">Paths that must always be disclosed.</param>
    /// <returns>
    /// A tuple containing the selected disclosures and whether all requirements were satisfied.
    /// </returns>
    public static (IReadOnlyList<SdDisclosure> Disclosures, bool SatisfiesRequirements) SelectOptimal(
        IReadOnlyList<SdDisclosure> allDisclosures,
        IEnumerable<CredentialPath>? verifierRequestedPaths = null,
        IEnumerable<CredentialPath>? userExcludedPaths = null,
        IEnumerable<CredentialPath>? mandatoryPaths = null)
    {
        ArgumentNullException.ThrowIfNull(allDisclosures);

        var lattice = CreateLattice(allDisclosures, mandatoryPaths);

        var requested = verifierRequestedPaths is not null
            ? new HashSet<CredentialPath>(verifierRequestedPaths)
            : null;

        var excluded = userExcludedPaths is not null
            ? new HashSet<CredentialPath>(userExcludedPaths)
            : null;

        var result = SelectiveDisclosure.ComputeOptimalDisclosure(
            lattice,
            verifierRequested: requested,
            userExclusions: excluded);

        var selectedDisclosures = SelectDisclosures(allDisclosures, result.SelectedClaims);

        return (selectedDisclosures, result.SatisfiesRequirements);
    }


    /// <summary>
    /// Validates that disclosed claims match the expected digests in the token payload.
    /// </summary>
    /// <param name="disclosures">The disclosures to validate.</param>
    /// <param name="expectedDigests">The digests from the <c>_sd</c> array in the payload.</param>
    /// <param name="computeDigest">Function to compute digest from encoded disclosure.</param>
    /// <param name="encodeDisclosure">Function to encode disclosure to wire format.</param>
    /// <returns><see langword="true"/> if all disclosed claims have matching digests.</returns>
    public static bool ValidateDisclosureDigests(
        IReadOnlyList<SdDisclosure> disclosures,
        IReadOnlySet<string> expectedDigests,
        Func<string, string> computeDigest,
        Func<SdDisclosure, string> encodeDisclosure)
    {
        ArgumentNullException.ThrowIfNull(disclosures);
        ArgumentNullException.ThrowIfNull(expectedDigests);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(encodeDisclosure);

        foreach(var disclosure in disclosures)
        {
            var encoded = encodeDisclosure(disclosure);
            var digest = computeDigest(encoded);

            if(!expectedDigests.Contains(digest))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Maps an <see cref="SdDisclosure"/> to its <see cref="CredentialPath"/>.
    /// </summary>
    /// <param name="disclosure">The disclosure to map.</param>
    /// <param name="arrayIndex">The index used for synthetic paths when the disclosure has no claim name.</param>
    /// <returns>The credential path for this disclosure.</returns>
    private static CredentialPath DisclosureToPath(SdDisclosure disclosure, int arrayIndex)
    {
        if(disclosure.ClaimName is not null)
        {
            return CredentialPath.FromJsonPointer($"/{JsonPointerType.Escape(disclosure.ClaimName)}");
        }

        //Array element disclosure without a claim name: synthetic path.
        return CredentialPath.FromJsonPointer($"/[{arrayIndex}]");
    }
}