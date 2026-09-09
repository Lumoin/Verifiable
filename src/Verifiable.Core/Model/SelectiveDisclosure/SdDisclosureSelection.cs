using System;
using System.Collections.Generic;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Bridges a parsed <see cref="SdToken{TEnvelope}"/>'s <see cref="SdDisclosurePaths"/> to the
/// <see cref="CredentialPath"/>-based lattice operations for selective disclosure computation.
/// </summary>
/// <remarks>
/// <para>
/// Every operation here reads the disclosure/path map the format-specific leaf computed at
/// parse time (<c>Verifiable.Json.SdJwtPathExtraction</c> for SD-JWT,
/// <c>Verifiable.Cbor.SdCwtPathExtraction</c> for SD-CWT) — the same path a nested disclosure
/// resolves to for selection, for the DCQL available-path set, and for the verifier's
/// disclosed-claims map. No site here synthesizes a path from a leaf claim name: the same
/// name legitimately recurs at different depths with independent salts per
/// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901</see> §9.3, so only the walk
/// over the signed payload can tell two occurrences apart.
/// </para>
/// </remarks>
public static class SdDisclosureSelection
{
    /// <summary>
    /// Creates a disclosure lattice from a token's resolved disclosure paths.
    /// </summary>
    /// <param name="disclosurePaths">The token's resolved disclosure/path map.</param>
    /// <param name="mandatoryPaths">Paths to claims that must always be disclosed.</param>
    /// <returns>A bounded lattice for disclosure selection.</returns>
    public static SetDisclosureLattice<CredentialPath> CreateLattice(
        SdDisclosurePaths disclosurePaths,
        IEnumerable<CredentialPath>? mandatoryPaths = null)
    {
        ArgumentNullException.ThrowIfNull(disclosurePaths);

        var mandatory = mandatoryPaths is not null
            ? new HashSet<CredentialPath>(mandatoryPaths)
            : [];

        return new SetDisclosureLattice<CredentialPath>(disclosurePaths.Paths, mandatory, ancestors: CredentialPath.Ancestry);
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

        return new SetDisclosureLattice<CredentialPath>(allPaths, mandatory, ancestors: CredentialPath.Ancestry);
    }


    /// <summary>
    /// Selects disclosures based on the selected <see cref="CredentialPath"/> set
    /// from the lattice computation.
    /// </summary>
    /// <param name="disclosurePaths">The token's resolved disclosure/path map.</param>
    /// <param name="selectedPaths">Paths selected by the lattice operation.</param>
    /// <returns>The disclosures at the selected paths.</returns>
    public static IReadOnlyList<SdDisclosure> SelectDisclosures(
        SdDisclosurePaths disclosurePaths,
        IReadOnlySet<CredentialPath> selectedPaths)
    {
        ArgumentNullException.ThrowIfNull(disclosurePaths);
        ArgumentNullException.ThrowIfNull(selectedPaths);

        var result = new List<SdDisclosure>();
        foreach(CredentialPath path in selectedPaths)
        {
            if(disclosurePaths.TryGetDisclosure(path, out SdDisclosure? disclosure))
            {
                result.Add(disclosure);
            }
        }

        return result;
    }


    /// <summary>
    /// Computes the optimal disclosure selection for a presentation.
    /// </summary>
    /// <param name="disclosurePaths">The token's resolved disclosure/path map.</param>
    /// <param name="verifierRequestedPaths">Paths requested by the verifier.</param>
    /// <param name="userExcludedPaths">Paths the user wants to exclude.</param>
    /// <param name="mandatoryPaths">Paths that must always be disclosed.</param>
    /// <returns>
    /// A tuple containing the selected disclosures and whether all requirements were satisfied.
    /// </returns>
    public static (IReadOnlyList<SdDisclosure> Disclosures, bool SatisfiesRequirements) SelectOptimal(
        SdDisclosurePaths disclosurePaths,
        IEnumerable<CredentialPath>? verifierRequestedPaths = null,
        IEnumerable<CredentialPath>? userExcludedPaths = null,
        IEnumerable<CredentialPath>? mandatoryPaths = null)
    {
        ArgumentNullException.ThrowIfNull(disclosurePaths);

        var lattice = CreateLattice(disclosurePaths, mandatoryPaths);

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

        var selectedDisclosures = SelectDisclosures(disclosurePaths, result.SelectedClaims);

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
}
