using System;
using System.Collections.Generic;
using Verifiable.JCose.Sd;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Helpers for selecting disclosures in SD-JWT and SD-CWT presentations.
/// </summary>
/// <remarks>
/// <para>
/// This class bridges the wallet disclosure lattice operations with the
/// concrete disclosure types used in SD-JWT and SD-CWT.
/// </para>
/// </remarks>
public static class SdDisclosureSelection
{
    /// <summary>
    /// Creates a disclosure lattice from a set of available disclosures.
    /// </summary>
    /// <param name="allDisclosures">All disclosures available from the issuer.</param>
    /// <param name="mandatoryClaimNames">Names of claims that must always be disclosed.</param>
    /// <returns>A bounded lattice for disclosure selection.</returns>
    /// <remarks>
    /// <para>
    /// The lattice uses claim names as the element type. For array element disclosures
    /// (which have no claim name), a synthetic identifier is generated.
    /// </para>
    /// </remarks>
    public static SetDisclosureLattice<string> CreateLattice(
        IReadOnlyList<SdDisclosure> allDisclosures,
        IEnumerable<string>? mandatoryClaimNames = null)
    {
        ArgumentNullException.ThrowIfNull(allDisclosures);

        var allClaims = new HashSet<string>();
        for(int i = 0; i < allDisclosures.Count; i++)
        {
            var disclosure = allDisclosures[i];
            var claimId = disclosure.ClaimName ?? $"[{i}]";
            allClaims.Add(claimId);
        }

        var mandatory = mandatoryClaimNames is not null
            ? new HashSet<string>(mandatoryClaimNames)
            : [];

        return new SetDisclosureLattice<string>(allClaims, mandatory);
    }


    /// <summary>
    /// Creates a disclosure lattice using JSON pointers as claim identifiers.
    /// </summary>
    /// <param name="allDisclosures">All disclosures with their JSON pointer paths.</param>
    /// <param name="mandatoryPointers">JSON pointers to claims that must always be disclosed.</param>
    /// <returns>A bounded lattice for disclosure selection.</returns>
    public static SetDisclosureLattice<string> CreateLatticeWithPointers(
        IReadOnlyDictionary<string, SdDisclosure> allDisclosures,
        IEnumerable<string>? mandatoryPointers = null)
    {
        ArgumentNullException.ThrowIfNull(allDisclosures);

        var allClaims = new HashSet<string>(allDisclosures.Keys);
        var mandatory = mandatoryPointers is not null
            ? new HashSet<string>(mandatoryPointers)
            : [];

        return new SetDisclosureLattice<string>(allClaims, mandatory);
    }


    /// <summary>
    /// Selects disclosures based on the optimal disclosure set from the lattice.
    /// </summary>
    /// <param name="allDisclosures">All available disclosures.</param>
    /// <param name="selectedClaimNames">Claim names selected by the lattice operation.</param>
    /// <returns>The filtered list of disclosures to include in the presentation.</returns>
    public static IReadOnlyList<SdDisclosure> SelectDisclosures(
        IReadOnlyList<SdDisclosure> allDisclosures,
        IReadOnlySet<string> selectedClaimNames)
    {
        ArgumentNullException.ThrowIfNull(allDisclosures);
        ArgumentNullException.ThrowIfNull(selectedClaimNames);

        var result = new List<SdDisclosure>();
        for(int i = 0; i < allDisclosures.Count; i++)
        {
            var disclosure = allDisclosures[i];
            var claimId = disclosure.ClaimName ?? $"[{i}]";

            if(selectedClaimNames.Contains(claimId))
            {
                result.Add(disclosure);
            }
        }

        return result;
    }


    /// <summary>
    /// Selects disclosures using JSON pointers.
    /// </summary>
    /// <param name="allDisclosures">All disclosures with their JSON pointer paths.</param>
    /// <param name="selectedPointers">JSON pointers selected by the lattice operation.</param>
    /// <returns>The filtered list of disclosures to include in the presentation.</returns>
    public static IReadOnlyList<SdDisclosure> SelectDisclosuresByPointer(
        IReadOnlyDictionary<string, SdDisclosure> allDisclosures,
        IReadOnlySet<string> selectedPointers)
    {
        ArgumentNullException.ThrowIfNull(allDisclosures);
        ArgumentNullException.ThrowIfNull(selectedPointers);

        var result = new List<SdDisclosure>();
        foreach(var pointer in selectedPointers)
        {
            if(allDisclosures.TryGetValue(pointer, out var disclosure))
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
    /// <param name="verifierRequestedClaims">Claims requested by the verifier.</param>
    /// <param name="userExcludedClaims">Claims the user wants to exclude.</param>
    /// <param name="mandatoryClaims">Claims that must always be disclosed.</param>
    /// <returns>
    /// A tuple containing the selected disclosures and whether all requirements were satisfied.
    /// </returns>
    public static (IReadOnlyList<SdDisclosure> Disclosures, bool SatisfiesRequirements) SelectOptimal(
        IReadOnlyList<SdDisclosure> allDisclosures,
        IEnumerable<string>? verifierRequestedClaims = null,
        IEnumerable<string>? userExcludedClaims = null,
        IEnumerable<string>? mandatoryClaims = null)
    {
        ArgumentNullException.ThrowIfNull(allDisclosures);

        //Build the lattice.
        var lattice = CreateLattice(allDisclosures, mandatoryClaims);

        //Build request sets.
        var requested = verifierRequestedClaims is not null
            ? new HashSet<string>(verifierRequestedClaims)
            : null;

        var excluded = userExcludedClaims is not null
            ? new HashSet<string>(userExcludedClaims)
            : null;

        //Compute optimal.
        var result = SelectiveDisclosure.ComputeOptimalDisclosure(
            lattice,
            verifierRequested: requested,
            userExclusions: excluded);

        //Select the disclosures.
        var selectedDisclosures = SelectDisclosures(allDisclosures, result.SelectedClaims);

        return (selectedDisclosures, result.SatisfiesRequirements);
    }


    /// <summary>
    /// Validates that disclosed claims match the expected digests in the token payload.
    /// </summary>
    /// <param name="disclosures">The disclosures to validate.</param>
    /// <param name="expectedDigests">The digests from the _sd array in the payload.</param>
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
    /// Extracts claim names from a verifier's presentation request.
    /// </summary>
    /// <param name="requestedPaths">JSON paths or pointers from the request.</param>
    /// <returns>Claim names suitable for lattice operations.</returns>
    /// <remarks>
    /// <para>
    /// Converts JSON pointers like "/credentialSubject/name" to claim names like "name".
    /// </para>
    /// </remarks>
    public static IReadOnlySet<string> ExtractClaimNames(IEnumerable<string> requestedPaths)
    {
        ArgumentNullException.ThrowIfNull(requestedPaths);

        var result = new HashSet<string>();
        foreach(var path in requestedPaths)
        {
            //Extract the last segment of a JSON pointer.
            var lastSlash = path.LastIndexOf('/');
            var claimName = lastSlash >= 0 ? path[(lastSlash + 1)..] : path;

            if(!string.IsNullOrEmpty(claimName))
            {
                result.Add(claimName);
            }
        }

        return result;
    }
}