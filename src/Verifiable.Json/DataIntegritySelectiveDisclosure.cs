using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.Json;

/// <summary>
/// Computes the minimal set of credential paths to disclose for a Data Integrity credential by
/// routing the request through the shared, query-language-neutral selective-disclosure engine
/// (<see cref="DisclosureComputation{TCredential}"/>).
/// </summary>
/// <remarks>
/// <para>
/// This is the bridge that lets ecdsa-sd-2023 derivation (<c>DeriveProofAsync</c>) be driven by
/// the same disclosure engine SD-JWT, mdoc, and SD-CWT use, while staying free of any
/// presentation-protocol coupling. The "request" is a plain set of
/// <see cref="CredentialPath"/> values — it may originate from DCQL, a DIF Presentation
/// Definition, or a manual selection; this helper neither knows nor cares. DCQL is therefore an
/// optional front-end that can produce the same path set, not a dependency.
/// </para>
/// <para>
/// The credential's full claim surface is enumerated from its serialized form
/// (<see cref="JsonPointerPaths.EnumerateAll"/>), excluding the structural <c>proof</c> and
/// <c>@context</c> members which are never selectively disclosed claims. Giving the engine the
/// complete available-path set is what lets it trim disclosure to required + mandatory and
/// reject over-disclosure. The returned <see cref="CredentialPath"/> set feeds directly into
/// <c>DeriveProofAsync</c>, which maps the JSON-Pointer paths to N-Quad statements internally.
/// </para>
/// </remarks>
public static class DataIntegritySelectiveDisclosure
{
    //A stable identifier for the single-credential disclosure requirement. The engine uses it
    //to correlate the match with its decision; it carries no protocol meaning.
    private const string DisclosureRequirementId = "data-integrity-disclosure";


    /// <summary>
    /// Runs the neutral disclosure engine for a single Data Integrity credential and returns the
    /// minimal set of paths to disclose (required + mandatory, over-disclosure trimmed away).
    /// </summary>
    /// <param name="credential">The base-secured credential to derive a disclosure from.</param>
    /// <param name="requestedPaths">The paths the verifier asked for (any front-end may produce these).</param>
    /// <param name="mandatoryPaths">Paths that must always be disclosed (the base proof's mandatory pointers).</param>
    /// <param name="serialize">Delegate that serializes the credential, used to enumerate its claim surface.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The paths the engine selected for disclosure; empty when the request cannot be satisfied.</returns>
    public static async Task<IReadOnlySet<CredentialPath>> ComputeDisclosurePathsAsync(
        DataIntegritySecuredCredential credential,
        IReadOnlySet<CredentialPath> requestedPaths,
        IReadOnlySet<CredentialPath> mandatoryPaths,
        CredentialSerializeDelegate serialize,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(requestedPaths);
        ArgumentNullException.ThrowIfNull(mandatoryPaths);
        ArgumentNullException.ThrowIfNull(serialize);

        var availablePaths = EnumerateClaimPaths(credential, serialize);

        var match = new DisclosureMatch<DataIntegritySecuredCredential>
        {
            Credential = credential,
            QueryRequirementId = DisclosureRequirementId,
            RequiredPaths = requestedPaths,
            MatchedPaths = requestedPaths,
            AllAvailablePaths = availablePaths,
            MandatoryPaths = mandatoryPaths,

            //Format is a downstream-encoding hint only; the engine is format-neutral and
            //ecdsa-sd derivation does not read it, so it is left unset to avoid any coupling.
            Format = null
        };

        var computation = new DisclosureComputation<DataIntegritySecuredCredential>();
        var graph = await computation.ComputeAsync([match], cancellationToken: cancellationToken).ConfigureAwait(false);

        return graph.Decisions.Count > 0
            ? graph.Decisions[0].SelectedPaths
            : new HashSet<CredentialPath>();
    }


    //Enumerates the credential's disclosable claim paths from its serialized form, excluding the
    //structural proof and @context members.
    private static HashSet<CredentialPath> EnumerateClaimPaths(DataIntegritySecuredCredential credential, CredentialSerializeDelegate serialize)
    {
        var json = serialize(credential);
        using var document = JsonDocument.Parse(json);

        var claimPaths = new HashSet<CredentialPath>();
        foreach(var path in JsonPointerPaths.EnumerateAll(document.RootElement))
        {
            if(IsUnder(path, "proof") || IsUnder(path, "@context"))
            {
                continue;
            }

            claimPaths.Add(path);
        }

        return claimPaths;
    }


    private static bool IsUnder(CredentialPath path, string rootSegment)
    {
        var pointer = path.ToJsonPointerString();
        var root = "/" + rootSegment;

        return pointer == root || pointer.StartsWith(root + "/", StringComparison.Ordinal);
    }
}
