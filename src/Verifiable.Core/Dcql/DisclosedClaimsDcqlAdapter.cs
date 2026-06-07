using System;
using System.Collections.Generic;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.Core.Dcql;

/// <summary>
/// A format-neutral <see cref="DcqlEvaluator"/> adapter over a set of
/// already-disclosed claims keyed by their concrete <see cref="CredentialPath"/>.
/// </summary>
/// <remarks>
/// <para>
/// Where the per-format adapters (<c>SdTokenDcqlAdapter</c>, <c>MdocDcqlAdapter</c>)
/// read a parsed credential to decide what <em>could</em> be disclosed, this reads
/// the flat view a verifier reconstructs from the wire — exactly what <em>was</em>
/// disclosed. It lets the verifier run the same
/// <see cref="DcqlDisclosure.ComputeStrategyAsync{TCredential}"/> engine path over
/// the disclosed claims to derive DCQL satisfaction (<c>graph.Satisfied</c>) and
/// over-disclosure (disclosed paths minus the engine's selected paths), instead of
/// hand-rolling a containment check.
/// </para>
/// <para>
/// The disclosed values are carried as <see cref="object"/> so the evaluator's
/// claim-value constraint checks (<c>ClaimsQuery.Values</c>) operate on the native
/// value where the parse step preserved it.
/// </para>
/// </remarks>
public static class DisclosedClaimsDcqlAdapter
{
    /// <summary>
    /// Builds a metadata extractor whose <see cref="DcqlCredentialMetadata.AvailablePaths"/>
    /// are exactly the disclosed paths. <see cref="DcqlCredentialMetadata.Format"/> /
    /// <see cref="DcqlCredentialMetadata.CredentialType"/> /
    /// <see cref="DcqlCredentialMetadata.Issuer"/> come from the supplied values — the
    /// verifier knows them from the per-format parse and trust resolution. The format
    /// MUST equal the credential query's <c>format</c> or the evaluator reports a
    /// format mismatch.
    /// </summary>
    public static DcqlMetadataExtractor<IReadOnlyDictionary<CredentialPath, object?>> CreateMetadataExtractor(
        string format,
        string? credentialType = null,
        string? issuer = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(format);

        return disclosed =>
        {
            ArgumentNullException.ThrowIfNull(disclosed);

            return new DcqlCredentialMetadata
            {
                Format = format,
                CredentialType = credentialType,
                Issuer = issuer,
                AvailablePaths = new HashSet<CredentialPath>(disclosed.Keys)
            };
        };
    }


    /// <summary>
    /// Extracts the disclosed value at a concrete claim pattern. Wildcard patterns
    /// return <see langword="false"/> — DCQL wildcard expansion resolves to concrete
    /// paths through <see cref="DcqlPathResolver"/> before the extractor is invoked.
    /// </summary>
    public static bool ClaimExtractor(
        IReadOnlyDictionary<CredentialPath, object?> disclosed,
        DcqlClaimPattern pattern,
        out object? value)
    {
        ArgumentNullException.ThrowIfNull(disclosed);
        ArgumentNullException.ThrowIfNull(pattern);

        if(pattern.TryResolve(out CredentialPath path) && disclosed.TryGetValue(path, out value))
        {
            return true;
        }

        value = null;
        return false;
    }
}
