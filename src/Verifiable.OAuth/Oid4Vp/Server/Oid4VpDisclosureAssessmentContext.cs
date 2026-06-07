using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// The request-derived inputs the verifier hands to an
/// <see cref="AssessVpDisclosureDelegate"/>: the DCQL credential query the
/// presentation answered and the claims it actually disclosed, keyed by their
/// concrete <see cref="CredentialPath"/> (full path — SD-JWT/SD-CWT
/// <c>/claimName</c>, mdoc <c>/{namespace}/{elementIdentifier}</c>) with the
/// native disclosed value.
/// </summary>
/// <remarks>
/// <para>
/// The view is format-neutral so the seam stays a single uniform drop-out across
/// every credential format — the per-format parse step (SD-JWT/mdoc/SD-CWT
/// <c>VerifyAsync</c>) reduces its parsed credential to this path/value map. The
/// application feeds it to <c>DcqlDisclosure.ComputeStrategyAsync</c> through a
/// <c>DisclosedClaimsDcqlAdapter</c>; the query's <see cref="CredentialQuery.Format"/>
/// is the format the adapter must report.
/// </para>
/// </remarks>
[DebuggerDisplay("Assess(Query={CredentialQuery.Id}, Disclosed={DisclosedClaims.Count})")]
public sealed record Oid4VpDisclosureAssessmentContext
{
    /// <summary>The DCQL credential query the presentation answered.</summary>
    public required CredentialQuery CredentialQuery { get; init; }

    /// <summary>The disclosed claims, keyed by full canonical path, with their native values.</summary>
    public required IReadOnlyDictionary<CredentialPath, object?> DisclosedClaims { get; init; }

    /// <summary>
    /// The verified credential issuer identifier (the SD-JWT <c>iss</c> the verifier
    /// resolved to find the issuer signing key), or <see langword="null"/> when the
    /// format does not surface a string issuer. The application's seam supplies this to
    /// the Core metadata extractor (<c>CreateMetadataExtractor(format, issuer: …)</c>) so
    /// <see cref="Verifiable.Core.Dcql.DcqlEvaluator"/> can enforce a
    /// <see cref="CredentialQuery.TrustedAuthorities"/>
    /// constraint; with no issuer the evaluator skips that check (it cannot fail-closed on
    /// an authority it was never given), so omitting this silently disables
    /// <c>trusted_authorities</c> enforcement.
    /// </summary>
    public string? Issuer { get; init; }
}
