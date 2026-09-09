using System.Diagnostics;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// The request-derived inputs the verifier hands to an
/// <see cref="AssessVpDisclosureDelegate"/>: the DCQL credential query the presentation answered
/// and the verified credential's claims, disclosures, type, issuer, and trust evidence.
/// </summary>
/// <remarks>
/// <para>
/// The view is format-neutral so the seam stays a single uniform drop-out across
/// every credential format — the per-format parse step (SD-JWT/mdoc/SD-CWT
/// <c>VerifyAsync</c>) reduces its parsed credential to <see cref="Credential"/>. The
/// application feeds <see cref="Credential"/>'s path/value maps to
/// <c>DcqlDisclosure.ComputeStrategyAsync</c> through a
/// <c>DisclosedClaimsDcqlAdapter</c>; the query's <see cref="CredentialQuery.Format"/>
/// is the format the adapter must report.
/// </para>
/// </remarks>
[DebuggerDisplay("Assess(Query={CredentialQuery.Id}, Disclosed={Credential.Disclosed.Count})")]
public sealed record Oid4VpDisclosureAssessmentContext
{
    /// <summary>The DCQL credential query the presentation answered.</summary>
    public required CredentialQuery CredentialQuery { get; init; }

    /// <summary>The verified credential's claims, disclosures, type, issuer, and trust evidence.</summary>
    public required VpCredentialClaims Credential { get; init; }
}
