namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// The verifier pipeline's disclosure-assessment drop-out — the mirror of the
/// wallet's <c>ProduceVpTokenPresentationsDelegate</c>.
/// </summary>
/// <remarks>
/// <para>
/// Given the DCQL credential query and the claims a presentation actually
/// disclosed (<see cref="Oid4VpDisclosureAssessmentContext"/>), the application
/// runs the wirable Core disclosure engine —
/// <c>DcqlDisclosure.ComputeStrategyAsync</c> over a
/// <c>DisclosedClaimsDcqlAdapter</c> — and reports whether the disclosure satisfies
/// the query and whether it disclosed more than was asked. Behind this seam the
/// application references the engine assembly freely; <c>Verifiable.OAuth</c> only
/// defines the seam and reads the two booleans onto the
/// <see cref="Verifiable.OAuth.Validation.ValidationContext"/> for the
/// <c>CheckDcqlSatisfaction</c> / <c>CheckNoOverDisclosure</c> rules. This keeps
/// the library free of the DCQL/disclosure engine, exactly as the wallet client is
/// free of the credential-format primitives.
/// </para>
/// </remarks>
/// <param name="context">The credential query and the disclosed claims to assess.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The satisfaction and over-disclosure verdict.</returns>
public delegate System.Threading.Tasks.ValueTask<Oid4VpDisclosureAssessment> AssessVpDisclosureDelegate(
    Oid4VpDisclosureAssessmentContext context,
    System.Threading.CancellationToken cancellationToken);
