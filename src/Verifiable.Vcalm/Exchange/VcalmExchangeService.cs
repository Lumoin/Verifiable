using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Model.DataIntegrity;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// The W3C VCALM 1.0 §3.6 exchange orchestration: it COMPOSES the §3.3.2 presentation-verify path
/// (<see cref="VcalmVerificationService.VerifyPresentationProofAsync"/>) to verify a holder
/// <c>verifiablePresentation</c> presented during a §3.6.5 vcapi step against the bound challenge /
/// domain, and composes the §3.4 VPR JSON the engine issues when it requests a presentation. It does
/// not re-roll cryptography nor decide step logic — verification seams flow in on
/// <see cref="VcalmCredentialVerification"/>, the step decision on the deployment's
/// <c>ResolveVcalmExchangeStepAsync</c> seam.
/// </summary>
public static class VcalmExchangeService
{
    /// <summary>
    /// Verifies a holder <c>verifiablePresentation</c> presented during a §3.6.5 step: its own proof
    /// against the active request's bound <paramref name="expectedChallenge"/> / <paramref name="expectedDomain"/>
    /// (composing the §3.3.2 presentation-proof verifier), then the <see cref="VcalmCredentialVerification.MaxContainedCredentials"/>
    /// bound, then "Verifying each contained verifiable credential's proof, status, and validity period(s)"
    /// through <see cref="VcalmVerificationService.VerifyContainedCredentialsAsync"/> — the same §3.3.2
    /// composition the verify endpoints use. The first of these three checks to fail decides the result,
    /// so a presentation with several failing parts is refused for the earliest one; its problem type is
    /// that of the failed check itself (a signature failure is the only case
    /// <see cref="VcalmProblemTypes.CryptographicSecurityError"/> is reported), and its detail names the
    /// failed part. A <see langword="null"/> verification configuration fails closed (the presentation
    /// cannot be asserted authentic).
    /// </summary>
    /// <param name="presentation">The presented embedded-secured presentation.</param>
    /// <param name="expectedChallenge">The challenge the engine bound the request to.</param>
    /// <param name="expectedDomain">The domain the engine bound the request to.</param>
    /// <param name="verification">The application-supplied Data Integrity verify seams, or <see langword="null"/> (fail-closed).</param>
    /// <param name="now">The verification instant the contained credentials' validity periods are measured against.</param>
    /// <param name="context">The per-request context threaded to the DID resolver and canonicalizer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The presentation on success; on failure, the failed check's own <see cref="VcalmProblemDetail"/>.</returns>
    public static async ValueTask<Result<DataIntegritySecuredPresentation, VcalmProblemDetail>> VerifyPresentationAsync(
        DataIntegritySecuredPresentation presentation,
        string expectedChallenge,
        string expectedDomain,
        VcalmCredentialVerification? verification,
        DateTimeOffset now,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(context);

        VcalmPresentationProofResult proofResult = await VcalmVerificationService.VerifyPresentationProofAsync(
            presentation,
            expectedChallenge,
            expectedDomain,
            verification,
            context,
            cancellationToken).ConfigureAwait(false);

        if(!proofResult.Verified)
        {
            return Result.Failure<DataIntegritySecuredPresentation, VcalmProblemDetail>(
                NameFailedPresentationProof(FirstError(proofResult.ProblemDetails)));
        }

        //§3.3.2: a presentation carrying more contained credentials than the exchange admits is refused
        //before any of them is verified, the same bound the verify endpoints enforce.
        int containedCount = (presentation.VerifiableCredential?.Count ?? 0) + (presentation.EnvelopedVerifiableCredential?.Count ?? 0);
        int maxContained = verification?.MaxContainedCredentials ?? VcalmCredentialVerification.DefaultMaxContainedCredentials;
        if(containedCount > maxContained)
        {
            return Result.Failure<DataIntegritySecuredPresentation, VcalmProblemDetail>(
                TooManyContainedCredentials(containedCount, maxContained));
        }

        ImmutableArray<VcalmVerificationOutcome> credentialOutcomes = await VcalmVerificationService.VerifyContainedCredentialsAsync(
            presentation, verification, resolveStatusList: null, now, context, cancellationToken).ConfigureAwait(false);

        for(int index = 0; index < credentialOutcomes.Length; ++index)
        {
            if(!credentialOutcomes[index].Verified)
            {
                return Result.Failure<DataIntegritySecuredPresentation, VcalmProblemDetail>(
                    NameFailedContainedCredential(FirstError(credentialOutcomes[index].ProblemDetails), index));
            }
        }

        return Result.Success<DataIntegritySecuredPresentation, VcalmProblemDetail>(presentation);
    }


    /// <summary>
    /// The first §3.8.1 ERROR ProblemDetail of <paramref name="problems"/>: the check's own classification of why it
    /// failed. Every failing check <see cref="VerifyPresentationAsync"/> composes reports at least one by construction.
    /// </summary>
    /// <param name="problems">The ProblemDetails of a check that failed.</param>
    private static VcalmProblemDetail FirstError(ImmutableArray<VcalmProblemDetail> problems)
    {
        foreach(VcalmProblemDetail problem in problems)
        {
            if(problem.IsError)
            {
                return problem;
            }
        }

        throw new InvalidOperationException("A failed check reported no error ProblemDetail.");
    }


    /// <summary>
    /// The <see href="https://www.w3.org/TR/vc-data-model-2.0/#problem-details">VC Data Model 2.0 §7.2</see>
    /// RANGE_ERROR for a presentation carrying more contained credentials than this exchange admits, checked
    /// before any contained credential is verified so a presentation cannot inflate an exchange's per-message
    /// verification cost past its configured bound.
    /// </summary>
    /// <param name="containedCount">The number of credentials the presentation contains.</param>
    /// <param name="maximum">The number of contained credentials this exchange accepts per presentation.</param>
    private static VcalmProblemDetail TooManyContainedCredentials(int containedCount, int maximum) =>
        VcalmProblemDetail.Error(
            VcalmProblemTypes.RangeError,
            "RANGE_ERROR",
            $"The presentation contains {containedCount.ToString(CultureInfo.InvariantCulture)} credentials, more than the "
            + $"{maximum.ToString(CultureInfo.InvariantCulture)} this exchange accepts per presentation.");


    /// <summary>
    /// Re-labels a failed presentation-proof check's <see cref="VcalmProblemDetail"/> so its detail names the
    /// presentation's own proof as the failed part, keeping the check's own <see cref="VcalmProblemDetail.Type"/>.
    /// </summary>
    /// <param name="problem">The presentation proof's own failed ProblemDetail.</param>
    private static VcalmProblemDetail NameFailedPresentationProof(VcalmProblemDetail problem) =>
        VcalmProblemDetail.Error(
            problem.Type,
            problem.Title ?? problem.Type,
            $"The presentation's own proof failed verification: {problem.Detail}");


    /// <summary>
    /// Re-labels a failed contained-credential check's <see cref="VcalmProblemDetail"/> so its detail names the
    /// failing credential by its position in the presentation's contained-credential sequence (plain credentials,
    /// then enveloped credentials, both in presentation order — the order
    /// <see cref="VcalmVerificationService.VerifyContainedCredentialsAsync"/> reports), keeping the check's own
    /// <see cref="VcalmProblemDetail.Type"/>.
    /// </summary>
    /// <param name="problem">The failing contained credential's own failed ProblemDetail.</param>
    /// <param name="index">The failing credential's zero-based position among the presentation's contained credentials.</param>
    private static VcalmProblemDetail NameFailedContainedCredential(VcalmProblemDetail problem, int index) =>
        VcalmProblemDetail.Error(
            problem.Type,
            problem.Title ?? problem.Type,
            $"The presentation's contained credential at index {index.ToString(CultureInfo.InvariantCulture)} failed verification: {problem.Detail}");


    /// <summary>
    /// Composes the verbatim §3.4 verifiable presentation request JSON the engine sends on a §3.6.5
    /// "request a presentation" reply: the step decision's <c>query</c> array (verbatim, the
    /// deployment's query JSON), plus the engine-bound anti-replay <paramref name="challenge"/> and
    /// <paramref name="domain"/> (§3.4.1). The query JSON is emitted raw so the deployment's exact
    /// query shape rides through byte-faithful.
    /// </summary>
    public static string BuildPresentationRequestJson(string queryJson, string challenge, string domain)
    {
        ArgumentException.ThrowIfNullOrEmpty(queryJson);
        ArgumentException.ThrowIfNullOrEmpty(challenge);
        ArgumentException.ThrowIfNullOrEmpty(domain);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            _ = sb.Append('{');
            bool first = true;

            //§3.4.1: query is the REQUIRED member; it rides through raw (the deployment composed the
            //query array). challenge / domain are the §3.4.1 anti-replay members the engine binds.
            JsonAppender.AppendRawField(sb, VcalmParameterNames.Query, queryJson, ref first);
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Challenge, challenge, ref first);
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Domain, domain, ref first);

            _ = sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }
}
