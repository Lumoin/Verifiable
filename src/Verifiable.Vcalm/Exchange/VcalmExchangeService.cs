using System.Diagnostics;
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
[DebuggerDisplay("VcalmExchangeService")]
public static class VcalmExchangeService
{
    /// <summary>
    /// Verifies a holder <c>verifiablePresentation</c> presented during a §3.6.5 step against the
    /// active request's bound <paramref name="expectedChallenge"/> / <paramref name="expectedDomain"/>,
    /// composing the §3.3.2 presentation-proof verifier. Returns whether the presentation is acceptable
    /// (a verified proof with the bound anti-replay values). A <see langword="null"/> verification
    /// configuration fails closed (the presentation cannot be asserted authentic).
    /// </summary>
    /// <param name="presentation">The presented embedded-secured presentation.</param>
    /// <param name="expectedChallenge">The challenge the engine bound the request to.</param>
    /// <param name="expectedDomain">The domain the engine bound the request to.</param>
    /// <param name="verification">The application-supplied Data Integrity verify seams, or <see langword="null"/> (fail-closed).</param>
    /// <param name="context">The per-request context threaded to the DID resolver and canonicalizer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<bool> VerifyPresentationAsync(
        DataIntegritySecuredPresentation presentation,
        string expectedChallenge,
        string expectedDomain,
        VcalmCredentialVerification? verification,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(context);

        VcalmPresentationProofResult result = await VcalmVerificationService.VerifyPresentationProofAsync(
            presentation,
            expectedChallenge,
            expectedDomain,
            verification,
            context,
            cancellationToken).ConfigureAwait(false);

        return result.Verified;
    }


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
            sb.Append('{');
            bool first = true;

            //§3.4.1: query is the REQUIRED member; it rides through raw (the deployment composed the
            //query array). challenge / domain are the §3.4.1 anti-replay members the engine binds.
            JsonAppender.AppendRawField(sb, VcalmParameterNames.Query, queryJson, ref first);
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Challenge, challenge, ref first);
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Domain, domain, ref first);

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }
}
