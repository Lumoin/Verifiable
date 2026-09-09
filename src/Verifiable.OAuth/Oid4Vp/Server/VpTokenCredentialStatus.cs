using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Dcql;
using Verifiable.Core.StatusList;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Reads a presented credential's IETF Token Status List entry through the verifier-agnostic
/// <see cref="CredentialStatusGate"/> when the credential carries a <c>status.status_list</c> reference. The
/// single implementation both the OID4VP <c>direct_post</c> seat and the SIOPv2 §12 combined-response seat run,
/// so "is it still valid now?" is checked identically wherever a vp_token is verified.
/// </summary>
internal static class VpTokenCredentialStatus
{
    /// <summary>
    /// Checks <paramref name="parsed"/>'s Token Status List status, if it carries one.
    /// </summary>
    /// <param name="parsed">The already signature- and holder-binding-verified presentation.</param>
    /// <param name="credentialQueryId">
    /// The DCQL credential query identifier <paramref name="parsed"/> was presented under, named in the
    /// undeterminable-status log reason and the no-resolver configuration fault.
    /// </param>
    /// <param name="resolveVerifiedStatusListToken">
    /// The caller-supplied resolver yielding the verified Status List Token, or <see langword="null"/> when the
    /// seat was constructed without one.
    /// </param>
    /// <param name="now">The current time for the token's expiry check.</param>
    /// <param name="freshnessPolicy">
    /// The caller's Section 8.3 step 4.b freshness policy for the token's <c>iat</c>, or <see langword="null"/>
    /// to skip the check. Threaded to <see cref="CredentialStatusGate.CheckAsync"/>.
    /// </param>
    /// <param name="cachingBounds">
    /// The caller's Section 11.5 refresh-interval floor and ceiling, or <see langword="null"/> to leave the
    /// resolved token's <c>ttl</c> unclamped. Threaded to <see cref="CredentialStatusGate.CheckAsync"/>.
    /// </param>
    /// <param name="unsupportedStatusMechanisms">
    /// What to do with a status claim naming only mechanisms this library does not evaluate:
    /// <see cref="UnsupportedStatusMechanismDisposition.Refuse"/> (the seats' default) fails the presentation
    /// closed, <see cref="UnsupportedStatusMechanismDisposition.Surface"/> accepts it and leaves the mechanism
    /// names on the verified credential for the relying party's own evaluation.
    /// </param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// <see cref="CredentialStatusCheck.NotReferenced"/> when the credential carries no status claim, and when
    /// it carries one naming only unevaluable mechanisms under
    /// <see cref="UnsupportedStatusMechanismDisposition.Surface"/>;
    /// <see cref="CredentialStatusCheck.Determined"/> with the read outcome when the status was determined — a
    /// determinable revoked or suspended status is recorded here, never refused, so the relying party's
    /// <see cref="CredentialStatusPolicy"/> can act on it; <see cref="CredentialStatusCheck.Undeterminable"/>
    /// with a <see cref="VerifierFlowRefusalKind.StatusUndeterminable"/> refusal when the status could not be
    /// determined.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <paramref name="parsed"/> references a status list but <paramref name="resolveVerifiedStatusListToken"/>
    /// is <see langword="null"/>: the credential's issuer gated its validity on a list the verifier cannot read,
    /// so silently treating it as valid would be a security gap. This mirrors the mdoc / SD-CWT / disclosure
    /// seams, which likewise throw when a presented credential needs a seam the executor was not constructed
    /// with — a configuration fault, not a wire answer.
    /// </exception>
    /// <remarks>
    /// <para>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-8.3">Token Status
    /// List §8.3</see>: "Upon receiving a Referenced Token, a Relying Party MUST first perform the validation of
    /// the Referenced Token"; "If the validation was successful, the Relying Party MUST perform the following
    /// validation steps to evaluate the status of the Referenced Token" (checking for the status claim,
    /// resolving and validating the Status List Token, retrieving the status value); "If any of these checks
    /// fails, no statement about the status of the Referenced Token can be made and the Referenced Token SHOULD
    /// be rejected." The gate is run after <paramref name="parsed"/>'s own signature and holder-binding
    /// verification, matching the §8.3 ordering.
    /// </para>
    /// <para>
    /// §8.3 step 1 — "Check for the existence of a status claim, check for the existence of a status_list
    /// claim within the status claim and validate that the content of status_list adheres to the rules
    /// defined in Section 6.2 for JOSE-based Referenced Tokens and Section 6.3 for COSE-based Referenced
    /// Tokens." — is the three-way read this method dispatches on. Existence separates a credential with no
    /// status claim from one that has it; the <c>status_list</c> check separates a claim this verifier can act
    /// on from one naming only mechanisms it cannot evaluate. For the latter §8.3's closing sentence applies —
    /// "If any of these checks fails, no statement about the status of the Referenced Token can be made and
    /// the Referenced Token SHOULD be rejected." — so <paramref name="unsupportedStatusMechanisms"/> defaults
    /// to refusing it, the SHOULD being what admits the explicit
    /// <see cref="UnsupportedStatusMechanismDisposition.Surface"/> opt-out at all.
    /// </para>
    /// <para>
    /// The resolution context the gate is handed carries more than the reference: the Referenced Token's
    /// verified <c>iss</c> (<see cref="VpCredentialClaims.Issuer"/>, absent for an mdoc, which carries no
    /// issuer claim) and the key its issuer signature verified under
    /// (<see cref="VpTokenParsed.CredentialIssuerKey"/>, present on this path for every format because
    /// §8.3 runs the status step only after that signature verified). A resolver therefore reaches
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">§11.3</see>'s
    /// key-resolution recommendations — the same-key one shipped as
    /// <see cref="StatusList.StatusListIssuerKeys.FromReferencedToken"/> — instead of binding its trust to
    /// the list URI's authority. The key is borrowed for the call: the seat owns it and releases it when
    /// the flow step ends.
    /// </para>
    /// <para>
    /// Undeterminable (400 <see cref="VerifierFlowRefusalKind.StatusUndeterminable"/>): any
    /// <see cref="Core.StatusList.StatusListValidationException"/> — a subject mismatch, an expired list, an
    /// out-of-range index, or its <see cref="Core.StatusList.StatusListResolutionException"/> subtype (the
    /// resolver could not obtain the Status List Token at all, including a <see langword="null"/> return).
    /// Fault (500, not caught here): any other exception <paramref name="resolveVerifiedStatusListToken"/>
    /// throws is the resolver's own defect — a transport failure it chose not to classify as a resolution
    /// failure, a bug in its trust verification — and propagates rather than being reported to the Wallet.
    /// </para>
    /// </remarks>
    public static async ValueTask<CredentialStatusCheck> CheckAsync(
        VpTokenParsed parsed,
        CredentialQueryId credentialQueryId,
        ResolveVerifiedStatusListTokenDelegate? resolveVerifiedStatusListToken,
        DateTimeOffset now,
        StatusListFreshnessPolicy? freshnessPolicy,
        StatusListCachingBounds? cachingBounds,
        UnsupportedStatusMechanismDisposition unsupportedStatusMechanisms,
        CancellationToken cancellationToken)
    {
        if(parsed.Credential.Status is not { } statusClaim)
        {
            return CredentialStatusCheck.NotReferenced();
        }

        if(statusClaim.StatusList is not { } statusReference)
        {
            return unsupportedStatusMechanisms switch
            {
                UnsupportedStatusMechanismDisposition.Surface => CredentialStatusCheck.NotReferenced(),
                _ => RefuseUnsupportedMechanisms(credentialQueryId, statusClaim)
            };
        }

        if(resolveVerifiedStatusListToken is null)
        {
            throw new InvalidOperationException(
                $"The presented credential for credential query '{credentialQueryId}' references an IETF " +
                $"Token Status List ({statusReference}) but the verifier executor was constructed without a " +
                "status resolver. Pass resolveVerifiedStatusListToken to HaipOid4VpVerifierExecutor.Create / " +
                "CreateWithRegistry, or SiopVerifierExecutor.Register / Create, wiring the status-list fetch " +
                "and verification behind it, to enable revocation checking.");
        }

        StatusListResolutionContext resolutionContext = new()
        {
            Reference = statusReference,
            ReferencedTokenIssuer = parsed.Credential.Issuer,
            ReferencedTokenIssuerKey = parsed.CredentialIssuerKey
        };

        try
        {
            CredentialStatusOutcome outcome = await CredentialStatusGate.CheckAsync(
                resolutionContext, resolveVerifiedStatusListToken, now, freshnessPolicy, cachingBounds, cancellationToken)
                .ConfigureAwait(false);

            return CredentialStatusCheck.Determined(outcome);
        }
        catch(StatusListValidationException exception)
        {
            //A credential whose Token Status List status the Verifier cannot determine is an unverifiable
            //presentation — RFC 6749 §4.1.2.1 invalid_request. The wire-safe description does not reveal which
            //undeterminable case (OID4VP 1.0 §15.9); the cause stays in the log-only reason.
            VerifierFlowRefusal refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.StatusUndeterminable);
            string logReason =
                $"Credential status could not be determined for credential query '{credentialQueryId}': " +
                $"{exception.Message}";

            return CredentialStatusCheck.Undeterminable(refusal, logReason);
        }
    }


    /// <summary>
    /// Builds the fail-closed outcome for a status claim naming only mechanisms this library does not
    /// evaluate: no statement about the credential's status can be made, so the presentation is refused as
    /// <see cref="VerifierFlowRefusalKind.StatusUndeterminable"/> — <c>invalid_request</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>, the same
    /// refusal an unreadable status list draws. The log-only reason names the credential query and the
    /// mechanisms the issuer stated; the wire description stays the fixed, non-revealing sentence
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-15.9">OID4VP
    /// 1.0 §15.9</see> asks for.
    /// </summary>
    /// <param name="credentialQueryId">The credential query the presentation answered.</param>
    /// <param name="statusClaim">The status claim whose mechanisms are all unevaluable here.</param>
    /// <returns>The undeterminable outcome carrying the refusal and the log reason.</returns>
    private static CredentialStatusCheck RefuseUnsupportedMechanisms(
        CredentialQueryId credentialQueryId, StatusClaim statusClaim)
    {
        VerifierFlowRefusal refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.StatusUndeterminable);

        //The mechanism set has no defined iteration order, so the names are ordered ordinally before
        //they are joined: two runs over the same credential then write the same operator-log line.
        string mechanisms = string.Join(", ", statusClaim.Mechanisms.Order(StringComparer.Ordinal));
        string logReason =
            $"Credential status could not be determined for credential query '{credentialQueryId}': the " +
            $"status claim names only status mechanisms this verifier does not evaluate " +
            $"({mechanisms}).";

        return CredentialStatusCheck.Undeterminable(refusal, logReason);
    }
}
