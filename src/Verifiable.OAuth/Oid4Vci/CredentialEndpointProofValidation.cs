using System.Buffers;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.Routing;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// Enforces the OID4VCI 1.0 Appendix F.4 holder-key-proof checks at the §8 Credential Endpoint
/// BEFORE the issuance seam mints — the §8 security core. This is an OPT-IN enforcement step: it
/// runs only when the deployment wires
/// <see cref="AuthorizationServerIntegration.ResolveCredentialProofExpectationAsync"/>. When that
/// seam is unwired the endpoint behaves exactly as before — proof verification is left entirely to
/// <see cref="AuthorizationServerIntegration.IssueCredentialAsync"/>. The shape mirrors
/// <c>CredentialEndpointDpopValidation</c>: resolve the expectation, run the library validator over
/// the §8.2 <c>proofs.jwt</c> batch, and map a failure to the §8.3.1.2 error.
/// </summary>
internal static class CredentialEndpointProofValidation
{
    /// <summary>
    /// Returns the §8.3.1.2 error response to return, or <see langword="null"/> when the proofs
    /// satisfy §F.4 (or when the opt-in seam is unwired and the check is deferred to the issuance
    /// seam).
    /// </summary>
    public static async ValueTask<ServerHttpResponse?> EnforceAsync(
        AuthorizationServer server,
        ExchangeContext context,
        ClientRecord registration,
        CredentialRequest request,
        JwtPayload accessToken,
        CancellationToken cancellationToken)
    {
        //Opt-in: with no expectation seam the endpoint validates no proofs and defers to the
        //issuance seam — the established default path stays byte-for-byte unchanged.
        if(server.Integration.ResolveCredentialProofExpectationAsync is null)
        {
            return null;
        }

        CredentialProofExpectation? expectation = await server.Integration.ResolveCredentialProofExpectationAsync(
            request, accessToken, registration, context, cancellationToken).ConfigureAwait(false);
        if(expectation is null)
        {
            //A wired seam may still decline per-request (e.g. an identifier path that binds no
            //key); defer that request to the issuance seam.
            return null;
        }

        if(server.Codecs.Encoder is null || server.Codecs.Decoder is null)
        {
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "Credential proof validation is configured but the server has no base64url codecs.");
        }

        string expectedAudience = await ResolveAudienceAsync(server, registration, context, cancellationToken)
            .ConfigureAwait(false);

        request.Proofs.TryGetValue(
            Oid4VciCredentialParameterNames.JwtProofType, out IReadOnlyList<string>? jwtProofs);

        bool hasJwtProofs = jwtProofs is not null && jwtProofs.Count > 0;

        //Appendix F.2 di_vp presentations are verified through the library's W3C Data Integrity
        //surface when the deployment wired the DI seams (DiVpVerification). With the seams unwired
        //each di_vp presentation stays in DiVpProofs for the issuance seam — the parse-and-surface
        //default — so the established behaviour is unchanged.
        bool hasDiVpProofs = request.DiVpProofs.Count > 0;
        bool canVerifyDiVp = expectation.DiVpVerification is not null;

        //§8.3.1.2 invalid_proof case (1): "the field is missing". A configuration that binds a
        //holder key needs at least one key proof; the application signals that via IsProofRequired.
        //A di_vp proof the library can verify (the seam is wired) counts as a present key proof.
        if(!hasJwtProofs && !(hasDiVpProofs && canVerifyDiVp))
        {
            return expectation.IsProofRequired
                ? CredentialError(
                    Oid4VciCredentialErrors.InvalidProof,
                    "The Credential Request carries no verifiable key proof, but one is required (§8.2 / Appendix F).")
                : null;
        }

        if(hasJwtProofs)
        {
            ServerHttpResponse? jwtFailure = await ValidateJwtProofsAsync(
                server, expectation, jwtProofs!, expectedAudience, context, cancellationToken).ConfigureAwait(false);
            if(jwtFailure is not null)
            {
                return jwtFailure;
            }
        }

        //Appendix F.2: domain MUST be the Credential Issuer Identifier, challenge MUST be the
        //server-provided c_nonce. The same expectedAudience the jwt path uses as the §F.1 aud is the
        //Credential Issuer Identifier, so it doubles as the di_vp expected domain.
        if(hasDiVpProofs && canVerifyDiVp)
        {
            ServerHttpResponse? diVpFailure = await ValidateDiVpProofsAsync(
                expectation, request.DiVpProofs, expectedAudience, context, cancellationToken)
                .ConfigureAwait(false);
            if(diVpFailure is not null)
            {
                return diVpFailure;
            }
        }

        return null;
    }


    //Runs the §F.4 jwt-proof batch and maps the first failure to its §8.3.1.2 error.
    private static async ValueTask<ServerHttpResponse?> ValidateJwtProofsAsync(
        AuthorizationServer server,
        CredentialProofExpectation expectation,
        IReadOnlyList<string> jwtProofs,
        string expectedAudience,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        Func<string, bool> isAlgAcceptable = BuildAlgAcceptancePredicate(expectation.AcceptableProofSigningAlgorithms);

        //§F.1 kid/x5c key-reference resolution is opt-in: with both seams unwired the batch resolves
        //only the embedded-jwk mode, and a kid/x5c proof fails KeyReferenceUnresolved → invalid_proof.
        //The context is threaded so a network-resolving kid is fetched under its SSRF policy and the
        //x5c chain validates to the trust anchors / validity instant the application stamped on it.
        IReadOnlyList<CredentialProofValidationResult> results = await CredentialProofValidator.ValidateBatchAsync(
            jwtProofs,
            expectedAudience,
            expectation.ExpectedNonce,
            expectation.IsNonceRequired,
            isAlgAcceptable,
            expectation.KidResolver,
            expectation.X509Verification,
            context,
            server.Codecs.Encoder!,
            server.Codecs.Decoder!,
            server.TimeProvider,
            SensitiveMemoryPool<byte>.Shared,
            expectation.IatSkew,
            cancellationToken).ConfigureAwait(false);

        foreach(CredentialProofValidationResult result in results)
        {
            if(result.IsValid)
            {
                continue;
            }

            //§8.3.1.2: a nonce mismatch/absence is invalid_nonce (the Wallet retrieves a fresh
            //c_nonce); every other §F.4 failure is invalid_proof.
            return result.FailureReason is CredentialProofValidationFailureReason.NonceMissing
                or CredentialProofValidationFailureReason.NonceMismatch
                ? CredentialError(
                    Oid4VciCredentialErrors.InvalidNonce,
                    $"A jwt key proof carries an invalid c_nonce ({result.FailureReason}); retrieve a fresh one (§7).")
                : CredentialError(
                    Oid4VciCredentialErrors.InvalidProof,
                    $"A jwt key proof failed validation: {result.FailureReason} (Appendix F.4).");
        }

        return null;
    }


    //Verifies each Appendix F.2 di_vp presentation by composing the library's W3C Data Integrity
    //presentation verifier (CredentialProofValidator.ValidateDiVpAsync), binding the proof
    //challenge to the expected c_nonce and the proof domain to the Credential Issuer Identifier.
    private static async ValueTask<ServerHttpResponse?> ValidateDiVpProofsAsync(
        CredentialProofExpectation expectation,
        IReadOnlyList<string> diVpProofs,
        string credentialIssuerIdentifier,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        //Appendix F.2: challenge is "REQUIRED when the Credential Issuer has provided a c_nonce ...
        //the value is a server-provided c_nonce". A di_vp proof carries its anti-replay binding in
        //the challenge; without an expected c_nonce there is nothing to bind it to, so the server
        //cannot accept the presentation.
        if(string.IsNullOrEmpty(expectation.ExpectedNonce))
        {
            return CredentialError(
                Oid4VciCredentialErrors.InvalidNonce,
                "A di_vp key proof requires a server-provided c_nonce to bind its challenge to (§7 / Appendix F.2).");
        }

        foreach(string presentationJson in diVpProofs)
        {
            DiVpProofValidationResult result = await CredentialProofValidator.ValidateDiVpAsync(
                presentationJson,
                expectation.ExpectedNonce,
                credentialIssuerIdentifier,
                expectation.DiVpVerification!,
                context,
                cancellationToken).ConfigureAwait(false);

            if(result.IsValid)
            {
                continue;
            }

            //§8.3.1.2: a stale challenge IS a stale c_nonce, so it is invalid_nonce (the Wallet
            //retrieves a fresh one); every other Data Integrity failure is invalid_proof.
            return result.FailureReason is DiVpProofValidationFailureReason.ChallengeMismatch
                ? CredentialError(
                    Oid4VciCredentialErrors.InvalidNonce,
                    "A di_vp key proof carries a challenge that is not the server-provided c_nonce; "
                    + "retrieve a fresh one (§7 / Appendix F.2).")
                : CredentialError(
                    Oid4VciCredentialErrors.InvalidProof,
                    $"A di_vp key proof failed Data Integrity validation: {result.FailureReason} (Appendix F.2).");
        }

        return null;
    }


    //§F.1: aud MUST be the Credential Issuer Identifier — the resolved issuer for this request.
    private static async ValueTask<string> ResolveAudienceAsync(
        AuthorizationServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        Uri issuer = server.Integration.ResolveIssuerAsync is not null
            ? await server.Integration.ResolveIssuerAsync(registration, context, cancellationToken)
                .ConfigureAwait(false)
            : await DefaultIssuerResolver.ResolveAsync(registration, context, cancellationToken)
                .ConfigureAwait(false);

        return issuer.OriginalString;
    }


    //An empty/absent acceptable set admits any registered asymmetric signature algorithm the
    //validator otherwise allows; a non-empty set restricts to its members (ordinal, case-sensitive
    //per §F.1's "case sensitive strings").
    private static Func<string, bool> BuildAlgAcceptancePredicate(IReadOnlyCollection<string>? acceptable)
    {
        if(acceptable is null || acceptable.Count == 0)
        {
            return static _ => true;
        }

        HashSet<string> allowed = new(acceptable, StringComparer.Ordinal);

        return allowed.Contains;
    }


    private static ServerHttpResponse CredentialError(string error, string description) =>
        ServerHttpResponse.BadRequest(error, description)
            .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore);
}
