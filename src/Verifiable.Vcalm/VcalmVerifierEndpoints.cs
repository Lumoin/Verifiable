using System.Collections.Immutable;
using System.Diagnostics;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.JCose;

namespace Verifiable.Vcalm;

/// <summary>
/// Endpoint builder for the W3C VCALM 1.0 verifier service
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>) — the §3.3.1 <c>POST /credentials/verify</c> and §3.3.2
/// <c>POST /presentations/verify</c> interfaces a §1.3 conforming verifier MUST provide, plus the
/// MAY §3.3.3 <c>POST /challenges</c> interface. Register at startup via
/// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
/// </summary>
/// <remarks>
/// <para>
/// Each endpoint is stateless (<see cref="StatelessFlowKind"/>): a single request reads the JSON
/// body, parses it through the application's parse seam (the <c>Verifiable.Vcalm</c> serialization
/// firewall keeps <c>System.Text.Json</c> behind the seam), composes the library's tested Data
/// Integrity verifier through <see cref="VcalmVerificationService"/>, and writes the §3.3 response
/// with <see cref="VcalmResponseWriter"/>. There is no flow state and no PDA.
/// </para>
/// <para>
/// §2.4 boundary MUSTs are enforced here: the body MUST be <c>application/json</c> (else 400), MUST
/// be within the configured <see cref="VcalmIntegration.VcalmMaxRequestBytes"/> cap (else 413),
/// and MUST NOT carry an option / member the verifier does not understand (an unknown option →
/// 400 with the §3.8 <see cref="VcalmProblemTypes.UnknownOptionProvided"/> problem type; an unknown
/// top-level member → 400). A 200 always means the verification PROCESS ran — an invalid credential
/// is a 200 with <c>verified:false</c>, per §3.3.1 / §3.3.2.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmVerifierEndpoints")]
public static class VcalmVerifierEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        EndpointServer? server = context.Server;
        if(registration.AllowedCapabilities.Contains(WellKnownVcalmCapabilities.VcalmVerifier))
        {
            //§3.3.1 / §3.3.2 are the §1.3 REQUIRED verifier interfaces; they materialize only when
            //the matching parse seam is wired (fail-closed — an endpoint that cannot read its body
            //would be a dead route).
            if(server?.Vcalm().ParseVcalmVerifyCredentialAsync is not null)
            {
                candidates.Add(BuildCredentialsVerify());
            }

            if(server?.Vcalm().ParseVcalmVerifyPresentationAsync is not null)
            {
                candidates.Add(BuildPresentationsVerify());
            }

            //§3.3.3 is a MAY; it needs only the identifier-generation seam the dispatcher always
            //provides to mint a challenge.
            candidates.Add(BuildCreateChallenge());
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    //§3.3.1 POST /credentials/verify.
    private static EndpointCandidate BuildCredentialsVerify() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmCredentialsVerify,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownVcalmCapabilities.VcalmVerifier,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            MatchesRequest = static (fields, context, endpoint, ct) => MatchPost(context, endpoint),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.Vcalm();

                ServerHttpResponse? boundaryFailure = CheckRequestBoundary(context, server, out string requestBody);
                if(boundaryFailure is not null)
                {
                    return (null, boundaryFailure);
                }

                VcalmVerifyCredentialRequest? request = await oauth.ParseVcalmVerifyCredentialAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null || request.Failure == VcalmParseFailure.Malformed)
                {
                    return (null, MalformedRequest());
                }

                if(request.Failure == VcalmParseFailure.UnknownOption)
                {
                    return (null, UnknownOptionRequest());
                }

                //§3.3.1 accepts an embedded Data Integrity credential or an
                //EnvelopedVerifiableCredential. The Data Integrity path is verified; an enveloped
                //credential without a wired envelope handler is reported as an unverifiable (200,
                //verified:false) rather than rejected, since the verification process did run.
                if(request.DataIntegrityCredential is DataIntegritySecuredCredential credential)
                {
                    DateTimeOffset now = server.TimeProvider.GetUtcNow();
                    VcalmVerificationOutcome outcome = await VcalmVerificationService.VerifyCredentialAsync(
                        credential,
                        oauth.VcalmCredentialVerification,
                        oauth.ResolveVcalmStatusListAsync,
                        now,
                        context,
                        ct).ConfigureAwait(false);

                    string body = VcalmResponseWriter.BuildCredentialVerificationResponse(
                        outcome, request.Options, request.CredentialJson);

                    return (null, ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json));
                }

                //Enveloped (data: URL) credential: the JOSE/COSE/SD-JWT envelope verification is a
                //registered-handler seam. With no envelope handler wired, the
                //process ran but could not assert the proof — a 200 with verified:false and a
                //cryptographic ERROR ProblemDetail (§3.8.1).
                VcalmVerificationOutcome envelopedOutcome = BuildUnverifiableEnvelopeOutcome();
                string envelopedBody = VcalmResponseWriter.BuildCredentialVerificationResponse(
                    envelopedOutcome, request.Options, request.CredentialJson);

                return (null, ServerHttpResponse.Ok(envelopedBody, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.3.2 POST /presentations/verify.
    private static EndpointCandidate BuildPresentationsVerify() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmPresentationsVerify,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownVcalmCapabilities.VcalmVerifier,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            MatchesRequest = static (fields, context, endpoint, ct) => MatchPost(context, endpoint),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.Vcalm();

                ServerHttpResponse? boundaryFailure = CheckRequestBoundary(context, server, out string requestBody);
                if(boundaryFailure is not null)
                {
                    return (null, boundaryFailure);
                }

                VcalmVerifyPresentationRequest? request = await oauth.ParseVcalmVerifyPresentationAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null || request.Failure == VcalmParseFailure.Malformed)
                {
                    return (null, MalformedRequest());
                }

                if(request.Failure == VcalmParseFailure.UnknownOption)
                {
                    return (null, UnknownOptionRequest());
                }

                return (null, await VerifyPresentationAsync(server, request, context, ct).ConfigureAwait(false));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.3.3 POST /challenges.
    private static EndpointCandidate BuildCreateChallenge() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmCreateChallenge,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownVcalmCapabilities.VcalmVerifier,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            MatchesRequest = static (fields, context, endpoint, ct) => MatchPost(context, endpoint),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.Vcalm();

                //§3.3.3 takes an empty body. A body that is PRESENT MUST still be within the configured
                //§2.4 / B.4 payload cap (else 413) and be application/json (else 400) — the same DoS and
                //content-type gates every other body-bearing endpoint enforces via CheckRequestBoundary;
                //an empty body carries no content type and is the expected shape.
                IncomingRequest? req = context.IncomingRequest;
                if(req is not null && !req.Body.IsEmpty)
                {
                    if(req.Body.Bytes.Length > oauth.VcalmMaxRequestBytes)
                    {
                        VcalmProblemDetail tooLarge = VcalmProblemDetail.Error(
                            VcalmProblemTypes.MalformedValueError,
                            "PAYLOAD_TOO_LARGE",
                            "The request body exceeds the configured maximum payload size.");

                        return (null, ServerHttpResponse.PayloadTooLarge(
                            VcalmResponseWriter.BuildProblemDetailBody(tooLarge), WellKnownMediaTypes.Application.Json));
                    }

                    if(!IsJsonContentType(req.Body.ContentType))
                    {
                        return (null, MalformedRequest());
                    }
                }

                //§3.3.3: "the instance should create a challenge for use during verification". The
                //value is minted through the host-generic identifier-generation seam (a host concern
                //the dispatch loop wires) so replay-deterministic / format-specific deployments own it.
                string challenge = await server.Integration.GenerateIdentifierAsync!(
                    WellKnownVcalmIdentifierPurposes.VcalmChallenge, context, ct).ConfigureAwait(false);

                //Persist the issued challenge so a later §3.3.2 call can gate options.challenge
                //against it. Optional — when unwired the instance does not track issuance.
                if(oauth.PersistVcalmChallengeAsync is { } persist)
                {
                    await persist(challenge, context, ct).ConfigureAwait(false);
                }

                string body = VcalmResponseWriter.BuildChallengeResponse(challenge);

                return (null, ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.3.2 verification: the presentation proof (when proofed), then each contained credential.
    private static async ValueTask<ServerHttpResponse> VerifyPresentationAsync(
        EndpointServer server,
        VcalmVerifyPresentationRequest request,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var oauth = server.Vcalm();
        VcalmVerifyOptions options = request.Options;

        //§3.3.3 issuance gating: when the deployment wired the consume seam and the caller bound a
        //challenge, a challenge this instance never issued is rejected at the presentation level.
        ImmutableArray<VcalmProblemDetail>.Builder presentationProblems =
            ImmutableArray.CreateBuilder<VcalmProblemDetail>();

        if(!string.IsNullOrEmpty(options.Challenge)
            && oauth.ConsumeVcalmChallengeAsync is { } consume)
        {
            bool isIssued = await consume(options.Challenge, context, cancellationToken).ConfigureAwait(false);
            if(!isIssued)
            {
                presentationProblems.Add(VcalmProblemDetail.Error(
                    VcalmProblemTypes.CryptographicSecurityError,
                    "CRYPTOGRAPHIC_SECURITY_ERROR",
                    "The presented options.challenge was not issued by this verifier instance."));
            }
        }

        VcalmPresentationProofResult presentationResult;
        List<VcalmVerificationOutcome> credentialOutcomes = [];
        bool presentationProofVerified;

        if(request.DataIntegrityPresentation is { } proofed)
        {
            presentationResult = await VcalmVerificationService.VerifyPresentationProofAsync(
                proofed,
                options.Challenge,
                options.Domain,
                oauth.VcalmCredentialVerification,
                context,
                cancellationToken).ConfigureAwait(false);

            presentationProofVerified = presentationResult.Verified;

            await VerifyContainedCredentialsAsync(
                server, proofed.VerifiableCredential, credentialOutcomes, context, cancellationToken)
                .ConfigureAwait(false);
        }
        else if(request.UnproofedPresentation is { } unproofed)
        {
            //§3.3.2 unproofed presentation alternative: there is no presentation proof to verify, so
            //the presentation-level result carries no proof and the verification reduces to the
            //contained credentials. The presentation sub-result reflects the bound challenge/domain
            //(verified as true since there is nothing to contradict them at the presentation level).
            presentationResult = new VcalmPresentationProofResult
            {
                Verified = true,
                Challenge = options.Challenge,
                Domain = options.Domain,
                Holder = unproofed.Holder,
                ProofInput = string.Empty,
                ProblemDetails = ImmutableArray<VcalmProblemDetail>.Empty
            };

            presentationProofVerified = true;

            await VerifyContainedCredentialsAsync(
                server, unproofed.VerifiableCredential, credentialOutcomes, context, cancellationToken)
                .ConfigureAwait(false);
        }
        else if(request.UnsecuredVerifiablePresentation is { } unsecured)
        {
            //§3.3.2: the verifiablePresentation member is the SECURED form (a Data Integrity proof or an
            //EnvelopedVerifiablePresentation); a presentation carrying neither is not a verifiable
            //presentation. This is a presentation-level §3.8.1 cryptographic ERROR (verified:false),
            //mirroring a proof-less verifiableCredential — the unproofed alternative is the separate
            //'presentation' member. The contained credentials are still verified and reported, but the
            //missing presentation-level securing flips the overall result to false regardless.
            presentationResult = new VcalmPresentationProofResult
            {
                Verified = false,
                Challenge = options.Challenge,
                Domain = options.Domain,
                Holder = unsecured.Holder,
                ProofInput = string.Empty,
                ProblemDetails =
                [
                    VcalmProblemDetail.Error(
                        VcalmProblemTypes.CryptographicSecurityError,
                        "CRYPTOGRAPHIC_SECURITY_ERROR",
                        "The verifiablePresentation carries no securing mechanism (no Data Integrity proof "
                        + "and not an EnvelopedVerifiablePresentation). Submit an unproofed presentation "
                        + "under the 'presentation' member instead.")
                ]
            };

            presentationProofVerified = false;

            await VerifyContainedCredentialsAsync(
                server, unsecured.VerifiableCredential, credentialOutcomes, context, cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            //Enveloped presentation: envelope verification is a registered-handler seam. The process
            //ran but could not assert the proof — verified:false with a cryptographic ERROR.
            presentationResult = new VcalmPresentationProofResult
            {
                Verified = false,
                Challenge = options.Challenge,
                Domain = options.Domain,
                Holder = null,
                ProofInput = string.Empty,
                ProblemDetails =
                [
                    VcalmProblemDetail.Error(
                        VcalmProblemTypes.CryptographicSecurityError,
                        "CRYPTOGRAPHIC_SECURITY_ERROR",
                        "Enveloped presentation verification is handled by a registered envelope handler "
                        + "the deployment wires; none is configured.")
                ]
            };

            presentationProofVerified = false;
        }

        //Gather the presentation proof's own problem details into the presentation-level set.
        presentationProblems.AddRange(presentationResult.ProblemDetails);

        //§3.3.2: verified is true iff the presentation passed AND every contained credential passed
        //(§3.8.1 roll-up across the whole response). A presentation-level ERROR also flips it.
        bool presentationLevelError = false;
        foreach(VcalmProblemDetail problem in presentationProblems)
        {
            if(problem.IsError)
            {
                presentationLevelError = true;
                break;
            }
        }

        bool allCredentialsVerified = true;
        foreach(VcalmVerificationOutcome outcome in credentialOutcomes)
        {
            if(!outcome.Verified)
            {
                allCredentialsVerified = false;
                break;
            }
        }

        bool overallVerified = presentationProofVerified && !presentationLevelError && allCredentialsVerified;

        string body = VcalmResponseWriter.BuildPresentationVerificationResponse(
            overallVerified,
            presentationResult,
            credentialOutcomes,
            presentationProblems.ToImmutable(),
            options,
            request.PresentationJson);

        return ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json);
    }


    //Verifies each embedded Data Integrity credential the presentation contains (§3.3.2: "Verifying
    //each contained verifiable credential's proof, status, and validity period(s)").
    private static async ValueTask VerifyContainedCredentialsAsync(
        EndpointServer server,
        IReadOnlyList<Core.Model.Credentials.VerifiableCredential>? credentials,
        List<VcalmVerificationOutcome> outcomes,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var oauth = server.Vcalm();
        if(credentials is null)
        {
            return;
        }

        DateTimeOffset now = server.TimeProvider.GetUtcNow();
        foreach(Core.Model.Credentials.VerifiableCredential credential in credentials)
        {
            if(credential is DataIntegritySecuredCredential secured)
            {
                VcalmVerificationOutcome outcome = await VcalmVerificationService.VerifyCredentialAsync(
                    secured,
                    oauth.VcalmCredentialVerification,
                    oauth.ResolveVcalmStatusListAsync,
                    now,
                    context,
                    cancellationToken).ConfigureAwait(false);

                outcomes.Add(outcome);
            }
            else
            {
                //A contained credential with no embedded proof cannot be cryptographically verified
                //here; report it as a credential-level ERROR (§3.8.1).
                outcomes.Add(BuildUnverifiableEnvelopeOutcome());
            }
        }
    }


    //Shared matcher: POST to this endpoint's resolved path.
    private static ValueTask<MatchPayload?> MatchPost(ExchangeContext context, ServerEndpoint endpoint)
    {
        IncomingRequest? req = context.IncomingRequest;
        if(req is null)
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        if(!WellKnownHttpMethods.IsPost(req.Method))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
    }


    //§2.4 request-boundary MUSTs for the verify endpoints: a body MUST be present, MUST be within
    //the configured size cap (else 413), and MUST be application/json (else 400). On success
    //requestBody carries the UTF-8-decoded body.
    private static ServerHttpResponse? CheckRequestBoundary(
        ExchangeContext context, EndpointServer server, out string requestBody)
    {
        var oauth = server.Vcalm();
        requestBody = string.Empty;

        IncomingRequest? req = context.IncomingRequest;
        if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
        {
            return MalformedRequest();
        }

        //§2.4 / B.4 payload size: a body over the configured cap is refused with 413 before parsing.
        if(req.Body.Bytes.Length > oauth.VcalmMaxRequestBytes)
        {
            VcalmProblemDetail tooLarge = VcalmProblemDetail.Error(
                VcalmProblemTypes.MalformedValueError,
                "PAYLOAD_TOO_LARGE",
                "The request body exceeds the configured maximum payload size.");

            return ServerHttpResponse.PayloadTooLarge(
                VcalmResponseWriter.BuildProblemDetailBody(tooLarge), WellKnownMediaTypes.Application.Json);
        }

        //§2.4: "All entity bodies […] MUST be serialized as JSON and include the Content-Type header
        //with a media type value of application/json."
        if(!IsJsonContentType(req.Body.ContentType))
        {
            return MalformedRequest();
        }

        requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);

        return null;
    }


    //Compares the request content type to application/json case-insensitively, ignoring any media
    //type parameters (e.g. "; charset=utf-8") per RFC 9110 §8.3.1.
    private static bool IsJsonContentType(string contentType)
    {
        if(string.IsNullOrEmpty(contentType))
        {
            return false;
        }

        int separator = contentType.IndexOf(';', StringComparison.Ordinal);
        string mediaType = separator >= 0 ? contentType[..separator].Trim() : contentType.Trim();

        return WellKnownMediaTypes.Application.IsJson(mediaType);
    }


    //A §3.3.1 / §3.3.2 malformed-input 400. The body is an RFC 9457 ProblemDetail naming the
    //malformed-value error type so the response is itself a conformant ProblemDetails document.
    private static ServerHttpResponse MalformedRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "The request body could not be parsed as a valid verification request.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    //The §2.4 unknown-option 400, carrying the §3.8 UNKNOWN_OPTION_PROVIDED problem type.
    private static ServerHttpResponse UnknownOptionRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.UnknownOptionProvided,
            "UNKNOWN_OPTION_PROVIDED",
            "An option that is unknown to the implementation was provided to the API call.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    //The §3.8.1 outcome for a credential the verifier cannot cryptographically check (an
    //enveloped credential with no wired envelope handler, or a contained credential with no embedded
    //proof): verified:false with a single cryptographic ERROR ProblemDetail.
    private static VcalmVerificationOutcome BuildUnverifiableEnvelopeOutcome() =>
        new()
        {
            Verified = false,
            ProblemDetails =
            [
                VcalmProblemDetail.Error(
                    VcalmProblemTypes.CryptographicSecurityError,
                    "CRYPTOGRAPHIC_SECURITY_ERROR",
                    "The credential's securing mechanism could not be verified by this verifier "
                    + "instance. Enveloped (JWT / SD-JWT / mdoc) verification is handled by a "
                    + "registered envelope handler the deployment wires.")
            ]
        };
}
