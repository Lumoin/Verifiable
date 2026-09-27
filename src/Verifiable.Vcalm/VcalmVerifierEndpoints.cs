using System.Collections.Immutable;
using System.Globalization;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;
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
public static class VcalmVerifierEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static EndpointBuilderDelegate Builder { get; } = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        EndpointServer? server = context.RequestServer;
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


    /// <summary>
    /// Builds the endpoint for §3.3.1 POST /credentials/verify.
    /// The handler uses the admitted request wiring for its parser and application delegates.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/">Credential lifecycle API</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
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
                //registered-handler seam. The envelope and an embedded credential that could not be
                //parsed have distinct causes.
                VcalmVerificationOutcome envelopedOutcome = request.EnvelopedCredential is not null
                    ? VcalmVerificationService.BuildUnverifiableEnvelopeOutcome()
                    : VcalmVerificationService.BuildUnparseableCredentialOutcome();
                string envelopedBody = VcalmResponseWriter.BuildCredentialVerificationResponse(
                    envelopedOutcome, request.Options, request.CredentialJson);

                return (null, ServerHttpResponse.Ok(envelopedBody, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the endpoint for §3.3.2 POST /presentations/verify.
    /// The handler uses the admitted request wiring for its parser and application delegates.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/">Credential lifecycle API</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
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


    /// <summary>
    /// Builds the endpoint for §3.3.3 POST /challenges.
    /// The handler uses the admitted request wiring for its parser and application delegates.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/">Credential lifecycle API</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.Vcalm();

                //§3.3.3: "Passing an empty body to this endpoint creates and returns a challenge string in the
                //response body." §2.4 Content Serialization: "All entity bodies in requests and responses sent to
                //or received from the API endpoints defined by this specification MUST be serialized as JSON and
                //include the Content-Type header with a media type value of application/json." So no body bytes
                //mint a challenge, and present bytes pass, in order, the B.4 payload cap (else 413), the
                //application/json media type (else 400) and the empty-object shape, the one empty body JSON can
                //carry (else 400). The gate keys on the bytes, not on RequestBody.IsEmpty, which says only that no
                //content type was declared: a body sent without a Content-Type header is refused like any other
                //body that is not application/json.
                IncomingRequest? req = context.IncomingRequest;
                if(req is not null && !req.Body.Bytes.IsEmpty)
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

                    if(!VcalmJsonShape.IsEmptyObject(req.Body.Bytes.Span))
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


    /// <summary>
    /// §3.3.2 verification: the presentation proof (when proofed), then each contained credential. A presentation
    /// containing more credentials than <see cref="VcalmCredentialVerification.MaxContainedCredentials"/> admits is
    /// refused first, with the <see href="https://www.w3.org/TR/vc-data-model-2.0/#problem-details">VC Data Model 2.0
    /// §7.2</see> RANGE_ERROR at the presentation level, before its proof or any contained credential is verified.
    /// </summary>
    private static async ValueTask<ServerHttpResponse> VerifyPresentationAsync(
        EndpointServer server,
        VcalmVerifyPresentationRequest request,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var oauth = server.Vcalm();
        VcalmVerifyOptions options = request.Options;
        DateTimeOffset now = server.TimeProvider.GetUtcNow();

        //Each contained credential costs a controller resolution, its proofs, and its status and schema fetches, so a
        //presentation carrying more than the verifier admits is refused before any of that work, and before its
        //challenge is consumed.
        VerifiablePresentation? presentation = request.DataIntegrityPresentation ?? request.UnproofedPresentation ?? request.UnsecuredVerifiablePresentation;
        int containedCount = (presentation?.VerifiableCredential?.Count ?? 0) + (presentation?.EnvelopedVerifiableCredential?.Count ?? 0);
        int maxContained = oauth.VcalmCredentialVerification?.MaxContainedCredentials ?? VcalmCredentialVerification.DefaultMaxContainedCredentials;
        if(containedCount > maxContained)
        {
            return BuildTooManyContainedCredentialsResponse(request, presentation, containedCount, maxContained);
        }

        //§3.3.3 issuance gating: when the deployment wired the consume seam and the caller bound a
        //challenge, a challenge this instance never issued is rejected at the presentation level.
        ImmutableArray<VcalmProblemDetail>.Builder presentationProblems =
            ImmutableArray.CreateBuilder<VcalmProblemDetail>();

        if(options.Challenge is not null
            && oauth.ConsumeVcalmChallengeAsync is { } consume)
        {
            bool isIssued = await consume(options.Challenge, context, cancellationToken).ConfigureAwait(false);
            if(!isIssued)
            {
                presentationProblems.Add(VcalmProblemDetail.Error(
                    VcalmProblemTypes.ChallengeNotIssued,
                    "CHALLENGE_NOT_ISSUED",
                    "The presented options.challenge was not issued by this verifier instance, or was already consumed."));
            }
        }

        VcalmPresentationProofResult presentationResult;
        ImmutableArray<VcalmVerificationOutcome> credentialOutcomes = ImmutableArray<VcalmVerificationOutcome>.Empty;
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

            credentialOutcomes = await VcalmVerificationService.VerifyContainedCredentialsAsync(
                proofed, oauth.VcalmCredentialVerification, oauth.ResolveVcalmStatusListAsync, now, context, cancellationToken)
                .ConfigureAwait(false);
        }
        else if(request.UnproofedPresentation is { } unproofed)
        {
            //§3.3.2 unproofed presentation alternative: there is no presentation proof to verify, so
            //the presentation-level result carries no proof and the verification reduces to the
            //contained credentials. Data Integrity §4.4 raises INVALID_CHALLENGE_ERROR / INVALID_DOMAIN_ERROR
            //when a binding "was given" and does not match the proof's own value; with no proof at all,
            //a bound challenge or domain trivially fails to match, so a request that gave neither has
            //nothing to contradict and the presentation sub-result reports verified.
            ImmutableArray<VcalmProblemDetail>.Builder unproofedBindingProblems =
                ImmutableArray.CreateBuilder<VcalmProblemDetail>();
            if(options.Challenge is not null)
            {
                unproofedBindingProblems.Add(VcalmProblemDetail.Error(
                    VcalmProblemTypes.InvalidChallengeError,
                    "INVALID_CHALLENGE_ERROR",
                    "The presentation carries no proof, so the requested options.challenge cannot be bound."));
            }

            if(options.Domain is not null)
            {
                unproofedBindingProblems.Add(VcalmProblemDetail.Error(
                    VcalmProblemTypes.InvalidDomainError,
                    "INVALID_DOMAIN_ERROR",
                    "The presentation carries no proof, so the requested options.domain cannot be bound."));
            }

            presentationResult = new VcalmPresentationProofResult
            {
                Verified = unproofedBindingProblems.Count == 0,
                Challenge = options.Challenge,
                Domain = options.Domain,
                Holder = unproofed.Holder,
                ProofResults = [],
                ProblemDetails = unproofedBindingProblems.ToImmutable()
            };

            presentationProofVerified = presentationResult.Verified;

            credentialOutcomes = await VcalmVerificationService.VerifyContainedCredentialsAsync(
                unproofed, oauth.VcalmCredentialVerification, oauth.ResolveVcalmStatusListAsync, now, context, cancellationToken)
                .ConfigureAwait(false);
        }
        else if(request.UnsecuredVerifiablePresentation is { } unsecured)
        {
            //§3.3.2: the verifiablePresentation member is the SECURED form (a Data Integrity proof or an
            //EnvelopedVerifiablePresentation); a presentation carrying neither is not a verifiable
            //presentation. Data Integrity §4.4 classifies the missing proof as PARSING_ERROR,
            //mirroring a proof-less verifiableCredential — the unproofed alternative is the separate
            //'presentation' member. The contained credentials are still verified and reported, but the
            //missing presentation-level securing flips the overall result to false regardless.
            presentationResult = new VcalmPresentationProofResult
            {
                Verified = false,
                Challenge = options.Challenge,
                Domain = options.Domain,
                Holder = unsecured.Holder,
                ProofResults = [],
                ProblemDetails =
                [
                    VcalmProblemDetail.Error(
                        VcalmProblemTypes.ParsingError,
                        "PARSING_ERROR",
                        "The secured presentation carries no Data Integrity proof map to verify.")
                ]
            };

            presentationProofVerified = false;

            credentialOutcomes = await VcalmVerificationService.VerifyContainedCredentialsAsync(
                unsecured, oauth.VcalmCredentialVerification, oauth.ResolveVcalmStatusListAsync, now, context, cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            //Enveloped presentation: envelope verification is a registered-handler seam. The process
            //ran but no securing-mechanism verifier could be dispatched.
            presentationResult = new VcalmPresentationProofResult
            {
                Verified = false,
                Challenge = options.Challenge,
                Domain = options.Domain,
                Holder = null,
                ProofResults = [],
                ProblemDetails =
                [
                    VcalmProblemDetail.Error(
                        VcalmProblemTypes.UnsupportedSecuringMechanism,
                        "UNSUPPORTED_SECURING_MECHANISM",
                        VcalmProblemTypes.UnsupportedSecuringMechanismDetail)
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


    /// <summary>
    /// The §3.3.2 answer for a presentation containing more credentials than the verifier admits: HTTP 200, since the
    /// verification process ran, with <c>verified</c> false and the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#problem-details">VC Data Model 2.0 §7.2</see> RANGE_ERROR, "A
    /// provided value is outside of the expected range of an associated value", at the presentation level, and no
    /// contained credential reported, none having been verified.
    /// </summary>
    /// <param name="request">The parsed verify request.</param>
    /// <param name="presentation">The presentation, or <see langword="null"/> for an enveloped one.</param>
    /// <param name="containedCount">The number of credentials the presentation contains.</param>
    /// <param name="maximum">The number of contained credentials this verifier admits per presentation.</param>
    /// <returns>The 200 verification response.</returns>
    private static ServerHttpResponse BuildTooManyContainedCredentialsResponse(
        VcalmVerifyPresentationRequest request, VerifiablePresentation? presentation, int containedCount, int maximum)
    {
        VcalmProblemDetail tooMany = VcalmProblemDetail.Error(
            VcalmProblemTypes.RangeError,
            "RANGE_ERROR",
            $"The presentation contains {containedCount.ToString(CultureInfo.InvariantCulture)} credentials, more than the "
            + $"{maximum.ToString(CultureInfo.InvariantCulture)} this verifier accepts per presentation.");
        VcalmPresentationProofResult presentationResult = new()
        {
            Verified = false,
            Challenge = request.Options.Challenge,
            Domain = request.Options.Domain,
            Holder = presentation?.Holder,
            ProofResults = [],
            ProblemDetails = [tooMany]
        };
        string body = VcalmResponseWriter.BuildPresentationVerificationResponse(
            false, presentationResult, [], [tooMany], request.Options, request.PresentationJson);

        return ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json);
    }


    /// <summary>
    /// Shared matcher: POST to this endpoint's resolved path.
    /// </summary>
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


    /// <summary>
    /// §2.4 request-boundary MUSTs for the verify endpoints: a body MUST be present, MUST be within
    /// the configured size cap (else 413), and MUST be application/json (else 400). On success
    /// requestBody carries the UTF-8-decoded body.
    /// </summary>
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

        //RFC 8259 §8.1 requires JSON text to be UTF-8 encoded; bytes that are not valid UTF-8 are data this
        //verifier cannot process (§2.4), refused rather than silently repaired into the Unicode replacement
        //character and parsed as if the client had sent that character.
        if(!VcalmJsonShape.TryDecodeStrictUtf8(req.Body.Bytes.Span, out string? decodedBody))
        {
            return MalformedRequest();
        }

        requestBody = decodedBody;

        return null;
    }


    /// <summary>
    /// Compares the request content type to application/json case-insensitively, ignoring any media
    /// type parameters (e.g. "; charset=utf-8") per RFC 9110 §8.3.1.
    /// </summary>
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


    /// <summary>
    /// A §3.3.1 / §3.3.2 malformed-input 400. The body is an RFC 9457 ProblemDetail naming the
    /// malformed-value error type so the response is itself a conformant ProblemDetails document.
    /// </summary>
    private static ServerHttpResponse MalformedRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "The request body could not be parsed as a valid verification request.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    /// <summary>
    /// The §2.4 unknown-option 400, carrying the §3.8 UNKNOWN_OPTION_PROVIDED problem type.
    /// </summary>
    private static ServerHttpResponse UnknownOptionRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.UnknownOptionProvided,
            "UNKNOWN_OPTION_PROVIDED",
            "An option that is unknown to the implementation was provided to the API call.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }
}
