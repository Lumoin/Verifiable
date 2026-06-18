using System.Diagnostics;
using System.Globalization;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.JCose;
using Verifiable.Vcalm.Exchange;

namespace Verifiable.Vcalm;

/// <summary>
/// Endpoint builder for the W3C VCALM 1.0 holder presentation surface
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>) — the §3.5 presenting interfaces: §3.5.1 <c>POST /credentials/derive</c>, §3.5.2
/// <c>POST /presentations</c>, §3.5.3 <c>GET /presentations</c>, §3.5.4 <c>GET /presentations/{id}</c>,
/// and §3.5.5 <c>DELETE /presentations/{id}</c>. Register at startup via
/// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
/// </summary>
/// <remarks>
/// <para>
/// §3.5 is the holder service's OPTIONAL presentation surface — the §1.3 conforming-holder MUST is
/// §3.6.4 / §3.6.5 exchange participation, NOT the presentation CRUD here. This builder ships §3.5 as
/// the conformant OPTIONAL surface gated on <see cref="WellKnownVcalmCapabilities.VcalmHolder"/>. Each
/// endpoint is stateless (<see cref="StatelessFlowKind"/>): a single request reads the body, parses it
/// through the application's parse seam (the serialization firewall keeps STJ behind the seam),
/// composes the library's tested derive / sign surface through <see cref="VcalmHolderService"/>, and
/// writes the §3.5 response with <see cref="VcalmResponseWriter"/>.
/// </para>
/// <para>
/// §2.4 boundary MUSTs are enforced for the §3.5.1 / §3.5.2 bodies exactly as the issuer / verifier
/// enforce them: the body MUST be <c>application/json</c> (else 400), MUST be within
/// <see cref="VcalmIntegration.VcalmMaxRequestBytes"/> (else 413), and MUST NOT carry an option /
/// member the holder does not understand (an unknown option → 400 with the §3.8
/// <see cref="VcalmProblemTypes.UnknownOptionProvided"/> type).
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmHolderEndpoints")]
public static class VcalmHolderEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        EndpointServer? server = context.Server;
        if(registration.AllowedCapabilities.Contains(WellKnownVcalmCapabilities.VcalmHolder))
        {
            //§3.5.1 derive materializes only when the parse seam and the derive configuration are both
            //wired (fail-closed — a holder surface that cannot read its body or cannot derive would be
            //a dead route).
            if(server?.Vcalm().ParseVcalmDeriveCredentialAsync is not null
                && (server?.Vcalm().VcalmCredentialDerivation is not null
                    || server?.Vcalm().ResolveVcalmCredentialDerivationAsync is not null))
            {
                candidates.Add(BuildDeriveCredential());
            }

            //§3.5.2 create-presentation materializes only when the parse seam and the signing
            //configuration are both wired.
            if(server?.Vcalm().ParseVcalmCreatePresentationAsync is not null
                && (server?.Vcalm().VcalmPresentationSigning is not null
                    || server?.Vcalm().ResolveVcalmPresentationSigningAsync is not null))
            {
                candidates.Add(BuildCreatePresentation());
            }

            //§3.5.3 / §3.5.4 / §3.5.5 are MAYs that need the matching storage seam — the library never
            //owns the presentation store, so an instance with no store does not advertise listing,
            //retrieval, or deletion.
            if(server?.Vcalm().ListVcalmPresentationsAsync is not null)
            {
                candidates.Add(BuildGetPresentations());
            }

            if(server?.Vcalm().LoadVcalmPresentationAsync is not null)
            {
                candidates.Add(BuildGetPresentation());
            }

            if(server?.Vcalm().DeleteVcalmPresentationAsync is not null)
            {
                candidates.Add(BuildDeletePresentation());
            }
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    //§3.5.1 POST /credentials/derive.
    private static EndpointCandidate BuildDeriveCredential() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmCredentialsDerive,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownVcalmCapabilities.VcalmHolder,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            MatchesRequest = static (fields, context, endpoint, ct) => MatchExact(context, endpoint, WellKnownHttpMethods.Post),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var vcalm = server.Vcalm();

                ServerHttpResponse? boundaryFailure = CheckRequestBoundary(context, server, out string requestBody);
                if(boundaryFailure is not null)
                {
                    return (null, boundaryFailure);
                }

                VcalmDeriveCredentialRequest? request = await vcalm.ParseVcalmDeriveCredentialAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null || request.Failure == VcalmParseFailure.Malformed)
                {
                    return (null, MalformedRequest());
                }

                //§2.4 unknown-option is checked before the credential-presence check: an unknown option
                //short-circuits the parser before it materializes the credential, and the §2.4 MUST is
                //the more specific outcome.
                if(request.Failure == VcalmParseFailure.UnknownOption)
                {
                    return (null, UnknownOptionRequest());
                }

                //§3.5.1: derivation needs a base-proofed credential. A credential that carries no
                //embedded proof is not a derivable ecdsa-sd-2023 base credential — a §3.5.1 400.
                if(request.Credential is null || request.Credential.Proof is not { Count: > 0 })
                {
                    return (null, NonDerivableRequest());
                }

                return (null, await DeriveAsync(server, request, context, ct).ConfigureAwait(false));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.5.2 POST /presentations.
    private static EndpointCandidate BuildCreatePresentation() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmCreatePresentation,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownVcalmCapabilities.VcalmHolder,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            MatchesRequest = static (fields, context, endpoint, ct) => MatchExact(context, endpoint, WellKnownHttpMethods.Post),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var vcalm = server.Vcalm();

                ServerHttpResponse? boundaryFailure = CheckRequestBoundary(context, server, out string requestBody);
                if(boundaryFailure is not null)
                {
                    return (null, boundaryFailure);
                }

                VcalmCreatePresentationRequest? request = await vcalm.ParseVcalmCreatePresentationAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null || request.Failure == VcalmParseFailure.Malformed)
                {
                    return (null, MalformedRequest());
                }

                if(request.Failure == VcalmParseFailure.UnknownOption)
                {
                    return (null, UnknownOptionRequest());
                }

                if(request.Presentation is null)
                {
                    return (null, MalformedRequest());
                }

                //§3.5.2: a presentation proof binds an anti-replay challenge and a domain (VC-DM 2.0
                //§4.13). A request that omits either cannot produce a valid presentation proof — a 400.
                if(string.IsNullOrEmpty(request.Options.Challenge) || string.IsNullOrEmpty(request.Options.Domain))
                {
                    return (null, MissingChallengeOrDomainRequest());
                }

                //§3.4.3.2 holder anti-replay: when the deployment's channel adapter populated the current
                //communication channel's domain on the context, the holder MUST verify the request's
                //domain (the verifier identity the proof will bind) matches it before signing. A mismatch
                //means the request's domain names a verifier other than the one on the wire — a relayed /
                //replayed presentation request — so the holder refuses fail-closed. When the channel
                //domain is unset the §3.5.2 stateless primitive signs the request domain verbatim;
                //populating it is the §3.4.3.2 deployment MUST (documented on CurrentChannelDomain).
                string? channelDomain = context.CurrentChannelDomain;
                if(channelDomain is not null
                    && !string.Equals(channelDomain, request.Options.Domain, StringComparison.Ordinal))
                {
                    return (null, ChannelDomainMismatchRequest());
                }

                return (null, await CreatePresentationAsync(server, request, context, ct).ConfigureAwait(false));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.5.3 GET /presentations.
    private static EndpointCandidate BuildGetPresentations() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmGetPresentations,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownVcalmCapabilities.VcalmHolder,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            MatchesRequest = static (fields, context, endpoint, ct) => MatchExact(context, endpoint, WellKnownHttpMethods.Get),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var vcalm = server.Vcalm();

                IReadOnlyList<string> presentations = await vcalm.ListVcalmPresentationsAsync!(
                    context, ct).ConfigureAwait(false);

                //§3.5.3: 200 with an array of the stored presentations (an empty array is valid).
                string body = VcalmResponseWriter.BuildPresentationsListResponse(presentations);

                return (null, ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.5.4 GET /presentations/{id}.
    private static EndpointCandidate BuildGetPresentation() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmGetPresentation,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownVcalmCapabilities.VcalmHolder,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            MatchesRequest = static (fields, context, endpoint, ct) =>
                MatchPresentationIdPath(context, endpoint, WellKnownHttpMethods.Get),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var vcalm = server.Vcalm();

                string? presentationId = ExtractPresentationId(context);
                if(string.IsNullOrEmpty(presentationId))
                {
                    return (null, MalformedRequest());
                }

                VcalmStoredPresentation? stored = await vcalm.LoadVcalmPresentationAsync!(
                    presentationId, context, ct).ConfigureAwait(false);

                //§3.5.4: 404 when no record exists, 410 Gone for a soft-deleted (§3.5.5) tombstone, 200
                //with the secured presentation otherwise.
                if(stored is null)
                {
                    return (null, ServerHttpResponse.NotFound());
                }

                if(stored.IsDeleted)
                {
                    return (null, Gone());
                }

                string body = VcalmResponseWriter.BuildVerifiablePresentationResponse(stored.VerifiablePresentationJson);

                return (null, ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.5.5 DELETE /presentations/{id}.
    private static EndpointCandidate BuildDeletePresentation() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmDeletePresentation,
            HttpMethod = WellKnownHttpMethods.Delete,
            Capability = WellKnownVcalmCapabilities.VcalmHolder,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            MatchesRequest = static (fields, context, endpoint, ct) =>
                MatchPresentationIdPath(context, endpoint, WellKnownHttpMethods.Delete),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var vcalm = server.Vcalm();

                string? presentationId = ExtractPresentationId(context);
                if(string.IsNullOrEmpty(presentationId))
                {
                    return (null, MalformedRequest());
                }

                bool existed = await vcalm.DeleteVcalmPresentationAsync!(
                    presentationId, context, ct).ConfigureAwait(false);

                //§3.5.5: 404 when no record exists; otherwise 202 — "this is a 202 by default as soft
                //deletes and processing time are assumed".
                if(!existed)
                {
                    return (null, ServerHttpResponse.NotFound());
                }

                return (null, ServerHttpResponse.Accepted());
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.5.1 derive: compose the selective-disclosure derive surface and return the 201 derived
    //credential. The §3.5.1 201 body is the derived credential object itself (the spec's response form
    //is "@context...id...type...issuer...proof"), not a wrapping {verifiableCredential} envelope.
    private static async ValueTask<ServerHttpResponse> DeriveAsync(
        EndpointServer server,
        VcalmDeriveCredentialRequest request,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var vcalm = server.Vcalm();

        //§3.5.1 derive configuration, resolved for the request's tenant (the per-tenant resolver or the
        //flat server-global value). A multi-tenant holder host derives each tenant's credentials under
        //that tenant's own keys.
        VcalmCredentialDerivation? derivation = await vcalm
            .ResolveEffectiveCredentialDerivationAsync(context, cancellationToken).ConfigureAwait(false);
        if(derivation is null)
        {
            return ServerHttpResponse.ServerError(
                ServerErrors.ServerError, "No VCALM credential-derivation configuration resolved for this tenant.");
        }

        DataIntegritySecuredCredential derived;
        try
        {
            derived = await VcalmHolderService.DeriveAsync(
                request.Credential!,
                request.SelectivePointers,
                derivation,
                context,
                cancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException)
        {
            //§3.5.1: the credential is not a derivable ecdsa-sd-2023 base credential (e.g. its proof is
            //a different cryptosuite). The derive surface rejects it; the holder maps that to a 400.
            return NonDerivableRequest();
        }
        catch(Exception ex) when(ex is not OperationCanceledException and not OutOfMemoryException)
        {
            //§3.8 process-safety boundary: a selectivePointer that is syntactically valid but does not
            //resolve in the supplied credential (or navigates into an array) makes the fragment selector
            //THROW (ArgumentException / NotImplementedException), and the canonicalizer can throw on
            //malformed JSON-LD. That is client-malformed input (§3.5.1 / §2.4), not a server fault — map
            //it to a sanitized MALFORMED_VALUE_ERROR 400, never an unhandled 500.
            return MalformedRequest();
        }

        string derivedJson = derivation.SerializeCredential(derived);

        return ServerHttpResponse.Created(derivedJson, WellKnownMediaTypes.Application.Json);
    }


    //§3.5.2 create-presentation: bind the request's challenge / domain / verificationMethod / created
    //(falling back to instance defaults), sign the presentation, persist it under its id, and return
    //the 201 {verifiablePresentation} body.
    private static async ValueTask<ServerHttpResponse> CreatePresentationAsync(
        EndpointServer server,
        VcalmCreatePresentationRequest request,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var vcalm = server.Vcalm();

        //§3.5.2 presentation-signing configuration, resolved for the request's tenant (the per-tenant
        //resolver or the flat server-global value). A multi-tenant holder host signs each tenant's
        //presentations under that tenant's own key.
        VcalmPresentationSigning? signing = await vcalm
            .ResolveEffectivePresentationSigningAsync(context, cancellationToken).ConfigureAwait(false);
        if(signing is null)
        {
            return ServerHttpResponse.ServerError(
                ServerErrors.ServerError, "No VCALM presentation-signing configuration resolved for this tenant.");
        }

        VcalmCreatePresentationOptions options = request.Options;

        //§3.5.2 verificationMethod: the request value, else the instance's configured default ("If
        //omitted, a default verification method will be used.").
        string verificationMethodId = !string.IsNullOrEmpty(options.VerificationMethod)
            ? options.VerificationMethod
            : signing.DefaultVerificationMethodId;

        //§3.5.2 created: the request value when it parses, else the instance clock ("Default current
        //system time.").
        DateTime proofCreated = TryParseCreated(options.Created, out DateTime parsed)
            ? parsed
            : server.TimeProvider.GetUtcNow().UtcDateTime;

        DataIntegritySecuredPresentation secured = await VcalmHolderService.CreatePresentationAsync(
            request.Presentation!,
            options.Challenge!,
            options.Domain!,
            verificationMethodId,
            proofCreated,
            signing,
            context,
            cancellationToken).ConfigureAwait(false);

        string securedPresentationJson = signing.SerializePresentation(secured);

        //§3.5.3 / §3.5.4 persistence: store the secured presentation so the listing / retrieval
        //interfaces can reach it. The store key is the presentation's own id when present, else a
        //minted id ("opaque to the client") — minted only to key the store, never written into the
        //presentation. Optional — when unwired the presentation is still secured and returned.
        if(vcalm.StoreVcalmPresentationAsync is { } store)
        {
            string presentationId = !string.IsNullOrEmpty(request.PresentationId)
                ? request.PresentationId
                : await server.Integration.GenerateIdentifierAsync!(
                    WellKnownVcalmIdentifierPurposes.VcalmPresentationId, context, cancellationToken).ConfigureAwait(false);

            await store(presentationId, securedPresentationJson, context, cancellationToken).ConfigureAwait(false);
        }

        string body = VcalmResponseWriter.BuildVerifiablePresentationResponse(securedPresentationJson);

        return ServerHttpResponse.Created(body, WellKnownMediaTypes.Application.Json);
    }


    //§3.5.2 created parsing: an ISO 8601 timestamp the request supplied. A value that does not parse
    //falls back to the instance clock (the §3.5.2 default).
    private static bool TryParseCreated(string? created, out DateTime parsed)
    {
        parsed = default;
        if(string.IsNullOrEmpty(created))
        {
            return false;
        }

        if(DateTimeOffset.TryParse(
            created,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out DateTimeOffset offset))
        {
            parsed = offset.UtcDateTime;

            return true;
        }

        return false;
    }


    //Reads the {id} path segment the §3.5.4 / §3.5.5 matcher extracted and carried on the match
    //payload. A skin that did template routing (/presentations/{presentationId}) populates the same id
    //on the request's RouteValues, which the matcher also honours.
    private static string? ExtractPresentationId(ExchangeContext context)
    {
        if(context.MatchPayload is VcalmPresentationIdMatchPayload payload && !string.IsNullOrEmpty(payload.PresentationId))
        {
            return Uri.UnescapeDataString(payload.PresentationId);
        }

        return null;
    }


    //Shared exact matcher: the given method to this endpoint's resolved path.
    private static ValueTask<MatchPayload?> MatchExact(ExchangeContext context, ServerEndpoint endpoint, string method)
    {
        IncomingRequest? req = context.IncomingRequest;
        if(req is null)
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        if(!WellKnownHttpMethods.Equals(req.Method, method))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
    }


    //§3.5.4 / §3.5.5 path matcher: the given method to a path that is the holder's resolved
    // /presentations collection path plus a single non-empty trailing {id} segment. The resolved URI
    //is the collection path; the request adds the id. A skin that did template routing populates the
    //id on RouteValues; honour it first.
    private static ValueTask<MatchPayload?> MatchPresentationIdPath(
        ExchangeContext context, ServerEndpoint endpoint, string method)
    {
        IncomingRequest? req = context.IncomingRequest;
        if(req is null)
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        if(!WellKnownHttpMethods.Equals(req.Method, method))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        if(req.RouteValues.TryGetValue(WellKnownVcalmRouteParameters.PresentationId, out string? routeValue)
            && !string.IsNullOrEmpty(routeValue))
        {
            return ValueTask.FromResult<MatchPayload?>(new VcalmPresentationIdMatchPayload(routeValue));
        }

        string collectionPath = endpoint.ResolvedUri.AbsolutePath;
        if(!TryExtractTrailingSegment(req.Path, collectionPath, out string idSegment))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        return ValueTask.FromResult<MatchPayload?>(new VcalmPresentationIdMatchPayload(idSegment));
    }


    //Whether requestPath equals collectionPath + "/" + <single non-empty segment>. Strips the query
    //and fragment, then checks the prefix and that exactly one non-empty trailing segment remains.
    private static bool TryExtractTrailingSegment(string requestPath, string collectionPath, out string segment)
    {
        segment = string.Empty;

        ReadOnlySpan<char> pathSpan = requestPath.AsSpan();
        int queryStart = pathSpan.IndexOf('?');
        if(queryStart >= 0) { pathSpan = pathSpan[..queryStart]; }

        int fragmentStart = pathSpan.IndexOf('#');
        if(fragmentStart >= 0) { pathSpan = pathSpan[..fragmentStart]; }

        ReadOnlySpan<char> collectionSpan = collectionPath.AsSpan();
        if(collectionSpan.Length > 1 && collectionSpan[^1] == '/')
        {
            collectionSpan = collectionSpan[..^1];
        }

        if(pathSpan.Length <= collectionSpan.Length + 1)
        {
            return false;
        }

        if(!pathSpan[..collectionSpan.Length].SequenceEqual(collectionSpan) || pathSpan[collectionSpan.Length] != '/')
        {
            return false;
        }

        ReadOnlySpan<char> tail = pathSpan[(collectionSpan.Length + 1)..];

        //Strip a single trailing slash on the tail, then require exactly one non-empty segment.
        if(tail.Length > 0 && tail[^1] == '/')
        {
            tail = tail[..^1];
        }

        if(tail.Length == 0 || tail.Contains('/'))
        {
            return false;
        }

        segment = tail.ToString();

        return true;
    }


    //§2.4 request-boundary MUSTs for the §3.5.1 / §3.5.2 body, mirroring the issuer / verifier: a body
    //MUST be present, within the configured size cap (else 413), and application/json (else 400).
    private static ServerHttpResponse? CheckRequestBoundary(
        ExchangeContext context, EndpointServer server, out string requestBody)
    {
        var vcalm = server.Vcalm();
        requestBody = string.Empty;

        IncomingRequest? req = context.IncomingRequest;
        if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
        {
            return MalformedRequest();
        }

        if(req.Body.Bytes.Length > vcalm.VcalmMaxRequestBytes)
        {
            VcalmProblemDetail tooLarge = VcalmProblemDetail.Error(
                VcalmProblemTypes.MalformedValueError,
                "PAYLOAD_TOO_LARGE",
                "The request body exceeds the configured maximum payload size.");

            return ServerHttpResponse.PayloadTooLarge(
                VcalmResponseWriter.BuildProblemDetailBody(tooLarge), WellKnownMediaTypes.Application.Json);
        }

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


    //A §3.5.1 / §3.5.2 malformed-input 400 (an RFC 9457 ProblemDetail naming the malformed-value type).
    private static ServerHttpResponse MalformedRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "The request body could not be parsed as a valid presenting request.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    //The §2.4 unknown-option 400, carrying the §3.8 UNKNOWN_OPTION_PROVIDED type.
    private static ServerHttpResponse UnknownOptionRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.UnknownOptionProvided,
            "UNKNOWN_OPTION_PROVIDED",
            "An option that is unknown to or unsupported by the holder instance was provided to the API call.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    //The §3.5.1 non-derivable-credential 400: the supplied credential carries no ecdsa-sd-2023 base
    //proof to derive from.
    private static ServerHttpResponse NonDerivableRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "The supplied credential is not a derivable selective-disclosure credential: it carries no "
            + "ecdsa-sd-2023 base proof to derive a selectively-disclosed credential from (§3.5.1).");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    //The §3.5.2 missing-challenge-or-domain 400: a presentation proof binds an anti-replay challenge
    //and a domain (VC-DM 2.0 §4.13); a request omitting either cannot produce a valid proof.
    private static ServerHttpResponse MissingChallengeOrDomainRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "A §3.5.2 presentation proof binds a challenge and a domain (VC Data Model 2.0 §4.13); the "
            + "request must supply options.challenge and options.domain.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    //The §3.4.3.2 channel-domain-mismatch 400: the request asked the holder to bind a verifier domain
    //that does not match the current communication channel the deployment staged on the context. That
    //is a relayed / replayed presentation request, so the holder refuses to sign — the anti-replay MUST
    //("the holder MUST check that the domain value matches the domain of the verifier it is
    //communicating with"). Carried as the §3.8 MALFORMED_VALUE_ERROR request-refusal family.
    private static ServerHttpResponse ChannelDomainMismatchRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "The request's options.domain does not match the current communication channel; a §3.4.3.2 "
            + "holder refuses to sign a presentation whose domain names a verifier other than the one it "
            + "is communicating with (anti-replay).");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    //The §3.5.4 410 Gone for a soft-deleted presentation whose tombstone the store retained ("Gone!
    //There is no data here").
    private static ServerHttpResponse Gone() =>
        ServerHttpResponse.Json(410, string.Empty, WellKnownMediaTypes.Application.Json);
}
